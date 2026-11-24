package policy

import (
	"fmt"
	"testing"
)

// protected-path-via-substitution through the SourceArg carriers (#4903).
//
// A shell-source carrier (`env -S`, `man -P`, osascript's `do shell script`,
// shellparse.shellSourceFlags) hands its operand to a shell, the way `bash -c`
// does. The substitution layer descended into `bash -c` and `eval` bodies only,
// so a protected path that appears only after a decode substitution BLOCKed
// bare and under `bash -c` and decided AUDIT under every SourceArg carrier.
// Measured on main b30340a1 through `agentshield check --shell-file`, inner
// command `cat $(echo <base64 of ~/.ssh/id_rsa> | base64 -d)`:
//
//	bare               BLOCK  protected-path-via-substitution
//	bash -c '…'        BLOCK  protected-path-via-substitution
//	env -S '…'         AUDIT  sec-audit-env-dump
//	man -P '…' ls      AUDIT  (none)
//	osascript -e '…'   AUDIT  (none)
//
// Unit tests rather than corpus rows, for the reasons env_read_scope_test.go
// gives: the corpus grader compares decisions only, and each row here must
// name the rule that carries its block.

// Encoded once here so no source line carries the decoded path.
const (
	b64SSHKey  = "fi8uc3NoL2lkX3JzYQ=="       // base64(~/.ssh/id_rsa)
	b64AWSCred = "fi8uYXdzL2NyZWRlbnRpYWxz"   // base64(~/.aws/credentials)
	hexSSHKey  = "7e2f2e7373682f69645f727361" // hex(~/.ssh/id_rsa)
	b64TmpFile = "L3RtcC9oZWxsby50eHQ="       // base64(/tmp/hello.txt)
)

// sourceArgCarriers wrap one shell command in each SourceArg spelling. The
// first three are the forms #4903 names; the rest are the other mechanisms the
// carrier table reads (the = spelling, an exec wrapper in front, a path-named
// program, a flag value after a value-taking option, the positional form).
var sourceArgCarriers = []struct{ name, format string }{
	// Real `env -S` (and --split-string) performs only ${VAR} expansion and
	// never runs $(…), so its rows here and in the scope table below are kept
	// for carrier parity (#3232), not as evidence of a working bypass.
	{"env -S", `env -S '%s'`},
	{"man -P", `man -P '%s' ls`},
	{"osascript do shell script", `osascript -e 'do shell script "%s"'`},
	{"env --split-string=", `env --split-string='%s'`},
	{"man --pager=", `man --pager='%s' ls`},
	{"sudo man -P", `sudo man -P '%s' ls`},
	{"/usr/bin/man -P", `/usr/bin/man -P '%s' ls`},
	{"flock FILE -c", `flock /tmp/x.lock -c '%s'`},
	{"watch -n 1", `watch -n 1 '%s'`},
	{"osascript after another -e", `osascript -e 'set x to 1' -e 'do shell script "%s"'`},
}

func TestProtectedPathViaSubstitution_ReachesSourceArgCarriers4903(t *testing.T) {
	engine := readScopeEngine(t)
	const rule = "protected-path-via-substitution"

	inners := []struct{ name, cmd string }{
		{"base64 ssh key", "cat $(echo " + b64SSHKey + " | base64 -d)"},
		{"base64 aws credentials", "cat $(echo " + b64AWSCred + " | base64 -d)"},
		{"hex ssh key", "cat $(echo " + hexSSHKey + " | xxd -r -p)"},
	}
	for _, in := range inners {
		// The controls are derived, not asserted from memory: the bare and the
		// bash -c spellings must BLOCK on this rule, or every carrier row
		// below would be measuring nothing.
		for _, ctl := range []struct{ name, cmd string }{
			{"bare", in.cmd},
			{"bash -c", "bash -c '" + in.cmd + "'"},
		} {
			res := evalNormalized(engine, ctl.cmd)
			if res.Decision != DecisionBlock || !has(res.TriggeredRules, rule) {
				t.Fatalf("control %s/%s decided %s %v; want BLOCK by %s, or the carrier rows are vacuous",
					in.name, ctl.name, res.Decision, res.TriggeredRules, rule)
			}
		}
		for _, c := range sourceArgCarriers {
			cmd := fmt.Sprintf(c.format, in.cmd)
			t.Run(in.name+"/"+c.name, func(t *testing.T) {
				res := evalNormalized(engine, cmd)
				if res.Decision != DecisionBlock {
					t.Fatalf("decoded protected-path read under a SourceArg carrier not BLOCKed: %s → %s %v",
						cmd, res.Decision, res.TriggeredRules)
				}
				if !has(res.TriggeredRules, rule) {
					t.Errorf("BLOCKed, but not by %s: %s → %v", rule, cmd, res.TriggeredRules)
				}
			})
		}
	}

	// Scope across the carrier. The carrier's shell is a child process, so it
	// sees the statement's prefix assignments and the exported environment.
	for _, tc := range []struct{ name, cmd string }{
		{"prefix binding", "B=" + b64SSHKey + " man -P 'cat $(echo $B | base64 -d)' ls"},
		{"exported binding", "export B=" + b64SSHKey + "; man -P 'cat $(echo $B | base64 -d)' ls"},
		{"exported binding, osascript", "export B=" + b64SSHKey + `; osascript -e 'do shell script "cat $(echo $B | base64 -d)"'`},
		// Carrier parity only: real env -S does not run $(…) (see sourceArgCarriers).
		{"exported binding, env -S", "export B=" + b64SSHKey + "; env -S 'cat $(echo $B | base64 -d)'"},
		// A word the walk cannot resolve elsewhere in argv does not hide the
		// source operand.
		{"unresolvable trailing operand", "man -P 'cat $(echo " + b64SSHKey + " | base64 -d)' $(date +%s)"},
	} {
		t.Run("scope/"+tc.name, func(t *testing.T) {
			res := evalNormalized(engine, tc.cmd)
			if res.Decision != DecisionBlock || !has(res.TriggeredRules, rule) {
				t.Errorf("%s → %s %v, want BLOCK by %s", tc.cmd, res.Decision, res.TriggeredRules, rule)
			}
		})
	}
}

// The negative half: each row reaches a SourceArg carrier and decodes or names
// something, and opens no protected file, so a BLOCK through this rule would be
// a false positive.
func TestProtectedPathViaSubstitution_SourceArgCarrierNegatives4903(t *testing.T) {
	engine := readScopeEngine(t)
	const rule = "protected-path-via-substitution"

	var cases []struct{ name, cmd string }
	// The same carriers decoding a path that is not protected.
	for _, c := range sourceArgCarriers {
		cases = append(cases, struct{ name, cmd string }{
			"benign decode/" + c.name,
			fmt.Sprintf(c.format, "cat $(echo "+b64TmpFile+" | base64 -d)"),
		})
	}
	cases = append(cases, []struct{ name, cmd string }{
		// The carrier's shell is a child: an UNEXPORTED binding is not in its
		// environment, so $B is empty there and nothing is decoded. Folding it
		// would be the same false BLOCK bash -c's negative pins.
		{"unexported binding, man -P", "B=" + b64SSHKey + "; man -P 'cat $(echo $B | base64 -d)' ls"},
		{"unexported binding, osascript", "B=" + b64SSHKey + `; osascript -e 'do shell script "cat $(echo $B | base64 -d)"'`},
		// A flag of a carrier that is not its source flag: -M is a manpath.
		{"man -M is not shell source", "man -M 'cat $(echo " + b64SSHKey + " | base64 -d)' ls"},
		// The decode is printed, not opened.
		{"decode only printed", "man -P 'echo $(echo " + b64SSHKey + " | base64 -d)' ls"},
		// A string literal in AppleScript is not a do shell script call.
		{"osascript dialog text", `osascript -e 'display dialog "cat $(echo ` + b64SSHKey + ` | base64 -d)"'`},
		// A relative ./man is a project script, not the carrier.
		{"relative ./man", "./man -P 'cat $(echo " + b64SSHKey + " | base64 -d)' ls"},
		// Not a carrier at all: grep's -e value is a pattern.
		{"grep -e pattern", "grep -e 'cat $(echo " + b64SSHKey + " | base64 -d)' notes.txt"},
	}...)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := evalNormalized(engine, tc.cmd)
			if has(res.TriggeredRules, rule) {
				t.Errorf("%s → %s %v: %s fired on a command that opens no protected file",
					tc.cmd, res.Decision, res.TriggeredRules, rule)
			}
			if res.Decision == DecisionBlock {
				t.Errorf("%s → BLOCK %v, want no BLOCK", tc.cmd, res.TriggeredRules)
			}
		})
	}
}
