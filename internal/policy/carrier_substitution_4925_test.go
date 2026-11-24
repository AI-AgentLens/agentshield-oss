package policy

import (
	"fmt"
	"testing"
)

// protected-path-via-substitution through two carrier shapes the scope walk
// missed (#4925, left open by #4924).
//
//  1. A wrapper in front of a `-c` carrier. The `-c` arm of scopeEval.carrier
//     keyed on Args[0], so `sudo bash -c '…'` reached neither it nor the
//     shell-source arm, which does strip wrappers (`sudo man -P` BLOCKed).
//  2. A double-quoted carrier operand. The outer shell runs the decode inside
//     the quotes, so the child body holds the decoded path as a plain literal,
//     and the child walk skipped plain literals.
//
// Measured on main 5687b16a through `agentshield check --shell-file`, inner
// command `cat $(echo <base64 of ~/.ssh/id_rsa> | base64 -d)`:
//
//	bash -c '…'        BLOCK  protected-path-via-substitution
//	sudo bash -c '…'   AUDIT  ts-audit-sudo
//	env bash -c '…'    AUDIT  sec-audit-env-dump
//	bash -c "…"        AUDIT  (none)
//	man -P "…" ls      AUDIT  (none)
//
// Unit tests rather than corpus rows for the reason source_arg_substitution_test.go
// gives: each row must name the rule that carries its block.

// carrierGaps4925 wrap one shell command in each spelling #4925 is about. The
// inner command is spliced in as written, so a double-quoted row hands the
// outer shell a decode to run.
var carrierGaps4925 = []struct{ name, format string }{
	// 1. An exec wrapper in front of a -c carrier.
	{"sudo bash -c", `sudo bash -c '%s'`},
	{"sudo -u root bash -c", `sudo -u root bash -c '%s'`},
	{"env bash -c", `env bash -c '%s'`},
	{"/usr/bin/env bash -c", `/usr/bin/env bash -c '%s'`},
	{"nice bash -c", `nice bash -c '%s'`},
	{"timeout 5 sh -c", `timeout 5 sh -c '%s'`},
	{"nohup bash -lc", `nohup bash -lc '%s'`},
	{"sudo su -c", `sudo su -c '%s'`},
	{"sudo nice zsh -c", `sudo nice zsh -c '%s'`},
	// 2. The outer shell decodes inside a double-quoted operand.
	{"bash -c dq", `bash -c "%s"`},
	{"sh -c dq", `sh -c "%s"`},
	{"sudo bash -c dq", `sudo bash -c "%s"`},
	{"eval dq", `eval "%s"`},
	{"man -P dq", `man -P "%s" ls`},
	{"man --pager= dq", `man --pager="%s" ls`},
	{"sudo man -P dq", `sudo man -P "%s" ls`},
	{"watch -n 1 dq", `watch -n 1 "%s"`},
	{"flock FILE -c dq", `flock /tmp/x.lock -c "%s"`},
	// Carrier parity only: real env -S runs no $(…) itself, but here the
	// OUTER shell has already run it (see source_arg_substitution_test.go).
	{"env -S dq", `env -S "%s"`},
}

func TestProtectedPathViaSubstitution_WrappedAndDoubleQuotedCarriers4925(t *testing.T) {
	engine := readScopeEngine(t)
	const rule = "protected-path-via-substitution"

	inners := []struct{ name, cmd string }{
		{"base64 ssh key", "cat $(echo " + b64SSHKey + " | base64 -d)"},
		{"base64 aws credentials", "cat $(echo " + b64AWSCred + " | base64 -d)"},
		{"hex ssh key", "cat $(echo " + hexSSHKey + " | xxd -r -p)"},
	}
	for _, in := range inners {
		// Derived controls: the bare and single-quoted bash -c forms must
		// BLOCK on this rule, or the rows below measure nothing.
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
		for _, c := range carrierGaps4925 {
			cmd := fmt.Sprintf(c.format, in.cmd)
			t.Run(in.name+"/"+c.name, func(t *testing.T) {
				res := evalNormalized(engine, cmd)
				if res.Decision != DecisionBlock || !has(res.TriggeredRules, rule) {
					t.Errorf("%s → %s %v, want BLOCK by %s", cmd, res.Decision, res.TriggeredRules, rule)
				}
			})
		}
	}

	for _, tc := range []struct{ name, cmd string }{
		// env -i BLOCKs on its own (ts-block-env-strip-shell-exec); the decode
		// is now attributed too, as it is for the unwrapped bash -c.
		{"env -i bash -c", "env -i bash -c 'cat $(echo " + b64SSHKey + " | base64 -d)'"},
		// The whole command is decoded by the outer shell.
		{"decoded command, bash -c dq", `bash -c "$(echo ` + b64Command4925 + ` | base64 -d)"`},
		// Only part of the path is decoded.
		{"tilde then decoded tail", `bash -c "cat ~$(echo ` + b64SSHTail4925 + ` | base64 -d)"`},
		{"redirect target", `bash -c "cat < $(echo ` + b64SSHKey + ` | base64 -d)"`},
		// Scope. The wrapper is transparent to the environment model, the same
		// as sudo man -P since #4903: an exported or prefix binding reaches the
		// child.
		{"exported binding, sudo bash -c", "export B=" + b64SSHKey + "; sudo bash -c 'cat $(echo $B | base64 -d)'"},
		{"prefix binding, env bash -c", "B=" + b64SSHKey + " env bash -c 'cat $(echo $B | base64 -d)'"},
		// In a double-quoted operand the OUTER shell expands $B, so an
		// unexported binding counts.
		{"unexported binding, bash -c dq", "B=" + b64SSHKey + `; bash -c "cat $(echo $B | base64 -d)"`},
	} {
		t.Run("shape/"+tc.name, func(t *testing.T) {
			res := evalNormalized(engine, tc.cmd)
			if res.Decision != DecisionBlock || !has(res.TriggeredRules, rule) {
				t.Errorf("%s → %s %v, want BLOCK by %s", tc.cmd, res.Decision, res.TriggeredRules, rule)
			}
		})
	}
}

// The negative half: each row reaches one of the readings above and opens no
// protected file, or opens one the substitution layer had no say in.
func TestProtectedPathViaSubstitution_WrappedAndDoubleQuotedNegatives4925(t *testing.T) {
	engine := readScopeEngine(t)
	const rule = "protected-path-via-substitution"

	var cases []struct{ name, cmd string }
	for _, c := range carrierGaps4925 {
		cases = append(cases, struct{ name, cmd string }{
			"benign decode/" + c.name,
			fmt.Sprintf(c.format, "cat $(echo "+b64TmpFile+" | base64 -d)"),
		})
	}
	cases = append(cases, []struct{ name, cmd string }{
		// An unexported binding is not in a single-quoted child's environment.
		{"unexported binding, env bash -c", "B=" + b64SSHKey + "; env bash -c 'cat $(echo $B | base64 -d)'"},
		// Behind a wrapper eval is not the builtin, and -c is not always a
		// shell's flag.
		{"sudo eval", "sudo eval 'cat $(echo " + b64SSHKey + " | base64 -d)'"},
		{"sudo grep -c", "sudo grep -c 'cat $(echo " + b64SSHKey + " | base64 -d)' notes.txt"},
		{"env echo bash -c", "env echo bash -c 'cat $(echo " + b64SSHKey + " | base64 -d)'"},
		{"sudo ./bash -c", "sudo ./bash -c 'cat $(echo " + b64SSHKey + " | base64 -d)'"},
		// The decoded path is printed, not opened.
		{"echo in dq body", `bash -c "echo $(echo ` + b64SSHKey + ` | base64 -d)"`},
		{"printf in dq body", `bash -c "printf %s $(echo ` + b64SSHKey + ` | base64 -d)"`},
		{"eval echo dq", `eval "echo $(echo ` + b64SSHKey + ` | base64 -d)"`},
		// Not shell source: -M is a manpath, grep's -e value a pattern.
		{"man -M dq", `man -M "cat $(echo ` + b64SSHKey + ` | base64 -d)" ls`},
		{"grep -e dq", `grep -e "cat $(echo ` + b64SSHKey + ` | base64 -d)" notes.txt`},
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

	// Only a DECODE the outer shell folds is marked. `$HOME` expanded inside
	// the double quotes is the ssh rule's (BLOCK sec-block-ssh-private with
	// the shipped packs), and main does not name this rule for it; the
	// receipt stays as it was.
	cmd := `bash -c "cat $HOME/.ssh/id_rsa"`
	if res := evalNormalized(engine, cmd); has(res.TriggeredRules, rule) {
		t.Errorf("%s → %s %v, want no %s (main's receipt)", cmd, res.Decision, res.TriggeredRules, rule)
	}
}

const (
	// base64("cat ~/.ssh/id_rsa"): a whole command the outer shell decodes.
	b64Command4925 = "Y2F0IH4vLnNzaC9pZF9yc2E="
	// base64("/.ssh/id_rsa"): the tail of the path after a literal `~`.
	b64SSHTail4925 = "Ly5zc2gvaWRfcnNh"
)
