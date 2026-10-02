package policy

import (
	"regexp"
	"testing"
)

// TestMayHaveProgramPathsBehindPrefixes pins the gate #4032 fixed, at the gate.
//
// mayHaveProgramPaths decides whether the ON evaluation (#3991's program-name
// reading) runs at all. A later heredoc line whose path-spelled command word
// sits behind a wrapper or assignment prefix used to be declined: the regex
// admitted a path only right after the newline (or after a bare `sudo `,
// #4029), and the line check peeled only a bare `sudo`. Every row here BLOCKs
// when the line is evaluated on its own; twelve of them fell to the policy
// default when embedded, measured on main 2a5c5a29 with
// configs/default_policy.yaml.
//
// The must-NOT rows matter as much: a gate that admitted every command with a
// path in it would pass the rows above and pay an ON evaluation on most of
// real traffic. Admission is a cost, never a decision (ON can only raise), so
// the false rows pin cost, and the decision-level pins live in
// internal/analyzer/abs_path_command_word_parity_test.go.
func TestMayHaveProgramPathsBehindPrefixes(t *testing.T) {
	rm := "r" + "m"
	later := func(line string) string { return "bash <<'EOF'\necho ok\n" + line + "\nEOF" }
	prefixes := []string{
		"", "sudo ", // admitted before #4032
		"sudo -n ", "sudo -u root ", "sudo -- ", "sudo sudo ",
		"doas ", "env ", "nice -n 1 ", "nohup ", "timeout 10 ", "command ",
		"X=1 ", "X=1 sudo ",
	}
	for _, p := range prefixes {
		cmd := later(p + "/usr/bin/" + rm + " -rf /var/log")
		if !mayHaveProgramPaths(cmd, nil) {
			t.Errorf("prefix %q: later heredoc line declined by the precheck:\n%s", p, cmd)
		}
	}
	admitted := map[string]string{
		"two statements on the later line":   later("echo a; sudo -n /usr/bin/" + rm + " -rf /var/log"),
		"and-chained on the later line":      later("echo a && nohup /usr/bin/" + rm + " -rf /var/log"),
		"home-anchored behind a wrapper":     later("sudo -n ~/bin/" + rm + " -rf /var/log"),
		"quoted path behind a wrapper":       later("sudo -n \"/usr/bin/" + rm + "\" -rf /var/log"),
		"benign path-spelled program (cost)": later("sudo -n /usr/bin/ls /tmp"),
		// Not a later line: the quoted body is admitted by the regex's
		// quote-then-`sudo ` alternative, which main had and Codex pass 1 on
		// #4032 found the first draft of the later-line rewrite had dropped
		// (BLOCK on main, AUDIT on the draft). The regex language must stay a
		// superset of main's.
		"quoted body behind bare sudo, piped to bash": "echo 'sudo /usr/bin/" + rm + " -rf /var/log' | bash",
	}
	for name, cmd := range admitted {
		if !mayHaveProgramPaths(cmd, nil) {
			t.Errorf("%s: declined by the precheck:\n%s", name, cmd)
		}
	}
	declined := map[string]string{
		"single line, path as an argument":         "ls /tmp",
		"later line, path as an argument":          later("see /usr/share/doc for details"),
		"later line, wrapper, bare program":        later("sudo -n ls /tmp"),
		"later line, env assignment, bare program": later("env FOO=1 ls"),
		"data heredoc, bare program":               "cat <<'EOF' > notes.txt\necho ok\nsudo -n " + rm + " -rf /var/log\nEOF",
		"relative path is a project script":        later("sudo -n ./" + rm + " -rf /var/log"),
		"dynamic path is not static":               later("sudo -n /usr/bin/$x -rf /var/log"),
	}
	for name, cmd := range declined {
		if mayHaveProgramPaths(cmd, nil) {
			t.Errorf("%s: admitted by the precheck (an ON evaluation with nothing to read):\n%s", name, cmd)
		}
	}
}

// TestEmbeddedPathWordReAdmitsEverythingMainDid is the gate-level
// monotonicity pin: every input the regex on main (before #4032) admitted, the
// current regex admits. Codex pass 1 and the Opus pass on #4032 both found the
// first draft dropping main's quote-then-`sudo ` allowance, which turned
// `echo 'sudo /usr/bin/rm …' | bash`, `bash -c '…'`, `x=$(sudo …)` and
// `(sudo …)` from BLOCK into AUDIT. The relaxation sweep compares ON against
// OFF and cannot see that; a superset check on the language can.
func TestEmbeddedPathWordReAdmitsEverythingMainDid(t *testing.T) {
	mainRe := regexp.MustCompile("[\n'\"(`=]\\s*(?:sudo\\s+)?(/|~[A-Za-z0-9._-]*/)[^\\s/]")
	rm := "r" + "m"
	payload := "sudo /usr/bin/" + rm + " -rf /var/log"
	plain := "/usr/bin/" + rm + " -rf /var/log"
	var inputs []string
	for _, pl := range []string{payload, plain} {
		inputs = append(inputs,
			"echo '"+pl+"' | bash",
			"echo \""+pl+"\" | bash",
			"bash -c '"+pl+"'",
			"x=$("+pl+")",
			"("+pl+")",
			"`"+pl+"`",
			"cmd="+pl,
			"bash <<'EOF'\necho ok\n"+pl+"\nEOF",
			"cat <<'EOF'\n"+pl+"\nEOF\necho '"+pl+"' | bash",
			"true\n"+pl,
			"bash -c '"+pl+"' <<'EOF'\nhi\nEOF",
		)
	}
	for _, p := range []string{"", "sudo ", "sudo -n ", "sudo -u root ", "sudo -- ", "sudo sudo ", "doas ", "env ", "nice -n 1 ", "nohup ", "timeout 10 ", "command ", "X=1 ", "X=1 sudo "} {
		inputs = append(inputs, "bash <<'EOF'\necho ok\n"+p+plain+"\nEOF")
	}
	admittedByMain := 0
	for _, in := range inputs {
		if !mainRe.MatchString(in) {
			continue
		}
		admittedByMain++
		if !embeddedPathWordRe.MatchString(in) {
			t.Errorf("main's regex admitted this and the current one does not:\n%s", in)
		}
	}
	if admittedByMain < 20 {
		t.Fatalf("positive control: main's regex admitted only %d/%d inputs; the table is not exercising it", admittedByMain, len(inputs))
	}
	t.Logf("%d/%d inputs admitted by main's regex, all admitted now", admittedByMain, len(inputs))
}

// TestMayHaveProgramPathsQuotedBodyBehindPrefixes pins #4046: a path-spelled
// command word inside a quoted body that RUNS, behind a wrapper prefix. The
// regex admits a quoted path only right after the quote (or a bare `sudo `),
// so `sudo -n /usr/bin/rm` in the body was declined and the command fell from
// BLOCK (bare spelling) to the policy default. The must-decline rows keep the
// admission cost bounded: quoted paths with no carrier shape never parse.
func TestMayHaveProgramPathsQuotedBodyBehindPrefixes(t *testing.T) {
	rm := "r" + "m"
	for _, p := range []string{"sudo -n ", "sudo -u root ", "nice -n 1 ", "env ", "X=1 ", "nohup ", "timeout 10 "} {
		cmd := "echo '" + p + "/usr/bin/" + rm + " -rf /var/log' | bash"
		if !mayHaveProgramPaths(cmd, nil) {
			t.Errorf("prefix %q: quoted body piped to bash declined:\n%s", p, cmd)
		}
	}
	// Each carrier channel ExecutedText covers needs its own admitted row, or a
	// narrowed gate survives (Opus pass on #4153: `|`-only and no-gate mutants).
	for name, cmd := range map[string]string{
		"write then execute":        "echo 'sudo -n /usr/bin/" + rm + " -rf /var/log' > /tmp/x.sh; bash /tmp/x.sh",
		"capture then eval":         "x=$(echo 'sudo -n /usr/bin/shutdown -h now'); eval \"$x\"",
		"process substitution":      "bash <(echo 'sudo -n /usr/bin/" + rm + " -rf /var/log')",
		"command substitution body": "bash -c \"$(echo 'sudo -n /usr/bin/" + rm + " -rf /var/log')\"",
	} {
		if !mayHaveProgramPaths(cmd, nil) {
			t.Errorf("%s: declined by the precheck:\n%s", name, cmd)
		}
	}
	for name, cmd := range map[string]string{
		"quoted path, no carrier shape":       "git commit -m 'fix /foo bar'",
		"wrapper-only prefix, bare program":   "echo 'sudo -n ls /tmp' | bash",
		"path as an argument inside a body":   "echo 'cat /etc/hosts' | bash",
		"emitted text never reaches executor": "echo 'sudo -n /usr/bin/" + rm + " -rf /x' | grep sudo",
	} {
		if mayHaveProgramPaths(cmd, nil) {
			t.Errorf("%s: admitted by the precheck:\n%s", name, cmd)
		}
	}
}
