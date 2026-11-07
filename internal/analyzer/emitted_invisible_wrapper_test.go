package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// TestEmittedInvisibleBehindWrapper_4660 pins, on the full pipeline, the #4660
// fix round: TP-STEG-AI-003 (`printf` of five escaped U+200B into source)
// BLOCKs bare, and must BLOCK behind every exec wrapper the parity sweeps
// prefix it with — TestWrapperPositionalParity, TestWrapperValueFlagParity and
// TestExecWrapperParity each counted it as one more leak (47 > 46) before the
// emitted-escape reading looked through wrappers. TestIFSSeparatorParity,
// TestUnsetParamExpParity and TestHeredocShellExecParity counted it too, until
// the guardian read every candidate form rather than only the raw text. The
// hex and octal spellings (#4659) and the \u spelling (#4660) each get the
// same wrapper matrix.
//
// Pipeline-only on purpose: the BLOCK comes from the guardian, which the
// regex-only engine behind TestAccuracy_* does not run, so these rows would be
// skipped there. Escapes are built from a backslash at run time.
func TestEmittedInvisibleBehindWrapper_4660(t *testing.T) {
	engine := newPipelineEngine(t)
	const bs = "\\"
	const zw = "​"

	var steg string
	for _, tc := range testdata.AllTestCases() {
		if tc.ID == "TP-STEG-AI-003" {
			steg = tc.Command
		}
	}
	if steg == "" {
		t.Fatal("TP-STEG-AI-003 is gone from the corpus; this test pins it")
	}

	block := func(t *testing.T, cmd string) {
		t.Helper()
		res := engine.Evaluate(cmd, nil)
		if string(res.Decision) != "BLOCK" {
			t.Errorf("%q decided %s (rules %v), want BLOCK", cmd, res.Decision, res.TriggeredRules)
		}
	}

	t.Run("TP-STEG-AI-003", func(t *testing.T) {
		block(t, steg)
		for _, w := range []string{"sudo", "nohup", "env", "env -i", "/usr/bin/env", "sudo -u root", "command",
			"flock -w 5 /var/lock/deploy.lock", "chroot /mnt/rootfs", "setarch x86_64", "busybox",
			"setpriv --reuid=0 --regid=0 --clear-groups", "runuser -u root", "runuser -u root --",
			"strace -o /tmp/trace.log", "timeout -s KILL 5", "taskset -c 0-3"} {
			block(t, w+" "+steg)
		}
		// The other sweeps that counted it: TestIFSSeparatorParity,
		// TestUnsetParamExpParity and TestHeredocShellExecParity.
		block(t, strings.Replace(steg, "printf ", "printf${IFS}", 1))
		block(t, "p${zqx}rintf"+strings.TrimPrefix(steg, "printf"))
		block(t, "bash <<EOF\n"+steg+"\nEOF")
	})

	escape := func(enc, prog string) string {
		var out strings.Builder
		switch enc {
		case "hex":
			for _, b := range []byte(zw) {
				fmt.Fprintf(&out, "%sx%02x", bs, b)
			}
		case "octal":
			lead := ""
			if prog == "echo" {
				lead = "0" // echo's octal is \0ddd
			}
			for _, b := range []byte(zw) {
				fmt.Fprintf(&out, "%s%s%03o", bs, lead, b)
			}
		case "u":
			out.WriteString(bs + "u200b")
		}
		return out.String()
	}
	quiet := func(t *testing.T, cmd string) {
		t.Helper()
		res := engine.Evaluate(cmd, nil)
		for _, r := range res.TriggeredRules {
			if r == "guardian-unicode_steganography" {
				t.Errorf("%q fired guardian-unicode_steganography (decision %s)", cmd, res.Decision)
			}
		}
		if string(res.Decision) == "BLOCK" {
			t.Errorf("%q decided BLOCK (rules %v)", cmd, res.TriggeredRules)
		}
	}
	// Each row BLOCKs only where the program that runs there writes the
	// bytes (class 4; Gary, 2026-10-30): printf behind any wrapper; echo bare
	// or behind `builtin`; `echo -e` and `command echo` for hex and \0ddd.
	// echo without -e behind sudo/env/nohup is /bin/echo, which writes the
	// escapes as text: those rows stay quiet.
	for _, enc := range []string{"hex", "octal", "u"} {
		for _, prog := range []string{"printf", "echo", "echo -e"} {
			encProg := "echo"
			if prog == "printf" {
				encProg = "printf"
			}
			emit := prog + " '" + strings.Repeat(escape(enc, encProg), 5) + "'"
			for _, w := range []string{"", "sudo ", "env -i ", "nohup ", "command ", "builtin "} {
				cmd := w + emit + " >> src/auth.py"
				wrapper := strings.TrimSpace(w)
				fire := true
				switch {
				case prog == "printf" || wrapper == "" || wrapper == "builtin":
				case prog == "echo" && wrapper != "command":
					fire = false // Gary, 2026-10-30: /bin/echo decodes nothing without -e
				default:
					fire = enc != "u" // /bin/echo -e and `command echo`: no \u anywhere
				}
				t.Run(enc+"/"+wrapper+"/"+prog, func(t *testing.T) {
					if fire {
						block(t, cmd)
					} else {
						quiet(t, cmd)
					}
				})
			}
		}
	}

	// Quiet: ordinary escapes, one zero-width (below the signal's threshold of
	// 5), an escape in a printf ARGUMENT rather than the format.
	for _, cmd := range []string{
		"sudo printf 'a" + bs + "tb" + bs + "x41c" + bs + "n' >> notes.md",
		"nohup echo 'tab" + bs + "there' >> notes.md",
		"sudo printf 'one" + escape("u", "printf") + "zero" + bs + "n' >> notes.md",
		"env -i printf 'one" + escape("hex", "printf") + "zero" + bs + "n' >> notes.md",
		"sudo printf '%s" + bs + "n' '" + strings.Repeat(escape("u", "printf"), 5) + "' >> notes.md",
		"command printf '%s" + bs + "n' '" + strings.Repeat(escape("octal", "printf"), 5) + "' >> notes.md",
	} {
		t.Run("quiet/"+cmd, func(t *testing.T) { quiet(t, cmd) })
	}
}
