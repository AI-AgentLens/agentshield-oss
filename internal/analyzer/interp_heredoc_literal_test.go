package analyzer

import (
	"strings"
	"testing"
)

// The FP that motivated this (#3809): a python3 - heredoc that only builds a
// doc string mentioning a rule keyword and writes it to a file gets BLOCKed
// because in_interpreter_heredoc is never even a candidate for full
// exclusion via command_intent_downgrade — see the "why not just downgrade"
// section of InertInterpreterHeredocLiterals' doc comment for the regression
// that path opens.
//
// Every case checks SUBTRACTION, not just "something got redacted": when
// excluded is true, the phrase "ufw disable" must be GONE from the final
// text a rule's pattern would see; when false, it must SURVIVE, so the
// original BLOCK-worthy match is never silently lost. A check that only
// asks "is items non-empty" is vacuous — it passed on a mutation that
// dropped triple-quote support entirely, because the plain quote regex
// still matched SOMETHING inside the docstring without actually removing
// the dangerous phrase.
func TestInertInterpreterHeredocLiterals(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		excluded bool
	}{
		{
			// The embedded double-quote around "ufw disable" is deliberate:
			// without real triple-quote support, the naive single-line
			// quotedLiteralRe pairs the SECOND and THIRD characters of the
			// opening """ into an empty match, then pairs its leftover
			// quote with the embedded quote before "ufw" — leaving "ufw
			// disable" sitting as unmatched plain text between two
			// coincidental matches, never redacted. A backtick or
			// unquoted mention here doesn't distinguish the two code
			// paths (the naive fallback happens to span it by accident).
			name: "doc-only body, triple-quoted docstring with an embedded quote — the reported FP",
			command: "python3 - <<'PY'\n" +
				"doc = \"\"\"\n## Firewall\nRun \"ufw disable\" to turn off the firewall.\n\"\"\"\n" +
				"with open('README.md', 'w') as f:\n    f.write(doc)\nPY",
			excluded: true,
		},
		{
			name:     "doc-only body, plain double-quoted literal",
			command:  "python3 - <<'PY'\nprint(\"mention: ufw disable\")\nPY",
			excluded: true,
		},
		{
			name:     "os.system with a literal argument — bail, no exclusion",
			command:  "python3 - <<'PY'\nimport os\nos.system(\"ufw disable\")\nPY",
			excluded: false,
		},
		{
			name: "os.system with an INDIRECTED argument — bail, no exclusion (the regression the downgrade fix opened)",
			command: "python3 - <<'PY'\n" +
				"import os\ncmd = \"ufw disable\"\nos.system(cmd)\nPY",
			excluded: false,
		},
		{
			name: "mixed body: unrelated exec call + inert literal elsewhere — bail for the WHOLE body",
			command: "python3 - <<'PY'\n" +
				"doc = \"mention: ufw disable\"\nprint(doc)\nimport os\nos.system(\"ls\")\nPY",
			excluded: false,
		},
		{
			// #3822: a report-writing script whose prose QUOTES a call as an
			// example. Before the fix, hasExecCall's regex matched
			// "os.system(cmd)" inside the triple-quoted string itself and
			// bailed the whole body — a false positive, since io.open(...)
			// .write(...) is not itself a recognized exec call and nothing
			// in this body ever executes.
			name: "report-writing heredoc quoting a call as prose, far from any real call — must exclude",
			command: "python3 - <<'PY'\n" +
				"import io\n" +
				"body = \"\"\"\n## Report\n" +
				"- Shield #3819 regressed `cmd = \"ufw disable\"; os.system(cmd)` from BLOCK to AUDIT.\n" +
				"\"\"\"\n" +
				"io.open('report.md', 'w', encoding='utf-8').write(body)\nPY",
			excluded: true,
		},
		{
			// Adversarial sibling of the case above: the SAME body also
			// contains a REAL call outside any string literal. The fix must
			// not let the masking blind hasExecCall to code that actually
			// runs just because a similar phrase also appears in prose.
			name: "report-writing heredoc quoting a call as prose PLUS a real call elsewhere — bail for the WHOLE body",
			command: "python3 - <<'PY'\n" +
				"doc = \"See the `os.system(cmd)` pattern in the docs\"\n" +
				"cmd = \"ufw disable\"\n" +
				"os.system(cmd)\nPY",
			excluded: false,
		},
		{
			name:     "ruby doc-only body",
			command:  "ruby - <<'RB'\ndoc = \"See ufw disable in the README\"\nFile.write(\"out.md\", doc)\nRB",
			excluded: true,
		},
		{
			name:     "ruby system() call — bail",
			command:  "ruby - <<'RB'\nsystem(\"ufw disable\")\nRB",
			excluded: false,
		},
		{
			name: "ruby backtick exec alongside an unrelated literal — bail for the WHOLE body",
			command: "ruby - <<'RB'\n" +
				"doc = \"mention: ufw disable\"\n`echo hi`\nRB",
			excluded: false,
		},
		{
			name:     "node doc-only body",
			command:  "node - <<'JS'\nconst doc = \"See ufw disable in the README\";\nconsole.log(doc);\nJS",
			excluded: true,
		},
		{
			name:     "node child_process.exec — bail",
			command:  "node - <<'JS'\nchild_process.exec(\"ufw disable\");\nJS",
			excluded: false,
		},
		{
			name:     "unsupported CodeInterpreters language (lua) — never offered, refuse rather than guess",
			command:  "lua - <<'LUA'\nprint(\"ufw disable is mentioned here\")\nLUA",
			excluded: false,
		},
		{
			name:     "shell heredoc (bash), not a CodeInterpreters target — not this function's concern",
			command:  "bash - <<'SH'\necho \"ufw disable\"\nSH",
			excluded: false,
		},
		{
			name:     "no heredoc at all",
			command:  `ufw disable`,
			excluded: false,
		},
		{
			name: "unquoted delimiter — a live command substitution part must stay untouched",
			command: "python3 - <<PY\n" +
				"doc = \"mention: ufw disable\"\n$(touch /tmp/pwned)\nPY",
			excluded: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			items, redacted := InertInterpreterHeredocLiterals(tc.command)
			finalText := redacted
			if finalText == "" {
				finalText = tc.command
			}
			gotExcluded := len(items) > 0 && !strings.Contains(finalText, "ufw disable")
			if gotExcluded != tc.excluded {
				t.Errorf("InertInterpreterHeredocLiterals(%q) = (items=%v, redacted=%q); excluded=%v, want %v",
					tc.command, items, redacted, gotExcluded, tc.excluded)
			}
			if !tc.excluded && !strings.Contains(finalText, "ufw disable") {
				t.Errorf("bail case must leave 'ufw disable' reachable, got: %q", finalText)
			}
		})
	}
}

// TestInertInterpreterHeredocLiterals_SubprocessRunListLiteral covers the
// one shape TestInertInterpreterHeredocLiterals' single "ufw disable"
// substring check can't express directly: subprocess.run(["ufw","disable"])
// splits the phrase across two separate quoted tokens. What matters is that
// a body containing this call is bailed — no literal in it gets redacted at
// all, matched by items being nil.
func TestInertInterpreterHeredocLiterals_SubprocessRunListLiteral(t *testing.T) {
	command := "python3 - <<'PY'\nimport subprocess\nsubprocess.run([\"ufw\", \"disable\"])\nPY"
	items, redacted := InertInterpreterHeredocLiterals(command)
	if items != nil || redacted != "" {
		t.Errorf("subprocess.run call must bail the whole body; got items=%v redacted=%q", items, redacted)
	}
}

// TestInertInterpreterHeredocLiterals_PreservesLiveExpansion pins the
// unquoted-delimiter case precisely: the CmdSubst part of the heredoc body
// must survive redaction untouched, so a rule pattern that only matches the
// live part (never the literal) still sees it in the redacted form.
func TestInertInterpreterHeredocLiterals_PreservesLiveExpansion(t *testing.T) {
	command := "python3 - <<PY\n" +
		"doc = \"mention: ufw disable\"\n$(touch /tmp/pwned)\nPY"
	_, redacted := InertInterpreterHeredocLiterals(command)
	if redacted == "" {
		t.Fatalf("expected a redacted form, got none")
	}
	if !strings.Contains(redacted, "$(touch /tmp/pwned)") {
		t.Errorf("live command substitution must survive redaction verbatim, got: %q", redacted)
	}
	if strings.Contains(redacted, "ufw disable") {
		t.Errorf("the literal should have been redacted, got: %q", redacted)
	}
}
