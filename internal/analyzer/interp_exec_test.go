package analyzer

import (
	"slices"
	"testing"
)

// interp_exec.go's core claim (#3697): a command-execution call inside an
// interpreter heredoc body is recovered as a standalone candidate, while a
// bare mention of the same phrase is not. See TP/TN-MACOS-SEC-005/006 in
// testdata for the end-to-end pipeline/fallback-engine proof; these tests
// pin the extractor itself, one language/call-form at a time.

func TestInterpreterHeredocExecStatements_RealCalls(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{
			"python os.system",
			"python3 - <<'PY'\nimport os\nos.system('csrutil disable')\nPY",
			"csrutil disable",
		},
		{
			"python subprocess.run list arg",
			"python3 - <<'PY'\nimport subprocess\nsubprocess.run([\"csrutil\", \"disable\"])\nPY",
			"csrutil disable",
		},
		{
			"python subprocess.Popen string arg",
			`python3 - <<'PY'
import subprocess
subprocess.Popen("csrutil disable")
PY`,
			"csrutil disable",
		},
		{
			// The closed allowlist matches the literal `child_process.exec`
			// spelling only (see the package doc comment) — an aliased
			// import (`const cp = require('child_process'); cp.exec(...)`)
			// is a documented residual, not a supported form.
			"node child_process.exec",
			"node - <<'JS'\nconst child_process = require('child_process');\nchild_process.exec('csrutil disable');\nJS",
			"csrutil disable",
		},
		{
			"node child_process.execSync",
			"node - <<'JS'\nchild_process.execSync('csrutil disable');\nJS",
			"csrutil disable",
		},
		{
			"ruby system",
			"ruby - <<'RB'\nsystem(\"csrutil disable\")\nRB",
			"csrutil disable",
		},
		{
			"ruby backticks",
			"ruby - <<'RB'\n`csrutil disable`\nRB",
			"csrutil disable",
		},
		{
			"perl system",
			"perl - <<'PL'\nsystem(\"csrutil disable\");\nPL",
			"csrutil disable",
		},
		{
			"perl backticks",
			"perl - <<'PL'\n`csrutil disable`;\nPL",
			"csrutil disable",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InterpreterHeredocExecStatements(tt.cmd)
			if !slices.Contains(got, tt.want) {
				t.Errorf("InterpreterHeredocExecStatements(%q) = %v, want to contain %q", tt.cmd, got, tt.want)
			}
		})
	}
}

// The FP #3668 was filed to document: a bare mention — prose, a comment, or
// a call in an unsupported language — must recover nothing. If it did, the
// candidate would defeat in_interpreter_heredoc for every rule using it,
// exactly the bypass this feature exists to avoid, in the opposite direction.
func TestInterpreterHeredocExecStatements_BareMentionRecoversNothing(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
	}{
		{
			"comment mentioning the phrase",
			"python3 - <<'PY'\n# docs: csrutil disable turns off SIP\nprint(1)\nPY",
		},
		{
			"comment mentioning actual call syntax",
			"python3 - <<'PY'\n# example: os.system(\"csrutil disable\") is how you would call it\nprint(1)\nPY",
		},
		{
			"string literal processed, not executed",
			"python3 - <<'PY'\nprint('the command is: csrutil disable')\nPY",
		},
		{
			"os.system with no argument to extract (dynamic)",
			"python3 - <<'PY'\nimport os\ncmd = input()\nos.system(cmd)\nPY",
		},
		{
			"no heredoc at all",
			"os.system('csrutil disable')",
		},
		{
			"shell heredoc — out of scope, in_heredoc already covers it",
			"bash <<'EOF'\ncsrutil disable\nEOF",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InterpreterHeredocExecStatements(tt.cmd)
			if len(got) != 0 {
				t.Errorf("InterpreterHeredocExecStatements(%q) = %v, want empty", tt.cmd, got)
			}
		})
	}
}

// AttributionStatements must surface the recovered candidate as its own
// statement (use 1 of 2 — see InterpreterHeredocExecStatements' doc
// comment), distinct from the original heredoc statement.
func TestAttributionStatements_IncludesInterpreterExecCandidate(t *testing.T) {
	cmd := "python3 - <<'PY'\nimport os\nos.system('csrutil disable')\nPY"
	stmts, parsed := AttributionStatements(cmd)
	if !parsed {
		t.Fatal("expected the heredoc command to parse")
	}
	if !slices.Contains(stmts, "csrutil disable") {
		t.Errorf("AttributionStatements(%q) = %v, want to contain the recovered candidate \"csrutil disable\"", cmd, stmts)
	}
	// The candidate must not itself classify as an interpreter heredoc —
	// that is the whole point (it contains no "<<").
	c := NewIntentClassifier()
	if got := c.Classify("csrutil disable"); got.InInterpreterHeredoc {
		t.Error("the recovered candidate must not classify as InInterpreterHeredoc")
	}
}

// #3755 case C: a "#" inside a string literal is data, not a comment. The
// quote-blind strip truncated the line there, destroying the closing quote
// and paren, so an allowlisted call recovered NOTHING — measured as a
// BLOCK->AUDIT bypass on ts-block-macos-sip-disable.
func TestStripHashComments_QuoteAware(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			"hash inside a single-quoted argument survives",
			`os.system('sudo csrutil disable # comment')`,
			`os.system('sudo csrutil disable # comment')`,
		},
		{
			"hash inside a double-quoted argument survives",
			`os.system("a # b")`,
			`os.system("a # b")`,
		},
		{
			"a real trailing comment is still stripped",
			`os.system('csrutil disable')  # danger`,
			`os.system('csrutil disable')  `,
		},
		{
			"a whole-line comment is still stripped",
			`# example: os.system("csrutil disable")`,
			``,
		},
		{
			"an apostrophe in comment prose does not open a string",
			`x = 1  # it's fine`,
			`x = 1  `,
		},
		{
			"escaped quote does not end the literal early",
			`os.system('a\'b # c')`,
			`os.system('a\'b # c')`,
		},
		{
			// The line is not self-contained source, so its quote state
			// says nothing; falling back to the quote-blind strip keeps
			// over-stripping (miss a call), never under-stripping.
			"unterminated literal falls back to the naive strip",
			`s = "unterminated # os.system('csrutil disable')`,
			`s = "unterminated `,
		},
		{
			"per-line, not whole-body",
			"# one\nos.system('a # b')\nprint(2)  # two",
			"\nos.system('a # b')\nprint(2)  ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripHashComments(tt.body); got != tt.want {
				t.Errorf("stripHashComments(%q) = %q, want %q", tt.body, got, tt.want)
			}
		})
	}
}

// #3755: the extractor deliberately does NOT try to tell an inert printed
// example apart from a call that executes — that distinction is Python string
// lexing, and the first cut at it (a per-line quoted-byte mask) failed OPEN
// on running code (an f-string interpolation and a call after a triple-quoted
// string both went AUDIT). So every one of these EXECUTES and MUST still have
// its command recovered; the cost is the printed-example false positive, which
// is asserted separately as an accepted FP.
func TestInterpreterHeredocExecStatements_RecoversFromExecutingForms(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{
			"plain call with a quoted argument",
			"python3 - <<'PY'\nos.system('csrutil disable')\nPY",
			"csrutil disable",
		},
		{
			// #3755 case Z — mask handled this, but pin it so a future
			// re-introduction of a mask cannot silently regress it.
			"real call after a closed single-line string",
			"python3 - <<'PY'\nx = \"note\"; os.system('csrutil disable')\nPY",
			"csrutil disable",
		},
		{
			// #3755 case X — f-string interpolation EXECUTES the call. The
			// mask masked the whole f-string and dropped it -> AUDIT bypass.
			"f-string interpolation",
			"python3 - <<'PY'\nprint(f\"{os.system('csrutil disable')}\")\nPY",
			"csrutil disable",
		},
		{
			// #3755 case Y — a real call after a triple-quoted string
			// closes. The line-local mask saw an unterminated quote and
			// masked the call -> AUDIT bypass.
			"call after a triple-quoted string closes",
			"python3 - <<'PY'\nx = \"\"\"doc\nend\"\"\"; os.system('csrutil disable')\nPY",
			"csrutil disable",
		},
		{
			"quote-aware strip lets an allowlisted call keep its # argument",
			"python3 - <<'PY'\nos.system('sudo csrutil disable # comment')\nPY",
			"sudo csrutil disable # comment",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InterpreterHeredocExecStatements(tt.cmd); !slices.Contains(got, tt.want) {
				t.Errorf("InterpreterHeredocExecStatements(%q) = %v, want to contain %q", tt.cmd, got, tt.want)
			}
		})
	}
}

// #3755 case D, stated as the accepted false positive it is: a printed
// example that only names a call still has its command recovered, because the
// extractor does not lex string context (see the RecoversFromExecutingForms
// rationale). Benign, so the end-to-end verdict is a documented FP
// (TN-MACOS-SEC-007) -- this pins the recovery that causes it, so that
// "recovers nothing here" can never be quietly reintroduced as a mask that
// would reopen the X/Y bypasses.
func TestInterpreterHeredocExecStatements_RecoversFromPrintedExample(t *testing.T) {
	cmd := "python3 - <<'PY'\nprint(\"os.system('csrutil disable')\")\nPY"
	if got := InterpreterHeredocExecStatements(cmd); !slices.Contains(got, "csrutil disable") {
		t.Errorf("InterpreterHeredocExecStatements(%q) = %v, want to contain \"csrutil disable\" (accepted FP, #3755 case D)", cmd, got)
	}
}

func TestInterpreterHeredocExecStatements_CommandSubstitution(t *testing.T) {
	// #3630-style embedding: the heredoc lives inside a command substitution
	// rather than being the top-level statement itself.
	cmd := "x=$(python3 - <<'PY'\nimport os\nos.system('csrutil disable')\nPY\n)"
	got := InterpreterHeredocExecStatements(cmd)
	if !slices.Contains(got, "csrutil disable") {
		t.Errorf("InterpreterHeredocExecStatements(%q) = %v, want to contain \"csrutil disable\" recovered from inside the command substitution", cmd, got)
	}
}
