package shellparse

import (
	"regexp"
	"strings"
	"testing"
)

// Regression tests for issue #3055 (continuation removal itself) and its
// #3472 follow-up (removal must never touch a statement it wasn't asked to
// join — see the doc comment on JoinLineContinuations for the full story).
func TestJoinLineContinuations(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string // "" means "nothing to join / no-op"
	}{
		{"simple continuation", "dd \\\nif=/dev/zero of=/dev/sda", "dd if=/dev/zero of=/dev/sda"},
		{"continuation with re-indent", "rm \\\n  -rf /", "rm   -rf /"},
		{"single-quoted continuation is literal data", "echo 'a\\\nb'", ""},
		{"no continuation at all", "rm -rf /", ""},
		{"empty", "", ""},

		// Double-quoted strings are NOT protected — a backslash-newline there
		// is still a continuation the shell removes.
		{"double-quoted continuation is still removed", "echo \"a\\\nb\"", "echo \"ab\""},

		// Heredoc bodies are read verbatim; nothing in them is a
		// continuation, regardless of whether the delimiter was quoted.
		{"unquoted heredoc body is literal", "cat <<EOF\nline1 \\\nline2\nEOF", ""},
		{"quoted heredoc body is literal", "cat <<'EOF'\nline1 \\\nline2\nEOF", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := JoinLineContinuations(tt.cmd); got != tt.want {
				t.Errorf("JoinLineContinuations(%q) = %q, want %q", tt.cmd, got, tt.want)
			}
		})
	}
}

// TestJoinLineContinuationsPreservesOtherStatements is the fitness function
// for #3472: a continuation buried in ONE top-level statement must not alter
// so much as a byte of any OTHER statement, including the newlines that
// separate them. An earlier implementation reprinted the whole parsed file
// with the AST's single-line printer, which turned every statement-
// separating newline into "; " — collapsing an unrelated multi-statement
// script into one line an unanchored regex could bridge across.
func TestJoinLineContinuationsPreservesOtherStatements(t *testing.T) {
	cmd := "echo hi | cat\nprintf foo \\\n  bar\nls something.mcp.json"
	got := JoinLineContinuations(cmd)
	if got == "" {
		t.Fatalf("JoinLineContinuations(%q) = \"\", want a joined form (the continuation should have been removed)", cmd)
	}

	// The continuation itself must be gone.
	if strings.Contains(got, "\\\n") {
		t.Errorf("joined form still contains a raw continuation: %q", got)
	}

	// Every OTHER statement's newline must survive untouched — that is what
	// stops an unanchored `.*`-based rule from reading across statements.
	wantNewlines := strings.Count(cmd, "\n") - 1 // -1 for the one continuation removed
	if gotNewlines := strings.Count(got, "\n"); gotNewlines != wantNewlines {
		t.Errorf("joined form has %d newlines, want %d (only the continuation's own newline should be removed): %q",
			gotNewlines, wantNewlines, got)
	}

	// The two untouched statements must appear byte-for-byte as written —
	// in particular, no "; " must have been substituted for their separator.
	if !strings.Contains(got, "echo hi | cat\n") {
		t.Errorf("first statement (and its trailing newline) was altered: %q", got)
	}
	if !strings.HasSuffix(got, "\nls something.mcp.json") {
		t.Errorf("third statement (and its leading newline) was altered: %q", got)
	}
}

// TestJoinLineContinuationsNeverWidensAnUnanchoredCrossStatementMatch pins
// the exact regression from issue #3472: sc-block-mcp-config-injection's
// pattern (echo|cat|printf|tee)\s+.*[>|].*mcp\.json must not fire on the
// JOINED form of a command whose statements individually never trigger it.
func TestJoinLineContinuationsNeverWidensAnUnanchoredCrossStatementMatch(t *testing.T) {
	cmd := "echo hi | cat\nprintf foo \\\n  bar\nls something.mcp.json"
	joined := JoinLineContinuations(cmd)
	if joined == "" {
		t.Fatalf("expected a joined form for %q", cmd)
	}

	pattern := regexp.MustCompile(`(echo|cat|printf|tee)\s+.*[>|].*mcp\.json`)
	if pattern.MatchString(joined) {
		t.Errorf("joined form %q spuriously matches the cross-statement MCP-config pattern — "+
			"the continuation in statement 2 must not bridge statement 1's pipe into statement 3's path", joined)
	}
}
