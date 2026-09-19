package shellparse

import "testing"

// InterpHeredocBody is the interpreter counterpart of HeredocBody (#3697):
// captured only when the executable is a CodeInterpreters entry, never a
// shell, and never treated as shell source anywhere downstream — see
// ExtractInlineCode's explicit "CodeInterpreters deliberately NOT here"
// comment for the reason a python/node/ruby heredoc body must stay off that
// path.
func TestInterpHeredocBody(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{"python dash form", "python3 - <<'PY'\nimport os\nos.system('id')\nPY", "import os\nos.system('id')"},
		{"python bare form", "python3 <<'PY'\nprint(1)\nPY", "print(1)"},
		{"node", "node <<'JS'\nconsole.log(1)\nJS", "console.log(1)"},
		{"ruby", "ruby <<'RB'\nputs 1\nRB", "puts 1"},
		{"perl", "perl <<'PL'\nprint 1;\nPL", "print 1;"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := Parse(tt.cmd, 1)
			if parsed == nil || len(parsed.Segments) == 0 {
				t.Fatalf("Parse(%q) produced no segments", tt.cmd)
			}
			got := parsed.Segments[0].InterpHeredocBody
			if got != tt.want {
				t.Errorf("InterpHeredocBody = %q, want %q", got, tt.want)
			}
			// HeredocBody is the SHELL-source field — must stay empty, or a
			// caller reading the wrong field would treat interpreter source
			// as shell source and reopen the #1570/#1788/#2995 FP class.
			if parsed.Segments[0].HeredocBody != "" {
				t.Errorf("HeredocBody = %q, want empty — interpreter body must not populate the shell-source field", parsed.Segments[0].HeredocBody)
			}
		})
	}
}

// A shell heredoc must populate HeredocBody, never InterpHeredocBody — the
// inverse of the above, pinning the IsShell/CodeInterpreters branches don't
// bleed into each other.
func TestInterpHeredocBody_ShellUnaffected(t *testing.T) {
	cmd := "bash <<'EOF'\nrm -rf /\nEOF"
	parsed := Parse(cmd, 1)
	if parsed == nil || len(parsed.Segments) == 0 {
		t.Fatalf("Parse(%q) produced no segments", cmd)
	}
	seg := parsed.Segments[0]
	if seg.HeredocBody != "rm -rf /" {
		t.Errorf("HeredocBody = %q, want %q", seg.HeredocBody, "rm -rf /")
	}
	if seg.InterpHeredocBody != "" {
		t.Errorf("InterpHeredocBody = %q, want empty for a shell heredoc", seg.InterpHeredocBody)
	}
}

// A command with no heredoc at all must leave both fields empty.
func TestInterpHeredocBody_NoHeredoc(t *testing.T) {
	parsed := Parse("python3 -c 'print(1)'", 1)
	if parsed == nil || len(parsed.Segments) == 0 {
		t.Fatalf("Parse produced no segments")
	}
	if got := parsed.Segments[0].InterpHeredocBody; got != "" {
		t.Errorf("InterpHeredocBody = %q, want empty when there is no heredoc redirect", got)
	}
}
