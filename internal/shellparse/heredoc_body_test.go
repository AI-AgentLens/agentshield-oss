package shellparse

import "testing"

// The FP that motivated this (#3397): a heredoc body that merely NAMES a
// sensitive filename in prose, written to an unrelated file.
func TestHeredocBodies(t *testing.T) {
	tests := []struct {
		name    string
		command string
		found   bool
		items   []string
	}{
		{
			name:    "cat heredoc body — the reported FP shape",
			command: "cat > \"$S/notes.md\" <<'EOF'\ndescribes sitecustomize.py\nEOF",
			found:   true,
		},
		{
			name:    "tee heredoc body",
			command: "tee /tmp/notes.txt <<'EOF'\nsome text\nEOF",
			found:   true,
		},
		{
			name:    "unquoted delimiter",
			command: "cat > f.txt <<EOF\nbody text\nEOF",
			found:   true,
		},
		{
			name:    "dash form strips leading tabs before the terminator",
			command: "cat > f.txt <<-EOF\n\tindented body\n\tEOF",
			found:   true,
		},
		{
			name:    "two independent heredocs",
			command: "cat > a <<'EOF'\nbody one\nEOF\ncat > b <<'EOF'\nbody two\nEOF",
			found:   true,
		},

		// --- not redacted: consumer interprets the body as code ---
		{
			name:    "bash heredoc — body IS shell, must stay live",
			command: "bash <<'EOF'\nrm -rf /\nEOF",
		},
		{
			name:    "python3 heredoc — body is source, not cat/tee data",
			command: "python3 <<'EOF'\nimport os\nEOF",
		},
		{
			name:    "eval heredoc",
			command: "eval <<'EOF'\nrm -rf /\nEOF",
		},

		// --- git commit -F - reading the message from stdin (#3493) ---
		{
			name:    "git commit -F - heredoc — the reported FP shape",
			command: "git commit -q -F - <<'EOF'\ndescribes ts-block-mcp-socket-hijack: socat/nc binding /tmp/mcp-x.sock\nEOF",
			found:   true,
		},
		{
			name:    "git commit --file - (long flag, space form)",
			command: "git commit --file - <<'EOF'\nnc /tmp/mcp-agent.sock\nEOF",
			found:   true,
		},
		{
			name:    "git commit --file=- (long flag, equals form)",
			command: "git commit --file=- <<'EOF'\nnc /tmp/mcp-agent.sock\nEOF",
			found:   true,
		},
		{
			name:    "git commit -F- (short flag, smushed form)",
			command: "git commit -F- <<'EOF'\nnc /tmp/mcp-agent.sock\nEOF",
			found:   true,
		},

		// --- not redacted: git shapes that don't read the message from stdin ---
		{
			name:    "git commit -F pointing at a real file, not stdin",
			command: "git commit -F somefile.txt <<'EOF'\nnc /tmp/mcp-agent.sock\nEOF",
		},
		{
			name:    "git apply — heredoc body is a patch, not prose",
			command: "git apply <<'EOF'\nnc /tmp/mcp-agent.sock\nEOF",
		},
		{
			name:    "git commit -m — no heredoc involved at all",
			command: "git commit -m 'nc /tmp/mcp-agent.sock'",
		},

		// --- not redacted: no heredoc at all ---
		{
			name:    "plain cat, no heredoc",
			command: "cat sitecustomize.py",
		},
		{
			name:    "no heredoc operator anywhere",
			command: "ls -la /tmp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items, redacted := HeredocBodies(tt.command)
			if tt.found {
				if redacted == "" {
					t.Fatalf("expected a redaction, got none")
				}
				if len(items) == 0 {
					t.Fatalf("expected at least one item, got none")
				}
				if redacted == tt.command {
					t.Errorf("redacted command unchanged: %q", redacted)
				}
			} else if redacted != "" || items != nil {
				t.Fatalf("expected no-op sentinel, got items=%#v redacted=%q", items, redacted)
			}
		})
	}
}

// The real write target of a `cat > FILE <<EOF` heredoc sits on the command
// line, before the body starts — it must never be swallowed into the
// redacted span, or a genuine `cat > sitecustomize.py <<EOF … EOF` write
// would lose its own evidence.
func TestHeredocBodiesNeverRedactsWriteTarget(t *testing.T) {
	items, redacted := HeredocBodies("cat > sitecustomize.py <<'EOF'\nimport os\nEOF")
	if redacted == "" {
		t.Fatal("expected a redaction of the body")
	}
	if !containsAll(redacted, "sitecustomize.py") {
		t.Errorf("write target was redacted away: %q", redacted)
	}
	for _, it := range items {
		if containsAll(it, "sitecustomize.py") {
			t.Errorf("write target leaked into a redacted item: %q", it)
		}
	}
}

// A heredoc piped into a second command (`cat <<EOF | tee FILE`) writes the
// body content into FILE — the tee argument is the real target and lives
// outside the heredoc body span, so it must survive redaction untouched.
func TestHeredocBodiesNeverRedactsPipeTarget(t *testing.T) {
	items, redacted := HeredocBodies("cat <<'EOF' | tee sitecustomize.py\nimport os\nEOF")
	if redacted == "" {
		t.Fatal("expected a redaction of the body")
	}
	if !containsAll(redacted, "sitecustomize.py") {
		t.Errorf("pipe target was redacted away: %q", redacted)
	}
	for _, it := range items {
		if containsAll(it, "sitecustomize.py") {
			t.Errorf("pipe target leaked into a redacted item: %q", it)
		}
	}
}

func TestHeredocBodiesNoOp(t *testing.T) {
	items, redacted := HeredocBodies("ls -la /tmp")
	if items != nil || redacted != "" {
		t.Fatalf("expected no-op sentinel, got items=%#v redacted=%q", items, redacted)
	}
}
