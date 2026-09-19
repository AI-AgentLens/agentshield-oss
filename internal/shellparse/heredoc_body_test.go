package shellparse

import (
	"strings"
	"testing"
)

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

		// --- #3827: the gate inverted from allowlist to blocklist ---
		// An unrecognised sink is DATA, not evidence of execution. These are
		// the shapes that used to BLOCK purely for not being cat/tee, which
		// made filing an FP report about a rule trip that same rule.
		{
			name:    "gh --body-file - (the #3827 report shape)",
			command: "gh issue comment 1 --body-file - <<'BODY'\nquotes an attack string as prose\nBODY",
			found:   true,
		},
		{
			name:    "gh with no flags at all",
			command: "gh issue create <<'BODY'\nquotes an attack string as prose\nBODY",
			found:   true,
		},
		{
			name:    "an in-house tool nobody has heard of",
			command: "notify-team --channel ops <<'BODY'\nquotes an attack string as prose\nBODY",
			found:   true,
		},
		{
			name:    "ordinary data filters",
			command: "sort <<'BODY'\nplain data\nBODY",
			found:   true,
		},

		// --- ...but the inversion must NOT un-block these ---
		// A binding sink does not execute the body; it binds it to a name that
		// IS executed later in the same command (TP-READ-SCALAR-EXEC-001).
		// A blanket "inert unless it is an interpreter" gets these wrong.
		{
			name:    "read binds the body to a name executed later",
			command: "read zc <<'EOF'\nrm -rf /\nEOF",
		},
		{
			name:    "mapfile binds the body to an array",
			command: "mapfile -t a <<'EOF'\nrm -rf /\nEOF",
		},
		{
			name:    "readarray is mapfile's other spelling",
			command: "readarray -t a <<'EOF'\nrm -rf /\nEOF",
		},
		{
			name:    "source /dev/stdin runs the body in the current shell",
			command: "source /dev/stdin <<'EOF'\nrm -rf /\nEOF",
		},
		{
			name:    "dot is source's other spelling",
			command: ". /dev/stdin <<'EOF'\nrm -rf /\nEOF",
		},
		{
			name:    "xargs forwards the body as arguments",
			command: "xargs sh -c <<'EOF'\nrm -rf /\nEOF",
		},
		{
			name:    "exec wrappers are stripped before naming the sink",
			command: "sudo bash <<'EOF'\nrm -rf /\nEOF",
		},
		{
			name:    "git apply takes a patch, not prose",
			command: "git apply <<'EOF'\nrm -rf /\nEOF",
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

// #3730: an UNQUOTED heredoc delimiter gets the shell's normal expansion —
// command substitution, parameter expansion, arithmetic — before the body
// ever reaches cat/tee. Redacting the whole span (as the pre-fix code did)
// hides a real, executing command from every rule using this label. A live
// expansion must never be redacted or collected as an item; only genuinely
// literal text may be.
func TestHeredocBodiesUnquotedDelimiterLeavesExpansionsLive(t *testing.T) {
	t.Run("command substitution stays live and unredacted", func(t *testing.T) {
		cmd := "cat > f.txt <<EOF\n$(rm -rf /)\nEOF"
		items, redacted := HeredocBodies(cmd)
		if !containsAll(redacted, "$(rm -rf /)") {
			t.Errorf("live command substitution was redacted away: %q", redacted)
		}
		for _, it := range items {
			if containsAll(it, "rm -rf /") {
				t.Errorf("live command substitution leaked into a redacted item: %q", it)
			}
		}
	})

	t.Run("the identical body under a QUOTED delimiter is fully literal and redacted as before", func(t *testing.T) {
		cmd := "cat > f.txt <<'EOF'\n$(rm -rf /)\nEOF"
		items, redacted := HeredocBodies(cmd)
		if redacted == "" {
			t.Fatal("expected a redaction — the quoted body is inert literal text")
		}
		if containsAll(redacted, "rm -rf /") {
			t.Errorf("literal body under a quoted delimiter was not redacted: %q", redacted)
		}
		if !containsAll(strings.Join(items, ""), "rm -rf /") {
			t.Errorf("literal body text was not captured as an item: %#v", items)
		}
	})

	t.Run("literal prose is redacted, live substitution beside it is not", func(t *testing.T) {
		cmd := "cat > f.txt <<EOF\nsafe prefix $(rm -rf /) safe suffix\nEOF"
		items, redacted := HeredocBodies(cmd)
		if redacted == "" {
			t.Fatal("expected the literal spans to be redacted")
		}
		if !containsAll(redacted, "$(rm -rf /)") {
			t.Errorf("live command substitution was redacted away: %q", redacted)
		}
		if containsAll(redacted, "safe prefix") || containsAll(redacted, "safe suffix") {
			t.Errorf("literal prose survived redaction: %q", redacted)
		}
		for _, it := range items {
			if containsAll(it, "rm -rf /") {
				t.Errorf("live command substitution leaked into a redacted item: %q", it)
			}
		}
	})

	t.Run("parameter expansion stays live and unredacted", func(t *testing.T) {
		cmd := "cat > f.txt <<EOF\n${SECRET}\nEOF"
		_, redacted := HeredocBodies(cmd)
		if redacted != "" && !containsAll(redacted, "${SECRET}") {
			t.Errorf("live parameter expansion was redacted away: %q", redacted)
		}
	})

	t.Run("fully literal unquoted body still redacts as before", func(t *testing.T) {
		cmd := "cat > \"$S/notes.md\" <<EOF\n- blocks cat/tee writes to sitecustomize.py\nEOF"
		items, redacted := HeredocBodies(cmd)
		if redacted == "" {
			t.Fatal("expected a redaction — no live expansion in this body")
		}
		if !containsAll(strings.Join(items, ""), "sitecustomize.py") {
			t.Errorf("literal body text was not captured as an item: %#v", items)
		}
		if containsAll(redacted, "sitecustomize.py") {
			t.Errorf("literal body was not redacted: %q", redacted)
		}
	})
}
