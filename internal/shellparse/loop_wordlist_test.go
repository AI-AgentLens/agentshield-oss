package shellparse

import (
	"strings"
	"testing"
)

// The FP that motivated this (#3376) and the shapes immediately around it.
// Every "live" case here is a bypass someone could write in one line if the
// exclusion were keyed on word-list POSITION alone, which is what the issue
// proposed; each is therefore a guard, not a nice-to-have.
func TestInertLoopWordLists(t *testing.T) {
	tests := []struct {
		name    string
		command string
		inert   bool
		items   []string
	}{
		{
			name:    "grep needle — the reported FP",
			command: `for p in ".ssh/" "/etc/shadow"; do n=$(grep -c -- "$p" "$F"); echo "$n <= $p"; done`,
			inert:   true,
			items:   []string{`".ssh/"`, `"/etc/shadow"`},
		},
		{
			name:    "echo only",
			command: `for p in "/etc/shadow"; do echo "$p"; done`,
			inert:   true,
			items:   []string{`"/etc/shadow"`},
		},
		{
			name:    "loop variable never referenced",
			command: `for p in "/etc/shadow"; do date; done`,
			inert:   true,
			items:   []string{`"/etc/shadow"`},
		},
		{
			name:    "grep short flag cluster and unquoted needle",
			command: `for p in /etc/shadow; do grep -qF $p notes.txt; done`,
			inert:   true,
			items:   []string{`/etc/shadow`},
		},
		{
			name:    "substring expansion of the loop variable in echo",
			command: `for s in "/etc/shadow"; do echo "${s:0:50}"; done`,
			inert:   true,
			items:   []string{`"/etc/shadow"`},
		},

		// --- live: the loop variable reaches something that acts on it ---
		{
			name:    "cat reads the loop variable",
			command: `for p in /etc/shadow; do cat "$p"; done`,
		},
		{
			name:    "loop variable in executable position",
			command: `for c in /etc/shadow; do "$c"; done`,
		},
		{
			name:    "loop variable as a redirect target",
			command: `for p in /etc/shadow; do echo x > "$p"; done`,
		},
		{
			name:    "loop variable retained in an assignment",
			command: `for p in /etc/shadow; do target="$p"; done`,
		},
		{
			name:    "command substitution nested inside an echo argument",
			command: `for p in /etc/shadow; do echo "$(cat $p)"; done`,
		},
		{
			name:    "loop variable is the grep HAYSTACK, not the needle",
			command: `for p in /etc/shadow; do grep -c root "$p"; done`,
		},
		{
			name:    "grep flag that consumes the next token — operand layout unknown",
			command: `for p in /etc/shadow; do grep -m 1 "$p" notes.txt; done`,
		},
		{
			name:    "grep -f makes the operand a pattern FILE",
			command: `for p in /etc/shadow; do grep -f "$p" notes.txt; done`,
		},
		{
			name:    "test clause stats the path",
			command: `for p in /etc/shadow; do [ -f "$p" ] && echo yes; done`,
		},
		{
			name:    "unrecognised command",
			command: `for p in /etc/shadow; do shred "$p"; done`,
		},
		{
			name:    "one inert use and one live use",
			command: `for p in /etc/shadow; do echo "$p"; cat "$p"; done`,
		},

		// --- the printed value must go nowhere a command can act on it ---
		// Found by probing this fix's own blast radius: "printing is inert" is
		// only true while nothing consumes the print.
		{
			name:    "echo piped into a consumer",
			command: `for p in /etc/shadow; do echo "$p" | xargs cat; done`,
		},
		{
			name:    "the whole loop is piped into a consumer",
			command: `for p in /etc/shadow; do echo "$p"; done | xargs cat`,
		},
		{
			name:    "echo output captured into a variable",
			command: `for p in /etc/shadow; do x=$(echo "$p"); cat "$x"; done`,
		},
		{
			name:    "echo output redirected to a file",
			command: `for p in /etc/shadow; do echo "$p" >> /tmp/list; done`,
		},
		{
			name:    "grep printing matched lines into a consumer",
			command: `for p in /etc/shadow; do grep "$p" list.txt | xargs cat; done`,
		},
		{
			name:    "grep -c inside a command substitution — the reported FP shape",
			command: `for p in /etc/shadow; do n=$(grep -c -- "$p" notes.txt); echo "$n"; done`,
			inert:   true,
			items:   []string{`/etc/shadow`},
		},
		{
			name:    "grep printing to the terminal is inert",
			command: `for p in /etc/shadow; do grep -n "$p" notes.txt; done`,
			inert:   true,
			items:   []string{`/etc/shadow`},
		},
		{
			name:    "no loop at all",
			command: `cat /etc/shadow`,
		},
		{
			name:    "iteration over positional parameters has no word list",
			command: `for p; do echo "$p"; done`,
		},

		// --- agentshield mcp-eval (issue #3547) ---
		{
			name:    "agentshield mcp-eval --arg with a leading echo statement — the reported FP",
			command: `for p in "/home/user/.vault-token" "/home/user/.ssh/id_rsa"; do echo "-- $p"; agentshield mcp-eval --tool read_file --arg "path=$p"; done`,
			inert:   true,
			items:   []string{`"/home/user/.vault-token"`, `"/home/user/.ssh/id_rsa"`},
		},
		{
			name:    "agentshield mcp-eval --json, single-statement body",
			command: `for p in "/home/user/.ssh/id_rsa"; do agentshield mcp-eval --tool read_file --json "{\"path\":\"$p\"}"; done`,
			inert:   true,
			items:   []string{`"/home/user/.ssh/id_rsa"`},
		},
		{
			name:    "cat alongside mcp-eval in the same body — cat is not inert",
			command: `for p in "/home/user/.ssh/id_rsa"; do cat "$p"; agentshield mcp-eval --tool read_file --arg path=/dev/null; done`,
		},
		{
			name:    "loop variable reaches --mcp-policy, a real file argument",
			command: `for p in "/home/user/.ssh/id_rsa"; do agentshield mcp-eval --tool read_file --arg path=/dev/null --mcp-policy "$p"; done`,
		},
		{
			name:    "agentshield without the mcp-eval subcommand does not qualify",
			command: `for p in "/home/user/.ssh/id_rsa"; do agentshield scan --arg "path=$p"; done`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items, redacted := InertLoopWordLists(tt.command)
			if !tt.inert {
				if redacted != "" {
					t.Fatalf("expected no redaction (loop variable is live), got %q", redacted)
				}
				return
			}
			if redacted == "" {
				t.Fatalf("expected the word list to be inert, got no redaction")
			}
			if len(items) != len(tt.items) {
				t.Fatalf("items = %q, want %q", items, tt.items)
			}
			for i := range items {
				if items[i] != tt.items[i] {
					t.Fatalf("items = %q, want %q", items, tt.items)
				}
			}
			for _, it := range tt.items {
				unquoted := strings.Trim(it, `"'`)
				if strings.Contains(redacted, unquoted) {
					t.Fatalf("redacted text still contains %q: %q", unquoted, redacted)
				}
			}
			if !strings.Contains(redacted, LoopItemPlaceholder) {
				t.Fatalf("redacted text lost the placeholder: %q", redacted)
			}
		})
	}
}

// Redaction must leave everything OUTSIDE the word list byte-for-byte intact —
// the caller re-runs the rule against this text, so any collateral rewriting
// would silently change what matches.
func TestInertLoopWordListsPreservesTheRest(t *testing.T) {
	cmd := `cat /etc/shadow && for p in "/etc/shadow"; do echo "$p"; done`
	_, redacted := InertLoopWordLists(cmd)
	if redacted == "" {
		t.Fatal("expected a redaction")
	}
	if !strings.HasPrefix(redacted, "cat /etc/shadow && for p in ") {
		t.Fatalf("text outside the word list was rewritten: %q", redacted)
	}
	if strings.Count(redacted, "/etc/shadow") != 1 {
		t.Fatalf("expected exactly the non-loop occurrence to survive: %q", redacted)
	}
}

// A nested loop is judged on its own body: the outer list stays live because
// the outer variable is read by `cat`, while the inner one is redacted.
func TestInertLoopWordListsNested(t *testing.T) {
	cmd := `for a in /etc/shadow; do for b in /etc/master.passwd; do echo "$b"; done; cat "$a"; done`
	items, redacted := InertLoopWordLists(cmd)
	if redacted == "" {
		t.Fatal("expected the inner word list to be redacted")
	}
	if len(items) != 1 || items[0] != "/etc/master.passwd" {
		t.Fatalf("items = %q, want the inner list only", items)
	}
	if !strings.Contains(redacted, "for a in /etc/shadow") {
		t.Fatalf("outer word list must stay live: %q", redacted)
	}
}

func TestInertLoopWordListsNoOp(t *testing.T) {
	for _, cmd := range []string{
		"",
		"ls -la",
		"for p in", // unparseable
	} {
		if items, redacted := InertLoopWordLists(cmd); items != nil || redacted != "" {
			t.Errorf("InertLoopWordLists(%q) = %q, %q; want no-op", cmd, items, redacted)
		}
	}
}
