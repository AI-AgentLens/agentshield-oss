package shellparse

import "testing"

// TestPrivilegeCarrierInlineCode pins the payload extraction for #3223 across
// every spelling of `su`/`runuser`, including the operand layouts that shift
// Args[0] away from the code (a user positional, a bare `-`, a value-taking
// flag). CFlagArg is what makes those work; these assert it stays that way.
func TestPrivilegeCarrierInlineCode(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    string
	}{
		{"bare su -c", "su -c 'rm -rf /'", "rm -rf /"},
		{"user positional", "su root -c 'rm -rf /'", "rm -rf /"},
		{"login dash", "su - root -c 'rm -rf /'", "rm -rf /"},
		{"login flag", "su -l root -c 'rm -rf /'", "rm -rf /"},
		{"runuser value flag", "runuser -u root -c 'rm -rf /'", "rm -rf /"},
		{"runuser positional", "runuser root -c 'rm -rf /'", "rm -rf /"},
		{"double-quoted payload", `su -c "rm -rf /"`, "rm -rf /"},
		{"inner quoting preserved", `su postgres -c 'psql -c "SELECT 1"'`, `psql -c "SELECT 1"`},

		// No -c means no payload. Inventing one out of the user operand would
		// push a username through the whole pipeline as if it were a command.
		{"interactive, no -c", "su - postgres", ""},
		{"bare su", "su", ""},
		{"runuser no -c", "runuser -u root", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := Parse(tc.command, 2)
			if p == nil || len(p.Segments) == 0 {
				t.Fatalf("Parse(%q) produced no segments", tc.command)
			}
			if got := ExtractInlineCode(p.Segments[0]); got != tc.want {
				t.Errorf("ExtractInlineCode(%q) = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
}

// TestPrivilegeCarrierSubParse is the half that the leak rate actually turned
// on. Extraction alone reached only the regex layer's candidate list and left
// 12.6% leaking against a 2.4% control, because the sub-parse gate in walkStmt
// keeps its own allowlist — so the structural and semantic layers still saw one
// opaque argument. This asserts the payload becomes a real parsed Subcommand.
func TestPrivilegeCarrierSubParse(t *testing.T) {
	cases := []struct {
		command  string
		wantExec string
	}{
		{"su -c 'rm -rf /'", "rm"},
		{"su root -c 'dd if=/dev/zero of=/dev/sda'", "dd"},
		{"su - root -c 'mkfs.ext4 /dev/sda1'", "mkfs.ext4"},
		{"runuser -u root -c 'rm --recursive --force /'", "rm"},
	}

	for _, tc := range cases {
		p := Parse(tc.command, 2)
		if p == nil {
			t.Fatalf("Parse(%q) returned nil", tc.command)
		}
		if len(p.Subcommands) == 0 {
			t.Errorf("Parse(%q): no Subcommands — payload was not sub-parsed", tc.command)
			continue
		}
		sub := p.Subcommands[0]
		if len(sub.Segments) == 0 {
			t.Errorf("Parse(%q): sub-parse produced no segments", tc.command)
			continue
		}
		if got := sub.Segments[0].Executable; got != tc.wantExec {
			t.Errorf("Parse(%q) subcommand executable = %q, want %q", tc.command, got, tc.wantExec)
		}
	}

	// A carrier with no -c must not manufacture a subcommand out of its user
	// operand — the FP direction of this fix.
	if p := Parse("su - postgres", 2); p != nil && len(p.Subcommands) != 0 {
		t.Errorf("Parse(\"su - postgres\") produced %d subcommands, want 0", len(p.Subcommands))
	}
}

// TestPrivilegeCarrierFragments pins the regex layer's view. InlineCodeFragments
// has its own copy of the carrier allowlist; the two must agree or anchored
// rules go blind on exactly the commands the AST layers now see.
func TestPrivilegeCarrierFragments(t *testing.T) {
	cases := []struct {
		command string
		want    string
	}{
		{"su -c 'rm -rf /'", "rm -rf /"},
		{"runuser -u root -c 'rm -rf /'", "rm -rf /"},
	}
	for _, tc := range cases {
		frags := InlineCodeFragments(tc.command)
		found := false
		for _, f := range frags {
			if f == tc.want {
				found = true
			}
		}
		if !found {
			t.Errorf("InlineCodeFragments(%q) = %v, want it to contain %q", tc.command, frags, tc.want)
		}
	}
	if frags := InlineCodeFragments("su - postgres"); len(frags) != 0 {
		t.Errorf("InlineCodeFragments(\"su - postgres\") = %v, want none", frags)
	}
}
