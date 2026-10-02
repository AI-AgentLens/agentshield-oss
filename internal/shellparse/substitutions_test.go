package shellparse

import (
	"reflect"
	"testing"
)

// TestParse_Substitutions pins the ParsedCommand.Substitutions contract
// (#4051 Codex pass 1): every command/process substitution at any depth,
// in walk order, with its body text sliced exactly and the redirects of its
// command-less statements. normalize's substitution path extraction reads
// this list; its fallback tokenizer reads Body, so an off-by-one in the slice
// would silently change what it sees.
func TestParse_Substitutions(t *testing.T) {
	tests := []struct {
		name       string
		cmd        string
		wantBodies []string
		wantExes   []string // first segment's Executable per substitution ("" = none)
	}{
		{"dollar-paren", `echo $(cat a)`, []string{"cat a"}, []string{"cat"}},
		{"backquote", "echo `cat a`", []string{"cat a"}, []string{"cat"}},
		{"input process substitution", `diff <(ls b) x`, []string{"ls b"}, []string{"ls"}},
		{"output process substitution", `echo > >(wc c)`, []string{"wc c"}, []string{"wc"}},
		{"nested, outer first", `echo $(echo $(cat a))`, []string{"echo $(cat a)", "cat a"}, []string{"echo", "cat"}},
		// Inside backquotes the nested substitution's escapes stay in the
		// outer body's text; the parse itself reads them as nesting.
		{"escaped backquote nested in backquotes", "echo `echo \\`cat a\\``", []string{"echo \\`cat a\\`", "cat a\\"}, []string{"echo", "cat"}},
		{"zero-segment body", `echo $(<f)`, []string{"<f"}, []string{""}},
		{"surrounding blanks trimmed", `echo $(  cat a  )`, []string{"cat a"}, []string{"cat"}},
		{"empty substitution is not one", `echo $()`, nil, nil},
		{"single-quoted is literal", `echo '$(cat a)'`, nil, nil},
		{"arithmetic expansion is not a substitution", `echo $((1+2))`, nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pc := Parse(tc.cmd, 2)
			var bodies, exes []string
			for _, s := range pc.Substitutions {
				if s.Parsed == nil {
					t.Fatalf("Substitution.Parsed is nil for %q", tc.cmd)
				}
				bodies = append(bodies, s.Body)
				exe := ""
				if len(s.Parsed.Segments) > 0 {
					exe = s.Parsed.Segments[0].Executable
				}
				exes = append(exes, exe)
			}
			if !reflect.DeepEqual(bodies, tc.wantBodies) {
				t.Errorf("bodies = %q, want %q", bodies, tc.wantBodies)
			}
			if !reflect.DeepEqual(exes, tc.wantExes) {
				t.Errorf("executables = %q, want %q", exes, tc.wantExes)
			}
		})
	}
}

// TestParse_SubstitutionsBareRedirects: `$(<file)` is a statement with no
// command, so the segment walk drops it; its redirect is kept here.
func TestParse_SubstitutionsBareRedirects(t *testing.T) {
	pc := Parse(`K=$(<f) && echo $(cat <g)`, 2)
	if len(pc.Substitutions) != 2 {
		t.Fatalf("got %d substitutions, want 2", len(pc.Substitutions))
	}
	if got, want := pc.Substitutions[0].BareRedirects, []Redirect{{Op: "<", Path: "f"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("bare redirects of $(<f) = %v, want %v", got, want)
	}
	// A redirect on a statement that HAS a command belongs to its segment,
	// not to BareRedirects.
	if got := pc.Substitutions[1].BareRedirects; len(got) != 0 {
		t.Errorf("bare redirects of $(cat <g) = %v, want none", got)
	}
}

// TestParse_SubstitutionsLeaveSubcommandsUnchanged: Substitutions is a view
// added for normalize; every other consumer reads Subcommands, which must be
// built exactly as before — a zero-segment substitution is still dropped
// there, and a `bash -c` body is still a Subcommand but never a Substitution.
func TestParse_SubstitutionsLeaveSubcommandsUnchanged(t *testing.T) {
	cases := []struct {
		cmd               string
		wantSubcommands   int
		wantSubstitutions int
	}{
		{`echo $(<f)`, 0, 1},
		{`echo $(cat a)`, 1, 1},
		{`bash -c 'cat a'`, 1, 0},
		{`echo $(bash -c 'cat a')`, 1, 1},
	}
	for _, tc := range cases {
		pc := Parse(tc.cmd, 2)
		if len(pc.Subcommands) != tc.wantSubcommands || len(pc.Substitutions) != tc.wantSubstitutions {
			t.Errorf("%q: %d subcommands / %d substitutions, want %d / %d",
				tc.cmd, len(pc.Subcommands), len(pc.Substitutions), tc.wantSubcommands, tc.wantSubstitutions)
		}
	}
}
