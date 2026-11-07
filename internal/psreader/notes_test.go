package psreader

import (
	"strings"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/facts"
)

func TestRead_Notes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want facts.NoteKind // "" means no note at all
	}{
		{"clean", `Get-ChildItem -Force | Where-Object Name -match 'x'`, ""},
		{"script block invoked in place", `& { Get-Process }; . { Get-Date }`, ""},
		{"unclosed single quote", `Get-Content 'abc`, facts.NoteParseError},
		{"unclosed double quote", `Write-Host "abc`, facts.NoteParseError},
		{"unclosed here-string", "$x = @'\nbody", facts.NoteParseError},
		{"unclosed block", `if ($a) { Get-Date`, facts.NoteParseError},
		{"stray bracket", `Get-Date )`, facts.NoteParseError},
		{"class body not read", `class C { [void] M() { Remove-Item x } }`, facts.NoteParseError},
		{"variable name", `& $exe --version`, facts.NoteDynamicName},
		{"expression name", `& (Get-Command git).Source status`, facts.NoteDynamicName},
		{"expandable name", `& "$dir\tool.exe" run`, facts.NoteDynamicName},
		{"dot-sourced variable", `. $PROFILE`, facts.NoteDynamicName},
	}
	for _, tc := range cases {
		f := Read(tc.in, Env{})
		if tc.want == "" {
			if len(f.Notes) != 0 {
				t.Errorf("%s: Read(%q).Notes = %+v, want none", tc.name, tc.in, f.Notes)
			}
			continue
		}
		if !hasNote(f, tc.want) {
			t.Errorf("%s: Read(%q).Notes = %+v, want a %s note", tc.name, tc.in, f.Notes, tc.want)
		}
	}
}

func TestRead_DynamicName(t *testing.T) {
	f := Read(`& $exe --version`, Env{})
	if len(f.Commands) != 1 || f.Commands[0].Name != facts.Dynamic || f.Commands[0].Written != facts.Dynamic {
		t.Fatalf("Commands = %+v, want one %s command", f.Commands, facts.Dynamic)
	}
	if len(f.Notes) != 1 || !strings.Contains(f.Notes[0].Detail, "$exe") {
		t.Fatalf("Notes = %+v, want one dynamic_name note naming $exe", f.Notes)
	}
}

// TestRead_SurvivesInternalFailure: a panic inside the reader becomes a
// parse_error note, and the stages after it still report, the raw-text path
// scan included.
func TestRead_SurvivesInternalFailure(t *testing.T) {
	in := `Get-Date; Get-Content $env:USERPROFILE\.ssh\id_rsa; Get-Item x`
	f := read(in, testEnv, 2)
	var internal bool
	for _, n := range f.Notes {
		if n.Kind == facts.NoteParseError && strings.Contains(n.Detail, "internal error in reader") {
			internal = true
		}
	}
	if !internal {
		t.Fatalf("Notes = %+v, want an internal-error parse_error", f.Notes)
	}
	if !contains(f.Mentions, "~/.ssh/id_rsa") {
		t.Errorf("Mentions = %q, want the raw scan's path despite the failure", f.Mentions)
	}
	if len(f.Commands) == 0 {
		t.Errorf("Commands empty: what was read before the failure should be kept")
	}
	// control: the same input without the forced failure reads cleanly
	if g := Read(in, testEnv); len(g.Notes) != 0 || len(g.Commands) != 3 {
		t.Errorf("control: Read = %d commands, notes %+v", len(g.Commands), g.Notes)
	}
}

// TestRead_DeepNestingEndsTheRead: nesting past maxDepth stops the reader
// with a note instead of exhausting the stack, which Go cannot recover from.
func TestRead_DeepNestingEndsTheRead(t *testing.T) {
	for _, open := range []string{"(", "{", "$(", "@(", "@{a=", "[a(", "Write-Output ,", "if(1){"} {
		in := strings.Repeat(open, 200000) + " ~\\.ssh\\id_rsa"
		if open == "Write-Output ," { // commas in argument position recurse; at statement start they are flat
			in = "Write-Output " + strings.Repeat(",", 200000) + " ~\\.ssh\\id_rsa"
		}
		start := time.Now()
		f := Read(in, Env{})
		if !hasNote(f, facts.NoteParseError) {
			t.Errorf("%q x200000: no parse_error note", open)
		}
		for _, n := range f.Notes {
			if strings.Contains(n.Detail, "internal error") {
				t.Errorf("%q x200000: %s", open, n.Detail)
			}
		}
		if !contains(f.Paths, "~/.ssh/id_rsa") && !contains(f.Mentions, "~/.ssh/id_rsa") {
			t.Errorf("%q x200000: raw scan lost the path", open)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%q x200000 took %v", open, d)
		}
	}
}

// TestRead_ExperimentHazards pins inputs the experiment reader mishandled:
// a switch body it looped on forever, and `${` / `<#` / a trailing backtick
// that moved the cursor past the end of the input.
func TestRead_ExperimentHazards(t *testing.T) {
	for _, in := range []string{
		`switch ($x) { | }`,
		`switch ($x) { a { 1 } , > }`,
		`a${b`,
		`Write-Host x${env:USERPROFILE`,
		`Get-Date <# unclosed`,
		"Get-Item x`",
		"\"abc`",
		"$(",
		"@'\n",
		"& ",
		"--%",
	} {
		done := make(chan facts.Facts, 1)
		go func() { done <- Read(in, Env{}) }()
		select {
		case f := <-done:
			for _, n := range f.Notes {
				if strings.Contains(n.Detail, "internal error") {
					t.Errorf("Read(%q): %s", in, n.Detail)
				}
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("Read(%q) did not return", in)
		}
	}
}

// A dynamic_name note quotes at most 80 characters of the computed name. A
// token cut at that limit used to leave its first part in the note, which the
// audit redactor (whole tokens only) cannot recognise. Every cut position is
// tried: the note carries the whole token or none of it.
func TestRead_DynamicNameNoteNeverEndsInATokenPrefix(t *testing.T) {
	tok := "gh" + "p_" + strings.Repeat("Ab3", 12) // assembled at runtime
	prefix := tok[:4]
	for pad := 0; pad <= 90; pad++ {
		in := "& ('" + strings.Repeat("a", pad) + " " + tok + "' + 'x') /list"
		f := Read(in, Env{})
		var seen bool
		for _, n := range f.Notes {
			if n.Kind != facts.NoteDynamicName {
				continue
			}
			seen = true
			if strings.Contains(n.Detail, prefix) && !strings.Contains(n.Detail, tok) {
				t.Errorf("pad %d: note %q carries part of the token", pad, n.Detail)
			}
		}
		if !seen {
			t.Fatalf("pad %d: Read(%q) wrote no dynamic_name note; the test would be vacuous", pad, in)
		}
	}
}

func TestClipWord(t *testing.T) {
	cases := []struct{ in, want string }{
		{"abc", "abc"},
		{"ab cdef", "ab …"},      // cut inside "cdef": the word goes
		{"abc def", "abc …"},     // cut on the space: nothing more goes
		{"('abcdef", "('…"},      // punctuation outside the token alphabet stops it
		{"abcdefgh", "…"},        // one word longer than the limit: nothing of it
		{"ab é" + "xyz", "ab …"}, // letters beyond ASCII count as word runes
	}
	for _, tc := range cases {
		if got := clipWord(tc.in, 4); got != tc.want {
			t.Errorf("clipWord(%q, 4) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
