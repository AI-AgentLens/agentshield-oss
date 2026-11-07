package normalize

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// #4676: when an option supplies a grep-family pattern (-e, --regexp, -f,
// --file), the tool reads no positional pattern, so every positional word is
// a file. The walk kept -e's text state on after its value and read the first
// file as the pattern, so `grep -e KEY <file>` extracted nothing while
// `grep KEY <file>` extracted the file.
func TestPatternOptionLeavesFileOperands_4676(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	acme := filepath.Join(cwd, "acme")
	if err := os.MkdirAll(acme, 0o700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(acme, "notes.txt")
	for _, p := range []string{f, filepath.Join(cwd, "pats"), filepath.Join(cwd, "README.md")} {
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	paths := func(cmd string) []string { return NormalizeCommand(cmd, cwd).Paths }

	// Control, main's reading: the positional pattern, then the file.
	if got := paths("grep KEY " + f); !slices.Contains(got, f) {
		t.Fatalf("control grep KEY <file>: paths %v; want %s", got, f)
	}

	for _, cmd := range []string{
		"grep -e KEY " + f,
		"grep -e KEY -n " + f,
		"grep --regexp=KEY " + f,
		"grep --regexp KEY " + f,
		"grep --reg=KEY " + f, // getopt_long's unique prefix
		"grep -eKEY " + f,
		"grep -ie KEY " + f,
		"grep -ieKEY " + f,
		"grep -e A -e B " + f,
		"grep -f pats -e X " + f,
		"grep --file=pats " + f,
		"grep -e -n " + f, // -e takes "-n" as the pattern
		"grep -e KEY -- " + f,
		"grep " + f + " -e KEY", // getopt permutes: the option still applies
		"egrep -e KEY " + f,
		"fgrep -e KEY " + f,
		"rg -e KEY " + f,
		"rg --regexp KEY " + f,
		"rg -tpy -e KEY " + f,
		"sudo grep -e KEY " + f,
		"cat pats | grep -e KEY " + f,
	} {
		if got := paths(cmd); !slices.Contains(got, f) {
			t.Errorf("%q: paths %v; want %s", cmd, got, f)
		}
	}
	if got := paths("grep -rn -e KEY " + acme); !slices.Contains(got, acme) {
		t.Errorf("grep -rn -e KEY <dir>: paths %v; want %s", got, acme)
	}

	// The -f value names a file the tool opens and reads.
	if got := paths("grep -f " + f + " README.md"); !slices.Contains(got, f) {
		t.Errorf("grep -f <file> README.md: paths %v; want the pattern file %s", got, f)
	}
	if got := paths("grep --file " + f + " README.md"); !slices.Contains(got, f) {
		t.Errorf("grep --file <file> README.md: paths %v; want the pattern file %s", got, f)
	}

	// Pattern text is never a path, wherever the pattern sits.
	for _, cmd := range []string{
		"grep -e " + f + " README.md",
		"grep -e" + f + " README.md",
		"grep --regexp=" + f + " README.md",
		"grep --regexp " + f + " README.md",
		"grep -ie " + f + " README.md",
		"grep -e 'see " + f + "' README.md",
		"echo x | grep -e " + f,
		"grep " + f + " README.md",        // positional pattern: main's reading
		"rg -tconf " + f + " README.md",   // -t takes "conf": no -f here
		"rg -telixir " + f + " README.md", // -t takes "elixir": no -e here
		"grep -A3e " + f + " README.md",   // -A takes "3e"
		"ag -f " + f + " README.md",       // ag: -f is --follow
	} {
		if got := paths(cmd); slices.Contains(got, f) {
			t.Errorf("%q: paths %v; %s is the pattern, not a file", cmd, got, f)
		}
	}

	// Commands outside the grep family keep main's reading.
	if got := paths("echo -e KEY " + f); slices.Contains(got, f) {
		t.Errorf("echo -e: paths %v; echo's words are text", got)
	}
}

// The reading names each path once: a file the walk already extracted is not
// appended again.
func TestPatternOptionReadingAddsNoDuplicates_4676(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(cwd, "notes.txt")
	if err := os.WriteFile(f, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The walk reads `pats` as the positional pattern and f as a file; the
	// second reading finds f again.
	got := NormalizeCommand("grep -f pats "+f, cwd).Paths
	n := 0
	for _, p := range got {
		if p == f {
			n++
		}
	}
	if n != 1 {
		t.Errorf("paths %v: %s appears %d times, want 1", got, f, n)
	}
}

func TestPatternOption_4676(t *testing.T) {
	for _, tc := range []struct {
		word     string
		opts     *PatternOptions
		letter   byte
		value    string
		attached bool
	}{
		{"-e", grepPatternOptions, 'e', "", false},
		{"-eKEY", grepPatternOptions, 'e', "KEY", true},
		{"-rne", grepPatternOptions, 'e', "", false},
		{"-rneKEY", grepPatternOptions, 'e', "KEY", true},
		{"-f", grepPatternOptions, 'f', "", false},
		{"-fpats", grepPatternOptions, 'f', "pats", true},
		{"--regexp", grepPatternOptions, 'e', "", false},
		{"--regexp=KEY", grepPatternOptions, 'e', "KEY", true},
		{"--rege=KEY", grepPatternOptions, 'e', "KEY", true},
		{"--file=pats", grepPatternOptions, 'f', "pats", true},
		{"--file", grepPatternOptions, 'f', "", false},
		{"-n", grepPatternOptions, 0, "", false},
		{"-A3e", grepPatternOptions, 0, "", false},
		{"-m1e", grepPatternOptions, 0, "", false},
		{"--re=KEY", grepPatternOptions, 0, "", false}, // also --recursive
		{"--fi=pats", grepPatternOptions, 0, "", false},
		{"--files-with-matches", grepPatternOptions, 0, "", false},
		{"--exclude=*.env", grepPatternOptions, 0, "", false},
		{"-g*.env", rgPatternOptions, 0, "", false},
		{"-tconf", rgPatternOptions, 0, "", false},
		{"-Ee", grepPatternOptions, 'e', "", false}, // grep -E is a switch
		{"-Ee", rgPatternOptions, 0, "", false},     // rg -E takes an encoding
		{"-", grepPatternOptions, 0, "", false},
	} {
		letter, value, attached := patternOption(tc.word, tc.opts)
		if letter != tc.letter || value != tc.value || attached != tc.attached {
			t.Errorf("patternOption(%q) = %q %q %v; want %q %q %v", tc.word, letter, value, attached, tc.letter, tc.value, tc.attached)
		}
	}
}
