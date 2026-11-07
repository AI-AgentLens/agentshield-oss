package normalize

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// #4682: grep's max-count -m is the walk's universal -m text flag (meant for
// `git commit -m`), whose state lasts until the next option word, so
// `grep -m 1 KEY <file>` extracted nothing while `grep KEY <file>` extracted
// the file. grepOperandPaths reads the argv as getopt does, with the tool's
// value-taking options, and adds what it finds to the walk's paths.
func TestGrepValueOptionLeavesFileOperands_4682(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	acme := filepath.Join(cwd, "acme")
	if err := os.MkdirAll(acme, 0o700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(acme, "notes.txt")
	for _, p := range []string{f, filepath.Join(cwd, "README.md")} {
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
		"grep -m 1 KEY " + f,
		"grep -m1 KEY " + f,
		"grep -m 1 KEY -n " + f, // -n ends the text state; the walk then read the file as the pattern
		"grep -n -m 1 KEY " + f,
		"grep -m 1 -A 2 KEY " + f,
		"grep -m 1 --exclude '*.md' KEY " + f,
		"grep -m 1 KEY README.md " + f,
		"grep -m 1 KEY - " + f, // a lone - is stdin, a positional
		"grep --max-count 1 KEY " + f,
		"grep --max-count=1 KEY " + f,
		"grep -A 3 KEY " + f,
		"grep -C2 KEY " + f,
		"grep -m 1 -e KEY " + f,
		"grep -Dread KEY " + f, // -D takes "read"; the walk saw an e in the cluster
		"grep -Xm1 KEY " + f,   // BSD -X is --xz, a switch
		"grep -- -KEY " + f,    // after --, -KEY is the pattern
		"egrep -m 1 KEY " + f,
		"fgrep -m1 KEY " + f,
		"rg -m 1 KEY " + f,
		"rg -m1 KEY " + f,
		"rg --max-count 1 KEY " + f,
		"rg -m 1 -g '*.txt' KEY " + f,
		"rg --color never -m 1 KEY " + f,
		"sudo grep -m 1 KEY " + f,
		"cat README.md | grep -m 1 KEY " + f,
	} {
		if got := paths(cmd); !slices.Contains(got, f) {
			t.Errorf("%q: paths %v; want %s", cmd, got, f)
		}
	}
	for _, cmd := range []string{"grep -rnm 5 KEY " + acme, "grep -rnm5 KEY " + acme, "grep -rn -m 5 KEY " + acme} {
		if got := paths(cmd); !slices.Contains(got, acme) {
			t.Errorf("%q: paths %v; want %s", cmd, got, acme)
		}
	}

	// An option's value and the pattern are never read as a file by this
	// reading.
	for _, cmd := range []string{
		"grep --exclude " + f + " KEY README.md",
		"grep -m 1 --exclude " + f + " KEY README.md",
		"grep --exclude=" + f + " KEY README.md",
		"grep -m 1 --label " + f + " KEY README.md",
		"grep " + f + " README.md", // positional pattern: main's reading
		"grep -m 1 " + f + " README.md",
		"grep -m1 " + f + " README.md",
		"grep -rnm 5 " + f + " README.md",
		"grep -m 1 KEY README.md",
		"echo x | grep -m 1 KEY",
		"echo x | grep -m 1 " + f,
		"rg -m 1 " + f + " README.md",
		"rg -m 1 -g " + f + " KEY README.md",
	} {
		if got := paths(cmd); slices.Contains(got, f) {
			t.Errorf("%q: paths %v; %s is not a file this command searches", cmd, got, f)
		}
	}

	// Commands outside the grep family keep main's reading.
	if got := paths("git commit -m 1 " + f); slices.Contains(got, f) {
		t.Errorf("git commit -m: paths %v; the message is text", got)
	}
	// ag is not in the grep family: its own reading reads its file (#4689).
	if got := paths("ag -m 1 KEY " + f); !slices.Contains(got, f) {
		t.Errorf("ag -m: paths %v; want %s (searchToolOperandPaths, #4689)", got, f)
	}
}

// The readings are added to the walk's paths, never replacing them: words the
// walk or #4676's reading extracted stay extracted, even where this reading
// calls them an option's value.
func TestGrepValueOptionReadingOnlyAdds_4682(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(cwd, "notes.txt")
	if err := os.WriteFile(f, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{
		"grep -A 3 " + f + " README.md",              // the walk reads 3 as the pattern
		"grep -e KEY --exclude " + f + " README.md",  // #4676's reading reads option values as files
		"grep --context 3 KEY " + f,                  // --context is a switch in this reading too
		"grep --max 1 " + f + " README.md",           // a unique prefix is read as a switch
		"rg --color never " + f + " README.md",       // the walk reads never as the pattern
		"grep -m 1 KEY " + f + " && grep KEY " + f,   // two segments, each read on its own
		"grep -f " + f + " README.md",                // a pattern file is read
		"grep -m 1 -f " + f + " README.md",           // ... after a value option too
		"grep -e KEY -m 1 " + f,                      // closed by #4676
		"grep -m 1 KEY " + f + " | grep -m 1 x " + f, // pipeline
	} {
		got := NormalizeCommand(cmd, cwd).Paths
		if !slices.Contains(got, f) {
			t.Errorf("%q: paths %v; want %s", cmd, got, f)
		}
		n := 0
		for _, p := range got {
			if p == f {
				n++
			}
		}
		if n > 2 { // at most once per segment
			t.Errorf("%q: paths %v; %s appears %d times", cmd, got, f, n)
		}
	}
}

func TestGrepOptionWord_4682(t *testing.T) {
	for _, tc := range []struct {
		word     string
		opts     *PatternOptions
		letter   byte
		value    string
		takes    bool
		attached bool
	}{
		{"-m", grepPatternOptions, 'm', "", true, false},
		{"-m1", grepPatternOptions, 'm', "1", true, true},
		{"-rnm", grepPatternOptions, 'm', "", true, false},
		{"-rnm5", grepPatternOptions, 'm', "5", true, true},
		{"-A3e", grepPatternOptions, 'A', "3e", true, true},
		{"-C2", grepPatternOptions, 'C', "2", true, true},
		{"-Dread", grepPatternOptions, 'D', "read", true, true},
		{"-d", grepPatternOptions, 'd', "", true, false},
		{"-e", grepPatternOptions, 'e', "", true, false},
		{"-ieKEY", grepPatternOptions, 'e', "KEY", true, true},
		{"-f", grepPatternOptions, 'f', "", true, false},
		{"-Xm1", grepPatternOptions, 'm', "1", true, true}, // BSD -X is a switch
		{"-X", grepPatternOptions, 0, "", false, false},
		{"-rn", grepPatternOptions, 0, "", false, false},
		{"-5", grepPatternOptions, 0, "", false, false}, // -NUM is a context switch
		{"-M", grepPatternOptions, 0, "", false, false}, // BSD --lzma
		{"--max-count", grepPatternOptions, 0, "", true, false},
		{"--max-count=1", grepPatternOptions, 0, "1", true, true},
		{"--exclude", grepPatternOptions, 0, "", true, false},
		{"--exclude-dir", grepPatternOptions, 0, "", true, false},
		{"--include-dir", grepPatternOptions, 0, "", true, false}, // BSD only
		{"--group-separator", grepPatternOptions, 0, "", true, false},
		{"--label", grepPatternOptions, 0, "", true, false},
		{"--regexp", grepPatternOptions, 'e', "", true, false},
		{"--regexp=KEY", grepPatternOptions, 'e', "KEY", true, true},
		{"--file=pats", grepPatternOptions, 'f', "pats", true, true},
		{"--context", grepPatternOptions, 0, "", false, false}, // optional in BSD
		{"--context=3", grepPatternOptions, 0, "3", true, true},
		{"--color", grepPatternOptions, 0, "", false, false}, // optional in both
		{"--color=always", grepPatternOptions, 0, "always", true, true},
		{"--max", grepPatternOptions, 0, "", false, false}, // prefixes read as switches
		{"--recursive", grepPatternOptions, 0, "", false, false},
		{"-m", rgPatternOptions, 'm', "", true, false},
		{"-tconf", rgPatternOptions, 't', "conf", true, true},
		{"-M", rgPatternOptions, 'M', "", true, false}, // rg --max-columns
		{"-p", rgPatternOptions, 0, "", false, false},
		{"--color", rgPatternOptions, 0, "", true, false}, // required in rg
		{"--context", rgPatternOptions, 0, "", true, false},
		{"--glob", rgPatternOptions, 0, "", true, false},
		{"--files", rgPatternOptions, 0, "", false, false},
	} {
		letter, value, takes, attached := grepOptionWord(tc.word, tc.opts)
		if letter != tc.letter || value != tc.value || takes != tc.takes || attached != tc.attached {
			t.Errorf("grepOptionWord(%q) = %q %q %v %v; want %q %q %v %v", tc.word, letter, value, takes, attached, tc.letter, tc.value, tc.takes, tc.attached)
		}
	}
}
