package normalize

import (
	"path/filepath"
	"slices"
	"testing"
)

// #4692: a long option with an attached value (`sort --output=<file>`) is one
// option word, so the walk never read the value as a path and the write
// decided ALLOW. longOptionValuePaths splits `--name=value`; its paths are
// only added to the walk's.
func TestLongOptionAttachedValueIsAPath_4692(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(cwd, "acme", "notes.txt")
	paths := func(cmd string) []string { return NormalizeCommand(cmd, cwd).Paths }

	// Control: the spaced spelling of the same option extracts the file on main.
	if got := paths("sort -o " + f + " README.md"); !slices.Contains(got, f) {
		t.Fatalf("control: paths %v; want %s", got, f)
	}

	for _, cmd := range []string{
		"sort --output=" + f + " README.md",
		"sort README.md --output=" + f,
		`sort --output="` + f + `" README.md`,
		"/usr/bin/sort --output=" + f + " README.md",
		"sudo sort --output=" + f + " README.md",
		"tool --log-file=" + f,
		"tool --config=" + f + " run",
		"cat README.md | tool --file=" + f,
	} {
		if got := paths(cmd); !slices.Contains(got, f) {
			t.Errorf("%q: paths %v; want %s", cmd, got, f)
		}
	}

	// Prose, words after `--`, and a nested interpreter body are not read.
	for _, cmd := range []string{
		`git commit --message=` + f,
		`git commit --message="` + f + `"`,
		"tool -- --output=" + f,
		`bash -c 'sort --output=` + f + `'`,
		"sort --output= README.md",
		"sort --output=notes README.md --flag=a=b",
	} {
		if got := paths(cmd); slices.Contains(got, f) {
			t.Errorf("%q: paths %v; %s is not a file this command names", cmd, got, f)
		}
	}
}

// longOptionValuePaths' own truth table, and the only-adds property.
func TestLongOptionValuePaths_4692(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	text := map[string]bool{"--message": true}
	for _, tc := range []struct {
		words []string
		want  []string
	}{
		{[]string{"--output=/a/b"}, []string{"/a/b"}},
		{[]string{"--output=/a/b", "--log=/c/d"}, []string{"/a/b", "/c/d"}},
		{[]string{"--message=/a/b"}, nil},
		{[]string{"--output", "/a/b"}, nil},
		{[]string{"-o=/a/b"}, nil},
		{[]string{"--output="}, nil},
		{[]string{"--", "--output=/a/b"}, nil},
		// A bare value is kept only for a reader whose bare operands are
		// (#4673); an unknown tool's `--level=3` is not a path.
	} {
		got := longOptionValuePaths(tc.words, text, cwd, "/home/u", "sort", false)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%q: got %v, want %v", tc.words, got, tc.want)
		}
	}
	if got := longOptionValuePaths([]string{"--level=3"}, text, cwd, "/home/u", "tool", false); len(got) != 0 {
		t.Errorf("--level=3 on an unknown tool: got %v, want none", got)
	}
}
