package normalize

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// #4689: the walk's universal -m text flag (meant for `git commit -m`) hid the
// file operands of every reader whose own -m is something else. Two
// additions, both only appended to the walk's paths:
//   - wc, sort, less and pr take -m as a switch, so switchOptionOperandPaths
//     reads their operands with every option a switch;
//   - a path-qualified grep (`/usr/bin/grep`) had no spec, because lookupSpec
//     reads the exact word, so the grep-family readings now fall back to the
//     basename's spec.
func TestMFlagReadersLeaveFileOperands_4689(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	acme := filepath.Join(cwd, "acme")
	if err := os.MkdirAll(acme, 0o700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(acme, "notes.txt")
	g := filepath.Join(acme, "other.txt")
	for _, p := range []string{f, g, filepath.Join(cwd, "README.md")} {
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	paths := func(cmd string) []string { return NormalizeCommand(cmd, cwd).Paths }

	// Controls, main's reading: without -m the walk extracts the file.
	for _, cmd := range []string{"wc " + shellPath(f), "sort " + shellPath(f) + " " + shellPath(g), "less " + shellPath(f), "pr " + shellPath(f) + " " + shellPath(g), "/usr/bin/grep KEY " + shellPath(f)} {
		if got := paths(cmd); !slices.Contains(got, f) {
			t.Fatalf("control %q: paths %v; want %s", cmd, got, f)
		}
	}

	for _, cmd := range []string{
		"wc -m " + shellPath(f),
		"wc -lm " + shellPath(f), // an m in a cluster set the text state too
		"wc -m -l " + shellPath(f),
		"wc -m -- " + shellPath(f),
		"/usr/bin/wc -m " + shellPath(f),
		"sort -m " + shellPath(f) + " " + shellPath(g),
		"sort -m " + shellPath(g) + " " + shellPath(f),
		"sort -m -o out.txt " + shellPath(f) + " " + shellPath(g),
		"less -m " + shellPath(f),
		"pr -m " + shellPath(f) + " " + shellPath(g),
		"cat README.md | wc -m " + shellPath(f),
		"sudo wc -m " + shellPath(f),
		"/usr/bin/grep -m 1 KEY " + shellPath(f),
		"/usr/bin/grep -e KEY " + shellPath(f),
		"/usr/bin/grep -m1 -e KEY " + shellPath(f),
		"/usr/bin/egrep -m 1 KEY " + shellPath(f),
		"/opt/homebrew/bin/rg -m 1 KEY " + shellPath(f),
	} {
		if got := paths(cmd); !slices.Contains(got, f) {
			t.Errorf("%q: paths %v; want %s", cmd, got, f)
		}
	}

	// A message is text, and a basename-spec grep reads its pattern as the
	// pattern. (The walk itself still has no spec for /usr/bin/grep, so
	// `/usr/bin/grep -e <f> README.md` keeps main's over-match.)
	for _, cmd := range []string{
		`git commit -m "` + shellPath(f) + `"`,
		"git commit -m " + shellPath(f),
		`hg commit -m "` + shellPath(f) + `"`,
		"wc -m README.md",
		"sort -m README.md",
		"/usr/bin/grep -m 1 " + shellPath(f) + " README.md",
		"/usr/bin/grep -m1 " + shellPath(f) + " README.md",
	} {
		if got := paths(cmd); slices.Contains(got, f) {
			t.Errorf("%q: paths %v; %s is not a file this command reads", cmd, got, f)
		}
	}

	// grep under another name (ggrep, the z/bz/xz/zstd wrappers) gets grep's
	// readings through grepReadingAliases; the pattern stays a pattern.
	for _, cmd := range []string{
		"ggrep -m 1 KEY " + shellPath(f),
		"zgrep -m 1 KEY " + shellPath(f),
		"zegrep -m1 KEY " + shellPath(f),
		"zfgrep -m 1 KEY " + shellPath(f),
		"bzgrep -m 1 KEY " + shellPath(f),
		"xzgrep -m 1 KEY " + shellPath(f),
		"zstdgrep -m 1 KEY " + shellPath(f),
		"ggrep -e KEY " + shellPath(f),
		"zgrep -e KEY " + shellPath(f),
		"/usr/bin/zgrep -m 1 KEY " + shellPath(f),
		"sudo zgrep -m 1 KEY " + shellPath(f),
	} {
		if got := paths(cmd); !slices.Contains(got, f) {
			t.Errorf("%q: paths %v; want %s", cmd, got, f)
		}
	}
	for _, cmd := range []string{
		"ggrep -m 1 " + shellPath(f) + " README.md",
		"zgrep -m 1 " + shellPath(f) + " README.md",
		"xzgrep -m1 " + shellPath(f) + " README.md",
	} {
		if got := paths(cmd); slices.Contains(got, f) {
			t.Errorf("%q: paths %v; %s is the pattern, not a file", cmd, got, f)
		}
	}

	// ag and ack, whose option sets are not grep's, have their own reading
	// (TestAgAckMFlagLeavesFileOperands_4689).
	for _, cmd := range []string{"ag -m 1 KEY " + shellPath(f), "ack -m 1 KEY " + shellPath(f)} {
		if got := paths(cmd); !slices.Contains(got, f) {
			t.Errorf("%q: paths %v; want %s", cmd, got, f)
		}
	}
}

// ls, zip, install and mkdir share the collision (#4689 comment from the #4716
// lane): the file operand after -m was hidden. The mode word install and mkdir
// take is not a path, and a message-style -m elsewhere stays text.
func TestMFlagCommandsLeaveFileOperands_4689(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(cwd, "acme", "notes.txt")
	for _, cmd := range []string{
		"ls " + shellPath(f), // control: no -m
		"ls -m " + shellPath(f),
		"zip -m out.zip " + shellPath(f),
		"install -m 600 " + shellPath(f) + " /tmp/x",
		"mkdir -m 700 " + shellPath(f) + "/new",
		"/bin/ls -m " + shellPath(f),
		"sudo install -m 600 " + shellPath(f) + " /tmp/x",
	} {
		if got := NormalizeCommand(cmd, cwd).Paths; !slices.ContainsFunc(got, func(p string) bool { return strings.HasPrefix(p, f) }) {
			t.Errorf("%q: paths %v; want %s", cmd, got, f)
		}
	}
	for _, cmd := range []string{
		`git commit -m "` + shellPath(f) + `"`,
		"install -m 600 README.md /tmp/x",
	} {
		if got := NormalizeCommand(cmd, cwd).Paths; slices.Contains(got, f) {
			t.Errorf("%q: paths %v; %s is not a file this command names", cmd, got, f)
		}
	}
}

// The readings only add: everything the walk extracted stays extracted, and a
// path appears once per segment.
func TestMFlagReadersReadingOnlyAdds_4689(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(cwd, "notes.txt")
	if err := os.WriteFile(f, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{
		"wc " + shellPath(f),
		"wc -l " + shellPath(f),
		"sort -t , -k 2 " + shellPath(f),
		"sort -o " + shellPath(f) + " -m README.md", // -o names the output file
		"sort -m -o " + shellPath(f) + " README.md",
		"pr -h HDR " + shellPath(f),
		"wc -m " + shellPath(f) + " && wc " + shellPath(f), // two segments, each read on its own
		"wc -m " + shellPath(f) + " | sort -m " + shellPath(f),
		"/usr/bin/grep " + shellPath(f) + " README.md", // no spec for the walk: it reads the pattern as a path, as on main
		"/usr/bin/grep -A 3 " + shellPath(f) + " README.md",
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
		if n > 2 {
			t.Errorf("%q: paths %v; %s appears %d times", cmd, got, f, n)
		}
	}
}

// switchOptionOperandPaths' own truth table.
func TestSwitchOptionOperandPaths_4689(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		words []string
		want  []string
	}{
		{[]string{"-m", "/a/b"}, []string{"/a/b"}},
		{[]string{"-lm", "/a/b", "/c/d"}, []string{"/a/b", "/c/d"}},
		{[]string{"-k", "2", "/a/b"}, []string{"2", "/a/b"}}, // a value is one more candidate; sort keeps an absent bare name (#4673)
		{[]string{"--", "-x", "/a/b"}, []string{"/a/b"}},
		{[]string{"-", "/a/b"}, []string{"/a/b"}},
		{[]string{"--merge", "--output=/o/p", "/a/b"}, []string{"/a/b"}},
		{[]string{"-m"}, nil},
	} {
		got := switchOptionOperandPaths(absWords(tc.words), cwd, "/home/u", "sort", false)
		if want := absWant(tc.want); !slices.Equal(got, want) {
			t.Errorf("%q: got %v, want %v", tc.words, got, want)
		}
	}
}
