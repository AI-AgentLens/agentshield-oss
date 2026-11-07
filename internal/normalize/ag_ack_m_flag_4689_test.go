package normalize

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// #4689, the ag and ack rows: their -m is max-count, so the walk's universal
// -m text flag (meant for `git commit -m`) hid their file operands, and
// `ag -m 1 KEY <file>` extracted nothing. searchToolOperandPaths reads their
// argv with the option sets measured on ag 2.2.0 and ack v3.6.0, and its
// paths are only appended to the walk's.
func TestAgAckMFlagLeavesFileOperands_4689(t *testing.T) {
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
	for _, cmd := range []string{"ag KEY " + f, "ack KEY " + f} {
		if got := paths(cmd); !slices.Contains(got, f) {
			t.Fatalf("control %q: paths %v; want %s", cmd, got, f)
		}
	}

	for _, cmd := range []string{
		"ag -m 1 KEY " + f,
		"ag -m1 KEY " + f,
		"ag -im 1 KEY " + f, // m in a cluster takes the next word
		"ag -m 1 -i KEY " + f,
		"ag --max-count 1 KEY " + f,
		"ag KEY -m 1 " + f, // getopt permutes: -m after the pattern
		"ag -m 1 KEY " + g + " " + f,
		"ag -A 3 -m 1 KEY " + f, // -A as a switch: 3 is read as the pattern
		"ag -m 1 -G notes KEY " + f,
		"ag -g notes -m 1 " + f, // -g: no pattern, every positional is a path
		"ag -ig notes -m 1 " + f,
		"ag --filename-pattern notes -m 1 " + f,
		"/opt/homebrew/bin/ag -m 1 KEY " + f,
		"sudo ag -m 1 KEY " + f,
		"cat README.md | ag -m 1 KEY " + f,
		"ack -m 1 KEY " + f,
		"ack -m1 KEY " + f,
		"ack -im 1 KEY " + f,
		"ack --max-count 1 KEY " + f,
		"ack KEY -m 1 " + f,
		"ack -t perl -m 1 KEY " + f,
		"ack --match KEY -m 1 " + f, // --match: the pattern is its value
		"ack -m 1 --match KEY " + f,
		"ack -f -m 1 " + f,     // -f lists files: no pattern
		"ag -m 1 -- -KEY " + f, // after --, -KEY is the pattern
		"ack -m 1 -- -KEY " + f,
		"/usr/bin/ack -m 1 KEY " + f,
		"sudo ack -m 1 KEY " + f,
		"cat README.md | ack -m 1 KEY " + f,
	} {
		if got := paths(cmd); !slices.Contains(got, f) {
			t.Errorf("%q: paths %v; want %s", cmd, got, f)
		}
	}

	// The pattern is text, not a file, wherever -m puts it (#3780): these
	// search README.md, or stdin, for the protected path's string.
	for _, cmd := range []string{
		"ag " + f + " README.md",
		"ag -m 1 " + f + " README.md",
		"ag -m1 " + f + " README.md",
		"ag -im 1 " + f + " README.md",
		"ag -f -m 1 " + f + " README.md", // ag: -f is --follow
		"echo x | ag -m 1 " + f,
		"ack " + f + " README.md",
		"ack -m 1 " + f + " README.md",
		"ack -m1 " + f + " README.md",
		"ack --match " + f + " -m 1 README.md",
		"ack -g -m 1 " + f + " README.md", // ack: -g is a switch, the pattern stays positional
		"echo x | ack -m 1 " + f,
	} {
		if got := paths(cmd); slices.Contains(got, f) {
			t.Errorf("%q: paths %v; %s is the pattern, not a file", cmd, got, f)
		}
	}
}

// The reading only adds: every path the walk extracted stays extracted, even
// where this reading calls the word an option's value or the pattern.
func TestAgAckReadingOnlyAdds_4689(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(cwd, "notes.txt")
	if err := os.WriteFile(f, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{
		"ag KEY " + f,
		"ag KEY -p " + f + " .",                // -p's value: the walk reads it
		"ag -A 3 " + f + " README.md",          // the walk reads 3 as the pattern
		"ag --path-to-ignore=" + f + " KEY .",  // #4692's --name=value reading
		"ack -t perl " + f + " README.md",      // the walk reads perl as the pattern
		"ag --max-count 1 " + f + " README.md", // the walk reads 1 as the pattern
		"ag -m 1 -G notes " + f + " README.md", // -G ends the walk's text state
		"ack --files-from=" + f + " KEY",
		"/opt/homebrew/bin/ag " + f + " README.md", // no spec for the walk: main's over-match
		"ag -m 1 KEY " + f + " && ag KEY " + f,
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

// searchToolOperandPaths' own truth table.
func TestSearchToolOperandPaths_4689(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		opts  *SearchToolOptions
		words []string
		want  []string
	}{
		{agOptions, []string{"-m", "1", "/p/q", "/a/b"}, []string{"/a/b"}},
		{agOptions, []string{"-m1", "/p/q", "/a/b"}, []string{"/a/b"}},
		{agOptions, []string{"-im", "1", "/p/q", "/a/b"}, []string{"/a/b"}},
		{agOptions, []string{"--max-count", "1", "/p/q", "/a/b"}, []string{"/a/b"}},
		{agOptions, []string{"--max-count=1", "/p/q", "/a/b"}, []string{"/a/b"}},
		{agOptions, []string{"--max", "1", "/p/q", "/a/b"}, []string{"/p/q", "/a/b"}}, // a prefix is a switch
		{agOptions, []string{"--after", "/p/q", "/a/b"}, []string{"/a/b"}},            // optional value: only after "="
		{agOptions, []string{"-A", "/p/q", "/a/b"}, []string{"/a/b"}},                 // -A: a switch here
		{agOptions, []string{"--depth=3", "/p/q", "/a/b"}, []string{"/a/b"}},          // "=": not a pattern supplier
		{agOptions, []string{"-g", "/p/q", "/a/b"}, []string{"/a/b"}},
		{agOptions, []string{"--filename-pattern=x", "/p/q", "/a/b"}, []string{"/p/q", "/a/b"}},
		{agOptions, []string{"-f", "/p/q", "/a/b"}, []string{"/a/b"}}, // ag -f: --follow
		{agOptions, []string{"--", "-m", "/a/b"}, []string{"/a/b"}},
		{agOptions, []string{"-m", "1", "/p/q"}, nil},
		{agOptions, []string{"-m"}, nil},
		{ackOptions, []string{"-m", "1", "/p/q", "/a/b"}, []string{"/a/b"}},
		{ackOptions, []string{"-T", "perl", "/p/q", "/a/b"}, []string{"/a/b"}},
		{ackOptions, []string{"--match", "/p/q", "/a/b"}, []string{"/a/b"}},
		{ackOptions, []string{"--match=/p/q", "/a/b"}, []string{"/a/b"}},
		{ackOptions, []string{"-f", "/p/q", "/a/b"}, []string{"/p/q", "/a/b"}},
		{ackOptions, []string{"-g", "/p/q", "/a/b"}, []string{"/a/b"}}, // ack -g: a switch
		{ackOptions, []string{"--pager", "/p/q", "/a/b"}, []string{"/a/b"}},
		{ackOptions, []string{"-", "/a/b"}, []string{"/a/b"}}, // "-" (stdin) is the pattern here
	} {
		got := searchToolOperandPaths(tc.words, tc.opts, cwd, "/home/u", "ag", false)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%q: got %v, want %v", tc.words, got, tc.want)
		}
	}
}
