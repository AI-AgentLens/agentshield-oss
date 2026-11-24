package analyzer

import (
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// #5049, stricter-of-two (Gary's redesign on PR #5057). On Windows,
// StripShellQuotes keeps a backslash between two names, as Git Bash does, so a
// comparison can read a word two ways: main's (every quote and backslash
// deleted) and Git Bash's (the backslash kept as a separator). A comparison
// whose match adds a finding counts when either matches; one whose match takes
// a finding away needs both. main's reading is always one of the two, so no
// decision is weaker than main's.
//
// Paths built from protected or system names are assembled at runtime: the
// hook reads test sources as commands.

// The join itself, on every OS through combineReadingsOn's goos parameter.
func TestCombineReadingsJoin_5049(t *testing.T) {
	for _, tt := range []struct {
		goos          string
		adds          bool
		main, bash    bool
		want          bool
		wantBashAsked bool
	}{
		// Windows, a match that adds: either reading.
		{"windows", true, true, false, true, false},
		{"windows", true, false, true, true, true},
		{"windows", true, false, false, false, true},
		{"windows", true, true, true, true, false},
		// Windows, a match that takes a finding away: both readings.
		{"windows", false, true, false, false, true},
		{"windows", false, false, true, false, false},
		{"windows", false, true, true, true, true},
		{"windows", false, false, false, false, false},
		// Every other OS: main's reading alone; Git Bash's is never asked.
		{"linux", true, false, true, false, false},
		{"darwin", false, true, false, true, false},
	} {
		asked := false
		got := combineReadingsOn(tt.goos, tt.adds, func(r quoteReading) bool {
			if r == readBash {
				asked = true
				return tt.bash
			}
			return tt.main
		})
		if got != tt.want || asked != tt.wantBashAsked {
			t.Errorf("%s adds=%v main=%v bash=%v: got %v (bash asked %v), want %v (bash asked %v)",
				tt.goos, tt.adds, tt.main, tt.bash, got, asked, tt.want, tt.wantBashAsked)
		}
	}
}

// main's matchArgGlob and normalizeTargetPath, verbatim but for the quote
// removal, which is main's through pathnorm.MainShellQuotes (StripShellQuotes
// is Git Bash's on Windows now). The oracle for "readMain is main's".
func mainMatchArgGlob(arg, pattern string) bool {
	arg = pathnorm.MainShellQuotes(arg)
	arg = shellparse.DeglobPath(arg)
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return arg == prefix || strings.HasPrefix(arg, prefix+"/")
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if !strings.HasPrefix(arg, prefix+"/") {
			return false
		}
		remainder := strings.TrimPrefix(arg, prefix+"/")
		return !strings.Contains(remainder, "/")
	}
	if strings.ContainsAny(pattern, "*?[") {
		matched, err := filepath.Match(pattern, arg)
		return err == nil && matched
	}
	return arg == pattern
}

func mainNormalizeTargetPath(p string) string {
	if p == "" {
		return p
	}
	p = pathnorm.MainShellQuotes(p)
	if p == "" {
		return p
	}
	p = shellparse.DeglobPath(p)
	glob := strings.HasSuffix(p, "/*")
	cleaned := path.Clean(p)
	if glob && cleaned != "/*" {
		if cleaned == "/" {
			cleaned = "/*"
		} else {
			cleaned += "/*"
		}
	}
	return cleaned
}

// readingWords spells each base word bare, double-quoted, single-quoted and
// half-quoted, with forward slashes and with backslashes.
func readingWords() []string {
	etc := "/" + "etc"
	bases := []string{
		`C:\zz\k5021\notes.pem`, `C:\zz\k5021\cfg\notes.txt`, `k5021\notes.txt`,
		`/tmp\zzbuild`, `/tmp\..\etc`, `/var/folders\zz`, `/Users/zzuser\proj`, `/home/zzuser\proj`,
		`/.\.` + etc, `/.\.`, `/usr/bin\rm`, `a\b`, `a\\b`, `/tmp/zz\sub`, `C:/zz/k5021/notes.pem`,
		etc + `/pass'w'd`, `~/.?sh/`, `/dev/zero`, `/dev\sda`,
	}
	var out []string
	for _, b := range bases {
		out = append(out, b, `"`+b+`"`, `'`+b+`'`, `"`+b[:len(b)/2]+`"`+b[len(b)/2:])
	}
	return out
}

var readingPatterns = []string{
	"*.pem", "*notes.txt", "*cfg*", "*/notes.txt", "*/*/notes.txt", "C:/zz/**", `C:\zz\*`,
	"/tmp/**", "/tmp/*", "/var/folders/**", "/Users/*", "/home/*", "/etc/**", "a?b", "/", "/dev/sd*",
}

// readMain is main's, byte for byte, on this OS: Windows included, where it
// is the half of every comparison that keeps decisions at main's or above.
func TestReadMainIsMain_5049(t *testing.T) {
	for _, w := range readingWords() {
		for _, p := range readingPatterns {
			if got, want := matchArgGlobAs(w, p, readMain), mainMatchArgGlob(w, p); got != want {
				t.Errorf("matchArgGlobAs(%q, %q, readMain) = %v, main %v", w, p, got, want)
			}
		}
		if got, want := normalizeTargetPathAs(w, readMain), mainNormalizeTargetPath(w); got != want {
			t.Errorf("normalizeTargetPathAs(%q, readMain) = %q, main %q", w, got, want)
		}
		if got, want := readMain.word(w), pathnorm.MainShellQuotes(w); got != want {
			t.Errorf("readMain.word(%q) = %q, main %q", w, got, want)
		}
	}
	// Off Windows Git Bash's reading is never taken, so every comparison is
	// main's alone.
	if runtime.GOOS != "windows" {
		for _, w := range readingWords() {
			for _, p := range readingPatterns {
				if got, want := matchArgGlob(w, p), mainMatchArgGlob(w, p); got != want {
					t.Errorf("%s: matchArgGlob(%q, %q) = %v, main %v", runtime.GOOS, w, p, got, want)
				}
			}
		}
	}
}

// The two word-level readings of an argument glob, through matchArgGlobOn's
// goos parameter, so the Windows rows run on every OS. Off Windows they go
// through globMatch's emulation of Windows filepath.Match; on Windows through
// filepath.Match itself, which checks the emulation against the real thing.
func TestMatchArgGlobWindowsReadings_5049(t *testing.T) {
	pem := `"C:\zz\k5021\notes.pem"`
	for _, tt := range []struct {
		arg, pattern string
		main, bash   bool
	}{
		// Git Bash's reading reads the backslash as a separator, where `*`
		// crosses it as Windows filepath.Match lets `*` cross '/'.
		{pem, "*.pem", true, true},
		{`"k5021\notes.pem"`, "*notes.pem", true, true},
		{`"C:\zz\k5021\cfg\notes.txt"`, "*cfg*", true, true},
		{`"C:\zz\k5021\notes.txt"`, "*/notes.txt", false, true},
		{`"C:\zz\k5021\notes.txt"`, "*/*/notes.txt", false, true},
		{`"C:\zz\k5021\notes.txt"`, "C:/zz/**", false, true},
		{`C:/zz/notes.txt`, `C:\zz\*.txt`, false, true}, // '/' is an ordinary byte to Windows filepath.Match
		{`"a\b"`, "a?b", false, true},
		{`"C:\zz\k5021\notes.txt"`, "*.pem", false, false},
		// Codex pass 2, finding 1: the native glob a customer writes. main
		// deleted the backslashes and never matched it; Git Bash's reading does.
		{`"C:\zz\notes.txt"`, `C:\zz\*`, false, true},
		// main's over-reads, which Git Bash's reading does not share.
		{`"/Users/zzuser\proj"`, "/Users/*", true, false},
		{`"/home/zzuser\proj"`, "/home/*", true, false},
		{`"/tmp/zz\sub"`, "/tmp/*", true, false},
		// Rows 205 and 208 of the #5057 decision kit: Git Bash's reading is
		// under /tmp, main's is not.
		{`"/tmp\zzbuild"`, "/tmp/**", false, true},
		{`"/tmp\..\etc"`, "/tmp/**", false, true},
		{`"/var/folders\zz"`, "/var/folders/**", false, true},
		// The same where the readings agree.
		{"/tmp/zzbuild", "/tmp/**", true, true},
		{"/Users/zzuser", "/Users/*", true, true},
		{"C:/zz/k5021/notes.pem", "*.pem", true, true},
	} {
		for _, r := range []quoteReading{readMain, readBash} {
			want := tt.main
			if r == readBash {
				want = tt.bash
			}
			if got := matchArgGlobOn(tt.arg, tt.pattern, r, "windows"); got != want {
				t.Errorf("windows %s: matchArgGlobOn(%q, %q) = %v, want %v", readingName(r), tt.arg, tt.pattern, got, want)
			}
		}
		either := combineReadingsOn("windows", true, func(r quoteReading) bool {
			return matchArgGlobOn(tt.arg, tt.pattern, r, "windows")
		})
		if either != (tt.main || tt.bash) {
			t.Errorf("windows either: %q %q = %v, want %v", tt.arg, tt.pattern, either, tt.main || tt.bash)
		}
		// On Windows matchArgGlob itself is that join.
		if runtime.GOOS == "windows" {
			if got := matchArgGlob(tt.arg, tt.pattern); got != either {
				t.Errorf("windows: matchArgGlob(%q, %q) = %v, want either reading's %v", tt.arg, tt.pattern, got, either)
			}
		}
	}
}

func readingName(r quoteReading) string {
	if r == readBash {
		return "bash"
	}
	return "main"
}

// Codex pass 2, finding 2, at the word level: main cleans `/../etc`, and Git
// Bash's reading turns its backslash into '/' before path.Clean. Round 2
// cleaned `/.\./etc` as one opaque name. The rule level is
// TestWindowsDotAliasKeepsSystemDirBlock_5049.
func TestNormalizeTargetPathReadings_5049(t *testing.T) {
	etc := "etc"
	sysDir := `"/.\./` + etc + `"`
	for _, tt := range []struct{ word, main, bash string }{
		{sysDir, "/" + etc, "/" + etc},
		{`"/.\."`, "/", "/"},
		{`"/` + etc + `\..\tmp"`, "/" + etc + "..tmp", "/tmp"},
		{`"/tmp\..\` + etc + `"`, "/tmp.." + etc, "/" + etc},
	} {
		if got := normalizeTargetPathAs(tt.word, readMain); got != tt.main {
			t.Errorf("readMain: normalizeTargetPathAs(%q) = %q, want %q", tt.word, got, tt.main)
		}
		if runtime.GOOS == "windows" {
			if got := normalizeTargetPathAs(tt.word, readBash); got != tt.bash {
				t.Errorf("readBash: normalizeTargetPathAs(%q) = %q, want %q", tt.word, got, tt.bash)
			}
		}
	}
}

// The gate that lets an evaluation skip Git Bash's reading when it would only
// repeat main's (combineReadingsIf). It must open for every command in which
// some word reads differently, including inside a carrier's payload, and may
// stay shut otherwise: most commands, whose quotes read the same both ways.
// A shut gate where it should open would only lose a finding Git Bash's
// reading adds; main's evaluation still runs.
func TestReadsTwoWaysGate_5049(t *testing.T) {
	for cmd, want := range map[string]bool{
		`grep 'x' notes.txt`:                     false,
		`echo "a b" 'c' d`:                       false,
		`cat /tmp/zz`:                            false,
		`git commit -m "fix: it works"`:          false,
		"cat $'\\x41'":                           false, // ANSI-C decodes the same both ways
		`cat "C:\zz\notes.txt"`:                  true,
		`cat C:\\zz\\notes.txt`:                  true,
		`rm -rf "/tmp\.."`:                       true,
		`echo "it's"`:                            true,
		"cat $'a\\\\b'":                          false, // decodes to a\b; both readings then delete the backslash
		`cat zz.txt > "C:\zz\out.txt"`:           true,
		`curl -o "k5021\x.sh" https://a.example`: true,
		`bash -c "cat 'k5021\x.sh'"`:             true,
		`echo $(cat "C:\zz\notes.txt")`:          true,
	} {
		p := parseCommand(t, cmd)
		if got := readsTwoWaysOn(p, "windows"); got != want {
			t.Errorf("windows: readsTwoWays(%s) = %v, want %v", cmd, got, want)
		}
		if readsTwoWaysOn(p, "linux") || readsTwoWaysOn(p, "darwin") {
			t.Errorf("%s: the gate opened off Windows", cmd)
		}
	}
	// Word level: shut exactly when the two readings are the same word.
	for _, w := range readingWords() {
		same := readMain.wordOn(w, "windows") == readBash.wordOn(w, "windows")
		if wordReadsTwoWaysOn(w, "windows") == same {
			t.Errorf("wordReadsTwoWays(%q) = %v, but the readings are the same: %v", w, !same, same)
		}
	}
	// A carrier's payload is parsed again later, so its text opens the gate by
	// itself, whatever the outer words read.
	payload := &ParsedCommand{Segments: []CommandSegment{{Executable: "bash", CFlagArg: `cat 'k5021\x.sh'`}}}
	if !readsTwoWaysOn(payload, "windows") {
		t.Error("a carrier payload with a backslash did not open the gate")
	}
	// Each field the evaluations read opens it on its own.
	for name, p := range map[string]*ParsedCommand{
		"args":                {Segments: []CommandSegment{{Executable: "cat", Args: []string{`"C:\zz\a"`}}}},
		"flag value":          {Segments: []CommandSegment{{Executable: "curl", Flags: map[string]string{"o": `"k5021\x.sh"`}}}},
		"segment redirect":    {Segments: []CommandSegment{{Executable: "cat", Redirects: []Redirect{{Op: ">", Path: `"C:\zz\out"`}}}}},
		"top-level redirect":  {Segments: []CommandSegment{{Executable: "cat"}}, Redirects: []Redirect{{Op: ">", Path: `"C:\zz\out"`}}},
		"subcommand argument": {Segments: []CommandSegment{{Executable: "echo"}}, Subcommands: []*ParsedCommand{{Segments: []CommandSegment{{Executable: "cat", Args: []string{`"C:\zz\a"`}}}}}},
		"executable":          {Segments: []CommandSegment{{Executable: `"k5021\x.sh"`}}},
	} {
		if !readsTwoWaysOn(p, "windows") {
			t.Errorf("%s: a word that reads differently did not open the gate", name)
		}
	}
	plain := &ParsedCommand{Segments: []CommandSegment{{Executable: "bash", CFlagArg: `cat 'k5021/x.sh'`}}}
	if readsTwoWaysOn(plain, "windows") {
		t.Error("a carrier payload with one kind of quote and no backslash opened the gate")
	}
	if !globsHaveBackslash([]string{"*.txt"}, []string{`C:\zz\*`}) || globsHaveBackslash([]string{"*.txt", "/tmp/**"}) {
		t.Error("globsHaveBackslash")
	}
}
