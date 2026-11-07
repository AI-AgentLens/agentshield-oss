package psreader

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/facts"
)

// Bounds on one read (Opus pass 2 on #4245, F1). A word's suffix spellings
// were resolved one by one to the end of the word, so a 24 KB word took the
// hook 40 s on Copilot's row, past its 30 s timeout, which fails open. The
// bounds touch mentions only; a whole value is a Path whatever its length or
// count. Every bound that drops something says so with a parse_error note,
// which floors the decision at AUDIT.

func sshKey() string { return "~/.ssh/id_" + "rsa" }

func boundedNote(f facts.Facts) bool {
	for _, n := range f.Notes {
		if n.Kind == facts.NoteParseError && strings.Contains(n.Detail, "path extraction bounded") {
			return true
		}
	}
	return false
}

func mentionBytes(f facts.Facts) int {
	n := 0
	for _, m := range f.Mentions {
		n += len(m)
	}
	return n
}

// TestRead_SuffixSpellingsAreBoundedPerWord: a word yields at most
// maxSuffixesPerWord suffix spellings; one more is not read and the read
// says so.
func TestRead_SuffixSpellingsAreBoundedPerWord(t *testing.T) {
	at := Read("Write-Output "+strings.Repeat("a=~/x", maxSuffixesPerWord), testEnv)
	if boundedNote(at) {
		t.Errorf("%d suffix spellings: bounded note %+v, want none", maxSuffixesPerWord, at.Notes)
	}
	past := Read("Write-Output "+strings.Repeat("a=~/x", maxSuffixesPerWord+1), testEnv)
	if !boundedNote(past) {
		t.Errorf("%d suffix spellings: notes %+v, want the bounded note", maxSuffixesPerWord+1, past.Notes)
	}
	// The first spellings are the ones read: the longest suffix is the first.
	first := "~/x" + strings.Repeat("a=~/x", maxSuffixesPerWord)
	if !contains(past.Mentions, first) {
		t.Errorf("Mentions %q lack the first suffix spelling %q", past.Mentions, first)
	}
}

// TestRead_SuffixSpellingIsClippedNotDropped: a suffix spelling longer than
// maxCandidateBytes is read clipped, so a pattern anchored at its start
// (every shipped one is) still matches it. A whole value is never clipped.
func TestRead_SuffixSpellingIsClippedNotDropped(t *testing.T) {
	long := "~/.ssh/" + strings.Repeat("k", 2*maxCandidateBytes)
	f := Read("Write-Output x="+long, testEnv)
	clipped := long[:maxCandidateBytes]
	if !contains(f.Mentions, clipped) {
		t.Errorf("Mentions lack the suffix clipped to %d bytes", maxCandidateBytes)
	}
	for _, m := range f.Mentions {
		if strings.HasPrefix(m, "~/.ssh/") && len(m) > maxCandidateBytes {
			t.Errorf("a suffix mention of %d bytes, want at most %d", len(m), maxCandidateBytes)
		}
	}
	if !contains(f.Paths, "x="+long) {
		t.Errorf("the whole value (%d bytes) is not a Path", len("x="+long))
	}
	g := Read("Get-Content "+long, testEnv)
	if !contains(g.Paths, long) {
		t.Errorf("a whole-value path of %d bytes was clipped or dropped", len(long))
	}
	if boundedNote(f) || boundedNote(g) {
		t.Errorf("clipping is not a bound that drops anything: notes %+v %+v", f.Notes, g.Notes)
	}
}

// TestClipCandidate: a clip never splits a UTF-8 sequence, and a candidate
// at the bound is kept whole.
func TestClipCandidate(t *testing.T) {
	at := strings.Repeat("a", maxCandidateBytes)
	if got := clipCandidate(at); got != at {
		t.Errorf("a candidate of exactly %d bytes was clipped to %d", maxCandidateBytes, len(got))
	}
	if got := clipCandidate(at + "b"); got != at {
		t.Errorf("clip of %d bytes = %d bytes, want %d", maxCandidateBytes+1, len(got), maxCandidateBytes)
	}
	split := strings.Repeat("a", maxCandidateBytes-1) + "\u00e9" + "b" // é straddles the bound
	if got := clipCandidate(split); got != strings.Repeat("a", maxCandidateBytes-1) {
		t.Errorf("clip split a UTF-8 sequence: %d bytes, last %q", len(got), got[len(got)-1:])
	}
}

// TestRead_MentionsAreBoundedNotPaths: past maxMentions mentions, or
// maxMentionBytes of them, a mention is not kept and the read says so; a
// whole value after the flood is still a Path.
func TestRead_MentionsAreBoundedNotPaths(t *testing.T) {
	var words []string
	for i := 0; i < 2*maxMentions; i++ {
		words = append(words, fmt.Sprintf("~/m%d", i))
	}
	f := Read(`Write-Output "`+strings.Join(words, " ")+`"; Get-Content `+sshKey(), testEnv)
	if len(f.Mentions) > maxMentions {
		t.Errorf("%d mentions, want at most %d", len(f.Mentions), maxMentions)
	}
	if !boundedNote(f) {
		t.Errorf("notes %+v, want the bounded note", f.Notes)
	}
	if !contains(f.Paths, sshKey()) {
		t.Errorf("Paths %q lack the whole value read after the mention flood", f.Paths)
	}

	h := Read(`Write-Output "`+strings.Join(words[:10], " ")+`"`, testEnv)
	if boundedNote(h) {
		t.Errorf("10 mentions: notes %+v, want no bounded note", h.Notes)
	}

	// Long suffix spellings: 8 words of 32 suffixes each, about 65 KB of
	// mentions a word from 4 KB of text, reach the byte bound well before
	// the count bound. Each word has its own unit, so no two share a suffix.
	var long []string
	for i := 0; i < 8; i++ {
		unit := fmt.Sprintf("=~/%c", 'a'+i) + strings.Repeat("y", 120)
		long = append(long, "w"+strings.Repeat(unit, maxSuffixesPerWord))
	}
	g := Read("Write-Output "+strings.Join(long, " "), testEnv)
	if n := mentionBytes(g); n > maxMentionBytes {
		t.Errorf("%d bytes of mentions, want at most %d", n, maxMentionBytes)
	}
	if len(g.Mentions) >= 8*maxSuffixesPerWord || !boundedNote(g) {
		t.Errorf("%d mentions, notes %+v; want the byte bound to stop it, with the note", len(g.Mentions), g.Notes)
	}
	for _, w := range long {
		if !contains(g.Paths, w) {
			t.Errorf("whole value %.12s… is not a Path", w)
		}
	}
}

// TestRead_PastTheTextBoundOnlyTheRawScanReads: a text longer than
// maxReadBytes is not parsed (no command, no nested text, no Path); the raw
// scan still reports what it finds as mentions, and a note says so. At the
// bound the text is parsed.
func TestRead_PastTheTextBoundOnlyTheRawScanReads(t *testing.T) {
	head := "Get-Content " + sshKey() + "; Write-Output "
	at := head + strings.Repeat("x", maxReadBytes-len(head))
	f := Read(at, testEnv)
	if len(f.Commands) == 0 || !contains(f.Paths, sshKey()) {
		t.Errorf("%d bytes: Commands %d Paths %q, want it parsed", len(at), len(f.Commands), f.Paths)
	}
	for _, n := range f.Notes {
		if strings.Contains(n.Detail, "past the reader's bound") {
			t.Errorf("%d bytes: note %q, want none", len(at), n.Detail)
		}
	}
	past := at + "x"
	g := Read(past, testEnv)
	if len(g.Commands) != 0 || len(g.Paths) != 0 || len(g.Nested) != 0 || g.Simple {
		t.Errorf("%d bytes: Commands %d Paths %q Nested %d Simple %v, want nothing parsed", len(past), len(g.Commands), g.Paths, len(g.Nested), g.Simple)
	}
	if !contains(g.Mentions, sshKey()) {
		t.Errorf("%d bytes: Mentions %q, want the raw scan's find", len(past), g.Mentions)
	}
	noted := false
	for _, n := range g.Notes {
		noted = noted || n.Kind == facts.NoteParseError && strings.Contains(n.Detail, "past the reader's bound")
	}
	if !noted {
		t.Errorf("%d bytes: notes %+v, want the text-bound note", len(past), g.Notes)
	}
}

// TestRead_AdversarialShapesStayBounded: the reviewer's shapes at 64 KiB
// (one long word of tilde, dollar or `=~` units, plain and inside two nested
// iex strings) report a bounded amount of mentions, so the back end's work
// on them is bounded too.
func TestRead_AdversarialShapesStayBounded(t *testing.T) {
	for name, unit := range map[string]string{"tilde-long": "ab=~/a/b/c.", "dollar": "a=$x", "eqtilde": "a=~x"} {
		word := strings.Repeat(unit, 64*1024/len(unit))
		for shape, text := range map[string]string{
			"plain": "Get-Date; Write-Output " + word,
			"iex2":  "Get-Date; iex 'iex ''Write-Output " + word + "'''",
		} {
			start := time.Now()
			f := Read(text, testEnv)
			for _, n := range f.Nested {
				Read(n.Text, testEnv)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("%s %s: read in %v", name, shape, d)
			}
			if len(f.Mentions) > maxMentions || mentionBytes(f) > maxMentionBytes {
				t.Errorf("%s %s: %d mentions, %d bytes", name, shape, len(f.Mentions), mentionBytes(f))
			}
		}
	}
}
