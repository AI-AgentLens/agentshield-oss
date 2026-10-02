package shellparse

import "testing"

// TestExecutedTextReport_CountsUnresolved pins the #3995 attestation input:
// an emitted program with an unexpanded `$` is refused AND counted, so the
// caller can say "retried nothing because it could not be resolved" rather
// than nothing at all. A static program is returned and not counted.
func TestExecutedTextReport_CountsUnresolved(t *testing.T) {
	texts, unresolved := ExecutedTextReport(`echo "$x" | bash`)
	if len(texts) != 0 || unresolved != 1 {
		t.Fatalf("dynamic program: texts=%v unresolved=%d, want none and 1", texts, unresolved)
	}
	texts, unresolved = ExecutedTextReport(`echo 'ls -la' | bash`)
	if len(texts) != 1 || texts[0] != "ls -la" || unresolved != 0 {
		t.Fatalf("static program: texts=%v unresolved=%d, want [ls -la] and 0", texts, unresolved)
	}
	if got := ExecutedText(`echo 'ls -la' | bash`); len(got) != 1 {
		t.Fatalf("ExecutedText wrapper drifted: %v", got)
	}
	if texts, unresolved := ExecutedTextReport(`ls -la`); texts != nil || unresolved != 0 {
		t.Fatalf("plain command: texts=%v unresolved=%d, want nil and 0", texts, unresolved)
	}
}

// Opus review of #4005: the count is per statement and per distinct text.
// A status line next to a static pipe-to-shell reaches nothing; a
// substitution whose output runs is counted once, not once per pass.
func TestExecutedTextReport_CountsOnlyTextThatReachesAnExecutor(t *testing.T) {
	cases := []struct {
		cmd  string
		want int
	}{
		{`echo "$HOME"; echo ls | bash`, 0},
		{`python3 run.py; echo "done $x"`, 0},
		{`echo "$x" | bash; echo "status $y"`, 1},
		{`bash -c "$(echo "$X")"; echo ls | sh`, 1},
		{`echo "$a" | sh; echo "$a" | bash`, 1},
	}
	for _, c := range cases {
		_, got := ExecutedTextReport(c.cmd)
		if got != c.want {
			t.Errorf("%q: unresolved=%d, want %d", c.cmd, got, c.want)
		}
	}
}
