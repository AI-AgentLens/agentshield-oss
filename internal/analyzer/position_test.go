package analyzer

import (
	"regexp"
	"strings"
	"testing"
)

// shadowMatcher stands in for a rule whose signal is a literal path — the
// shape command_position_exclude exists for.
func shadowMatcher() func(string) bool {
	re := regexp.MustCompile(`(/etc/shadow|/etc/master\.passwd)`)
	return re.MatchString
}

func TestPositionExcludedLoopWordList(t *testing.T) {
	matches := shadowMatcher()
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{
			name:    "grep needle in an inert loop — the #3376 FP",
			command: `for p in ".ssh/" "/etc/shadow"; do n=$(grep -c -- "$p" "$F"); echo "$n <= $p"; done`,
			want:    true,
		},
		{
			name:    "printed only",
			command: `for p in /etc/shadow; do echo "checking $p"; done`,
			want:    true,
		},

		// Attribution: the loop exists and is inert, but the match does not
		// live in it. Without the attribution half, any command containing a
		// harmless loop would qualify.
		{
			name:    "inert loop present, match is elsewhere",
			command: `for f in a b; do echo "$f"; done; cat /etc/shadow`,
			want:    false,
		},
		// Subtraction: the match lives in the loop AND outside it.
		{
			name:    "same path inside the loop and in a real read",
			command: `for p in /etc/shadow; do echo "$p"; done && cat /etc/shadow`,
			want:    false,
		},
		{
			name:    "second occurrence only visible after quote removal",
			command: `for p in /etc/shadow; do echo "$p"; done; cat /etc/sha'dow'`,
			want:    false,
		},
		// Inertness: the loop variable reaches something that acts on it.
		{
			name:    "loop variable is read",
			command: `for p in /etc/shadow; do cat "$p"; done`,
			want:    false,
		},
		{
			name:    "printed value consumed by a pipe",
			command: `for p in /etc/shadow; do echo "$p" | xargs cat; done`,
			want:    false,
		},
		{
			name:    "no loop at all",
			command: `cat /etc/shadow`,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PositionExcluded(tt.command, []string{LabelPosLoopWordList}, matches)
			if got != tt.want {
				t.Fatalf("PositionExcluded(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// fridaNameMatcher stands in for ts-block-frida-name-attach — a rule whose
// signal spans two tokens ("frida" then "-n"/"--name") rather than one
// literal path, which is the shape #3382 needs covered.
func fridaNameMatcher() func(string) bool {
	re := regexp.MustCompile(`(?:sudo\s+)?frida\b(?:\s+\S+)*?\s+(?:-n|--name)\s+\S+`)
	return re.MatchString
}

func TestPositionExcludedSearchNeedle(t *testing.T) {
	matches := fridaNameMatcher()
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{
			name:    "quoted multi-word needle — the #3382 FP",
			command: `grep -i "frida -n <process>" -r docs/`,
			want:    true,
		},
		{
			name:    "ripgrep, single-quoted needle",
			command: `rg -i 'frida --name chrome' docs/`,
			want:    true,
		},

		// Attribution: a grep needle is present, but it does not itself
		// satisfy the rule's pattern (the "-n" comes from elsewhere).
		{
			name:    "needle present, match spans outside it",
			command: `grep -i frida -r . ; ls -n`,
			want:    false,
		},
		// Subtraction: the same phrase also appears as a real invocation.
		{
			name:    "needle plus a genuine attach elsewhere",
			command: `grep -i "frida -n <process>" -r docs/ && frida -n chrome`,
			want:    false,
		},
		{
			name:    "genuine attach, no search at all",
			command: `frida -n chrome`,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PositionExcluded(tt.command, []string{LabelPosSearchNeedle}, matches)
			if got != tt.want {
				t.Fatalf("PositionExcluded(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// sitecustomizeMatcher stands in for ts-block-python-sitecustomize-write — a
// rule whose signal is TWO co-required tokens (an executable word and a
// filename), which stresses attribution differently than the single-region
// shapes above: the exclusion only works when both tokens are co-located
// within the excluded position, since PositionExcluded tests the rule's WHOLE
// pattern against the isolated redacted text (#3397).
func sitecustomizeMatcher() func(string) bool {
	re := regexp.MustCompile(`(echo|printf|tee|cat|cp|mv|install)\b.*\b(site|user)customize\.py`)
	return re.MatchString
}

func TestPositionExcludedHeredocBody(t *testing.T) {
	matches := sitecustomizeMatcher()
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{
			name:    "both trigger tokens co-located in heredoc body prose — the #3397 FP",
			command: "cat > \"$S/notes.md\" <<'EOF'\n- blocks cat/tee writes to sitecustomize.py\nEOF",
			want:    true,
		},

		// Attribution: the filename is in the body, but the required
		// executable-word token never occurs there — the isolated body text
		// alone does not satisfy the rule's own pattern, so this label does
		// not apply (the whole-command match must have come from elsewhere,
		// e.g. the command's own "cat" — a case the rule's DOTALL-less regex
		// can only reach when both tokens share a line, so it is already
		// covered by the co-located case above in practice).
		{
			name:    "filename only, no co-located executable word",
			command: "cat > \"$S/notes.md\" <<'EOF'\nsitecustomize.py\nEOF",
			want:    false,
		},
		// Subtraction: the filename is the ACTUAL write target on the
		// command line — a real attack — and must never be excused just
		// because the invocation also carries a heredoc.
		{
			name:    "filename is the real write target, not body prose",
			command: "cat > sitecustomize.py <<'EOF'\nimport os\nEOF",
			want:    false,
		},
		// Subtraction: heredoc piped into tee, whose own argument is the
		// real write target — outside the body span.
		{
			name:    "filename is a pipe-sink target, not body prose",
			command: "cat <<'EOF' | tee sitecustomize.py\nimport os\nEOF",
			want:    false,
		},
		// Never excused: the consumer interprets the body as code.
		{
			name:    "bash heredoc — body is shell, stays live",
			command: "bash <<'EOF'\ncat sitecustomize.py\nEOF",
			want:    false,
		},
		{
			name:    "no heredoc at all",
			command: "cp backdoor.py sitecustomize.py",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PositionExcluded(tt.command, []string{LabelPosHeredocBody}, matches)
			if got != tt.want {
				t.Fatalf("PositionExcluded(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// An empty or unrecognised label list must never suppress anything — the
// mechanism is opt-in, and a rule that did not ask for it must behave exactly
// as before.
func TestPositionExcludedIsOptIn(t *testing.T) {
	cmd := `for p in /etc/shadow; do echo "$p"; done`
	matches := shadowMatcher()
	if PositionExcluded(cmd, nil, matches) {
		t.Error("no labels must never exclude")
	}
	if PositionExcluded(cmd, []string{"not_a_label"}, matches) {
		t.Error("unrecognised label must never exclude")
	}
	if !PositionExcluded(cmd, []string{"not_a_label", LabelPosLoopWordList}, matches) {
		t.Error("a recognised label alongside an unrecognised one must still apply")
	}
}

func TestIsValidPositionLabel(t *testing.T) {
	if !IsValidPositionLabel(LabelPosLoopWordList) {
		t.Errorf("%q must be valid", LabelPosLoopWordList)
	}
	if !IsValidPositionLabel(LabelPosSearchNeedle) {
		t.Errorf("%q must be valid", LabelPosSearchNeedle)
	}
	if !IsValidPositionLabel(LabelPosHeredocBody) {
		t.Errorf("%q must be valid", LabelPosHeredocBody)
	}
	for _, bad := range []string{"", "loop_word_list", "is_doc_text", "loop_wordlists", "search_needles", "grep_needle", "heredoc_bodies", "in_heredoc"} {
		if IsValidPositionLabel(bad) {
			t.Errorf("%q must not be valid", bad)
		}
	}
}

// A rule whose pattern happens to match the placeholder text would be
// suppressed on every inert loop, so the placeholder must be inert itself.
// Cheap guard against someone "simplifying" it to something short.
func TestLoopItemPlaceholderMatchesNoShippedLiteral(t *testing.T) {
	cmd := `for p in /etc/shadow; do echo "$p"; done`
	greedy := func(s string) bool { return strings.Contains(s, "/etc/shadow") }
	if !PositionExcluded(cmd, []string{LabelPosLoopWordList}, greedy) {
		t.Fatal("expected the inert loop to be excluded")
	}
}

// Same guard as above, for the search-needle placeholder.
func TestSearchNeedlePlaceholderMatchesNoShippedLiteral(t *testing.T) {
	cmd := `grep -i "frida -n <process>" -r docs/`
	greedy := func(s string) bool { return strings.Contains(s, "frida") }
	if !PositionExcluded(cmd, []string{LabelPosSearchNeedle}, greedy) {
		t.Fatal("expected the search needle to be excluded")
	}
}

// Same guard as above, for the heredoc-body placeholder.
func TestHeredocBodyPlaceholderMatchesNoShippedLiteral(t *testing.T) {
	cmd := "cat > notes.md <<'EOF'\nsitecustomize.py\nEOF"
	greedy := func(s string) bool { return strings.Contains(s, "sitecustomize.py") }
	if !PositionExcluded(cmd, []string{LabelPosHeredocBody}, greedy) {
		t.Fatal("expected the heredoc body to be excluded")
	}
}
