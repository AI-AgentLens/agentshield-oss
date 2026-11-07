package mcp

import (
	"math/rand"
	"slices"
	"testing"
)

// #4686: pattern_not_match, the per-match exclusion. These rows pin the
// semantics written on ArgFieldMatch.PatternNotMatch with synthetic tokens
// (KEY-<digits> stands for a secret, DUMMY for an excused literal), so no
// credential-shaped string appears in this file.

func pnmFires(fm ArgFieldMatch, value string) bool {
	return matchArgField(map[string]interface{}{"content": value}, "content", fm)
}

// The positive pattern and the exclusion used by most rows. They have the
// shape of the credential rule's generic alternative and its placeholder
// exclusion: the positive match spans the whole literal (`DUMMY KEY-1`, like
// `name = "changeme…"`) and the exclusion matches inside it.
const (
	pnmKey    = `(?:DUMMY )?KEY-[0-9]+`
	pnmExcuse = `DUMMY KEY-[0-9]+`
)

func TestPatternNotMatch_ExcusesOnlyTheMatchItLiesInside(t *testing.T) {
	perMatch := ArgFieldMatch{PatternAny: []string{pnmKey}, PatternNotMatch: []string{pnmExcuse}}
	contentWide := ArgFieldMatch{PatternAny: []string{pnmKey}, PatternNot: []string{pnmExcuse}}
	rows := []struct {
		name        string
		value       string
		perMatch    bool
		contentWide bool
	}{
		{"secret alone", "x KEY-123 y", true, true},
		{"excused literal alone", "x DUMMY KEY-1 y", false, false},
		{"two excused literals", "DUMMY KEY-1\nDUMMY KEY-2", false, false},
		{"two excused literals, one line", "DUMMY KEY-1, DUMMY KEY-2", false, false},
		{"decoy then secret", "DUMMY KEY-1\nKEY-999", true, false},
		{"secret then decoy", "KEY-999\nDUMMY KEY-1", true, false},
		{"decoy and secret on one line", "DUMMY KEY-1 KEY-999", true, false},
		{"excused literal in prose", "see DUMMY KEY-1 and nothing else", false, false},
		{"nothing", "plain text", false, false},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			if got := pnmFires(perMatch, tc.value); got != tc.perMatch {
				t.Errorf("pattern_not_match: fires=%v, want %v", got, tc.perMatch)
			}
			// pattern_not keeps its content-wide meaning (pinned, not changed).
			if got := pnmFires(contentWide, tc.value); got != tc.contentWide {
				t.Errorf("pattern_not: fires=%v, want %v", got, tc.contentWide)
			}
		})
	}
}

// An exclusion match excuses a positive match only when it lies ENTIRELY
// inside it. One that starts before the positive match, or runs past its end,
// excuses nothing.
func TestPatternNotMatch_ContainmentNotOverlap(t *testing.T) {
	rows := []struct {
		name, excuse, value string
		fires               bool
	}{
		{"inside", `KEY-1`, "KEY-1", false},
		{"inside, shorter", `KEY`, "KEY-1", false},
		{"starts before the match", `X KEY`, "X KEY-1", true},
		{"runs past the end", `KEY-1 TAIL`, "KEY-1 TAIL", true},
		{"elsewhere in the value", `TAIL`, "KEY-1 TAIL", true},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			fm := ArgFieldMatch{PatternAny: []string{pnmKey}, PatternNotMatch: []string{tc.excuse}}
			if got := pnmFires(fm, tc.value); got != tc.fires {
				t.Errorf("fires=%v, want %v", got, tc.fires)
			}
		})
	}
}

// The exclusion runs over the whole value, as pattern_not does, so ^, $ and
// \b keep their meaning. Testing the exclusion against the matched text on its
// own would read ^ as "start of this match" and excuse every match.
func TestPatternNotMatch_AnchorsReadTheWholeValue(t *testing.T) {
	rows := []struct {
		name, excuse, value string
		fires               bool
	}{
		{"^ at the value start excuses", `^KEY-1`, "KEY-1", false},
		{"^ not at the value start excuses nothing", `^KEY-[0-9]+`, "x KEY-1", true},
		{"$ at the value end excuses", `KEY-1$`, "x KEY-1", false},
		{"$ not at the value end excuses nothing", `KEY-[0-9]+$`, "KEY-1 x", true},
		{`\b inside a longer word excuses nothing`, `\bKEY-[0-9]+`, "XKEY-1", true},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			fm := ArgFieldMatch{PatternAny: []string{pnmKey}, PatternNotMatch: []string{tc.excuse}}
			if got := pnmFires(fm, tc.value); got != tc.fires {
				t.Errorf("fires=%v, want %v", got, tc.fires)
			}
		})
	}
}

// pattern_all: every pattern needs a match that is not excused.
func TestPatternNotMatch_PatternAll(t *testing.T) {
	fm := ArgFieldMatch{PatternAll: []string{pnmKey, `TOKEN-[a-z]+`}, PatternNotMatch: []string{pnmExcuse}}
	rows := []struct {
		name, value string
		fires       bool
	}{
		{"both present", "KEY-1 TOKEN-ab", true},
		{"only the KEY match is excused", "DUMMY KEY-1 TOKEN-ab", false},
		{"an excused KEY and a counting one", "DUMMY KEY-1 KEY-2 TOKEN-ab", true},
		{"TOKEN missing", "KEY-1", false},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			if got := pnmFires(fm, tc.value); got != tc.fires {
				t.Errorf("fires=%v, want %v", got, tc.fires)
			}
		})
	}
}

// The down-level copy: a pattern listed in both pattern_not and
// pattern_not_match is read per match only. A pattern_not entry NOT restated
// in pattern_not_match keeps its content-wide meaning beside it.
func TestPatternNotMatch_DownLevelCopyAndOtherPatternNot(t *testing.T) {
	mirrored := ArgFieldMatch{
		PatternAny:      []string{pnmKey},
		PatternNot:      []string{pnmExcuse},
		PatternNotMatch: []string{pnmExcuse},
	}
	if !pnmFires(mirrored, "DUMMY KEY-1\nKEY-999") {
		t.Errorf("mirrored entry: the decoy still hides the secret, so its pattern_not copy was applied")
	}
	if pnmFires(mirrored, "DUMMY KEY-1") {
		t.Errorf("mirrored entry: an excused literal alone fires")
	}

	other := ArgFieldMatch{
		PatternAny:      []string{pnmKey},
		PatternNot:      []string{pnmExcuse, `GENERATED FILE`},
		PatternNotMatch: []string{pnmExcuse},
	}
	if pnmFires(other, "GENERATED FILE\nKEY-999") {
		t.Errorf("an unmirrored pattern_not entry lost its content-wide meaning")
	}
	if !pnmFires(other, "DUMMY KEY-1\nKEY-999") {
		t.Errorf("unmirrored entry absent: the mirrored one still hid the secret")
	}
}

// Edges that keep the field from switching a rule off or on by accident.
func TestPatternNotMatch_Edges(t *testing.T) {
	// An exclusion that does not compile excuses nothing, and its mirrored
	// pattern_not copy is not applied content-wide either.
	bad := ArgFieldMatch{PatternAny: []string{pnmKey}, PatternNot: []string{`(`}, PatternNotMatch: []string{`(`}}
	if !pnmFires(bad, "KEY-1") {
		t.Errorf("an invalid exclusion switched the field off")
	}
	// Alone, with no positive pattern, it excuses nothing and the field holds
	// as a field with no pattern predicate does.
	alone := ArgFieldMatch{PatternNotMatch: []string{`.*`}}
	for _, v := range []string{"anything", ""} {
		if pnmFires(alone, v) != pnmFires(ArgFieldMatch{}, v) {
			t.Errorf("pattern_not_match alone changed the field's outcome on %q", v)
		}
	}
	// A batch argument: each value is judged on its own.
	fm := ArgFieldMatch{PatternAny: []string{pnmKey}, PatternNotMatch: []string{pnmExcuse}}
	batch := map[string]interface{}{"contents": []interface{}{"DUMMY KEY-1", "KEY-2"}}
	if !matchArgField(batch, "contents", fm) {
		t.Errorf("batch: the unexcused value does not fire")
	}
	// taxonomy_from reads these: the excused value is not a matched value.
	got := matchedArgValues(batch, map[string]ArgFieldMatch{"contents": fm})
	if !slices.Contains(got, "KEY-2") || slices.Contains(got, "DUMMY KEY-1") {
		t.Errorf("matched values %q, want KEY-2 and not the excused DUMMY KEY-1", got)
	}
}

// Residual, pinned: matches are leftmost-first and non-overlapping, so a
// positive match that begins inside an excused one is never seen. Here the
// first match swallows the start of the second. Main misses it too (its
// content-wide exclusion matches), so this is not a regression; closing it
// means rescanning after each excused match, which is quadratic on
// attacker-chosen content.
func TestPatternNotMatch_OverlappingMatchResidual(t *testing.T) {
	fm := ArgFieldMatch{PatternAny: []string{`A[^;]*;`}, PatternNotMatch: []string{`AX`}}
	if pnmFires(fm, "AX Ay;") {
		t.Errorf("residual changed: the match inside the excused one is now seen; rewrite this as a TP row")
	}
	if !pnmFires(fm, "AX; Ay;") {
		t.Errorf("control: a separate unexcused match must fire")
	}
}

// The construction argument, as a fitness function: moving a pattern from
// pattern_not to pattern_not_match never lowers a decision. Over generated
// values and patterns that include anchors and word boundaries, whenever the
// content-wide twin fires, the per-match field fires too.
func TestPatternNotMatch_MovingAPatternNeverLowers(t *testing.T) {
	positives := []string{`KEY-[0-9]+`, `KEY`, `^KEY`, `[0-9]+$`, `\bKEY\b`, `(?i)key-[0-9]`}
	exclusions := []string{`DUMMY KEY-[0-9]+`, `KEY-1`, `^KEY-[0-9]`, `KEY$`, `\bDUMMY\b`, `[0-9]`, `Y-`, `(?i)dummy`}
	words := []string{"KEY", "KEY-1", "KEY-22", "DUMMY", "XKEY-3", "key-4", " ", "\n", "-", "1", "Y"}
	rng := rand.New(rand.NewSource(4686))
	total, twinFired, raised := 0, 0, 0
	for i := 0; i < 4000; i++ {
		var v string
		for n := rng.Intn(7); n >= 0; n-- {
			v += words[rng.Intn(len(words))]
		}
		pos := []string{positives[rng.Intn(len(positives))]}
		ex := []string{exclusions[rng.Intn(len(exclusions))]}
		if rng.Intn(3) == 0 {
			ex = append(ex, exclusions[rng.Intn(len(exclusions))])
		}
		for _, all := range []bool{false, true} {
			twin := ArgFieldMatch{PatternAny: pos, PatternNot: ex}
			moved := ArgFieldMatch{PatternAny: pos, PatternNotMatch: ex}
			kept := ArgFieldMatch{PatternAny: pos, PatternNot: ex, PatternNotMatch: ex}
			if all {
				twin = ArgFieldMatch{PatternAll: pos, PatternNot: ex}
				moved = ArgFieldMatch{PatternAll: pos, PatternNotMatch: ex}
				kept = ArgFieldMatch{PatternAll: pos, PatternNot: ex, PatternNotMatch: ex}
			}
			total++
			before, after, withCopy := pnmFires(twin, v), pnmFires(moved, v), pnmFires(kept, v)
			if after != withCopy {
				t.Fatalf("down-level copy changed the per-match outcome: %q pos=%q ex=%q", v, pos, ex)
			}
			if before {
				twinFired++
				if !after {
					t.Fatalf("lowered: value %q pos=%q ex=%q all=%v", v, pos, ex, all)
				}
			} else if after {
				raised++
			}
		}
	}
	// Vacuity floors: the twin must fire often, and the move must raise some.
	if twinFired < total/10 || raised == 0 {
		t.Fatalf("vacuous sweep: %d cases, twin fired %d, raised %d", total, twinFired, raised)
	}
	t.Logf("%d cases, content-wide fired %d, per-match raised %d, lowered 0", total, twinFired, raised)
}
