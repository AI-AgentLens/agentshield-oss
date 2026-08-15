package datalabel

import (
	"strings"
	"testing"
)

func TestACAutomaton_NilOnEmpty(t *testing.T) {
	a := NewACAutomaton(nil)
	if a != nil {
		t.Fatal("expected nil automaton for empty patterns")
	}
	// nil automaton must be safe to search
	matches := a.Search("some text")
	if matches != nil {
		t.Fatal("expected nil matches from nil automaton")
	}
}

func TestACAutomaton_SinglePattern(t *testing.T) {
	a := NewACAutomaton([]ACPattern{
		{Text: "hello", ID: 0, CaseSensitive: true},
	})
	matches := a.Search("say hello world")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Start != 4 || matches[0].End != 9 {
		t.Errorf("wrong match position: start=%d end=%d", matches[0].Start, matches[0].End)
	}
}

func TestACAutomaton_CaseInsensitive(t *testing.T) {
	a := NewACAutomaton([]ACPattern{
		{Text: "SECRET", ID: 0, CaseSensitive: false},
	})
	matches := a.Search("this is a Secret value")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].PatternID != 0 {
		t.Errorf("wrong pattern ID: %d", matches[0].PatternID)
	}
}

func TestACAutomaton_CaseSensitive_NoMatch(t *testing.T) {
	a := NewACAutomaton([]ACPattern{
		{Text: "SECRET", ID: 0, CaseSensitive: true},
	})
	matches := a.Search("this is a Secret value")
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for case-sensitive, got %d", len(matches))
	}
}

func TestACAutomaton_MultiplePatterns(t *testing.T) {
	a := NewACAutomaton([]ACPattern{
		{Text: "cat", ID: 0, CaseSensitive: false},
		{Text: "dog", ID: 1, CaseSensitive: false},
		{Text: "bird", ID: 2, CaseSensitive: false},
	})
	matches := a.Search("I have a cat and a dog")
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}

	ids := map[int]bool{}
	for _, m := range matches {
		ids[m.PatternID] = true
	}
	if !ids[0] || !ids[1] {
		t.Error("expected cat (0) and dog (1) to match")
	}
}

func TestACAutomaton_OverlappingPatterns(t *testing.T) {
	a := NewACAutomaton([]ACPattern{
		{Text: "he", ID: 0, CaseSensitive: true},
		{Text: "her", ID: 1, CaseSensitive: true},
		{Text: "hers", ID: 2, CaseSensitive: true},
	})
	matches := a.Search("hers")
	if len(matches) != 3 {
		t.Fatalf("expected 3 overlapping matches, got %d", len(matches))
	}
}

func TestACAutomaton_MixedSensitivity(t *testing.T) {
	a := NewACAutomaton([]ACPattern{
		{Text: "PHOENIX", ID: 0, CaseSensitive: true},
		{Text: "titan", ID: 1, CaseSensitive: false},
	})

	// PHOENIX case-sensitive: exact match
	m1 := a.Search("project PHOENIX launch")
	if len(m1) != 1 || m1[0].PatternID != 0 {
		t.Errorf("expected PHOENIX match, got %v", m1)
	}

	// PHOENIX case-sensitive: wrong case
	m2 := a.Search("project phoenix launch")
	if len(m2) != 0 {
		t.Errorf("expected no PHOENIX match for lowercase, got %v", m2)
	}

	// titan case-insensitive
	m3 := a.Search("operation TITAN is go")
	if len(m3) != 1 || m3[0].PatternID != 1 {
		t.Errorf("expected titan match, got %v", m3)
	}
}

func TestACAutomaton_EmptyText(t *testing.T) {
	a := NewACAutomaton([]ACPattern{
		{Text: "hello", ID: 0, CaseSensitive: true},
	})
	matches := a.Search("")
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches on empty text, got %d", len(matches))
	}
}

func TestACAutomaton_EmptyPattern(t *testing.T) {
	a := NewACAutomaton([]ACPattern{
		{Text: "", ID: 0, CaseSensitive: true},
	})
	if a != nil {
		t.Fatal("expected nil automaton for empty pattern text")
	}
}

func BenchmarkACAutomaton_100Keywords_1KB(b *testing.B) {
	// Build 100 keyword patterns
	patterns := make([]ACPattern, 100)
	for i := range patterns {
		patterns[i] = ACPattern{
			Text:          strings.Repeat("kw", 3) + string(rune('A'+i%26)) + string(rune('a'+i/26%26)),
			ID:            i,
			CaseSensitive: false,
		}
	}
	a := NewACAutomaton(patterns)

	// 1KB text with no matches (worst case — full scan)
	text := strings.Repeat("the quick brown fox jumps over the lazy dog ", 23) // ~1012 bytes

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		a.Search(text)
	}
}
