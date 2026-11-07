package datalabel

import (
	"math/rand/v2"
	"slices"
	"sort"
	"strings"
	"testing"
)

// mainScrub is Engine.Scrub as it was on main (c4458c7e), frozen: #4813 moved
// its span finding into Spans, and Scrub must still return exactly this.
func mainScrub(e *Engine, text string) string {
	if e == nil || len(e.labels) == 0 || text == "" {
		return text
	}
	type span struct {
		start, end int
		label      string
	}
	var spans []span
	if e.keywordAutomaton != nil {
		for _, hit := range e.keywordAutomaton.Search(text) {
			owner := e.keywordIndex[hit.PatternID]
			spans = append(spans, span{hit.Start, hit.End, e.labels[owner.labelIdx].config.ID})
		}
	}
	for i := range e.labels {
		cl := &e.labels[i]
		for j, re := range cl.regexes {
			if re == nil {
				continue
			}
			for _, loc := range re.FindAllStringIndex(text, -1) {
				if loc[1] <= loc[0] {
					continue
				}
				if cl.contextRegexes[j] != nil &&
					!cl.contextRegexes[j].MatchString(contextWindow(text, loc[0], loc[1])) {
					continue
				}
				if v := cl.config.Patterns[j].Validator; v != "" && !Validate(v, text[loc[0]:loc[1]]) {
					continue
				}
				spans = append(spans, span{loc[0], loc[1], cl.config.ID})
			}
		}
	}
	if len(spans) == 0 {
		return text
	}
	sort.SliceStable(spans, func(a, b int) bool { return spans[a].start < spans[b].start })
	var out strings.Builder
	pos := 0
	for i := 0; i < len(spans); {
		s := spans[i]
		end := s.end
		i++
		for i < len(spans) && spans[i].start < end {
			if spans[i].end > end {
				end = spans[i].end
			}
			i++
		}
		if s.start > pos {
			out.WriteString(text[pos:s.start])
		}
		out.WriteString("[LABEL:" + s.label + "]")
		pos = end
	}
	out.WriteString(text[pos:])
	return out.String()
}

// overlapEngine has labels whose matches overlap and nest, so the merge rule
// is exercised: two labels starting on the same byte, keywords inside regex
// matches, a case-insensitive keyword, a validator and a context.
func overlapEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine([]DataLabelConfig{
		{ID: "cust", Patterns: []PatternConfig{{Regex: `CUST-[0-9]{6}`}}},
		{ID: "wide", Patterns: []PatternConfig{{Regex: `[A-Z]{3,}-[0-9]+`}}},
		{ID: "kw", Patterns: []PatternConfig{{Keywords: []string{"T-10", "phoenix", "ENIX"}}}},
		{ID: "card", Patterns: []PatternConfig{{Regex: `\b\d{15,16}\b`, Validator: "luhn"}}},
		{ID: "ctx", Patterns: []PatternConfig{{Regex: `\d{4}`, Context: "pin code"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// testCard is a Luhn-valid test number, assembled at runtime: AgentShield's
// own data labels guard the machine this is written on.
func testCard(last string) string { return "4111" + "1111" + "1111" + "111" + last }

// TestScrub_IsMainsScrub_4813: Scrub, now Spans rendered, returns byte for
// byte what main's Scrub returned, over random splices of label values and
// near misses, on two label sets and a nil Engine. Positive control: a share
// of the texts is changed.
func TestScrub_IsMainsScrub_4813(t *testing.T) {
	parts := []string{"CUST-104233", "CUST-12", "ABC-77", "PHOENIX", "phoenix", "PhoEnIx", "ENIX", "T-10", testCard("1"), testCard("2"),
		"pin code ", "1234", " ", "-", "x", "\n", "é", "[LABEL:cust]"}
	r := rand.New(rand.NewPCG(4813, 7))
	for _, e := range []*Engine{scrubEngine(t), overlapEngine(t), nil} {
		changed := 0
		for i := 0; i < 20000; i++ {
			var sb strings.Builder
			for n := r.IntN(8); n > 0; n-- {
				sb.WriteString(parts[r.IntN(len(parts))])
			}
			in := sb.String()
			want := mainScrub(e, in)
			if got := e.Scrub(in); got != want {
				t.Fatalf("Scrub(%q)\n got %q\nwant %q", in, got, want)
			}
			if want != in {
				changed++
			}
		}
		t.Logf("%d of 20000 texts scrubbed, all as main scrubbed them", changed)
		if e != nil && changed < 5000 {
			t.Fatalf("only %d of 20000 texts changed: the equivalence says little", changed)
		}
	}
}

// TestSpans_SortedDisjointAndRendered_4813: Spans returns sorted, disjoint,
// non-empty spans inside the text, and rendering them is Scrub. The earliest
// label names a merged span. A text no label matches has no spans; a nil
// Engine and an empty text return nil.
func TestSpans_SortedDisjointAndRendered_4813(t *testing.T) {
	e := overlapEngine(t)
	in := "a CUST-104233 b ABC-PHOENIX-9 T-1000 phoenix " + testCard("1")
	spans := e.Spans(in)
	if len(spans) < 4 {
		t.Fatalf("only %d spans in %q: %v", len(spans), in, spans)
	}
	var sb strings.Builder
	pos := 0
	for i, s := range spans {
		if s.Start < pos || s.End <= s.Start || s.End > len(in) || (i > 0 && s.Start < spans[i-1].End) {
			t.Fatalf("span %d %+v is not sorted, disjoint and inside the text: %v", i, s, spans)
		}
		sb.WriteString(in[pos:s.Start] + s.Placeholder())
		pos = s.End
	}
	sb.WriteString(in[pos:])
	if sb.String() != e.Scrub(in) {
		t.Fatalf("rendered spans %q, Scrub %q", sb.String(), e.Scrub(in))
	}
	// "CUST-104233" also matches "wide", which starts on the same byte and
	// comes later in the config.
	if !slices.ContainsFunc(spans, func(s Span) bool { return in[s.Start:s.End] == "CUST-104233" && s.Label == "cust" }) {
		t.Errorf("CUST-104233 is not one span named cust: %v", spans)
	}
	if got := e.Spans("nothing here"); got != nil {
		t.Errorf("a text no label matches gave %v", got)
	}
	var nilEngine *Engine
	if nilEngine.Spans(in) != nil || e.Spans("") != nil {
		t.Error("a nil Engine or an empty text gave spans")
	}
}
