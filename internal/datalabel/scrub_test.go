package datalabel

import (
	"strings"
	"testing"
)

func scrubEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine([]DataLabelConfig{
		{ID: "customer-records", Decision: "BLOCK", Patterns: []PatternConfig{{Regex: `CUST-[0-9]{6}`}}},
		{ID: "codename", Decision: "AUDIT", Patterns: []PatternConfig{{Keywords: []string{"PHOENIX"}}}},
		{ID: "card", Decision: "BLOCK", Patterns: []PatternConfig{{Regex: `\b\d{15,16}\b`, Validator: "luhn"}}},
		{ID: "ctx", Decision: "BLOCK", Patterns: []PatternConfig{{Regex: `\d{4}`, Context: "pin code"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestScrub_ReplacesEveryMatchNotJustTheFirst(t *testing.T) {
	e := scrubEngine(t)
	got := e.Scrub("export CUST-104233 and CUST-104234 then project phoenix")
	for _, leak := range []string{"CUST-104233", "CUST-104234", "phoenix"} {
		if strings.Contains(got, leak) {
			t.Fatalf("%q leaked in %q", leak, got)
		}
	}
	if strings.Count(got, "[LABEL:customer-records]") != 2 || !strings.Contains(got, "[LABEL:codename]") {
		t.Fatalf("placeholders missing: %q", got)
	}
}

func TestScrub_UnmatchedTextIsByteIdentical(t *testing.T) {
	e := scrubEngine(t)
	for _, in := range []string{"", "ls -la", "echo CUST-12 ok", "git status"} {
		if got := e.Scrub(in); got != in {
			t.Errorf("Scrub(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestScrub_ValidatorAndContextStillGate(t *testing.T) {
	e := scrubEngine(t)
	// 4111111111111111 passes Luhn; 4111111111111112 does not.
	if got := e.Scrub("pay 4111111111111111"); strings.Contains(got, "4111") {
		t.Errorf("valid card leaked: %q", got)
	}
	if in := "pay 4111111111111112"; e.Scrub(in) != in {
		t.Errorf("non-Luhn number was scrubbed")
	}
	if got := e.Scrub("the pin code is 1234"); strings.Contains(got, "1234") {
		t.Errorf("context match leaked: %q", got)
	}
	if in := "build 1234"; e.Scrub(in) != in {
		t.Errorf("context-less number was scrubbed")
	}
}

func TestScrub_MergesOverlappingSpans(t *testing.T) {
	e, err := NewEngine([]DataLabelConfig{
		{ID: "a", Decision: "BLOCK", Patterns: []PatternConfig{{Regex: `abcdef`}}},
		{ID: "b", Decision: "BLOCK", Patterns: []PatternConfig{{Regex: `defghi`}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := e.Scrub("x abcdefghi y")
	if strings.ContainsAny(got, "cdefgh") {
		t.Fatalf("overlap leaked bytes: %q", got)
	}
	if got != "x [LABEL:a] y" {
		t.Fatalf("got %q", got)
	}
}

func TestScrub_NoCapOnLongInput(t *testing.T) {
	e := scrubEngine(t)
	in := strings.Repeat("a", 300*1024) + " CUST-999999"
	if got := e.Scrub(in); strings.Contains(got, "CUST-999999") {
		t.Fatal("match past the 256 KiB scan cap leaked")
	}
}

func TestScrub_NilEngineIsIdentity(t *testing.T) {
	var e *Engine
	if got := e.Scrub("CUST-104233"); got != "CUST-104233" {
		t.Fatalf("got %q", got)
	}
}
