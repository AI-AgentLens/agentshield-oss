package route

import (
	"strings"
	"testing"
)

func v(l Lane, decision, original string, rules ...string) Verdict {
	return Verdict{Lane: l, Decision: decision, OriginalDecision: original, Rules: rules}
}

// TestCombine_StricterWinsEarlierWinsTies is the combiner's order, case by
// case: the strictest pre-downgrade decision wins, and on a tie the earlier
// lane in the row (the old lane) keeps its record.
func TestCombine_StricterWinsEarlierWinsTies(t *testing.T) {
	cases := []struct {
		name        string
		vs          []Verdict
		winner      int
		decision    string
		originalDec string
		keptBlock   bool
		wantFloored bool
	}{
		{"posix BLOCK beats structured AUDIT",
			[]Verdict{v(Structured, "AUDIT", ""), v(POSIX, "BLOCK", "", "ts-block-rm-root")}, 1, "BLOCK", "", false, false},
		{"structured AUDIT beats posix ALLOW (a swap would lower this)",
			[]Verdict{v(Structured, "AUDIT", ""), v(POSIX, "ALLOW", "", "ts-allow-readonly")}, 0, "AUDIT", "", false, false},
		{"AUDIT tie keeps the earlier lane",
			[]Verdict{v(Structured, "AUDIT", "", "mcp-x"), v(POSIX, "AUDIT", "", "ts-y")}, 0, "AUDIT", "", false, false},
		{"BLOCK tie keeps the earlier lane",
			[]Verdict{v(Structured, "BLOCK", "", "mcp-x"), v(POSIX, "BLOCK", "", "ts-y")}, 0, "BLOCK", "", false, false},
		{"ALLOW tie keeps the earlier lane",
			[]Verdict{v(Structured, "ALLOW", ""), v(POSIX, "ALLOW", "")}, 0, "ALLOW", "", false, false},
		{"REQUIRE_APPROVAL beats AUDIT",
			[]Verdict{v(Structured, "AUDIT", ""), v(POSIX, "REQUIRE_APPROVAL", "")}, 1, "REQUIRE_APPROVAL", "", false, false},
		{"BLOCK beats REQUIRE_APPROVAL",
			[]Verdict{v(Structured, "REQUIRE_APPROVAL", ""), v(POSIX, "BLOCK", "")}, 1, "BLOCK", "", false, false},
		{"REQUIRE_APPROVAL is not below ALLOW (#3298's trap)",
			[]Verdict{v(Structured, "REQUIRE_APPROVAL", ""), v(POSIX, "ALLOW", "")}, 0, "REQUIRE_APPROVAL", "", false, false},
		{"earlier BLOCK beats later AUDIT",
			[]Verdict{v(Structured, "BLOCK", "", "mcp-x"), v(POSIX, "AUDIT", "")}, 0, "BLOCK", "", false, false},
		// Audit-only mode: rank on the decision before the downgrade.
		{"downgraded BLOCK beats a plain AUDIT (#4021)",
			[]Verdict{v(Structured, "AUDIT", ""), v(POSIX, "AUDIT", "BLOCK", "ts-block-rm-root")}, 1, "AUDIT", "BLOCK", false, false},
		{"two downgraded BLOCKs tie: the earlier lane",
			[]Verdict{v(Structured, "AUDIT", "BLOCK", "mcp-x"), v(POSIX, "AUDIT", "BLOCK", "ts-y")}, 0, "AUDIT", "BLOCK", false, false},
		{"kept BLOCK ties a downgraded BLOCK: the kept lane's record, as BLOCK (C1)",
			[]Verdict{v(Structured, "AUDIT", "BLOCK", "mcp-x"), v(POSIX, "BLOCK", "", "sp-y")}, 1, "BLOCK", "", true, false},
		{"two kept BLOCKs after a downgraded one: the first kept lane",
			[]Verdict{v(Structured, "AUDIT", "BLOCK", "mcp-x"), v(POSIX, "BLOCK", "", "sp-y"), v(PowerShell, "BLOCK", "", "ps-z")}, 1, "BLOCK", "", true, false},
		{"downgraded BLOCK later than a kept BLOCK: the kept one wins the tie as is",
			[]Verdict{v(Structured, "BLOCK", "", "mcp-x"), v(POSIX, "AUDIT", "BLOCK", "ts-y")}, 0, "BLOCK", "", false, false},
		// Unranked results never win.
		{"unranked later lane never wins",
			[]Verdict{v(Structured, "ALLOW", ""), v(POSIX, "BOGUS", "")}, 0, "ALLOW", "", false, false},
		{"unranked earlier lane loses to a ranked one",
			[]Verdict{v(Structured, "", ""), v(POSIX, "ALLOW", "")}, 1, "ALLOW", "", false, false},
		{"nothing ranked: the first verdict",
			[]Verdict{v(Structured, "", ""), v(POSIX, "BOGUS", "")}, 0, "", "", false, false},
		{"one verdict is itself",
			[]Verdict{v(POSIX, "BLOCK", "", "ts-block-rm-root")}, 0, "BLOCK", "", false, false},
		{"three lanes, strictest in the middle",
			[]Verdict{v(Structured, "AUDIT", ""), v(POSIX, "BLOCK", ""), v(PowerShell, "AUDIT", "")}, 1, "BLOCK", "", false, false},
	}
	for _, c := range cases {
		got := Combine(c.vs)
		if got.Winner != c.winner || got.Decision != c.decision || got.OriginalDecision != c.originalDec || got.KeptBlock != c.keptBlock || got.Floored != c.wantFloored {
			t.Errorf("%s: Combine = %+v, want winner %d decision %q original %q keptBlock %v floored %v",
				c.name, got, c.winner, c.decision, c.originalDec, c.keptBlock, c.wantFloored)
		}
	}
}

// TestCombine_AuditFloor: an uncertainty note on any lane raises an ALLOW (or
// an unranked result) to AUDIT, keeping the winner's record; it never touches
// a pick already at AUDIT or above. No lane emits such a note yet (the
// PowerShell lane's parse_error will), so the note here is a fake.
func TestCombine_AuditFloor(t *testing.T) {
	unsure := Note{Kind: "fake_parse_error", Detail: "test", Uncertain: true}
	sure := Note{Kind: "parse_fallback", Detail: "the POSIX lane's note keeps its meaning"}
	withNote := func(x Verdict, n Note) Verdict { x.Notes = []Note{n}; return x }

	cases := []struct {
		name     string
		vs       []Verdict
		winner   int
		decision string
		floored  bool
	}{
		{"uncertain later lane lifts the earlier ALLOW",
			[]Verdict{v(POSIX, "ALLOW", "", "ts-allow-readonly"), withNote(v(PowerShell, "ALLOW", ""), unsure)}, 0, "AUDIT", true},
		{"uncertain winner's own ALLOW is lifted",
			[]Verdict{withNote(v(POSIX, "ALLOW", "", "ts-allow-readonly"), unsure)}, 0, "AUDIT", true},
		{"nothing ranked and uncertain: AUDIT",
			[]Verdict{withNote(v(PowerShell, "", ""), unsure)}, 0, "AUDIT", true},
		{"a certain note is no floor",
			[]Verdict{withNote(v(POSIX, "ALLOW", "", "ts-allow-readonly"), sure), v(Structured, "ALLOW", "")}, 0, "ALLOW", false},
		{"AUDIT needs no floor",
			[]Verdict{v(Structured, "AUDIT", ""), withNote(v(PowerShell, "ALLOW", ""), unsure)}, 0, "AUDIT", false},
		{"BLOCK is untouched",
			[]Verdict{v(Structured, "AUDIT", ""), withNote(v(PowerShell, "BLOCK", "", "ps-x"), unsure)}, 1, "BLOCK", false},
		{"a downgraded BLOCK is untouched (it ranks above AUDIT)",
			[]Verdict{withNote(v(POSIX, "AUDIT", "BLOCK", "ts-x"), unsure)}, 0, "AUDIT", false},
	}
	for _, c := range cases {
		got := Combine(c.vs)
		if got.Winner != c.winner || got.Decision != c.decision || got.Floored != c.floored {
			t.Errorf("%s: Combine = %+v, want winner %d decision %q floored %v", c.name, got, c.winner, c.decision, c.floored)
		}
		if got.Floored && got.OriginalDecision != "" {
			t.Errorf("%s: a floored decision carries OriginalDecision %q", c.name, got.OriginalDecision)
		}
	}
}

// TestCombine_NeverBelowAnyLane is the raise-only property, over every pair
// and triple of decisions: the combined decision ranks at least as high as
// every lane's, so adding a lane after the old one can never lower a call.
// And the winner's record is the first lane's whenever no later lane is
// strictly stricter.
func TestCombine_NeverBelowAnyLane(t *testing.T) {
	type d struct{ dec, orig string }
	decisions := []d{{"ALLOW", ""}, {"AUDIT", ""}, {"REQUIRE_APPROVAL", ""}, {"BLOCK", ""}, {"AUDIT", "BLOCK"}, {"AUDIT", "REQUIRE_APPROVAL"}, {"", ""}}
	checked := 0
	for _, a := range decisions {
		for _, b := range decisions {
			for _, c := range decisions {
				vs := []Verdict{v(Structured, a.dec, a.orig), v(POSIX, b.dec, b.orig), v(PowerShell, c.dec, c.orig)}
				got := Combine(vs)
				gotRank := Rank(Verdict{Decision: got.Decision, OriginalDecision: got.OriginalDecision})
				for _, x := range vs {
					if Rank(x) > gotRank {
						t.Errorf("Combine(%v) = %+v ranks below lane %s (%s/%s)", vs, got, x.Lane, x.Decision, x.OriginalDecision)
					}
				}
				// The first lane's record is kept unless a later lane is
				// strictly stricter, or the first lane's BLOCK was
				// downgraded and a later lane kept its BLOCK (KeptBlock).
				want := 0
				for i, x := range vs[1:] {
					if Rank(x) > Rank(vs[want]) {
						want = i + 1
					}
				}
				if vs[want].OriginalDecision == "BLOCK" {
					for i, x := range vs {
						if i != want && x.Decision == "BLOCK" && x.OriginalDecision == "" {
							want = i
							break
						}
					}
				}
				if got.Winner != want {
					t.Errorf("Combine(%v) kept lane %d, want %d", vs, got.Winner, want)
				}
				checked++
			}
		}
	}
	if checked != 343 {
		t.Fatalf("checked %d combinations, want 343", checked)
	}
}

// TestCombine_WinnerDecides: the record kept is the one that decided the
// call. Outside the AUDIT floor, the combined decision is exactly the
// winner's own, so a receipt never names rules that decided something else
// (#4753 Opus pass 1, C1: a keep-BLOCK raise recorded the downgraded lane's
// rules under a BLOCK they did not decide). Every triple of decisions,
// including the audit-only shapes.
func TestCombine_WinnerDecides(t *testing.T) {
	type d struct{ dec, orig string }
	decisions := []d{{"ALLOW", ""}, {"AUDIT", ""}, {"REQUIRE_APPROVAL", ""}, {"BLOCK", ""}, {"AUDIT", "BLOCK"}, {"AUDIT", "REQUIRE_APPROVAL"}, {"", ""}}
	kept := 0
	for _, a := range decisions {
		for _, b := range decisions {
			for _, c := range decisions {
				vs := []Verdict{v(Structured, a.dec, a.orig), v(POSIX, b.dec, b.orig), v(PowerShell, c.dec, c.orig)}
				got := Combine(vs)
				w := vs[got.Winner]
				if got.Decision != w.Decision || got.OriginalDecision != w.OriginalDecision {
					t.Errorf("Combine(%v) = %+v: decision %s/%s, but the winner %s decided %s/%s", vs, got, got.Decision, got.OriginalDecision, w.Lane, w.Decision, w.OriginalDecision)
				}
				if got.KeptBlock {
					kept++
				}
			}
		}
	}
	if kept == 0 {
		t.Fatal("no triple exercised KeptBlock: the check is vacuous for the case it exists for")
	}
}

func TestCombine_Empty(t *testing.T) {
	if got := Combine(nil); got.Winner != -1 {
		t.Fatalf("Combine(nil) = %+v, want Winner -1", got)
	}
}

func TestReadingsDetail(t *testing.T) {
	row := []Lane{Structured, POSIX}
	cases := []struct {
		name string
		vs   []Verdict
		want string
	}{
		{"posix wins",
			[]Verdict{v(Structured, "AUDIT", ""), v(POSIX, "BLOCK", "", "ts-block-rm-root", "other")},
			"tool=Monitor; structured=AUDIT; posix=BLOCK(ts-block-rm-root); kept=posix"},
		{"structured wins a tie",
			[]Verdict{v(Structured, "AUDIT", "", "mcp-x"), v(POSIX, "AUDIT", "")},
			"tool=Monitor; structured=AUDIT(mcp-x); posix=AUDIT; kept=structured"},
		{"a lane with nothing to read",
			[]Verdict{v(Structured, "AUDIT", "")},
			"tool=Monitor; structured=AUDIT; posix=none; kept=structured"},
		{"audit-only downgrade shown",
			[]Verdict{v(Structured, "AUDIT", ""), v(POSIX, "AUDIT", "BLOCK", "ts-block-rm-root")},
			"tool=Monitor; structured=AUDIT; posix=AUDIT[was BLOCK](ts-block-rm-root); kept=posix"},
		{"block kept",
			[]Verdict{v(Structured, "AUDIT", "BLOCK", "mcp-x"), v(POSIX, "BLOCK", "", "sp-y")},
			"tool=Monitor; structured=AUDIT[was BLOCK](mcp-x); posix=BLOCK(sp-y); kept=posix; block kept"},
	}
	for _, c := range cases {
		if got := ReadingsDetail("Monitor", row, c.vs, Combine(c.vs)); got != c.want {
			t.Errorf("%s: ReadingsDetail = %q, want %q", c.name, got, c.want)
		}
	}
	floored := []Verdict{{Lane: POSIX, Decision: "ALLOW", Notes: []Note{{Kind: "fake", Uncertain: true}}}}
	if got := ReadingsDetail("Monitor", []Lane{POSIX}, floored, Combine(floored)); !strings.HasSuffix(got, "; audit floor") {
		t.Errorf("floored ReadingsDetail = %q, want it to name the floor", got)
	}
}
