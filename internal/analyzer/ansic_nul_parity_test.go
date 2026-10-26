package analyzer_test

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// $'...' byte-0 escape parity — the fitness function for #4540.
//
// bash ends a $'...' body at the first escape that decodes to byte 0, so a
// NUL spliced into a command word (`r` + $'\0' + `m`) runs the same program
// as the word with an empty $'...' span in that place. The invariant: for
// every corpus command that BLOCKs today and starts with a plain command
// word, the NUL-spliced spelling decides at least what the empty-span
// spelling decides. The empty-span spelling is the oracle, not the original
// command: an empty quote splice has gaps of its own that are not this
// issue's (they are the same with or without a NUL), and comparing against
// the original would count them here.
//
// The splice rotates through every byte-0 spelling pathnorm.ANSICNULIndex
// lists, so each one is exercised across the corpus.

var ansicNULSpellings = []string{
	`\0`, `\00`, `\000`, `\400`, `\x0`, `\x00`, `\u0`, `\u0000`, `\U0`,
	`\U00000000`, `\c@`, "\\c`", `\c `,
}

var ansicNULVerbRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.+-]+`)

// ansicNULSplice returns cmd with span inserted after the first character of
// its leading command word, or "" when cmd does not start with a plain word.
func ansicNULSplice(cmd, span string) string {
	verb := ansicNULVerbRe.FindString(cmd)
	if verb == "" {
		return ""
	}
	if rest := cmd[len(verb):]; rest != "" && !strings.ContainsAny(rest[:1], " \t\n;|&") {
		return ""
	}
	return cmd[:1] + span + cmd[1:]
}

func ansicNULDecideWith(engine *policy.Engine, mode policy.ANSICNULMode) func(string) policy.EvalResult {
	return func(cmd string) policy.EvalResult {
		n := normalize.NormalizeCommand(cmd, "")
		return engine.EvaluateANSICNUL(cmd, n.Paths, n.Parsed, "", mode)
	}
}

type ansicNULSweep struct {
	probes, variants int
	leaks            []string
}

func runANSICNULSweep(t *testing.T, decide func(string) policy.EvalResult, oracle func(string) policy.EvalResult, probes []testdata.TestCase) ansicNULSweep {
	t.Helper()
	var sw ansicNULSweep
	for i, tc := range probes {
		spelling := ansicNULSpellings[i%len(ansicNULSpellings)]
		variant := ansicNULSplice(tc.Command, "$'"+spelling+"'")
		// A command that already carries a byte-0 escape has a cut reading
		// of its own, so the empty-span spelling is not bash's reading of
		// the variant; TestANSICNULNeverRelaxes covers those.
		if variant == "" || shellparse.ANSICNULReading(tc.Command) != "" {
			continue
		}
		sw.probes++
		empty := oracle(ansicNULSplice(tc.Command, "$''"))
		sw.variants++
		got := decide(variant)
		if privateAliasRank[got.Decision] < privateAliasRank[empty.Decision] {
			sw.leaks = append(sw.leaks, fmt.Sprintf("%s: %s (empty span) -> %s %v : %s", tc.ID, empty.Decision, got.Decision, got.TriggeredRules, variant))
		}
	}
	return sw
}

// TestANSICNULVerbSpliceParity is the ratchet: the NUL-spliced spelling of a
// BLOCKing command decides at least what bash's own reading of it decides.
func TestANSICNULVerbSpliceParity(t *testing.T) {
	engine, baseline := blockingBaseline(t)
	decide := ansicNULDecideWith(engine, policy.ANSICNULStricter)
	sw := runANSICNULSweep(t, decide, decide, baseline)
	t.Logf("ansic-nul verb-splice parity: %d BLOCK probes, %d variants, %d leaked", sw.probes, sw.variants, len(sw.leaks))
	// Liveness floor: 2,652 variants at measurement (2026-10-25); the OSS tree
	// (community packs only, fewer BLOCK probes) measured 1,755 on 2026-10-26.
	floor := 2000
	if !premiumPacksPresent() {
		floor = 1300
	}
	assertProbeNotVacuous(t, "ansic-nul verb splice", sw.variants, floor)
	if len(sw.leaks) > 0 {
		sort.Strings(sw.leaks)
		t.Errorf("a NUL escape spliced into the command word decided LOWER than bash's reading of the same command for %d variant(s) (#4540):\n%s",
			len(sw.leaks), joinLines(sw.leaks))
	}
}

// TestANSICNULPositiveControl is the sweep with the cut reading switched off:
// the pre-#4540 engine. It must leak — a sweep that cannot see the bypass
// with the fix removed proves nothing.
func TestANSICNULPositiveControl(t *testing.T) {
	engine, baseline := blockingBaseline(t)
	off := ansicNULDecideWith(engine, policy.ANSICNULOff)
	sw := runANSICNULSweep(t, off, off, baseline)
	t.Logf("ansic-nul positive control (reading OFF): %d of %d variants leaked", len(sw.leaks), sw.variants)
	// Measured 2026-10-25: 1,555 of 2,652. The floor is half of that.
	if len(sw.leaks) < 775 {
		t.Errorf("positive control too weak: with the reading OFF only %d variants leaked — the sweep may no longer be able to see the #4540 bypass", len(sw.leaks))
	}
}

// TestANSICNULNeverRelaxes is the raise-only half: over every corpus command
// and inline TP and TN, plus a NUL-spliced and a NUL-truncated spelling of
// each, the production decision is never below the as-written (pre-#4540)
// one. It holds by construction (EvaluateANSICNUL keeps the cut reading only
// when stricter); this pins the construction, TNs included so benign shapes
// are in the sweep.
func TestANSICNULNeverRelaxes(t *testing.T) {
	engine, _ := blockingBaseline(t)
	var srcs []string
	for _, tc := range testdata.AllTestCases() {
		srcs = append(srcs, tc.Command)
	}
	for _, r := range loadTestPolicy(t).Rules {
		if r.Tests == nil {
			continue
		}
		srcs = append(srcs, r.Tests.TP...)
		srcs = append(srcs, r.Tests.TN...)
	}
	seen := map[string]bool{}
	tried, raised := 0, 0
	off := ansicNULDecideWith(engine, policy.ANSICNULOff)
	on := ansicNULDecideWith(engine, policy.ANSICNULStricter)
	for i, src := range srcs {
		// One form per source, so the sweep stays cheap: the source itself
		// when it already carries a byte-0 escape, otherwise a NUL spliced
		// into its command word or ending a span around it, alternately.
		spelling := ansicNULSpellings[i%len(ansicNULSpellings)]
		cmd := ""
		switch verb := ansicNULVerbRe.FindString(src); {
		case shellparse.ANSICNULReading(src) != "":
			cmd = src
		case i%2 == 0:
			cmd = ansicNULSplice(src, "$'"+spelling+"'")
		case verb != "" && ansicNULSplice(src, "") != "":
			cmd = "$'" + verb + spelling + "zz'" + src[len(verb):]
		}
		if cmd == "" || seen[cmd] {
			continue
		}
		seen[cmd] = true
		tried++
		a, b := off(cmd), on(cmd)
		switch {
		case privateAliasRank[b.Decision] < privateAliasRank[a.Decision]:
			t.Errorf("the cut reading LOWERED the decision %s -> %s : %s", a.Decision, b.Decision, cmd)
		case privateAliasRank[b.Decision] > privateAliasRank[a.Decision]:
			raised++
		}
	}
	// Liveness floor: 14,165 forms at measurement (2026-10-25); the OSS tree
	// measured 9,716 on 2026-10-26.
	floor := 10000
	if !premiumPacksPresent() {
		floor = 7000
	}
	assertProbeNotVacuous(t, "ansic-nul never-relaxes", tried, floor)
	t.Logf("ansic-nul never-relaxes: %d commands; %d raised, 0 lowered", tried, raised)
}

// TestANSICNULKeepsBenignDecisions: benign commands that carry a byte-0
// escape (or a nearby control escape) keep exactly their as-written decision
// and record. `read -d $'\0'` is the canonical NUL-delimited read loop, and
// the IFS shape is #4526's.
func TestANSICNULKeepsBenignDecisions(t *testing.T) {
	engine, _ := blockingBaseline(t)
	off := ansicNULDecideWith(engine, policy.ANSICNULOff)
	on := ansicNULDecideWith(engine, policy.ANSICNULStricter)
	cuts := 0
	for _, cmd := range []string{
		`while IFS= read -r -d $'\0' f; do echo "$f"; done < list.txt`,
		`read -d $'\0' line < file.bin`,
		`find . -name '*.log' -print0 | while IFS= read -r -d $'\0' f; do wc -l "$f"; done`,
		`IFS=$'\037' read -r a b <<< "$row"`,
		`tr $'\0' $'\n' < records.bin`,
		`printf $'a\0b' > out.bin`,
		`sort -z -t $'\0' names.bin`,
	} {
		if shellparse.ANSICNULReading(cmd) != "" {
			cuts++
		}
		a, b := off(cmd), on(cmd)
		if a.Decision != b.Decision || strings.Join(a.TriggeredRules, ",") != strings.Join(b.TriggeredRules, ",") {
			t.Errorf("%q: %s %v as written, %s %v with the cut reading; want unchanged", cmd, a.Decision, a.TriggeredRules, b.Decision, b.TriggeredRules)
		}
	}
	// Non-vacuous: most rows do run the cut reading.
	if cuts < 5 {
		t.Errorf("only %d rows carry a byte-0 escape; the test no longer exercises the cut reading", cuts)
	}
}
