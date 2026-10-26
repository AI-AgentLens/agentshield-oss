package analyzer_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// macOS /private alias parity for system paths — the fitness function for
// #4387.
//
// On macOS `/etc`, `/var` and `/tmp` are symlinks into `/private`, so
// `/private/etc/hosts` IS `/etc/hosts`. Rules are written against the short
// spelling. Before #4387 nothing canonicalized the long one, and 35 of the 43
// system-path BLOCK rules the issue sampled decided lower (33 AUDIT, 2 ALLOW)
// for the `/private` spelling of the same file.
//
// The invariant: for every BLOCK probe that names a system path under /etc or
// /var, the `/private` spelling of that path BLOCKs too. Probes are every
// shell-pack inline TP and every corpus command that BLOCKs today and carries
// an anchored `/etc` or `/var` path; each anchored occurrence is rewritten on
// its own, and all of them together when there are several. Evaluated the way
// the hook evaluates: normalize.NormalizeCommand paths + parsed tree into
// EvaluateWithParsed, so protected_paths and every analyzer get their chance.
//
// `/tmp` is the third alias and is NOT read short (see
// pathnorm.CanonicalPrivateAlias for the measured reason). Its residue is
// measured by TestPrivateAliasTmpIsABudgetedGap, on the fail-open budget.

// privateAliasRoots are the macOS symlinks into /private that production
// reads short. privateAliasTmpRoot is the third, deliberately not read short
// (see pathnorm.CanonicalPrivateAlias) and measured on its own budget below.
var (
	privateAliasRoots   = []string{"etc", "var"}
	privateAliasTmpRoot = []string{"tmp"}
)

// privateAliasOpener reports whether a `/` directly after c begins an absolute
// path in shell text. Kept local to the test (not pathnorm's table) so the
// variant generator and the production canonicalizer do not share a blind
// spot: the oracle is the end-to-end decision either way.
func privateAliasOpener(c byte) bool {
	return strings.IndexByte(" \t\n'\"=:@,{(<>|;&`", c) >= 0
}

// privateAliasEnd reports whether c ends the root segment (`/etc` followed by
// `/`, a word break, a quote, or the end of the text).
func privateAliasEnd(c byte) bool {
	return strings.IndexByte("/ \t\n'\"),;&|<>`}", c) >= 0
}

// privateAliasSites returns the byte offsets of every anchored root segment
// of roots in cmd.
func privateAliasSites(cmd string, roots []string) []int {
	var sites []int
	for i := 0; i < len(cmd); i++ {
		if cmd[i] != '/' || (i > 0 && !privateAliasOpener(cmd[i-1])) {
			continue
		}
		for _, root := range roots {
			end := i + 1 + len(root)
			if !strings.HasPrefix(cmd[i+1:], root) {
				continue
			}
			if end == len(cmd) || privateAliasEnd(cmd[end]) {
				sites = append(sites, i)
			}
		}
	}
	return sites
}

// privateAliasRewrite inserts `/private` before the root segments at sites.
func privateAliasRewrite(cmd string, sites []int) string {
	var b strings.Builder
	last := 0
	for _, s := range sites {
		b.WriteString(cmd[last:s])
		b.WriteString("/private")
		last = s
	}
	b.WriteString(cmd[last:])
	return b.String()
}

// privateAliasVariants is one variant per anchored site, plus one with every
// site rewritten when there are several.
func privateAliasVariants(cmd string, roots []string) []string {
	sites := privateAliasSites(cmd, roots)
	var out []string
	for _, s := range sites {
		out = append(out, privateAliasRewrite(cmd, []int{s}))
	}
	if len(sites) > 1 {
		out = append(out, privateAliasRewrite(cmd, sites))
	}
	return out
}

type privateAliasProbe struct{ id, cmd string }

// privateAliasProbes is every shell-pack inline TP of a BLOCK rule and every
// corpus command expected to BLOCK that names an anchored root of roots,
// deduplicated by command text.
func privateAliasProbes(t *testing.T, roots []string) (packTPs, corpus []privateAliasProbe) {
	t.Helper()
	seen := map[string]bool{}
	keep := func(cmd string) bool {
		if seen[cmd] || len(privateAliasSites(cmd, roots)) == 0 {
			return false
		}
		seen[cmd] = true
		return true
	}
	for _, r := range loadTestPolicy(t).Rules {
		if r.Tests == nil || r.Decision != policy.DecisionBlock {
			continue
		}
		for i, cmd := range r.Tests.TP {
			if keep(cmd) {
				packTPs = append(packTPs, privateAliasProbe{fmt.Sprintf("%s/TP-%d", r.ID, i+1), cmd})
			}
		}
	}
	for _, tc := range testdata.AllTestCases() {
		if tc.ExpectedDecision == "BLOCK" && keep(tc.Command) {
			corpus = append(corpus, privateAliasProbe{tc.ID, tc.Command})
		}
	}
	return packTPs, corpus
}

var privateAliasRank = map[policy.Decision]int{
	policy.DecisionAllow: 0, policy.DecisionAudit: 1,
	policy.DecisionRequireApproval: 2, policy.DecisionBlock: 3,
}

// privateAliasKnownGaps is the residual the canonical reading does not close,
// one entry per "<probe id>|<variant index>". Ratchet DOWN: an entry that
// stops leaking fails the test until removed.
var privateAliasKnownGaps = map[string]bool{}

type privateAliasSweep struct {
	probes, evaluated int
	leaks             []string
	stillOpen         map[string]bool
}

func runPrivateAliasSweep(t *testing.T, decide func(string) policy.EvalResult, probes []privateAliasProbe, roots []string, gaps map[string]bool) privateAliasSweep {
	t.Helper()
	sw := privateAliasSweep{stillOpen: map[string]bool{}}
	for _, p := range probes {
		canon := decide(p.cmd)
		if canon.Decision != policy.DecisionBlock {
			continue // a separate gap, not a leak the alias causes
		}
		sw.probes++
		for i, variant := range privateAliasVariants(p.cmd, roots) {
			sw.evaluated++
			got := decide(variant)
			if privateAliasRank[got.Decision] >= privateAliasRank[canon.Decision] {
				continue
			}
			key := fmt.Sprintf("%s|%d", p.id, i)
			if gaps[key] {
				sw.stillOpen[key] = true
				continue
			}
			sw.leaks = append(sw.leaks, fmt.Sprintf("%s: BLOCK -> %s %v : %s", key, got.Decision, got.TriggeredRules, variant))
		}
	}
	return sw
}

func pipelineDecide(engine *policy.Engine) func(string) policy.EvalResult {
	return func(cmd string) policy.EvalResult {
		n := normalize.NormalizeCommand(cmd, "")
		return engine.EvaluateWithParsed(cmd, n.Paths, n.Parsed)
	}
}

// TestPrivateAliasSystemPathParity is the ratchet: the /private spelling of a
// system path a BLOCK names must BLOCK too.
func TestPrivateAliasSystemPathParity(t *testing.T) {
	engine, _ := blockingBaseline(t)
	packTPs, corpus := privateAliasProbes(t, privateAliasRoots)
	decide := pipelineDecide(engine)

	pack := runPrivateAliasSweep(t, decide, packTPs, privateAliasRoots, privateAliasKnownGaps)
	corp := runPrivateAliasSweep(t, decide, corpus, privateAliasRoots, privateAliasKnownGaps)
	t.Logf("private-alias parity: pack TPs %d BLOCK probes / %d variants, %d leaked; corpus %d BLOCK probes / %d variants, %d leaked; %d pinned gaps still open",
		pack.probes, pack.evaluated, len(pack.leaks), corp.probes, corp.evaluated, len(corp.leaks), len(pack.stillOpen)+len(corp.stillOpen))

	assertProbeNotVacuous(t, "private-alias pack TPs", pack.evaluated, 1)
	assertProbeNotVacuous(t, "private-alias corpus", corp.evaluated, 1)

	leaks := append(append([]string{}, pack.leaks...), corp.leaks...)
	if len(leaks) > 0 {
		sort.Strings(leaks)
		t.Errorf("the macOS /private spelling of a system path decided LOWER than the path itself for %d variant(s) (#4387).\n"+
			"On macOS /etc, /var and /tmp are symlinks into /private: the variant names the same file.\n%s",
			len(leaks), joinLines(leaks))
	}
	for key := range privateAliasKnownGaps {
		if !pack.stillOpen[key] && !corp.stillOpen[key] {
			t.Errorf("known gap %q no longer leaks — remove it from privateAliasKnownGaps (ratchet down)", key)
		}
	}
}

// TestPrivateAliasPositiveControl is the sweep with the reading switched off:
// the pre-#4387 engine. It must leak — a sweep that cannot see the bypass
// with the fix removed proves nothing. Measured 2026-10-17: 118 of 373
// variants; the floor is half of that.
func TestPrivateAliasPositiveControl(t *testing.T) {
	ossbuild.SkipPremiumSized(t) // counts are measured on the full pack set (#4387)
	engine, _ := blockingBaseline(t)
	packTPs, corpus := privateAliasProbes(t, privateAliasRoots)
	off := func(cmd string) policy.EvalResult {
		n := normalize.NormalizeCommand(cmd, "")
		return engine.EvaluatePrivateAlias(cmd, n.Paths, n.Parsed, "", policy.PrivateAliasOff)
	}
	pack := runPrivateAliasSweep(t, off, packTPs, privateAliasRoots, nil)
	corp := runPrivateAliasSweep(t, off, corpus, privateAliasRoots, nil)
	leaked := len(pack.leaks) + len(corp.leaks)
	t.Logf("private-alias positive control (reading OFF): %d of %d variants leaked", leaked, pack.evaluated+corp.evaluated)
	if leaked < 59 {
		t.Errorf("positive control too weak: with the reading OFF only %d variants leaked — the sweep may no longer be able to see the #4387 bypass", leaked)
	}
}

// TestPrivateAliasNoOpControl: the identity rewrite (no sites) run through the
// same harness decides exactly as the original, rules included. If the
// harness itself manufactured differences, every leak above would be suspect.
func TestPrivateAliasNoOpControl(t *testing.T) {
	engine, _ := blockingBaseline(t)
	decide := pipelineDecide(engine)
	packTPs, _ := privateAliasProbes(t, privateAliasRoots)
	diffs := 0
	for _, p := range packTPs {
		if privateAliasRewrite(p.cmd, nil) != p.cmd {
			t.Fatalf("identity rewrite changed %q — the harness is not a no-op", p.cmd)
		}
		a, b := decide(p.cmd), decide(privateAliasRewrite(p.cmd, nil))
		if a.Decision != b.Decision || strings.Join(a.TriggeredRules, ",") != strings.Join(b.TriggeredRules, ",") {
			diffs++
			t.Errorf("%s: two evaluations of the same command disagree: %s %v vs %s %v", p.id, a.Decision, a.TriggeredRules, b.Decision, b.TriggeredRules)
		}
	}
	t.Logf("no-op control: %d probes, %d disagreements", len(packTPs), diffs)
}

// TestPrivateAliasNeverRelaxes is the raise-only half, swept over every
// aliased command the corpus can produce: each corpus command and inline TP
// and TN that carries the alias as written, plus the /private variants of
// every one of them (TNs included, so the sweep sees benign shapes too). The
// production decision is never below the as-written (pre-#4387) one. It
// holds by construction (EvaluatePrivateAlias keeps the short reading only
// when stricter); this pins the construction.
func TestPrivateAliasNeverRelaxes(t *testing.T) {
	engine, _ := blockingBaseline(t)
	type src struct {
		cmd string
		tn  bool
	}
	var srcs []src
	for _, tc := range testdata.AllTestCases() {
		srcs = append(srcs, src{tc.Command, tc.ExpectedDecision != "BLOCK"})
	}
	for _, r := range loadTestPolicy(t).Rules {
		if r.Tests == nil {
			continue
		}
		for _, c := range r.Tests.TP {
			srcs = append(srcs, src{c, false})
		}
		for _, c := range r.Tests.TN {
			srcs = append(srcs, src{c, true})
		}
	}
	// Every root, /tmp included: the reading must not lower a /tmp form
	// either, whatever it reads short.
	allRoots := append(append([]string{}, privateAliasRoots...), privateAliasTmpRoot...)
	seen := map[string]bool{}
	tried, raised, raisedFromTN := 0, 0, 0
	for _, s := range srcs {
		forms := privateAliasVariants(s.cmd, allRoots)
		if pathnorm.CanonicalPrivateAlias(s.cmd) != "" {
			forms = append(forms, s.cmd)
		}
		for _, cmd := range forms {
			if seen[cmd] {
				continue
			}
			seen[cmd] = true
			tried++
			n := normalize.NormalizeCommand(cmd, "")
			off := engine.EvaluatePrivateAlias(cmd, n.Paths, n.Parsed, "", policy.PrivateAliasOff)
			got := engine.EvaluatePrivateAlias(cmd, n.Paths, n.Parsed, "", policy.PrivateAliasStricter)
			switch {
			case privateAliasRank[got.Decision] < privateAliasRank[off.Decision]:
				t.Errorf("the /private reading LOWERED the decision %s -> %s : %s", off.Decision, got.Decision, cmd)
			case privateAliasRank[got.Decision] > privateAliasRank[off.Decision]:
				raised++
				if s.tn {
					raisedFromTN++
					t.Logf("raised from a non-BLOCK source: %s -> %s %v : %s", off.Decision, got.Decision, got.TriggeredRules, cmd)
				}
			}
		}
	}
	// Liveness floor: 2,095 aliased forms at measurement (2026-10-17).
	assertProbeNotVacuous(t, "private-alias never-relaxes", tried, 1500)
	t.Logf("private-alias never-relaxes: %d aliased commands; %d raised (%d of them from a non-BLOCK source), 0 lowered", tried, raised, raisedFromTN)
}

// TestPrivateAliasKeepsLiteralPrivateRules is the additive guard on the
// shipped packs. Several rules match `/private` literally; rewriting the
// command in place would switch them off. For every inline TP of such a rule,
// the production result equals the as-written one exactly (decision and rule
// set) unless the short reading is strictly stricter, and the rule itself is
// still named whenever the as-written evaluation named it.
func TestPrivateAliasKeepsLiteralPrivateRules(t *testing.T) {
	engine, _ := blockingBaseline(t)
	checked, rules := 0, 0
	for _, r := range loadTestPolicy(t).Rules {
		if r.Tests == nil || !strings.Contains(r.Match.CommandRegex, "/private") {
			continue
		}
		rules++
		for _, cmd := range r.Tests.TP {
			if pathnorm.CanonicalPrivateAlias(cmd) == "" {
				continue
			}
			checked++
			n := normalize.NormalizeCommand(cmd, "")
			off := engine.EvaluatePrivateAlias(cmd, n.Paths, n.Parsed, "", policy.PrivateAliasOff)
			got := engine.EvaluatePrivateAlias(cmd, n.Paths, n.Parsed, "", policy.PrivateAliasStricter)
			if privateAliasRank[got.Decision] > privateAliasRank[off.Decision] {
				continue // raised: the stricter reading's own record is the evidence
			}
			if got.Decision != off.Decision || !sameRuleSet(got.TriggeredRules, off.TriggeredRules) {
				t.Errorf("%s: %q decides %s %v; as written it decides %s %v — at an equal decision the as-written record must be kept",
					r.ID, cmd, got.Decision, got.TriggeredRules, off.Decision, off.TriggeredRules)
			}
			if contains(off.TriggeredRules, r.ID) && !contains(got.TriggeredRules, r.ID) {
				t.Errorf("%s: no longer fires on its own TP %q", r.ID, cmd)
			}
		}
	}
	if rules == 0 || checked == 0 {
		t.Fatalf("no shipped rule matches /private literally with an aliased TP (%d rules, %d TPs) — the guard measures nothing", rules, checked)
	}
	t.Logf("literal-/private rules: %d rules, %d aliased TPs, all keep their as-written result", rules, checked)
}

// TestPrivateAliasParityRegexFallback runs the ratchet through the regex-only
// fallback engine (no analyzer pipeline). EvaluatePrivateAlias sits above
// both evaluation paths, so the reading must reach this one too (#3717).
func TestPrivateAliasParityRegexFallback(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(t)
	decide := func(cmd string) policy.EvalResult {
		n := normalize.NormalizeCommand(cmd, "")
		return engine.EvaluateWithParsed(cmd, n.Paths, n.Parsed)
	}
	packTPs, corpus := privateAliasProbes(t, privateAliasRoots)
	pack := runPrivateAliasSweep(t, decide, packTPs, privateAliasRoots, privateAliasFallbackKnownGaps)
	corp := runPrivateAliasSweep(t, decide, corpus, privateAliasRoots, privateAliasFallbackKnownGaps)
	assertProbeNotVacuous(t, "private-alias regex fallback", pack.evaluated+corp.evaluated, 1)
	leaks := append(append([]string{}, pack.leaks...), corp.leaks...)
	t.Logf("private-alias regex fallback: %d variants of BLOCKing probes, %d leaked", pack.evaluated+corp.evaluated, len(leaks))
	if len(leaks) > 0 {
		sort.Strings(leaks)
		t.Errorf("regex-only fallback: %d /private variant(s) of a BLOCKing command decided lower (#4387):\n%s", len(leaks), joinLines(leaks))
	}
	for key := range privateAliasFallbackKnownGaps {
		if !pack.stillOpen[key] && !corp.stillOpen[key] {
			t.Errorf("known gap %q no longer leaks on the fallback path — remove it (ratchet down)", key)
		}
	}
}

// privateAliasFallbackKnownGaps: as privateAliasKnownGaps, for the regex-only
// fallback engine.
var privateAliasFallbackKnownGaps = map[string]bool{}

// TestPrivateAliasTmpIsABudgetedGap measures the alias production does NOT
// read short: the /private spelling of a /tmp path. It is a documented gap,
// not a pass: reading /private/tmp short closes these, and was measured to add
// 22 new BLOCKs on ten days of real traffic, all ts-block-home-redirect on an
// agent's scratch HOME under Claude Code's `/private/tmp/claude-501/`. Whether
// to take that is Gary's call (#4387). Until then the residue is on the
// fail-open budget, so it can only shrink, and the sweep fails if the
// canonicalizer starts reading /tmp short without this budget moving with it.
func TestPrivateAliasTmpIsABudgetedGap(t *testing.T) {
	ossbuild.SkipPremiumSized(t) // counts are measured on the full pack set (#4387)
	engine, _ := blockingBaseline(t)
	packTPs, corpus := privateAliasProbes(t, privateAliasTmpRoot)
	decide := pipelineDecide(engine)
	pack := runPrivateAliasSweep(t, decide, packTPs, privateAliasTmpRoot, nil)
	corp := runPrivateAliasSweep(t, decide, corpus, privateAliasTmpRoot, nil)
	leaked, evaluated := len(pack.leaks)+len(corp.leaks), pack.evaluated+corp.evaluated
	// Measured 2026-10-17: 117 of 890 variants; with /tmp read short, 0.
	const maxLeaksTmpAlias = 117
	assertProbeNotVacuous(t, "private-alias /tmp gap", evaluated, 1)
	t.Logf("private-alias /tmp gap: %d of %d /private/tmp variants of BLOCKing probes decide lower (budget %d)", leaked, evaluated, maxLeaksTmpAlias)
	if leaked > maxLeaksTmpAlias {
		all := append(append([]string{}, pack.leaks...), corp.leaks...)
		sort.Strings(all)
		t.Errorf("%d /private/tmp variants leak, over the budget of %d:\n%s", leaked, maxLeaksTmpAlias, joinLines(all))
	}
	if leaked < maxLeaksTmpAlias {
		t.Errorf("only %d /private/tmp variants leak, under the budget of %d: ratchet maxLeaksTmpAlias down (and the fail-open baseline with it)", leaked, maxLeaksTmpAlias)
	}
}
