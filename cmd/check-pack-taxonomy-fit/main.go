// Package main implements a CI guardrail that catches SEMANTIC-FIT drift
// between a taxonomy node's prose and the AgentShield PACK RULES that point at
// it.
//
// The gap it closes (issue #3333)
// -------------------------------
// Every semantic-consistency gate in this ecosystem reads the Semgrep tree in
// AI_risk_compliance (`rules/`). None of them reads `packs/`:
//
//	check-taxonomy-fit          comply   rules/   does node prose describe its rules?
//	check-sibling-node-agreement comply  rules/   do language variants agree on a node?
//	check-risk-cap-severity     comply   rules/   ERROR rule on a risk_cap: low node?
//	check-taxonomy-refs.sh      SHIELD   packs/   does the ref RESOLVE? (existence only)
//
// That is backwards from where the stakes are. Since aiagentlens#78/#81 the
// SaaS resolves a finding's compliance controls THROUGH its taxonomy ref, and
// it is the RUNTIME rules whose ref rides the wire onto a customer's compliance
// dashboard. The refs with the shortest path to an auditor were the ones
// nothing checked for meaning.
//
// It is not hypothetical. `governance-risk/ai-governance-gap/ai-uncontrolled-
// invocations` was audited on 2026-07-28 (comply#3385), every Semgrep rule was
// re-homed, and the node's own prose was updated to say "no Semgrep rule
// references this entry" — while three pack rules pointed at it the whole time.
// Two did not belong (#3332, comply#3653). Worse, draining its Semgrep
// referrers to zero dropped it BELOW the comply gate's eligibility bar: the
// more thoroughly it was cleaned, the less anything looked at it.
//
// What this checks
// ----------------
// For every taxonomy node referenced by at least -min-refs pack FILES, it
// measures lexical overlap between each referring rule and the node's prose,
// and flags the node when at least -misfit-frac of those files share ZERO
// distinctive terms with it.
//
// No LLM, no network, no model: a deterministic bag-of-words comparison, for
// the same reason the comply-side gate is one (reproducible attestation,
// air-gapped CI, per-scan cost — CLAUDE.md, ADG-lite invariant). Same corpus
// in, same output out; asserted by TestDeterminism.
//
// Where this DIVERGES from the comply-side gate, and why
// ------------------------------------------------------
// This is a deliberate port, not a copy. Two differences are load-bearing, and
// both were named as prerequisites in #3333.
//
//  1. THE RULE SIDE SCORES THE `match:` BLOCK, not just the ID and never the
//     `reason:`. A Semgrep rule carries its semantics in `patterns:` and states
//     them again in prose, so the comply scorer gets away with reading the ID.
//     A Shield rule carries its semantics in `match:` — path globs, tool-name
//     regexes, `args_match` keys — and its `reason:` describes the BYPASS AXIS
//     rather than the target. #3333 measured this: a crude ID+reason scorer put
//     mcp-alt-path-arg-credential-access.yaml at 7/7 misfit against the SSH
//     private-key node, because those rules' prose is about alternative
//     argument key names (`file`, `filepath`, `src`) while the credential
//     targeting they key on lives entirely in `match:`. That is a systematic
//     false-positive class a naive port would have inherited whole.
//
//  2. TERMS ARE FILTERED BY *TWO* DOCUMENT FREQUENCIES, not one. The comply
//     gate drops terms common across taxonomy NODES. That is necessary here
//     too, but not sufficient: Shield rule IDs and match blocks are full of
//     structural boilerplate that is rare in taxonomy prose and therefore reads
//     as highly distinctive — `block`, `mcp`, `sec`, `prem`, `regex`,
//     `pattern`, `any`. Scoring those would let a rule "fit" any node that
//     happens to mention a pattern. So a term is also dropped when it appears
//     in at least -rule-generic-df of all pack RULES.
//
//     The filter is corpus-derived on both axes, exactly like the comply gate's
//     single one, and for the same reason: a hand-written stoplist is a knob
//     somebody can turn until their favourite case passes. Nobody tunes a
//     document frequency.
//
// Everything else is ported verbatim and deliberately so — the majority-zero
// aggregation, the 5-character prefix match, the better-home precision test,
// the advisory-first baseline ratchet with STALE detection. Those were
// calibrated against a real corpus in comply#3382 and re-deriving them here
// would be re-litigating a settled decision, not evolving it.
//
// Layering (workspace CLAUDE.md, invariant 3)
// -------------------------------------------
// This runs HERE, in Shield, against a taxonomy tree the CALLER supplies —
// the same shape as scripts/check-taxonomy-refs.sh, and wired into that same
// CI job, which already sparse-clones the tree. It adds no new cross-repo
// coupling: it reads a path. The tempting alternative — a comply CI job that
// clones Shield and scores packs/ — would put the private product in the OSS
// repo's build path and depend on a moving branch. #3333 rules it out
// explicitly, and so does this comment, at the point of coupling.
//
// Known limits, stated up front
// -----------------------------
// PRECISION is the honest weakness of a lexical check, and #3333 already
// measured one false positive before a line of this existed. Hand-verified
// verdicts for every flag are recorded in baseline.txt. Read them before
// trusting a flag; the check exists to raise a node for HUMAN review, not to
// decide.
//
// RECALL is worse than precision and always will be. A bag of words cannot
// tell "the node mentions credentials in passing" from "the node is about
// credentials". A clean run means nothing was caught, not that nothing is
// wrong.
//
// Bootstrap or refresh:
//
//	go run ./cmd/check-pack-taxonomy-fit -taxonomy <dir> -write-baseline
//
// -testdata mode (#3336)
// -----------------------
// The `-testdata` flag scores internal/analyzer/testdata's TestCase.TaxonomyRef
// against the same node prose, instead of pack rules. `internal/analyzer/testdata`
// carries a TaxonomyRef per case and nothing checked it describes the command —
// found when the whole PackageRegistryPublishCases block sat on the
// CI-config-injection node, discovered only because the last legitimate pack
// rule referencing that node moved elsewhere. Term harvesting reuses tokenize
// on Command + Description; cases group by a coarse ID-derived key
// (testdataGroupKey) approximating "which declared *Cases variable this case
// lives in" without parsing Go source. Only Classification == "TP" cases vote
// — a TN case is deliberately unlike its node. Separate baseline file
// (testdata-baseline.txt), separate bootstrap:
//
//	go run ./cmd/check-pack-taxonomy-fit -testdata -taxonomy <dir> -write-baseline
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// ---------------------------------------------------------------------------
// Tunables. The node-side numbers are inherited from comply#3382, where they
// were read off a live corpus. The rule-side one is calibrated here — see the
// PR for #3333.
// ---------------------------------------------------------------------------

const (
	// defaultMinRefs — a node needs this many referring pack FILES before "most
	// of the rules pointing here don't fit" is a statement about the node
	// rather than about one rule.
	defaultMinRefs = 3

	// defaultMisfitFrac — flag when at least this fraction of referring files
	// share zero distinctive terms with the node's prose.
	defaultMisfitFrac = 0.30

	// defaultGenericDF — a term appearing in this fraction of taxonomy NODES or
	// more is corpus-generic and carries no discriminative power.
	defaultGenericDF = 0.20

	// defaultRuleGenericDF — a term appearing in this fraction of pack RULES or
	// more is Shield-side structural boilerplate (`block`, `mcp`, `regex`,
	// `pattern`), not a claim about the threat. See divergence 2 in the package
	// doc. Set high deliberately: dropping a term can only ever make this check
	// quieter, and the terms above sit far above any threat vocabulary.
	defaultRuleGenericDF = 0.15

	// prefixMatchLen — two terms of at least this length sharing this many
	// leading characters are treated as one term. Cheap morphology, not a
	// stemmer: catches credential/credentials, misses invoke/invocation.
	prefixMatchLen = 5

	// defaultAltMinOverlap — the better-home test. A rule sharing nothing with
	// its declared node counts as a MISFIT only if some OTHER node shares at
	// least this many of its distinctive terms. One shared word is a
	// coincidence; two is a claim about which concept the text describes.
	defaultAltMinOverlap = 2
)

// stopwords are English function words. Everything else generic is removed by
// the two corpus-derived document-frequency filters, not by hand.
var stopwords = map[string]bool{
	"a": true, "an": true, "and": true, "are": true, "as": true, "at": true,
	"be": true, "but": true, "by": true, "can": true, "for": true, "from": true,
	"has": true, "have": true, "in": true, "into": true, "is": true, "it": true,
	"its": true, "not": true, "of": true, "on": true, "or": true, "that": true,
	"the": true, "their": true, "then": true, "this": true, "to": true,
	"via": true, "when": true, "which": true, "with": true, "without": true,
}

// ---------------------------------------------------------------------------
// Corpus model
// ---------------------------------------------------------------------------

type node struct {
	ID    string
	Name  string
	Path  string
	Terms map[string]bool
}

type packRule struct {
	ID    string
	Terms []string
}

// referent is one PACK FILE pointing at a node. The file, not the rule ID, is
// the unit of the check: per-ID, a pack that enumerates one rule per argument
// key would outvote every other referrer on rule count alone.
type referent struct {
	File  string
	Rules []packRule

	BestID    string
	Matched   []string
	Total     int
	Scoreable bool

	AltNode      string
	AltShared    []string
	NoBetterFit  bool
	MajorityZero bool
}

func (r referent) misfit() bool {
	return r.Scoreable && len(r.Matched) == 0 && !r.NoBetterFit
}

// votes reports whether this referent counts toward the node's score. A file
// abstains when its rules carry no distinctive terms, or when they share
// nothing with ANY node — a threat the taxonomy has no vocabulary for is a
// coverage question, not a semantic-fit defect.
func (r referent) votes() bool { return r.Scoreable && !r.NoBetterFit }

type finding struct {
	Node       node
	Refs       []referent
	Misfits    int
	NRefs      int
	MisfitFrac float64
}

// ---------------------------------------------------------------------------

func main() {
	taxDir := flag.String("taxonomy", "", "Directory containing the AI_risk_compliance taxonomy YAML tree (required)")
	packsDir := flag.String("packs", "packs", "Directory containing AgentShield policy packs")
	testdataMode := flag.Bool("testdata", false, "Score internal/analyzer/testdata TestCase.TaxonomyRef instead of pack rules (#3336)")
	baselinePath := flag.String("baseline", "", "Baseline file of known, tracked flags (default depends on -testdata)")
	minRefs := flag.Int("min-refs", defaultMinRefs, "Minimum referring pack files before a node is eligible")
	misfitFrac := flag.Float64("misfit-frac", defaultMisfitFrac, "Flag when this fraction of referents share zero distinctive terms")
	genericDF := flag.Float64("generic-df", defaultGenericDF, "Drop terms appearing in this fraction of taxonomy nodes or more")
	ruleGenericDF := flag.Float64("rule-generic-df", defaultRuleGenericDF, "Drop terms appearing in this fraction of pack rules or more")
	altMinOverlap := flag.Int("alt-min-overlap", defaultAltMinOverlap, "Shared terms with some OTHER node required before a zero-overlap referent counts as a misfit")
	writeBaseline := flag.Bool("write-baseline", false, "Rewrite the baseline from the current corpus")
	verbose := flag.Bool("v", false, "Print a summary even when clean")
	dump := flag.Bool("dump", false, "Calibration: print every eligible node with its score, sorted")
	explain := flag.String("explain", "", "Calibration: print per-rule detail for one node ID")
	dumpTerms := flag.Int("dump-terms", 0, "Calibration: print the N most frequent rule-side terms and exit")
	flag.Parse()

	if *taxDir == "" {
		fmt.Fprintln(os.Stderr, "FAIL: -taxonomy is required (path to AI_risk_compliance/taxonomy)")
		os.Exit(2)
	}
	if fi, err := os.Stat(*taxDir); err != nil || !fi.IsDir() {
		fmt.Fprintf(os.Stderr, "FAIL: -taxonomy %q is not a directory\n", *taxDir)
		os.Exit(2)
	}
	if *baselinePath == "" {
		if *testdataMode {
			*baselinePath = "cmd/check-pack-taxonomy-fit/testdata-baseline.txt"
		} else {
			*baselinePath = "cmd/check-pack-taxonomy-fit/baseline.txt"
		}
	}

	an, err := analyze(*taxDir, *packsDir, *genericDF, *ruleGenericDF, *altMinOverlap, *testdataMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(2)
	}
	nodes, refs, nRules := an.Nodes, an.Refs, an.NRules
	nodeDF, ruleDF, nodeCut, ruleCut := an.NodeDF, an.RuleDF, an.NodeCut, an.RuleCut

	if *dumpTerms > 0 {
		dumpTermFrequencies(ruleDF, nRules, *dumpTerms, ruleCut)
		return
	}

	scored := an.Scored

	if *explain != "" {
		explainNode(scored, *explain, nodeDF, ruleDF, nodeCut, ruleCut)
		return
	}
	if *dump {
		dumpAll(scored, *minRefs, len(nodes), len(refs), nRules, nodeCut, ruleCut)
		return
	}

	flagged := an.flag(*minRefs, *misfitFrac)

	if *writeBaseline {
		n, err := writeBaselineFile(*baselinePath, flagged, *testdataMode)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: writing baseline: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("wrote %d baselined pair(s) to %s\n", n, *baselinePath)
		return
	}

	baseline, err := loadBaseline(*baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: reading baseline %s: %v\n", *baselinePath, err)
		os.Exit(2)
	}

	fresh, stale := reconcile(flagged, baseline)

	fail := false
	if len(fresh) > 0 {
		fail = true
		fmt.Printf("FAIL: %d NEW semantic-fit misfit pair(s) in packs/\n\n", len(fresh))
		for _, f := range flagged {
			shown := false
			for _, r := range f.Refs {
				if r.misfit() && !baseline[pairKey(f.Node.ID, r.File)] {
					if !shown {
						printFinding(f)
						shown = true
					}
				}
			}
		}
		fmt.Println("Each pair above is a pack rule whose taxonomy ref rides the wire to a")
		fmt.Println("customer's compliance dashboard while the node's prose describes a")
		fmt.Println("different threat. Two ways to fix, both improving the attestation text:")
		fmt.Println("  1. Point the rule at a node whose prose describes what it detects.")
		fmt.Println("  2. Broaden the node's prose so it genuinely covers what it has accreted.")
		fmt.Println("Adding a baseline line instead requires Gary + Kai sign-off.")
		fmt.Println()
	}
	if len(stale) > 0 {
		fail = true
		fmt.Printf("FAIL: %d STALE baseline entr(y/ies) — the pair no longer misfits.\n", len(stale))
		fmt.Println("The ratchet turns one way: delete these lines from", *baselinePath)
		for _, k := range stale {
			fmt.Println("  -", k)
		}
		fmt.Println()
	}
	if fail {
		os.Exit(1)
	}

	if *verbose || true {
		itemNoun, unit := "rule(s)", "pack file-refs"
		if *testdataMode {
			itemNoun, unit = "TP case(s)", "testdata group-refs"
		}
		fmt.Printf("OK: %d taxonomy node(s), %d %s across %d %s; %d baselined pair(s), 0 new, 0 stale\n",
			len(nodes), nRules, itemNoun, countRefFiles(refs), unit, len(baseline))
	}
}

// analysis is everything one pass over the two corpora produces. Extracted from
// main so tests can drive the whole pipeline against a synthetic corpus without
// exec'ing a binary or touching the real trees.
type analysis struct {
	Nodes            map[string]node
	Refs             map[string][]referent
	NRules           int
	NodeDF, RuleDF   map[string]int
	NodeCut, RuleCut int
	Scored           []finding
}

func analyze(taxDir, packsDir string, genericDF, ruleGenericDF float64, altMinOverlap int, useTestdata bool) (*analysis, error) {
	nodes, err := loadNodes(taxDir)
	if err != nil {
		return nil, fmt.Errorf("loading taxonomy: %w", err)
	}

	var refs map[string][]referent
	var nRules int
	source := packsDir
	if useTestdata {
		source = "internal/analyzer/testdata"
		refs, nRules, err = loadTestdataRefs()
	} else {
		refs, nRules, err = loadRefs(packsDir)
	}
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", source, err)
	}

	// Loading zero of either side means a directory moved or a key was renamed
	// — never that the corpus is clean. A gate that cannot fail is worse than
	// no gate (CLAUDE.md, "Gates must be able to fail", #3130), and a gate that
	// silently vouches for an empty corpus is the same defect wearing a hat.
	if len(nodes) == 0 {
		return nil, fmt.Errorf("found no taxonomy nodes under %s — cannot vouch for anything", taxDir)
	}
	if nRules == 0 {
		noun := "taxonomy-bearing rules"
		if useTestdata {
			noun = "taxonomy-bearing TP test cases"
		}
		return nil, fmt.Errorf("found no %s under %s — cannot vouch for anything", noun, source)
	}

	a := &analysis{Nodes: nodes, Refs: refs, NRules: nRules}
	a.NodeCut = int(genericDF * float64(len(nodes)))
	if a.NodeCut < 1 {
		a.NodeCut = 1
	}
	a.RuleCut = int(ruleGenericDF * float64(nRules))
	if a.RuleCut < 1 {
		a.RuleCut = 1
	}
	a.NodeDF = nodeDocumentFrequency(nodes)
	a.RuleDF = ruleDocumentFrequency(refs)
	a.Scored = score(nodes, refs, a.NodeDF, a.RuleDF, a.NodeCut, a.RuleCut, altMinOverlap)
	return a, nil
}

// flag returns the findings that cross both thresholds.
func (a *analysis) flag(minRefs int, misfitFrac float64) []finding {
	var out []finding
	for _, f := range a.Scored {
		if f.NRefs >= minRefs && f.MisfitFrac >= misfitFrac {
			out = append(out, f)
		}
	}
	return out
}

// reconcile splits the live misfit pairs against the baseline into the ones
// that are NEW (fail: undocumented drift) and the baselined ones that no longer
// misfit (fail: the ratchet turns one way, so a fixed pair must lose its line).
func reconcile(flagged []finding, baseline map[string]bool) (fresh, stale []string) {
	live := map[string]bool{}
	for _, f := range flagged {
		for _, r := range f.Refs {
			if !r.misfit() {
				continue
			}
			k := pairKey(f.Node.ID, r.File)
			live[k] = true
			if !baseline[k] {
				fresh = append(fresh, k)
			}
		}
	}
	for k := range baseline {
		if !live[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(fresh)
	sort.Strings(stale)
	return fresh, stale
}

func countRefFiles(refs map[string][]referent) int {
	n := 0
	for _, rs := range refs {
		n += len(rs)
	}
	return n
}

func printFinding(f finding) {
	fmt.Printf("  %s\n    %s  (%d/%d referring files share zero distinctive terms)\n",
		f.Node.ID, f.Node.Name, f.Misfits, f.NRefs)
	for _, r := range f.Refs {
		if !r.misfit() {
			continue
		}
		fmt.Printf("      :: %s\n", r.File)
		fmt.Printf("         rule %s — terms: %s\n", r.BestID, strings.Join(termsOf(r), ", "))
		if r.AltNode != "" {
			fmt.Printf("         also in %s (shares: %s)\n", r.AltNode, strings.Join(r.AltShared, ", "))
		}
	}
	fmt.Println()
}

func termsOf(r referent) []string {
	for _, rule := range r.Rules {
		if rule.ID == r.BestID {
			return rule.Terms
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Scoring — ported from comply cmd/check-taxonomy-fit, with the second
// (rule-side) document-frequency filter added.
// ---------------------------------------------------------------------------

func score(nodes map[string]node, refs map[string][]referent, nodeDF, ruleDF map[string]int, nodeCut, ruleCut, altMinOverlap int) []finding {
	var out []finding
	ids := make([]string, 0, len(refs))
	for id := range refs {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		n, ok := nodes[id]
		if !ok {
			// Unresolved refs are check-taxonomy-refs.sh's job, and it fails
			// the build on them. Skipping here keeps one defect in one gate.
			continue
		}
		f := finding{Node: n}
		for _, r := range refs[id] {
			r = scoreReferent(r, n, nodeDF, ruleDF, nodeCut, ruleCut)
			if r.Scoreable && len(r.Matched) == 0 {
				r = findBetterHome(r, nodes, id, nodeDF, ruleDF, nodeCut, ruleCut, altMinOverlap)
			}
			f.Refs = append(f.Refs, r)
		}
		for _, r := range f.Refs {
			if r.votes() {
				f.NRefs++
				if r.misfit() {
					f.Misfits++
				}
			}
		}
		if f.NRefs > 0 {
			f.MisfitFrac = float64(f.Misfits) / float64(f.NRefs)
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].MisfitFrac != out[j].MisfitFrac {
			return out[i].MisfitFrac > out[j].MisfitFrac
		}
		return out[i].Node.ID < out[j].Node.ID
	})
	return out
}

// distinctive drops terms that are common in taxonomy prose (they prove nothing
// about fit) and terms that are common in pack rules (Shield boilerplate).
func distinctive(terms []string, nodeDF, ruleDF map[string]int, nodeCut, ruleCut int) []string {
	var out []string
	for _, t := range terms {
		if nodeDF[t] >= nodeCut || ruleDF[t] >= ruleCut {
			continue
		}
		out = append(out, t)
	}
	return out
}

func scoreReferent(r referent, n node, nodeDF, ruleDF map[string]int, nodeCut, ruleCut int) referent {
	scoredRules, zeroOverlap := 0, 0
	for _, rule := range r.Rules {
		terms := distinctive(rule.Terms, nodeDF, ruleDF, nodeCut, ruleCut)
		if len(terms) == 0 {
			continue
		}
		var matched []string
		for _, t := range terms {
			if termInSet(t, n.Terms) {
				matched = append(matched, t)
			}
		}
		scoredRules++
		if len(matched) == 0 {
			zeroOverlap++
		}
		better := !r.Scoreable ||
			float64(len(matched))/float64(len(terms)) > float64(len(r.Matched))/float64(r.Total)
		if better {
			r.Scoreable = true
			r.BestID = rule.ID
			r.Matched = matched
			r.Total = len(terms)
		}
	}
	// A file is a misfit when MOST of its rules share nothing with the node,
	// not when its single best-matching rule does. Best-wins is too easy to
	// rescue by coincidence — see the comply gate's note on ai-packet-capture.
	r.MajorityZero = scoredRules > 0 && zeroOverlap*2 > scoredRules
	if r.Scoreable && r.MajorityZero {
		r.Matched = nil
	}
	return r
}

// findBetterHome is the precision knob. Zero overlap alone is far too noisy,
// because the taxonomy is full of legitimate FAMILY nodes whose prose cannot
// enumerate every vendor and sink technology their members name. What
// distinguishes a real mis-attachment is that a BETTER HOME demonstrably
// exists. A rule sharing nothing with ANY node abstains instead of voting.
func findBetterHome(r referent, nodes map[string]node, declaredID string, nodeDF, ruleDF map[string]int, nodeCut, ruleCut, minOverlap int) referent {
	bestN, bestShared := "", []string(nil)
	for _, rule := range r.Rules {
		terms := distinctive(rule.Terms, nodeDF, ruleDF, nodeCut, ruleCut)
		if len(terms) == 0 {
			continue
		}
		for id, other := range nodes {
			if id == declaredID {
				continue
			}
			var shared []string
			for _, t := range terms {
				if termInSet(t, other.Terms) {
					shared = append(shared, t)
				}
			}
			if len(shared) > len(bestShared) || (len(shared) == len(bestShared) && len(shared) > 0 && id < bestN) {
				bestN, bestShared = id, shared
			}
		}
	}
	if len(bestShared) < minOverlap {
		r.NoBetterFit = true
		return r
	}
	sort.Strings(bestShared)
	r.AltNode, r.AltShared = bestN, bestShared
	return r
}

// termInSet reports whether t matches any term in set, exactly or by a shared
// prefixMatchLen-character prefix (both terms at least that long).
func termInSet(t string, set map[string]bool) bool {
	if set[t] {
		return true
	}
	if len(t) < prefixMatchLen {
		return false
	}
	p := t[:prefixMatchLen]
	for s := range set {
		if len(s) >= prefixMatchLen && s[:prefixMatchLen] == p {
			return true
		}
	}
	return false
}

func nodeDocumentFrequency(nodes map[string]node) map[string]int {
	df := map[string]int{}
	for _, n := range nodes {
		for t := range n.Terms {
			df[t]++
		}
	}
	return df
}

// ruleDocumentFrequency counts, per term, how many pack RULES contain it. This
// is the filter the comply-side gate does not need — see divergence 2 in the
// package doc.
func ruleDocumentFrequency(refs map[string][]referent) map[string]int {
	df := map[string]int{}
	for _, rs := range refs {
		for _, r := range rs {
			for _, rule := range r.Rules {
				seen := map[string]bool{}
				for _, t := range rule.Terms {
					if seen[t] {
						continue
					}
					seen[t] = true
					df[t]++
				}
			}
		}
	}
	return df
}

// ---------------------------------------------------------------------------
// Loading — taxonomy side
// ---------------------------------------------------------------------------

type nodeYAML struct {
	ID             string `yaml:"id"`
	Name           string `yaml:"name"`
	Abstract       string `yaml:"abstract"`
	Explanation    string `yaml:"explanation"`
	Recommendation string `yaml:"recommendation"`
	Examples       struct {
		Bad  []exampleItem `yaml:"bad"`
		Good []exampleItem `yaml:"good"`
	} `yaml:"examples"`
}

// exampleItem tolerates both shapes the corpus uses: a bare string, and a
// mapping with `code`/`description` keys. A strict struct here would silently
// drop half the example vocabulary on whichever shape it did not model — the
// fail-open-on-attacker-chosen-shape trap this repo documents for
// ElicitationSchema, in a lower-stakes place.
type exampleItem struct{ raw string }

func (e *exampleItem) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err == nil {
		e.raw = s
		return nil
	}
	var m map[string]any
	if err := value.Decode(&m); err == nil {
		var parts []string
		for _, k := range []string{"code", "command", "description", "text"} {
			if v, ok := m[k]; ok {
				parts = append(parts, fmt.Sprint(v))
			}
		}
		e.raw = strings.Join(parts, " ")
		return nil
	}
	return nil
}

func loadNodes(dir string) (map[string]node, error) {
	out := map[string]node{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var y nodeYAML
		if err := yaml.Unmarshal(b, &y); err != nil {
			return nil // not a node file; the schema gate owns malformed YAML
		}
		if y.ID == "" || y.Name == "" {
			return nil
		}
		var sb strings.Builder
		sb.WriteString(y.Name + " " + y.ID + " " + y.Abstract + " " + y.Explanation + " " + y.Recommendation)
		for _, e := range y.Examples.Bad {
			sb.WriteString(" " + e.raw)
		}
		for _, e := range y.Examples.Good {
			sb.WriteString(" " + e.raw)
		}
		terms := map[string]bool{}
		for _, t := range tokenize(sb.String()) {
			terms[t] = true
		}
		out[y.ID] = node{ID: y.ID, Name: y.Name, Path: path, Terms: terms}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Loading — pack side
// ---------------------------------------------------------------------------

// isExcludeKey reports whether a match-block key holds patterns describing what
// the rule deliberately does NOT match. Harvesting those would credit a rule
// with vocabulary about the very cases it was written to let through — a
// systematic noise source with no upside.
func isExcludeKey(k string) bool {
	lk := strings.ToLower(k)
	switch {
	case strings.Contains(lk, "exclude"),
		strings.Contains(lk, "not_contains"),
		strings.Contains(lk, "downgrade"),
		lk == "confidence_min", lk == "min", lk == "max":
		return true
	}
	return false
}

// harvestMatch walks a rule's `match:` block and collects literal word-runs
// from every positive pattern, tool name, argument key and executable name.
// Regex metacharacters fall out naturally: the tokenizer splits on anything
// that is not [a-z0-9], so `"\\.aws/credentials"` yields "aws", "credentials"
// and `"[A-Za-z0-9]+"` yields nothing at all.
//
// Map KEYS are harvested as well as values, because `args_match: {path: ...}`
// names the argument the rule keys on. Structural keys (`pattern_any`,
// `tool_name_regex`) are harvested too and then removed by the rule-side
// document-frequency filter, which is the point of having one: the boilerplate
// list is derived, not maintained.
func harvestMatch(v any, out *[]string) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys) // determinism
		for _, k := range keys {
			if isExcludeKey(k) {
				continue
			}
			*out = append(*out, tokenize(k)...)
			harvestMatch(t[k], out)
		}
	case []any:
		for _, vv := range t {
			harvestMatch(vv, out)
		}
	case string:
		*out = append(*out, tokenize(t)...)
	}
}

// loadRefs walks the pack tree and returns, per taxonomy id, the pack files
// referencing it. Files whose basename starts with "_" are disabled legacy
// packs and are skipped, matching the loader's own behaviour.
func loadRefs(dir string) (map[string][]referent, int, error) {
	byNodeFile := map[string]map[string]*referent{}
	nRules := 0

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		if strings.HasPrefix(d.Name(), "_") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var doc map[string]any
		if err := yaml.Unmarshal(b, &doc); err != nil {
			return nil
		}
		base := d.Name()

		// Rule-bearing keys are discovered structurally, not enumerated.
		// CLAUDE.md records that MCP packs carry rules under SEVEN different
		// keys and that hand-enumerating them silently dropped 386 rules from
		// the published count. Anything that is a list of maps with an `id` is
		// a rule list, so a future eighth key is covered on the day it lands.
		keys := make([]string, 0, len(doc))
		for k := range doc {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			list, ok := doc[k].([]any)
			if !ok {
				continue
			}
			for _, item := range list {
				m, ok := item.(map[string]any)
				if !ok {
					continue
				}
				id, _ := m["id"].(string)
				if id == "" {
					continue
				}
				tax, _ := m["taxonomy"].(string)
				tax = strings.TrimSpace(tax)
				if tax == "" {
					continue // ALLOW rules and the documented #3118 backstop
				}
				nRules++

				terms := tokenize(id)
				if mm, ok := m["match"]; ok {
					harvestMatch(mm, &terms)
				}
				// Dedupe, preserving order for stable output.
				seen := map[string]bool{}
				var uniq []string
				for _, t := range terms {
					if seen[t] {
						continue
					}
					seen[t] = true
					uniq = append(uniq, t)
				}

				if byNodeFile[tax] == nil {
					byNodeFile[tax] = map[string]*referent{}
				}
				r := byNodeFile[tax][base]
				if r == nil {
					r = &referent{File: base}
					byNodeFile[tax][base] = r
				}
				r.Rules = append(r.Rules, packRule{ID: id, Terms: uniq})
			}
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}

	out := map[string][]referent{}
	for tax, files := range byNodeFile {
		names := make([]string, 0, len(files))
		for f := range files {
			names = append(names, f)
		}
		sort.Strings(names)
		for _, f := range names {
			out[tax] = append(out[tax], *files[f])
		}
	}
	return out, nRules, nil
}

// ---------------------------------------------------------------------------
// Loading — testdata side (#3336: internal/analyzer/testdata carries its own
// TaxonomyRef per case, and nothing checked it describes the command.)
// ---------------------------------------------------------------------------

// testdataGroupKey derives a coarse grouping key from a TestCase ID by
// dropping the classification prefix and the trailing sequence number, e.g.
// "TP-PKGPUB-SUDO-001" -> "PKGPUB-SUDO". This approximates "which declared
// *Cases variable this case lives in" without parsing Go source: sibling
// cases in one block share an ID's middle segment(s) by convention (see
// types.go's ID doc), and grouping at that granularity is exactly what
// distinguishes the #3336 example — PKGPUB (mislabelled) from PKGPUB-SUDO
// (correctly labelled) three lines below it.
func testdataGroupKey(id string) string {
	parts := strings.Split(id, "-")
	if len(parts) <= 2 {
		return id
	}
	return strings.Join(parts[1:len(parts)-1], "-")
}

// loadTestdataRefs mirrors loadRefs's shape but reads
// internal/analyzer/testdata.AllTestCases() instead of pack YAML. Only
// Classification == "TP" cases vote: a TN case is deliberately UNLIKE its
// node — it is the benign command a real rule must not fire on — so scoring
// it the same way as a positive assertion would manufacture misfits out of
// the fixture's own design, exactly the false-positive class the package doc
// already names for pack TN rules.
func loadTestdataRefs() (map[string][]referent, int, error) {
	byNodeGroup := map[string]map[string]*referent{}
	nRules := 0
	for _, tc := range testdata.AllTestCases() {
		if tc.Classification != "TP" {
			continue
		}
		tax := strings.TrimSpace(tc.TaxonomyRef)
		if tax == "" {
			continue
		}
		nRules++

		terms := append(tokenize(tc.Command), tokenize(tc.Description)...)
		seen := map[string]bool{}
		var uniq []string
		for _, t := range terms {
			if seen[t] {
				continue
			}
			seen[t] = true
			uniq = append(uniq, t)
		}

		group := testdataGroupKey(tc.ID)
		if byNodeGroup[tax] == nil {
			byNodeGroup[tax] = map[string]*referent{}
		}
		r := byNodeGroup[tax][group]
		if r == nil {
			r = &referent{File: group}
			byNodeGroup[tax][group] = r
		}
		r.Rules = append(r.Rules, packRule{ID: tc.ID, Terms: uniq})
	}

	out := map[string][]referent{}
	for tax, groups := range byNodeGroup {
		names := make([]string, 0, len(groups))
		for g := range groups {
			names = append(names, g)
		}
		sort.Strings(names)
		for _, g := range names {
			out[tax] = append(out[tax], *groups[g])
		}
	}
	return out, nRules, nil
}

// tokenize lowercases, splits on any non-alphanumeric boundary, and drops
// stopwords and 1-2 character fragments.
func tokenize(s string) []string {
	s = strings.ToLower(s)
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() == 0 {
			return
		}
		t := cur.String()
		cur.Reset()
		if len(t) < 3 || stopwords[t] {
			return
		}
		out = append(out, t)
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			cur.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return out
}

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------

func pairKey(nodeID, file string) string { return nodeID + " :: " + file }

func loadBaseline(path string) (map[string]bool, error) {
	out := map[string]bool{}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out[line] = true
	}
	return out, sc.Err()
}

func writeBaselineFile(path string, flagged []finding, useTestdata bool) (int, error) {
	var lines []string
	for _, f := range flagged {
		for _, r := range f.Refs {
			if r.misfit() {
				lines = append(lines, pairKey(f.Node.ID, r.File))
			}
		}
	}
	sort.Strings(lines)
	var sb strings.Builder
	if useTestdata {
		sb.WriteString(testdataBaselineHeader)
	} else {
		sb.WriteString(baselineHeader)
	}
	for _, l := range lines {
		sb.WriteString(l + "\n")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, err
	}
	return len(lines), os.WriteFile(path, []byte(sb.String()), 0o644)
}

const baselineHeader = `# baseline.txt — (taxonomy node :: pack file) pairs where the node's prose does
# not describe the threat that pack rule detects.
#
# Read by cmd/check-pack-taxonomy-fit. See that package's doc comment for what
# the check measures and where it deliberately diverges from the comply-side
# gate. A line here is a known flag; any pair NOT listed is new and fails CI.
#
# Format: <taxonomy node id> :: <pack file basename>. Comments after '#'.
#
# Keyed on the PAIR, not the node, so a node that is already known-bad cannot
# silently accrete more mismatched rules.
#
# BURN IT DOWN. Two ways to clear a line, both improving the attestation text a
# customer reads:
#   1. Point the rule at a node whose prose describes what it detects.
#   2. Broaden the node's prose so it covers the family it has accreted.
# Adding a NEW line requires Gary + Kai sign-off. Removing one is MANDATORY
# once the pair stops misfitting — the checker reports STALE entries and fails.
#
# Bootstrap:  go run ./cmd/check-pack-taxonomy-fit -taxonomy <dir> -write-baseline
# NOTE: -write-baseline DISCARDS the hand-written verdicts below. It is a
# bootstrap tool, not a maintenance one — to clear an entry, delete its line.
#
`

const testdataBaselineHeader = `# testdata-baseline.txt — (taxonomy node :: TestCase ID-group) pairs where the
# node's prose does not describe the threat that internal/analyzer/testdata
# TP case group asserts (#3336).
#
# Read by cmd/check-pack-taxonomy-fit -testdata. See that package's doc
# comment for what the check measures. A line here is a known flag; any pair
# NOT listed is new and fails CI. Only Classification == "TP" cases vote — a
# TN case is deliberately unlike its node, so it is excluded rather than
# scored.
#
# Format: <taxonomy node id> :: <ID-group>, where ID-group is a TestCase.ID
# with its classification prefix and trailing sequence number stripped
# (testdataGroupKey) — an approximation of "which declared *Cases variable
# this case lives in" that does not require parsing Go source.
#
# Keyed on the PAIR, not the node, so a node that is already known-bad cannot
# silently accrete more mismatched cases.
#
# BURN IT DOWN. Two ways to clear a line, both making the test corpus assert
# the truth about what it validates:
#   1. Point the case(s) at a node whose prose describes the technique.
#   2. Broaden the node's prose so it covers the family it has accreted.
# Adding a NEW line requires Gary + Kai sign-off. Removing one is MANDATORY
# once the pair stops misfitting — the checker reports STALE entries and fails.
#
# Bootstrap:  go run ./cmd/check-pack-taxonomy-fit -testdata -taxonomy <dir> -write-baseline
# NOTE: -write-baseline DISCARDS the hand-written verdicts below. It is a
# bootstrap tool, not a maintenance one — to clear an entry, delete its line.
#
`

// ---------------------------------------------------------------------------
// Calibration output
// ---------------------------------------------------------------------------

func dumpTermFrequencies(ruleDF map[string]int, nRules, n, cut int) {
	type kv struct {
		T string
		N int
	}
	var all []kv
	for t, c := range ruleDF {
		all = append(all, kv{t, c})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].N != all[j].N {
			return all[i].N > all[j].N
		}
		return all[i].T < all[j].T
	})
	fmt.Printf("rule-side term frequency over %d rules (cutoff %d = %.0f%%)\n\n", nRules, cut, 100*float64(cut)/float64(nRules))
	for i, e := range all {
		if i >= n {
			break
		}
		mark := " "
		if e.N >= cut {
			mark = "-"
		}
		fmt.Printf("  %s %-28s %5d  %5.1f%%\n", mark, e.T, e.N, 100*float64(e.N)/float64(nRules))
	}
}

func dumpAll(scored []finding, minRefs, nNodes, nRefNodes, nRules, nodeCut, ruleCut int) {
	fmt.Printf("%d taxonomy nodes, %d referenced by packs, %d rules; node-generic cutoff df>=%d, rule-generic cutoff df>=%d\n\n",
		nNodes, nRefNodes, nRules, nodeCut, ruleCut)
	fmt.Printf("%-6s %-5s %s\n", "frac", "refs", "node")
	for _, f := range scored {
		if f.NRefs < minRefs {
			continue
		}
		fmt.Printf("%-6.2f %-5d %s\n", f.MisfitFrac, f.NRefs, f.Node.ID)
		for _, r := range f.Refs {
			if r.misfit() {
				fmt.Printf("           MISFIT :: %-52s best=%s\n", r.File, r.BestID)
				if r.AltNode != "" {
					fmt.Printf("                     also in %s (%s)\n", r.AltNode, strings.Join(r.AltShared, ", "))
				}
			}
		}
	}
}

func explainNode(scored []finding, id string, nodeDF, ruleDF map[string]int, nodeCut, ruleCut int) {
	for _, f := range scored {
		if f.Node.ID != id {
			continue
		}
		fmt.Printf("%s — %s\n", f.Node.ID, f.Node.Name)
		fmt.Printf("  %d referring file(s), %d voting, %d misfit (%.2f)\n\n", len(f.Refs), f.NRefs, f.Misfits, f.MisfitFrac)
		for _, r := range f.Refs {
			status := "fit"
			switch {
			case r.misfit():
				status = "MISFIT"
			case !r.Scoreable:
				status = "abstain (no distinctive terms)"
			case r.NoBetterFit:
				status = "abstain (no better home)"
			}
			fmt.Printf("  %-56s %s\n", r.File, status)
			for _, rule := range r.Rules {
				terms := distinctive(rule.Terms, nodeDF, ruleDF, nodeCut, ruleCut)
				var hit []string
				for _, t := range terms {
					if termInSet(t, f.Node.Terms) {
						hit = append(hit, t)
					}
				}
				fmt.Printf("      %-46s distinctive=%d matched=%v\n", rule.ID, len(terms), hit)
			}
			if r.AltNode != "" {
				fmt.Printf("      -> also in %s (%s)\n", r.AltNode, strings.Join(r.AltShared, ", "))
			}
			fmt.Println()
		}
		return
	}
	fmt.Printf("node %q is not referenced by any pack rule\n", id)
}
