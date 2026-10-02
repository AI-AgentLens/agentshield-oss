package analyzer_test

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Prefix-bypass ratchet (#3901).
//
// # The defect class
//
// A `command_regex_exclude` match suppresses the ENTIRE rule, not the span it
// matched. So an exclusion anchored only to "this tool appears in execution
// position" is satisfied by a statement that merely PRECEDES the malicious one,
// and a harmless prefix switches a BLOCK rule off:
//
//	claude --dangerously-skip-permissions -p "x"                         -> BLOCK
//	sed -n 1p notes.txt && claude --dangerously-skip-permissions -p "x"  -> AUDIT
//
// `sed -n 1p` is a pure read doing no work except satisfying the anchor. This
// has been rediscovered three times as individual FP fixes (#1867 -> #3874 ->
// #3901); it is a class, and a class needs a gate rather than a fourth fix.
//
// # Why the full pipeline and not matchRule
//
// `Engine.matchRule` tests the rule regex and its exclusion against the WHOLE
// command with no per-statement retry, so it reports a "bypass" for every
// `^`-anchored rule the moment anything is prefixed — findings that are an
// artifact of the probe, not of the rule. `Evaluate` is what a hook actually
// runs, and `TriggeredRules` answers the question that matters: did THIS rule
// still fire. Paths are nil, as in the accuracy runner, which also keeps
// `protected-path` from masking a rule that stopped firing.
//
// # The assertion is per-RULE, not per-decision
//
// Two of the baselined entries still decide BLOCK — another rule catches the
// command. That is defence in depth working, and it is NOT a reason to ignore
// them: the audit event then names a different rule and resolves to a different
// taxonomy node, so the attestation describes the wrong attempt. Asserting on
// `result.Decision` would have found seven of nine and called it clean.
//
// # Scope, stated honestly
//
// This tests rules that carry a `command_regex_exclude`, on their own declared
// TPs, against a fixed prefix list. It is a LOWER BOUND on the class. Rules
// whose plain TP does not name them are skipped, not reported, because
// "absent when prefixed" means nothing if it was absent to begin with — that
// skip count is logged so the blind spot stays visible rather than implicit.

// benignPrefixes are harmless leading statements, each chosen because the
// corpus actually carries an exclusion idiom it satisfies: sed text
// manipulation (#1867), the git/gh prose carve-out, read-only searchers
// (#3897), and a doc-text echo. Every one is a no-op on its own.
var benignPrefixes = []struct{ label, text string }{
	{"sed", "sed -n 1p notes.txt && "},
	{"git", `git commit -m "chore: notes" && `},
	{"gh", `gh issue create --title "t" --body "b" && `},
	{"grep", "grep -q needle notes.txt && "},
	{"echo", `echo "note"; `},
}

const prefixBypassBaselineFile = "prefix_bypass_baseline.txt"

// prefixBypassFloor guards the vacuous pass. If the pack loader breaks, or the
// rules stop carrying inline TPs, every set below goes empty and the ratchet
// reports a clean corpus with total confidence and zero evidence — the exact
// shape #3130 is a monument to. Measured 64 on 2026-09-19; the floor is set
// well under that so ordinary rule churn does not trip it.
const prefixBypassFloor = 40

func TestPrefixBypassRatchet(t *testing.T) {
	t.Parallel()

	pol := loadTestPolicy(t)
	engine, err := policy.NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("failed to create pipeline engine: %v", err)
	}

	loaded := map[string]bool{}
	for _, r := range pol.Rules {
		loaded[r.ID] = true
	}

	// Returns whether the named rule fired, and the overall decision. The
	// decision is carried because the two outcomes need different urgency: a
	// BLOCK -> AUDIT transition is a silent fail-open, while BLOCK -> BLOCK
	// means another rule caught it and only the ATTESTATION is wrong (the event
	// names a different taxonomy node than the attempt). Both are defects; only
	// the first one lets the command through.
	eval := func(cmd, id string) (bool, string) {
		res := engine.Evaluate(cmd, nil)
		for _, fired := range res.TriggeredRules {
			if fired == id {
				return true, string(res.Decision)
			}
		}
		return false, string(res.Decision)
	}

	found := map[string]string{} // rule id -> "prefix: TP"
	tested, skipped := 0, 0

	for _, rule := range pol.Rules {
		if rule.Decision != policy.DecisionBlock {
			continue
		}
		if rule.Match.CommandRegexExclude == "" || rule.Tests == nil {
			continue
		}
		counted := false
		for _, tp := range rule.Tests.TP {
			// A multi-line TP is a heredoc; prefixing one changes which lines
			// are body and which are command, so the probe would be testing
			// its own edit rather than the rule.
			if strings.Contains(tp, "\n") {
				continue
			}
			plainFired, plainDec := eval(tp, rule.ID)
			if !plainFired {
				continue // control failed for this TP
			}
			if !counted {
				tested++
				counted = true
			}
			for _, p := range benignPrefixes {
				fired, dec := eval(p.text+tp, rule.ID)
				if fired {
					continue
				}
				kind := "LAUNDERED (another rule still blocks; attestation names the wrong node)"
				if dec != plainDec {
					kind = fmt.Sprintf("FAIL-OPEN %s -> %s", plainDec, dec)
				}
				if _, dup := found[rule.ID]; !dup {
					found[rule.ID] = fmt.Sprintf("%-5s %s", p.label, kind)
				}
			}
		}
		if !counted {
			skipped++
		}
	}

	if tested < prefixBypassFloor {
		t.Fatalf("VACUOUS: only %d rules had a TP that names them (floor %d). "+
			"The probe, not the corpus, is what changed — fix it before reading any result below.",
			tested, prefixBypassFloor)
	}

	baseline := loadPrefixBypassBaseline(t)

	var added []string
	for id := range found {
		if !baseline[id] {
			added = append(added, id)
		}
	}
	sort.Strings(added)

	// Stale entries: baselined, still loaded, no longer bypassable -> the line
	// must come out so the baseline only ever shrinks.
	//
	// "still loaded" is load-bearing and not defensive padding: the OSS build
	// runs this package against a tree with packs/premium/ stripped, so every
	// premium entry would read as stale there and a blanket staleness failure
	// would turn the OSS distribution suite permanently red for a reason that
	// has nothing to do with the OSS tier.
	var stale []string
	for id := range baseline {
		if loaded[id] && found[id] == "" {
			stale = append(stale, id)
		}
	}
	sort.Strings(stale)

	t.Logf("prefix-bypass ratchet: %d rules tested, %d skipped (plain TP did not name them), %d bypassable, %d baselined",
		tested, skipped, len(found), len(baseline))
	for _, id := range sortedKeys(found) {
		t.Logf("  bypassable: %-52s %s", id, found[id])
	}

	if len(added) > 0 {
		t.Errorf("%d rule(s) newly switched off by a benign prefix:\n  %s\n\n"+
			"A leading statement that does no work must not silence a BLOCK rule. Fix by giving the\n"+
			"exclusion a same-statement requirement (the trigger text must be reachable from the excused\n"+
			"tool without crossing an unquoted separator) and pinning it with must-NOT-match rows in tp:.\n"+
			"See packs/community/terminal-safety.yaml ts-block-claude-dangerous-skip-permissions for the shape.\n"+
			"Baselining instead requires Gary + Kai sign-off — these are fail-opens, not style nits.",
			len(added), strings.Join(added, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("%d baselined rule(s) no longer bypassable — remove them from %s so the baseline only shrinks:\n  %s",
			len(stale), prefixBypassBaselineFile, strings.Join(stale, "\n  "))
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func loadPrefixBypassBaseline(t *testing.T) map[string]bool {
	t.Helper()
	f, err := os.Open(prefixBypassBaselineFile)
	if err != nil {
		t.Fatalf("cannot read %s: %v (an unreadable baseline must not read as an empty one)",
			prefixBypassBaselineFile, err)
	}
	defer func() { _ = f.Close() }()

	out := map[string]bool{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// First field is the rule id; anything after it is a human annotation
		// (which prefix, and whether it fails open or only launders the rule).
		// Keeping the annotation on the same line as the id is what stops it
		// drifting away from the entry it describes.
		out[strings.Fields(line)[0]] = true
	}
	if err := s.Err(); err != nil {
		t.Fatalf("error reading %s: %v", prefixBypassBaselineFile, err)
	}
	return out
}
