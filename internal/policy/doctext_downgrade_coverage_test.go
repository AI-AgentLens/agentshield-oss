package policy

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// doctextDowngradeBaseline is the residue file for
// TestBlockShellRulesCarryDocTextDowngrade. See its header for the classes.
var doctextDowngradeBaseline = filepath.Join("testdata", "doctext_downgrade_unlabelled_baseline.txt")

// carriesDocTextDowngrade reports whether a rule downgrades (fires, then
// attests at AUDIT) when its match sits only in documentation text: a gh/git
// --body/--message argument (is_doc_text) or a cat/tee heredoc body
// (in_heredoc). in_interpreter_heredoc is deliberately NOT required: it also
// downgrades `cmd = "<payload>"; os.system(cmd)` inside a python heredoc, which
// interp_exec.go cannot recover (#3939, PR #3942). Interpreter heredocs are
// handled per rule with command_position_exclude: [interp_heredoc_literal].
func carriesDocTextDowngrade(r Rule) bool {
	var docText, heredoc bool
	for _, l := range r.Match.CommandIntentDowngrade {
		switch l {
		case "is_doc_text":
			docText = true
		case "in_heredoc":
			heredoc = true
		}
	}
	return docText && heredoc
}

// unlabelledBlockShellRules returns the ids of BLOCK rules with a
// regex-family command matcher (the only matchers command_intent_downgrade
// acts on — structural/dataflow/semantic/stateful rules ignore it) that do not
// carry the doc-text downgrade.
func unlabelledBlockShellRules(rules []Rule) map[string]bool {
	out := map[string]bool{}
	for _, r := range rules {
		if r.Decision != DecisionBlock {
			continue
		}
		if r.Match.CommandRegex == "" && r.Match.CommandExact == "" && len(r.Match.CommandPrefix) == 0 {
			continue
		}
		if !carriesDocTextDowngrade(r) {
			out[r.ID] = true
		}
	}
	return out
}

func readDoctextDowngradeBaseline(t *testing.T, path string) map[string]bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open baseline: %v", err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id := strings.SplitN(line, "\t", 2)[0]
		if out[id] {
			t.Errorf("baseline lists %q twice", id)
		}
		out[id] = true
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	return out
}

// TestBlockShellRulesCarryDocTextDowngrade is the "fix the generator" half of
// #3963. #3937 moved the inertness labels of the 462 rules that had them from
// exclude to downgrade, and TestDocTextDowngradeCannotBeLaundered guards the
// label against laundering — but nothing guarded its ABSENCE, so 543 of 872
// BLOCK shell rules (62%) accumulated with no label at all and BLOCKed a
// `cat > notes.txt <<'EOF'` body that merely mentioned the command.
//
// Default for a new BLOCK shell rule: command_intent_downgrade: [is_doc_text,
// in_heredoc]. A rule that cannot take it (its attack IS a text position —
// e.g. `echo ... > /etc/sudoers`) goes in the baseline with the reason, which
// makes the exception visible in review instead of silent.
//
// The baseline only shrinks: an unlabelled rule missing from it fails, and so
// does a baseline line whose rule is now labelled or no longer exists.
func TestBlockShellRulesCarryDocTextDowngrade(t *testing.T) {
	// Pack rules only: the built-in DefaultPolicy rules (block-rm-root,
	// block-pipe-to-shell) are Go-defined and outside the pack corpus #3963
	// measured.
	builtin := map[string]bool{}
	for _, r := range DefaultPolicy().Rules {
		builtin[r.ID] = true
	}
	var rules []Rule
	for _, r := range loadAllRules(t) {
		if !builtin[r.ID] {
			rules = append(rules, r)
		}
	}
	unlabelled := unlabelledBlockShellRules(rules)
	baseline := readDoctextDowngradeBaseline(t, doctextDowngradeBaseline)

	var missing, stale []string
	for id := range unlabelled {
		if !baseline[id] {
			missing = append(missing, id)
		}
	}
	for id := range baseline {
		if !unlabelled[id] {
			stale = append(stale, id)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	for _, id := range missing {
		t.Errorf("BLOCK shell rule %s has no command_intent_downgrade: [is_doc_text, in_heredoc] — add it "+
			"(and move any inline tn: that now fires-then-downgrades to tests.attested:), or, if a true positive "+
			"loses BLOCK with it, record the rule in %s with the reason (#3963)", id, doctextDowngradeBaseline)
	}
	for _, id := range stale {
		t.Errorf("baseline line %s no longer applies (rule is labelled or gone) — delete it from %s so the "+
			"baseline only shrinks (#3963)", id, doctextDowngradeBaseline)
	}

	blockShell := 0
	for _, r := range rules {
		if r.Decision == DecisionBlock && (r.Match.CommandRegex != "" || r.Match.CommandExact != "" || len(r.Match.CommandPrefix) > 0) {
			blockShell++
		}
	}
	// Denominator guard: a loader regression that drops packs would otherwise
	// turn this into a vacuous pass.
	if blockShell < 800 {
		t.Fatalf("only %d BLOCK shell rules loaded — expected 870+; is a pack failing to load?", blockShell)
	}
	t.Logf("BLOCK shell rules: %d; unlabelled: %d; baselined: %d", blockShell, len(unlabelled), len(baseline))
}

// TestDocTextDowngradeKeepsInlineTPsAtBlock is the measurement #3963 used to
// decide which rules could take the label, kept as a ratchet: on a BLOCK rule
// that carries command_intent_downgrade, every inline tp: must still decide
// BLOCK. TestRuleYAMLTests only asserts that a tp FIRES, so a label that turns
// a true positive into an attested AUDIT (an echo/tee write into a sensitive
// file, where the echo argument IS the attack) passes it silently. A case that
// is meant to fire-then-downgrade belongs in tests.attested:, not tp:.
func TestDocTextDowngradeKeepsInlineTPsAtBlock(t *testing.T) {
	rules := loadAllRules(t)
	engine, err := NewEngine(&Policy{Rules: rules})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	probes := 0
	for _, r := range rules {
		if r.Tests == nil || r.Decision != DecisionBlock || len(r.Match.CommandIntentDowngrade) == 0 {
			continue
		}
		if r.Match.CommandRegex == "" && r.Match.CommandExact == "" && len(r.Match.CommandPrefix) == 0 {
			continue
		}
		for _, tp := range r.Tests.TP {
			if !engine.matchRule(tp, r) {
				continue // TestRuleYAMLTests reports a tp that does not fire
			}
			probes++
			if got := engine.effectiveDecision(tp, r); got != DecisionBlock {
				t.Errorf("rule %s: inline tp decides %s, want BLOCK — its command_intent_downgrade label excuses a "+
					"true positive. Drop the label and record the rule in %s, or move the case to attested: if it "+
					"really is documentation:\n  %s", r.ID, got, doctextDowngradeBaseline, tp)
			}
		}
	}
	if probes < 1800 {
		t.Fatalf("only %d tp probes on downgrade-labelled BLOCK rules — expected ~2180; vacuous run?", probes)
	}
	t.Logf("tp probes on downgrade-labelled BLOCK rules: %d", probes)
}
