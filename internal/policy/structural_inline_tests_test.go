package policy

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// TestStructuralRuleInlineTests_Measure grades the inline tp:/tn: lists of the
// shell rules TestRuleYAMLTests skips (#4037): structural, semantic, dataflow
// and stateful rules with no regex, prefix or exact match.
//
// Warn-only on purpose. The issue's smallest next step is a measurement: a gate
// added before the count is known red-lines CI on unknown debt. Every failure
// is logged with its rule id, and the totals (with the denominator) are the
// backlog; each entry is either a wrong fixture or a real detection gap.
//
// A TP passes when the rule id appears in the full pipeline's TriggeredRules.
// A TN passes when it does not. Both go through NewEngineWithAnalyzers, the
// same construction the hook uses.
func TestStructuralRuleInlineTests_Measure(t *testing.T) {
	rules := loadAllRules(t)
	engine, err := NewEngineWithAnalyzers(&Policy{Rules: rules}, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}

	var graded, tpTotal, tnTotal int
	var failures []string
	for _, rule := range rules {
		if rule.Tests == nil || strings.HasPrefix(rule.ID, "mcp-") {
			continue
		}
		if rule.Match.CommandRegex != "" || rule.Match.CommandExact != "" || len(rule.Match.CommandPrefix) > 0 {
			continue // TestRuleYAMLTests grades these
		}
		if len(rule.Tests.TP)+len(rule.Tests.TN) == 0 {
			continue
		}
		graded++
		fired := func(cmd string) bool {
			for _, id := range engine.Evaluate(cmd, nil).TriggeredRules {
				if id == rule.ID {
					return true
				}
			}
			return false
		}
		for i, cmd := range rule.Tests.TP {
			tpTotal++
			if !fired(cmd) {
				failures = append(failures, fmt.Sprintf("%s TP-%d did not fire: %s", rule.ID, i+1, cmd))
			}
		}
		for i, cmd := range rule.Tests.TN {
			tnTotal++
			if fired(cmd) {
				failures = append(failures, fmt.Sprintf("%s TN-%d fired: %s", rule.ID, i+1, cmd))
			}
		}
	}

	// Vacuity floor: a zero here means the loader or the skip filter broke,
	// not that the backlog is clear.
	if graded < 50 {
		t.Fatalf("only %d structural-only rules graded; expected ~98 (#4037)", graded)
	}
	sort.Strings(failures)
	for _, f := range failures {
		t.Logf("FAIL: %s", f)
	}
	t.Logf("structural-only inline tests: %d rules, %d TP, %d TN graded; %d failing (warn-only, #4037)",
		graded, tpTotal, tnTotal, len(failures))
}
