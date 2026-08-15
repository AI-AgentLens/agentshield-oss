package analyzer_test

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// ---------------------------------------------------------------------------
// agentshield-oss#3118 — taxonomy-tagged twins of ts-sem-block-high-risk.
//
// The three ts-sem-block-<category>-critical rules in
// packs/premium/terminal-safety-advanced.yaml exist so every BLOCK resolves to
// a taxonomy node (and from there to a compliance control). They are pure
// attestation metadata: they must match EXACTLY the command set the untaxed
// backstop already matched, and must not move the decision surface.
//
// The trap they sit on: UserSemanticRule.RiskMin is optional, and
// matchesSingleIntent SKIPS the risk predicate when it is empty. So
// `intent: persistence` with no risk_min BLOCKs every persistence-classified
// command at any risk level — including routine crontab installs that the
// built-in classifier rates "high", not "critical".
//
// These tests are the fitness function for that. TestSemanticTwin3118_RiskFloor
// is a mutation check: it asserts the defect IS present in the risk_min-less
// rule shape, so the guard below cannot silently become a no-op.
// ---------------------------------------------------------------------------

// benignInCategoryIntents are intent classifications a benign command can
// legitimately produce in each twinned category, at a risk level BELOW
// critical. sem-audit-crontab-modify emits the persistence/high one for real
// commands today (`crontab <file>`); the other two are forward guards — the
// moment a built-in rule starts emitting a sub-critical file-delete or
// resource-exhaust intent, the risk floor must already be holding.
var benignInCategoryIntents = map[string]analyzer.CommandIntent{
	"persistence": {
		Category: "persistence", Risk: "high", Confidence: 0.85, Segment: -1,
		Detail: "crontab modification",
	},
	"file-delete": {
		Category: "file-delete", Risk: "medium", Confidence: 0.85, Segment: -1,
		Detail: "scoped delete under a temp path",
	},
	"resource-exhaust": {
		Category: "resource-exhaust", Risk: "medium", Confidence: 0.85, Segment: -1,
		Detail: "bounded parallel job fan-out",
	},
}

// TestSemanticTwin3118_RiskFloor pins the semantics of the twin rules at the
// matcher level, in both directions:
//
//	without risk_min -> the rule DOES match a benign sub-critical intent (the
//	                    false positive; asserted so this test fails loudly if
//	                    the trap is ever "fixed" in matchesSingleIntent and the
//	                    guard below stops proving anything)
//	with risk_min    -> the rule does NOT match it, but still matches critical
func TestSemanticTwin3118_RiskFloor(t *testing.T) {
	for category, benign := range benignInCategoryIntents {
		t.Run(category, func(t *testing.T) {
			intents := []analyzer.CommandIntent{benign}

			// Mutation check — the shape the WIP fix shipped with.
			noFloor := analyzer.UserSemanticRule{Intent: category, Decision: "BLOCK"}
			if !analyzer.MatchSemanticRule(intents, noFloor) {
				t.Fatalf("mutation check failed: `intent: %s` with no risk_min was expected to "+
					"match the benign %s intent (empty RiskMin skips the risk predicate). "+
					"If matchesSingleIntent changed, this test no longer proves the guard below.",
					category, benign.Risk)
			}

			// The fix.
			withFloor := analyzer.UserSemanticRule{Intent: category, RiskMin: "critical", Decision: "BLOCK"}
			if analyzer.MatchSemanticRule(intents, withFloor) {
				t.Errorf("FP: `intent: %s` + `risk_min: critical` must NOT match a benign %s-risk "+
					"%s intent", category, benign.Risk, category)
			}

			// ...and it still catches the real thing.
			critical := benign
			critical.Risk = "critical"
			if !analyzer.MatchSemanticRule([]analyzer.CommandIntent{critical}, withFloor) {
				t.Errorf("FN: `intent: %s` + `risk_min: critical` must still match a critical-risk "+
					"%s intent", category, category)
			}
		})
	}
}

// TestSemanticTwin3118_NoDecisionMovement runs the real shipped packs through
// the full analyzer pipeline and asserts the twin rules did not turn any
// benign in-category command into a BLOCK.
//
// `crontab <file>` is the load-bearing case: sem-audit-crontab-modify
// classifies it as persistence/high, so the risk_min-less twin BLOCKed it —
// and it was the SOLE triggering rule, i.e. a decision the corpus had at AUDIT
// on main. Installing a crontab from a checked-in file is routine deployment
// work, so a hard BLOCK there is a false positive on a BLOCK decision.
func TestSemanticTwin3118_NoDecisionMovement(t *testing.T) {
	requirePremiumPack(t)
	engine := newPipelineEngine(t)

	benign := []struct {
		cmd  string
		want policy.Decision
	}{
		{"crontab /home/dev/deploy.cron", policy.DecisionAudit},
		{"crontab /etc/cron.d/backup", policy.DecisionAudit},
		{"crontab -l", policy.DecisionAudit},
		{"find /tmp -type f -name '*.log' -delete", policy.DecisionAllow},
		{"python3 -c \"print('hello')\"", policy.DecisionAudit},
	}
	for _, tc := range benign {
		if got := engine.Evaluate(tc.cmd, nil); got.Decision != tc.want {
			t.Errorf("benign command regressed:\n  command:  %s\n  expected: %s\n  got:      %s\n  rules:    %v",
				tc.cmd, tc.want, got.Decision, got.TriggeredRules)
		}
	}

	// TPs still BLOCK, and each now carries a taxonomy-tagged twin alongside
	// the untaxed backstop so the block is attestable.
	attested := []struct {
		cmd  string
		twin string
	}{
		{"echo '* * * * * evil' | crontab -", "ts-sem-block-persistence-critical"},
		{"find /var/log -name '*.gz' -delete", "ts-sem-block-file-delete-critical"},
		{"python3 -c \"os.fork()\"", "ts-sem-block-resource-exhaust-critical"},
		{"shred -vfz /dev/sda", "ts-sem-block-disk-destroy"},
	}
	for _, tc := range attested {
		got := engine.Evaluate(tc.cmd, nil)
		if got.Decision != policy.DecisionBlock {
			t.Errorf("expected BLOCK for %q, got %s (rules: %v)", tc.cmd, got.Decision, got.TriggeredRules)
			continue
		}
		if !contains(got.TriggeredRules, tc.twin) {
			t.Errorf("expected taxonomy-tagged twin %s to fire on %q — an untaxed BLOCK is "+
				"unattestable (#3118). Triggered: %v", tc.twin, tc.cmd, got.TriggeredRules)
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
