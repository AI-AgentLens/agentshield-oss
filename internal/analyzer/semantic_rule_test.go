package analyzer

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Test: Semantic intent matching
// ---------------------------------------------------------------------------

func TestSemanticRule_Intent(t *testing.T) {
	intents := []CommandIntent{
		{Category: "disk-destroy", Risk: "critical", Confidence: 0.95},
		{Category: "file-delete", Risk: "high", Confidence: 0.90},
	}

	tests := []struct {
		name    string
		intents []CommandIntent
		rule    UserSemanticRule
		want    bool
	}{
		{
			name:    "exact intent match",
			intents: intents,
			rule:    UserSemanticRule{Intent: "disk-destroy"},
			want:    true,
		},
		{
			name:    "intent not present",
			intents: intents,
			rule:    UserSemanticRule{Intent: "network-scan"},
			want:    false,
		},
		{
			name:    "intent_any match",
			intents: intents,
			rule:    UserSemanticRule{IntentAny: []string{"network-scan", "file-delete", "code-execute"}},
			want:    true,
		},
		{
			name:    "intent_any no match",
			intents: intents,
			rule:    UserSemanticRule{IntentAny: []string{"network-scan", "code-execute"}},
			want:    false,
		},
		{
			name:    "empty intents — no match",
			intents: nil,
			rule:    UserSemanticRule{Intent: "disk-destroy"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchSemanticRule(tt.intents, tt.rule)
			if got != tt.want {
				t.Errorf("MatchSemanticRule() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: Semantic risk_min threshold
// ---------------------------------------------------------------------------

func TestSemanticRule_RiskMin(t *testing.T) {
	tests := []struct {
		name    string
		intents []CommandIntent
		rule    UserSemanticRule
		want    bool
	}{
		{
			name:    "risk_min: critical meets critical",
			intents: []CommandIntent{{Category: "disk-destroy", Risk: "critical"}},
			rule:    UserSemanticRule{RiskMin: "critical"},
			want:    true,
		},
		{
			name:    "risk_min: high does not meet critical",
			intents: []CommandIntent{{Category: "file-delete", Risk: "high"}},
			rule:    UserSemanticRule{RiskMin: "critical"},
			want:    false,
		},
		{
			name:    "risk_min: high meets medium threshold",
			intents: []CommandIntent{{Category: "file-delete", Risk: "high"}},
			rule:    UserSemanticRule{RiskMin: "medium"},
			want:    true,
		},
		{
			name:    "risk_min: low meets low",
			intents: []CommandIntent{{Category: "info-query", Risk: "low"}},
			rule:    UserSemanticRule{RiskMin: "low"},
			want:    true,
		},
		{
			name:    "risk_min: info does not meet medium",
			intents: []CommandIntent{{Category: "info-query", Risk: "info"}},
			rule:    UserSemanticRule{RiskMin: "medium"},
			want:    false,
		},
		{
			name:    "risk_min + intent: both must match",
			intents: []CommandIntent{{Category: "disk-destroy", Risk: "critical"}},
			rule:    UserSemanticRule{Intent: "disk-destroy", RiskMin: "high"},
			want:    true,
		},
		{
			name:    "risk_min + intent: intent wrong → no match",
			intents: []CommandIntent{{Category: "file-delete", Risk: "critical"}},
			rule:    UserSemanticRule{Intent: "disk-destroy", RiskMin: "high"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchSemanticRule(tt.intents, tt.rule)
			if got != tt.want {
				t.Errorf("MatchSemanticRule() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: Semantic negate
// ---------------------------------------------------------------------------

func TestSemanticRule_Negate(t *testing.T) {
	tests := []struct {
		name    string
		intents []CommandIntent
		rule    UserSemanticRule
		want    bool
	}{
		{
			name:    "negate: intent present → negated = false",
			intents: []CommandIntent{{Category: "disk-destroy", Risk: "critical"}},
			rule:    UserSemanticRule{Intent: "disk-destroy", Negate: true},
			want:    false,
		},
		{
			name:    "negate: intent absent → negated = true (ALLOW override)",
			intents: []CommandIntent{{Category: "info-query", Risk: "low"}},
			rule:    UserSemanticRule{Intent: "disk-destroy", Negate: true},
			want:    true,
		},
		{
			name:    "negate: no intents → negated = true",
			intents: nil,
			rule:    UserSemanticRule{Intent: "disk-destroy", Negate: true},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchSemanticRule(tt.intents, tt.rule)
			if got != tt.want {
				t.Errorf("MatchSemanticRule() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: riskLevel ordering
// ---------------------------------------------------------------------------

func TestRiskLevel(t *testing.T) {
	levels := []string{"none", "info", "low", "medium", "high", "critical"}
	for i := 0; i < len(levels)-1; i++ {
		if riskLevel(levels[i]) >= riskLevel(levels[i+1]) {
			t.Errorf("riskLevel(%q) = %d should be < riskLevel(%q) = %d",
				levels[i], riskLevel(levels[i]), levels[i+1], riskLevel(levels[i+1]))
		}
	}
}

// ---------------------------------------------------------------------------
// Test: SemanticAnalyzer integration with user rules
// ---------------------------------------------------------------------------

func TestSemanticAnalyzer_UserRules(t *testing.T) {
	sa := NewStructuralAnalyzer(2)
	sem := NewSemanticAnalyzer()
	sem.SetUserRules([]UserSemanticRule{
		{
			ID:       "user-block-disk-destroy",
			Decision: "BLOCK",
			Reason:   "user rule: block all disk-destroy intents",
			Intent:   "disk-destroy",
		},
		{
			ID:       "user-allow-dns-safe",
			Decision: "ALLOW",
			Reason:   "user rule: allow safe DNS queries",
			Intent:   "dns-query-safe",
		},
	})

	tests := []struct {
		name       string
		command    string
		wantRuleID string
	}{
		{
			name:       "shred /dev/sda triggers disk-destroy intent → user rule matches",
			command:    "shred /dev/sda",
			wantRuleID: "user-block-disk-destroy",
		},
		{
			name:       "dig _dmarc.example.com triggers dns-query-safe → user ALLOW matches",
			command:    "dig _dmarc.example.com TXT",
			wantRuleID: "user-allow-dns-safe",
		},
		{
			name:       "ls -la triggers no semantic intent → no user rule",
			command:    "ls -la",
			wantRuleID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &AnalysisContext{RawCommand: tt.command}
			ctx.Parsed = sa.Parse(tt.command)
			findings := sem.Analyze(ctx)

			found := false
			for _, f := range findings {
				if f.RuleID == tt.wantRuleID {
					found = true
				}
			}

			if tt.wantRuleID != "" && !found {
				t.Errorf("expected finding %q, got %v", tt.wantRuleID, findingIDs(findings))
			}
			if tt.wantRuleID == "" {
				for _, f := range findings {
					if f.RuleID == "user-block-disk-destroy" || f.RuleID == "user-allow-dns-safe" {
						t.Errorf("unexpected user rule finding: %s", f.RuleID)
					}
				}
			}
		})
	}
}
