package policy

import (
	"testing"
)

// #3717 — command_intent_downgrade/_exclude attributed a match to the wrong
// statement.
//
// The per-statement predicate tested each top-level statement with the plain
// matcher against RAW text, while the top-level match folded ${IFS}
// separators, unset-parameter splices and friends. In a compound command
// pairing an obfuscated REAL invocation with an unobfuscated doc-text sibling
// that repeats the rule's pattern verbatim, the real statement did not count
// as matching and was skipped, so the doc-text sibling carried the whole
// decision and the executed BLOCK downgraded to AUDIT (or, under
// command_intent_exclude, vanished entirely).
//
// Fail-open, and specifically an ATTESTATION defect: the audit record then
// says "documented, not executed" about a statement that executed.

// foldDowngradeCases is the #3717 probe table, identical to the analyzer-side
// table in internal/analyzer/downgrade_statement_fold_test.go and to the
// corpus cases TP/TN-SYSTEMD-RUN-010..017 / TP-SYSTEMD-RUN-CARRIER-001..003.
// Keeping one table in three places is deliberate: the point of the issue is
// that two evaluation paths disagreed about the SAME command, so the tables
// have to be the same command list.
//
// wantExcluded is IntentExcludedForStatements' verdict — "every statement that
// makes this rule fire is doc-text". Each row is run against BOTH intent
// labels, because they share the predicate and the statement list:
//
//	command_intent_downgrade -> excluded means BLOCK becomes AUDIT, rule still fires
//	command_intent_exclude   -> excluded means the rule does not fire at all
//
// Running only the downgrade label left the exclude call site un-load-bearing:
// reverting it alone survived every test (found by adversarial review of #3724).
var foldDowngradeCases = []struct {
	probe        string
	name         string
	cmd          string
	wantExcluded bool
}{
	{
		probe:        "P1",
		name:         "IFS-obfuscated real statement + verbatim doc-text sibling",
		cmd:          `systemd-run${IFS}--system /tmp/payload.sh; git commit -m \"deploying via systemd-run --system for persistence, documented here\"`,
		wantExcluded: false,
	},
	{
		probe:        "P2",
		name:         "unset-param-splice real statement + verbatim doc-text sibling",
		cmd:          `s${zqx}ystemd-run --system /tmp/payload.sh; git commit -m \"deploying via systemd-run --system for persistence, documented here\"`,
		wantExcluded: false,
	},
	{
		probe:        "P3",
		name:         "unobfuscated real invocation alone (positive control)",
		cmd:          `systemd-run --system /tmp/payload.sh`,
		wantExcluded: false,
	},
	{
		probe:        "P4",
		name:         "doc-text statement alone keeps its downgrade (FP protection)",
		cmd:          `git commit -m \"deploying via systemd-run --system for persistence, documented here\"`,
		wantExcluded: true,
	},
	{
		probe:        "P5",
		name:         "doc-text statement chained with an unrelated benign command",
		cmd:          `git commit -m \"deploying via systemd-run --system for persistence, documented here\"; echo done`,
		wantExcluded: true,
	},
	{
		probe:        "P6",
		name:         "IFS-obfuscated real invocation alone (no doc-text sibling)",
		cmd:          `systemd-run${IFS}--system /tmp/payload.sh`,
		wantExcluded: false,
	},
	// --- carrier payloads: the dangerous statement and the doc-text statement
	// both live inside ONE carrier body, so the raw top-level split yields a
	// single statement whose own text reads as doc-text. Attribution has to see
	// the carrier's resolved statements (AttributionStatements) or the whole
	// command is laundered. Found by adversarial review of #3724; the fallback
	// engine was reaching AUDIT on all three while the pipeline reached BLOCK.
	{
		probe:        "C1",
		name:         "eval carrier: IFS-obfuscated real + doc-text, both inside the body",
		cmd:          `eval 'systemd-run${IFS}--system /tmp/payload.sh; git commit -m "using systemd-run --system"'`,
		wantExcluded: false,
	},
	{
		probe:        "C2",
		name:         "bash -c carrier: IFS-obfuscated real + doc-text, both inside the body",
		cmd:          `bash -c 'systemd-run${IFS}--system /tmp/payload.sh; git commit -m "using systemd-run --system"'`,
		wantExcluded: false,
	},
	{
		probe:        "C3",
		name:         "eval carrier, no obfuscation at all (pre-#3717 divergence control)",
		cmd:          `eval 'systemd-run --system /tmp/payload.sh; git commit -m "using systemd-run --system"'`,
		wantExcluded: false,
	},
	// --- assignment-invalidated folds: bash resolves shell parameters against
	// the whole shell, not one statement, so a fold applied to an isolated
	// statement can invent an invocation that never runs. `IFS=` makes
	// `${IFS}` empty (one concatenated word); `x=:` means the `${x:-...}`
	// default never fires. Both must stay excused — the doc-text sibling is
	// the only statement that legitimately matches. Found by adversarial
	// review of #3724, where the first cut turned these into false BLOCKs.
	{
		probe:        "N1",
		name:         "empty IFS assigned in a sibling statement invalidates the IFS fold",
		cmd:          `IFS=; : systemd-run${IFS}--system; git commit -m "using systemd-run --system"`,
		wantExcluded: true,
	},
	{
		probe:        "N2",
		name:         "default-value expansion whose name IS assigned in a sibling statement",
		cmd:          `x=:; ${x:-systemd-run} --system /tmp/payload.sh; git commit -m "using systemd-run --system"`,
		// #3798 strict purity: an expanded command word makes the line
		// impure, so the doc-text exemption is void. Accepted cost (Gary,
		// 2026-09-23); corpus mirror TN-SYSTEMD-RUN-017 is now FP.
		wantExcluded: false,
	},
}

const foldRulePattern = `systemd-run\s+.*--system`

// foldDowngradeRule and foldExcludeRule are the same rule under the two intent
// labels, mirroring packs/community/terminal-safety.yaml's
// ts-block-systemd-run-system. A one-rule policy keeps the assertion about THIS
// mechanism — with the shipped packs loaded, a sibling rule or the guardian
// stage can supply a BLOCK of its own and the test would pass with the fix
// entirely removed.
func foldDowngradeRule() Rule {
	return Rule{
		ID:       "test-fold-downgrade-3717",
		Taxonomy: "persistence-evasion/transient-persistence/systemd-run-root",
		Match: Match{
			CommandRegex:           foldRulePattern,
			CommandIntentDowngrade: []string{"is_doc_text", "in_heredoc"},
		},
		Decision:   DecisionBlock,
		Confidence: 0.95,
		Reason:     "test rule (downgrade label)",
	}
}

func foldExcludeRule() Rule {
	return Rule{
		ID:       "test-fold-exclude-3717",
		Taxonomy: "persistence-evasion/transient-persistence/systemd-run-root",
		Match: Match{
			CommandRegex:         foldRulePattern,
			CommandIntentExclude: []string{"is_doc_text", "in_heredoc"},
		},
		Decision:   DecisionBlock,
		Confidence: 0.95,
		Reason:     "test rule (exclude label)",
	}
}

func onePolicy(r Rule) *Policy {
	return &Policy{
		Version:  "0.1",
		Defaults: Defaults{Decision: DecisionAudit},
		Rules:    []Rule{r},
	}
}

// TestEffectiveDecision_StatementFoldAware_3717 pins the regex-fallback half
// directly, at the function the downgrade lives in.
func TestEffectiveDecision_StatementFoldAware_3717(t *testing.T) {
	engine, err := NewEngine(onePolicy(foldDowngradeRule()))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	rule := foldDowngradeRule()
	for _, tt := range foldDowngradeCases {
		t.Run(tt.probe+"/"+tt.name, func(t *testing.T) {
			want := DecisionBlock
			if tt.wantExcluded {
				want = DecisionAudit
			}
			if got := engine.effectiveDecision(tt.cmd, rule); got != want {
				t.Errorf("effectiveDecision(%q) = %v, want %v", tt.cmd, got, want)
			}
		})
	}
}

// TestIntentExcluded_StatementFoldAware_3717 is the command_intent_exclude
// mirror. Without it, reverting either exclude call site alone survives every
// other test in this PR — every rule added exercised the downgrade label only.
func TestIntentExcluded_StatementFoldAware_3717(t *testing.T) {
	engine, err := NewEngine(onePolicy(foldExcludeRule()))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	rule := foldExcludeRule()
	for _, tt := range foldDowngradeCases {
		t.Run(tt.probe+"/"+tt.name, func(t *testing.T) {
			if got := engine.intentExcluded(tt.cmd, rule); got != tt.wantExcluded {
				t.Errorf("intentExcluded(%q) = %v, want %v", tt.cmd, got, tt.wantExcluded)
			}
		})
	}
}

// TestDowngradeStatementFoldParityAcrossEvaluationPaths_3717 is the fitness
// function that keeps the two halves from drifting again — the trap this repo
// has now sprung on command_regex_exclude (#3232), command_intent_exclude
// (#3234) and command_position_exclude (#3376).
//
// Each row is evaluated four ways: {downgrade label, exclude label} x
// {regex-only fallback, full analyzer pipeline}. Every combination asserts the
// verdict, that the two paths agree, and — for the rows where the rule is
// meant to fire — that the rule's OWN id is on the result, because a one-rule
// policy plus a guardian BLOCK would otherwise make the assertion vacuous.
func TestDowngradeStatementFoldParityAcrossEvaluationPaths_3717(t *testing.T) {
	labels := []struct {
		name string
		rule func() Rule
		// want returns the expected decision and whether the rule id must be
		// present on the result.
		want func(excluded bool) (Decision, bool)
	}{
		{
			name: "downgrade",
			rule: foldDowngradeRule,
			// A downgraded rule still FIRES — that is the whole point of
			// downgrade over exclude: the event stays attested.
			want: func(excluded bool) (Decision, bool) {
				if excluded {
					return DecisionAudit, true
				}
				return DecisionBlock, true
			},
		},
		{
			name: "exclude",
			rule: foldExcludeRule,
			want: func(excluded bool) (Decision, bool) {
				if excluded {
					return DecisionAudit, false
				}
				return DecisionBlock, true
			},
		},
	}

	for _, lb := range labels {
		t.Run(lb.name, func(t *testing.T) {
			fallback, err := NewEngine(onePolicy(lb.rule()))
			if err != nil {
				t.Fatalf("NewEngine: %v", err)
			}
			pipeline, err := NewEngineWithAnalyzers(onePolicy(lb.rule()), 2)
			if err != nil {
				t.Fatalf("NewEngineWithAnalyzers: %v", err)
			}
			ruleID := lb.rule().ID

			for _, tt := range foldDowngradeCases {
				t.Run(tt.probe+"/"+tt.name, func(t *testing.T) {
					want, wantFired := lb.want(tt.wantExcluded)
					fb := fallback.Evaluate(tt.cmd, nil)
					pl := pipeline.Evaluate(tt.cmd, nil)

					if fb.Decision != want {
						t.Errorf("regex-fallback Evaluate(%q) = %v, want %v (rules=%v)", tt.cmd, fb.Decision, want, fb.TriggeredRules)
					}
					if pl.Decision != want {
						t.Errorf("pipeline Evaluate(%q) = %v, want %v (rules=%v)", tt.cmd, pl.Decision, want, pl.TriggeredRules)
					}
					if fb.Decision != pl.Decision {
						t.Errorf("evaluation paths DISAGREE on %q: fallback=%v pipeline=%v", tt.cmd, fb.Decision, pl.Decision)
					}
					assertRuleFired(t, "regex-fallback", ruleID, tt.cmd, fb, wantFired)
					assertRuleFired(t, "pipeline", ruleID, tt.cmd, pl, wantFired)
				})
			}
		})
	}
}

func assertRuleFired(t *testing.T, path, ruleID, cmd string, r EvalResult, want bool) {
	t.Helper()
	got := false
	for _, id := range r.TriggeredRules {
		if id == ruleID {
			got = true
			break
		}
	}
	if got != want {
		t.Errorf("%s: rule %s fired=%v want %v on %q (rules=%v decision=%v)", path, ruleID, got, want, cmd, r.TriggeredRules, r.Decision)
	}
}
