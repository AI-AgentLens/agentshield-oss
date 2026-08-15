package policy

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/execenv"
)

// This file is the fitness function for the CI-context match dimension (issue
// #3291). It proves the gate actually gates: the SAME command flips decision
// with the SAME engine and ruleset, changing only the detected execution
// context. It exercises both evaluation paths — the analyzer pipeline (what the
// hook and `agentshield check` run in production) and the regex-only fallback —
// because match semantics live in two places in this codebase and have drifted
// before.

// loadCIContextPolicy loads the embedded community packs (which include
// ci-context.yaml) plus the disk premium packs, mirroring the hook's ruleset.
func loadCIContextPolicy(t *testing.T) *Policy {
	t.Helper()
	pol, _, err := LoadEmbeddedShellPacks(DefaultPolicy())
	if err != nil {
		t.Fatalf("LoadEmbeddedShellPacks: %v", err)
	}
	pol, _, err = LoadPacks(packsDir(), pol)
	if err != nil {
		t.Fatalf("LoadPacks: %v", err)
	}
	return pol
}

var ciContextCases = []struct {
	name       string
	command    string
	rule       string // the CI-context rule expected to fire in CI
	inCIDecion Decision
}{
	{"env-dump-bare", "env", "ci-block-env-dump", DecisionBlock},
	{"env-dump-printenv", "printenv", "ci-block-env-dump", DecisionBlock},
	{"env-dump-piped", "env | grep -i token", "ci-block-env-dump", DecisionBlock},
	{"secrets-enum-gh", "gh secret list -R org/repo", "ci-block-cicd-secrets-enumeration", DecisionBlock},
	{"secrets-enum-glab", "glab variable list --project org/prod-api", "ci-block-cicd-secrets-enumeration", DecisionBlock},
}

// assertGate runs one command under CI and non-CI contexts and asserts the flip.
func assertGate(t *testing.T, newEngine func() *Engine, path string) {
	t.Helper()
	for _, tc := range ciContextCases {
		t.Run(path+"/"+tc.name, func(t *testing.T) {
			// --- In CI: the tightened rule fires. ---
			ci := newEngine()
			ci.SetExecContext(execenv.Context{CI: true, Provider: "github-actions"})
			got := ci.Evaluate(tc.command, nil)
			if got.Decision != tc.inCIDecion {
				t.Errorf("in CI: %q => %s, want %s (triggered: %v)",
					tc.command, got.Decision, tc.inCIDecion, got.TriggeredRules)
			}
			if !ciContains(got.TriggeredRules, tc.rule) {
				t.Errorf("in CI: %q did not trigger %s (triggered: %v)",
					tc.command, tc.rule, got.TriggeredRules)
			}

			// --- Outside CI (the same command, same engine kind): the tightened
			// rule must NOT fire, and the decision must not be the tightened
			// BLOCK. This is the issue's "TN: same command outside CI context". ---
			noci := newEngine() // zero-value exec context = not CI
			out := noci.Evaluate(tc.command, nil)
			if ciContains(out.TriggeredRules, tc.rule) {
				t.Errorf("outside CI: %q wrongly triggered CI-only rule %s (triggered: %v)",
					tc.command, tc.rule, out.TriggeredRules)
			}
			if out.Decision == DecisionBlock {
				t.Errorf("outside CI: %q got BLOCK (%v) — CI-only tightening leaked to the trusted-developer baseline",
					tc.command, out.TriggeredRules)
			}
		})
	}
}

func TestCIContextGate_Pipeline(t *testing.T) {
	pol := loadCIContextPolicy(t)
	assertGate(t, func() *Engine {
		e, err := NewEngineWithAnalyzers(pol, 2)
		if err != nil {
			t.Fatalf("NewEngineWithAnalyzers: %v", err)
		}
		return e
	}, "pipeline")
}

func TestCIContextGate_RegexFallback(t *testing.T) {
	pol := loadCIContextPolicy(t)
	assertGate(t, func() *Engine {
		e, err := NewEngine(pol)
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		return e
	}, "fallback")
}

// TestCIContextGate_ProviderIndependent confirms the gate keys on CI-ness, not a
// specific provider string.
func TestCIContextGate_ProviderIndependent(t *testing.T) {
	pol := loadCIContextPolicy(t)
	e, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	for _, prov := range []string{"github-actions", "gitlab-ci", "generic"} {
		e.SetExecContext(execenv.Context{CI: true, Provider: prov})
		if got := e.Evaluate("env", nil); got.Decision != DecisionBlock {
			t.Errorf("provider %s: env => %s, want BLOCK", prov, got.Decision)
		}
	}
}

// TestContextGate_RejectedOnNonRegexRule is the fitness function for the
// load-time guard in BuildAnalyzerPipeline: a match.context gate on a
// non-regex-family rule must fail loud rather than silently no-op.
func TestContextGate_RejectedOnNonRegexRule(t *testing.T) {
	ciTrue := true
	pol := &Policy{
		Rules: []Rule{{
			ID:       "bad-context-on-structural",
			Taxonomy: "credential-exposure/secret-env-exposure/env-dump",
			Match: Match{
				Context:    &ContextMatch{CI: &ciTrue},
				Structural: &StructuralMatch{Executable: StringOrList{"env"}},
			},
			Decision: DecisionBlock,
			Reason:   "test",
		}},
	}
	_, err := BuildAnalyzerPipeline(pol, 2)
	if err == nil {
		t.Fatal("expected BuildAnalyzerPipeline to reject match.context on a structural rule, got nil")
	}
	if !strings.Contains(err.Error(), "context") {
		t.Errorf("error should mention context, got: %v", err)
	}
}

func ciContains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
