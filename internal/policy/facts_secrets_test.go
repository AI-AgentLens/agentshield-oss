package policy

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
)

// EvaluateInlineSecrets is the shell pipeline's inline-secrets heuristic over
// a dialect lane's text (#4802). Each row is first evaluated as a shell
// command on the same engine (the control: the Bash twin decides on the
// guardian's finding), then through EvaluateInlineSecrets, which must give
// that finding's decision, rule, reason and taxonomy.
//
// Token-shaped strings are assembled at run time: the hook on a developer
// machine reads test sources it is asked to run as commands.

const secretsRule = "guardian-secrets_in_command"

func secretsToken() string { return "gh" + "p_" + strings.Repeat("a1B2", 9) }

// bashSecretsRecord is the shell pipeline's guardian-secrets record on text:
// its decision and the rule's reason and node, or ok false when the rule is
// not among the triggered rules.
func bashSecretsRecord(t *testing.T, e *Engine, text string) (EvalResult, bool) {
	t.Helper()
	r := e.Evaluate(text, nil)
	i := slices.Index(r.TriggeredRules, secretsRule)
	if i < 0 {
		return r, false
	}
	return r, true
}

func TestEvaluateInlineSecrets_BashTwin(t *testing.T) {
	e := factsEngine(t)
	rows := []struct{ text, decision string }{
		{"Write-Output " + secretsToken(), "BLOCK"},
		{"$env:GITHUB_TOKEN = '" + secretsToken() + "'; gh repo list", "BLOCK"},
		{"[Environment]::SetEnvironmentVariable('GITHUB_TOKEN', '" + secretsToken() + "', 'User')", "BLOCK"},
		{"$env:API" + "_KEY = 'notarealvalue'", "AUDIT"},
	}
	for _, row := range rows {
		bash, ok := bashSecretsRecord(t, e, row.text)
		if !ok || string(bash.Decision) != row.decision {
			t.Fatalf("control: the shell pipeline decides %s %v on %q; want %s by %s", bash.Decision, bash.TriggeredRules, row.text, row.decision, secretsRule)
		}
		got, ok := e.EvaluateInlineSecrets(row.text)
		if !ok {
			t.Fatalf("%q: EvaluateInlineSecrets did not fire", row.text)
		}
		want := EvalResult{
			Decision:       Decision(row.decision),
			TriggeredRules: []string{secretsRule},
			Reasons:        []string{bash.Reasons[slices.Index(bash.TriggeredRules, secretsRule)]},
			TaxonomyRefs:   []string{"credential-exposure/inline-credential/secret-in-command-line"},
		}
		want.Explanation = buildExplanation(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q:\n got  %+v\n want %+v", row.text, got, want)
		}
		if !slices.Contains(bash.TaxonomyRefs, want.TaxonomyRefs[0]) {
			t.Errorf("%q: the shell's taxonomy %v lacks %s", row.text, bash.TaxonomyRefs, want.TaxonomyRefs[0])
		}
	}
	if r, ok := e.EvaluateInlineSecrets("Get-ChildItem -Recurse | Select-Object -First 5"); ok {
		t.Errorf("benign text: %+v; want nothing", r)
	}
}

// TestEvaluateInlineSecrets_AuditOnly: audit-only mode lowers the BLOCK to
// AUDIT and records it as the original decision, as the shell does for the
// same text.
func TestEvaluateInlineSecrets_AuditOnly(t *testing.T) {
	e := factsEngine(t)
	e.SetMode("audit-only")
	text := "Write-Output " + secretsToken()
	bash := e.Evaluate(text, nil)
	if bash.Decision != DecisionAudit || bash.OriginalDecision != DecisionBlock {
		t.Fatalf("control: the shell decides %s (was %s) in audit-only; want AUDIT (was BLOCK)", bash.Decision, bash.OriginalDecision)
	}
	got, ok := e.EvaluateInlineSecrets(text)
	if !ok || got.Decision != DecisionAudit || got.OriginalDecision != DecisionBlock || !slices.Equal(got.TriggeredRules, []string{secretsRule}) {
		t.Errorf("audit-only: %+v, %v; want AUDIT (was BLOCK) by %s", got, ok, secretsRule)
	}
}

// TestEvaluateInlineSecrets_OnlyWhereTheShellRunsTheGuardian: an engine whose
// shell evaluation has no guardian stage (no pipeline: the regex-only
// fallback; or a pipeline without the stage) reports nothing, as its shell
// evaluation of the same text names no guardian rule (the control).
func TestEvaluateInlineSecrets_OnlyWhereTheShellRunsTheGuardian(t *testing.T) {
	text := "Write-Output " + secretsToken()

	bare, err := NewEngine(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bashSecretsRecord(t, bare, text); ok {
		t.Fatal("control: the regex-only engine names the guardian rule")
	}
	if r, ok := bare.EvaluateInlineSecrets(text); ok {
		t.Errorf("no pipeline: %+v; want nothing", r)
	}

	noGuardian, err := NewEngine(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	noGuardian.SetRegistry(analyzer.NewRegistry([]analyzer.Analyzer{analyzer.NewRegexAnalyzer(nil)}, nil))
	if _, ok := bashSecretsRecord(t, noGuardian, text); ok {
		t.Fatal("control: a pipeline without the guardian names the guardian rule")
	}
	if r, ok := noGuardian.EvaluateInlineSecrets(text); ok {
		t.Errorf("pipeline without the guardian: %+v; want nothing", r)
	}

	if _, ok := factsEngine(t).EvaluateInlineSecrets(text); !ok {
		t.Error("positive control: the full pipeline's engine does not fire")
	}
}
