package policy

import (
	"path/filepath"
	"reflect"
	"testing"
)

// The audit-only keep rule sees the files a protected_paths match decided a
// BLOCK on, resolved (#4424). On a managed host AgentShield's directory is a
// protected path and that check returns before the pipeline, so without the
// files the keep saw only "protected-path" and lowered the BLOCK.

type keepCall struct {
	rules, hits []string
}

// recordingKeep records every call and keeps when keepIt says so.
func recordingKeep(calls *[]keepCall, keepIt bool) SelfProtectionKeep {
	return func(command string, rules, hits []string) bool {
		*calls = append(*calls, keepCall{append([]string{}, rules...), append([]string{}, hits...)})
		return keepIt
	}
}

func keepHitsPolicy() *Policy {
	return &Policy{
		Defaults: Defaults{Decision: DecisionAudit, ProtectedPaths: []string{"~/.zq-other/**", "~/.zq-sp/**"}},
		Rules: []Rule{
			{ID: "zq-plain-block", Match: Match{CommandRegex: `^zqblock\b`}, Decision: DecisionBlock, Reason: "test"},
		},
	}
}

func TestSelfProtectionKeep_ProtectedPathHits(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sp, other := filepath.Join(home, ".zq-sp", "audit.jsonl"), filepath.Join(home, ".zq-other", "a")
	for _, tc := range []struct {
		name     string
		command  string
		paths    []string
		cwd      string
		wantHits []string
	}{
		{"an absolute path", "rm x", []string{sp}, "", []string{sp}},
		{"a ~ spelling, expanded", "rm x", []string{"~/.zq-sp/audit.jsonl"}, "", []string{sp}},
		{"every pattern's hits, not the first pattern's", "rm x y", []string{other, sp}, "", []string{other, sp}},
		{"a path no pattern matches is not a hit", "rm x y", []string{filepath.Join(home, "plain"), sp}, "", []string{sp}},
		{"no protected-path match: no hits", "zqblock now", nil, "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := NewEngine(keepHitsPolicy())
			if err != nil {
				t.Fatal(err)
			}
			e.SetMode("audit-only")
			var calls []keepCall
			e.SetSelfProtectionKeep(recordingKeep(&calls, true))
			r := e.EvaluateWithParsedCwd(tc.command, tc.paths, nil, tc.cwd)
			if r.Decision != DecisionBlock || r.OriginalDecision != "" {
				t.Errorf("kept: %s (original %q), want BLOCK", r.Decision, r.OriginalDecision)
			}
			if len(calls) == 0 {
				t.Fatal("keep never asked")
			}
			if got := calls[0].hits; !reflect.DeepEqual(got, tc.wantHits) && !(len(got) == 0 && len(tc.wantHits) == 0) {
				t.Errorf("hits %v, want %v (rules %v)", got, tc.wantHits, calls[0].rules)
			}
		})
	}
}

// The materialized-path post-pass passes its files too.
func TestSelfProtectionKeep_SubstitutionHits(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	e, err := NewEngineWithAnalyzers(keepHitsPolicy(), 0)
	if err != nil {
		t.Fatal(err)
	}
	e.SetMode("audit-only")
	var calls []keepCall
	e.SetSelfProtectionKeep(recordingKeep(&calls, false))
	r := e.Evaluate("P=~/.zq-sp; cat $P/audit.jsonl", nil)
	if r.OriginalDecision != DecisionBlock || !reflect.DeepEqual(calls[len(calls)-1].rules, r.TriggeredRules) {
		t.Fatalf("setup: %s (original %q, rules %v); want a protected-path-via-substitution BLOCK the keep declined", r.Decision, r.OriginalDecision, r.TriggeredRules)
	}
	want := []string{filepath.Join(home, ".zq-sp", "audit.jsonl")}
	if got := calls[len(calls)-1].hits; !reflect.DeepEqual(got, want) {
		t.Errorf("hits %v, want %v (rules %v)", got, want, r.TriggeredRules)
	}
}

// Enforce mode never asks the keep and never resolves the hits; a declined
// keep downgrades as before.
func TestSelfProtectionKeep_EnforceNeverAsks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sp := filepath.Join(home, ".zq-sp", "audit.jsonl")
	for _, mode := range []string{"", "enforce"} {
		e, err := NewEngine(keepHitsPolicy())
		if err != nil {
			t.Fatal(err)
		}
		e.SetMode(mode)
		var calls []keepCall
		e.SetSelfProtectionKeep(recordingKeep(&calls, true))
		if r := e.Evaluate("rm x", []string{sp}); r.Decision != DecisionBlock || len(calls) != 0 {
			t.Errorf("mode %q: %s, %d keep calls; want BLOCK, none", mode, r.Decision, len(calls))
		}
	}
	e, _ := NewEngine(keepHitsPolicy())
	e.SetMode("audit-only")
	var calls []keepCall
	e.SetSelfProtectionKeep(recordingKeep(&calls, false))
	if r := e.Evaluate("rm x", []string{sp}); r.Decision != DecisionAudit || r.OriginalDecision != DecisionBlock {
		t.Errorf("declined keep: %s (original %q), want AUDIT (original BLOCK)", r.Decision, r.OriginalDecision)
	}
}
