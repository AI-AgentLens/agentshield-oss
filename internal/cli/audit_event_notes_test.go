package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #3995 (Opus review mutation e): the hook's AuditEvent construction must
// carry the evaluation's notes, and the logged line must too. A test-only
// rule with an intent exclusion, excused by a bash comment, is the shape:
// the pattern fires, the label excuses it, the event names both.
func TestEvaluateCommand_AuditEventCarriesNotes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	configDir := filepath.Join(home, ".agentshield")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	policyYAML := `version: "0.1"

defaults:
  decision: "ALLOW"

rules:
  - id: e2e-block-frobnicate-excusable
    match:
      command_regex: "frobnicate"
      command_intent_exclude: [is_bash_comment]
    decision: "BLOCK"
    reason: "Test-only rule for the notes contract."
`
	if err := os.WriteFile(filepath.Join(configDir, "policy.yaml"), []byte(policyYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	evalResult, event := evaluateCommand("# frobnicate later", "/workspace/acme-api", "claude-code-hook", "sess-3995")
	if evalResult.Decision == policy.DecisionBlock {
		t.Fatalf("a bash comment must not BLOCK: %v", evalResult.TriggeredRules)
	}
	want := analyzer.Note{Kind: analyzer.NoteExcused, Rule: "e2e-block-frobnicate-excusable", Detail: "intent:is_bash_comment"}
	found := false
	for _, n := range evalResult.Notes {
		if n == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("EvalResult.Notes = %v; want %v", evalResult.Notes, want)
	}
	if event == nil {
		t.Fatal("evaluateCommand returned a nil AuditEvent")
	}
	if len(event.Notes) != 1 || event.Notes[0].Kind != want.Kind || event.Notes[0].Rule != want.Rule || event.Notes[0].Detail != want.Detail {
		t.Fatalf("AuditEvent.Notes = %v; the EvalResult knew the note and the audit event dropped it", event.Notes)
	}

	logged := readAuditEventsForTest(t, home)
	if len(logged) != 1 || len(logged[0].Notes) != 1 || logged[0].Notes[0].Rule != want.Rule {
		t.Fatalf("logged event notes = %+v; want the excused note on disk", logged)
	}

	// And a benign command logs no notes key at all.
	_, benign := evaluateCommand("ls -la", "/workspace/acme-api", "claude-code-hook", "sess-3995")
	if benign == nil || benign.Notes != nil {
		t.Fatalf("benign event must omit notes: %+v", benign)
	}
}
