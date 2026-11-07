package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Issue #4560 at the shell hook surface: the event the hook records for a
// built-in unicode-zero-width BLOCK carries the approved taxonomy node, in the
// returned event, the local audit log line and the SaaS wire payload. The
// policy package pins the engine; this pins that the hook does not drop it.

const zeroWidthTaxonomyNode = "unauthorized-execution/agentic-attacks/invisible-unicode-prompt-injection"

// enforceHome is a scratch HOME with the shipped (embedded) packs, no disk
// packs, no policy file and `mode: enforce`, so the decision under test is
// the one a fresh enforcing install makes.
func enforceHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".agentshield")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agentshield.yaml"), []byte("mode: enforce\n"), 0o600); err != nil {
		t.Fatalf("WriteFile agentshield.yaml: %v", err)
	}
	return home
}

func TestEvaluateCommand_ZeroWidthBlockEventCarriesInvisibleUnicodeNode(t *testing.T) {
	home := enforceHome(t)
	// Assembled from the code point: a literal invisible character in source
	// is unreviewable.
	command := "echo hel" + string(rune(0x200B)) + "lo"

	result, event := evaluateCommand(command, "/workspace/acme-api", "claude-code-hook", "sess-4560")
	if result.Decision != policy.DecisionBlock {
		t.Fatalf("decision = %s, want BLOCK (rules=%v)", result.Decision, result.TriggeredRules)
	}
	if event == nil {
		t.Fatal("evaluateCommand returned a nil AuditEvent")
	}
	if !containsStr(event.TriggeredRules, "unicode-zero-width") {
		t.Fatalf("event rules = %v, want unicode-zero-width", event.TriggeredRules)
	}
	want := []string{zeroWidthTaxonomyNode}
	if !reflect.DeepEqual(event.TaxonomyRefs, want) {
		t.Errorf("event taxonomy = %v, want exactly %v", event.TaxonomyRefs, want)
	}

	logged := readAuditEventsForTest(t, home)
	if len(logged) != 1 {
		t.Fatalf("expected 1 logged event, got %d", len(logged))
	}
	if logged[0].Decision != "BLOCK" || !reflect.DeepEqual(logged[0].TaxonomyRefs, want) {
		t.Errorf("logged event = {decision:%s taxonomy:%v}, want {BLOCK %v}", logged[0].Decision, logged[0].TaxonomyRefs, want)
	}

	payload, err := buildAuditPayload(event, "")
	if err != nil {
		t.Fatalf("buildAuditPayload: %v", err)
	}
	if !strings.Contains(string(payload), zeroWidthTaxonomyNode) {
		t.Errorf("wire payload does not carry the node: %s", payload)
	}
}

// Control: another built-in, recorded through the same hook path, still
// carries no node. The homoglyph rule fires alone on this input (no pack rule
// or guardian signal cites a node for it), so an empty taxonomy here is the
// built-in's own, not a side effect of something else winning.
func TestEvaluateCommand_HomoglyphBuiltinEventCarriesNoTaxonomy(t *testing.T) {
	home := enforceHome(t)
	command := "echo c" + string(rune(0x0430)) + "fe"

	result, event := evaluateCommand(command, "/workspace/acme-api", "claude-code-hook", "sess-4560-control")
	if result.Decision != policy.DecisionAudit {
		t.Fatalf("decision = %s, want AUDIT (rules=%v)", result.Decision, result.TriggeredRules)
	}
	if !reflect.DeepEqual(event.TriggeredRules, []string{"unicode-homoglyph-cyrillic"}) {
		t.Fatalf("event rules = %v, want exactly [unicode-homoglyph-cyrillic]", event.TriggeredRules)
	}
	if len(event.TaxonomyRefs) != 0 {
		t.Errorf("event taxonomy = %v, want none: only unicode-zero-width has an approved node (#4560)", event.TaxonomyRefs)
	}
	logged := readAuditEventsForTest(t, home)
	if len(logged) != 1 || len(logged[0].TaxonomyRefs) != 0 {
		t.Errorf("logged events = %+v, want one with no taxonomy", logged)
	}
}
