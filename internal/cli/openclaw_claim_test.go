package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// OpenClaw has no integration that sends a tool call to `agentshield hook`:
// the installed hook subscribes to agent:bootstrap and injects text. These
// tests pin that nothing we print or ship says otherwise (#4582). If a real
// pre-tool-call integration lands, replace them with a live block test.

func TestOpenClawStatus_DoesNotReportEnforcement_4582(t *testing.T) {
	home := t.TempDir()
	hookDir := filepath.Join(home, ".openclaw", "hooks", "agentshield")
	if err := os.MkdirAll(hookDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, "handler.ts"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	out := captureStdout(t, checkOpenClawHook)
	if strings.Contains(out, "✅") || strings.Contains(out, "hook active") {
		t.Errorf("status reports OpenClaw as protected: %q", out)
	}
	if !strings.Contains(out, "NOT evaluated") {
		t.Errorf("status must say commands are not evaluated: %q", out)
	}
}

func TestOpenClawShippedText_MakesNoEnforcementClaim_4582(t *testing.T) {
	dir := filepath.Join("..", "..", "openclaw-hook", "agentshield")
	for _, name := range []string{"AGENTSHIELD.md", "HOOK.md", "handler.ts"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		text := strings.ToLower(string(b))
		for _, claim := range []string{
			"evaluates every",
			"will intercept",
			"pretooluse hook evaluates",
			"blocked before execution",
			"7-layer",
		} {
			if strings.Contains(text, claim) {
				t.Errorf("%s still claims enforcement: %q", name, claim)
			}
		}
		if !strings.Contains(text, "not") {
			t.Errorf("%s does not state the limitation", name)
		}
	}
}
