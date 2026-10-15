package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// #4351 under audit-only, the default for new installs. A pack rule authored
// against the bare tool name must put its would-be block on the record for the
// namespaced call, exactly as it does for the bare call. Before the shared
// helper, the hook kept the bare reading only on a live BLOCK, which audit-only
// never produces, so the namespaced call was recorded as AUDIT with no rule.
func TestHook_MCPNamespacedRecordedUnderAuditOnly(t *testing.T) {
	const auditOnlyPolicy = `version: "0.1"
enforcement_mode: "audit-only"
defaults:
  decision: "AUDIT"
rules: []
`
	path := map[string]interface{}{"path": "/home/user/" + ".vault-token"}
	for _, tool := range []string{"read_file", "mcp__fs__read_file"} {
		home, configDir := newFailSafeHome(t, false, auditOnlyPolicy)
		code, _, stderr := runHookChild(t, home, claudeToolPayload(t, "ao", tool, path))
		if code != 0 {
			t.Fatalf("%s: exit %d, want 0 under audit-only. stderr:\n%s", tool, code, stderr)
		}
		var ev struct {
			Decision         string   `json:"decision"`
			OriginalDecision string   `json:"original_decision"`
			TriggeredRules   []string `json:"triggered_rules"`
		}
		lines := strings.Split(strings.TrimSpace(readFailSafeAuditLog(t, configDir)), "\n")
		if err := json.Unmarshal([]byte(lines[len(lines)-1]), &ev); err != nil {
			t.Fatalf("%s: audit line: %v", tool, err)
		}
		if ev.Decision != "AUDIT" || ev.OriginalDecision != "BLOCK" || len(ev.TriggeredRules) == 0 {
			t.Errorf("%s: recorded %q/%q rules %v, want AUDIT/BLOCK with the bare-name rule",
				tool, ev.Decision, ev.OriginalDecision, ev.TriggeredRules)
		}
	}
}
