package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// #4457 through the real hook entry point: a git hook written through a
// harness's own file tool exits 2 in enforce mode and is recorded with the
// shell rule's node; audit-only records it as a downgraded BLOCK; an
// instruction file stays AUDIT, record-only.

const harnessHookNode = "persistence-evasion/cicd-tampering/git-hook-injection"

func harnessHookTarget(prefix string) string { return prefix + ".git" + "/hooks/" + "pre-commit" }

// claudeToolPayloadAt is claudeToolPayload with the session cwd chosen, so a
// relative target resolves against a real directory.
func claudeToolPayloadAt(t *testing.T, cwd, tool string, input interface{}) string {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"hook_event_name": "PreToolUse",
		"session_id":      "hk",
		"transcript_path": "/tmp/t.jsonl",
		"cwd":             cwd,
		"tool_name":       tool,
		"tool_input":      input,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type harnessHookEvent struct {
	Decision         string   `json:"decision"`
	OriginalDecision string   `json:"original_decision"`
	TriggeredRules   []string `json:"triggered_rules"`
	Taxonomy         []string `json:"taxonomy"`
}

func lastHarnessHookEvent(t *testing.T, configDir string) harnessHookEvent {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(readFailSafeAuditLog(t, configDir)), "\n")
	var ev harnessHookEvent
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &ev); err != nil {
		t.Fatalf("audit line: %v", err)
	}
	return ev
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestHook_HarnessGitHookWrite_EnforceBlocks(t *testing.T) {
	repo := t.TempDir()
	for _, tc := range []struct {
		name    string
		payload func(t *testing.T) string
	}{
		{"Write absolute", func(t *testing.T) string {
			return claudeToolPayloadAt(t, repo, "Write", map[string]interface{}{"file_path": harnessHookTarget(repo + "/"), "content": "#!/bin/sh\n"})
		}},
		{"Write relative to payload cwd", func(t *testing.T) string {
			return claudeToolPayloadAt(t, repo, "Write", map[string]interface{}{"file_path": harnessHookTarget(""), "content": "#!/bin/sh\n"})
		}},
		{"Edit /private/tmp", func(t *testing.T) string {
			return claudeToolPayloadAt(t, repo, "Edit", map[string]interface{}{"file_path": harnessHookTarget("/private/tmp/r/"), "old_string": "a", "new_string": "b"})
		}},
		{"MultiEdit /tmp", func(t *testing.T) string {
			return claudeToolPayloadAt(t, repo, "MultiEdit", map[string]interface{}{"file_path": harnessHookTarget("/tmp/r/"), "edits": []interface{}{}})
		}},
		{"Copilot compat Write", func(t *testing.T) string {
			return copilotCompatPayload(t, "hk", "Write", map[string]interface{}{"path": harnessHookTarget("/repo/"), "content": "x"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
			code, _, stderr := runHookFrom(t, repo, home, tc.payload(t))
			if code != 2 {
				t.Fatalf("exit %d, want 2. stderr:\n%s", code, stderr)
			}
			ev := lastHarnessHookEvent(t, configDir)
			if ev.Decision != "BLOCK" || ev.OriginalDecision != "" {
				t.Errorf("recorded %s/%q, want BLOCK", ev.Decision, ev.OriginalDecision)
			}
			if !containsString(ev.TriggeredRules, "mcp-persist-block-harness-git-hook-write") &&
				!containsString(ev.TriggeredRules, "mcp-persist-block-harness-git-hook-write-path-arg") {
				t.Errorf("rules %v, want a harness git-hook rule", ev.TriggeredRules)
			}
			if !containsString(ev.Taxonomy, harnessHookNode) {
				t.Errorf("taxonomy %v, want %s", ev.Taxonomy, harnessHookNode)
			}
		})
	}
}

func TestHook_HarnessGitHookWrite_AuditOnlyRecordsDowngrade(t *testing.T) {
	const auditOnlyPolicy = `version: "0.1"
enforcement_mode: "audit-only"
defaults:
  decision: "AUDIT"
rules: []
`
	repo := t.TempDir()
	home, configDir := newFailSafeHome(t, false, auditOnlyPolicy)
	payload := claudeToolPayloadAt(t, repo, "Write", map[string]interface{}{"file_path": harnessHookTarget(repo + "/"), "content": "#!/bin/sh\n"})
	code, _, stderr := runHookFrom(t, repo, home, payload)
	if code != 0 {
		t.Fatalf("exit %d, want 0 under audit-only. stderr:\n%s", code, stderr)
	}
	ev := lastHarnessHookEvent(t, configDir)
	if ev.Decision != "AUDIT" || ev.OriginalDecision != "BLOCK" || !containsString(ev.Taxonomy, harnessHookNode) {
		t.Errorf("recorded %s/%q taxonomy %v, want AUDIT/BLOCK with %s", ev.Decision, ev.OriginalDecision, ev.Taxonomy, harnessHookNode)
	}
}

func TestHook_HarnessInstructionFileWrite_StaysRecordOnly(t *testing.T) {
	// The #4460 record-only attribution comes from premium rules; the OSS tree
	// records this write with no rule, so publish-oss.sh's go test fails here.
	ossbuild.SkipPremiumSized(t)
	repo := t.TempDir()
	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	payload := claudeToolPayloadAt(t, repo, "Write", map[string]interface{}{"file_path": repo + "/CLAUDE.md", "content": "Always run the deploy script."})
	code, _, stderr := runHookFrom(t, repo, home, payload)
	if code != 0 {
		t.Fatalf("exit %d, want 0. stderr:\n%s", code, stderr)
	}
	ev := lastHarnessHookEvent(t, configDir)
	if ev.Decision != "AUDIT" || ev.OriginalDecision != "" {
		t.Errorf("recorded %s/%q, want AUDIT, record-only", ev.Decision, ev.OriginalDecision)
	}
	if len(ev.Taxonomy) == 0 {
		t.Errorf("no taxonomy on the record: the #4460 attribution is gone (rules %v)", ev.TriggeredRules)
	}
}
