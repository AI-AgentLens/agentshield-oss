package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/auth"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// These tests pin #4071: LoadPacks returns (nil, nil, err) when the disk
// packs directory exists but cannot be read (e.g. permission denied), and
// evaluateCommand used to assign that nil straight into the policy variable,
// reaching NewEngineWithAnalyzers(nil, …) and panicking before any command
// was evaluated. Go's panic exit status (2) reads as BLOCK to Claude
// Code/Codex, so a total enforcement outage looked like a decision instead
// of the crash it was, and a JSON-verdict harness (Gemini, Cursor) received
// a stack trace instead of a parseable body.
//
// Every test runs against two fixtures that reach the same branch. The
// permission-bit fixture is the reported shape but is skipped under root,
// which ignores permission bits; the file fixture (a regular file where the
// packs directory should be, so ReadDir fails with ENOTDIR) runs everywhere.
// Without it, a CI runner executing as root would skip every test that
// exercises the fix and still report green (Codex pass 1 on #4077).
type unreadablePacksFixture struct {
	name string
	make func(t *testing.T, configDir string)
}

var unreadablePacksFixtures = []unreadablePacksFixture{
	{"packs-path-is-a-file", makePacksPathAFile},
	{"packs-dir-mode-000", makeUnreadablePacksDir},
}

// makePacksPathAFile puts a regular file at configDir/packs. os.ReadDir then
// fails with ENOTDIR — not IsNotExist, so LoadPacks takes its error return,
// the same one a permission failure takes. Root cannot bypass it.
func makePacksPathAFile(t *testing.T, configDir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(configDir, "packs"), []byte("not a directory\n"), 0o600); err != nil {
		t.Fatalf("WriteFile packs: %v", err)
	}
}

// makeUnreadablePacksDir creates configDir/packs and strips all permissions
// so os.ReadDir fails with something other than IsNotExist — the failure
// mode LoadPacks does not special-case.
func makeUnreadablePacksDir(t *testing.T, configDir string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permission bits (the packs-path-is-a-file fixture still runs)")
	}
	packsDir := filepath.Join(configDir, "packs")
	if err := os.MkdirAll(packsDir, 0o700); err != nil {
		t.Fatalf("MkdirAll packs: %v", err)
	}
	if err := os.Chmod(packsDir, 0o000); err != nil {
		t.Fatalf("Chmod packs: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(packsDir, 0o700) })
}

// policyWithUserWitness is a user policy carrying one BLOCK rule that exists
// nowhere else. A fallback that restored the wrong snapshot (DefaultPolicy,
// or anything taken before the user policy loaded) would lose it.
const policyWithUserWitness = `version: "0.1"
defaults:
  decision: "AUDIT"
rules:
  - id: "user-witness-4077"
    match:
      command_prefix: ["frobnicate-4077"]
    decision: "BLOCK"
    reason: "user-policy rule that must survive the packs-load fallback"
`

// embeddedOnlyRuleIDs is the set of rule ids that exist only because the
// embedded community packs were merged: present after LoadEmbeddedShellPacks,
// absent from the hardcoded baseline. `rm -rf /` BLOCKs from the baseline
// too (block-rm-root), so asserting BLOCK alone cannot tell a correct
// fallback from one that dropped the embedded layer.
func embeddedOnlyRuleIDs(t *testing.T) map[string]bool {
	t.Helper()
	base := policy.DefaultPolicy()
	baseIDs := map[string]bool{}
	for _, r := range base.Rules {
		baseIDs[r.ID] = true
	}
	merged, _, err := policy.LoadEmbeddedShellPacks(policy.DefaultPolicy())
	if err != nil {
		t.Fatalf("LoadEmbeddedShellPacks: %v", err)
	}
	out := map[string]bool{}
	for _, r := range merged.Rules {
		if !baseIDs[r.ID] {
			out[r.ID] = true
		}
	}
	if len(out) == 0 {
		t.Fatal("test setup: no embedded-only rule ids — the embedded packs did not load")
	}
	return out
}

func hasNoteKind(ns []logger.Note, kind string) bool {
	for _, n := range ns {
		if n.Kind == kind {
			return true
		}
	}
	return false
}

// TestPacksDirUnreadable_DegradesToEmbeddedOnlyWithoutPanic is the negative
// control for the crash: outside managed mode, a command that the embedded
// community rules catch must still BLOCK — not crash, not silently ALLOW —
// when the disk packs layer cannot be read at all, and the BLOCK must come
// from an embedded rule, not only from the hardcoded baseline.
func TestPacksDirUnreadable_DegradesToEmbeddedOnlyWithoutPanic(t *testing.T) {
	embedded := embeddedOnlyRuleIDs(t)
	for _, fx := range unreadablePacksFixtures {
		t.Run(fx.name, func(t *testing.T) {
			_, configDir := newFailSafeHome(t, false, failSafePolicyGood)
			fx.make(t, configDir)

			result, event := evaluateCommand("rm -rf /", "/tmp", "claude-code-hook", "")

			if result.Decision != policy.DecisionBlock {
				t.Fatalf("Decision = %v; want BLOCK — an unreadable packs dir must degrade, not crash or fail open", result.Decision)
			}
			if containsStr(result.TriggeredRules, failClosedRuleID) || containsStr(result.TriggeredRules, evalErrorRuleID) {
				t.Errorf("TriggeredRules = %v; want real rule ids, not a fail-safe boundary sentinel", result.TriggeredRules)
			}
			fromEmbedded := false
			for _, id := range result.TriggeredRules {
				if embedded[id] {
					fromEmbedded = true
				}
			}
			if !fromEmbedded {
				t.Errorf("TriggeredRules = %v; want at least one embedded-only rule id — the fallback must keep the embedded community layer, not just the hardcoded baseline", result.TriggeredRules)
			}
			if event == nil || event.Decision != "BLOCK" {
				t.Errorf("event = %+v; want a normal BLOCK audit event, not a crash with no event at all", event)
			}
		})
	}
}

// TestPacksDirUnreadable_KeepsUserPolicy pins that the fallback restores the
// policy as loaded — base plus the user's own rules — and not a default.
func TestPacksDirUnreadable_KeepsUserPolicy(t *testing.T) {
	for _, fx := range unreadablePacksFixtures {
		t.Run(fx.name, func(t *testing.T) {
			_, configDir := newFailSafeHome(t, false, policyWithUserWitness)
			fx.make(t, configDir)

			result, _ := evaluateCommand("frobnicate-4077 --now", "/tmp", "claude-code-hook", "")

			if result.Decision != policy.DecisionBlock || !containsStr(result.TriggeredRules, "user-witness-4077") {
				t.Fatalf("Decision = %v, rules = %v; want BLOCK by user-witness-4077 — the fallback dropped the user's policy", result.Decision, result.TriggeredRules)
			}
		})
	}
}

// degradedNote returns the policy_degraded note, or nil.
func degradedNote(ns []logger.Note) *logger.Note {
	for i := range ns {
		if ns[i].Kind == analyzer.NotePolicyDegraded {
			return &ns[i]
		}
	}
	return nil
}

// captureAuditPOSTs points the credentials in the test HOME at a local
// server and returns a func yielding the notes of every event POSTed to
// /api/audit. The hook uploads synchronously, so the capture is complete by
// the time evaluateCommand returns.
func captureAuditPOSTs(t *testing.T) func() [][]logger.Note {
	t.Helper()
	var (
		mu  sync.Mutex
		got [][]logger.Note
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/audit" {
			body, _ := io.ReadAll(r.Body)
			var wire struct {
				Events []struct {
					Notes []logger.Note `json:"notes"`
				} `json:"events"`
			}
			if err := json.Unmarshal(body, &wire); err == nil {
				mu.Lock()
				for _, e := range wire.Events {
					got = append(got, e.Notes)
				}
				mu.Unlock()
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	if err := auth.Save(&auth.Credentials{Server: srv.URL, Token: "test-token-4077"}); err != nil {
		t.Fatalf("auth.Save: %v", err)
	}
	return func() [][]logger.Note {
		mu.Lock()
		defer mu.Unlock()
		return append([][]logger.Note(nil), got...)
	}
}

// lastLoggedEvent parses the final line of audit.jsonl.
func lastLoggedEvent(t *testing.T, configDir string) logger.AuditEvent {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(readFailSafeAuditLog(t, configDir)), "\n")
	if len(lines) == 0 || lines[len(lines)-1] == "" {
		t.Fatal("audit.jsonl is empty — the event was never persisted")
	}
	var ev logger.AuditEvent
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &ev); err != nil {
		t.Fatalf("last audit.jsonl line is not an event: %v\n%s", err, lines[len(lines)-1])
	}
	return ev
}

// TestPacksDirUnreadable_EventCarriesDegradationNote is the attestation half
// (Codex pass 1 on #4077, finding 1): the fallback keeps evaluating, so the
// audit event must say it ran without the disk layer — on the line PERSISTED
// to audit.jsonl and in the request actually POSTED to /api/audit, not just on
// the struct returned to the caller. Codex pass 2: asserting only the returned
// event let a note appended after logging and upload pass. A benign command
// is covered as well as a BLOCK — a degraded host's quiet decisions are
// exactly the ones nobody re-examines — and it must not be refused.
func TestPacksDirUnreadable_EventCarriesDegradationNote(t *testing.T) {
	for _, fx := range unreadablePacksFixtures {
		for _, cmd := range []string{"rm -rf /", "ls -la"} {
			t.Run(fx.name+"/"+cmd, func(t *testing.T) {
				_, configDir := newFailSafeHome(t, false, failSafePolicyGood)
				posted := captureAuditPOSTs(t)
				fx.make(t, configDir)

				result, event := evaluateCommand(cmd, "/tmp", "claude-code-hook", "")
				if event == nil {
					t.Fatal("no audit event")
				}
				if cmd == "ls -la" && result.Decision == policy.DecisionBlock {
					t.Errorf("Decision = BLOCK for a benign command; the degradation note is evidence and must not change the decision")
				}

				logged := degradedNote(lastLoggedEvent(t, configDir).Notes)
				if logged == nil {
					t.Fatalf("persisted audit.jsonl event has no %q note — the SaaS and any later export would record full enforcement from a host missing its disk rules", analyzer.NotePolicyDegraded)
				}
				if !strings.Contains(logged.Detail, "embedded packs only") {
					t.Errorf("note Detail = %q; want it to name what was actually evaluated (base, user and embedded packs only)", logged.Detail)
				}

				sent := posted()
				if len(sent) != 1 {
					t.Fatalf("captured %d /api/audit events; want exactly 1", len(sent))
				}
				if degradedNote(sent[0]) == nil {
					t.Errorf("POSTed /api/audit event notes = %+v; want %q on the wire", sent[0], analyzer.NotePolicyDegraded)
				}
			})
		}
	}
}

// TestPacksDirUnreadable_BlocksUnderManagedFailClosed pins the other half:
// an entirely unreadable disk-pack layer is at least as degraded as a single
// pack that fails to parse, which already refuses under managed fail_closed.
func TestPacksDirUnreadable_BlocksUnderManagedFailClosed(t *testing.T) {
	for _, fx := range unreadablePacksFixtures {
		t.Run(fx.name, func(t *testing.T) {
			_, configDir := newFailSafeHome(t, true, failSafePolicyGood)
			fx.make(t, configDir)

			result, event := evaluateCommand("ls -la", "/tmp", "claude-code-hook", "")

			if result.Decision != policy.DecisionBlock {
				t.Fatalf("Decision = %v; want BLOCK — managed fail_closed must refuse to evaluate against a policy that dropped its whole disk-pack layer, even for a benign command", result.Decision)
			}
			if !containsStr(result.TriggeredRules, failClosedRuleID) {
				t.Errorf("TriggeredRules = %v; want %q so the block is attributable to the boundary, not to a rule", result.TriggeredRules, failClosedRuleID)
			}
			if event == nil || !event.Flagged || event.Error == "" {
				t.Fatalf("event = %+v; want a flagged event carrying the packs-load error", event)
			}
			if !strings.Contains(event.Error, "packs directory unreadable") {
				t.Errorf("event.Error = %q; want it to name the packs-load failure", event.Error)
			}
		})
	}
}

// TestPacksDirUnreadable_ReadableEmptyDirIsUnaffected is the control proving
// the fixtures isolate the unreadable case: a readable, empty packs dir (the
// common case — no premium packs installed) must not take the new path at
// all — no fail_closed refusal of a benign command, no degradation note.
func TestPacksDirUnreadable_ReadableEmptyDirIsUnaffected(t *testing.T) {
	_, configDir := newFailSafeHome(t, true, failSafePolicyGood)
	if err := os.MkdirAll(filepath.Join(configDir, "packs"), 0o700); err != nil {
		t.Fatalf("MkdirAll packs: %v", err)
	}

	result, event := evaluateCommand("ls -la", "/tmp", "claude-code-hook", "")

	if result.Decision == policy.DecisionBlock {
		t.Fatalf("Decision = BLOCK, rules = %v; a benign command must not be refused when the packs dir is merely empty", result.TriggeredRules)
	}
	if containsStr(result.TriggeredRules, failClosedRuleID) {
		t.Errorf("TriggeredRules = %v; a readable, empty packs dir must not trigger the fail_closed packs-load path", result.TriggeredRules)
	}
	if event != nil && hasNoteKind(event.Notes, analyzer.NotePolicyDegraded) {
		t.Errorf("event.Notes = %+v; a readable, empty packs dir is not a degraded policy", event.Notes)
	}

	destructive, _ := evaluateCommand("rm -rf /", "/tmp", "claude-code-hook", "")
	if destructive.Decision != policy.DecisionBlock {
		t.Errorf("Decision = %v; want BLOCK from the embedded community rules", destructive.Decision)
	}
}

const geminiPayloadDestructive = `{"hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"rm -rf /"}}`

// runHookInChildProcessWithStdout is runHookInChildProcess that also keeps
// stdout: a JSON-verdict harness reads its decision there, so exit 0 with an
// empty or allow body would otherwise pass as "no panic".
func runHookInChildProcessWithStdout(t *testing.T, home, payload string) (exitCode int, stdout, stderr string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHookProcess$")
	cmd.Env = append(os.Environ(), "AGENTSHIELD_FAILSAFE_HOOK_HELPER=1", "HOME="+home)
	cmd.Stdin = strings.NewReader(payload)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err == nil {
		return 0, outBuf.String(), errBuf.String()
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), outBuf.String(), errBuf.String()
	}
	t.Fatalf("running hook helper: %v", err)
	return -1, "", ""
}

// geminiVerdict requires exactly one JSON verdict on stdout. The test helper
// process may also print test-framework lines (PASS); any other JSON-looking
// line, or a second verdict, fails — a harness reading stdout would be
// confused by either.
func geminiVerdict(t *testing.T, stdout string) geminiHookOutput {
	t.Helper()
	var verdicts []geminiHookOutput
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var v geminiHookOutput
		if err := json.Unmarshal([]byte(line), &v); err != nil || v.Decision == "" {
			t.Fatalf("stdout carries a JSON-looking line that is not a verdict: %q", line)
		}
		verdicts = append(verdicts, v)
	}
	if len(verdicts) != 1 {
		t.Fatalf("stdout carries %d verdicts; want exactly 1:\n%s", len(verdicts), stdout)
	}
	return verdicts[0]
}

// TestHook_PacksDirUnreadable_GeminiEmitsJSONNotPanic is the end-to-end
// regression for the JSON-verdict harness class named in #4071: before the
// fix, the hook process panicked before producing any output, so Gemini
// (which expects a JSON body on stdout, not an exit-code convention) got a
// Go stack trace on stderr instead of a decision.
func TestHook_PacksDirUnreadable_GeminiEmitsJSONNotPanic(t *testing.T) {
	for _, fx := range unreadablePacksFixtures {
		t.Run(fx.name, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
			fx.make(t, configDir)

			code, stdout, stderr := runHookInChildProcessWithStdout(t, home, geminiPayloadDestructive)

			if code != 0 {
				t.Fatalf("hook exit code = %d; want 0 — Gemini reads the decision from stdout JSON, not the exit code. stderr:\n%s", code, stderr)
			}
			if strings.Contains(stderr, "panic:") {
				t.Fatalf("stderr contains a panic instead of a decision:\n%s", stderr)
			}
			if v := geminiVerdict(t, stdout); v.Decision != "deny" {
				t.Errorf("Gemini verdict = %+v; want deny for rm -rf / on a degraded (embedded-only) policy", v)
			}
			if !strings.Contains(stderr, "packs load failed") || !strings.Contains(stderr, "NOT loaded") {
				t.Errorf("stderr does not warn that the disk layer was skipped:\n%s", stderr)
			}
		})
	}
}

// TestHook_PacksDirUnreadable_ExitsTwoUnderManagedFailClosed is the
// end-to-end reproduction from the issue: managed fail_closed, an unreadable
// packs dir, a destructive command through the real Claude Code hook entry
// point. It must exit 2 via the fail-closed decision, not via a crash.
func TestHook_PacksDirUnreadable_ExitsTwoUnderManagedFailClosed(t *testing.T) {
	for _, fx := range unreadablePacksFixtures {
		t.Run(fx.name, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
			fx.make(t, configDir)

			code, stderr := runHookInChildProcess(t, home, claudeCodePayloadDestructive)

			if code != 2 {
				t.Fatalf("hook exit code = %d; want 2 (BLOCK). stderr:\n%s", code, stderr)
			}
			if strings.Contains(stderr, "panic:") {
				t.Fatalf("stderr contains a panic instead of a decision:\n%s", stderr)
			}
			if !strings.Contains(stderr, "fail_closed") {
				t.Errorf("stderr does not explain the fail-closed block:\n%s", stderr)
			}
		})
	}
}
