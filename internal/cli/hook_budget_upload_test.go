package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/auth"
	"github.com/AI-AgentLens/agentshield/internal/route"
)

// TestHookBudget_UploadTimeout: the synchronous upload keeps its full
// timeout with no budget, or with time to spare, and is cut to what is left
// before the harness timeout (less the exit guard) near the end (#4803).
func TestHookBudget_UploadTimeout(t *testing.T) {
	prev := hookProcessStart
	t.Cleanup(func() { hookProcessStart = prev })
	const timeout = 10 * time.Second
	b := &hookBudget{timeout: timeout}

	var nilBudget *hookBudget
	if got := nilBudget.uploadTimeout(syncUploadTimeout); got != syncUploadTimeout {
		t.Errorf("no budget: %v, want the full %v", got, syncUploadTimeout)
	}
	hookProcessStart = time.Now()
	if got := b.uploadTimeout(syncUploadTimeout); got != syncUploadTimeout {
		t.Errorf("at the start of the call: %v, want the full %v", got, syncUploadTimeout)
	}
	hookProcessStart = time.Now().Add(-8 * time.Second)
	if got, max := b.uploadTimeout(syncUploadTimeout), timeout-8*time.Second-hookAnswerExitGuard; got > max || got <= 0 {
		t.Errorf("8 s into a 10 s call: %v, want in (0, %v]", got, max)
	}
	hookProcessStart = time.Now().Add(-9 * time.Second)
	if got := b.uploadTimeout(syncUploadTimeout); got > 0 {
		t.Errorf("9 s into a 10 s call: %v, want none left (the upload is skipped)", got)
	}
}

// TestHookBudget_SyncUploadBoundedByDeadline_4803 is #4803's Codex finding
// as a regression. On an enrolled host whose audit queue cannot be written
// (or with AGENTSHIELD_AUDIT_UPLOAD=sync), the watchdog's BLOCK used to wait
// on a synchronous POST after its record. With the record at about 8.3 s of
// Codex's 10 s and a server answering in 2.9 s, it exited at 11.25 s, BLOCK,
// with no late mark: the harness would have run the call. Now the POST gets
// only the time left, so the answer lands before the timeout. The control: a
// call decided at once on the same degraded host still uploads its event.
func TestHookBudget_SyncUploadBoundedByDeadline_4803(t *testing.T) {
	if testing.Short() {
		t.Skip("holds a hook call for most of Codex's 10 s timeout")
	}
	timeout := hookTimeouts[route.Codex].timeout
	payload := claudeShaped(t, "PreToolUse", "Bash", routingCmd(routingDestructive()), map[string]interface{}{"turn_id": "turn-1"})
	held := envTestHookSlow + "=before-record=" + (timeout - hookAnswerExitGuard - 300*time.Millisecond).String()

	cases := []struct {
		name       string
		delay      time.Duration // the server's answer time
		blockQueue bool
		extraEnv   []string
		wantPosts  int64 // audit uploads the server receives; -1: not checked
	}{
		{"queue unwritable, watchdog answer near the deadline", 2900 * time.Millisecond, true, []string{envTestHookBudget + "=1ns", held}, -1},
		{"sync mode, watchdog answer near the deadline", 2900 * time.Millisecond, false, []string{envTestHookBudget + "=1ns", held, auditUploadEnv + "=sync"}, -1},
		{"control: queue unwritable, decided at once", 0, true, nil, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Only audit uploads are counted: an enrolled hook also talks to
			// other endpoints.
			var posts atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/api/audit" {
					posts.Add(1)
					time.Sleep(c.delay)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()
			home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
			if err := auth.Save(&auth.Credentials{Server: srv.URL, Token: "test-agent-token"}); err != nil {
				t.Fatal(err)
			}
			if c.blockQueue {
				// A file where the queue directory goes: MkdirAll fails, so
				// the event takes the synchronous fallback.
				if err := os.WriteFile(auditQueueDir(), []byte("not a directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			env := append([]string{envAuditDetachedSpawn + "=1"}, c.extraEnv...)
			start := time.Now()
			code, _, stderr := runHookChild(t, home, payload, env...)
			elapsed := time.Since(start)
			if code != 2 {
				t.Fatalf("exit %d; want Codex's BLOCK (exit 2). stderr:\n%s", code, stderr)
			}
			if elapsed >= timeout {
				t.Errorf("answered after %v, at or past Codex's %v timeout: the harness would have run the call", elapsed.Round(10*time.Millisecond), timeout)
			}
			if e := oneEvent(t, configDir); e.Decision != "BLOCK" {
				t.Errorf("recorded %s; want BLOCK", e.Decision)
			}
			if c.wantPosts >= 0 && posts.Load() != c.wantPosts {
				t.Errorf("server received %d uploads; want %d", posts.Load(), c.wantPosts)
			}
		})
	}
}
