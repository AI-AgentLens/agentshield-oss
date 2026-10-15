package cli

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/auth"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Issue #4332: the audit log redacted a COPY of the event (Log takes it by
// value), and the hook then POSTed the original to the SaaS. buildAuditPayload
// copied command and MCP arguments verbatim, so every secret in an agent
// command reached /api/audit while the local line read [REDACTED]. A second
// gap lived on the local side: args were redacted token by token, so the
// token in `curl -H "Authorization: Bearer <tok>"` survived in `args`.
//
// The contract these tests pin: whatever leaves the hook — the audit.jsonl
// line or the wire payload — has had the same redaction applied.

// redactionCanary ends every secret below. Asserting on it as well as on the
// whole secret catches a partial redaction that leaves the tail behind.
const redactionCanary = "Lk4332canary"

// Secret-shaped values are assembled at runtime: AgentShield guards the
// machine these tests are written on, and a literal key-shaped string in a
// file write is exactly what it is built to stop.
func testAPIKey() string      { return "sk_" + "test_" + "Zm9v" + "YmFy" + "YmF6" + redactionCanary }
func testBearerToken() string { return "tok_" + "live_" + "A1b2" + "C3d4" + "E5f6" + redactionCanary }
func testPassword() string    { return "Pw-" + "Sx9" + "-q7" + redactionCanary }

// redactionCase is one way a secret reaches an audit event.
type redactionCase struct {
	name   string
	secret string
	event  func(t *testing.T) logger.AuditEvent
}

func redactionCases() []redactionCase {
	return []redactionCase{
		{
			name:   "exported API key assignment",
			secret: testAPIKey(),
			event: func(t *testing.T) logger.AuditEvent {
				cmd := "export OPENAI_API_KEY=" + testAPIKey() + " && python3 app.py"
				return logger.AuditEvent{
					Command: cmd, Args: strings.Fields(cmd),
					Decision: "AUDIT", Mode: "enforce", Source: "claude-code-hook",
				}
			},
		},
		{
			name:   "bearer header, double-quoted",
			secret: testBearerToken(),
			event: func(t *testing.T) logger.AuditEvent {
				cmd := `curl -sS -H "Authorization: Bearer ` + testBearerToken() + `" https://api.example.com/v1/me`
				return logger.AuditEvent{
					Command: cmd, Args: strings.Fields(cmd),
					Decision: "AUDIT", Mode: "enforce", Source: "claude-code-hook",
				}
			},
		},
		{
			name:   "bearer header, single-quoted",
			secret: testBearerToken(),
			event: func(t *testing.T) logger.AuditEvent {
				cmd := `curl -sS -H 'Authorization: Bearer ` + testBearerToken() + `' https://api.example.com/v1/me`
				return logger.AuditEvent{
					Command: cmd, Args: strings.Fields(cmd),
					Decision: "AUDIT", Mode: "enforce", Source: "claude-code-hook",
				}
			},
		},
		{
			name:   "MCP arguments, password field",
			secret: testPassword(),
			event: func(t *testing.T) logger.AuditEvent {
				return logger.AuditEvent{
					ToolName: "postgres_connect",
					MCPArguments: map[string]interface{}{
						"host": "db.internal", "user": "app", "password": testPassword(),
					},
					Decision: "AUDIT", Mode: "enforce", Source: "claude-code-mcp-hook",
				}
			},
		},
		{
			name:   "MCP arguments, nested token field",
			secret: testAPIKey(),
			event: func(t *testing.T) logger.AuditEvent {
				return logger.AuditEvent{
					ToolName: "http_request",
					MCPArguments: map[string]interface{}{
						"url": "https://api.example.com/v1/me",
						"auth": map[string]interface{}{
							"access_token": testAPIKey(),
							"scopes":       []interface{}{"read", "write"},
						},
						"retries": 3.0,
					},
					Decision: "AUDIT", Mode: "enforce", Source: "claude-code-mcp-hook",
				}
			},
		},
		{
			// Built by failSafeDecision itself, so the case covers both places
			// the error text lands: the event's Error field and the reason the
			// fail-safe composes from it (the reason is what goes on the wire).
			name:   "error text",
			secret: testPassword(),
			event: func(t *testing.T) logger.AuditEvent {
				newRedactionHome(t, "")
				errText := `yaml: line 4: mapping values are not allowed here near "password=` + testPassword() + `"`
				_, ev := failSafeDecision(evalFailure{stage: "config load", err: errors.New(errText)},
					"agentshield-test-cmd", "/workspace", "claude-code-hook", "")
				return *ev
			},
		},
	}
}

// newRedactionHome points HOME at a fresh directory, optionally logged in to
// server, and pins the package-level config flags to their defaults. With no
// server, sendRemoteAudit finds no credentials and sends nothing.
func newRedactionHome(t *testing.T, server string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".agentshield"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if server != "" {
		if err := auth.Save(&auth.Credentials{Server: server, Token: "test-agent-token"}); err != nil {
			t.Fatalf("auth.Save: %v", err)
		}
	}
	prevPolicy, prevLog, prevMode := policyPath, logPath, mode
	policyPath, logPath, mode = "", "", ""
	t.Cleanup(func() { policyPath, logPath, mode = prevPolicy, prevLog, prevMode })
	return home
}

func assertSecretAbsent(t *testing.T, where string, data []byte, secret string) {
	t.Helper()
	s := string(data)
	if strings.Contains(s, secret) || strings.Contains(s, redactionCanary) {
		t.Errorf("%s carries the secret unredacted:\n%s", where, s)
	}
	if !strings.Contains(s, "[REDACTED]") {
		t.Errorf("%s has no [REDACTED] marker — the secret was dropped some other way, or the fixture no longer reaches this field:\n%s", where, s)
	}
}

// TestAuditRedaction_WirePayloadAndDiskLine is the #4332 contract: for each
// way a secret reaches an event, neither the SaaS payload nor the audit.jsonl
// line carries it, and the caller's event is left untouched.
func TestAuditRedaction_WirePayloadAndDiskLine(t *testing.T) {
	for _, tc := range redactionCases() {
		t.Run(tc.name, func(t *testing.T) {
			ev := tc.event(t)

			// Denominator: the fixture really carries the secret. Without this
			// a fixture that lost its secret would pass every assertion below.
			before, err := json.Marshal(ev)
			if err != nil {
				t.Fatalf("marshal event: %v", err)
			}
			if !strings.Contains(string(before), tc.secret) {
				t.Fatalf("fixture does not carry the secret; the test would be vacuous: %s", before)
			}

			payload, err := buildAuditPayload(&ev)
			if err != nil {
				t.Fatalf("buildAuditPayload: %v", err)
			}
			assertSecretAbsent(t, "wire payload", payload, tc.secret)

			logPath := filepath.Join(t.TempDir(), "audit.jsonl")
			l, err := logger.New(logPath)
			if err != nil {
				t.Fatalf("logger.New: %v", err)
			}
			if err := l.Log(ev); err != nil {
				t.Fatalf("Log: %v", err)
			}
			_ = l.Close()
			line, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatalf("read audit log: %v", err)
			}
			assertSecretAbsent(t, "audit.jsonl line", line, tc.secret)

			// The chain hashes the redacted bytes, so it must still verify.
			if r := logger.VerifyChain(logPath); r.State != logger.ChainStateVerified {
				t.Errorf("chain over the redacted line: %q: %s", r.State, r.Message)
			}

			// Redaction works on copies: the hook still holds this event.
			after, _ := json.Marshal(ev)
			if string(after) != string(before) {
				t.Errorf("redaction mutated the caller's event:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}

// TestAuditRedaction_DiskArgsKeepCommandShape pins that the header-token fix
// redacts args without discarding them: the non-secret words survive.
func TestAuditRedaction_DiskArgsKeepCommandShape(t *testing.T) {
	cmd := `curl -sS -H "Authorization: Bearer ` + testBearerToken() + `" https://api.example.com/v1/me`
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := logger.New(logPath)
	if err != nil {
		t.Fatalf("logger.New: %v", err)
	}
	if err := l.Log(logger.AuditEvent{Command: cmd, Args: strings.Fields(cmd), Decision: "AUDIT"}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	_ = l.Close()
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var got logger.AuditEvent
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode line: %v", err)
	}
	joined := strings.Join(got.Args, " ")
	for _, want := range []string{"curl", "-sS", "-H", "https://api.example.com/v1/me", "[REDACTED]"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args %q lost %q", got.Args, want)
		}
	}
	if strings.Contains(joined, redactionCanary) {
		t.Errorf("args still carry the token: %q", got.Args)
	}
}

// captureAudit starts a server standing in for the SaaS and returns it with
// a function reporting every /api/audit body it received.
func captureAudit(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/api/audit" {
			mu.Lock()
			bodies = append(bodies, string(b))
			mu.Unlock()
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), bodies...)
	}
}

// TestAuditRedaction_EveryHookSenderRedacts drives each function that POSTs
// to /api/audit — evaluateCommand, auditMCPCall, failSafeDecision — against a
// capture server, with a real login in a scratch HOME. buildAuditPayload being
// correct is not enough if a sender builds its own body; this pins that every
// sender's bytes on the wire, and its audit.jsonl line, are redacted.
func TestAuditRedaction_EveryHookSenderRedacts(t *testing.T) {
	senders := []struct {
		name   string
		secret string
		run    func(t *testing.T, home string)
	}{
		{
			name:   "shell hook (evaluateCommand)",
			secret: testBearerToken(),
			run: func(t *testing.T, home string) {
				cmd := `curl -sS -H "Authorization: Bearer ` + testBearerToken() + `" https://api.example.com/v1/me`
				evaluateCommand(cmd, "/workspace", "claude-code-hook", "sess-4332")
			},
		},
		{
			name:   "MCP hook (auditMCPCall)",
			secret: testPassword(),
			run: func(t *testing.T, home string) {
				auditMCPCall("postgres_connect",
					map[string]interface{}{"host": "db.internal", "password": testPassword()},
					mcp.MCPEvalResult{Decision: policy.DecisionAudit, TriggeredRules: []string{"test-rule"}, Reasons: []string{"test"}},
					"claude-code-hook", "enforce", "sess-4332")
			},
		},
		{
			name:   "fail-safe boundary (failSafeDecision)",
			secret: testPassword(),
			run: func(t *testing.T, home string) {
				l, err := logger.New(filepath.Join(home, ".agentshield", "audit.jsonl"))
				if err != nil {
					t.Fatalf("logger.New: %v", err)
				}
				defer func() { _ = l.Close() }()
				errText := `yaml: line 4: mapping values are not allowed here near "password=` + testPassword() + `"`
				failSafeDecision(evalFailure{stage: "policy load", err: errors.New(errText), log: l},
					"agentshield-test-cmd", "/workspace", "claude-code-hook", "sess-4332")
			},
		},
	}
	for _, s := range senders {
		t.Run(s.name, func(t *testing.T) {
			srv, bodies := captureAudit(t)
			home := newRedactionHome(t, srv.URL)

			s.run(t, home)

			got := bodies()
			if len(got) != 1 {
				t.Fatalf("capture server received %d /api/audit bodies; want 1 — without a body this test asserts nothing", len(got))
			}
			assertSecretAbsent(t, "POST /api/audit body", []byte(got[0]), s.secret)

			line, err := os.ReadFile(filepath.Join(home, ".agentshield", "audit.jsonl"))
			if err != nil {
				t.Fatalf("read audit log: %v", err)
			}
			assertSecretAbsent(t, "audit.jsonl", line, s.secret)
		})
	}
}
