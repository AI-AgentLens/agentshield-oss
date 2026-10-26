package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4208, option B: every /api/audit event carries machine_id and, when its
// local line was written chained, local_chain {prev_hash, line_hash}. The
// SaaS joins each event's prev_hash to a line_hash it received from the
// same machine; one it never received is a local line deleted before
// upload. These tests drive the real senders against a capture server and
// hold what arrives against the audit.jsonl the same calls wrote.

// wireEntry is the single event of one captured /api/audit body.
func wireEntry(t *testing.T, body string) map[string]any {
	t.Helper()
	return decodeEntry(t, []byte(body))
}

// wireLocalChain returns the event's local_chain object, failing when the
// key is absent or not an object of two strings.
func wireLocalChain(t *testing.T, entry map[string]any) (prevHash, lineHash string) {
	t.Helper()
	raw, present := entry["local_chain"]
	if !present {
		t.Fatalf("event has no local_chain key: %v", entry)
	}
	obj, ok := raw.(map[string]any)
	if !ok || len(obj) != 2 {
		t.Fatalf("local_chain = %#v, want an object with exactly prev_hash and line_hash", raw)
	}
	prev, prevOK := obj["prev_hash"].(string)
	line, lineOK := obj["line_hash"].(string)
	if !prevOK || !lineOK {
		t.Fatalf("local_chain = %#v, want string prev_hash and line_hash (prev_hash present even when \"\")", obj)
	}
	return prev, line
}

// auditLines returns each record of the scratch HOME's audit.jsonl as
// written, without its "\n": the bytes the chain hashes.
func auditLines(t *testing.T, home string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(home, ".agentshield", "audit.jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var out [][]byte
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if len(line) > 0 {
			out = append(out, line)
		}
	}
	return out
}

func lineSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// warmRealMachineID installs a fresh machine-id source with the real read
// and waits for it, without a deadline, so these tests compare against
// enterprise.MachineID() whatever the machine's load. The bound on the
// wait is pinned separately (machine_id_test.go); here a slow ioreg would
// only make machine_id absent and the equality assertions flaky.
func warmRealMachineID(t *testing.T) {
	t.Helper()
	src := useMachineIDSource(t, enterprise.MachineID)
	src.start()
	select {
	case <-src.done:
	case <-time.After(30 * time.Second):
		t.Fatal("the real machine-id read did not finish in 30 s")
	}
}

func recordPrevHash(t *testing.T, line []byte) string {
	t.Helper()
	var rec struct {
		PrevHash string `json:"prev_hash"`
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		t.Fatalf("decode audit line: %v", err)
	}
	return rec.PrevHash
}

// TestRemoteAudit_EverySenderSendsItsLocalLink drives all four functions
// that POST to /api/audit, in turn, into one log. What the SaaS receives
// must be one unbroken chain that matches the file line for line: event 1
// a genesis link, each later prev_hash the previous event's line_hash, and
// every line_hash the SHA-256 of its line on disk.
func TestRemoteAudit_EverySenderSendsItsLocalLink(t *testing.T) {
	srv, bodies := captureAudit(t)
	home := newRedactionHome(t, srv.URL)
	warmRealMachineID(t)
	logFile := filepath.Join(home, ".agentshield", "audit.jsonl")

	senders := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"shell hook (evaluateCommand)", func(t *testing.T) {
			evaluateCommand("ls -la", "/workspace", "claude-code-hook", "sess-4208")
		}},
		{"shell hook again (evaluateCommand)", func(t *testing.T) {
			evaluateCommand("git status", "/workspace", "claude-code-hook", "sess-4208")
		}},
		{"MCP hook (auditMCPCall)", func(t *testing.T) {
			auditMCPCall("read_file", map[string]interface{}{"path": "/workspace/README.md"},
				mcp.MCPEvalResult{Decision: policy.DecisionAudit, TriggeredRules: []string{"test-rule"}, Reasons: []string{"test"}},
				"claude-code-hook", "enforce", "sess-4208", "", nil)
		}},
		{"fail-safe boundary (failSafeDecision)", func(t *testing.T) {
			l, err := logger.New(logFile)
			if err != nil {
				t.Fatalf("logger.New: %v", err)
			}
			defer func() { _ = l.Close() }()
			failSafeDecision(evalFailure{stage: "policy load", err: errors.New("policy unparseable"), log: l},
				"agentshield-test-cmd", "/workspace", "claude-code-hook", "sess-4208")
		}},
		{"self-protect block (recordSelfProtectBlock)", func(t *testing.T) {
			recordSelfProtectBlock(&logger.AuditEvent{
				Timestamp: "2026-10-21T00:00:00Z", Command: "agentshield-test-tamper", Decision: "BLOCK",
				TriggeredRules: []string{"enterprise-self-protect"}, Mode: "managed", Source: "claude-code-hook",
			})
		}},
	}
	for _, s := range senders {
		s.run(t)
	}

	got := bodies()
	lines := auditLines(t, home)
	if len(got) != len(senders) || len(lines) != len(senders) {
		t.Fatalf("captured %d bodies and %d audit lines; want %d of each, one per sender", len(got), len(lines), len(senders))
	}
	wantMachine := enterprise.MachineID()
	if wantMachine == "" {
		t.Fatal("control: enterprise.MachineID() is empty, so machine_id cannot be checked")
	}

	prevLine := ""
	for i, body := range got {
		name := senders[i].name
		entry := wireEntry(t, body)
		if m, _ := entry["machine_id"].(string); m != wantMachine {
			t.Errorf("%s: machine_id = %q, want the heartbeat's value %q", name, m, wantMachine)
		}
		prev, line := wireLocalChain(t, entry)
		if want := lineSHA256(lines[i]); line != want {
			t.Errorf("%s: line_hash = %s, want SHA-256 of its audit.jsonl line %s", name, line, want)
		}
		if want := recordPrevHash(t, lines[i]); prev != want {
			t.Errorf("%s: prev_hash = %q, but its audit.jsonl line says %q", name, prev, want)
		}
		if prev != prevLine {
			t.Errorf("%s: prev_hash = %q, want the previous event's line_hash %q (the receiver would report a break)", name, prev, prevLine)
		}
		prevLine = line
	}
	if r := logger.VerifyChain(logFile); r.State != logger.ChainStateVerified {
		t.Errorf("control: the local chain itself is %s: %s", r.State, r.Message)
	}
}

// TestRemoteAudit_NoLocalLineMeansNoLocalChain: when nothing was written,
// or the write failed, the event still goes to the SaaS with its machine
// id but without local_chain. An absent key is "not chain-reported", which
// the SaaS counts and never flags; a made-up link would read as a break.
func TestRemoteAudit_NoLocalLineMeansNoLocalChain(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, home string)
	}{
		{"fail-safe with no logger", func(t *testing.T, home string) {
			failSafeDecision(evalFailure{stage: "audit log init", err: errors.New("log unopenable")},
				"agentshield-test-cmd", "/workspace", "claude-code-hook", "sess-4208")
		}},
		{"fail-safe whose write fails", func(t *testing.T, home string) {
			l, err := logger.New(filepath.Join(home, ".agentshield", "audit.jsonl"))
			if err != nil {
				t.Fatalf("logger.New: %v", err)
			}
			_ = l.Close() // every write after this fails
			failSafeDecision(evalFailure{stage: "policy load", err: errors.New("policy unparseable"), log: l},
				"agentshield-test-cmd", "/workspace", "claude-code-hook", "sess-4208")
		}},
		{"MCP hook whose log cannot open (#4470)", func(t *testing.T, home string) {
			if err := os.Mkdir(filepath.Join(home, ".agentshield", "audit.jsonl"), 0o700); err != nil {
				t.Fatal(err)
			}
			auditMCPCall("read_file", map[string]interface{}{"path": "/etc/hosts"},
				mcp.MCPEvalResult{Decision: policy.DecisionAudit, TriggeredRules: []string{"mcp-test-rule"}, Reasons: []string{"test"}},
				"claude-code-hook", "enforce", "sess-4470", "", nil)
		}},
		{"self-protect block whose log cannot open", func(t *testing.T, home string) {
			// A directory where the log should be: logger.New fails.
			if err := os.Mkdir(filepath.Join(home, ".agentshield", "audit.jsonl"), 0o700); err != nil {
				t.Fatal(err)
			}
			recordSelfProtectBlock(&logger.AuditEvent{
				Timestamp: "2026-10-21T00:00:00Z", Command: "agentshield-test-tamper", Decision: "BLOCK", Mode: "managed",
			})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, bodies := captureAudit(t)
			home := newRedactionHome(t, srv.URL)
			warmRealMachineID(t)

			tc.run(t, home)

			got := bodies()
			if len(got) != 1 {
				t.Fatalf("captured %d bodies, want 1; without a body this asserts nothing", len(got))
			}
			entry := wireEntry(t, got[0])
			if _, present := entry["local_chain"]; present {
				t.Errorf("event carries local_chain %v although no line was written", entry["local_chain"])
			}
			if m, _ := entry["machine_id"].(string); m == "" || m != enterprise.MachineID() {
				t.Errorf("machine_id = %q, want %q: it does not depend on the local write", m, enterprise.MachineID())
			}
		})
	}
}

// TestBuildLinkedAuditPayload_KeysAreAdditive: adding the link changes
// nothing else in the event. The golden's event with a genesis link, minus
// the two new keys, is the golden byte for byte; and the genesis prev_hash
// is sent as "", not omitted.
func TestBuildLinkedAuditPayload_KeysAreAdditive(t *testing.T) {
	event := &logger.AuditEvent{
		Command:          "telnet legacy-router.lan 23",
		Decision:         "AUDIT",
		Mode:             "audit-only",
		OriginalDecision: "BLOCK",
		TriggeredRules:   []string{"ne-block-telnet"},
		Reasons:          []string{"Plaintext telnet to internal host"},
		TaxonomyRefs:     []string{"data-exfiltration/network-egress/reverse-shell"},
		Source:           "claude-code-hook",
		Cwd:              "/workspace/acme-api",
		SessionID:        "9f2c1d64-3b7a-4c05-8e11-a6d0b4f37c92",
		Principal:        "dev",
	}
	golden, err := os.ReadFile(filepath.Join("testdata", "audit-only-payload-contract.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	lineHash := lineSHA256([]byte("line"))
	got, err := buildLinkedAuditPayload(event, goldenClientEventID, auditLink{
		MachineID: "machine-4208",
		Chain:     &logger.ChainLink{PrevHash: "", LineHash: lineHash},
	})
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string][]map[string]any
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatal(err)
	}
	entry := parsed["events"][0]
	if entry["machine_id"] != "machine-4208" {
		t.Errorf("machine_id = %v", entry["machine_id"])
	}
	if prev, line := wireLocalChain(t, entry); prev != "" || line != lineHash {
		t.Errorf("local_chain = {%q, %q}, want {\"\", %q}", prev, line, lineHash)
	}
	delete(entry, "machine_id")
	delete(entry, "local_chain")
	rest, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != string(golden) {
		t.Errorf("linked payload minus the two keys differs from the golden:\n got: %s\nwant: %s", rest, golden)
	}

	// And with no link, the linked builder is buildAuditPayload: the golden.
	plain, err := buildLinkedAuditPayload(event, goldenClientEventID, auditLink{})
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != string(golden) {
		t.Errorf("payload with an empty link differs from the golden:\n got: %s\nwant: %s", plain, golden)
	}
}
