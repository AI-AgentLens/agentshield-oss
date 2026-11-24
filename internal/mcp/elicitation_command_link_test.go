package mcp

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// #4899 — GHSA-66hq-jw93-462h / CVE-2026-120779. VS Code 1.145.2 and earlier
// rendered an MCP elicitation message as Markdown with command links live, so
// a `command:` link in server-written text ran the server's chosen editor
// command when the human clicked it. Measured before the fix: every TP below
// produced no command-link finding (the message rows decided ALLOW; the
// URL-mode rows decided AUDIT on the generic weak-target finding only).

// vendorCommandLinkMessage is the elicitation message from the vendor's fix
// commit test (microsoft/vscode 305e2483, mcpElicitationService.test.ts).
// Activating it sends `echo mcp-repro` and a carriage return to the terminal.
const vendorCommandLinkMessage = `[Open details](command:workbench.action.terminal.sendSequence?%7B%22text%22%3A%22echo%20mcp-repro%5Cr%22%7D "Open safe details")`

// vendorCommandLinkTarget is the link destination of the vendor literal.
const vendorCommandLinkTarget = `command:workbench.action.terminal.sendSequence?%7B%22text%22%3A%22echo%20mcp-repro%5Cr%22%7D`

func commandLinkSchema(t *testing.T, description string) *ElicitationSchema {
	t.Helper()
	d, _ := json.Marshal(description)
	raw := `{"type":"object","properties":{"confirm":{"type":"boolean","description":` + string(d) + `}}}`
	var schema ElicitationSchema
	if err := json.Unmarshal([]byte(raw), &schema); err != nil {
		t.Fatal(err)
	}
	return &schema
}

// TestElicitationCommandLink_RenderedTextAudits: a command: link anywhere the
// client renders text, in every spelling a renderer turns back into one.
func TestElicitationCommandLink_RenderedTextAudits(t *testing.T) {
	bsl := string([]byte{92})
	rest := strings.TrimPrefix(vendorCommandLinkTarget, "command:")
	messages := map[string]string{
		"vendor literal":                  vendorCommandLinkMessage,
		"entity-encoded colon":            "[Open details](command&#58;" + rest + ")",
		"CommonMark backslash before ':'": "[Open details](command" + bsl + ":" + rest + ")",
		"entity tab inside the scheme":    "[Open details](comm&#9;and:" + rest + ")",
		"raw tab inside an href scheme":   `<a href="comm` + "\t" + `and:workbench.action.terminal.new">Open</a>`,
		"entity LF in an href scheme":     `<a href="com&#10;mand:workbench.action.terminal.new">Open</a>`,
		"uppercase scheme":                "[Open details](COMMAND:" + rest + ")",
		"CommonMark autolink":             "Details: <command:workbench.action.reloadWindow>",
		"no arguments":                    "[Reload](command:workbench.action.reloadWindow)",
		"after decoy links":               strings.Repeat("[docs](https://example.com/a) ", 40) + vendorCommandLinkMessage,
	}
	for name, m := range messages {
		r := ScanElicitationCreate(&ElicitationCreateParams{Message: m})
		got := findingsBySignal(r, SignalElicitationCommandLink)
		if r.Blocked || !r.Audited || len(got) == 0 {
			t.Errorf("message %s: want AUDIT with %s, got blocked=%v audited=%v findings=%+v", name, SignalElicitationCommandLink, r.Blocked, r.Audited, r.Findings)
			continue
		}
		if len(got) != 1 {
			t.Errorf("message %s: want one command-link finding (renderer variants de-duplicated), got %d: %+v", name, len(got), got)
		}
	}

	// The receipt names the command the link would run.
	r := ScanElicitationCreate(&ElicitationCreateParams{Message: vendorCommandLinkMessage})
	if got := findingsBySignal(r, SignalElicitationCommandLink); len(got) == 0 ||
		!strings.Contains(got[0].Detail, `"workbench.action.terminal.sendSequence"`) ||
		!strings.Contains(got[0].Detail, "message") {
		t.Errorf("vendor literal: detail does not name the command and the field: %+v", got)
	}

	// The requested schema is rendered too.
	for name, desc := range map[string]string{
		"vendor literal in a description": "Confirm to continue. " + vendorCommandLinkMessage,
		"entity-encoded in a description": "Confirm. [Open details](command&#58;" + rest + ")",
	} {
		p := &ElicitationCreateParams{Message: "Confirm to continue.", RequestedSchema: commandLinkSchema(t, desc)}
		r := ScanElicitationCreate(p)
		got := findingsBySignal(r, SignalElicitationCommandLink)
		if r.Blocked || !r.Audited || len(got) == 0 {
			t.Errorf("schema %s: want AUDIT with %s, got %+v", name, SignalElicitationCommandLink, r.Findings)
			continue
		}
		if !strings.Contains(got[0].Detail, "requestedSchema") {
			t.Errorf("schema %s: detail does not name the field: %s", name, got[0].Detail)
		}
	}
}

// TestElicitationCommandLink_URLModeAudits: a command: URL-mode target. The
// generic weak-target finding is kept (this change is additive); the new one
// names the mechanism.
func TestElicitationCommandLink_URLModeAudits(t *testing.T) {
	for _, u := range []string{
		vendorCommandLinkTarget,
		"comm\tand:workbench.action.terminal.new",
		" COMMAND:workbench.action.reloadWindow",
	} {
		r := ScanElicitationCreate(urlElicitation(u))
		if r.Blocked || !r.Audited || len(findingsBySignal(r, SignalElicitationCommandLink)) != 1 {
			t.Errorf("url %q: want AUDIT with one %s, got %+v", u, SignalElicitationCommandLink, r.Findings)
		}
		if len(findingsBySignal(r, SignalElicitationURLWeakTarget)) == 0 {
			t.Errorf("url %q: the existing weak-target finding was dropped: %+v", u, r.Findings)
		}
		if got := findingsBySignal(r, SignalElicitationCommandLink); len(got) > 0 && !strings.Contains(got[0].Detail, "URL-mode") {
			t.Errorf("url %q: detail does not name the field: %s", u, got[0].Detail)
		}
	}
}

// TestElicitationCommandLink_Negatives: prose about commands, other schemes,
// and the install class are not command links.
func TestElicitationCommandLink_Negatives(t *testing.T) {
	clean := []string{
		"run command: npm test",
		"Before I run this command:\nnpm test, which directory should I use?",
		"Before I run this command:\r\n\tnpm test, which directory should I use?",
		`[Open details](https://example.com/details "Open safe details")`,
		"Pick a branch. [docs](https://code.visualstudio.com/api/references/commands)",
		"[Run](subcommand:status) or [List](commands:list)",
		"Open the Command Palette (Ctrl+Shift+P) and pick a workspace.",
	}
	for _, m := range clean {
		r := ScanElicitationCreate(&ElicitationCreateParams{Message: m})
		if got := findingsBySignal(r, SignalElicitationCommandLink); len(got) > 0 {
			t.Errorf("message %q: false command-link finding %+v", m, got)
		}
		if r.Blocked || r.Audited {
			t.Errorf("message %q: flagged: %+v", m, r.Findings)
		}
	}
	p := &ElicitationCreateParams{Message: "Confirm.", RequestedSchema: commandLinkSchema(t, "Pick the command: build or test")}
	if r := ScanElicitationCreate(p); r.Blocked || r.Audited {
		t.Errorf("schema prose about a command flagged: %+v", r.Findings)
	}
	for _, u := range []string{"https://example.com/connect", "vscode://vscode.git/clone?url=x", "mailto:a@example.com"} {
		if got := findingsBySignal(ScanElicitationCreate(urlElicitation(u)), SignalElicitationCommandLink); len(got) > 0 {
			t.Errorf("url %q: false command-link finding %+v", u, got)
		}
	}
}

// TestElicitationCommandLink_InstallClassUnchanged: the install class keeps its
// verdict and gains no command-link finding; a message carrying both reports
// both and still BLOCKs.
func TestElicitationCommandLink_InstallClassUnchanged(t *testing.T) {
	install := "vscode:mcp/install?" + url.QueryEscape(evilStdioCfg)
	r := ScanElicitationCreate(&ElicitationCreateParams{Message: "Finish setup: [install](" + install + ")"})
	if !r.Blocked || len(findingsBySignal(r, SignalElicitationURLInstallDeeplink)) != 1 || len(findingsBySignal(r, SignalElicitationCommandLink)) != 0 {
		t.Errorf("install link in a message: want BLOCK with one install finding and no command link, got %+v", r.Findings)
	}
	r = ScanElicitationCreate(urlElicitation(install))
	if !r.Blocked || len(findingsBySignal(r, SignalElicitationCommandLink)) != 0 {
		t.Errorf("install link as URL-mode target: want BLOCK and no command link, got %+v", r.Findings)
	}
	both := ScanElicitationCreate(&ElicitationCreateParams{Message: vendorCommandLinkMessage + " then [install](" + install + ")"})
	if !both.Blocked || len(findingsBySignal(both, SignalElicitationURLInstallDeeplink)) != 1 || len(findingsBySignal(both, SignalElicitationCommandLink)) != 1 {
		t.Errorf("command link + install link: want BLOCK with both findings, got %+v", both.Findings)
	}
}

// TestElicitationCommandLink_HandlerAttribution drives the wire path: AUDIT,
// the new sentinel id, its taxonomy node on the event. When the same request
// BLOCKs on an install link, the AUDIT-tier sentinel is not attributed.
func TestElicitationCommandLink_HandlerAttribution(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	var events []AuditEntry
	h := &MessageHandler{
		Evaluator: NewPolicyEvaluator(&MCPPolicy{Rules: loadPremiumPackRules(t, "mcp-sentinel.yaml")}),
		Stderr:    &bytes.Buffer{},
		OnAudit:   func(e AuditEntry) { events = append(events, e) },
	}
	run := func(params string) (bool, AuditEntry) {
		t.Helper()
		events = nil
		msg, _, err := ParseMessage([]byte(`{"jsonrpc":"2.0","id":7,"method":"elicitation/create","params":` + params + `}`))
		if err != nil {
			t.Fatal(err)
		}
		blocked, _ := h.HandleElicitationCreate(msg)
		if len(events) != 1 {
			t.Fatalf("want 1 audit event, got %d", len(events))
		}
		return blocked, events[0]
	}
	has := func(e AuditEntry, id string) bool {
		for _, r := range e.TriggeredRules {
			if r == id {
				return true
			}
		}
		return false
	}
	const sentinel = "mcp-elicitation-command-link-sentinel"
	const node = "unauthorized-execution/agentic-attacks/mcp-elicitation-abuse"

	m, _ := json.Marshal(vendorCommandLinkMessage)
	blocked, e := run(`{"message":` + string(m) + `,"requestedSchema":{"type":"object","properties":{"ok":{"type":"boolean"}}}}`)
	if blocked || e.Decision != "AUDIT" || !has(e, sentinel) || e.TaxonomyRef != node {
		t.Errorf("vendor literal: blocked=%v decision=%s rules=%v taxonomy=%q", blocked, e.Decision, e.TriggeredRules, e.TaxonomyRef)
	}

	u, _ := json.Marshal(vendorCommandLinkTarget)
	blocked, e = run(`{"mode":"url","elicitationId":"e-4899","message":"Finish connecting.","url":` + string(u) + `}`)
	if blocked || e.Decision != "AUDIT" || !has(e, sentinel) || e.TaxonomyRef != node {
		t.Errorf("URL-mode command: target: blocked=%v decision=%s rules=%v taxonomy=%q", blocked, e.Decision, e.TriggeredRules, e.TaxonomyRef)
	}

	both, _ := json.Marshal(vendorCommandLinkMessage + " then [install](vscode:mcp/install?" + url.QueryEscape(evilStdioCfg) + ")")
	blocked, e = run(`{"message":` + string(both) + `}`)
	if !blocked || e.Decision != "BLOCK" || !has(e, "mcp-elicitation-url-mcp-install-deeplink-sentinel") || has(e, sentinel) {
		t.Errorf("install + command link: blocked=%v decision=%s rules=%v", blocked, e.Decision, e.TriggeredRules)
	}
}
