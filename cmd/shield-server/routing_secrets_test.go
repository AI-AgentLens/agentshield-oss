package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/assembly"
)

// Inline secrets on a routed Claude Code PowerShell call (#4802). The
// Python thin client sends Claude Code's PowerShell call as a tool call
// (tool_name), so its lanes are Structured, then PowerShell, with no POSIX
// lane, and a token in a cmdlet call decided AUDIT with no rule. The
// PowerShell lane now runs the shell pipeline's inline-secrets heuristic, so
// the call BLOCKs as guardian-secrets_in_command, as the same text sent as a
// shell command does (the control). The PowerShell thin client sends a
// command, so its legacy POSIX lane already BLOCKed it, and keeps its record
// on the tie.
//
// Token-shaped strings are assembled at run time: the hook on a developer
// machine reads test sources it is asked to run as commands.

const serverSecretsRule = "guardian-secrets_in_command"

func serverToken() string { return "gh" + "p_" + strings.Repeat("Kq7Z", 9) }

func TestRoutedRequest_InlineSecrets(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	srv, err := NewServer(Options{Version: "test", LogPath: logPath, Mode: "enforce"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	cmd := "$env:GITHUB_TOKEN = '" + serverToken() + "'; gh repo list"
	py := evaluateRequest{ToolName: "PowerShell", Cwd: `C:\repo`, Arguments: map[string]interface{}{"command": cmd}}
	pwshClient := evaluateRequest{Command: cmd, Cwd: `C:\repo`, Arguments: map[string]interface{}{"command": cmd}}

	if r := mustPost(t, ts, evaluateRequest{Command: cmd}); r.Decision != "BLOCK" || !slices.Contains(r.Rules, serverSecretsRule) {
		t.Fatalf("control: the same text as a shell command decides %s %v; want BLOCK by %s", r.Decision, r.Rules, serverSecretsRule)
	}
	if r := mustPost(t, ts, py); r.Decision == "BLOCK" {
		t.Fatalf("control: the unkeyed tool call decides %s %v; MCP policy was expected to miss it", r.Decision, r.Rules)
	}

	r := mustPost(t, ts, withRoute(py, "claude-code", "PowerShell", "windows"))
	lr := noteDetails(r.Notes, analyzer.NoteLaneReadings)
	if r.Decision != "BLOCK" || !slices.Equal(r.Rules, []string{serverSecretsRule}) ||
		!slices.Equal(r.Taxonomy, []string{"credential-exposure/inline-credential/secret-in-command-line"}) ||
		len(lr) != 1 || !strings.HasSuffix(lr[0], "; powershell=BLOCK("+serverSecretsRule+"); kept=powershell") {
		t.Errorf("Python client: %s %v %v %q; want BLOCK by %s with its node, kept from the PowerShell lane", r.Decision, r.Rules, r.Taxonomy, lr, serverSecretsRule)
	}

	r = mustPost(t, ts, withRoute(pwshClient, "claude-code", "PowerShell", "windows"))
	lr = noteDetails(r.Notes, analyzer.NoteLaneReadings)
	if r.Decision != "BLOCK" || !slices.Contains(r.Rules, serverSecretsRule) || len(lr) != 1 || !strings.HasSuffix(lr[0], "kept=posix") {
		t.Errorf("PowerShell client: %s %v %q; want POSIX's BLOCK kept, as on main", r.Decision, r.Rules, lr)
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), serverToken()) || !strings.Contains(string(raw), "[REDACTED]") {
		t.Errorf("the server's audit log carries the token, or no [REDACTED] marker:\n%s", raw)
	}
}

// TestRoutedRequest_InlineSecretsBoundedOnTheServer: shield-server's lane
// reads at most assembly.ServerInlineSecretsBytes of a text with the
// inline-secrets heuristic, for its thin clients' 5 s timeout; past it the
// call decides as on main (AUDIT here). Control: the hook's lane, with no
// bound, BLOCKs the same text.
func TestRoutedRequest_InlineSecretsBoundedOnTheServer(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	head := "Write-Output " + serverToken() + "; "
	text := head + strings.Repeat("Get-Date; ", assembly.ServerInlineSecretsBytes/10+1)

	l := sharedServer.powerShellLane(`C:\repo`)
	if l.InlineSecretsBytes != assembly.ServerInlineSecretsBytes {
		t.Fatalf("server lane bound %d, want %d", l.InlineSecretsBytes, assembly.ServerInlineSecretsBytes)
	}
	l.InlineSecretsBytes = 0
	if res, err := l.Read(text); err != nil || res.Decision != "BLOCK" {
		t.Fatalf("control, unbounded lane: %s %v; want BLOCK", res.Decision, err)
	}

	r := mustPost(t, ts, withRoute(evaluateRequest{ToolName: "PowerShell", Cwd: `C:\repo`,
		Arguments: map[string]interface{}{"command": text}}, "claude-code", "PowerShell", "windows"))
	if r.Decision != "AUDIT" || slices.Contains(r.Rules, serverSecretsRule) {
		t.Errorf("server: %s %v; want AUDIT, as on main", r.Decision, r.Rules)
	}
	// A short text with the same token still BLOCKs on the server.
	if r := mustPost(t, ts, withRoute(evaluateRequest{ToolName: "PowerShell", Cwd: `C:\repo`,
		Arguments: map[string]interface{}{"command": head}}, "claude-code", "PowerShell", "windows")); r.Decision != "BLOCK" {
		t.Errorf("server, short text: %s %v; want BLOCK", r.Decision, r.Rules)
	}
}
