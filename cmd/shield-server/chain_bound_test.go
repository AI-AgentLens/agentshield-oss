package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// The chain bound on shield-server (#4778). On main a pipeline of about 330 000
// stages overflowed the Go stack inside readShell, which killed the whole
// server and every request in flight: these tests would take the test binary
// down with it. Texts are generated, never fixtures.

func pipeOf(n int) string { return strings.Repeat("a|", n-1) + "a" }

func countChainNotes(ns []analyzer.Note) int {
	n := 0
	for _, x := range ns {
		if x.Kind == analyzer.NoteChainTooLong {
			n++
		}
	}
	return n
}

// stillServes asks the server for a decision it makes on main, after a call
// past the bound.
func stillServes(t *testing.T, ts *httptest.Server) {
	t.Helper()
	code, resp := postEval(t, ts, evaluateRequest{Command: destructiveCommand()})
	if code != http.StatusOK || resp.Decision != "BLOCK" {
		t.Fatalf("after the call past the bound: status %d decision %q, want 200 BLOCK", code, resp.Decision)
	}
}

// TestEvaluate_ChainPastTheBound_AuditsAndKeepsServing: the 1 MiB pipeline,
// and a 26 KiB command whose nested text is past the bound once its variable
// is substituted, are each answered AUDIT agentshield-eval-error with a
// chain_too_long note, unkeyed and on a routed POSIX lane; the server keeps
// serving.
func TestEvaluate_ChainPastTheBound_AuditsAndKeepsServing(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()

	x := pipeOf(shellparse.MaxChainOperators/40 + 100)
	derived := "X='" + x + "'; bash -c \"" + strings.Repeat("$X|", 39) + "$X\""
	bash := &routeKey{Harness: "claude-code", Tool: "Bash", OS: "darwin"}
	for name, req := range map[string]evaluateRequest{
		"own 1 MiB":     {Command: pipeOf(524288)},
		"own, routed":   {Command: pipeOf(524288), Route: bash},
		"derived":       {Command: derived},
		"just past":     {Command: pipeOf(shellparse.MaxChainOperators + 2)},
		"derived route": {Command: derived, Route: bash},
	} {
		code, resp := postEval(t, ts, req)
		if code != http.StatusOK || resp.Decision != "AUDIT" || !slices.Equal(resp.Rules, []string{evalErrorRuleID}) || countChainNotes(resp.Notes) != 1 {
			t.Errorf("%s: status %d %s %v notes %v; want 200 AUDIT [%s] with one %s", name, code, resp.Decision, resp.Rules, resp.Notes, evalErrorRuleID, analyzer.NoteChainTooLong)
		}
	}
	stillServes(t, ts)
}

// TestEvaluate_ChainAtTheBoundIsRead is the control: a pipeline AT the bound
// whose first stage is destructive is read as before (BLOCK, no note).
func TestEvaluate_ChainAtTheBoundIsRead(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	code, resp := postEval(t, ts, evaluateRequest{Command: destructiveCommand() + strings.Repeat("|a", shellparse.MaxChainOperators)})
	if code != http.StatusOK || resp.Decision != "BLOCK" || countChainNotes(resp.Notes) != 0 {
		t.Errorf("status %d %s %v notes %v; want 200 BLOCK with no %s", code, resp.Decision, resp.Rules, resp.Notes, analyzer.NoteChainTooLong)
	}
}

// TestRoutedPowerShell_NestedChainPastTheBound: a PowerShell text whose
// nested bash text is past the bound reaches the PowerShell lane's nested
// reading (readShell): the lane's reading is AUDIT with the chain_too_long
// note, which the lane carries as an uncertain note. Through the handler, the
// Python client's Claude Code PowerShell call is answered, at least AUDIT,
// and the server keeps serving.
func TestRoutedPowerShell_NestedChainPastTheBound(t *testing.T) {
	text := "bash -c '" + pipeOf(40000) + "'"
	r, err := sharedServer.powerShellLane("").Read(text)
	if err != nil {
		t.Fatalf("the lane failed: %v", err)
	}
	if r.Decision != "AUDIT" || countChainNotes(r.Notes) != 1 {
		t.Errorf("lane reading %s %v notes %v; want AUDIT with one %s", r.Decision, r.TriggeredRules, r.Notes, analyzer.NoteChainTooLong)
	}

	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	code, resp := postEval(t, ts, evaluateRequest{
		ToolName:  "PowerShell",
		Arguments: map[string]interface{}{"command": text},
		Route:     &routeKey{Harness: "claude-code", Tool: "PowerShell", OS: "windows"},
	})
	if code != http.StatusOK || (resp.Decision != "AUDIT" && resp.Decision != "BLOCK") {
		t.Fatalf("status %d decision %q; want 200 and at least AUDIT", code, resp.Decision)
	}
	stillServes(t, ts)
}
