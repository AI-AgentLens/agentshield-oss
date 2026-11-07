package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/policy/remediation"
)

// ADR-001 step 2's two fitness functions, over the PowerShell reader's
// corpora: the 12 attack shapes and the benign agent text
// (internal/psreader/testdata/corpora), plus slices of the bash corpus.
//
//   - Version skew: a request with no route key decides exactly as main.
//   - Updated-client parity: for each entry point, the same call decides at
//     least as strictly with the updated client's request (the key) as with
//     the old client's on main. Nothing goes down.

const psCorpora = "../../internal/psreader/testdata/corpora"

type corpusInput struct {
	corpus, id, command string
}

func (c corpusInput) name() string { return c.corpus + "/" + c.id }

var (
	corpusOnce sync.Once
	corpusRows []corpusInput
	corpusErr  error
)

// psCorpus is every input of the PowerShell corpora, attack shapes first.
func psCorpus(t *testing.T) []corpusInput {
	t.Helper()
	corpusOnce.Do(func() {
		files, err := filepath.Glob(filepath.Join(psCorpora, "corpus-*.jsonl"))
		if err != nil {
			corpusErr = err
			return
		}
		sort.Slice(files, func(i, j int) bool {
			return strings.HasSuffix(files[i], "corpus-attack.jsonl") && !strings.HasSuffix(files[j], "corpus-attack.jsonl")
		})
		for _, f := range files {
			fh, err := os.Open(f)
			if err != nil {
				corpusErr = err
				return
			}
			sc := bufio.NewScanner(fh)
			sc.Buffer(make([]byte, 1<<20), 1<<22)
			corpus := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "corpus-"), ".jsonl")
			for sc.Scan() {
				if strings.TrimSpace(sc.Text()) == "" {
					continue
				}
				var r struct {
					ID      interface{} `json:"id"`
					Command string      `json:"command"`
				}
				if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
					corpusErr = fmt.Errorf("%s: %v", f, err)
					return
				}
				corpusRows = append(corpusRows, corpusInput{corpus, fmt.Sprint(r.ID), r.Command})
			}
			_ = fh.Close()
			if err := sc.Err(); err != nil {
				corpusErr = err
				return
			}
		}
	})
	if corpusErr != nil {
		t.Fatal(corpusErr)
	}
	// Denominator floor: an emptied corpus must not pass.
	if len(corpusRows) < 400 || corpusRows[0].corpus != "attack" {
		t.Fatalf("PowerShell corpora: %d inputs (first %q); want at least 400, attack shapes first", len(corpusRows), corpusRows[0].corpus)
	}
	return corpusRows
}

// --- main's evaluation, frozen ---------------------------------------------
//
// mainEvaluateShell and mainEvaluateMCP are main's evaluateShell and
// evaluateMCP bodies as of fe86ae40, the last commit before step 2, copied
// verbatim. The version-skew test holds a request with no key to them, so a
// change to today's path, or to what reaches it, fails here.

func mainEvaluateShell(s *Server, req evaluateRequest) evaluateResponse {
	normalized := normalize.NormalizeCommand(req.Command, req.Cwd)
	result := s.engine.EvaluateWithParsedCwd(req.Command, normalized.Paths, normalized.Parsed, req.Cwd)
	return evaluateResponse{
		Decision:         string(result.Decision),
		Rules:            result.TriggeredRules,
		Reasons:          result.Reasons,
		Taxonomy:         result.TaxonomyRefs,
		Explanation:      result.Explanation,
		Notes:            result.Notes,
		OriginalDecision: string(result.OriginalDecision),
		Remediation:      remediation.SuggestForShell(result.TriggeredRules, req.Command, enterprise.ManagedHost()),
	}
}

// mainEvaluateMCP: main's body without the session history, which no
// request here carries (no session_id, so main read no history either).
func mainEvaluateMCP(s *Server, req evaluateRequest) evaluateResponse {
	args := req.Arguments
	if args == nil {
		args = map[string]interface{}{}
	}
	var history []mcp.RecordedCall
	ev := s.mcpEval.InWorkingDir(req.Cwd)
	result := ev.EvaluateToolCallWithHistory(req.ToolName, args, req.ToolDescription, history)
	if bare, ok := mcp.BareToolName(req.ToolName); ok {
		result = mcp.PreferBlockingBareResult(result,
			ev.EvaluateToolCallWithHistory(bare, args, req.ToolDescription, history))
	}
	result, _ = s.mcpEval.ApplyValueLimits(result, req.ToolName, args)
	result = s.mcpEval.ApplyModeKeepingSelfProtection(result, s.mode, req.ToolName, args)
	return evaluateResponse{
		Decision:         string(result.Decision),
		Rules:            result.TriggeredRules,
		Reasons:          result.Reasons,
		Taxonomy:         result.AllTaxonomyRefs(),
		OriginalDecision: string(result.OriginalDecision),
		Remediation:      remediation.SuggestForMCP(result.TriggeredRules, enterprise.ManagedHost()),
	}
}

// wire is a response as the client reads it: through JSON, with the fields
// the handler adds.
func wire(t *testing.T, s *Server, resp evaluateResponse, req evaluateRequest) evaluateResponse {
	t.Helper()
	resp.Mode, resp.Degraded, resp.SessionID = s.mode, s.degraded, req.SessionID
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var out evaluateResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// bashSample is every 25th case of the bash corpus: shell text, attack and
// benign, for the command half of the version-skew check.
func bashSample() []corpusInput {
	var out []corpusInput
	for i, c := range testdata.AllTestCases() {
		if i%25 == 0 {
			out = append(out, corpusInput{"bash", c.ID, c.Command})
		}
	}
	return out
}

// TestVersionSkew_UnkeyedRequestDecidesAsMain: a request from a client that
// predates the route key decides exactly as main, field for field: as a
// command (the PowerShell client's shell tools, the Python client's Bash) and
// as a tool call (every other tool, Claude Code's PowerShell from the Python
// client). Control: the same call with the key decides differently on at
// least one input, so the comparison can tell the two paths apart.
func TestVersionSkew_UnkeyedRequestDecidesAsMain(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	inputs := append(append([]corpusInput(nil), psCorpus(t)...), bashSample()...)

	decisions := map[string]int{}
	keyedDiffers := 0
	for _, in := range inputs {
		for _, req := range []evaluateRequest{
			{Command: in.command, Cwd: `C:\repo`},
			{ToolName: "PowerShell", Cwd: `C:\repo`, Arguments: map[string]interface{}{"command": in.command}},
		} {
			got := mustPost(t, ts, req)
			var want evaluateResponse
			if req.Command != "" {
				want = mainEvaluateShell(sharedServer, req)
				decisions[got.Decision]++
			} else {
				want = mainEvaluateMCP(sharedServer, req)
			}
			want = wire(t, sharedServer, want, req)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s (%s): the unkeyed request decides\n %+v\nmain decided\n %+v", in.name(), map[bool]string{true: "command", false: "tool call"}[req.Command != ""], got, want)
			}
		}
		if keyedDiffers == 0 {
			keyed := mustPost(t, ts, withRoute(evaluateRequest{Command: in.command, Cwd: `C:\repo`}, "claude-code", "PowerShell", "windows"))
			if keyed.Decision != mustPost(t, ts, evaluateRequest{Command: in.command, Cwd: `C:\repo`}).Decision {
				keyedDiffers++
			}
		}
	}
	if decisions["BLOCK"] == 0 || decisions["ALLOW"] == 0 || decisions["AUDIT"] == 0 {
		t.Errorf("unkeyed command decisions %v: the corpus must exercise BLOCK, AUDIT and ALLOW", decisions)
	}
	if keyedDiffers == 0 {
		t.Error("control: no input decides differently with the key; the comparison cannot tell the paths apart")
	}
	t.Logf("%d inputs, unkeyed command decisions %v", len(inputs), decisions)
}

// --- updated-client parity --------------------------------------------------

// parityCall is one entry point's call: the request its client on main sent
// (old) and the one the updated client sends (new).
type parityCall struct {
	entry, call string
	old, new    func(cmd string) evaluateRequest
}

// The clients' request shapes, as TestRemoteHookSendsRoutingKey and
// TestPwshHookSendsRoutingKey capture them from the real scripts.
func ps1Command(cmd string) evaluateRequest {
	return evaluateRequest{Command: cmd, Cwd: `C:\repo`}
}

func ps1Keyed(harness, tool string) func(string) evaluateRequest {
	return func(cmd string) evaluateRequest {
		return withRoute(evaluateRequest{Command: cmd, Cwd: `C:\repo`, Arguments: map[string]interface{}{"command": cmd}}, harness, tool, "windows")
	}
}

func pyToolCall(cmd string) evaluateRequest {
	return evaluateRequest{ToolName: "PowerShell", Cwd: `C:\repo`, Arguments: map[string]interface{}{"command": cmd}}
}

var parityCalls = []parityCall{
	{"PowerShell client", "Claude Code PowerShell", ps1Command, ps1Keyed("claude-code", "PowerShell")},
	{"PowerShell client", "Copilot compat Bash, AGENTSHIELD_AGENT_ID=copilot-cli", ps1Command, ps1Keyed("copilot-cli", "Bash")},
	{"PowerShell client", "Copilot compat Bash, AGENTSHIELD_AGENT_ID unset", ps1Command, ps1Keyed("claude-code", "Bash")},
	{"PowerShell client", "Copilot native powershell", ps1Command, ps1Keyed("copilot-cli-native", "powershell")},
	{"PowerShell client", "Copilot native bash", ps1Command, ps1Keyed("copilot-cli-native", "bash")},
	{"PowerShell client", "Codex PowerShell (turn_id)", ps1Command, ps1Keyed("codex", "PowerShell")},
	{"Python client", "Claude Code PowerShell", pyToolCall, func(cmd string) evaluateRequest {
		return withRoute(pyToolCall(cmd), "claude-code", "PowerShell", "windows")
	}},
	{"Python client", "Claude Code Bash", func(cmd string) evaluateRequest {
		return evaluateRequest{Command: cmd, Cwd: `C:\repo`}
	}, func(cmd string) evaluateRequest {
		return withRoute(evaluateRequest{Command: cmd, Cwd: `C:\repo`, Arguments: map[string]interface{}{"command": cmd}}, "claude-code", "Bash", "linux")
	}},
	{"Python client", "Codex PowerShell (turn_id)", pyToolCall, func(cmd string) evaluateRequest {
		return withRoute(pyToolCall(cmd), "codex", "PowerShell", "windows")
	}},
}

var decisionRank = map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}

func firstRule(rs []string) string {
	if len(rs) == 0 {
		return "-"
	}
	return rs[0]
}

// crossPlatformCLIs are programs that run verbatim under PowerShell as under
// bash, so a BLOCK the POSIX pipeline gives their invocation must survive any
// entry point that starts sending tool names (#4766 Opus pass 1, F1: the
// PowerShell lane has no rules for them).
var crossPlatformCLIs = map[string]bool{
	"git": true, "gh": true, "docker": true, "kubectl": true, "helm": true, "terraform": true, "pulumi": true,
	"aws": true, "gcloud": true, "az": true, "vault": true, "npm": true, "npx": true, "yarn": true, "pnpm": true,
	"pip": true, "pip3": true, "python": true, "python3": true, "node": true, "cargo": true, "go": true,
	"dotnet": true, "ssh": true, "scp": true, "rsync": true, "openssl": true, "psql": true, "mysql": true,
	"mongosh": true, "redis-cli": true, "ncat": true, "curl": true,
}

// cliSlice is every single-line BLOCK true positive of the bash corpus whose
// program is a cross-platform CLI.
func cliSlice() []corpusInput {
	var out []corpusInput
	for _, c := range testdata.AllTestCases() {
		cmd := strings.TrimSpace(c.Command)
		if c.Classification != "TP" || c.ExpectedDecision != "BLOCK" || cmd == "" || strings.Contains(cmd, "\n") {
			continue
		}
		if f := strings.Fields(cmd); crossPlatformCLIs[f[0]] {
			out = append(out, corpusInput{"bash-cli", c.ID, c.Command})
		}
	}
	return out
}

// loweredDecisions compares two request shapes over inputs and returns the
// inputs whose decision goes down, keyed "<input> <old decision>(<rule>)",
// with the new decision, and how many went up.
func loweredDecisions(t *testing.T, ts *httptest.Server, inputs []corpusInput, old, new func(string) evaluateRequest, seen map[string]evaluateResponse) (lowered map[string]string, raised, oldBlocks int) {
	t.Helper()
	lowered = map[string]string{}
	for _, in := range inputs {
		// Main's request shapes repeat across calls (the PowerShell client
		// sent every shell tool as the same command), so each is evaluated
		// once. A request with no session reads no history: the cache
		// cannot change a decision.
		oreq := old(in.command)
		ok := mustJSON(t, oreq)
		o, hit := seen[ok]
		if !hit {
			o = mustPost(t, ts, oreq)
			seen[ok] = o
		}
		n := mustPost(t, ts, new(in.command))
		if o.Decision == "BLOCK" {
			oldBlocks++
		}
		switch {
		case decisionRank[n.Decision] < decisionRank[o.Decision]:
			lowered[fmt.Sprintf("%s %s(%s)", in.name(), o.Decision, firstRule(o.Rules))] = fmt.Sprintf("%s(%s)", n.Decision, firstRule(n.Rules))
		case decisionRank[n.Decision] > decisionRank[o.Decision]:
			raised++
		}
	}
	return lowered, raised, oldBlocks
}

// TestUpdatedClientParity (ADR-001 fitness function "Updated-client
// parity"): for each entry point and each call it sends, the updated
// client's request decides at least as strictly as main's client's did, on
// the 12 attack shapes, the benign PowerShell corpora and the bash corpus's
// cross-platform CLI BLOCKs. Nothing may go down: a keyed request is read by
// the lane its shape took on main first (routing.go), so this holds by
// construction, and a lowered decision here is a regression.
func TestUpdatedClientParity(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	cli := cliSlice()
	inputs := append(append([]corpusInput(nil), psCorpus(t)...), cli...)
	if len(cli) < 200 {
		t.Fatalf("cross-platform CLI slice: %d inputs, want at least 200", len(cli))
	}

	// Control: the comparison sees a lowering. Main's two clients sent the
	// same destructive text as a command (BLOCK) and as a PowerShell tool
	// call (AUDIT, TestEvaluateRoutingCharacterization).
	ctl, _, _ := loweredDecisions(t, ts, []corpusInput{{"control", "rm-root", destructiveCommand()}},
		func(c string) evaluateRequest { return evaluateRequest{Command: c} }, pyToolCall, map[string]evaluateResponse{})
	if len(ctl) != 1 {
		t.Fatalf("control: lowered %v, want the command's BLOCK lowered by the tool call", ctl)
	}

	seen := map[string]evaluateResponse{}
	for _, pc := range parityCalls {
		key := pc.entry + ": " + pc.call
		lowered, raised, oldBlocks := loweredDecisions(t, ts, inputs, pc.old, pc.new, seen)
		if oldBlocks == 0 {
			t.Errorf("%s: main's request BLOCKs nothing in the corpus, so nothing could be seen to lower", key)
		}
		var names []string
		for in, now := range lowered {
			names = append(names, in+" -> "+now)
		}
		sort.Strings(names)
		for _, n := range names {
			t.Errorf("%s: %s: the updated client's request decides below main's client", key, n)
		}
		t.Logf("%s: %d inputs (%d CLI), main BLOCKs %d, %d raised, %d lowered", key, len(inputs), len(cli), oldBlocks, raised, len(lowered))
	}
}
