package cli

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/assembly"
	"github.com/AI-AgentLens/agentshield/internal/facts"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/psreader"
	"github.com/AI-AgentLens/agentshield/internal/route"
)

// The PowerShell lane in the hook (ADR-001 step 4 part 2, #4245). The rows
// in TestHookRoutingCharacterization pin which lane each PowerShell row keeps;
// these tests pin what the lane itself guarantees: the bash spelling's
// taxonomy on a protected-path BLOCK, one receipt per call with the lane's
// notes, managed-host self-protection, nested interpreters and their depth
// bound, and the fail-safe reading on a panic.
//
// Attack strings are assembled at runtime: the hook reads test sources as
// commands (dogfooding).

func sshKeyPath() string { return "~/.ssh/id_" + "rsa" }

// psEncoded is `powershell -EncodedCommand <text>`, encoded as PowerShell
// encodes it: base64 of the UTF-16LE text.
func psEncoded(text string) string {
	u := utf16.Encode([]rune(text))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return "powershell -EncodedCommand " + base64.StdEncoding.EncodeToString(b)
}

func psCall(t *testing.T, cmd string) string {
	return claudeShaped(t, "PreToolUse", "PowerShell", routingCmd(cmd), nil)
}

func oneEvent(t *testing.T, configDir string) logger.AuditEvent {
	t.Helper()
	events := loggedEvents(t, configDir)
	if len(events) != 1 {
		t.Fatalf("want exactly one audit line, got %d: %+v", len(events), events)
	}
	return events[0]
}

func noteKinds(ns []logger.Note) []string {
	var out []string
	for _, n := range ns {
		out = append(out, n.Kind)
	}
	return out
}

func countKind(ns []logger.Note, kind string) int {
	n := 0
	for _, x := range ns {
		if x.Kind == kind {
			n++
		}
	}
	return n
}

// TestPowerShellLane_TaxonomyMatchesTheBashSpelling: a protected-path BLOCK
// from the PowerShell lane carries the rule and the taxonomy node a bash read
// of the same file gets, so the receipt attests the same control.
func TestPowerShellLane_TaxonomyMatchesTheBashSpelling(t *testing.T) {
	cases := []struct{ name, bash, ps string }{
		{"ssh key", "cat " + sshKeyPath(), psKeyRead()},
		{"aws credentials", "cat ~/.aws/" + "credentials", "Get-Content $env:USERPROFILE" + `\.aws\` + "credentials"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
			if code, _, stderr := runHookChild(t, home, claudeShaped(t, "PreToolUse", "Bash", routingCmd(c.bash), nil)); code != 2 {
				t.Fatalf("control: the bash spelling exits %d, want 2. stderr:\n%s", code, stderr)
			}
			bash := oneEvent(t, configDir)

			home, configDir = newFailSafeHome(t, false, failSafePolicyGood)
			if code, _, stderr := runHookChild(t, home, psCall(t, c.ps)); code != 2 {
				t.Fatalf("the PowerShell spelling exits %d, want 2. stderr:\n%s", code, stderr)
			}
			ps := oneEvent(t, configDir)

			if !containsStr(bash.TriggeredRules, policy.ProtectedPathRuleID) || !containsStr(ps.TriggeredRules, policy.ProtectedPathRuleID) {
				t.Fatalf("rules: bash %v, PowerShell %v; want %s on both", bash.TriggeredRules, ps.TriggeredRules, policy.ProtectedPathRuleID)
			}
			b, p := slices.Clone(bash.TaxonomyRefs), slices.Clone(ps.TaxonomyRefs)
			slices.Sort(b)
			slices.Sort(p)
			if len(p) == 0 || !slices.Equal(b, p) {
				t.Errorf("taxonomy: bash %v, PowerShell %v; want the same node(s)", b, p)
			}
		})
	}
}

// TestPowerShellLane_OneReceiptWithTheLaneNotes: a call the PowerShell lane
// decides leaves one local line and one upload, shell-shaped (the PowerShell
// text as the command, the harness's shell source), carrying the dialect note
// once and the lane_readings note once.
func TestPowerShellLane_OneReceiptWithTheLaneNotes(t *testing.T) {
	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	posted := captureAuditPOSTs(t)
	cmd := psKeyRead()
	if code, _, stderr := runHookChild(t, home, psCall(t, cmd)); code != 2 {
		t.Fatalf("exit %d, want 2. stderr:\n%s", code, stderr)
	}
	e := oneEvent(t, configDir)
	if e.Command != cmd || e.ToolName != "" || e.Source != "claude-code-hook" || e.Decision != "BLOCK" {
		t.Errorf("event command=%q tool=%q source=%q decision=%q; want the PowerShell text, no tool, claude-code-hook, BLOCK", e.Command, e.ToolName, e.Source, e.Decision)
	}
	if countKind(e.Notes, analyzer.NoteDialect) != 1 || countKind(e.Notes, analyzer.NoteLaneReadings) != 1 {
		t.Errorf("notes %v; want one %s and one %s", noteKinds(e.Notes), analyzer.NoteDialect, analyzer.NoteLaneReadings)
	}
	for _, n := range e.Notes {
		if n.Kind == analyzer.NoteDialect && n.Detail != facts.DialectPowerShell {
			t.Errorf("dialect note detail %q, want %q", n.Detail, facts.DialectPowerShell)
		}
	}
	sent := posted()
	if len(sent) != 1 {
		t.Fatalf("want exactly one event uploaded, got %d", len(sent))
	}
	if countKind(sent[0], analyzer.NoteDialect) != 1 || countKind(sent[0], analyzer.NoteLaneReadings) != 1 {
		t.Errorf("uploaded notes %v; want one %s and one %s", noteKinds(sent[0]), analyzer.NoteDialect, analyzer.NoteLaneReadings)
	}
}

// allowDefaultPolicy decides ALLOW where nothing matches, so a lane's AUDIT
// floor is the only thing that can raise a benign call.
const allowDefaultPolicy = `version: "0.1"
defaults:
  decision: "ALLOW"
rules: []
`

// TestPowerShellLane_ReaderNotesFloorAndReachTheReceipt: text the reader
// cannot follow puts the AUDIT floor under the call, and the reader's note is
// on the receipt (ADR-001 D4). Copilot's native powershell row, under a
// policy whose default is ALLOW, so the bash pipeline's reading is ALLOW and
// only the floor raises it.
func TestPowerShellLane_ReaderNotesFloorAndReachTheReceipt(t *testing.T) {
	home, configDir := newFailSafeHome(t, false, allowDefaultPolicy)
	cmd := "Get-Date; @{ a = 1"
	if code, _, stderr := runHookChild(t, home, copilotNativePayload(t, "ps-notes", "powershell", shellArgs(cmd))); code != 0 {
		t.Fatalf("exit %d, want 0. stderr:\n%s", code, stderr)
	}
	e := oneEvent(t, configDir)
	if e.Decision != "AUDIT" || countKind(e.Notes, string(facts.NoteParseError)) == 0 {
		t.Fatalf("decision %q notes %v; want AUDIT with the reader's %s note", e.Decision, noteKinds(e.Notes), facts.NoteParseError)
	}
	n := laneReadingsNotes(e.Notes)
	if len(n) != 1 || !strings.Contains(n[0], "posix=ALLOW") || !strings.Contains(n[0], "powershell=AUDIT") || !strings.HasSuffix(n[0], "kept=powershell") {
		t.Errorf("%s notes %q; want the bash pipeline's ALLOW and the PowerShell lane's AUDIT, kept", analyzer.NoteLaneReadings, n)
	}
}

// policyFile is AgentShield's policy file under HOME, spelled as a Windows
// agent writes it.
func policyFileWindowsSpelling() string {
	return "$env:USERPROFILE" + `\.agent` + `shield\policy.yaml`
}

// TestPowerShellLane_ManagedSelfProtection: on a managed host a PowerShell
// text that names AgentShield's config directory is blocked unless it is a
// known read (Gary's decision 3), on every PowerShell row. The sp-* text rules
// reach PowerShell text through the POSIX lane on the two Copilot rows, and
// through a nested bash text's POSIX reading on every row; they are not
// duplicated in the PowerShell lane. Claude Code's PowerShell row has no
// POSIX lane (Kai, 2026-11-03); its native programs' argv reach them through
// the native-command bridge (#4768), so `setup --disable` there BLOCKs, and
// the binary's own refusal (CheckDisableAllowed) stays underneath.
func TestPowerShellLane_ManagedSelfProtection(t *testing.T) {
	remove := "Remove-Item " + policyFileWindowsSpelling()
	read := "Get-Content " + policyFileWindowsSpelling()
	disable := "agentshield setup claude-code " + "--disable"
	cases := []struct {
		name, payload string
		env           []string
		exit          int
		rule          string // "" asserts no BLOCK rule
		kept          string // the lane whose record is kept
	}{
		// The bash text rules do not read a backslash path, and the bash
		// path layer does not resolve $env:USERPROFILE: only the PowerShell
		// lane sees this write.
		{"claude-code PowerShell Remove-Item", psCall(t, remove), nil, 2, "enterprise-self-protect", "powershell"},
		{"copilot compat Bash on windows Remove-Item", copilotCompatPayload(t, "sp", "Bash", shellArgs(remove)), append([]string{"AGENTSHIELD_AGENT_ID=copilot-cli"}, onWindows...), 2, "enterprise-self-protect", "powershell"},
		{"copilot native powershell Remove-Item", copilotNativePayload(t, "sp", "powershell", shellArgs(remove)), nil, 2, "enterprise-self-protect", "powershell"},
		// A known read passes the PowerShell lane, and nothing else blocks it.
		{"claude-code PowerShell Get-Content", psCall(t, read), nil, 0, "", "structured"},
		{"copilot native powershell Get-Content", copilotNativePayload(t, "sp", "powershell", shellArgs(read)), nil, 0, "", "posix"},
		// sp-block-setup-disable, through the POSIX lane.
		{"copilot native powershell setup --disable", copilotNativePayload(t, "sp", "powershell", shellArgs(disable)), nil, 2, "enterprise-self-protect", "posix"},
		// No POSIX lane on Claude Code's row, but `agentshield` is a native
		// program: the native-command bridge (#4768) reads its argv with the
		// POSIX lane, middleware first, so sp-block-setup-disable BLOCKs it
		// as through the Bash tool. Main decided AUDIT here and relied on the
		// binary refusing the disable itself, which it still does.
		{"claude-code PowerShell setup --disable (the bridge)", psCall(t, disable), nil, 2, "enterprise-self-protect", "powershell"},
		// Text the row's POSIX lane cannot see: encoded PowerShell starting
		// bash. The nested bash text is read by the POSIX lane's middleware
		// inside the PowerShell lane.
		{"claude-code PowerShell encoded bash -c setup --disable", psCall(t, psEncoded("bash -c '"+disable+"'")), nil, 2, "enterprise-self-protect", "powershell"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
			code, _, stderr := runHookChild(t, home, c.payload, c.env...)
			if code != c.exit {
				t.Fatalf("exit %d, want %d. stderr:\n%s", code, c.exit, stderr)
			}
			e := oneEvent(t, configDir)
			if c.rule != "" && (e.Decision != "BLOCK" || !containsStr(e.TriggeredRules, c.rule)) {
				t.Errorf("decision %q rules %v, want BLOCK by %s", e.Decision, e.TriggeredRules, c.rule)
			}
			if c.rule == "" && e.Decision == "BLOCK" {
				t.Errorf("decision BLOCK (rules %v), want a known read to pass", e.TriggeredRules)
			}
			n := laneReadingsNotes(e.Notes)
			if len(n) != 1 || !strings.HasSuffix(n[0], "kept="+c.kept) {
				t.Errorf("%s notes %q, want the %s lane's record kept", analyzer.NoteLaneReadings, n, c.kept)
			}
		})
	}
}

// TestPowerShellLane_ManagedForwardSlashReadIsBlockedByPOSIX pins a residue
// of Copilot's POSIX lane, not a PowerShell-lane decision: with forward
// slashes, the POSIX lane's default-deny rule (sp-block-config-touch) reads a
// PowerShell read of the policy file too, and Get-Content is not on bash's
// read list, so the call is blocked even though the PowerShell lane passes it.
// Lowering it is Gary's call (a POSIX lane leaving the row is ADR-001 step
// 6). Claude Code's row, which has no POSIX lane, lets the known read pass.
func TestPowerShellLane_ManagedForwardSlashReadIsBlockedByPOSIX(t *testing.T) {
	cmd := "Get-Content ~/.agent" + "shield/policy.yaml"
	home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
	if code, _, stderr := runHookChild(t, home, psCall(t, cmd)); code != 0 {
		t.Fatalf("claude-code: exit %d, want 0 (a known read, no POSIX lane). stderr:\n%s", code, stderr)
	}
	home, configDir = newFailSafeHome(t, true, failSafePolicyGood)
	if code, _, stderr := runHookChild(t, home, copilotNativePayload(t, "sp", "powershell", shellArgs(cmd))); code != 2 {
		t.Fatalf("copilot native: exit %d, want 2. stderr:\n%s", code, stderr)
	}
	e := oneEvent(t, configDir)
	n := laneReadingsNotes(e.Notes)
	if len(n) != 1 || !strings.Contains(n[0], "posix=BLOCK(enterprise-self-protect)") || !strings.Contains(n[0], "powershell=AUDIT") || !strings.HasSuffix(n[0], "kept=posix") {
		t.Errorf("%s notes %q; want POSIX's BLOCK kept over the PowerShell lane's AUDIT", analyzer.NoteLaneReadings, n)
	}
}

// TestPowerShellLane_NestedInterpreters: text a nested interpreter runs goes
// back to the router (ADR-001 D6) and decides with the call. With the default
// bound (max_parse_depth 2), the call's text and two levels under it are
// read: `powershell -EncodedCommand` wrapping a `bash -c` is depth 2 and is
// read; one more encoding puts the bash text at depth 3, which is not read,
// and the call decides AUDIT.
func TestPowerShellLane_NestedInterpreters(t *testing.T) {
	keyRead := "Get-Content " + sshKeyPath()
	bashRoot := "bash -c '" + routingDestructive() + "'"
	cases := []struct {
		name, cmd string
		exit      int
		decision  string
		rule      string
		kept      string
	}{
		{"encoded key read", psEncoded(keyRead), 2, "BLOCK", policy.ProtectedPathRuleID, "powershell"},
		// The bash pipeline reads this one too (sec-block-ssh-private) and,
		// earlier in the row, keeps the record on the tie.
		{"bash -c key read", "bash -c 'cat " + sshKeyPath() + "'", 2, "BLOCK", "", ""},
		{"encoded bash -c (depth 2: read)", psEncoded(bashRoot), 2, "BLOCK", "ts-block-rm-root", "powershell"},
		{"encoded encoded bash -c (depth 3: not read)", psEncoded(psEncoded(bashRoot)), 0, "AUDIT", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
			code, _, stderr := runHookChild(t, home, psCall(t, c.cmd))
			if code != c.exit {
				t.Fatalf("exit %d, want %d. stderr:\n%s", code, c.exit, stderr)
			}
			e := oneEvent(t, configDir)
			if e.Decision != c.decision || (c.rule != "" && !containsStr(e.TriggeredRules, c.rule)) {
				t.Errorf("decision %q rules %v, want %s %s", e.Decision, e.TriggeredRules, c.decision, c.rule)
			}
			if c.kept != "" {
				if n := laneReadingsNotes(e.Notes); len(n) != 1 || !strings.HasSuffix(n[0], "kept="+c.kept) {
					t.Errorf("%s notes %q, want the %s lane kept", analyzer.NoteLaneReadings, n, c.kept)
				}
			}
		})
	}
}

// testPSLane is a PowerShell lane over the embedded packs, on a policy whose
// default is ALLOW: a nested reading is then the only thing that can decide
// above ALLOW.
func testPSLane(t *testing.T, maxDepth int) *psLane {
	t.Helper()
	newFailSafeHome(t, false, "")
	pol := &policy.Policy{Version: "0.1", Defaults: policy.Defaults{Decision: policy.DecisionAllow}}
	pol, _, err := policy.LoadEmbeddedShellPacks(pol)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := assembly.ShellEngine(pol, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	home := os.Getenv("HOME")
	return &psLane{engine: engine, env: psreader.Env{Home: home}, opts: policy.FactsOptions{Home: home},
		cwd: home, source: "claude-code-hook", maxDepth: maxDepth}
}

// read is the lane's decision on text, for the tests that call the lane
// directly. A lane failure, which the hook turns into its fail-safe reading,
// fails the test here.
func (l *psLane) read(text string) policy.EvalResult {
	r, err := l.lane().Read(text)
	if err != nil {
		panic(err)
	}
	return r
}

func hasNote(ns []analyzer.Note, kind string) bool {
	for _, n := range ns {
		if n.Kind == kind {
			return true
		}
	}
	return false
}

// TestPSLane_NestedRouting: each nested interpreter's text is read by the lane
// route.NestedLane names, and an interpreter with no lane is recorded and
// floored. Every outer text here decides ALLOW on its own.
func TestPSLane_NestedRouting(t *testing.T) {
	root := routingDestructive()
	cases := []struct {
		name, cmd string
		decision  policy.Decision
		rule      string
		note      string
	}{
		{"control: no nesting", "Get-Date", policy.DecisionAllow, "", ""},
		{"bash -c", "bash -c '" + root + "'", policy.DecisionBlock, "ts-block-rm-root", ""},
		{"sh -c", "sh -c '" + root + "'", policy.DecisionBlock, "ts-block-rm-root", ""},
		{"BASH.EXE -c (case, .exe)", "BASH.EXE -c '" + root + "'", policy.DecisionBlock, "ts-block-rm-root", ""},
		{"path to bash.exe", `& 'C:\Program Files\Git\bin\bash.exe' -c '` + root + "'", policy.DecisionBlock, "ts-block-rm-root", ""},
		{"pwsh -c reads its text as PowerShell", "pwsh -c \"bash -c '" + root + "'\"", policy.DecisionBlock, "ts-block-rm-root", ""},
		{"encoded PowerShell", psEncoded("bash -c '" + root + "'"), policy.DecisionBlock, "ts-block-rm-root", ""},
		{"encoded PowerShell with a parse error", psEncoded("Get-Date; @{ a = 1"), policy.DecisionAudit, "", string(facts.NoteParseError)},
		// No lane reads cmd's grammar (the note), but since Windows round 4
		// its command's words reach the native-command bridge, as the same
		// program written directly does.
		{"cmd /c: no lane, its command bridged", "cmd /c " + root, policy.DecisionBlock, "ts-block-rm-root", analyzer.NoteRoutingGap},
		{"wsl: no lane", "wsl " + root, policy.DecisionAudit, "", analyzer.NoteRoutingGap},
	}
	l := testPSLane(t, 2)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := l.read(c.cmd)
			if r.Decision != c.decision || (c.rule != "" && !containsStr(r.TriggeredRules, c.rule)) {
				t.Errorf("decision %s rules %v, want %s %s", r.Decision, r.TriggeredRules, c.decision, c.rule)
			}
			if c.note != "" && !hasNote(r.Notes, c.note) {
				t.Errorf("notes %+v, want a %s note", r.Notes, c.note)
			}
			if !hasNote(r.Notes, analyzer.NoteDialect) {
				t.Errorf("notes %+v lack the dialect note", r.Notes)
			}
		})
	}
}

// TestPSLane_DepthBound: with a bound of d, a nested text at depth d is read
// and one at depth d+1 is not, which is recorded and floored at AUDIT.
func TestPSLane_DepthBound(t *testing.T) {
	inner := "bash -c '" + routingDestructive() + "'" // depth 1 when it is the outer text's nested
	texts := map[int]string{
		1: inner,                       // the bash text is at depth 1
		2: psEncoded(inner),            // depth 2
		3: psEncoded(psEncoded(inner)), // depth 3
	}
	for bound := 1; bound <= 3; bound++ {
		l := testPSLane(t, bound)
		for depth := 1; depth <= 3; depth++ {
			r := l.read(texts[depth])
			read := depth <= bound
			switch {
			case read && (r.Decision != policy.DecisionBlock || hasNote(r.Notes, analyzer.NoteNestedDepthExceeded)):
				t.Errorf("bound %d, bash at depth %d: decision %s notes %+v; want it read (BLOCK, no %s note)", bound, depth, r.Decision, r.Notes, analyzer.NoteNestedDepthExceeded)
			case !read && (r.Decision != policy.DecisionAudit || !hasNote(r.Notes, analyzer.NoteNestedDepthExceeded)):
				t.Errorf("bound %d, bash at depth %d: decision %s notes %+v; want it unread (AUDIT with a %s note)", bound, depth, r.Decision, r.Notes, analyzer.NoteNestedDepthExceeded)
			}
		}
	}
}

// TestPSLane_NestedTieKeepsTheOuterRecord: when the call's own text and a
// nested text decide alike, the receipt is the call's own (its rule and
// node), as the row combiner keeps the earlier lane's.
func TestPSLane_NestedTieKeepsTheOuterRecord(t *testing.T) {
	l := testPSLane(t, 2)
	l.engine = mustEngineWithProtectedSSH(t)
	r := l.read("Get-Content " + sshKeyPath() + "; bash -c '" + routingDestructive() + "'")
	if r.Decision != policy.DecisionBlock || len(r.TriggeredRules) == 0 || r.TriggeredRules[0] != policy.ProtectedPathRuleID {
		t.Errorf("decision %s rules %v; want the outer text's %s record", r.Decision, r.TriggeredRules, policy.ProtectedPathRuleID)
	}

	// A nested reading that loses still says what it could not read.
	r = l.read("Get-Content " + sshKeyPath() + "; " + psEncoded("Get-Date; @{ a = 1"))
	if r.Decision != policy.DecisionBlock || !hasNote(r.Notes, string(facts.NoteParseError)) {
		t.Errorf("decision %s notes %+v; want the outer BLOCK carrying the nested text's %s note", r.Decision, r.Notes, facts.NoteParseError)
	}
}

func mustEngineWithProtectedSSH(t *testing.T) *policy.Engine {
	t.Helper()
	pol := &policy.Policy{Version: "0.1", Defaults: policy.Defaults{Decision: policy.DecisionAllow, ProtectedPaths: []string{"~/.ssh/**"}}}
	pol, _, err := policy.LoadEmbeddedShellPacks(pol)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := assembly.ShellEngine(pol, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

// TestPowerShellLane_PanicTakesTheFailSafeReading: a panic in the lane (a new
// parser on the hook path) is a lane failure (ADR-001 D9): BLOCK under managed
// fail_closed, AUDIT otherwise, never a crash and never a silent pass. The
// reading writes nothing until the combiner keeps it.
func TestPowerShellLane_PanicTakesTheFailSafeReading(t *testing.T) {
	prev := psRead
	psRead = func(string, psreader.Env) facts.Facts { panic("reader exploded") }
	t.Cleanup(func() { psRead = prev })

	for _, c := range []struct {
		name    string
		managed bool
		want    policy.Decision
		rule    string
	}{
		{"unmanaged", false, policy.DecisionAudit, evalErrorRuleID},
		{"managed fail_closed", true, policy.DecisionBlock, failClosedRuleID},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, configDir := newFailSafeHome(t, c.managed, failSafePolicyGood)
			r := readPowerShell(psBenign, t.TempDir(), "claude-code-hook", "s", nil)
			defer r.release()
			if r.result.Decision != c.want || !containsStr(r.result.TriggeredRules, c.rule) {
				t.Fatalf("decision %s rules %v, want %s by %s", r.result.Decision, r.result.TriggeredRules, c.want, c.rule)
			}
			if !strings.Contains(r.event.Error, "panicked") {
				t.Errorf("event error %q, want the panic named", r.event.Error)
			}
			if n := len(loggedEvents(t, configDir)); n != 0 {
				t.Errorf("the reading wrote %d line(s) before the combiner kept it", n)
			}
		})
	}

	// In a row, the failed reading is combined like any other: unmanaged, its
	// AUDIT ties and MCP policy keeps the record, with the failure named.
	t.Run("in the Claude Code PowerShell row", func(t *testing.T) {
		_, configDir := newFailSafeHome(t, false, failSafePolicyGood)
		payload := psCall(t, psBenign)
		input, raw := parseHookPayload(t, payload)
		call := preToolUseCall(route.ClaudeCode, input)
		if err := combineLanes(route.Route(call), call, input, raw.ToolInput, "claude-code-hook"); err != nil {
			t.Fatal(err)
		}
		e := oneEvent(t, configDir)
		n := laneReadingsNotes(e.Notes)
		if e.ToolName != "PowerShell" || len(n) != 1 || !strings.Contains(n[0], "powershell=AUDIT("+evalErrorRuleID+")") {
			t.Errorf("event tool=%q %s=%q; want MCP policy's record with the lane's fail-safe reading named", e.ToolName, analyzer.NoteLaneReadings, n)
		}
	})
}

func parseHookPayload(t *testing.T, payload string) (hookInput, rawHookInput) {
	t.Helper()
	var input hookInput
	var raw rawHookInput
	if err := json.Unmarshal([]byte(payload), &input); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal([]byte(payload), &raw)
	return input, raw
}

// TestProcessEnvVars: names fold to upper case, an upper-case spelling wins a
// collision whatever the order, and entries with no name are skipped.
func TestProcessEnvVars(t *testing.T) {
	got := processEnvVars([]string{"Path=a", "PATH=b", "home=c", "=C:=C:\\x", "USERPROFILE=C:\\Users\\a", "noequals", "userprofile=z", "E="})
	want := map[string]string{"PATH": "b", "HOME": "c", "USERPROFILE": `C:\Users\a`, "E": ""}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
}

// TestPowerShellLane_ResolvesTheProcessEnvironment: a variable the harness
// set resolves, so a key read spelled through it is seen.
func TestPowerShellLane_ResolvesTheProcessEnvironment(t *testing.T) {
	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	cmd := "Get-Content $env:ZQ_KEYS" + `\id_` + "rsa"
	keys := filepath.Join(home, ".ssh")
	if code, _, stderr := runHookChild(t, home, psCall(t, cmd), "ZQ_KEYS="+keys); code != 2 {
		t.Fatalf("exit %d, want 2: the variable's value is the ssh directory. stderr:\n%s", code, stderr)
	}
	if e := oneEvent(t, configDir); !containsStr(e.TriggeredRules, policy.ProtectedPathRuleID) {
		t.Errorf("rules %v, want %s", e.TriggeredRules, policy.ProtectedPathRuleID)
	}
	// Control: unset, the reference names nothing.
	home, _ = newFailSafeHome(t, false, failSafePolicyGood)
	if code, _, stderr := runHookChild(t, home, psCall(t, cmd)); code != 0 {
		t.Fatalf("control: exit %d with the variable unset, want 0. stderr:\n%s", code, stderr)
	}
}

// TestPowerShellLane_ProseNamingAProtectedPathIsAMention: a commit message
// that mentions a protected file names it inside a longer value, so the
// PowerShell lane records it (AUDIT, path_mention naming the pattern) and does
// not BLOCK (Kai, 2026-11-03: Paths are whole values, Mentions are recorded).
// It was the lane's pinned false positive before; the bash pipeline decides
// AUDIT on the same text.
func TestPowerShellLane_ProseNamingAProtectedPathIsAMention(t *testing.T) {
	cmd := `git commit -m "docs: explain how ~/.ssh/` + `config is parsed"`
	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	if code, _, stderr := runHookChild(t, home, claudeShaped(t, "PreToolUse", "Bash", routingCmd(cmd), nil)); code != 0 {
		t.Fatalf("control: the bash pipeline exits %d on the commit message, want 0. stderr:\n%s", code, stderr)
	}
	if e := oneEvent(t, configDir); e.Decision == "BLOCK" {
		t.Fatalf("control: the bash pipeline BLOCKs the commit message (%v)", e.TriggeredRules)
	}
	for name, p := range map[string]string{
		"claude-code PowerShell":    psCall(t, cmd),
		"copilot native powershell": copilotNativePayload(t, "fp", "powershell", shellArgs(cmd)),
	} {
		home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
		if code, _, stderr := runHookChild(t, home, p); code != 0 {
			t.Errorf("%s: exit %d, want 0 (a mention is not blocked). stderr:\n%s", name, code, stderr)
			continue
		}
		e := oneEvent(t, configDir)
		if n := laneReadingsNotes(e.Notes); e.Decision != "AUDIT" || len(n) != 1 || !strings.Contains(n[0], "powershell=AUDIT") {
			t.Errorf("%s: decision %s, %s %q; want AUDIT with the PowerShell lane's AUDIT", name, e.Decision, analyzer.NoteLaneReadings, n)
		}
	}
	// The lane's own reading carries the note naming the pattern. (On a tie
	// the row keeps the earlier lane's record, so the receipt may not.)
	newFailSafeHome(t, false, failSafePolicyGood)
	r := readPowerShell(cmd, t.TempDir(), "claude-code-hook", "s", nil)
	defer r.release()
	var detail string
	for _, n := range r.event.Notes {
		if n.Kind == analyzer.NotePathMention {
			detail = n.Detail
		}
	}
	if r.result.Decision != "AUDIT" || detail != "~/.ssh/**" {
		t.Errorf("lane reading %s with path_mention %q, want AUDIT naming ~/.ssh/**", r.result.Decision, detail)
	}
}

// TestPowerShellLane_InvokeExpressionIsReadAsPowerShell: Invoke-Expression
// runs its string as PowerShell, so the reader hands it back to the router as
// nested PowerShell text, where a key read inside it BLOCKs as the plain read
// does. Outside the nested reading the key is only a mention.
func TestPowerShellLane_InvokeExpressionIsReadAsPowerShell(t *testing.T) {
	inner := "Get-Content " + sshKeyPath()
	for _, cmd := range []string{"iex '" + inner + "'", "Invoke-Expression -Command \"" + inner + "\""} {
		home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
		if code, _, stderr := runHookChild(t, home, psCall(t, cmd)); code != 2 {
			t.Fatalf("%q: exit %d, want 2. stderr:\n%s", cmd, code, stderr)
		}
		e := oneEvent(t, configDir)
		if !containsStr(e.TriggeredRules, policy.ProtectedPathRuleID) || !containsStr(e.TaxonomyRefs, sshKeyReadNode) {
			t.Errorf("%q: rules %v taxonomy %v, want %s with the ssh node", cmd, e.TriggeredRules, e.TaxonomyRefs, policy.ProtectedPathRuleID)
		}
	}
}

// psCallIn is psCall with the payload's working directory.
func psCallIn(t *testing.T, cmd, cwd string) string {
	return claudeShaped(t, "PreToolUse", "PowerShell", routingCmd(cmd), map[string]interface{}{"cwd": cwd})
}

// TestPowerShellLane_BareCredentialNameInsideAProtectedDir (Codex pass 1 on
// #4245, finding 1): a bare file name is a path relative to the payload's
// working directory, so reading the key by its bare name from inside ~/.ssh
// BLOCKs, quoted or not, as the bash read of the same file does. The same
// names from any other directory are unchanged (MCP policy's AUDIT): a bare
// word can match only where cwd is inside a protected directory.
func TestPowerShellLane_BareCredentialNameInsideAProtectedDir(t *testing.T) {
	key := "id_" + "rsa"
	names := []string{"Get-Content " + key, "Get-Content '" + key + "'", "type " + key}
	setup := func(t *testing.T) (home, configDir, sshDir, projDir string) {
		home, configDir = newFailSafeHome(t, false, failSafePolicyGood)
		sshDir, projDir = filepath.Join(home, ".ssh"), filepath.Join(home, "proj")
		for _, d := range []string{sshDir, projDir} {
			if err := os.MkdirAll(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		// The file exists, as a real key would; bash's bare-operand reading
		// needs it (the control), the PowerShell lane does not.
		if err := os.WriteFile(filepath.Join(sshDir, key), []byte("not a key"), 0o600); err != nil {
			t.Fatal(err)
		}
		return home, configDir, sshDir, projDir
	}

	t.Run("control: the bash read from inside ~/.ssh blocks", func(t *testing.T) {
		home, configDir, sshDir, _ := setup(t)
		bash := claudeShaped(t, "PreToolUse", "Bash", routingCmd("cat "+key), map[string]interface{}{"cwd": sshDir})
		if code, _, stderr := runHookChild(t, home, bash); code != 2 {
			t.Fatalf("exit %d, want 2. stderr:\n%s", code, stderr)
		}
		if e := oneEvent(t, configDir); !containsStr(e.TriggeredRules, policy.ProtectedPathRuleID) {
			t.Fatalf("rules %v, want %s", e.TriggeredRules, policy.ProtectedPathRuleID)
		}
	})
	for _, cmd := range names {
		t.Run(cmd+" from inside ~/.ssh", func(t *testing.T) {
			home, configDir, sshDir, _ := setup(t)
			if code, _, stderr := runHookChild(t, home, psCallIn(t, cmd, sshDir)); code != 2 {
				t.Fatalf("exit %d, want 2. stderr:\n%s", code, stderr)
			}
			e := oneEvent(t, configDir)
			if !containsStr(e.TriggeredRules, policy.ProtectedPathRuleID) || !containsStr(e.TaxonomyRefs, sshKeyReadNode) {
				t.Errorf("rules %v taxonomy %v, want %s with the ssh node", e.TriggeredRules, e.TaxonomyRefs, policy.ProtectedPathRuleID)
			}
		})
		t.Run(cmd+" from elsewhere", func(t *testing.T) {
			home, configDir, _, projDir := setup(t)
			if code, _, stderr := runHookChild(t, home, psCallIn(t, cmd, projDir)); code != 0 {
				t.Fatalf("exit %d, want 0 (unchanged). stderr:\n%s", code, stderr)
			}
			if e := oneEvent(t, configDir); e.Decision != "AUDIT" || e.ToolName != "PowerShell" {
				t.Errorf("decision %s tool %q, want MCP policy's AUDIT record as on main", e.Decision, e.ToolName)
			}
		})
	}
}

// TestPowerShellLane_FileSystemProviderQualifiedRead (Codex pass 1 on #4245,
// finding 2): a FileSystem provider qualifier, short or module-qualified and
// in any case, names the file after it, so the read BLOCKs on Claude Code's
// default PowerShell route. A Registry:: path names no file and does not.
func TestPowerShellLane_FileSystemProviderQualifiedRead(t *testing.T) {
	tail := `$env:USERPROFILE\.ssh\id_` + "rsa"
	for _, prefix := range []string{"FileSystem::", "filesystem::", `Microsoft.PowerShell.Core\FileSystem::`, `MICROSOFT.POWERSHELL.CORE\FILESYSTEM::`} {
		cmd := "Get-Content " + prefix + tail
		home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
		if code, _, stderr := runHookChild(t, home, psCall(t, cmd)); code != 2 {
			t.Fatalf("%q: exit %d, want 2. stderr:\n%s", cmd, code, stderr)
		}
		if e := oneEvent(t, configDir); !containsStr(e.TriggeredRules, policy.ProtectedPathRuleID) || !containsStr(e.TaxonomyRefs, sshKeyReadNode) {
			t.Errorf("%q: rules %v taxonomy %v, want %s with the ssh node", cmd, e.TriggeredRules, e.TaxonomyRefs, policy.ProtectedPathRuleID)
		}
	}
	cmd := "Get-Item Registry::" + tail
	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	if code, _, stderr := runHookChild(t, home, psCall(t, cmd)); code != 0 {
		t.Fatalf("control %q: exit %d, want 0 (a registry path names no file). stderr:\n%s", cmd, code, stderr)
	}
	if e := oneEvent(t, configDir); e.Decision == "BLOCK" {
		t.Errorf("control %q: BLOCK %v", cmd, e.TriggeredRules)
	}
}

// TestPowerShellLane_ManagedRedirectionOntoABareConfigName (Codex pass 2 on
// #4245): with cwd inside AgentShield's config directory on a managed host, a
// redirection or a write cmdlet onto a bare `policy.yaml` names the config
// file, so self-protection BLOCKs it. A redirect to $null or NUL writes no
// file. The same writes on an unmanaged host are unchanged (MCP policy's
// AUDIT, as on main).
func TestPowerShellLane_ManagedRedirectionOntoABareConfigName(t *testing.T) {
	target := "policy" + ".yaml"
	writes := []string{
		"Get-Date > " + target,
		"Get-Date >> " + target,
		"Get-Date 2> " + target,
		"Get-Date | Out-File " + target,
		"Set-Content " + target + " x",
		"Add-Content -Path " + target + " -Value x",
		"Get-Date | Tee-Object -FilePath " + target,
	}
	for _, cmd := range writes {
		t.Run("managed: "+cmd, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
			if code, _, stderr := runHookChild(t, home, psCallIn(t, cmd, configDir)); code != 2 {
				t.Fatalf("exit %d, want 2 (self-protection). stderr:\n%s", code, stderr)
			}
			if e := oneEvent(t, configDir); !containsStr(e.TriggeredRules, "enterprise-self-protect") {
				t.Errorf("rules %v, want enterprise-self-protect", e.TriggeredRules)
			}
		})
	}
	for _, cmd := range []string{"Get-Date > $null", "Get-Date > NUL", "Get-Date"} {
		t.Run("managed, no file: "+cmd, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
			if code, _, stderr := runHookChild(t, home, psCallIn(t, cmd, configDir)); code != 0 {
				t.Fatalf("exit %d, want 0. stderr:\n%s", code, stderr)
			}
		})
	}
	for _, cmd := range writes[:2] {
		t.Run("unmanaged: "+cmd, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
			if code, _, stderr := runHookChild(t, home, psCallIn(t, cmd, configDir)); code != 0 {
				t.Fatalf("exit %d, want 0 (unchanged). stderr:\n%s", code, stderr)
			}
			if e := oneEvent(t, configDir); e.Decision != "AUDIT" || e.ToolName != "PowerShell" {
				t.Errorf("decision %s tool %q, want MCP policy's AUDIT record as on main", e.Decision, e.ToolName)
			}
		})
	}
}

// TestPowerShellLane_RedirectionOntoABareCredentialName: a redirection onto a
// bare credential file name from inside ~/.ssh writes the key file, so it
// BLOCKs as protected-path, like a bare read does.
func TestPowerShellLane_RedirectionOntoABareCredentialName(t *testing.T) {
	key := "id_" + "rsa"
	for _, cmd := range []string{"Get-Date > " + key, "Get-Date >> '" + key + "'"} {
		home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
		sshDir := filepath.Join(home, ".ssh")
		if err := os.MkdirAll(sshDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if code, _, stderr := runHookChild(t, home, psCallIn(t, cmd, sshDir)); code != 2 {
			t.Fatalf("%q: exit %d, want 2. stderr:\n%s", cmd, code, stderr)
		}
		if e := oneEvent(t, configDir); !containsStr(e.TriggeredRules, policy.ProtectedPathRuleID) {
			t.Errorf("%q: rules %v, want %s", cmd, e.TriggeredRules, policy.ProtectedPathRuleID)
		}
	}
}

// TestPowerShellLane_TrailingSpaceOrDotReadsTheFile (Opus pass 1 on #4245,
// confirmed on Windows 10): `Get-Content "<file> "` and `"<file>."` open
// <file>, so the read BLOCKs as protected-path with the taxonomy a bash read
// of <file> gets.
func TestPowerShellLane_TrailingSpaceOrDotReadsTheFile(t *testing.T) {
	cases := []struct{ name, bash, ps string }{
		{".git-credentials with a trailing space", "cat ~/.git-" + "credentials", `Get-Content "$env:USERPROFILE\.git-` + `credentials "`},
		{".netrc with a trailing dot", "cat ~/.ne" + "trc", `Get-Content "$env:USERPROFILE\.ne` + `trc."`},
		{"ssh key with a trailing dot and space", "cat " + sshKeyPath(), `Get-Content "$env:USERPROFILE\.ssh\id_` + `rsa. "`},
		{"ssh key with two trailing spaces", "cat " + sshKeyPath(), `Get-Content -LiteralPath "$env:USERPROFILE\.ssh\id_` + `rsa  "`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
			if code, _, stderr := runHookChild(t, home, claudeShaped(t, "PreToolUse", "Bash", routingCmd(c.bash), nil)); code != 2 {
				t.Fatalf("control: the bash read exits %d, want 2. stderr:\n%s", code, stderr)
			}
			bash := oneEvent(t, configDir)
			home, configDir = newFailSafeHome(t, false, failSafePolicyGood)
			if code, _, stderr := runHookChild(t, home, psCall(t, c.ps)); code != 2 {
				t.Fatalf("exit %d, want 2. stderr:\n%s", code, stderr)
			}
			ps := oneEvent(t, configDir)
			if !containsStr(ps.TriggeredRules, policy.ProtectedPathRuleID) {
				t.Fatalf("rules %v, want %s", ps.TriggeredRules, policy.ProtectedPathRuleID)
			}
			b, p := slices.Clone(bash.TaxonomyRefs), slices.Clone(ps.TaxonomyRefs)
			slices.Sort(b)
			slices.Sort(p)
			if len(p) == 0 || !slices.Equal(b, p) {
				t.Errorf("taxonomy: bash %v, PowerShell %v; want the same node(s)", b, p)
			}
		})
	}
}

// driveHome is a hook home spelled as a Windows profile, C:/Users/alice,
// made under a temporary directory the child runs in: on this host that
// spelling is a relative path, so `\\?\C:\Users\alice\…` names the home as
// it does on Windows. Not on Windows, where it would be the real C: drive.
func driveHome(t *testing.T, managed bool) (dir, home, configDir string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("C:/Users/alice is a real path on Windows")
	}
	newFailSafeHome(t, managed, failSafePolicyGood) // resets the hook's globals
	dir = t.TempDir()
	home = "C:/Users/alice"
	configDir = filepath.Join(dir, home, ".agent"+"shield")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "policy.yaml"), []byte(failSafePolicyGood), 0o600); err != nil {
		t.Fatal(err)
	}
	if managed {
		if err := os.WriteFile(filepath.Join(configDir, "managed.json"), []byte(`{"managed": true, "fail_closed": true}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, home, configDir
}

// TestPowerShellLane_Win32NamespacePrefix (Opus pass 2 on #4245, F2): a
// `\\?\` or `\\.\` prefix names the same file, so each prefixed spelling
// decides as its unprefixed control does, with the same rule, on Claude
// Code's and Copilot's PowerShell rows, unmanaged and managed. Before, every
// prefixed row decided AUDIT.
func TestPowerShellLane_Win32NamespacePrefix(t *testing.T) {
	win := `C:\Users\alice`
	key := `\.ssh\id_` + "rsa"
	cfg := `\.agent` + "shield"
	type row struct {
		name, control string
		prefixed      []string
		rule          string
		managedOnly   bool
	}
	rows := []row{
		{"key read", "Get-Content '" + win + key + "'", []string{
			`Get-Content '\\?\` + win + key + "'",
			`Get-Content '\\.\` + win + key + "'",
			`Get-Content "\\?\$env:USERPROFILE` + key + `"`,
		}, policy.ProtectedPathRuleID, false},
		{"config dir removed", "Remove-Item -LiteralPath '" + win + cfg + "'", []string{
			`Remove-Item -LiteralPath '\\?\` + win + cfg + "'",
		}, "enterprise-self-protect", true},
		{"policy written", "Set-Content -LiteralPath '" + win + cfg + `\policy.yaml' x`, []string{
			`Set-Content -LiteralPath '\\?\` + win + cfg + `\policy.yaml' x`,
		}, "enterprise-self-protect", true},
	}
	payloads := map[string]func(string) string{
		"claude-code PowerShell": func(c string) string { return psCall(t, c) },
		"copilot native powershell": func(c string) string {
			return copilotNativePayload(t, "ns", "powershell", shellArgs(c))
		},
	}
	decide := func(t *testing.T, managed bool, payload string) (int, []string) {
		t.Helper()
		dir, home, configDir := driveHome(t, managed)
		code, _, stderr := runHookChildIn(t, dir, home, payload)
		if code != 0 && code != 2 {
			t.Fatalf("exit %d. stderr:\n%s", code, stderr)
		}
		return code, oneEvent(t, configDir).TriggeredRules
	}
	for _, r := range rows {
		for _, managed := range []bool{false, true} {
			for rowName, payload := range payloads {
				name := fmt.Sprintf("%s, %s, managed=%v", r.name, rowName, managed)
				t.Run(name, func(t *testing.T) {
					code, rules := decide(t, managed, payload(r.control))
					wantBlock := managed || !r.managedOnly
					if wantBlock && (code != 2 || !containsStr(rules, r.rule)) {
						t.Fatalf("control: exit %d rules %v, want BLOCK by %s", code, rules, r.rule)
					}
					if !wantBlock && code != 0 {
						t.Fatalf("control: exit %d rules %v, want 0 unmanaged", code, rules)
					}
					for _, p := range r.prefixed {
						pc, pr := decide(t, managed, payload(p))
						if pc != code || wantBlock && !containsStr(pr, r.rule) {
							t.Errorf("%s: exit %d rules %v; the control exits %d by %v", p, pc, pr, code, rules)
						}
					}
				})
			}
		}
	}
}

// TestPowerShellLane_CmdLauncherReentersTheLane (Opus pass 1 on #4245): cmd /c
// running powershell, pwsh, bash or sh is the standard Windows launcher, so
// cmd's text goes back to that interpreter's lane, one nesting level. A cmd
// line that starts anything else keeps its routing_gap reading.
func TestPowerShellLane_CmdLauncherReentersTheLane(t *testing.T) {
	keyRead := "Get-Content " + sshKeyPath()
	enc := strings.TrimPrefix(psEncoded(keyRead), "powershell ")
	cases := []struct {
		name, cmd string
		exit      int
	}{
		{"cmd /c powershell -EncodedCommand", "cmd /c powershell " + enc, 2},
		{"cmd /c \"powershell -EncodedCommand\"", "cmd /c \"powershell " + enc + "\"", 2},
		{"cmd.exe /c pwsh.exe -EncodedCommand", "cmd.exe /c pwsh.exe " + enc, 2},
		{"cmd /c \"pwsh -c\"", "cmd /c \"pwsh -c " + keyRead + "\"", 2},
		{"cmd /c dir (unchanged)", "cmd /c dir", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
			code, _, stderr := runHookChild(t, home, psCall(t, c.cmd))
			if code != c.exit {
				t.Fatalf("exit %d, want %d. stderr:\n%s", code, c.exit, stderr)
			}
			e := oneEvent(t, configDir)
			if c.exit == 2 && !containsStr(e.TriggeredRules, policy.ProtectedPathRuleID) {
				t.Errorf("rules %v, want %s", e.TriggeredRules, policy.ProtectedPathRuleID)
			}
			if c.exit == 0 && e.Decision != "AUDIT" {
				t.Errorf("decision %s, want AUDIT as before", e.Decision)
			}
		})
	}
}

// TestPowerShellLane_CmdJoinedSwitches (Opus pass 2 on #4245, S1, run on
// Windows): cmd takes its switches joined, so `cmd /d/c <launcher>` re-enters
// the lane as `cmd /d /c` does. `cmd /c/d …` runs nothing and keeps its
// decision.
func TestPowerShellLane_CmdJoinedSwitches(t *testing.T) {
	enc := strings.TrimPrefix(psEncoded("Get-Content "+sshKeyPath()), "powershell ")
	cases := []struct {
		name, cmd string
		exit      int
	}{
		{"control: cmd /d /c", "cmd /d /c powershell " + enc, 2},
		{"cmd /d/c", "cmd /d/c powershell " + enc, 2},
		{"cmd /s/c, quoted", "cmd /s/c \"powershell " + enc + "\"", 2},
		{"cmd /d/s/c", "cmd /d/s/c powershell " + enc, 2},
		{"cmd /q/d/c", "cmd /q/d/c powershell " + enc, 2},
		{"cmd /D/K", "cmd /D/K powershell " + enc, 2},
		{"cmd /c/d keeps its decision", "cmd /c/d powershell " + enc, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
			code, _, stderr := runHookChild(t, home, psCall(t, c.cmd))
			if code != c.exit {
				t.Fatalf("exit %d, want %d. stderr:\n%s", code, c.exit, stderr)
			}
			e := oneEvent(t, configDir)
			if c.exit == 2 && !containsStr(e.TriggeredRules, policy.ProtectedPathRuleID) {
				t.Errorf("rules %v, want %s", e.TriggeredRules, policy.ProtectedPathRuleID)
			}
			if c.exit == 0 && e.Decision != "AUDIT" {
				t.Errorf("decision %s, want AUDIT as before", e.Decision)
			}
		})
	}
}

// TestPSLane_CmdHopIsOneNestingLevel: cmd's text is read at the next depth,
// so with a bound of 1 an encoded command behind cmd is past the bound
// (AUDIT, nested_depth_exceeded) and with 2 it is read (BLOCK). bash and sh
// behind cmd go to the POSIX lane; cmd behind cmd has no lane.
func TestPSLane_CmdHopIsOneNestingLevel(t *testing.T) {
	keyRead := "Get-Content " + sshKeyPath()
	text := "cmd /c " + psEncoded(keyRead)
	for bound, want := range map[int]policy.Decision{1: policy.DecisionAudit, 2: policy.DecisionBlock} {
		l := testPSLane(t, bound)
		l.engine = mustEngineWithProtectedSSH(t)
		r := l.read(text)
		if r.Decision != want {
			t.Errorf("bound %d: %s rules %v notes %+v, want %s", bound, r.Decision, r.TriggeredRules, r.Notes, want)
		}
		if bound == 1 && !hasNote(r.Notes, analyzer.NoteNestedDepthExceeded) {
			t.Errorf("bound 1: notes %+v, want %s", r.Notes, analyzer.NoteNestedDepthExceeded)
		}
	}
	l := testPSLane(t, 2)
	for text, want := range map[string]policy.Decision{
		"cmd /c bash -c '" + routingDestructive() + "'": policy.DecisionBlock,
		"cmd /c sh -c '" + routingDestructive() + "'":   policy.DecisionBlock,
		"cmd /c cmd /c " + routingDestructive():         policy.DecisionAudit, // no lane: routing_gap
	} {
		if r := l.read(text); r.Decision != want {
			t.Errorf("%q: %s rules %v, want %s", text, r.Decision, r.TriggeredRules, want)
		}
	}
}

// TestPowerShellLane_HookReadsEveryNestedText (#4766 Opus pass 1, F2): the
// hook's PowerShell lane, built as production builds it
// (powershellEvaluation), sets no bound on nested sh texts, as on main: a
// destructive `bash -c` after 1100 distinct nested texts is still read and
// BLOCKs. shield-server bounds them for its clients' 5 s timeout
// (assembly.ServerNestedPOSIXBound); the hook's budget is the harness's
// hook timeout.
func TestPowerShellLane_HookReadsEveryNestedText(t *testing.T) {
	l := testPSLane(t, 2)
	var b strings.Builder
	for i := 0; i < 1100; i++ {
		fmt.Fprintf(&b, "sh -c a%d; ", i)
	}
	b.WriteString("bash -c '" + routingDestructive() + "'")

	r, err := powershellEvaluation("claude-code-hook").evaluate(l.engine, nil, b.String(), l.cwd)
	if err != nil {
		t.Fatal(err)
	}
	if r.Decision != policy.DecisionBlock {
		t.Errorf("decision %s rules %v notes %+v; want the 1101st nested text's BLOCK", r.Decision, r.TriggeredRules, r.Notes)
	}
	for _, n := range r.Notes {
		if strings.Contains(n.Detail, "distinct nested bash/sh texts") {
			t.Errorf("the hook bounded nested texts: %+v", n)
		}
	}
}
