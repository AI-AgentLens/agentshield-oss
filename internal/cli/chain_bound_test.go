package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/assembly"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// The chain bound on the hook, the PowerShell lane's nested readings and
// `agentshield check` (#4778, Gary 2026-11-04: "AUDIT"). Every HOME here is a
// throwaway with no credentials, except captureAuditPOSTs', which points at a
// local test server. Texts are generated, never fixtures; the destructive
// stage is assembled at runtime (the hook reads test sources as commands).

// pipeOf is n stages of `a` joined by `|`: n-1 chain operators.
func pipeOf(n int) string { return strings.Repeat("a|", n-1) + "a" }

// oneMiBPipe is #4778's reproduction: 524 288 stages, 1023 KiB. On main the
// hook died on it with exit 2, a Go stack trace and no audit record.
func oneMiBPipe() string { return pipeOf(524288) }

// derivedChainCommand is a command under the bound whose nested shell text,
// once X is substituted, is past it: 40 copies of X. On main the 10 000-stage
// version (20 KiB) overflowed the stack in buildExecSymbols at depth 1.
func derivedChainCommand() string {
	x := pipeOf(shellparse.MaxChainOperators/40 + 100)
	return "X='" + x + "'; bash -c \"" + strings.Repeat("$X|", 39) + "$X\""
}

func chainNotes(ns []analyzer.Note) int {
	n := 0
	for _, x := range ns {
		if x.Kind == analyzer.NoteChainTooLong {
			n++
		}
	}
	return n
}

// TestHook_ChainPastTheBound_AuditsWithOneReceipt: the 1 MiB pipeline through
// the real hook entry point, on a normal install, is AUDIT
// agentshield-eval-error with a chain_too_long note, on exactly one local
// line and one upload, and the process does not crash.
func TestHook_ChainPastTheBound_AuditsWithOneReceipt(t *testing.T) {
	home, configDir := newFailSafeHome(t, false, "")
	posted := captureAuditPOSTs(t)
	code, _, stderr := runHookChild(t, home, claudeShaped(t, "PreToolUse", "Bash", routingCmd(oneMiBPipe()), nil))
	if strings.Contains(stderr, "stack exceeds") || strings.Contains(stderr, "goroutine ") {
		t.Fatalf("the hook crashed:\n%.600s", stderr)
	}
	if code != 0 {
		t.Fatalf("exit %d, want 0 (AUDIT). stderr:\n%.600s", code, stderr)
	}
	e := oneEvent(t, configDir)
	if e.Decision != "AUDIT" || !slices.Equal(e.TriggeredRules, []string{evalErrorRuleID}) {
		t.Errorf("event decision=%s rules=%v; want AUDIT [%s]", e.Decision, e.TriggeredRules, evalErrorRuleID)
	}
	if countKind(e.Notes, analyzer.NoteChainTooLong) != 1 {
		t.Errorf("notes %v; want one %s", noteKinds(e.Notes), analyzer.NoteChainTooLong)
	}
	if !strings.Contains(e.Error, "chain operators") || !e.Flagged {
		t.Errorf("event error=%q flagged=%v; want the bound's error on a flagged event", e.Error, e.Flagged)
	}
	sent := posted()
	if len(sent) != 1 || countKind(sent[0], analyzer.NoteChainTooLong) != 1 {
		t.Errorf("uploads %d (notes %v); want one, carrying the note", len(sent), sent)
	}
}

// TestHook_ChainPastTheBound_BlocksUnderManagedFailClosed: the same call on a
// managed fail_closed host is the harness's deny: exit 2 with the reason on
// stderr, and the event is BLOCK enterprise-fail-closed with the note.
func TestHook_ChainPastTheBound_BlocksUnderManagedFailClosed(t *testing.T) {
	home, configDir := newFailSafeHome(t, true, "")
	code, _, stderr := runHookChild(t, home, claudeShaped(t, "PreToolUse", "Bash", routingCmd(oneMiBPipe()), nil))
	if code != 2 {
		t.Fatalf("exit %d, want 2 (BLOCK). stderr:\n%.600s", code, stderr)
	}
	if !strings.Contains(stderr, "fail_closed") || !strings.Contains(stderr, "chain operators") || strings.Contains(stderr, "goroutine ") {
		t.Errorf("stderr does not give the fail-closed reason (or shows a crash):\n%.600s", stderr)
	}
	e := oneEvent(t, configDir)
	if e.Decision != "BLOCK" || !slices.Equal(e.TriggeredRules, []string{failClosedRuleID}) || countKind(e.Notes, analyzer.NoteChainTooLong) != 1 {
		t.Errorf("event decision=%s rules=%v notes=%v; want BLOCK [%s] with one %s", e.Decision, e.TriggeredRules, noteKinds(e.Notes), failClosedRuleID, analyzer.NoteChainTooLong)
	}
}

// mainReading is main's evaluation of cmd on the hook's engine for this HOME:
// the POSIX pipeline with no bound (normalize, then the analyzers), which is
// what readShellShaped ran before #4778.
func mainReading(t *testing.T, cmd, cwd string) policy.EvalResult {
	t.Helper()
	ce, err := newCheckEngine("")
	if err != nil {
		t.Fatal(err)
	}
	normalized := normalize.NormalizeCommand(cmd, cwd)
	return ce.engine.EvaluateWithParsedCwd(cmd, normalized.Paths, normalized.Parsed, cwd)
}

// TestHook_ChainAtTheBound_DecidesAsMain: a command with exactly
// MaxChainOperators operators, whose first stage is destructive, decides as
// main's unbounded pipeline does (BLOCK, the same rules, no note); one
// operator more is the fail-safe AUDIT. The boundary, both sides.
func TestHook_ChainAtTheBound_DecidesAsMain(t *testing.T) {
	_, configDir := newFailSafeHome(t, false, "")
	at := routingDestructive() + strings.Repeat("|a", shellparse.MaxChainOperators)
	if n := shellparse.ChainOperators(at); n != shellparse.MaxChainOperators {
		t.Fatalf("control: %d operators, want %d", n, shellparse.MaxChainOperators)
	}
	want := mainReading(t, at, "/tmp")
	if want.Decision != policy.DecisionBlock {
		t.Fatalf("control: main decides %s on the destructive pipeline, want BLOCK", want.Decision)
	}
	got, ev := evaluateCommand(at, "/tmp", "claude-code-hook", "chain-at")
	if got.Decision != want.Decision || !slices.Equal(got.TriggeredRules, want.TriggeredRules) || chainNotes(got.Notes) != 0 {
		t.Errorf("at the bound: %s %v notes %v; main %s %v", got.Decision, got.TriggeredRules, got.Notes, want.Decision, want.TriggeredRules)
	}
	if countKind(ev.Notes, analyzer.NoteChainTooLong) != 0 {
		t.Errorf("at the bound the event carries %v", noteKinds(ev.Notes))
	}

	past, ev := evaluateCommand(at+"|a", "/tmp", "claude-code-hook", "chain-past")
	if past.Decision != policy.DecisionAudit || !slices.Equal(past.TriggeredRules, []string{evalErrorRuleID}) || countKind(ev.Notes, analyzer.NoteChainTooLong) != 1 {
		t.Errorf("one past the bound: %s %v notes %v; want AUDIT [%s] with the note", past.Decision, past.TriggeredRules, noteKinds(ev.Notes), evalErrorRuleID)
	}
	if n := len(loggedEvents(t, configDir)); n != 2 {
		t.Errorf("%d audit lines, want 2 (one per call)", n)
	}
}

// TestHook_DerivedChainPastTheBound: a 26 KiB command whose nested shell text
// is past the bound once X is substituted. On main it crashed the hook; now
// it is the fail-safe decision, AUDIT, or BLOCK under managed fail_closed,
// with a note that names a derived text, on one event.
func TestHook_DerivedChainPastTheBound(t *testing.T) {
	cmd := derivedChainCommand()
	if n := shellparse.ChainOperators(cmd); n > shellparse.MaxChainOperators {
		t.Fatalf("control: the command itself has %d operators, past the bound", n)
	}
	for _, c := range []struct {
		managed bool
		want    policy.Decision
		rule    string
	}{{false, policy.DecisionAudit, evalErrorRuleID}, {true, policy.DecisionBlock, failClosedRuleID}} {
		_, configDir := newFailSafeHome(t, c.managed, "")
		r, ev := evaluateCommand(cmd, "/tmp", "claude-code-hook", "chain-derived")
		if r.Decision != c.want || !slices.Equal(r.TriggeredRules, []string{c.rule}) {
			t.Errorf("managed=%v: %s %v; want %s [%s]", c.managed, r.Decision, r.TriggeredRules, c.want, c.rule)
		}
		if countKind(ev.Notes, analyzer.NoteChainTooLong) != 1 {
			t.Fatalf("managed=%v: notes %v; want one %s", c.managed, noteKinds(ev.Notes), analyzer.NoteChainTooLong)
		}
		for _, n := range ev.Notes {
			if n.Kind == analyzer.NoteChainTooLong && !strings.Contains(n.Detail, "derived") {
				t.Errorf("managed=%v: note detail %q does not say the text was derived", c.managed, n.Detail)
			}
		}
		if n := len(loggedEvents(t, configDir)); n != 1 {
			t.Errorf("managed=%v: %d audit lines, want 1", c.managed, n)
		}
	}
}

// psNestedPastTheBound is a PowerShell call running bash on a pipeline past
// the bound: 80 KiB, under the reader's 128 KiB text bound, so the lane reads
// the nested text and hands it to POSIX.
func psNestedPastTheBound() string {
	return "bash -c '" + pipeOf(40000) + "'"
}

// TestPSLane_NestedChainPastTheBound: the PowerShell lane's nested POSIX
// reading of a text past the bound is the fail-safe decision with the note,
// which floors the call at AUDIT and is carried onto its record
// (assembly.UncertainNote), and BLOCK enterprise-fail-closed under managed
// fail_closed.
func TestPSLane_NestedChainPastTheBound(t *testing.T) {
	if !assembly.UncertainNote(analyzer.NoteChainTooLong) {
		t.Errorf("%s is not an uncertain note: a tie would drop it from the record", analyzer.NoteChainTooLong)
	}
	l := testPSLane(t, 2)
	texts := map[string]string{
		"own":     psNestedPastTheBound(),
		"derived": psNestedDerivedPastTheBound(),
	}
	for name, text := range texts {
		r := l.read(text)
		if r.Decision != policy.DecisionAudit || chainNotes(r.Notes) != 1 {
			t.Errorf("%s, unmanaged: %s %v notes %v; want AUDIT with one %s", name, r.Decision, r.TriggeredRules, r.Notes, analyzer.NoteChainTooLong)
		}
	}

	configDir := filepath.Join(os.Getenv("HOME"), ".agentshield")
	if err := os.WriteFile(filepath.Join(configDir, "managed.json"), []byte(`{"managed": true, "fail_closed": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, text := range texts {
		r := l.read(text)
		if r.Decision != policy.DecisionBlock || !slices.Contains(r.TriggeredRules, failClosedRuleID) || chainNotes(r.Notes) != 1 {
			t.Errorf("%s, managed fail_closed: %s %v notes %v; want BLOCK [%s] with the note", name, r.Decision, r.TriggeredRules, r.Notes, failClosedRuleID)
		}
	}
}

// psNestedDerivedPastTheBound is a PowerShell call whose nested bash text is
// under the bound but splices 40 copies of X into an eval: the text the POSIX
// reading derives from it is past the bound.
func psNestedDerivedPastTheBound() string {
	x := pipeOf(shellparse.MaxChainOperators/40 + 100)
	return `bash -c 'X="` + x + `"; eval ` + strings.Repeat("$X", 40) + `'`
}

// TestHook_PowerShellNestedChainPastTheBound_BlocksUnderManagedFailClosed is
// the same through the real hook, on Claude Code's PowerShell row: the deny
// (exit 2) on a managed fail_closed host. On main the nested text was read
// and the call exited 0.
func TestHook_PowerShellNestedChainPastTheBound_BlocksUnderManagedFailClosed(t *testing.T) {
	home, _ := newFailSafeHome(t, true, "")
	code, _, stderr := runHookChild(t, home, psCall(t, psNestedPastTheBound()))
	if code != 2 || !strings.Contains(stderr, failClosedRuleID) {
		t.Fatalf("exit %d, want 2 with %s on stderr:\n%.600s", code, failClosedRuleID, stderr)
	}
}

// TestCheck_ChainPastTheBound: `agentshield check` predicts the hook's
// fail-safe decision without parsing, for the call's own text and a derived
// one, instead of crashing.
func TestCheck_ChainPastTheBound(t *testing.T) {
	newFailSafeHome(t, false, "")
	for name, cmd := range map[string]string{"own": oneMiBPipe(), "derived": derivedChainCommand()} {
		r, err := evaluateShellCommand(cmd, "")
		if err != nil {
			t.Fatal(err)
		}
		if r.Decision != policy.DecisionAudit || !slices.Equal(r.TriggeredRules, []string{evalErrorRuleID}) || chainNotes(r.Notes) != 1 {
			t.Errorf("%s: %s %v notes %v; want AUDIT [%s] with one %s", name, r.Decision, r.TriggeredRules, r.Notes, evalErrorRuleID, analyzer.NoteChainTooLong)
		}
	}
}

// writeManagedNotFailClosed makes the HOME's host managed, without
// fail_closed.
func writeManagedNotFailClosed(t *testing.T, configDir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(configDir, "managed.json"), []byte(`{"managed": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

// spPastTheBound is a self-protection TP padded past the chain bound with
// harmless stages.
func spPastTheBound(tp string) string {
	return tp + strings.Repeat("|a", shellparse.MaxChainOperators+1)
}

// TestHook_SelfProtectPastTheBound_ManagedStillBlocks (#4778 fix round): on a
// managed host without fail_closed, a tamper command padded past the bound is
// still BLOCKed by the self-protection rules on its raw text, as main's
// middleware BLOCKed it, with main's rule in the reason and the note on the
// one event. Before the fix round it was AUDIT. A spelling only a parsing
// reading finds (a quote splice) is the residual: AUDIT, pinned.
func TestHook_SelfProtectPastTheBound_ManagedStillBlocks(t *testing.T) {
	as := "agent" + "shield"
	for _, c := range []struct{ tp, rule string }{
		{"rm -rf ~/." + as + "/", "sp-block-delete-config"},
		{"export AGENTSHIELD_" + "BYPASS=1", "sp-block-bypass-env"},
		{as + " setup claude-code --disable", "sp-block-setup-disable"},
	} {
		home, configDir := newFailSafeHome(t, false, "")
		writeManagedNotFailClosed(t, configDir)
		code, _, stderr := runHookChild(t, home, claudeShaped(t, "PreToolUse", "Bash", routingCmd(spPastTheBound(c.tp)), nil))
		if code != 2 || !strings.Contains(stderr, "enterprise-self-protect") || !strings.Contains(stderr, c.rule) {
			t.Errorf("%s: exit %d, want 2 naming enterprise-self-protect and %s:\n%.400s", c.rule, code, c.rule, stderr)
			continue
		}
		e := oneEvent(t, configDir)
		if e.Decision != "BLOCK" || !slices.Equal(e.TriggeredRules, []string{"enterprise-self-protect"}) || countKind(e.Notes, analyzer.NoteChainTooLong) != 1 {
			t.Errorf("%s: event %s %v notes %v; want BLOCK enterprise-self-protect with the note", c.rule, e.Decision, e.TriggeredRules, noteKinds(e.Notes))
		}
		// The receipt cites what main's record of the same command cites,
		// under the bound on the same managed host: rules, reasons and
		// taxonomy (#4823 Opus pass 1, M12/M18: nothing pinned the node).
		home2, configDir2 := newFailSafeHome(t, false, "")
		writeManagedNotFailClosed(t, configDir2)
		if code, _, _ := runHookChild(t, home2, claudeShaped(t, "PreToolUse", "Bash", routingCmd(c.tp), nil)); code != 2 {
			t.Fatalf("%s: control: under the bound exit %d, want 2", c.rule, code)
		}
		want := oneEvent(t, configDir2)
		wantRefs := want.TaxonomyRefs
		if c.rule == "sp-block-delete-config" {
			// Its node is the delete's target, which only a parse finds: past
			// the bound the text is not parsed, so the receipt attests nothing,
			// as main's does for a delete it cannot parse
			// (selfProtectTaxonomyRefsUnparsed). Under the bound it cites the
			// target's nodes; the control proves this row can tell.
			if len(want.TaxonomyRefs) == 0 {
				t.Fatalf("control: under the bound the delete cites no node")
			}
			wantRefs = nil
		}
		if !slices.Equal(e.TriggeredRules, want.TriggeredRules) || !slices.Equal(e.Reasons, want.Reasons) || !slices.Equal(e.TaxonomyRefs, wantRefs) {
			t.Errorf("%s: past the bound rules %v reasons %q taxonomy %v; want %v %q %v", c.rule, e.TriggeredRules, e.Reasons, e.TaxonomyRefs, want.TriggeredRules, want.Reasons, wantRefs)
		}
	}

	// Unmanaged, nothing changes: the raw self-protection reading is a
	// managed host's, as the middleware is.
	home, configDir := newFailSafeHome(t, false, "")
	if code, _, stderr := runHookChild(t, home, claudeShaped(t, "PreToolUse", "Bash", routingCmd(spPastTheBound("export AGENTSHIELD_"+"BYPASS=1")), nil)); code != 0 || strings.Contains(stderr, "enterprise-self-protect") {
		t.Errorf("unmanaged: exit %d, want 0 (AUDIT) with no self-protection:\n%.400s", code, stderr)
	}
	if e := oneEvent(t, configDir); !slices.Equal(e.TriggeredRules, []string{evalErrorRuleID}) {
		t.Errorf("unmanaged: rules %v, want [%s]", e.TriggeredRules, evalErrorRuleID)
	}

	// A spelling only a parsing reading finds (a quote splice) matches no
	// self-protection pattern on its raw text, so it is not attributed to
	// one: the managed host BLOCKs it as enterprise-chain-too-long (Gary,
	// 2026-11-04), never as enterprise-self-protect.
	home, configDir = newFailSafeHome(t, false, "")
	writeManagedNotFailClosed(t, configDir)
	code, _, stderr := runHookChild(t, home, claudeShaped(t, "PreToolUse", "Bash", routingCmd(spPastTheBound("rm -rf ~/.agentshi'e'ld/")), nil))
	if code != 2 || !strings.Contains(stderr, chainTooLongManagedRuleID) || strings.Contains(stderr, "enterprise-self-protect") {
		t.Errorf("spliced row: exit %d, want 2 naming %s and not enterprise-self-protect:\n%.400s", code, chainTooLongManagedRuleID, stderr)
	}
}

// TestHook_ManagedPastTheBound_Blocks (Gary, 2026-11-04): past the bound
// every managed host BLOCKs. Without fail_closed, a call no self-protection
// pattern matches is BLOCK enterprise-chain-too-long with the note, through
// the real hook: exit 2, the rule and reason on stderr, Copilot's deny line.
func TestHook_ManagedPastTheBound_Blocks(t *testing.T) {
	home, configDir := newFailSafeHome(t, false, "")
	writeManagedNotFailClosed(t, configDir)
	code, stdout, stderr := runHookChild(t, home, claudeShaped(t, "PreToolUse", "Bash", routingCmd(oneMiBPipe()), nil), "AGENTSHIELD_AGENT_ID=copilot-cli")
	if code != 2 || !strings.Contains(stderr, chainTooLongManagedRuleID) || !strings.Contains(stderr, "chain operators") {
		t.Fatalf("exit %d, want 2 with %s and the reason on stderr:\n%.600s", code, chainTooLongManagedRuleID, stderr)
	}
	if !strings.Contains(stdout, "deny") {
		t.Errorf("no Copilot deny line on stdout: %.300s", stdout)
	}
	e := oneEvent(t, configDir)
	if e.Decision != "BLOCK" || !slices.Equal(e.TriggeredRules, []string{chainTooLongManagedRuleID}) || e.Mode != "managed" || countKind(e.Notes, analyzer.NoteChainTooLong) != 1 || len(e.TaxonomyRefs) != 0 {
		t.Errorf("event %s %v mode=%q notes %v taxonomy %v; want BLOCK [%s], managed, the note, no node", e.Decision, e.TriggeredRules, e.Mode, noteKinds(e.Notes), e.TaxonomyRefs, chainTooLongManagedRuleID)
	}
}

// managedPastBoundRows are calls past the bound on a managed host without
// fail_closed, with the rule each must BLOCK as: main's self-protection
// record when a pattern matches the raw text, enterprise-chain-too-long for
// everything else, including the spellings only a parsing reading finds.
func managedPastBoundRows() map[string]string {
	as := "agent" + "shield"
	rows := map[string]string{
		spPastTheBound("rm -rf ~/." + as + "/"):            "enterprise-self-protect",
		spPastTheBound("export AGENTSHIELD_" + "BYPASS=1"): "enterprise-self-protect",
		spPastTheBound("ls -la"):                           chainTooLongManagedRuleID,
		oneMiBPipe():                                       chainTooLongManagedRuleID,
		derivedChainCommand():                              chainTooLongManagedRuleID,
	}
	for _, spliced := range []string{
		"export AGENTSHIELD_BYPA'S'S=1",
		"rm -rf ~/.agentshi'e'ld/",
		"rm -rf ~/.agentshi${zqx}eld",
		"rm ~/.cla'u'de/settings.json",
		"echo 'rules: []' > ~/." + as + "/poli'c'y.yaml",
		"cp /tmp/fake /opt/homebrew/bin/agentshi'e'ld",
		"b'r'ew unlink " + as,
		"brew unlink agentshi${zqx}eld",
		as + " --disable setup mcp",
		"true && " + as + " setup --disable mcp",
		"/opt/bin/" + as + " setup --disable mcp",
	} {
		rows[spPastTheBound(spliced)] = chainTooLongManagedRuleID
	}
	return rows
}

// TestManagedPastTheBound_EveryCallBlocks: in-process, every row BLOCKs with
// its rule and the note; enterprise-self-protect only where a pattern
// matched. The derived row's own text is under the bound.
func TestManagedPastTheBound_EveryCallBlocks(t *testing.T) {
	_, configDir := newFailSafeHome(t, false, "")
	writeManagedNotFailClosed(t, configDir)
	for cmd, rule := range managedPastBoundRows() {
		r, ev := evaluateCommand(cmd, "/tmp", "claude-code-hook", "managed-past-bound")
		name := cmd
		if len(name) > 60 {
			name = name[:60]
		}
		if r.Decision != policy.DecisionBlock || !slices.Equal(r.TriggeredRules, []string{rule}) || countKind(ev.Notes, analyzer.NoteChainTooLong) != 1 {
			t.Errorf("%q: %s %v notes %v; want BLOCK [%s] with the note", name, r.Decision, r.TriggeredRules, noteKinds(ev.Notes), rule)
		}
	}
}

// TestManagedPastTheBound_PowerShellAndCheck: the PowerShell lane's nested
// reading and `agentshield check` decide the same on a managed host.
func TestManagedPastTheBound_PowerShellAndCheck(t *testing.T) {
	l := testPSLane(t, 2)
	writeManagedNotFailClosed(t, filepath.Join(os.Getenv("HOME"), ".agentshield"))
	r := l.read(psNestedPastTheBound())
	if r.Decision != policy.DecisionBlock || !slices.Contains(r.TriggeredRules, chainTooLongManagedRuleID) || chainNotes(r.Notes) != 1 {
		t.Errorf("PowerShell nested: %s %v notes %v; want BLOCK [%s] with the note", r.Decision, r.TriggeredRules, r.Notes, chainTooLongManagedRuleID)
	}
	c, err := evaluateShellCommand(oneMiBPipe(), "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Decision != policy.DecisionBlock || !slices.Equal(c.TriggeredRules, []string{chainTooLongManagedRuleID}) || chainNotes(c.Notes) != 1 {
		t.Errorf("check: %s %v notes %v; want BLOCK [%s] with the note", c.Decision, c.TriggeredRules, c.Notes, chainTooLongManagedRuleID)
	}
}

// TestPSLane_SelfProtectPastTheBound_ManagedStillBlocks: the same through the
// PowerShell lane's nested bash text.
func TestPSLane_SelfProtectPastTheBound_ManagedStillBlocks(t *testing.T) {
	l := testPSLane(t, 2)
	writeManagedNotFailClosed(t, filepath.Join(os.Getenv("HOME"), ".agentshield"))
	r := l.read("bash -c '" + spPastTheBound("rm -rf ~/."+"agent"+"shield/") + "'")
	if r.Decision != policy.DecisionBlock || !slices.Contains(r.TriggeredRules, "enterprise-self-protect") || chainNotes(r.Notes) != 1 {
		t.Errorf("%s %v notes %v; want BLOCK enterprise-self-protect with the note", r.Decision, r.TriggeredRules, r.Notes)
	}
}

// TestManagedPastTheBound_OnlyTheBoundBlocks: Gary's managed BLOCK is for the
// chain bound only. Any other evaluation failure on a managed host without
// fail_closed (here an engine that will not build) stays the fail-safe AUDIT.
func TestManagedPastTheBound_OnlyTheBoundBlocks(t *testing.T) {
	_, configDir := newFailSafeHome(t, false, failSafePolicyBadLabel)
	writeManagedNotFailClosed(t, configDir)
	r, _ := evaluateCommand("ls -la", "/tmp", "claude-code-hook", "managed-other-failure")
	if r.Decision != policy.DecisionAudit || !slices.Equal(r.TriggeredRules, []string{evalErrorRuleID}) {
		t.Errorf("engine-init failure on a managed host: %s %v; want AUDIT [%s]", r.Decision, r.TriggeredRules, evalErrorRuleID)
	}
}
