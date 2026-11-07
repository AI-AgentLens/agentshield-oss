package assembly

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/facts"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/psreader"
	"github.com/AI-AgentLens/agentshield/internal/route"
)

// fakeReading is a lane reading that is only its verdict.
type fakeReading struct{ v route.Verdict }

func (f fakeReading) Verdict() route.Verdict { return f.v }

func verdict(l route.Lane, d string, rules ...string) fakeReading {
	return fakeReading{route.Verdict{Lane: l, Decision: d, Rules: rules}}
}

// TestReadRow: lanes read in row order, a lane with nothing to read is
// skipped, route.Combine picks (the earlier lane wins a tie of two AUDITs
// that both name rules), and the note is route.ReadingsDetail's over the
// readings there were.
func TestReadRow(t *testing.T) {
	lanes := []route.Lane{route.Structured, route.POSIX, route.PowerShell}
	var order []route.Lane
	row, ok := ReadRow("PowerShell", lanes, func(l route.Lane) (fakeReading, bool) {
		order = append(order, l)
		switch l {
		case route.Structured:
			return verdict(l, route.DecisionAudit, "mcp-x"), true
		case route.POSIX:
			return fakeReading{}, false // nothing to read
		}
		return verdict(l, route.DecisionAudit, "ps-y"), true
	})
	if !ok {
		t.Fatal("ok = false with two readings")
	}
	if !slices.Equal(order, lanes) {
		t.Errorf("read order %v, want the row's %v", order, lanes)
	}
	if len(row.Readings) != 2 || row.Combined.Winner != 0 || row.Kept().v.Lane != route.Structured {
		t.Fatalf("readings %d winner %d; want 2 readings, the earlier lane kept on a tie", len(row.Readings), row.Combined.Winner)
	}
	if row.Note.Kind != analyzer.NoteLaneReadings {
		t.Errorf("note kind %q, want %q", row.Note.Kind, analyzer.NoteLaneReadings)
	}
	want := "tool=PowerShell; structured=AUDIT(mcp-x); posix=none; powershell=AUDIT(ps-y); kept=structured"
	if row.Note.Detail != want {
		t.Errorf("note detail\n %q\nwant\n %q", row.Note.Detail, want)
	}

	// The stricter wins, from any position.
	row, _ = ReadRow("Bash", []route.Lane{route.POSIX, route.PowerShell}, func(l route.Lane) (fakeReading, bool) {
		if l == route.PowerShell {
			return verdict(l, route.DecisionBlock, "protected-path"), true
		}
		return verdict(l, route.DecisionAllow, "ts-allow-readonly"), true
	})
	if row.Kept().v.Lane != route.PowerShell || row.Combined.Decision != route.DecisionBlock {
		t.Errorf("kept %s deciding %s; want the PowerShell lane's BLOCK", row.Kept().v.Lane, row.Combined.Decision)
	}

	// Nothing read: no row.
	if _, ok := ReadRow("Bash", []route.Lane{route.POSIX}, func(route.Lane) (fakeReading, bool) { return fakeReading{}, false }); ok {
		t.Error("ok = true with no reading")
	}
}

// TestReadRow_AuditTie (#4779): a rule-less AUDIT gives its record to a
// tied AUDIT that names a rule; the kept record carries the moved-off pick's
// notes, and every other reading's uncertainty notes, before the
// lane_readings note.
func TestReadRow_AuditTie(t *testing.T) {
	cwd := route.Note{Kind: "payload_cwd_unusable", Detail: "relative"}
	parse := analyzer.Note{Kind: string(facts.NoteParseError), Detail: "native-command bridge: cut"}
	row, _ := ReadRow("PowerShell", []route.Lane{route.Structured, route.PowerShell}, func(l route.Lane) (fakeReading, bool) {
		if l == route.Structured {
			v := verdict(l, route.DecisionAudit)
			v.v.Notes = []route.Note{cwd, {Kind: "structured_only", Detail: "x"}}
			return v, true
		}
		r := policy.EvalResult{Decision: policy.DecisionAudit, TriggeredRules: []string{"ts-audit-credential-manager-list"},
			Notes: []analyzer.Note{{Kind: analyzer.NoteDialect, Detail: "powershell"}, parse}}
		return fakeReading{FactsVerdict(l, &r, append(RouteNotes(r.Notes), cwd))}, true
	})
	if row.Kept().v.Lane != route.PowerShell || row.Combined.Pick != 0 || row.Combined.Decision != route.DecisionAudit {
		t.Fatalf("kept %s (pick %d) deciding %s; want the PowerShell lane's rule-bearing AUDIT kept over the rule-less pick",
			row.Kept().v.Lane, row.Combined.Pick, row.Combined.Decision)
	}
	if want := []analyzer.Note{{Kind: "structured_only", Detail: "x"}}; !slices.Equal(row.Carried, want) {
		t.Errorf("carried %+v, want the pick's note the kept record lacks %+v", row.Carried, want)
	}
	if want := "tool=PowerShell; structured=AUDIT; powershell=AUDIT(ts-audit-credential-manager-list); kept=powershell; audit tie moved from structured"; row.Note.Detail != want {
		t.Errorf("note %q, want %q", row.Note.Detail, want)
	}
	if extra := row.Extra(); len(extra) != 2 || extra[0] != row.Carried[0] || extra[1] != row.Note {
		t.Errorf("Extra %+v, want the carried notes then lane_readings", extra)
	}

	// A BLOCK the Structured lane keeps carries the PowerShell lane's
	// uncertainty note; its certain notes stay with the lane.
	row, _ = ReadRow("PowerShell", []route.Lane{route.Structured, route.PowerShell}, func(l route.Lane) (fakeReading, bool) {
		if l == route.Structured {
			return verdict(l, route.DecisionBlock, "mcp-x"), true
		}
		r := policy.EvalResult{Decision: policy.DecisionAudit, Notes: []analyzer.Note{{Kind: analyzer.NoteDialect, Detail: "powershell"}, parse}}
		return fakeReading{FactsVerdict(l, &r, nil)}, true
	})
	if row.Kept().v.Lane != route.Structured || !slices.Equal(row.Carried, []analyzer.Note{parse}) {
		t.Errorf("kept %s carrying %+v; want MCP policy's BLOCK carrying only the parse_error note", row.Kept().v.Lane, row.Carried)
	}

	// One reading: nothing to carry, Extra is the note alone.
	row, _ = ReadRow("Bash", []route.Lane{route.POSIX}, func(l route.Lane) (fakeReading, bool) { return verdict(l, route.DecisionAudit), true })
	if len(row.Carried) != 0 || len(row.Extra()) != 1 {
		t.Errorf("single reading: carried %+v extra %+v", row.Carried, row.Extra())
	}
}

// TestCombineNested_AuditTie (#4779): inside the PowerShell lane, a
// rule-less AUDIT gives its record to a nested reading's tied AUDIT that
// names a rule (the native-command bridge's POSIX reading of `cmdkey
// /list`), and no note the old record carried is lost: the text's own, the
// unread notes, and a moved-off nested pick's.
func TestCombineNested_AuditTie(t *testing.T) {
	own := policy.EvalResult{Decision: policy.DecisionAudit, Notes: []analyzer.Note{{Kind: analyzer.NoteDialect, Detail: "powershell"}}}
	bridge := policy.EvalResult{Decision: policy.DecisionAudit, TriggeredRules: []string{"ts-audit-credential-manager-list"},
		Reasons: []string{"cmdkey /list"}, TaxonomyRefs: []string{"reconnaissance/credential-discovery/windows-credential-manager-enumeration"},
		Notes: []analyzer.Note{{Kind: "parse_fallback", Detail: "posix"}}}
	cut := analyzer.Note{Kind: string(facts.NoteParseError), Detail: "native-command bridge: cut"}
	r := combineNested([]policy.EvalResult{own, bridge}, []analyzer.Note{cut})
	if r.Decision != policy.DecisionAudit || r.OriginalDecision != "" || !slices.Equal(r.TriggeredRules, bridge.TriggeredRules) ||
		!slices.Equal(r.TaxonomyRefs, bridge.TaxonomyRefs) || !slices.Equal(r.Reasons, bridge.Reasons) {
		t.Fatalf("record %s %v %v %v; want the bridge's rule, reasons and taxonomy at AUDIT", r.Decision, r.TriggeredRules, r.Reasons, r.TaxonomyRefs)
	}
	if want := []analyzer.Note{own.Notes[0], cut, bridge.Notes[0]}; !slices.Equal(r.Notes, want) {
		t.Errorf("notes %+v, want %+v", r.Notes, want)
	}

	// Both name rules: the text's own record, as before.
	own.TriggeredRules = []string{"ps-audit-encoded-command"}
	if r := combineNested([]policy.EvalResult{own, bridge}, nil); !slices.Equal(r.TriggeredRules, own.TriggeredRules) {
		t.Errorf("both name rules: %v, want the text's own", r.TriggeredRules)
	}

	// The pick is a nested reading that names no rule: its notes stay on
	// the record the next nested reading now gives.
	allow := policy.EvalResult{Decision: policy.DecisionAllow, Notes: []analyzer.Note{{Kind: analyzer.NoteDialect, Detail: "powershell"}}}
	ruleless := policy.EvalResult{Decision: policy.DecisionAudit, Notes: []analyzer.Note{{Kind: "nested_pick_note", Detail: "x"}}}
	r = combineNested([]policy.EvalResult{allow, ruleless, bridge}, nil)
	if !slices.Equal(r.TriggeredRules, bridge.TriggeredRules) {
		t.Fatalf("rules %v, want the rule-bearing nested reading's", r.TriggeredRules)
	}
	if want := []analyzer.Note{allow.Notes[0], ruleless.Notes[0], bridge.Notes[0]}; !slices.Equal(r.Notes, want) {
		t.Errorf("notes %+v, want the text's, the moved-off pick's and the kept reading's %+v", r.Notes, want)
	}
}

// TestReadRow_AuditFloor: an uncertain note (a dialect lane that could not
// read all of the call) floors an ALLOW at AUDIT, through the runner.
func TestReadRow_AuditFloor(t *testing.T) {
	row, _ := ReadRow("Bash", []route.Lane{route.POSIX, route.PowerShell}, func(l route.Lane) (fakeReading, bool) {
		v := verdict(l, route.DecisionAllow)
		if l == route.PowerShell {
			r := policy.EvalResult{Decision: policy.DecisionAllow, Notes: []analyzer.Note{{Kind: string(facts.NoteParseError)}}}
			v.v = FactsVerdict(l, &r, nil)
		}
		return v, true
	})
	if row.Combined.Decision != route.DecisionAudit || !row.Combined.Floored {
		t.Errorf("decision %s floored %v; want AUDIT by the floor", row.Combined.Decision, row.Combined.Floored)
	}
}

// TestVerdictAdapters: only a dialect lane's uncertainty notes are marked; a
// POSIX or Structured note of the same kind keeps today's meaning (D4).
func TestVerdictAdapters(t *testing.T) {
	r := policy.EvalResult{Decision: policy.DecisionAudit, TriggeredRules: []string{"r"},
		Notes: []analyzer.Note{{Kind: string(facts.NoteParseError)}, {Kind: analyzer.NoteDialect}}}

	fv := FactsVerdict(route.PowerShell, &r, nil)
	if len(fv.Notes) != 2 || !fv.Notes[0].Uncertain || fv.Notes[1].Uncertain {
		t.Errorf("FactsVerdict notes %+v; want parse_error uncertain, dialect not", fv.Notes)
	}
	given := []route.Note{{Kind: analyzer.NoteNestedDepthExceeded}}
	fv = FactsVerdict(route.PowerShell, &r, given)
	if len(fv.Notes) != 1 || !fv.Notes[0].Uncertain || given[0].Uncertain {
		t.Errorf("FactsVerdict with notes %+v (given %+v); want the given note marked on a copy", fv.Notes, given)
	}

	sv := ShellVerdict(route.POSIX, &r, RouteNotes(r.Notes))
	for _, n := range sv.Notes {
		if n.Uncertain {
			t.Errorf("ShellVerdict marked %s uncertain", n.Kind)
		}
	}
	if sv.Decision != route.DecisionAudit || sv.Rules[0] != "r" {
		t.Errorf("ShellVerdict %+v", sv)
	}

	for _, kind := range []string{string(facts.NoteParseError), string(facts.NoteDynamicName), string(facts.NoteDynamicNested),
		string(facts.NoteDecodeFailed), analyzer.NoteNestedDepthExceeded, analyzer.NoteRoutingGap} {
		if !UncertainNote(kind) {
			t.Errorf("UncertainNote(%q) = false", kind)
		}
	}
	for _, kind := range []string{analyzer.NoteDialect, analyzer.NotePathMention, analyzer.NoteLaneReadings, "excused"} {
		if UncertainNote(kind) {
			t.Errorf("UncertainNote(%q) = true", kind)
		}
	}
}

func TestNestedDepthBound(t *testing.T) {
	for in, want := range map[int]int{0: 2, -1: 2, 1: 1, 3: 3} {
		if got := NestedDepthBound(in); got != want {
			t.Errorf("NestedDepthBound(%d) = %d, want %d", in, got, want)
		}
	}
}

// TestCmdProgram: the program a cmd line starts, as cmd finds it.
func TestCmdProgram(t *testing.T) {
	rows := map[string]string{
		"powershell -enc x": "powershell",
		"  pwsh.exe -c x":   "pwsh.exe",
		`"C:\Program Files\PowerShell\7\pwsh.exe" -c x`: `C:\Program Files\PowerShell\7\pwsh.exe`,
		"\tbash -c x":   "bash",
		"dir":           "dir",
		`"unterminated`: "unterminated",
		"":              "",
	}
	for in, want := range rows {
		if got := CmdProgram(in); got != want {
			t.Errorf("CmdProgram(%q) = %q, want %q", in, got, want)
		}
	}
}

func testEngine(t *testing.T) *policy.Engine {
	t.Helper()
	pol := &policy.Policy{Version: "0.1", Defaults: policy.Defaults{Decision: policy.DecisionAudit, ProtectedPaths: []string{"~/.ssh/**"}}}
	e, err := ShellEngine(pol, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// TestPowerShellLane_PanicIsAnError: a panic anywhere in the lane comes back
// as an error the surface turns into its fail-safe reading (D9).
func TestPowerShellLane_PanicIsAnError(t *testing.T) {
	l := &PowerShellLane{Engine: testEngine(t), MaxDepth: 2,
		Reader: func(string, psreader.Env) facts.Facts { panic("reader exploded") }}
	_, err := l.Read("Get-Date")
	if err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("err = %v, want the panic named", err)
	}
}

// TestPowerShellLane_NestedPOSIXIsTheSurfaces: a nested bash text is decided
// by the POSIX reading the surface supplies, and its BLOCK is combined into
// the lane's result. Control: the same text without the nested call.
func TestPowerShellLane_NestedPOSIXIsTheSurfaces(t *testing.T) {
	var seen []string
	l := &PowerShellLane{Engine: testEngine(t), Env: psreader.Env{Home: "/home/u"}, Opts: policy.FactsOptions{Home: "/home/u"},
		Cwd: "/home/u", MaxDepth: 2,
		POSIX: func(text string) policy.EvalResult {
			seen = append(seen, text)
			return policy.EvalResult{Decision: policy.DecisionBlock, TriggeredRules: []string{"surface-rule"}}
		}}
	r, err := l.Read("Get-Date")
	if err != nil || r.Decision != policy.DecisionAudit || len(seen) != 0 {
		t.Fatalf("control: %s %v, POSIX saw %q; want AUDIT and no POSIX reading", r.Decision, err, seen)
	}
	r, err = l.Read("Get-Date; bash -c 'echo hi'")
	if err != nil || r.Decision != policy.DecisionBlock || !slices.Contains(r.TriggeredRules, "surface-rule") {
		t.Fatalf("decision %s rules %v err %v; want the surface's BLOCK", r.Decision, r.TriggeredRules, err)
	}
	if len(seen) != 1 || seen[0] != "echo hi" {
		t.Errorf("POSIX saw %q, want the nested text", seen)
	}
}

// nestedFlood is a PowerShell text of n nested sh texts, `sh -c a0; sh -c
// a1; …`, with `sh -c <marker>` at position at (-1: none). DATA only.
func nestedFlood(n, at int, marker string) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		if i == at {
			b.WriteString("sh -c " + marker + "; ")
			continue
		}
		fmt.Fprintf(&b, "sh -c a%d; ", i)
	}
	return b.String()
}

// TestPowerShellLane_NestedPOSIXReadingsAreBounded (#4766 Opus pass 1, F2):
// identical nested texts are read once on every surface. Distinct ones are
// all read when the lane has no bound (the hook, as on main), and up to
// NestedPOSIXBound when it has one (shield-server, ServerNestedPOSIXBound);
// past it a text is not read and the call floors at AUDIT with a parse_error
// note naming the bound.
func TestPowerShellLane_NestedPOSIXReadingsAreBounded(t *testing.T) {
	const bound = ServerNestedPOSIXBound
	var calls int
	lane := func(nestedBound int) *PowerShellLane {
		return &PowerShellLane{Engine: testEngine(t), Env: psreader.Env{Home: "/home/u"}, Opts: policy.FactsOptions{Home: "/home/u"},
			Cwd: "/home/u", MaxDepth: 2, NestedPOSIXBound: nestedBound,
			POSIX: func(text string) policy.EvalResult {
				calls++
				if text == "BAD" {
					return policy.EvalResult{Decision: policy.DecisionBlock, TriggeredRules: []string{"surface-rule"}}
				}
				return policy.EvalResult{Decision: policy.DecisionAudit}
			}}
	}
	read := func(l *PowerShellLane, text string) policy.EvalResult {
		t.Helper()
		calls = 0
		r, err := l.Read(text)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	bounded := func(r policy.EvalResult) bool {
		for _, n := range r.Notes {
			if n.Kind == string(facts.NoteParseError) && strings.Contains(n.Detail, "distinct nested bash/sh texts") {
				return true
			}
		}
		return false
	}
	hook, server := lane(0), lane(bound)

	// Identical texts: one reading, on both.
	for name, l := range map[string]*PowerShellLane{"hook": hook, "server": server} {
		if r := read(l, strings.Repeat("sh -c a; ", 3000)); calls != 1 || bounded(r) {
			t.Errorf("%s: 3000 identical nested texts: %d POSIX readings (bounded %v), want 1", name, calls, bounded(r))
		}
	}

	// Up to the bound, both read every distinct text, the last one included.
	for name, l := range map[string]*PowerShellLane{"hook": hook, "server": server} {
		if r := read(l, nestedFlood(bound, bound-1, "BAD")); calls != bound || r.Decision != policy.DecisionBlock || bounded(r) {
			t.Errorf("%s: %d distinct texts, the last BLOCKs: %d readings, %s, bounded %v; want all read and BLOCK",
				name, bound, calls, r.Decision, bounded(r))
		}
	}

	// Past it, the hook reads on (main's behaviour) and BLOCKs ...
	flood := nestedFlood(bound+500, bound+10, "BAD")
	if r := read(hook, flood); calls != bound+500 || r.Decision != policy.DecisionBlock || bounded(r) {
		t.Errorf("hook past %d: %d readings, %s, bounded %v; want every text read and BLOCK", bound, calls, r.Decision, bounded(r))
	}
	// ... while the server stops: no more readings, the note, the AUDIT floor.
	if r := read(server, flood); calls != bound || !bounded(r) || r.Decision != policy.DecisionAudit {
		t.Errorf("server past %d: %d readings, %s, bounded %v; want %d, AUDIT with the note", bound, calls, r.Decision, bounded(r), bound)
	}

	// The server's bound is per call, across nesting levels: texts inside a
	// nested pwsh count against the same budget.
	outer := strings.ReplaceAll(nestedFlood(10, -1, ""), "sh -c a", "sh -c b") // b0..b9, distinct from the inner a0..
	if r := read(server, outer+"pwsh -c '"+nestedFlood(bound, -1, "")+"'"); calls != bound || !bounded(r) {
		t.Errorf("server bound across levels: %d readings, bounded %v; want %d and the note", calls, bounded(r), bound)
	}
}

// bridgeLane is a PowerShell lane whose surface POSIX reading records each
// text and BLOCKs one that runs `git frobnicate` (a stand-in for a shell
// rule).
func bridgeLane(t *testing.T, bridge bool, seen *[]string) *PowerShellLane {
	return &PowerShellLane{Engine: testEngine(t), Env: psreader.Env{Home: "/home/u"}, Opts: policy.FactsOptions{Home: "/home/u"},
		Cwd: "/home/u", MaxDepth: 2, NativeBridge: bridge,
		POSIX: func(text string) policy.EvalResult {
			*seen = append(*seen, text)
			if strings.Contains(text, "git frobnicate") {
				return policy.EvalResult{Decision: policy.DecisionBlock, OriginalDecision: policy.DecisionBlock,
					TriggeredRules: []string{"bash-rule"}, Reasons: []string{"bash reason"}, TaxonomyRefs: []string{"bash/taxonomy"}}
			}
			return policy.EvalResult{Decision: policy.DecisionAudit}
		}}
}

// TestPowerShellLane_NativeBridge (#4768): with NativeBridge set, the native
// programs of the call's text and of every nested PowerShell text are read by
// the surface's POSIX reading in ONE pass, as rebuilt command lines, and a
// BLOCK it decides is the call's with the bash rule's id, reasons and
// taxonomy. Without it, nothing reaches POSIX. A text with no native program
// makes no POSIX reading, and a BLOCK the lane decides itself keeps its own
// record (the tie, D4).
func TestPowerShellLane_NativeBridge(t *testing.T) {
	text := `Get-ChildItem; & 'C:\tools\Git.EXE' frobnicate --now; pwsh -c 'kubectl get pods'`

	var seen []string
	r, err := bridgeLane(t, false, &seen).Read(text)
	if err != nil || r.Decision != policy.DecisionAudit || len(seen) != 0 {
		t.Fatalf("bridge off: %s %v, POSIX saw %q; want AUDIT and no POSIX reading", r.Decision, err, seen)
	}

	seen = nil
	r, err = bridgeLane(t, true, &seen).Read(text)
	if err != nil || r.Decision != policy.DecisionBlock {
		t.Fatalf("bridge on: %s %v; want the bridge's BLOCK", r.Decision, err)
	}
	if !slices.Equal(r.TriggeredRules, []string{"bash-rule"}) || !slices.Equal(r.TaxonomyRefs, []string{"bash/taxonomy"}) ||
		!slices.Equal(r.Reasons, []string{"bash reason"}) {
		t.Errorf("record rules %v reasons %v taxonomy %v; want the bash reading's", r.TriggeredRules, r.Reasons, r.TaxonomyRefs)
	}
	if want := []string{"git frobnicate --now\nkubectl get pods"}; !slices.Equal(seen, want) {
		t.Errorf("POSIX saw %q, want one reading of both levels' native programs %q", seen, want)
	}

	seen = nil
	if r, _ := bridgeLane(t, true, &seen).Read(`Get-ChildItem | Remove-Item x`); len(seen) != 0 || r.Decision != policy.DecisionAudit {
		t.Errorf("no native program: POSIX saw %q, decision %s; want no reading and AUDIT", seen, r.Decision)
	}

	seen = nil
	r, _ = bridgeLane(t, true, &seen).Read(`Get-Content ~/.ssh/id_rsa; git frobnicate`)
	if r.Decision != policy.DecisionBlock || len(r.TriggeredRules) == 0 || r.TriggeredRules[0] != "protected-path" {
		t.Errorf("tie: rules %v, want the lane's own protected-path record kept", r.TriggeredRules)
	}
}

// TestPowerShellLane_NativeBridgeLimit: a rebuilt text past the call's text
// plus BridgeSlack is cut at a line: what fits is read, and a parse_error
// note floors the call at AUDIT.
func TestPowerShellLane_NativeBridgeLimit(t *testing.T) {
	var seen []string
	l := bridgeLane(t, true, &seen)
	l.Reader = func(text string, env psreader.Env) facts.Facts {
		f := psreader.Read(text, env)
		f.Native = append(psreader.Read("git frobnicate", env).Native, psreader.Read("git "+strings.Repeat("a", BridgeSlack+64), env).Native...)
		return f
	}
	r, err := l.Read("Get-Date -Format yyyy") // 21 bytes: a limit of 21 + BridgeSlack
	if err != nil || r.Decision != policy.DecisionBlock || !slices.Equal(seen, []string{"git frobnicate"}) {
		t.Fatalf("decision %s err %v, POSIX saw %q; want the statement that fits read and BLOCK", r.Decision, err, seen)
	}
	var cut bool
	for _, n := range r.Notes {
		cut = cut || n.Kind == string(facts.NoteParseError) && strings.Contains(n.Detail, "native-command bridge")
	}
	if !cut {
		t.Errorf("notes %+v lack the bridge's parse_error note", r.Notes)
	}

	// A long pipeline is read in windows: every stage is read, and the
	// window note floors the call.
	seen = nil
	l.Reader = nil
	long := strings.Repeat("a | ", 20) + "git frobnicate | " + strings.Repeat("a | ", 20) + "a"
	r, _ = l.Read(long)
	var windowed bool
	for _, n := range r.Notes {
		windowed = windowed || n.Kind == string(facts.NoteParseError) && strings.Contains(n.Detail, "in windows of")
	}
	if r.Decision != policy.DecisionBlock || !windowed || len(seen) != 1 || strings.Count(seen[0], "\n") != 2 {
		t.Errorf("long pipeline: %s, windowed note %v, POSIX saw %q; want BLOCK, the note, one reading of 3 windows", r.Decision, windowed, seen)
	}

	// A surface's byte bound: what passes it is not read.
	seen = nil
	l.NativeBridgeBytes = 20
	r, _ = l.Read("git status; git log; git frobnicate")
	if r.Decision != policy.DecisionAudit || !slices.Equal(seen, []string{"git status\ngit log"}) {
		t.Errorf("bound 20: %s, POSIX saw %q; want the first 19 bytes read and AUDIT", r.Decision, seen)
	}
	l.NativeBridgeBytes = 0

	// Only the cut statement over the limit: the floor alone.
	seen = nil
	l.Reader = func(text string, env psreader.Env) facts.Facts {
		f := psreader.Read(text, env)
		f.Native = psreader.Read("git "+strings.Repeat("a", BridgeSlack+64), env).Native
		return f
	}
	if r, _ := l.Read("Get-Date -Format yyyy"); r.Decision != policy.DecisionAudit || len(seen) != 0 {
		t.Errorf("decision %s, POSIX saw %q; want AUDIT and no reading", r.Decision, seen)
	}
}
