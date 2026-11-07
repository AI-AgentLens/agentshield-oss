package assembly

import (
	"fmt"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/abandon"
	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/facts"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/psreader"
	"github.com/AI-AgentLens/agentshield/internal/route"
)

// The lanes of ADR-001 (docs/architecture/adr-001-tool-routing-dialect-lanes.md),
// shared by every surface that routes a call through the table: the local hook
// (internal/cli) and shield-server (cmd/shield-server, step 2).
//
// internal/route decides which lanes read a call and how their verdicts
// combine. This file holds what the surfaces must not each write for
// themselves:
//
//   - ReadRow, the row runner: every lane of a row reads the call in row
//     order, route.Combine picks the reading that is the call's receipt, and
//     a lane_readings note names what every lane decided (D4).
//   - the verdict adapters (D9), so a lane's verdict, and which of its notes
//     put the AUDIT floor under the call, is computed one way.
//   - PowerShellLane, the PowerShell lane itself (step 4): the reader, the
//     Facts evaluator and nested routing (D6).
//
// What a surface supplies is its own: how it loads an engine, evaluates a
// POSIX text (the hook runs the enterprise middleware first; shield-server
// has none), and records the kept reading.

// LaneReading is one lane's reading of a routed call, held until the row's
// lanes are combined.
type LaneReading interface {
	Verdict() route.Verdict
}

// Row is a call read by every lane of its routing row.
type Row[R LaneReading] struct {
	// Readings are the lanes' readings in row order. A lane with nothing to
	// read (a shell lane and no command text) has none.
	Readings []R
	// Combined is route.Combine's verdict over the readings. Its Winner
	// indexes Readings: the reading whose record is the call's receipt.
	Combined route.Combined
	// Carried are the other readings' notes the kept reading's record
	// carries (route.CarriedNotes): their uncertainty notes, and the pick's
	// notes when the AUDIT tie rule moved the record off it (#4779).
	Carried []analyzer.Note
	// Note is the lane_readings note for the kept reading's record: the tool,
	// every lane's decision and first rule, the lane kept.
	Note analyzer.Note
}

// Extra is what the kept reading's record carries after its own notes:
// Carried, then the lane_readings Note.
func (r Row[R]) Extra() []analyzer.Note {
	return append(append(make([]analyzer.Note, 0, len(r.Carried)+1), r.Carried...), r.Note)
}

// Kept is the reading whose record is the call's receipt.
func (r Row[R]) Kept() R { return r.Readings[r.Combined.Winner] }

// ReadRow reads a call with each lane of its row, in row order, and combines
// the readings (ADR-001 D4): the stricter pre-downgrade decision wins, the
// earlier lane wins a tie, except that a self-protection BLOCK kept in
// audit-only mode wins its tie and a rule-less AUDIT gives its record to a
// tied AUDIT that names a rule, and an uncertain note floors the call at
// AUDIT (route.Combine). read returns a lane's reading, or false when the
// lane has nothing to read. ok is false when no lane read the call.
//
// The caller records the kept reading, with Combined's decision (the
// reading's own, unless the AUDIT floor raised it) and Extra (the carried
// notes and the lane_readings note), and releases the others unwritten, so a
// call leaves one receipt whichever lane decided it.
func ReadRow[R LaneReading](tool string, lanes []route.Lane, read func(route.Lane) (R, bool)) (row Row[R], ok bool) {
	for _, l := range lanes {
		if r, has := read(l); has {
			row.Readings = append(row.Readings, r)
		}
	}
	if len(row.Readings) == 0 {
		return row, false
	}
	verdicts := make([]route.Verdict, len(row.Readings))
	for i, r := range row.Readings {
		verdicts[i] = r.Verdict()
	}
	row.Combined = route.Combine(verdicts)
	for _, n := range route.CarriedNotes(verdicts, row.Combined) {
		row.Carried = append(row.Carried, analyzer.Note{Kind: n.Kind, Rule: n.Rule, Detail: n.Detail})
	}
	row.Note = analyzer.Note{
		Kind:   analyzer.NoteLaneReadings,
		Detail: route.ReadingsDetail(tool, lanes, verdicts, row.Combined),
	}
	return row, true
}

// RoutingGapNote is the routing_gap note on a call route.Gap reports (ADR-001
// D5): a tool no row names, carrying command text, evaluated as a tool call by
// MCP policy and read by no shell lane. Evidence only: it never changes a
// decision.
func RoutingGapNote(c route.ToolCall) analyzer.Note {
	return analyzer.Note{
		Kind:   analyzer.NoteRoutingGap,
		Detail: fmt.Sprintf("tool %q (harness %s) carries command text and no routing row names it; evaluated as a tool call by MCP policy, not read by a shell lane", c.Tool, c.Harness),
	}
}

// RouteNotes converts analyzer notes to the combiner's, none of them marked
// uncertain: the POSIX and Structured lanes' notes keep today's meaning (D4).
func RouteNotes(ns []analyzer.Note) []route.Note {
	if len(ns) == 0 {
		return nil
	}
	out := make([]route.Note, 0, len(ns))
	for _, n := range ns {
		out = append(out, route.Note{Kind: n.Kind, Rule: n.Rule, Detail: n.Detail})
	}
	return out
}

// ShellVerdict adapts the POSIX lane's result (ADR-001 D9). notes are the
// reading's notes as its record carries them. None is marked uncertain: the
// POSIX lane's notes keep today's meaning (D4).
func ShellVerdict(lane route.Lane, r *policy.EvalResult, notes []route.Note) route.Verdict {
	return route.Verdict{
		Lane:             lane,
		Decision:         string(r.Decision),
		OriginalDecision: string(r.OriginalDecision),
		Rules:            r.TriggeredRules,
		Reasons:          r.Reasons,
		TaxonomyRefs:     r.TaxonomyRefs,
		Notes:            notes,
	}
}

// ToolCallVerdict adapts the Structured lane's result (ADR-001 D9). Its
// taxonomy is the merged view a tool call's record carries.
func ToolCallVerdict(r mcp.MCPEvalResult, notes []route.Note) route.Verdict {
	return route.Verdict{
		Lane:             route.Structured,
		Decision:         string(r.Decision),
		OriginalDecision: string(r.OriginalDecision),
		Rules:            r.TriggeredRules,
		Reasons:          r.Reasons,
		TaxonomyRefs:     r.AllTaxonomyRefs(),
		Notes:            notes,
	}
}

// FactsVerdict adapts a dialect lane's result (ADR-001 D9). notes are the
// reading's notes as its record carries them; nil takes the result's own.
// Unlike the POSIX lane's notes, its uncertainty notes are marked
// (UncertainNote), so the combiner puts the AUDIT floor under the call (D4).
func FactsVerdict(lane route.Lane, r *policy.EvalResult, notes []route.Note) route.Verdict {
	ns := notes
	if ns == nil {
		ns = RouteNotes(r.Notes)
	} else {
		ns = append([]route.Note(nil), ns...)
	}
	for i := range ns {
		ns[i].Uncertain = UncertainNote(ns[i].Kind)
	}
	return route.Verdict{
		Lane:             lane,
		Decision:         string(r.Decision),
		OriginalDecision: string(r.OriginalDecision),
		Rules:            r.TriggeredRules,
		Reasons:          r.Reasons,
		TaxonomyRefs:     r.TaxonomyRefs,
		Notes:            ns,
	}
}

// uncertainNotes are the note kinds that say the PowerShell lane did not read
// all of a call (ADR-001 D4): the reader's four, and the three for nested text
// it did not read.
var uncertainNotes = map[string]bool{
	string(facts.NoteParseError):     true,
	string(facts.NoteDynamicName):    true,
	string(facts.NoteDynamicNested):  true,
	string(facts.NoteDecodeFailed):   true,
	analyzer.NoteNestedDepthExceeded: true,
	analyzer.NoteRoutingGap:          true,
	// A nested bash text past the chain bound was not parsed (#4778).
	analyzer.NoteChainTooLong: true,
}

// UncertainNote reports whether a dialect lane's note of this kind says the
// lane did not read all of the call.
func UncertainNote(kind string) bool { return uncertainNotes[kind] }

// NestedDepthBound is how deep the PowerShell lane follows nested
// interpreters: the analyzer's max_parse_depth (default 2), the bound the
// bash parser uses for `bash -c` (ADR-001 D6). A value of 0 or less is unset.
func NestedDepthBound(maxParseDepth int) int {
	if maxParseDepth > 0 {
		return maxParseDepth
	}
	return 2
}

// PowerShellLane is the PowerShell lane (ADR-001 step 4, #4245). It reads a
// text with internal/psreader and decides on what it read with
// policy.Engine.EvaluateFacts: protected paths with every pattern the shell
// enforces, on a managed host self-protection of AgentShield's config
// directory ("only known reads pass"), and the PowerShell pack rules
// (`powershell:` match blocks, packs/community/powershell.yaml, step 5). It
// also runs the shell pipeline's inline-secrets heuristic over each text it
// reads (policy.Engine.EvaluateInlineSecrets, #4802), the one guardian
// heuristic it runs. Each nested interpreter's text goes back to the router
// (route.NestedLane, D6).
//
// Reading is side-effect free: the reader reads characters and never runs or
// evaluates them.
type PowerShellLane struct {
	Engine *policy.Engine
	// Env resolves `~`, `$HOME`, `$env:NAME` and `%NAME%` in the text.
	Env psreader.Env
	// Opts are EvaluateFacts' options: whether the host is managed, and the
	// home directory `~` stands for.
	Opts policy.FactsOptions
	// Cwd is the directory the text runs in.
	Cwd string
	// MaxDepth bounds nested interpreters (NestedDepthBound).
	MaxDepth int
	// POSIX is the surface's POSIX reading of a nested bash or sh text: what
	// its POSIX lane decides for a command, on this lane's engine.
	POSIX func(text string) policy.EvalResult
	// Reader reads a text; nil is psreader.Read. A field only so a test can
	// make the lane fail.
	Reader func(string, psreader.Env) facts.Facts
	// NestedPOSIXBound bounds the distinct nested bash and sh texts one call
	// hands to POSIX; 0 is no bound. See ServerNestedPOSIXBound for which
	// surface sets one and why.
	NestedPOSIXBound int
	// NativeBridge reads the native programs the call runs (git, kubectl,
	// terraform …; facts.Facts.Native, from its text and every nested
	// PowerShell text) with POSIX, as rebuilt command lines in one nested
	// reading (the native-command bridge, #4768, bridge.go), so the shell
	// rules for those programs apply. The hook sets it on every row the lane
	// is on: where POSIX reads the raw text too, it still misses a program
	// written the Windows way (`git.exe …`, `& '…\git.exe' …`).
	// shield-server sets it only for a call no POSIX lane reads, for its
	// thin clients' 5 s budget (Kai, 2026-11-04).
	NativeBridge bool
	// NativeBridgeBytes bounds the bridge's rebuilt text in bytes; 0 is
	// only the bound every surface has, the call's text plus BridgeSlack.
	// See ServerNativeBridgeBytes for which surface sets one and why.
	NativeBridgeBytes int
	// InlineSecretsBytes bounds, per text, what the inline-secrets heuristic
	// reads (#4802); 0 is no bound. See ServerInlineSecretsBytes for which
	// surface sets one and why.
	InlineSecretsBytes int
}

// ServerInlineSecretsBytes is shield-server's bound on a text the PowerShell
// lane's inline-secrets heuristic reads (#4802): the reader's own parse bound
// (128 KiB), past which the lane already reads the text by raw scan only and
// floors it at AUDIT. The heuristic is linear but not free: about 0.6 s a MiB
// on a text dense with credential-named assignments (measured 2.3 s on 4 MiB
// under load), and the server takes 4 MiB bodies while its thin clients fail
// open at 5 s. main never ran the heuristic there, so a text past the bound
// decides as on main, with a parse_error note saying the heuristic did not
// read it, and no new time is spent on it. The hook sets none: its budget is
// the harness's hook timeout and its decision budget (#4772).
const ServerInlineSecretsBytes = 128 << 10

// BridgeSlack is how far the bridge's rebuilt text may pass the call's own
// text (#4768): one POSIX reading of no more than the input, plus room for
// the quotes a short command gains (`--principal *` is written
// `--principal '*'`). The rebuilt text is usually much shorter than the
// input (cmdlets, operators and comments drop out); text built to pass the
// bound (a long pipeline of one-letter programs, many one-character quoted
// words) is cut, and its note floors the call at AUDIT, which is no more
// than a computed command name gets (`& ('gi'+'t') …`, which the bridge
// never reads).
const BridgeSlack = 1 << 10

// ServerNativeBridgeBytes is shield-server's bound on the native-command
// bridge's rebuilt text (#4768). The bridge runs there on the Python
// client's Claude Code PowerShell call, whose path on main read no POSIX
// text at all, and a thin client fails open at 5 s, so the bridge's one POSIX
// reading must stay well inside that under load. Past the bound a line is
// not read, and a parse_error note floors the call at AUDIT, which is where
// main's reading of that call stops (MCP policy and the PowerShell lane,
// both still read in full). The hook sets none: its budget is the
// harness's hook timeout, and the bridge's own bound (the text plus
// BridgeSlack, long pipelines and chains in windows) keeps its reading
// linear in the text.
const ServerNativeBridgeBytes = 16 << 10

// ServerNestedPOSIXBound is shield-server's bound on the distinct nested
// bash and sh texts one call's PowerShell reading hands to the POSIX lane
// (#4766 Opus pass 1, F2). Each is a full pipeline run (about 0.12 ms for a
// short text): 16 000 distinct `sh -c aN;` in 126 KiB took the server from
// 2.7 s to 4.3 s, and under load past the thin clients' 5 s timeout, which
// fails open. Past the bound a text is not read: the call gets a parse_error
// note, so it floors at AUDIT, like the lane's other bounds.
//
// The bound is the server's only. On the server it never decides below main:
// a call from the PowerShell client keeps its POSIX reading of the outer
// text (the legacy lane), and the Python client's tool call had no nested
// reading on main at all. The hook sets none (0): main's hook reads every
// nested text, and its budget is the harness's hook timeout (Copilot's 30 s),
// not 5 s.
//
// Identical texts are read once on every surface: a reading depends only on
// the text, the engine and the cwd, all fixed for one call. Reading the rest
// as one joined script was measured and rejected: only twice as cheap
// (0.06 ms a text), and one text can change how the next is read (an
// unclosed heredoc or quote, a trailing backslash, a variable or a cd),
// which would hide a command rather than bound the work.
const ServerNestedPOSIXBound = 1024

// readState is what one call's reading shares across its nesting levels.
type readState struct {
	posix   map[string]policy.EvalResult // nested POSIX readings, by text
	bounded bool                         // a text past NestedPOSIXBound was dropped
	native  []facts.NativeStatement      // every level's native programs, for the bridge
}

// Read decides the call's text. A panic anywhere in the lane is returned as
// an error, a lane failure the surface turns into its fail-safe reading
// (ADR-001 D9), never a crash.
func (l *PowerShellLane) Read(text string) (result policy.EvalResult, err error) {
	defer func() {
		if p := recover(); p != nil {
			result, err = policy.EvalResult{}, fmt.Errorf("the PowerShell lane panicked: %v", p)
		}
	}()
	st := &readState{posix: map[string]policy.EvalResult{}}
	result = l.read(text, 0, st)
	if l.NativeBridge && len(st.native) > 0 {
		limit := len(text) + BridgeSlack
		if l.NativeBridgeBytes > 0 {
			limit = min(limit, l.NativeBridgeBytes)
		}
		result = l.bridge(result, st, limit)
	}
	return result, nil
}

// bridge reads the call's native programs (every level's) with POSIX, as
// command lines NativePOSIXText rebuilds from their argument vectors, in one
// reading on the call's engine and cwd (l.POSIX), and combines it with the
// call's reading as a nested reading is combined: stricter wins, the
// PowerShell reading on a tie, so a BLOCK the bridge decides carries the
// bash rule's id, reasons and taxonomy. On an AUDIT tie where the
// PowerShell reading names no rule and the bridge's does (`cmdkey /list`,
// #4779), the bridge's record is kept, so the AUDIT carries the bash
// rule's id and node. limit bounds the rebuilt text; a
// line past it is not read, and a pipeline or chain longer than
// BridgeWindow is read in windows. Either writes a parse_error note (the
// AUDIT floor), because some of what the programs do was not read.
func (l *PowerShellLane) bridge(own policy.EvalResult, st *readState, limit int) policy.EvalResult {
	bt := NativePOSIXText(st.native, limit)
	text := bt.Text
	var unread []analyzer.Note
	if bt.Cut {
		unread = append(unread, analyzer.Note{Kind: string(facts.NoteParseError),
			Detail: fmt.Sprintf("native-command bridge: the rebuilt command lines passed %d bytes; the rest were not read", limit)})
	}
	if bt.Windowed {
		unread = append(unread, analyzer.Note{Kind: string(facts.NoteParseError),
			Detail: fmt.Sprintf("native-command bridge: a pipeline or chain longer than %d was read in windows of %d; programs further apart were not read together", BridgeWindow, BridgeWindow)})
	}
	results := []policy.EvalResult{own}
	abandon.Checkpoint()
	if text != "" {
		r, done := st.posix[text]
		if !done {
			r = l.POSIX(text)
			st.posix[text] = r
		}
		results = append(results, r)
	}
	if len(results) == 1 && len(unread) == 0 {
		return own
	}
	return combineNested(results, unread)
}

// read decides one PowerShell text: the call's own at depth 0, or text a
// nested interpreter at that depth runs.
//
// Each nested interpreter's text goes back to the router (route.NestedLane,
// ADR-001 D6), up to MaxDepth levels under the call's text: powershell and
// pwsh to this lane, bash and sh to the POSIX lane. Its verdict is combined
// with this text's by route.Combine (combineNested), and it has no record of
// its own: the call has one receipt. Text past the bound, and text of an
// interpreter no lane reads, is not read; a note records it and the decision
// is at least AUDIT.
func (l *PowerShellLane) read(text string, depth int, st *readState) policy.EvalResult {
	reader := l.Reader
	if reader == nil {
		reader = psreader.Read
	}
	f := reader(text, l.Env)
	// An evaluation the hook's watchdog has already answered parks here and
	// between nested readings (#4785); otherwise a no-op.
	abandon.Checkpoint()
	if l.NativeBridge {
		st.native = append(st.native, f.Native...)
	}
	own := l.Engine.EvaluateFacts(f, l.Cwd, l.Opts)
	// The shell pipeline's inline-secrets heuristic over this text as
	// written (#4802), so a token in a cmdlet call, an assignment or a .NET
	// call decides what the Bash tool decides on the same text: BLOCK
	// guardian-secrets_in_command. Here, in the lane, because the lane is
	// what both surfaces run on a call no POSIX lane reads (the hook's
	// Claude Code PowerShell row, shield-server's Python-client call), and
	// because only the lane has the text: EvaluateFacts decides on facts.
	// Every level a nested interpreter reaches is read too, as the lane
	// reads it for protected paths (a decoded -EncodedCommand included). It
	// is combined as a nested reading is: stricter wins, this text's own
	// record on a tie, except that a rule-less AUDIT gives its record to the
	// heuristic's AUDIT (#4779). Raise-only. Past InlineSecretsBytes (the
	// server's bound) the text is not read by it, and a note says so.
	if l.InlineSecretsBytes > 0 && len(text) > l.InlineSecretsBytes {
		own = combineNested([]policy.EvalResult{own}, []analyzer.Note{{Kind: string(facts.NoteParseError),
			Detail: fmt.Sprintf("inline-secrets heuristic: the text of %d bytes passed the bound of %d bytes and was not read", len(text), l.InlineSecretsBytes)}})
	} else if sec, ok := l.Engine.EvaluateInlineSecrets(text); ok {
		own = combineNested([]policy.EvalResult{own, sec}, nil)
	}
	if len(f.Nested) == 0 {
		return own
	}

	results := []policy.EvalResult{own}
	var unread []analyzer.Note
	inResults := map[string]bool{} // nested POSIX texts already in results
	for _, n := range f.Nested {
		abandon.Checkpoint()
		if depth+1 > l.MaxDepth {
			unread = append(unread, analyzer.Note{Kind: analyzer.NoteNestedDepthExceeded,
				Detail: fmt.Sprintf("%s at nesting depth %d, past the bound of %d (max_parse_depth): its text was not read", n.Exe, depth+1, l.MaxDepth)})
			continue
		}
		lane, ok := route.NestedLane(n.Exe)
		if !ok && n.Exe == "cmd" {
			// cmd /c runs its text as a command line; when that line starts
			// an interpreter the router knows (`cmd /c powershell -enc …`,
			// the standard Windows launcher), the text re-enters that lane.
			// The cmd hop is this one nesting level.
			lane, ok = route.NestedLane(CmdProgram(n.Text))
			if !ok {
				// No lane reads cmd's own grammar, but its commands are still
				// read, each as one more reading (Windows round 4): a delete
				// built-in (rd, del) as the Remove-Item call with its effect,
				// and every other command's words, as cmd hands them to a
				// program, through the native-command bridge, so a native
				// program behind `cmd /c` reads as it does written directly.
				// The routing_gap note below stays: cmd's grammar is unread.
				for _, words := range CmdCommands(n.Text) {
					if ps, del := CmdDeleteAsPowerShell(words); del {
						results = append(results, l.read(ps, depth+1, st))
					} else if l.NativeBridge {
						st.native = append(st.native, cmdNative(words))
					}
				}
			}
		}
		switch {
		case !ok:
			unread = append(unread, analyzer.Note{Kind: analyzer.NoteRoutingGap,
				Detail: fmt.Sprintf("nested interpreter %q at depth %d: no lane reads its text", n.Exe, depth+1)})
		case lane == route.PowerShell:
			results = append(results, l.read(n.Text, depth+1, st))
		case lane == route.POSIX:
			if inResults[n.Text] {
				continue // the same reading is already combined at this level
			}
			r, done := st.posix[n.Text]
			if !done {
				if l.NestedPOSIXBound > 0 && len(st.posix) >= l.NestedPOSIXBound {
					if !st.bounded {
						st.bounded = true
						unread = append(unread, analyzer.Note{Kind: string(facts.NoteParseError),
							Detail: fmt.Sprintf("more than %d distinct nested bash/sh texts in one call: the rest were not read", l.NestedPOSIXBound)})
					}
					continue
				}
				r = l.POSIX(n.Text)
				st.posix[n.Text] = r
			}
			inResults[n.Text] = true
			results = append(results, r)
		}
	}
	return combineNested(results, unread)
}

// CmdProgram is the program a cmd command line starts: its first word, which
// a leading double quote delimits (`"C:\Program Files\PowerShell\7\pwsh.exe"
// -c …`) and otherwise ends at the first space or tab, as cmd finds the
// program.
func CmdProgram(text string) string {
	t := strings.TrimLeft(text, " \t")
	if strings.HasPrefix(t, `"`) {
		if end := strings.IndexByte(t[1:], '"'); end >= 0 {
			return t[1 : 1+end]
		}
		return t[1:]
	}
	if end := strings.IndexAny(t, " \t"); end >= 0 {
		return t[:end]
	}
	return t
}

// CmdCommands splits a cmd command line into its commands' words, as cmd
// hands them to a program: commands end at an unquoted &, &&, |, || or a
// line break; words at an unquoted space, tab, comma, semicolon or equals
// sign; double quotes group a word and are removed; `^` escapes the next
// byte. A redirection (`>`, `<`) and its target are dropped, and so is an
// `@` (echo off) before a command. Read for the lane's extra readings of a
// cmd line, never for a decision of its own.
func CmdCommands(text string) [][]string {
	var cmds [][]string
	var words []string
	var w strings.Builder
	inWord, quoted, target := false, false, false
	flushWord := func() {
		if inWord {
			if !target {
				words = append(words, w.String())
			}
			target = false
		}
		w.Reset()
		inWord = false
	}
	flushCmd := func() {
		flushWord()
		target = false
		if len(words) > 0 {
			if words[0] = strings.TrimPrefix(words[0], "@"); words[0] == "" {
				words = words[1:]
			}
		}
		if len(words) > 0 {
			cmds = append(cmds, words)
		}
		words = nil
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '"':
			quoted, inWord = !quoted, true
		case quoted:
			w.WriteByte(c)
		case c == '^' && i+1 < len(text):
			i++
			w.WriteByte(text[i])
			inWord = true
		case c == '&' || c == '|' || c == '\n' || c == '\r':
			flushCmd()
		case c == '>' || c == '<':
			flushWord()
			target = true
		case c == ' ' || c == '\t' || c == ',' || c == ';' || c == '=':
			flushWord()
		default:
			w.WriteByte(c)
			inWord = true
		}
	}
	flushCmd()
	return cmds
}

// cmdDeleteBuiltins are cmd.exe's delete commands. cmd runs them itself, so
// no program starts and neither a lane nor the native-command bridge sees
// them.
var cmdDeleteBuiltins = map[string]bool{"rd": true, "rmdir": true, "del": true, "erase": true}

// CmdDeleteAsPowerShell reads one cmd command (CmdCommands) that is one of
// cmd's delete built-ins (rd, rmdir, del, erase) as the Remove-Item call with
// the same effect: `rd /s /q C:\` is `Remove-Item -Path 'C:\' -Recurse
// -Force`. `/s` (subdirectories) is -Recurse; `/q` (no prompt) and `/f`
// (read-only files too) are -Force, the roles rm's -f plays; every other
// switch is dropped, and switches may be joined (`rd/s/q`). ok is false for any other command, or
// one that names no target. The text is only ever an additional reading, so
// a command it misreads costs at most an extra BLOCK on a delete.
func CmdDeleteAsPowerShell(words []string) (string, bool) {
	if len(words) == 0 {
		return "", false
	}
	prog, switches, _ := strings.Cut(words[0], "/")
	if !cmdDeleteBuiltins[asciiLowerString(prog)] {
		return "", false
	}
	recurse, force := false, false
	var targets []string
	for _, s := range append([]string{"/" + switches}, words[1:]...) {
		if !strings.HasPrefix(s, "/") {
			targets = append(targets, "'"+strings.ReplaceAll(s, "'", "''")+"'")
			continue
		}
		for _, sw := range strings.Split(s[1:], "/") {
			switch {
			case strings.EqualFold(sw, "s"):
				recurse = true
			case strings.EqualFold(sw, "q"), strings.EqualFold(sw, "f"):
				force = true
			}
		}
	}
	if len(targets) == 0 {
		return "", false
	}
	ps := "Remove-Item -Path " + strings.Join(targets, ",")
	if recurse {
		ps += " -Recurse"
	}
	if force {
		ps += " -Force"
	}
	return ps, true
}

// cmdNative is one cmd command's words as the native-command bridge reads a
// program's argument vector: literal words, one pipeline of one stage.
func cmdNative(words []string) facts.NativeStatement {
	argv := make(facts.Argv, len(words))
	for i, w := range words {
		argv[i] = facts.Word{{Text: w}}
	}
	return facts.NativeStatement{Pipelines: []facts.NativePipeline{{Stages: []facts.Argv{argv}}}}
}

func asciiLowerString(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// combineNested combines a text's own result (results[0]) with its nested
// readings' (route.Combine: stricter wins, the text's own on a tie, except
// that in audit-only mode a BLOCK that was not downgraded wins a tie with a
// downgraded one, and a rule-less AUDIT gives its record to a tied AUDIT
// that names a rule, #4779; the AUDIT floor when anything was not read). The
// result is the kept reading's record, so its rules are the ones that
// decided, with the combined decision. It carries the text's own notes, the
// notes on what was not read, every nested reading's uncertainty notes, the
// kept nested reading's notes, and, when the AUDIT tie rule moved the record
// off a nested reading, that reading's notes.
func combineNested(results []policy.EvalResult, unread []analyzer.Note) policy.EvalResult {
	verdicts := make([]route.Verdict, len(results))
	for i := range results {
		verdicts[i] = FactsVerdict(route.PowerShell, &results[i], nil)
	}
	for _, n := range unread {
		verdicts[0].Notes = append(verdicts[0].Notes, route.Note{Kind: n.Kind, Detail: n.Detail, Uncertain: true})
	}
	c := route.Combine(verdicts)

	kept := results[c.Winner]
	kept.Decision, kept.OriginalDecision = policy.Decision(c.Decision), policy.Decision(c.OriginalDecision)
	notes := append([]analyzer.Note(nil), results[0].Notes...)
	for _, n := range unread {
		notes = analyzer.AppendNote(notes, n)
	}
	for i := 1; i < len(results); i++ {
		for _, n := range results[i].Notes {
			if i == c.Winner || i == c.Pick || UncertainNote(n.Kind) {
				notes = analyzer.AppendNote(notes, n)
			}
		}
	}
	kept.Notes = notes
	return kept
}
