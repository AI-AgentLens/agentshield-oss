package policy

import "testing"

// TestCustomRulesKeyedOnWrittenPaths pins the two Codex pass-1 counterexamples
// on #3993 that only a custom policy can express. Both regressed when the first
// version of #3991 rewrote CommandSegment.Executable to the program name for
// every consumer:
//
//   - A custom BLOCK regex written against a path (`^/tmp/x/dd`) was OVERRIDDEN:
//     the built-in st-allow-dd-to-file started matching the planted /tmp/x/dd as
//     "dd", and its structural-override ALLOW suppressed the BLOCK.
//   - A custom structural rule keyed on a path (`executable: /opt/review/tool`)
//     stopped matching at all, because the executable it compared against had
//     become "tool".
//
// Executable now keeps the written spelling; only restricting rules also see
// the program name, and only as a union. Both rules BLOCK again, as on main.
func TestCustomRulesKeyedOnWrittenPaths(t *testing.T) {
	pol := DefaultPolicy()
	pol.Rules = append(pol.Rules,
		Rule{
			ID:       "custom-block-planted-dd",
			Match:    Match{CommandRegex: `^/tmp/x/dd\b`},
			Decision: DecisionBlock,
			Reason:   "custom rule keyed on a written path",
		},
		Rule{
			ID:       "custom-block-review-tool",
			Match:    Match{Structural: &StructuralMatch{Executable: StringOrList{"/opt/review/tool"}}},
			Decision: DecisionBlock,
			Reason:   "custom structural rule keyed on a written path",
		},
	)
	engine, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	cases := []struct{ cmd, rule string }{
		{"/tmp/x/dd if=/dev/zero of=./disk.img bs=1M count=1", "custom-block-planted-dd"},
		{"/opt/review/tool --scan .", "custom-block-review-tool"},
	}
	for _, c := range cases {
		res := engine.Evaluate(c.cmd, nil)
		if res.Decision != DecisionBlock || !has(res.TriggeredRules, c.rule) {
			t.Errorf("%q: decision=%v rules=%v; want BLOCK by %s", c.cmd, res.Decision, res.TriggeredRules, c.rule)
		}
		if has(res.TriggeredRules, "st-allow-dd-to-file") {
			t.Errorf("%q: a planted dd earned st-allow-dd-to-file (rules=%v)", c.cmd, res.TriggeredRules)
		}
	}
}

// TestProgramNameMatchEarnsNoExcludeLabel pins that attribution — which
// statement a match belongs to, for command_intent_exclude and
// command_intent_downgrade — reads only the as-written candidates, never the
// program-name renderings (#3991, restrict-only). A match found only by reading
// a path as a program must not be excused by a label on that statement.
//
// The witness needs a label that a path-spelled statement can carry: the
// is_self_mgmt classifier is an unanchored substring test, so
// `/opt/x/agentshield mcp-eval …` is labelled self-management today (a
// pre-existing name-trust, listed as a residual on the PR). The rule matches
// only through the program name, so with attribution kept as written no
// statement is counted and the exclude cannot hold. Feeding the program-name
// candidates into attribution (mutation M4 on #3993) makes the labelled
// statement count and excuses the match; this test is what catches it.
// Multi-statement on purpose: a single statement is attributed by label alone.
func TestProgramNameMatchEarnsNoExcludeLabel(t *testing.T) {
	pol := DefaultPolicy()
	pol.Rules = append(pol.Rules, Rule{
		ID: "custom-block-selfmgmt-probe",
		Match: Match{
			CommandRegex:         `^agentshield\s+mcp-eval\s+zzprobe\b`,
			CommandIntentExclude: []string{"is_self_mgmt"},
		},
		Decision: DecisionBlock,
		Reason:   "probe for restrict-only attribution",
	})
	engine, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	cmd := "echo hi; /opt/x/agentshield mcp-eval zzprobe"
	res := engine.Evaluate(cmd, nil)
	if res.Decision != DecisionBlock || !has(res.TriggeredRules, "custom-block-selfmgmt-probe") {
		t.Errorf("%q: decision=%v rules=%v; want BLOCK — a program-name-only match must not be excused by a label", cmd, res.Decision, res.TriggeredRules)
	}
}

// Codex pass 2 on #3993 found three relaxations, each needing a custom policy
// — which is why the corpus sweep under the shipped default could not see them
// — and two gaps. Each is pinned here as it was reported. R1-R3 are the reason
// #3991's guarantee is structural (EvaluateProgramPaths keeps ON only when
// strictly more restrictive) rather than a per-consumer classification.

func customEngine(t *testing.T, def Decision, rules ...Rule) *Engine {
	t.Helper()
	pol := DefaultPolicy()
	pol.Defaults.Decision = def
	pol.Rules = append(pol.Rules, rules...)
	engine, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	return engine
}

// R1: PositionExcluded also runs for ALLOW rules. Widening the redacted forms
// with the program-name reading CANCELS an ALLOW rule's position exclusion:
// the `/tmp/x/zzprobe` statement read as `zzprobe` keeps the ALLOW alive, and
// the default BLOCK is replaced by ALLOW. Closed twice: the widened forms go
// only to restricting rules, and the engine's max keeps OFF's BLOCK anyway.
func TestCodexR1AllowPositionExcludeNotCancelled(t *testing.T) {
	engine := customEngine(t, DecisionBlock, Rule{
		ID: "custom-allow-zzprobe",
		Match: Match{
			CommandRegex:           `(^|[ "])zzprobe\b`,
			CommandPositionExclude: []string{"search_needle"},
		},
		Decision: DecisionAllow,
		Reason:   "R1 witness",
	})
	cmd := `grep "zzprobe" notes.txt; /tmp/x/zzprobe`
	if res := engine.Evaluate(cmd, nil); res.Decision != DecisionBlock {
		t.Errorf("%q: decision=%v rules=%v; want BLOCK (main)", cmd, res.Decision, res.TriggeredRules)
	}
}

// R2: with defaults.decision BLOCK, ON's sem-audit-nmap finding (AUDIT)
// displaces the default: "AUDIT is restricting" is false whenever the
// default is stricter than AUDIT.
func TestCodexR2AuditFindingDoesNotDisplaceStricterDefault(t *testing.T) {
	engine := customEngine(t, DecisionBlock)
	cmd := "/tmp/x/nmap example.com"
	if res := engine.Evaluate(cmd, nil); res.Decision != DecisionBlock {
		t.Errorf("%q: decision=%v rules=%v; want BLOCK (main: the default)", cmd, res.Decision, res.TriggeredRules)
	}
}

// R3: the combiner ranks REQUIRE_APPROVAL below AUDIT (decisionToSeverity has
// no case for it — pre-existing, #3298, NOT changed here), so ON adding
// sem-audit-nmap turns a custom REQUIRE_APPROVAL into AUDIT. The engine's
// max uses its own total order, where REQUIRE_APPROVAL > AUDIT.
func TestCodexR3RequireApprovalNotDisplacedByAudit(t *testing.T) {
	engine := customEngine(t, DecisionAudit, Rule{
		ID:       "custom-ra-planted-nmap",
		Match:    Match{CommandRegex: `^/tmp/x/nmap\b`},
		Decision: DecisionRequireApproval,
		Reason:   "R3 witness",
	})
	cmd := "/tmp/x/nmap example.com"
	res := engine.Evaluate(cmd, nil)
	if res.Decision != DecisionRequireApproval || !has(res.TriggeredRules, "custom-ra-planted-nmap") {
		t.Errorf("%q: decision=%v rules=%v; want REQUIRE_APPROVAL by custom-ra-planted-nmap (main)", cmd, res.Decision, res.TriggeredRules)
	}
}

// G5: program-name renderings used to reach only position-sensitive rules
// (the per-statement retry). An unanchored pattern and a `\A` anchor — which
// isPositionSensitive does not recognise — both missed the path spelling.
func TestCodexG5UnanchoredRulesSeeProgramNames(t *testing.T) {
	engine := customEngine(t, DecisionAudit,
		Rule{ID: "custom-block-sudo-zzprobe", Match: Match{CommandRegex: `sudo\s+zzprobe\b`}, Decision: DecisionBlock, Reason: "G5 witness"},
		Rule{ID: "custom-block-A-zzprobe", Match: Match{CommandRegex: `\Azzprobe\b`}, Decision: DecisionBlock, Reason: "G5 witness"},
	)
	cases := []struct{ cmd, rule string }{
		{"sudo /tmp/x/zzprobe --go", "custom-block-sudo-zzprobe"},
		{"/tmp/x/zzprobe --go", "custom-block-A-zzprobe"},
		// The bare spellings, for contrast — these always matched.
		{"sudo zzprobe --go", "custom-block-sudo-zzprobe"},
		{"zzprobe --go", "custom-block-A-zzprobe"},
	}
	for _, c := range cases {
		res := engine.Evaluate(c.cmd, nil)
		if res.Decision != DecisionBlock || !has(res.TriggeredRules, c.rule) {
			t.Errorf("%q: decision=%v rules=%v; want BLOCK by %s", c.cmd, res.Decision, res.TriggeredRules, c.rule)
		}
	}
}

// TestStricterResult is the max() #3991's guarantee rests on, over every
// ordered pair of decisions: ON replaces OFF only when strictly more
// restrictive under ALLOW < AUDIT < REQUIRE_APPROVAL < BLOCK. In particular a
// REQUIRE_APPROVAL is never replaced by AUDIT or ALLOW — the combiner's
// decisionToSeverity would rank REQUIRE_APPROVAL lowest (#3298).
func TestStricterResult(t *testing.T) {
	order := []Decision{DecisionAllow, DecisionAudit, DecisionRequireApproval, DecisionBlock}
	for i, off := range order {
		for j, on := range order {
			got := stricterResult(
				EvalResult{Decision: off, TriggeredRules: []string{"off"}},
				EvalResult{Decision: on, TriggeredRules: []string{"on"}},
			)
			want := "off"
			if j > i {
				want = "on"
			}
			if got.TriggeredRules[0] != want || (want == "off" && got.Decision != off) || (want == "on" && got.Decision != on) {
				t.Errorf("stricterResult(off=%s, on=%s) returned %s (%s); want %s", off, on, got.TriggeredRules[0], got.Decision, want)
			}
		}
	}
	// Anything outside the order never replaces, and is never replaced by
	// something the order cannot compare it with.
	if got := stricterResult(EvalResult{Decision: DecisionAudit}, EvalResult{Decision: "SOMETHING"}); got.Decision != DecisionAudit {
		t.Errorf("unknown ON decision replaced OFF: %v", got.Decision)
	}
	if got := stricterResult(EvalResult{Decision: "SOMETHING"}, EvalResult{Decision: DecisionBlock}); got.Decision != "SOMETHING" {
		t.Errorf("unknown OFF decision was replaced: %v", got.Decision)
	}
}

// TestStricterResult_AuditOnlyRanksPreDowngrade pins #4021. Under audit-only
// both results arrive already downgraded, so the ranking has to read
// OriginalDecision, or a downgraded BLOCK ties a plain AUDIT and loses its
// "would have blocked" record.
func TestStricterResult_AuditOnlyRanksPreDowngrade(t *testing.T) {
	cases := []struct {
		name     string
		off, on  EvalResult
		want     string
		wantOrig Decision
	}{
		{"ON would have blocked, OFF plain audit",
			EvalResult{Decision: DecisionAudit, TriggeredRules: []string{"off"}},
			EvalResult{Decision: DecisionAudit, OriginalDecision: DecisionBlock, TriggeredRules: []string{"on"}},
			"on", DecisionBlock},
		{"ON would have blocked, OFF would have asked",
			EvalResult{Decision: DecisionAudit, OriginalDecision: DecisionRequireApproval, TriggeredRules: []string{"off"}},
			EvalResult{Decision: DecisionAudit, OriginalDecision: DecisionBlock, TriggeredRules: []string{"on"}},
			"on", DecisionBlock},
		{"OFF would have blocked, ON would have asked",
			EvalResult{Decision: DecisionAudit, OriginalDecision: DecisionBlock, TriggeredRules: []string{"off"}},
			EvalResult{Decision: DecisionAudit, OriginalDecision: DecisionRequireApproval, TriggeredRules: []string{"on"}},
			"off", DecisionBlock},
		{"tie on the original keeps OFF",
			EvalResult{Decision: DecisionAudit, OriginalDecision: DecisionBlock, TriggeredRules: []string{"off"}},
			EvalResult{Decision: DecisionAudit, OriginalDecision: DecisionBlock, TriggeredRules: []string{"on"}},
			"off", DecisionBlock},
		{"ON plain audit never replaces OFF's would-have-blocked",
			EvalResult{Decision: DecisionAudit, OriginalDecision: DecisionBlock, TriggeredRules: []string{"off"}},
			EvalResult{Decision: DecisionAudit, TriggeredRules: []string{"on"}},
			"off", DecisionBlock},
	}
	for _, c := range cases {
		got := stricterResult(c.off, c.on)
		if got.TriggeredRules[0] != c.want || got.OriginalDecision != c.wantOrig || got.Decision != DecisionAudit {
			t.Errorf("%s: got %s (%s, original %q); want %s (AUDIT, original %q)",
				c.name, got.TriggeredRules[0], got.Decision, got.OriginalDecision, c.want, c.wantOrig)
		}
	}
}

// TestProgramPathCatchVisibleInAuditOnly is #4021 end to end: in shadow mode a
// path-spelled command word that production would BLOCK through the program
// name must say so on the record, exactly as the bare spelling does, while the
// decision stays AUDIT.
func TestProgramPathCatchVisibleInAuditOnly(t *testing.T) {
	pol := DefaultPolicy()
	pol.Rules = append(pol.Rules, Rule{
		ID:       "custom-block-zzprobe",
		Match:    Match{CommandRegex: `^zzprobe\b`},
		Decision: DecisionBlock,
		Reason:   "probe keyed on a program name",
	})
	engine, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	for _, cmd := range []string{"zzprobe --go", "/tmp/x/zzprobe --go"} {
		engine.SetMode("")
		if res := engine.Evaluate(cmd, nil); res.Decision != DecisionBlock {
			t.Fatalf("enforce %q: got %s %v, want BLOCK (precondition)", cmd, res.Decision, res.TriggeredRules)
		}
		engine.SetMode("audit-only")
		res := engine.Evaluate(cmd, nil)
		if res.Decision != DecisionAudit || res.OriginalDecision != DecisionBlock || !has(res.TriggeredRules, "custom-block-zzprobe") {
			t.Errorf("audit-only %q: got %s original=%q rules=%v; want AUDIT original=BLOCK by custom-block-zzprobe",
				cmd, res.Decision, res.OriginalDecision, res.TriggeredRules)
		}
	}
}
