package policy

import (
	"slices"
	"testing"
)

// Pins for the #4387 /private alias reading (EvaluatePrivateAlias). The safety
// argument: the as-written evaluation is unchanged, and the short reading can
// only raise. Each test names the mutant it exists to kill.
//
// System paths are assembled at runtime: the hook reads test sources as
// commands.

func privateAliasEngine(t *testing.T, protected []string, rules ...Rule) *Engine {
	t.Helper()
	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = protected
	pol.Rules = append(pol.Rules, rules...)
	engine, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

// Mutant: the short reading rewrites the command but not the argv paths
// normalize extracted. The shipped policy template protects /etc/**, and a
// protected_paths hit is decided on those paths, so the alias spelling would
// keep walking past it.
func TestPrivateAlias_PathsReadShort_4387(t *testing.T) {
	engine := privateAliasEngine(t, []string{"/etc/**"})
	alias := "/private" + "/etc/hosts"
	cmd := "wc -l " + alias
	paths := []string{alias}

	// Control: the short spelling is protected, so the wiring is live.
	if r := engine.EvaluatePrivateAlias("wc -l /etc/hosts", []string{"/etc/hosts"}, nil, "", PrivateAliasOff); r.Decision != DecisionBlock {
		t.Fatalf("control: short spelling = %v %v; want BLOCK via protected-path", r.Decision, r.TriggeredRules)
	}
	if r := engine.EvaluatePrivateAlias(cmd, paths, nil, "", PrivateAliasOff); r.Decision == DecisionBlock {
		t.Fatalf("control: the alias must leak with the reading off (the pre-#4387 gap); got %v %v", r.Decision, r.TriggeredRules)
	}
	r := engine.EvaluatePrivateAlias(cmd, paths, nil, "", PrivateAliasStricter)
	if r.Decision != DecisionBlock || !slices.Contains(r.TriggeredRules, "protected-path") {
		t.Errorf("alias spelling decided %v %v; want BLOCK via protected-path", r.Decision, r.TriggeredRules)
	}
	if paths[0] != alias {
		t.Errorf("the caller's paths slice was mutated: %q", paths[0])
	}
}

// Mutant: cwd is not read short. A relative protected_paths pattern is matched
// against the path made relative to cwd. When the harness reports the cwd in
// its /private spelling and the command names the short one (or the other way
// round), the path looks like it sits outside cwd, so cwd must read short with
// the path.
func TestPrivateAlias_CwdReadsShort_4387(t *testing.T) {
	engine := privateAliasEngine(t, []string{"secrets/**"})
	cwdShort, cwdAlias := "/var/app", "/private"+"/var/app"
	cmd := "cat " + cwdShort + "/secrets/token"
	paths := []string{cwdShort + "/secrets/token"}

	if r := engine.EvaluatePrivateAlias(cmd, paths, nil, cwdShort, PrivateAliasOff); r.Decision != DecisionBlock {
		t.Fatalf("control: relative-pattern hit under the short cwd = %v %v; want BLOCK", r.Decision, r.TriggeredRules)
	}
	if r := engine.EvaluatePrivateAlias(cmd, paths, nil, cwdAlias, PrivateAliasOff); r.Decision == DecisionBlock {
		t.Fatalf("control: with the reading off, the alias cwd must leak (the pre-#4387 gap); got %v", r.Decision)
	}
	r := engine.EvaluatePrivateAlias(cmd, paths, nil, cwdAlias, PrivateAliasStricter)
	if r.Decision != DecisionBlock {
		t.Errorf("relative-pattern hit under the alias cwd decided %v %v; want BLOCK (cwd must read short with the path)", r.Decision, r.TriggeredRules)
	}
}

// Mutant: the short reading replaces the as-written one instead of being
// compared with it. A rule that matches /private literally must keep firing,
// and at an equal decision the as-written record is kept (no tie rule).
func TestPrivateAlias_KeepsLiteralPrivateRule_4387(t *testing.T) {
	literal := Rule{
		ID:       "t-literal-private",
		Match:    Match{CommandRegex: `/private/etc/agent-test\.conf`},
		Decision: DecisionBlock,
		Reason:   "test",
	}
	short := Rule{
		ID:       "t-short-audit",
		Match:    Match{CommandRegex: `\s/etc/agent-test\.conf`},
		Decision: DecisionAudit,
		Reason:   "test",
	}
	engine := privateAliasEngine(t, nil, literal, short)
	cmd := "cat /private" + "/etc/agent-test.conf"

	off := engine.EvaluatePrivateAlias(cmd, nil, nil, "", PrivateAliasOff)
	if off.Decision != DecisionBlock || !slices.Contains(off.TriggeredRules, literal.ID) {
		t.Fatalf("control: as written = %v %v; want BLOCK by %s", off.Decision, off.TriggeredRules, literal.ID)
	}
	if on := engine.EvaluatePrivateAlias(cmd, nil, nil, "", PrivateAliasOn); slices.Contains(on.TriggeredRules, literal.ID) {
		t.Fatalf("control: the short reading alone must not see the literal rule (it is what a replacing rewrite would lose); got %v", on.TriggeredRules)
	}
	got := engine.EvaluatePrivateAlias(cmd, nil, nil, "", PrivateAliasStricter)
	if got.Decision != DecisionBlock || !slices.Contains(got.TriggeredRules, literal.ID) {
		t.Errorf("got %v %v; want BLOCK by %s (the literal /private rule must keep firing)", got.Decision, got.TriggeredRules, literal.ID)
	}

	// Equal decision: an AUDIT-level literal rule and an AUDIT-level short
	// rule. The as-written record is kept.
	literal.Decision = DecisionAudit
	engine = privateAliasEngine(t, nil, literal, short)
	got = engine.EvaluatePrivateAlias(cmd, nil, nil, "", PrivateAliasStricter)
	if got.Decision != DecisionAudit || !slices.Contains(got.TriggeredRules, literal.ID) || slices.Contains(got.TriggeredRules, short.ID) {
		t.Errorf("tie: got %v %v; want AUDIT with the as-written record [%s] only", got.Decision, got.TriggeredRules, literal.ID)
	}
}

// Mutant: the short reading is skipped when only a path, or only cwd,
// carries the alias (the command text itself has none).
func TestPrivateAlias_RunsWhenOnlyPathsOrCwdCarryTheAlias_4387(t *testing.T) {
	engine := privateAliasEngine(t, []string{"/etc/**"})
	paths := []string{"/private" + "/etc/hosts"}
	if r := engine.EvaluatePrivateAlias("wc -l hosts", paths, nil, "", PrivateAliasStricter); r.Decision != DecisionBlock {
		t.Errorf("paths only: decided %v %v; want BLOCK via protected-path", r.Decision, r.TriggeredRules)
	}
	rel := privateAliasEngine(t, []string{"secrets/**"})
	if r := rel.EvaluatePrivateAlias("cat /var/app/secrets/token", []string{"/var/app/secrets/token"}, nil, "/private"+"/var/app", PrivateAliasStricter); r.Decision != DecisionBlock {
		t.Errorf("cwd only: decided %v %v; want BLOCK via protected-path", r.Decision, r.TriggeredRules)
	}
}

// Mutant: a tie rule (caseFoldResult's "strictly richer record wins"). At an
// equal decision the as-written record is kept even when the short reading
// names more rules, so a command whose decision the reading does not change
// carries exactly main's record: the short reading can name AUDIT rules on
// the short path that no decision needed, and a receipt should not gain them.
func TestPrivateAlias_NoTieRule_4387(t *testing.T) {
	both := Rule{ID: "t-both", Match: Match{CommandRegex: `agent-tie\.log`}, Decision: DecisionAudit, Reason: "test"}
	short := Rule{ID: "t-short-only", Match: Match{CommandRegex: `\s/var/agent-tie\.log`}, Decision: DecisionAudit, Reason: "test"}
	engine := privateAliasEngine(t, nil, both, short)
	cmd := "cat /private" + "/var/agent-tie.log"
	if on := engine.EvaluatePrivateAlias(cmd, nil, nil, "", PrivateAliasOn); !slices.Contains(on.TriggeredRules, both.ID) || !slices.Contains(on.TriggeredRules, short.ID) {
		t.Fatalf("control: the short reading must name both rules (a strict superset); got %v", on.TriggeredRules)
	}
	got := engine.EvaluatePrivateAlias(cmd, nil, nil, "", PrivateAliasStricter)
	if got.Decision != DecisionAudit || !slices.Equal(got.TriggeredRules, []string{both.ID}) {
		t.Errorf("got %v %v; want AUDIT with the as-written record [%s]", got.Decision, got.TriggeredRules, both.ID)
	}
}

// The reading is never below the as-written result, including where the short
// reading alone decides LOWER (an ALLOW that only matches the short text).
func TestPrivateAlias_NeverBelowAsWritten_4387(t *testing.T) {
	block := Rule{ID: "t-block-alias", Match: Match{CommandRegex: `/private/var/agent-x`}, Decision: DecisionBlock, Reason: "test"}
	allow := Rule{ID: "t-allow-short", Match: Match{CommandRegex: `^ls /var/agent-x$`}, Decision: DecisionAllow, Reason: "test"}
	engine := privateAliasEngine(t, nil, block, allow)
	cmd := "ls /private" + "/var/agent-x"
	if on := engine.EvaluatePrivateAlias(cmd, nil, nil, "", PrivateAliasOn); on.Decision == DecisionBlock {
		t.Fatalf("control: the short reading alone must decide below BLOCK here; got %v %v", on.Decision, on.TriggeredRules)
	}
	if got := engine.EvaluatePrivateAlias(cmd, nil, nil, "", PrivateAliasStricter); got.Decision != DecisionBlock {
		t.Errorf("got %v %v; want BLOCK (the as-written decision)", got.Decision, got.TriggeredRules)
	}
}
