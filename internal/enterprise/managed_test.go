package enterprise

import (
	"testing"
)

func TestSelfProtect_BlockBypassEnv(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "export AGENTSHIELD_BYPASS=1"}
	mw(ctx, func() { t.Error("next() should not be called when blocked") })
	if !ctx.Blocked {
		t.Error("expected command to be blocked")
	}
}

// TestSelfProtect_BypassEnv_AllSettingForms pins #3212: sp-block-bypass-env was
// anchored on the literal `export` keyword, which is one of five ways to set
// this variable and the least likely to be typed. Measured before the fix,
// four of the five went unblocked -- including `AGENTSHIELD_BYPASS=1 claude`, the bare inline
// prefix, which is the form anyone would actually reach for and the form a
// bypass instruction would be written in.
//
// BypassGuard independently ignores the variable in managed mode, so the
// bypass never *worked*. This rule exists to block and audit the ATTEMPT, on
// the layer that backs the claim that AgentShield cannot be turned off by an
// AI agent -- and a tamper layer that misses four attempts in five is not one.
func TestSelfProtect_BypassEnv_AllSettingForms(t *testing.T) {
	V := "AGENTSHIELD_BYPASS"
	for _, cmd := range []string{
		"export " + V + "=1",
		"declare -x " + V + "=1",
		"typeset -x " + V + "=1",
		"declare -gx " + V + "=1",
		V + "=1 claude",
		"env " + V + "=1 claude",
		V + " = 1",
	} {
		t.Run(cmd, func(t *testing.T) {
			mw := SelfProtect()
			ctx := &EvalContext{Command: cmd}
			mw(ctx, func() { t.Error("next() should not be called when blocked") })
			if !ctx.Blocked {
				t.Errorf("expected %q to be blocked", cmd)
			}
		})
	}
}

// TestSelfProtect_BypassEnv_ReadsStillPass is the other half of the trade.
// Anchoring on the assignment rather than the keyword widens the rule, so the
// boundary has to be pinned: a pure READ carries no `=` and must keep passing.
// Without this, a later "tighten it further" edit that starts matching the
// bare variable name would sail through -- and reading an env var is not an
// attempt to disable anything.
func TestSelfProtect_BypassEnv_ReadsStillPass(t *testing.T) {
	V := "AGENTSHIELD_BYPASS"
	for _, cmd := range []string{
		"printenv " + V,
		"echo $" + V,
		"grep -r " + V + " docs/",
		"env | grep " + V,
	} {
		t.Run(cmd, func(t *testing.T) {
			mw := SelfProtect()
			called := false
			ctx := &EvalContext{Command: cmd}
			mw(ctx, func() { called = true })
			if ctx.Blocked {
				t.Errorf("expected %q to pass (read, not an assignment)", cmd)
			}
			if !called {
				t.Errorf("expected next() to run for %q", cmd)
			}
		})
	}
}

// TestSelfProtect_EscapeSpliceBypass_BypassEnv is the #3211 regression, and it
// is deliberately a re-add: #3210 wrote this test, found it failed for a reason
// outside that PR's scope, and removed it rather than weaken it. The reason was
// this — mvdan/sh rejects the whole command as an invalid var name, so
// DequoteCommand returned its no-op sentinel and the self-protection layer saw
// nothing to match against. One backslash in the variable name.
//
// That is the layer behind "AgentShield cannot be turned off by an AI agent",
// so a silent hole in it is worth a named test rather than a table row.
func TestSelfProtect_EscapeSpliceBypass_BypassEnv(t *testing.T) {
	V := "AGENTSHIE" + "LD_BYPASS"
	spliced := V[:len(V)-1] + "\\" + V[len(V)-1:]
	for _, cmd := range []string{
		"export " + spliced + "=1",
		"declare -x " + spliced + "=1",
		"typeset -x " + spliced + "=1",
	} {
		t.Run(cmd, func(t *testing.T) {
			mw := SelfProtect()
			ctx := &EvalContext{Command: cmd}
			mw(ctx, func() { t.Error("next() should not be called when blocked") })
			if !ctx.Blocked {
				t.Errorf("escape-spliced variable name evaded self-protection: %q", cmd)
			}
		})
	}
}

func TestSelfProtect_BlockSetupDisable(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "agentshield setup claude-code --disable"}
	mw(ctx, func() { t.Error("next() should not be called when blocked") })
	if !ctx.Blocked {
		t.Error("expected command to be blocked")
	}
}

func TestSelfProtect_BlockDeleteConfig(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "rm -rf ~/.agentshield/"}
	mw(ctx, func() { t.Error("next() should not be called when blocked") })
	if !ctx.Blocked {
		t.Error("expected command to be blocked")
	}
}

func TestSelfProtect_BlockDeleteHooks(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "rm ~/.claude/settings.json"}
	mw(ctx, func() { t.Error("next() should not be called when blocked") })
	if !ctx.Blocked {
		t.Error("expected command to be blocked")
	}
}

func TestSelfProtect_BlockPolicyWrite(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "echo 'rules: []' > ~/.agentshield/policy.yaml"}
	mw(ctx, func() { t.Error("next() should not be called when blocked") })
	if !ctx.Blocked {
		t.Error("expected command to be blocked")
	}
}

func TestSelfProtect_BlockBinaryReplace(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "cp /tmp/fake /opt/homebrew/bin/agentshield"}
	mw(ctx, func() { t.Error("next() should not be called when blocked") })
	if !ctx.Blocked {
		t.Error("expected command to be blocked")
	}
}

// TestSelfProtect_QuoteSpliceBypass_* close the GuardFall/quote-splice class
// (issue #2813 family: #2813/#2814 structural, #2854 regex, #2945/#2947
// dataflow/stateful, #2984/#2985 datalabel) for the enterprise tamper-
// protection layer. selfProtectRules match ctx.Command directly with no
// dequote fallback — bash's unconditional quote removal makes a spliced
// token like AGENTSHIELD_BYPA'S'S resolve to the real AGENTSHIELD_BYPASS at
// execution, but the raw regex never sees it as a contiguous substring. This
// is the single mechanism behind "AgentShield cannot be turned off by an AI
// agent" (CLAUDE.md, Enterprise Tamper Protection) — every one of the 6
// hardcoded rules shares the same raw-text-match shape and needs the fix.

func TestSelfProtect_QuoteSpliceBypass_BypassEnv(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "export AGENTSHIELD_BYPA'S'S=1"}
	mw(ctx, func() {})
	if !ctx.Blocked {
		t.Error("expected quote-spliced AGENTSHIELD_BYPASS to be blocked")
	}
}

func TestSelfProtect_QuoteSpliceBypass_SetupDisable(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "agentshield setup claude-code --disa'b'le"}
	mw(ctx, func() {})
	if !ctx.Blocked {
		t.Error("expected quote-spliced --disable to be blocked")
	}
}

func TestSelfProtect_QuoteSpliceBypass_DeleteConfig(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "rm -rf ~/.agentshi'e'ld/"}
	mw(ctx, func() {})
	if !ctx.Blocked {
		t.Error("expected quote-spliced ~/.agentshield to be blocked")
	}
}

func TestSelfProtect_QuoteSpliceBypass_DeleteHooks(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "rm ~/.cla'u'de/settings.json"}
	mw(ctx, func() {})
	if !ctx.Blocked {
		t.Error("expected quote-spliced ~/.claude/settings.json to be blocked")
	}
}

func TestSelfProtect_QuoteSpliceBypass_PolicyWrite(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "echo 'rules: []' > ~/.agentshield/poli'c'y.yaml"}
	mw(ctx, func() {})
	if !ctx.Blocked {
		t.Error("expected quote-spliced policy.yaml path to be blocked")
	}
}

func TestSelfProtect_QuoteSpliceBypass_BinaryReplace(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "cp /tmp/fake /opt/homebrew/bin/agentshi'e'ld"}
	mw(ctx, func() {})
	if !ctx.Blocked {
		t.Error("expected quote-spliced agentshield binary path to be blocked")
	}
}

func TestSelfProtect_AllowSafeCommand(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "ls -la"}
	nextCalled := false
	mw(ctx, func() { nextCalled = true })
	if ctx.Blocked {
		t.Error("safe command should not be blocked")
	}
	if !nextCalled {
		t.Error("next() should be called for safe commands")
	}
}

func TestSelfProtect_NotLoadedInNonManaged(t *testing.T) {
	// Verify the middleware chain is empty when no managed config exists
	// This test validates the buildMiddlewareChain logic pattern
	cfg := LoadManagedConfigFrom("/nonexistent/managed.json")
	if cfg != nil {
		t.Error("expected nil config for nonexistent file")
	}
}

func TestRunChain_Order(t *testing.T) {
	var order []int
	mw1 := func(ctx *EvalContext, next func()) {
		order = append(order, 1)
		next()
	}
	mw2 := func(ctx *EvalContext, next func()) {
		order = append(order, 2)
		next()
	}
	mw3 := func(ctx *EvalContext, next func()) {
		order = append(order, 3)
		next()
	}

	ctx := &EvalContext{Command: "test"}
	RunChain(ctx, []EvalMiddleware{mw1, mw2, mw3})

	if len(order) != 3 || order[0] != 1 || order[1] != 2 || order[2] != 3 {
		t.Errorf("expected chain order [1,2,3], got %v", order)
	}
}

func TestRunChain_ShortCircuit(t *testing.T) {
	var order []int
	mw1 := func(ctx *EvalContext, next func()) {
		order = append(order, 1)
		ctx.Blocked = true
		// Don't call next()
	}
	mw2 := func(ctx *EvalContext, next func()) {
		order = append(order, 2)
		next()
	}

	ctx := &EvalContext{Command: "test"}
	RunChain(ctx, []EvalMiddleware{mw1, mw2})

	if len(order) != 1 {
		t.Errorf("expected only mw1 to run, got %v", order)
	}
	if !ctx.Blocked {
		t.Error("expected ctx.Blocked = true")
	}
}

// TestSelfProtect_UnsetParamExpBypass_* close the same tamper-protection hole
// as the quote-splice tests above, reached with a different primitive: an
// unset variable expands to nothing, so `AGENTSHIELD_BYPA${zqx}SS` resolves
// to the real variable name at execution while no raw-text pattern matches.
//
// It is strictly cheaper for an attacker than the quote splice — nothing has
// to be bound, quoted, or set up; any name that happens to be unset works,
// and the agent picks the name. Verified in bash before the fix: `export
// AGENTSHIELD_BYPA${zqx}SS=1` sets AGENTSHIELD_BYPASS, and `${zqx:-AGENTSHIELD_BYPASS}=1`
// does too via the default-value form. Every one of the 6 hardcoded rules
// shares the raw-text-match shape, so every one is covered here.

func TestSelfProtect_UnsetParamExpBypass_BypassEnv(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "export AGENTSHIELD_BYPA${zqx}SS=1"}
	mw(ctx, func() {})
	if !ctx.Blocked {
		t.Error("expected param-spliced AGENTSHIELD_BYPASS to be blocked")
	}
}

func TestSelfProtect_UnsetParamExpBypass_SetupDisable(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "agentshield setup claude-code --disa${zqx}ble"}
	mw(ctx, func() {})
	if !ctx.Blocked {
		t.Error("expected param-spliced --disable to be blocked")
	}
}

func TestSelfProtect_UnsetParamExpBypass_DeleteConfig(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "rm -rf ~/.agentshi${zqx}eld/"}
	mw(ctx, func() {})
	if !ctx.Blocked {
		t.Error("expected param-spliced ~/.agentshield to be blocked")
	}
}

func TestSelfProtect_UnsetParamExpBypass_DeleteHooks(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "rm ~/.cla${zqx}ude/settings.json"}
	mw(ctx, func() {})
	if !ctx.Blocked {
		t.Error("expected param-spliced ~/.claude/settings.json to be blocked")
	}
}

func TestSelfProtect_UnsetParamExpBypass_PolicyWrite(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "echo 'rules: []' > ~/.agentshield/poli${zqx}cy.yaml"}
	mw(ctx, func() {})
	if !ctx.Blocked {
		t.Error("expected param-spliced policy.yaml path to be blocked")
	}
}

func TestSelfProtect_UnsetParamExpBypass_BinaryReplace(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "cp /tmp/fake /opt/homebrew/bin/agentshi${zqx}eld"}
	mw(ctx, func() {})
	if !ctx.Blocked {
		t.Error("expected param-spliced agentshield binary path to be blocked")
	}
}

// The two primitives composed in one token. This is the case that fixes the
// ORDER of the fallback chain: DequoteCommand bails on any word containing a
// ParamExp, so dequote-then-fold leaves this standing and only fold-then-
// dequote resolves it.
func TestSelfProtect_UnsetParamExpBypass_ComposedWithQuoteSplice(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "rm -rf ~/.agentshi'e'${zqx}ld/"}
	mw(ctx, func() {})
	if !ctx.Blocked {
		t.Error("expected quote-splice + param-splice combination to be blocked")
	}
}

// The default-value form reaches the same place without any splice at all.
func TestSelfProtect_UnsetParamExpBypass_DefaultForm(t *testing.T) {
	mw := SelfProtect()
	ctx := &EvalContext{Command: "export ${zqx:-AGENTSHIELD_BYPASS}=1"}
	mw(ctx, func() {})
	if !ctx.Blocked {
		t.Error("expected default-value-form AGENTSHIELD_BYPASS to be blocked")
	}
}

// FP boundary: ordinary parameterization near an AgentShield path must still
// pass. A developer reading their own config is not tampering.
func TestSelfProtect_UnsetParamExp_AllowsOrdinaryParameterization(t *testing.T) {
	for _, cmd := range []string{
		"cat ${CONFIG_DIR}/settings.json",
		"ls ~/.config/${APP}/",
		"echo ${VERSION:-1.0.0}",
	} {
		mw := SelfProtect()
		ctx := &EvalContext{Command: cmd}
		nextCalled := false
		mw(ctx, func() { nextCalled = true })
		if ctx.Blocked || !nextCalled {
			t.Errorf("expected %q to pass self-protection", cmd)
		}
	}
}
