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
