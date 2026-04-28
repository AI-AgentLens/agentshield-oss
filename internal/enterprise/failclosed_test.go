package enterprise

import (
	"testing"
)

func TestFailClosed_TrueBlocksOnNilResult(t *testing.T) {
	cfg := &ManagedConfig{FailClosed: true}
	mw := FailClosed(cfg)

	ctx := &EvalContext{Command: "test", Result: nil}
	nextCalled := false
	mw(ctx, func() { nextCalled = true })

	if !nextCalled {
		t.Error("next() should be called (post-eval middleware)")
	}
	if !ctx.Blocked {
		t.Error("expected block when fail_closed=true and Result is nil")
	}
	if ctx.BlockMsg == "" {
		t.Error("expected non-empty BlockMsg")
	}
}

func TestFailClosed_FalseAllowsOnNilResult(t *testing.T) {
	cfg := &ManagedConfig{FailClosed: false}
	mw := FailClosed(cfg)

	ctx := &EvalContext{Command: "test", Result: nil}
	mw(ctx, func() {})

	if ctx.Blocked {
		t.Error("expected no block when fail_closed=false")
	}
}

func TestFailClosed_TrueAllowsWhenResultPresent(t *testing.T) {
	cfg := &ManagedConfig{FailClosed: true}
	mw := FailClosed(cfg)

	ctx := &EvalContext{Command: "test", Result: "some-result"}
	mw(ctx, func() {})

	if ctx.Blocked {
		t.Error("expected no block when Result is present")
	}
}
