package mcp

import "sync"

// boundedHistory is a mutex-guarded, bounded sliding window of the most
// recent entries. It absorbs the append-and-trim history skeleton previously
// copy-pasted across the per-session MCP trackers (ApprovalFatigueTracker,
// MCPCallHistoryTracker, SubAgentTracker, ElicitationFatigueTracker).
//
// Construct with newBoundedHistory to set the bound. A zero-value
// boundedHistory is usable but unbounded (max == 0 disables trimming).
type boundedHistory[T any] struct {
	mu      sync.Mutex
	entries []T
	max     int
}

// newBoundedHistory returns a boundedHistory that keeps at most max entries.
func newBoundedHistory[T any](max int) boundedHistory[T] {
	return boundedHistory[T]{max: max}
}

// append adds v to the window, evicting the oldest entries beyond the bound.
func (h *boundedHistory[T]) append(v T) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = append(h.entries, v)
	h.trimLocked()
}

// view runs fn on the live entries under the lock. fn must treat the slice as
// read-only and must not retain it after returning. Used by trackers whose
// Scan logic needs a consistent point-in-time view without a copy.
func (h *boundedHistory[T]) view(fn func(entries []T)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fn(h.entries)
}

// snapshot returns a copy of the entries, oldest first.
func (h *boundedHistory[T]) snapshot() []T {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]T, len(h.entries))
	copy(out, h.entries)
	return out
}

// mutate replaces the entries with fn's result under the lock, evicts the
// oldest entries beyond the bound, and returns the resulting length. fn may
// reuse the input slice's backing array (e.g. entries[:0] pruning).
func (h *boundedHistory[T]) mutate(fn func(entries []T) []T) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = fn(h.entries)
	h.trimLocked()
	return len(h.entries)
}

// trimLocked evicts the oldest entries beyond max. Caller must hold mu.
func (h *boundedHistory[T]) trimLocked() {
	if h.max > 0 && len(h.entries) > h.max {
		h.entries = h.entries[len(h.entries)-h.max:]
	}
}
