package main

import (
	"sync"

	"github.com/AI-AgentLens/agentshield/internal/mcp"
)

// maxSessions bounds the session map so an unauthenticated-loopback or
// misbehaving client cannot grow memory without limit. Phase 0 eviction is
// deliberately dumb (drop an arbitrary session, losing its MCP call history);
// LRU or TTL eviction is not worth building before a real deployment shows
// the access pattern. A dropped session degrades sequence-rule context, never
// enforcement of single-call rules.
const maxSessions = 1024

// sessionStore hands out one MCP call-history tracker per session_id. The
// trackers themselves are mutex-guarded (boundedHistory), so the store only
// synchronizes map access.
type sessionStore struct {
	mu sync.Mutex
	m  map[string]*mcp.MCPCallHistoryTracker
}

func newSessionStore() *sessionStore {
	return &sessionStore{m: make(map[string]*mcp.MCPCallHistoryTracker)}
}

func (s *sessionStore) get(id string) *mcp.MCPCallHistoryTracker {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.m[id]; ok {
		return t
	}
	if len(s.m) >= maxSessions {
		for k := range s.m {
			delete(s.m, k)
			break
		}
	}
	t := mcp.NewMCPCallHistoryTracker()
	s.m[id] = t
	return t
}

// count reports the number of live sessions (test observability).
func (s *sessionStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}
