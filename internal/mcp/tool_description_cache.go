package mcp

import "sync"

// ToolDescriptionCache caches tool descriptions from the most recent tools/list
// response. A tools/call message carries only the tool name and arguments — the
// description that description-driven semantic rules (ClassifyToolIntent's
// classifyDescription signal) classify against lives in the tools/list
// response and must be cached session-side so a later tools/call can be
// evaluated with it.
//
// Before this cache existed, the stdio and HTTP proxies (internal/mcp/proxy.go,
// http_proxy.go) always evaluated tools/call with an empty description — only
// the agentless /v1/evaluate surface (cmd/shield-server) and the scenario test
// harness ever passed a real one. Every BLOCK that depends on the description
// signal was therefore inert on live proxy traffic while still grading as a
// pass in the corpus (#3692).
type ToolDescriptionCache struct {
	mu    sync.RWMutex
	cache map[string]string
}

// NewToolDescriptionCache returns an initialized, empty cache.
func NewToolDescriptionCache() *ToolDescriptionCache {
	return &ToolDescriptionCache{cache: make(map[string]string)}
}

// Update atomically replaces the entire cache with the descriptions from the
// latest tools/list response. Tools with no description are stored as "".
func (c *ToolDescriptionCache) Update(tools []ToolDefinition) {
	next := make(map[string]string, len(tools))
	for _, t := range tools {
		next[t.Name] = t.Description
	}
	c.mu.Lock()
	c.cache = next
	c.mu.Unlock()
}

// Get returns the cached description for toolName, or "" if the tool is
// unknown or was never seen in a tools/list response this session — the same
// fallback the proxies used unconditionally before this cache existed, so a
// tool called before any tools/list is evaluated exactly as it was before.
func (c *ToolDescriptionCache) Get(toolName string) string {
	c.mu.RLock()
	desc := c.cache[toolName]
	c.mu.RUnlock()
	return desc
}
