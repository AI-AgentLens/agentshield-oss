package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// ToolRegistryEntry records a single tool registered by an MCP server.
type ToolRegistryEntry struct {
	Name       string `json:"name"`
	SchemaHash string `json:"schema_hash"`
}

// ServerEntry records all tools registered by a single MCP server.
type ServerEntry struct {
	Tools    []ToolRegistryEntry `json:"tools"`
	LastSeen string              `json:"last_seen"`
}

// ToolCollision describes a tool name collision between two MCP servers.
type ToolCollision struct {
	ToolName      string
	CurrentServer string
	OtherServer   string
}

// CollisionResult holds the outcome of a collision check.
type CollisionResult struct {
	Collisions []ToolCollision
}

// ToolRegistry maintains a file-based registry of MCP server tool lists
// for cross-server collision detection.
type ToolRegistry struct {
	CacheDir string
}

// allServersRegistry is the top-level persisted structure.
type allServersRegistry map[string]ServerEntry

// NewToolRegistry returns a registry that persists state in the default
// AgentShield config directory (~/.agentshield).
func NewToolRegistry() *ToolRegistry {
	return newToolRegistryWithDir("")
}

func newToolRegistryWithDir(cacheDir string) *ToolRegistry {
	if cacheDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		cacheDir = filepath.Join(home, ".agentshield")
	}
	return &ToolRegistry{CacheDir: cacheDir}
}

// Register updates the registry for serverName and checks for cross-server
// tool name collisions. Returns nil if no collisions found.
func (r *ToolRegistry) Register(serverName string, tools []ToolDefinition) *CollisionResult {
	entries := make([]ToolRegistryEntry, len(tools))
	for i, t := range tools {
		entries[i] = ToolRegistryEntry{
			Name:       t.Name,
			SchemaHash: hashInputSchema(t.InputSchema),
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })

	newEntry := ServerEntry{
		Tools:    entries,
		LastSeen: time.Now().UTC().Format(time.RFC3339),
	}

	all := r.lockedReadWrite(serverName, newEntry)
	if all == nil {
		return nil
	}

	// Build tool→server index from all OTHER servers.
	toolOwners := make(map[string]string)
	for name, entry := range all {
		if name == serverName {
			continue
		}
		for _, t := range entry.Tools {
			toolOwners[t.Name] = name
		}
	}

	// Check current server's tools for collisions.
	var collisions []ToolCollision
	for _, t := range entries {
		if other, exists := toolOwners[t.Name]; exists {
			collisions = append(collisions, ToolCollision{
				ToolName:      t.Name,
				CurrentServer: serverName,
				OtherServer:   other,
			})
		}
	}

	if len(collisions) == 0 {
		return nil
	}
	return &CollisionResult{Collisions: collisions}
}

// ListServers returns all registered servers and their tools.
func (r *ToolRegistry) ListServers() map[string]ServerEntry {
	data, err := os.ReadFile(r.registryPath())
	if err != nil {
		return nil
	}
	var all allServersRegistry
	if err := json.Unmarshal(data, &all); err != nil {
		return nil
	}
	return all
}

// Prune removes server entries older than maxAge.
func (r *ToolRegistry) Prune(maxAge time.Duration) int {
	path := r.registryPath()
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return 0
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return 0
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var all allServersRegistry
	if err := json.Unmarshal(data, &all); err != nil {
		return 0
	}

	cutoff := time.Now().Add(-maxAge)
	pruned := 0
	for name, entry := range all {
		t, err := time.Parse(time.RFC3339, entry.LastSeen)
		if err != nil || t.Before(cutoff) {
			delete(all, name)
			pruned++
		}
	}

	if pruned > 0 {
		out, _ := json.MarshalIndent(all, "", "  ")
		_ = f.Truncate(0)
		_, _ = f.Seek(0, 0)
		_, _ = f.Write(out)
	}
	return pruned
}

// CollisionSummary returns a human-readable summary of collisions.
func (cr *CollisionResult) CollisionSummary() string {
	if cr == nil || len(cr.Collisions) == 0 {
		return "no tool name collisions"
	}
	parts := make([]string, len(cr.Collisions))
	for i, c := range cr.Collisions {
		parts[i] = fmt.Sprintf("%q (on %s and %s)", c.ToolName, c.CurrentServer, c.OtherServer)
	}
	return "tool name collisions: " + strings.Join(parts, ", ")
}

func (r *ToolRegistry) registryPath() string {
	return filepath.Join(r.CacheDir, "mcp-tool-registry.json")
}

// lockedReadWrite atomically reads the registry, updates the entry for serverName,
// writes back, and returns the full registry for collision checking.
func (r *ToolRegistry) lockedReadWrite(serverName string, entry ServerEntry) allServersRegistry {
	if err := os.MkdirAll(r.CacheDir, 0o700); err != nil {
		return nil
	}

	path := r.registryPath()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	var all allServersRegistry
	data, err := os.ReadFile(path)
	if err == nil && len(data) > 0 {
		_ = json.Unmarshal(data, &all)
	}
	if all == nil {
		all = make(allServersRegistry)
	}

	all[serverName] = entry

	out, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return all
	}
	_ = f.Truncate(0)
	_, _ = f.Seek(0, 0)
	_, _ = f.Write(out)

	return all
}
