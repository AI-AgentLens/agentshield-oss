package mcp

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SchemaDriftResult holds the outcome of a schema drift check.
type SchemaDriftResult struct {
	// Drifted is true when the current schema differs from the cached baseline.
	Drifted bool
	// ServerName identifies the MCP server being checked.
	ServerName string
	// AddedTools lists tool names that appear in the current schema but not the baseline.
	AddedTools []string
	// RemovedTools lists tool names present in the baseline but missing from the current schema.
	RemovedTools []string
	// ChangedTools lists tool names whose input schemas have changed.
	ChangedTools []string
	// FirstSeen is true when no baseline existed (first-time connection).
	FirstSeen bool
}

// toolSchemaEntry is the persisted schema fingerprint for a single tool.
type toolSchemaEntry struct {
	InputSchemaHash string `json:"inputSchemaHash"`
}

// schemaCache is the persisted per-server schema baseline.
type schemaCache struct {
	Tools map[string]toolSchemaEntry `json:"tools"`
}

// SchemaDriftScanner detects tool schema mutations between MCP sessions
// by persisting a schema fingerprint cache and comparing on each tools/list response.
type SchemaDriftScanner struct {
	CacheDir string // directory for mcp-schema-cache.json; defaults to ~/.agentshield
}

// NewSchemaDriftScanner returns a scanner that persists cache in the default AgentShield
// config directory (~/.agentshield).
func NewSchemaDriftScanner() *SchemaDriftScanner {
	return newSchemaDriftScannerWithDir("")
}

// newSchemaDriftScannerWithDir returns a scanner using the given cacheDir.
// When cacheDir is empty, the default ~/.agentshield directory is used.
func newSchemaDriftScannerWithDir(cacheDir string) *SchemaDriftScanner {
	if cacheDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		cacheDir = filepath.Join(home, ".agentshield")
	}
	return &SchemaDriftScanner{CacheDir: cacheDir}
}

// CheckDrift compares the supplied tools list against the cached baseline for serverName.
// It always updates the cache to the current schema so subsequent calls use the latest
// authorized state as the new baseline.
// Returns nil if there is no cached baseline (first connection) — first-time connections
// are not treated as drift.
func (s *SchemaDriftScanner) CheckDrift(serverName string, tools []ToolDefinition) *SchemaDriftResult {
	result := &SchemaDriftResult{ServerName: serverName}

	current := buildSchemaCache(tools)
	cached, err := s.loadCache(serverName)

	// Always persist the new schema as the updated baseline.
	_ = s.saveCache(serverName, current)

	if err != nil {
		// No prior baseline → first-time connection, not drift.
		result.FirstSeen = true
		return result
	}

	// Compare cached vs current.
	for name := range current.Tools {
		if _, existed := cached.Tools[name]; !existed {
			result.AddedTools = append(result.AddedTools, name)
			result.Drifted = true
		} else if current.Tools[name].InputSchemaHash != cached.Tools[name].InputSchemaHash {
			result.ChangedTools = append(result.ChangedTools, name)
			result.Drifted = true
		}
	}
	for name := range cached.Tools {
		if _, stillPresent := current.Tools[name]; !stillPresent {
			result.RemovedTools = append(result.RemovedTools, name)
			result.Drifted = true
		}
	}

	sort.Strings(result.AddedTools)
	sort.Strings(result.RemovedTools)
	sort.Strings(result.ChangedTools)

	return result
}

// buildSchemaCache constructs an in-memory schemaCache from a tools list.
func buildSchemaCache(tools []ToolDefinition) schemaCache {
	cache := schemaCache{Tools: make(map[string]toolSchemaEntry, len(tools))}
	for _, t := range tools {
		cache.Tools[t.Name] = toolSchemaEntry{
			InputSchemaHash: hashInputSchema(t.InputSchema),
		}
	}
	return cache
}

// hashInputSchema returns a stable SHA-256 hex digest of a tool's input schema JSON.
// Keys are sorted to ensure consistent hashing regardless of marshal ordering.
func hashInputSchema(raw []byte) string {
	if len(raw) == 0 {
		return "empty"
	}
	// Unmarshal → re-marshal with sorted keys for canonical form.
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		// Not valid JSON — hash the raw bytes.
		h := sha256.Sum256(raw)
		return fmt.Sprintf("%x", h)
	}
	canonical, err := json.Marshal(sortedJSON(v))
	if err != nil {
		h := sha256.Sum256(raw)
		return fmt.Sprintf("%x", h)
	}
	h := sha256.Sum256(canonical)
	return fmt.Sprintf("%x", h)
}

// sortedJSON recursively converts maps to sorted-key representations so that
// JSON marshalling produces a canonical (stable) byte sequence.
func sortedJSON(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ordered := make([]interface{}, 0, len(keys)*2)
		for _, k := range keys {
			ordered = append(ordered, k, sortedJSON(val[k]))
		}
		return ordered
	case []interface{}:
		for i, item := range val {
			val[i] = sortedJSON(item)
		}
		return val
	default:
		return v
	}
}

// cacheFilePath returns the path to the per-server schema cache file.
func (s *SchemaDriftScanner) cacheFilePath() string {
	return filepath.Join(s.CacheDir, "mcp-schema-cache.json")
}

// allCaches is the top-level structure persisted to disk: a map from server name to schema.
type allCaches map[string]schemaCache

// loadCache reads the cached schema for a specific server.
// Returns an error if no cache exists or the server has no entry.
func (s *SchemaDriftScanner) loadCache(serverName string) (schemaCache, error) {
	data, err := os.ReadFile(s.cacheFilePath())
	if err != nil {
		return schemaCache{}, err
	}
	var all allCaches
	if err := json.Unmarshal(data, &all); err != nil {
		return schemaCache{}, err
	}
	cache, ok := all[serverName]
	if !ok {
		return schemaCache{}, fmt.Errorf("no cache for server %q", serverName)
	}
	return cache, nil
}

// saveCache persists the updated schema for serverName, merging with any existing entries.
func (s *SchemaDriftScanner) saveCache(serverName string, cache schemaCache) error {
	if err := os.MkdirAll(s.CacheDir, 0o700); err != nil {
		return err
	}

	// Load existing cache file to merge.
	var all allCaches
	data, err := os.ReadFile(s.cacheFilePath())
	if err == nil {
		_ = json.Unmarshal(data, &all)
	}
	if all == nil {
		all = make(allCaches)
	}
	all[serverName] = cache

	out, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.cacheFilePath(), out, 0o600)
}

// DriftSummary returns a concise human-readable summary of the drift for logging.
func (r *SchemaDriftResult) DriftSummary() string {
	if r.FirstSeen {
		return "first-time connection — schema baseline saved"
	}
	if !r.Drifted {
		return "no schema drift detected"
	}
	parts := []string{}
	if len(r.AddedTools) > 0 {
		parts = append(parts, fmt.Sprintf("new tools: [%s]", strings.Join(r.AddedTools, ", ")))
	}
	if len(r.RemovedTools) > 0 {
		parts = append(parts, fmt.Sprintf("removed tools: [%s]", strings.Join(r.RemovedTools, ", ")))
	}
	if len(r.ChangedTools) > 0 {
		parts = append(parts, fmt.Sprintf("schema changes: [%s]", strings.Join(r.ChangedTools, ", ")))
	}
	return strings.Join(parts, "; ")
}
