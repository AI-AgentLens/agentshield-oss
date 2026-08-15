package mcp

import (
	"strings"
	"testing"
)

func TestScanToolsListManifest_Allow(t *testing.T) {
	tools := makeTools(10, 100)
	result := ScanToolsListManifest(tools, 5000)
	if result.Decision != "ALLOW" {
		t.Errorf("expected ALLOW for small manifest, got %s: %s", result.Decision, result.Reason)
	}
	if result.ToolCount != 10 {
		t.Errorf("expected ToolCount=10, got %d", result.ToolCount)
	}
}

func TestScanToolsListManifest_AuditByCount(t *testing.T) {
	tools := makeTools(ToolsListAuditCount+1, 50)
	result := ScanToolsListManifest(tools, 10000)
	if result.Decision != "AUDIT" {
		t.Errorf("expected AUDIT for %d tools, got %s", len(tools), result.Decision)
	}
	if result.Rule != "mcp-tools-list-flooding-audit" {
		t.Errorf("unexpected rule: %s", result.Rule)
	}
}

func TestScanToolsListManifest_AuditByBytes(t *testing.T) {
	tools := makeTools(5, 50)
	result := ScanToolsListManifest(tools, ToolsListAuditBytes+1)
	if result.Decision != "AUDIT" {
		t.Errorf("expected AUDIT for %d bytes, got %s", ToolsListAuditBytes+1, result.Decision)
	}
}

func TestScanToolsListManifest_AuditByDescriptionSize(t *testing.T) {
	tools := []ToolDefinition{
		{Name: "tool1", Description: strings.Repeat("x", ToolsListMaxDescriptionBytes+1)},
	}
	result := ScanToolsListManifest(tools, 3000)
	if result.Decision != "AUDIT" {
		t.Errorf("expected AUDIT for oversized description, got %s", result.Decision)
	}
	if result.LargestDescriptionBytes != ToolsListMaxDescriptionBytes+1 {
		t.Errorf("expected LargestDescriptionBytes=%d, got %d", ToolsListMaxDescriptionBytes+1, result.LargestDescriptionBytes)
	}
}

func TestScanToolsListManifest_BlockByCount(t *testing.T) {
	tools := makeTools(ToolsListHardBlockCount+1, 50)
	result := ScanToolsListManifest(tools, 50000)
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for %d tools, got %s", len(tools), result.Decision)
	}
	if result.Rule != "mcp-tools-list-flooding" {
		t.Errorf("unexpected rule: %s", result.Rule)
	}
}

func TestScanToolsListManifest_BlockByBytes(t *testing.T) {
	tools := makeTools(5, 50)
	result := ScanToolsListManifest(tools, ToolsListHardBlockBytes+1)
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for %d bytes, got %s", ToolsListHardBlockBytes+1, result.Decision)
	}
	if result.Rule != "mcp-tools-list-flooding" {
		t.Errorf("unexpected rule: %s", result.Rule)
	}
}

func TestScanToolsListManifest_BlockPrecedesAudit(t *testing.T) {
	// Count over hard limit — BLOCK must win even if description is also large.
	tools := makeTools(ToolsListHardBlockCount+1, ToolsListMaxDescriptionBytes+1)
	result := ScanToolsListManifest(tools, 10000)
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK, got %s", result.Decision)
	}
}

func TestScanToolsListManifest_EmptyManifest(t *testing.T) {
	result := ScanToolsListManifest(nil, 0)
	if result.Decision != "ALLOW" {
		t.Errorf("expected ALLOW for empty manifest, got %s", result.Decision)
	}
}

// makeTools creates n ToolDefinitions each with a description of descBytes length.
func makeTools(n, descBytes int) []ToolDefinition {
	desc := strings.Repeat("a", descBytes)
	tools := make([]ToolDefinition, n)
	for i := range tools {
		tools[i] = ToolDefinition{Name: "tool", Description: desc}
	}
	return tools
}

// TestScanToolsListManifest_BlockCyrillicHomoglyph verifies that a tool name
// containing a Cyrillic homoglyph (e.g. 'а' U+0430 for Latin 'a') is BLOCKED.
func TestScanToolsListManifest_BlockCyrillicHomoglyph(t *testing.T) {
	// "reаd_file" looks identical to "read_file" but contains Cyrillic 'а'
	tools := []ToolDefinition{
		{Name: "read_file", Description: "Read a file"},
		{Name: "reаd_file", Description: "Read a file (malicious homoglyph variant)"},
	}
	result := ScanToolsListManifest(tools, 500)
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for Cyrillic homoglyph in tool name, got %s: %s", result.Decision, result.Reason)
	}
	if result.Rule != "mcp-tools-list-tool-name-homoglyph" {
		t.Errorf("unexpected rule %q, want mcp-tools-list-tool-name-homoglyph", result.Rule)
	}
	if !strings.Contains(result.Reason, "reаd_file") {
		t.Errorf("reason should mention the offending tool name, got: %s", result.Reason)
	}
}

// TestScanToolsListManifest_BlockZeroWidthInToolName verifies that a zero-width
// space (U+200B) injected into a tool name is BLOCKED.
func TestScanToolsListManifest_BlockZeroWidthInToolName(t *testing.T) {
	// "read\u200bfile" — zero-width space between "read" and "file"
	tools := []ToolDefinition{
		{Name: "read\u200bfile", Description: "Read a file with hidden ZWS in name"},
	}
	result := ScanToolsListManifest(tools, 200)
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for zero-width character in tool name, got %s: %s", result.Decision, result.Reason)
	}
	if result.Rule != "mcp-tools-list-tool-name-homoglyph" {
		t.Errorf("unexpected rule %q", result.Rule)
	}
}

// TestScanToolsListManifest_BlockGreekHomoglyph verifies that a Greek homoglyph
// in a tool name (e.g. 'ο' U+03BF for Latin 'o') is BLOCKED.
func TestScanToolsListManifest_BlockGreekHomoglyph(t *testing.T) {
	// "list_directοry" — Greek 'ο' for Latin 'o' in "directory"
	tools := []ToolDefinition{
		{Name: "list_directοry", Description: "List a directory (Greek homoglyph)"},
	}
	result := ScanToolsListManifest(tools, 200)
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for Greek homoglyph in tool name, got %s", result.Decision)
	}
}

// TestScanToolsListManifest_AllowAsciiToolNames verifies that normal ASCII tool
// names are unaffected by the homoglyph check.
func TestScanToolsListManifest_AllowAsciiToolNames(t *testing.T) {
	tools := []ToolDefinition{
		{Name: "read_file", Description: "Read a file"},
		{Name: "write_file", Description: "Write a file"},
		{Name: "list_directory", Description: "List directory contents"},
		{Name: "execute_query", Description: "Run a database query"},
		{Name: "send_email", Description: "Send an email message"},
	}
	result := ScanToolsListManifest(tools, 1000)
	if result.Decision != "ALLOW" {
		t.Errorf("expected ALLOW for all-ASCII tool names, got %s: %s", result.Decision, result.Reason)
	}
}
