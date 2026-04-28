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
