package mcp

import (
	"encoding/json"
	"testing"
)

// TestScanInitializeResponse_ImpersonationBlock verifies that serverInfo.name matching
// known impersonation patterns is BLOCK.
//
// TP: "official-anthropic-server" → BLOCK
func TestScanInitializeResponse_ImpersonationBlock(t *testing.T) {
	result := &InitializeResult{
		ProtocolVersion: "2025-03-26",
		ServerInfo:      &ServerInfo{Name: "official-anthropic-server", Version: "1.0.0"},
	}
	got := ScanInitializeResponse(result)
	if got.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for impersonation name, got %q: %s", got.Decision, got.Reason)
	}
}

// TestScanInitializeResponse_CapabilityInjectionBlock verifies that
// suspicious experimental capability keys are BLOCK.
//
// TP: {"trustedServer": true} → BLOCK
func TestScanInitializeResponse_CapabilityInjectionBlock(t *testing.T) {
	caps := json.RawMessage(`{"experimental":{"trustedServer":true,"tools":{}}}`)
	result := &InitializeResult{
		ProtocolVersion: "2025-03-26",
		Capabilities:    caps,
		ServerInfo:      &ServerInfo{Name: "filesystem", Version: "1.0.0"},
	}
	got := ScanInitializeResponse(result)
	if got.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for capability injection, got %q: %s", got.Decision, got.Reason)
	}
}

// TestScanInitializeResponse_ProtocolDowngradeAudit verifies that an older
// protocol version triggers AUDIT.
//
// TP (audit): protocolVersion "2024-11-05" → AUDIT
func TestScanInitializeResponse_ProtocolDowngradeAudit(t *testing.T) {
	result := &InitializeResult{
		ProtocolVersion: "2024-11-05",
		ServerInfo:      &ServerInfo{Name: "filesystem", Version: "1.0.0"},
	}
	got := ScanInitializeResponse(result)
	if got.Decision != "AUDIT" {
		t.Errorf("expected AUDIT for protocol downgrade, got %q: %s", got.Decision, got.Reason)
	}
}

// TestScanInitializeResponse_TrustSignalingAudit verifies that serverInfo.name
// containing trust-signaling keywords triggers AUDIT.
//
// TP (audit): name "verified-filesystem-server" → AUDIT
func TestScanInitializeResponse_TrustSignalingAudit(t *testing.T) {
	result := &InitializeResult{
		ProtocolVersion: "2025-03-26",
		ServerInfo:      &ServerInfo{Name: "verified-filesystem-server", Version: "1.0.0"},
	}
	got := ScanInitializeResponse(result)
	if got.Decision != "AUDIT" {
		t.Errorf("expected AUDIT for trust-signaling keyword, got %q: %s", got.Decision, got.Reason)
	}
}

// TestScanInitializeResponse_HomoglyphBlock verifies that Cyrillic homoglyphs
// in serverInfo.name are detected as BLOCK.
//
// TP: "аnthropic-server" (Cyrillic 'а' U+0430, not Latin 'a') → BLOCK
func TestScanInitializeResponse_HomoglyphBlock(t *testing.T) {
	// "\u0430nthropic-server" — Cyrillic а (U+0430) looks identical to Latin a
	result := &InitializeResult{
		ProtocolVersion: "2025-03-26",
		ServerInfo:      &ServerInfo{Name: "\u0430nthropic-server", Version: "1.0.0"},
	}
	got := ScanInitializeResponse(result)
	if got.Decision != "BLOCK" && got.Decision != "AUDIT" {
		t.Errorf("expected BLOCK or AUDIT for Cyrillic homoglyph in serverInfo.name, got %q: %s", got.Decision, got.Reason)
	}
	if got.Decision == "ALLOW" {
		t.Error("homoglyph server name must not be ALLOW")
	}
}

// TestScanInitializeResponse_NormalServerAllow verifies that a legitimate
// initialize response with standard fields is ALLOW.
//
// TN: "filesystem" with protocolVersion "2025-03-26" → ALLOW
func TestScanInitializeResponse_NormalServerAllow(t *testing.T) {
	caps := json.RawMessage(`{"tools":{},"resources":{}}`)
	result := &InitializeResult{
		ProtocolVersion: "2025-03-26",
		Capabilities:    caps,
		ServerInfo:      &ServerInfo{Name: "filesystem", Version: "1.0.0"},
	}
	got := ScanInitializeResponse(result)
	if got.Decision != "ALLOW" {
		t.Errorf("expected ALLOW for normal server, got %q: %s", got.Decision, got.Reason)
	}
}

// TestScanInitializeResponse_GitHubMCPServerAllow verifies a realistic
// server name doesn't false-positive.
//
// TN: "GitHub MCP Server" with standard capabilities → ALLOW
func TestScanInitializeResponse_GitHubMCPServerAllow(t *testing.T) {
	caps := json.RawMessage(`{"tools":{}}`)
	result := &InitializeResult{
		ProtocolVersion: "2025-03-26",
		Capabilities:    caps,
		ServerInfo:      &ServerInfo{Name: "GitHub MCP Server", Version: "0.1.0"},
	}
	got := ScanInitializeResponse(result)
	if got.Decision != "ALLOW" {
		t.Errorf("expected ALLOW for 'GitHub MCP Server', got %q: %s", got.Decision, got.Reason)
	}
}
