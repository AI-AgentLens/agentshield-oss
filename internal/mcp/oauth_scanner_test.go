package mcp

import (
	"testing"
)

func TestScanOAuthASMetadata_CleanMetadata(t *testing.T) {
	meta := &OAuthASMetadata{
		Issuer:                        "https://auth.example.com",
		AuthorizationEndpoint:         "https://auth.example.com/oauth/authorize",
		TokenEndpoint:                 "https://auth.example.com/oauth/token",
		CodeChallengeMethodsSupported: []string{"S256", "plain"},
	}
	result := ScanOAuthASMetadata(meta, "auth.example.com")
	if result.Decision != "ALLOW" {
		t.Errorf("expected ALLOW for clean metadata, got %s: %v", result.Decision, result.Findings)
	}
}

func TestScanOAuthASMetadata_NonHTTPSAuthorizationEndpoint(t *testing.T) {
	meta := &OAuthASMetadata{
		Issuer:                        "https://auth.example.com",
		AuthorizationEndpoint:         "http://auth.example.com/oauth/authorize",
		TokenEndpoint:                 "https://auth.example.com/oauth/token",
		CodeChallengeMethodsSupported: []string{"S256"},
	}
	result := ScanOAuthASMetadata(meta, "auth.example.com")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for HTTP authorization_endpoint, got %s", result.Decision)
	}
	if len(result.Findings) == 0 || result.Findings[0].Signal != SignalOAuthNonHTTPS {
		t.Errorf("expected SignalOAuthNonHTTPS finding, got: %v", result.Findings)
	}
}

func TestScanOAuthASMetadata_NonHTTPSTokenEndpoint(t *testing.T) {
	meta := &OAuthASMetadata{
		Issuer:                        "https://auth.example.com",
		AuthorizationEndpoint:         "https://auth.example.com/oauth/authorize",
		TokenEndpoint:                 "http://auth.example.com/oauth/token",
		CodeChallengeMethodsSupported: []string{"S256"},
	}
	result := ScanOAuthASMetadata(meta, "auth.example.com")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for HTTP token_endpoint, got %s", result.Decision)
	}
}

func TestScanOAuthASMetadata_MissingPKCE(t *testing.T) {
	meta := &OAuthASMetadata{
		Issuer:                "https://auth.example.com",
		AuthorizationEndpoint: "https://auth.example.com/oauth/authorize",
		TokenEndpoint:         "https://auth.example.com/oauth/token",
		// CodeChallengeMethodsSupported intentionally omitted
	}
	result := ScanOAuthASMetadata(meta, "auth.example.com")
	if result.Decision != "AUDIT" {
		t.Errorf("expected AUDIT for missing PKCE, got %s", result.Decision)
	}
	found := false
	for _, f := range result.Findings {
		if f.Signal == SignalOAuthPKCEMissing {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SignalOAuthPKCEMissing finding, got: %v", result.Findings)
	}
}

func TestScanOAuthASMetadata_EmptyPKCEList(t *testing.T) {
	meta := &OAuthASMetadata{
		Issuer:                        "https://auth.example.com",
		AuthorizationEndpoint:         "https://auth.example.com/oauth/authorize",
		TokenEndpoint:                 "https://auth.example.com/oauth/token",
		CodeChallengeMethodsSupported: []string{},
	}
	result := ScanOAuthASMetadata(meta, "auth.example.com")
	if result.Decision != "AUDIT" {
		t.Errorf("expected AUDIT for empty PKCE list, got %s", result.Decision)
	}
}

func TestScanOAuthASMetadata_DomainMismatch(t *testing.T) {
	meta := &OAuthASMetadata{
		Issuer:                        "https://attacker.example.com",
		AuthorizationEndpoint:         "https://attacker.example.com/oauth/authorize",
		TokenEndpoint:                 "https://attacker.example.com/oauth/token",
		CodeChallengeMethodsSupported: []string{"S256"},
	}
	// Metadata served from mcp.example.com but points to attacker.example.com
	result := ScanOAuthASMetadata(meta, "mcp.example.com")
	if result.Decision != "AUDIT" {
		t.Errorf("expected AUDIT for domain mismatch, got %s", result.Decision)
	}
	found := false
	for _, f := range result.Findings {
		if f.Signal == SignalOAuthDomainMismatch {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SignalOAuthDomainMismatch finding, got: %v", result.Findings)
	}
}

func TestScanOAuthASMetadata_NoDomainMismatch_Subpath(t *testing.T) {
	// auth.mcp.example.com is a subdomain of mcp.example.com — should ALLOW
	meta := &OAuthASMetadata{
		Issuer:                        "https://auth.mcp.example.com",
		AuthorizationEndpoint:         "https://auth.mcp.example.com/oauth/authorize",
		TokenEndpoint:                 "https://auth.mcp.example.com/oauth/token",
		CodeChallengeMethodsSupported: []string{"S256"},
	}
	result := ScanOAuthASMetadata(meta, "mcp.example.com")
	if result.Decision != "ALLOW" {
		t.Errorf("expected ALLOW for subdomain auth endpoint, got %s: %v", result.Decision, result.Findings)
	}
}

func TestScanOAuthASMetadata_NoOriginDomain_SkipsDomainCheck(t *testing.T) {
	meta := &OAuthASMetadata{
		Issuer:                        "https://auth.example.com",
		AuthorizationEndpoint:         "https://auth.example.com/oauth/authorize",
		TokenEndpoint:                 "https://auth.example.com/oauth/token",
		CodeChallengeMethodsSupported: []string{"S256"},
	}
	// Empty origin domain: domain check is skipped
	result := ScanOAuthASMetadata(meta, "")
	if result.Decision != "ALLOW" {
		t.Errorf("expected ALLOW when origin domain is empty (skip domain check), got %s", result.Decision)
	}
}

func TestScanOAuthASMetadata_IssuerMismatch(t *testing.T) {
	// Issuer points to attacker.evil.com but metadata was served from mcp.example.com
	meta := &OAuthASMetadata{
		Issuer:                        "https://attacker.evil.com",
		AuthorizationEndpoint:         "https://mcp.example.com/oauth/authorize",
		TokenEndpoint:                 "https://mcp.example.com/oauth/token",
		CodeChallengeMethodsSupported: []string{"S256"},
	}
	result := ScanOAuthASMetadata(meta, "mcp.example.com")
	if result.Decision != "AUDIT" {
		t.Errorf("expected AUDIT for issuer mismatch, got %s", result.Decision)
	}
	found := false
	for _, f := range result.Findings {
		if f.Signal == SignalOAuthIssuerMismatch {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SignalOAuthIssuerMismatch finding, got: %v", result.Findings)
	}
}

func TestScanOAuthASMetadata_IssuerMatchesOrigin(t *testing.T) {
	// Issuer matches origin domain — no mismatch signal
	meta := &OAuthASMetadata{
		Issuer:                        "https://mcp.example.com",
		AuthorizationEndpoint:         "https://mcp.example.com/oauth/authorize",
		TokenEndpoint:                 "https://mcp.example.com/oauth/token",
		CodeChallengeMethodsSupported: []string{"S256"},
	}
	result := ScanOAuthASMetadata(meta, "mcp.example.com")
	if result.Decision != "ALLOW" {
		t.Errorf("expected ALLOW when issuer matches origin, got %s: %v", result.Decision, result.Findings)
	}
}

func TestScanOAuthASMetadata_IssuerSubdomainOfOrigin(t *testing.T) {
	// Issuer is a subdomain of origin — should not mismatch
	meta := &OAuthASMetadata{
		Issuer:                        "https://auth.mcp.example.com",
		AuthorizationEndpoint:         "https://auth.mcp.example.com/oauth/authorize",
		TokenEndpoint:                 "https://auth.mcp.example.com/oauth/token",
		CodeChallengeMethodsSupported: []string{"S256"},
	}
	result := ScanOAuthASMetadata(meta, "mcp.example.com")
	if result.Decision != "ALLOW" {
		t.Errorf("expected ALLOW for issuer as subdomain of origin, got %s: %v", result.Decision, result.Findings)
	}
}

func TestIsOAuthMetadataPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/.well-known/oauth-authorization-server", true},
		{"/prefix/.well-known/oauth-authorization-server", true},
		{"/mcp/sse", false},
		{"/", false},
		{"/oauth/token", false},
	}
	for _, tc := range tests {
		got := isOAuthMetadataPath(tc.path)
		if got != tc.want {
			t.Errorf("isOAuthMetadataPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
