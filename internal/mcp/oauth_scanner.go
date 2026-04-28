package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OAuthScanSignal identifies a type of suspicious signal in AS metadata.
type OAuthScanSignal string

const (
	// SignalOAuthNonHTTPS indicates a non-HTTPS endpoint in AS metadata.
	// MCP OAuth 2.1 requires all endpoints to use HTTPS (RFC 8414 §3.3).
	SignalOAuthNonHTTPS OAuthScanSignal = "oauth_non_https_endpoint"

	// SignalOAuthPKCEMissing indicates that code_challenge_methods_supported
	// is absent or empty, meaning the AS doesn't advertise PKCE support.
	// MCP 2025 mandates PKCE with S256.
	SignalOAuthPKCEMissing OAuthScanSignal = "oauth_pkce_missing"

	// SignalOAuthDomainMismatch indicates that an endpoint in the AS metadata
	// resolves to a different domain than the server that served the metadata.
	// This suggests redirection to a rogue authorization server.
	SignalOAuthDomainMismatch OAuthScanSignal = "oauth_domain_mismatch"

	// SignalOAuthIssuerMismatch indicates that the issuer field in AS metadata
	// does not match the origin domain from which the metadata was fetched.
	// RFC 8414 §3.3 requires the issuer to exactly match the URL used to
	// fetch the metadata — a mismatch is a strong indicator of a rogue AS.
	SignalOAuthIssuerMismatch OAuthScanSignal = "oauth_issuer_mismatch"
)

// OAuthScanFinding records one suspicious signal in AS metadata.
type OAuthScanFinding struct {
	Signal  OAuthScanSignal `json:"signal"`
	Detail  string          `json:"detail"`
	Field   string          `json:"field,omitempty"`
	Value   string          `json:"value,omitempty"`
}

// OAuthScanResult is the result of scanning AS metadata.
type OAuthScanResult struct {
	Decision string             `json:"decision"` // "BLOCK", "AUDIT", or "ALLOW"
	Findings []OAuthScanFinding `json:"findings,omitempty"`
}

// wellKnownOAuthPath is the RFC 8414 discovery path for AS metadata.
const wellKnownOAuthPath = "/.well-known/oauth-authorization-server"

// ScanOAuthASMetadata inspects an AS metadata document for:
//   - Non-HTTPS endpoints (authorization_endpoint, token_endpoint, etc.)
//   - Missing PKCE support (code_challenge_methods_supported absent or empty,
//     or S256 not listed)
//   - Endpoint domain mismatch vs. the metadata origin domain
//
// The decision is BLOCK if non-HTTPS endpoints are found (plaintext credential theft),
// AUDIT for domain mismatch or missing PKCE (suspicious but may be legitimate), and
// ALLOW if no issues are found.
func ScanOAuthASMetadata(meta *OAuthASMetadata, originDomain string) OAuthScanResult {
	var result OAuthScanResult

	// Check HTTPS on all critical endpoints
	type endpointField struct {
		name  string
		value string
	}
	endpoints := []endpointField{
		{"authorization_endpoint", meta.AuthorizationEndpoint},
		{"token_endpoint", meta.TokenEndpoint},
		{"introspection_endpoint", meta.IntrospectionEndpoint},
		{"revocation_endpoint", meta.RevocationEndpoint},
		{"jwks_uri", meta.JWKsURI},
		{"registration_endpoint", meta.RegistrationEndpoint},
	}

	for _, ep := range endpoints {
		if ep.value == "" {
			continue
		}
		u, err := url.Parse(ep.value)
		if err != nil {
			continue
		}
		if u.Scheme == "http" {
			result.Findings = append(result.Findings, OAuthScanFinding{
				Signal: SignalOAuthNonHTTPS,
				Detail: fmt.Sprintf("OAuth AS endpoint %s uses HTTP instead of HTTPS — plaintext credential exchange", ep.name),
				Field:  ep.name,
				Value:  ep.value,
			})
		}
	}

	// Check PKCE support
	pkceFound := false
	for _, m := range meta.CodeChallengeMethodsSupported {
		if strings.ToUpper(m) == "S256" {
			pkceFound = true
			break
		}
	}
	if !pkceFound {
		detail := "code_challenge_methods_supported does not include S256 — PKCE protection is absent or downgraded"
		if len(meta.CodeChallengeMethodsSupported) == 0 {
			detail = "code_challenge_methods_supported is missing or empty — PKCE not advertised by AS"
		}
		result.Findings = append(result.Findings, OAuthScanFinding{
			Signal: SignalOAuthPKCEMissing,
			Detail: detail,
			Field:  "code_challenge_methods_supported",
		})
	}

	// Check endpoint domain matches origin (if origin domain is known)
	if originDomain != "" {
		for _, ep := range endpoints {
			if ep.value == "" {
				continue
			}
			u, err := url.Parse(ep.value)
			if err != nil {
				continue
			}
			epHost := strings.ToLower(u.Hostname())
			origin := strings.ToLower(originDomain)
			if epHost != origin && !strings.HasSuffix(epHost, "."+origin) {
				result.Findings = append(result.Findings, OAuthScanFinding{
					Signal: SignalOAuthDomainMismatch,
					Detail: fmt.Sprintf("OAuth AS endpoint %s resolves to %s but metadata was served from %s — possible rogue AS redirection", ep.name, epHost, origin),
					Field:  ep.name,
					Value:  ep.value,
				})
				break // one mismatch finding is sufficient
			}
		}
	}

	// Check issuer field against origin domain (RFC 8414 §3.3: issuer MUST match
	// the URL used to fetch the metadata — a mismatch indicates a rogue AS).
	if originDomain != "" && meta.Issuer != "" {
		issuerURL, err := url.Parse(meta.Issuer)
		if err == nil {
			issuerHost := strings.ToLower(issuerURL.Hostname())
			origin := strings.ToLower(originDomain)
			if issuerHost != origin && !strings.HasSuffix(issuerHost, "."+origin) {
				result.Findings = append(result.Findings, OAuthScanFinding{
					Signal: SignalOAuthIssuerMismatch,
					Detail: fmt.Sprintf("OAuth AS issuer %q does not match metadata origin %s — RFC 8414 §3.3 violation, possible rogue AS", meta.Issuer, origin),
					Field:  "issuer",
					Value:  meta.Issuer,
				})
			}
		}
	}

	// Determine decision:
	// BLOCK if any non-HTTPS endpoint (active credential interception risk).
	// AUDIT for domain mismatch or missing PKCE (suspicious, needs review).
	// ALLOW if clean.
	for _, f := range result.Findings {
		if f.Signal == SignalOAuthNonHTTPS {
			result.Decision = "BLOCK"
			return result
		}
	}
	if len(result.Findings) > 0 {
		result.Decision = "AUDIT"
		return result
	}
	result.Decision = "ALLOW"
	return result
}

// interceptOAuthASMetadata checks whether an HTTP request is for the OAuth AS
// metadata discovery endpoint (/.well-known/oauth-authorization-server or a
// path-prefixed variant). If it is, the function:
//  1. Fetches the upstream response via the provided client.
//  2. Parses it as OAuthASMetadata.
//  3. Calls ScanOAuthASMetadata.
//  4. Writes an audit entry and optionally rewrites the response.
//
// Returns (true, statusCode, body) if the request was intercepted (caller must
// not forward the request itself), or (false, 0, nil) if the request is not an
// AS metadata request.
func interceptOAuthASMetadata(
	upstreamURL string,
	reqPath string,
	originDomain string,
	client *http.Client,
	onAudit AuditFunc,
	serverName string,
	stderr io.Writer,
) (intercepted bool, statusCode int, body []byte) {
	if !isOAuthMetadataPath(reqPath) {
		return false, 0, nil
	}

	// Build upstream URL preserving the discovery path
	target := buildOAuthMetadataURL(upstreamURL, reqPath)
	resp, err := client.Get(target) //nolint:noctx // discovery is a fire-and-read
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "[AgentShield MCP-HTTP] oauth metadata fetch error: %v\n", err)
		return true, http.StatusBadGateway, []byte(`{"error":"upstream unavailable"}`)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "[AgentShield MCP-HTTP] oauth metadata read error: %v\n", err)
		return true, http.StatusBadGateway, []byte(`{"error":"read error"}`)
	}

	// Only scan if the response looks like JSON AS metadata
	var meta OAuthASMetadata
	if jsonErr := json.Unmarshal(respBody, &meta); jsonErr != nil || meta.AuthorizationEndpoint == "" {
		// Not AS metadata (e.g. 404 or HTML) — pass through unmodified
		return true, resp.StatusCode, respBody
	}

	scan := ScanOAuthASMetadata(&meta, originDomain)

	if scan.Decision != "ALLOW" {
		reasons := make([]string, 0, len(scan.Findings))
		for _, f := range scan.Findings {
			reasons = append(reasons, string(f.Signal)+": "+f.Detail)
			_, _ = fmt.Fprintf(stderr, "[AgentShield MCP-HTTP] %s oauth-as-metadata: [%s] %s\n",
				scan.Decision, f.Signal, f.Detail)
		}
		if onAudit != nil {
			onAudit(AuditEntry{
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
				ToolName:       "oauth-as-metadata",
				Decision:       scan.Decision,
				Flagged:        true,
				TriggeredRules: []string{"mcp-oauth-as-metadata-spoofing"},
				Reasons:        reasons,
				Source:         "mcp-proxy-oauth-scanner",
				ServerName:     serverName,
				TaxonomyRef:    "unauthorized-execution/agentic-attacks/mcp-oauth-as-metadata-spoofing",
			})
		}
		if scan.Decision == "BLOCK" {
			return true, http.StatusForbidden,
				[]byte(`{"error":"blocked","reason":"OAuth AS metadata contains non-HTTPS endpoints — possible credential interception"}`)
		}
	}

	return true, resp.StatusCode, respBody
}

// isOAuthMetadataPath reports whether the given HTTP path is a well-known
// OAuth AS metadata discovery path (RFC 8414).
func isOAuthMetadataPath(path string) bool {
	return strings.HasSuffix(path, wellKnownOAuthPath) ||
		path == wellKnownOAuthPath
}

// buildOAuthMetadataURL constructs the full upstream URL for the discovery request.
// It preserves any path prefix before /.well-known/ (some servers use /path/.well-known/...).
func buildOAuthMetadataURL(upstreamBase, reqPath string) string {
	// Strip any trailing path from the upstream base and append the request path
	u, err := url.Parse(upstreamBase)
	if err != nil {
		return upstreamBase + reqPath
	}
	u.Path = reqPath
	u.RawQuery = ""
	return u.String()
}
