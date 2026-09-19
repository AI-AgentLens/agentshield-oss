package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
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

	// SignalOAuthCommandInjection indicates that an AS metadata endpoint
	// value contains shell metacharacters or raw characters that must be
	// percent-encoded in a well-formed URI (RFC 3986). A malicious server
	// can smuggle a command-injection payload into authorization_endpoint /
	// token_endpoint; clients that shell out to open the value (e.g. to
	// launch a browser for OAuth consent) without argv-array spawning
	// achieve pre-authentication RCE on the developer's machine
	// (CVE-2025-6514 class — mcp-remote).
	SignalOAuthCommandInjection OAuthScanSignal = "oauth_command_injection"

	// SignalOAuthLegacyGrantAdvertised indicates that grant_types_supported
	// names a grant type OAuth 2.1 REMOVED: the resource owner password
	// credentials grant, or the implicit grant. MCP mandates OAuth 2.1, so an
	// AS advertising either is offering the MCP client a flow the profile it
	// claims to implement does not contain.
	//
	// ROPC is the sharper of the two for an agent: it means "hand me the
	// user's password directly", and an agent that hits an authorization
	// failure and self-corrects toward whatever the AS says it supports is
	// exactly the consumer that will take that offer. That is the same
	// error-recovery-steering shape response_error_remediation_scanner.go
	// detects in tool results, arriving here through a structured field
	// instead of prose.
	SignalOAuthLegacyGrantAdvertised OAuthScanSignal = "oauth_legacy_grant_advertised"

	// SignalOAuthImplicitResponseType indicates that response_types_supported
	// includes a token-bearing response type ("token", or a space-delimited
	// set containing it such as "id_token token"). The implicit flow returns
	// the access token in the URL FRAGMENT, where it reaches browser history,
	// Referer headers and any redirect logging in between — and where PKCE,
	// which binds a code to the requesting client, has nothing to protect
	// because there is no code. OAuth 2.1 removed it for those reasons.
	SignalOAuthImplicitResponseType OAuthScanSignal = "oauth_implicit_response_type"

	// SignalOAuthCodeFlowUnavailable indicates that the AS advertises a
	// REMOVED flow while omitting the authorization-code flow entirely, so an
	// MCP client that proceeds has no compliant path left.
	//
	// The conjunction is what makes this safe to enforce. "authorization_code
	// is absent" alone is ordinary — a machine-to-machine AS advertising only
	// client_credentials is well-formed OAuth 2.1 and must not fire. It is
	// the combination of pushing a removed flow AND withholding the only
	// permitted one that has no legitimate reading.
	SignalOAuthCodeFlowUnavailable OAuthScanSignal = "oauth_code_flow_unavailable"
)

// oauth21RemovedGrants are the grant types OAuth 2.1 removes. Matching is
// case-insensitive on the exact token: "password" and "implicit" are
// registered grant type identifiers, not substrings to search for, and a
// vendor extension like "urn:example:params:oauth:grant-type:password-reset"
// is not the ROPC grant.
var oauth21RemovedGrants = map[string]string{
	"password": "resource owner password credentials (ROPC) — the client handles the user's raw password; " +
		"removed in OAuth 2.1",
	"implicit": "implicit grant — access token returned in the URL fragment, unprotected by PKCE; " +
		"removed in OAuth 2.1",
}

// oauthCommandInjectionPattern matches content in an OAuth endpoint value
// that indicates a shell command-injection payload rather than a
// well-formed URL. Backtick, pipe, backslash, angle brackets, and raw
// whitespace must be percent-encoded to appear literally in a valid URI
// (RFC 3986) — their unescaped presence is already anomalous. "$(" and "&&"
// are additional shell-operator signals that are technically legal URI
// sub-delims but never appear in real OAuth endpoint URLs.
var oauthCommandInjectionPattern = regexp.MustCompile("[`|\\\\<>;\\s]|\\$\\(|&&")

// OAuthScanFinding records one suspicious signal in AS metadata.
type OAuthScanFinding struct {
	Signal OAuthScanSignal `json:"signal"`
	Detail string          `json:"detail"`
	Field  string          `json:"field,omitempty"`
	Value  string          `json:"value,omitempty"`
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

	// Check for shell command-injection payloads. A malicious AS can smuggle
	// shell metacharacters into an endpoint value; clients that shell out to
	// open it (e.g. to launch a browser for OAuth consent) without
	// argv-array spawning execute the attacker's payload pre-authentication
	// (CVE-2025-6514 class).
	for _, ep := range endpoints {
		if ep.value == "" {
			continue
		}
		if oauthCommandInjectionPattern.MatchString(ep.value) {
			result.Findings = append(result.Findings, OAuthScanFinding{
				Signal: SignalOAuthCommandInjection,
				Detail: fmt.Sprintf("OAuth AS endpoint %s contains shell metacharacters — possible command-injection payload for clients that shell out to open this value (CVE-2025-6514 class)", ep.name),
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

	// OAuth 2.1 flow downgrade. MCP mandates OAuth 2.1; these two fields were
	// parsed into OAuthASMetadata and read by nothing, so an AS could advertise
	// a removed flow and the metadata scan stayed silent.
	//
	// Deliberately NOT flagged: grant_types_supported being absent altogether.
	// RFC 8414 defines its default as ["authorization_code", "implicit"], so
	// omission technically implies implicit support — but omission is not an
	// assertion by the server, it is the commonest shape of a minimal metadata
	// document, and flagging it would fire on most well-behaved deployments.
	// Only an explicit advertisement counts.
	var hasAuthCodeGrant bool
	var legacyGrants []string
	for _, g := range meta.GrantTypesSupported {
		token := strings.ToLower(strings.TrimSpace(g))
		if token == "authorization_code" {
			hasAuthCodeGrant = true
		}
		if why, removed := oauth21RemovedGrants[token]; removed {
			legacyGrants = append(legacyGrants, token)
			result.Findings = append(result.Findings, OAuthScanFinding{
				Signal: SignalOAuthLegacyGrantAdvertised,
				Detail: "grant_types_supported advertises " + token + ": " + why,
				Field:  "grant_types_supported",
				Value:  token,
			})
		}
	}

	var hasCodeResponse, hasTokenResponse bool
	for _, rt := range meta.ResponseTypesSupported {
		// A response type is a space-delimited SET ("id_token token"), so the
		// value has to be split rather than compared whole — otherwise the
		// commonest hybrid spelling of the implicit flow walks past.
		for _, part := range strings.Fields(strings.ToLower(rt)) {
			switch part {
			case "code":
				hasCodeResponse = true
			case "token":
				hasTokenResponse = true
			}
		}
	}
	if hasTokenResponse {
		result.Findings = append(result.Findings, OAuthScanFinding{
			Signal: SignalOAuthImplicitResponseType,
			Detail: "response_types_supported includes a token-bearing response type — the implicit flow " +
				"returns the access token in the URL fragment, where it reaches browser history and Referer " +
				"headers and where PKCE has no code to protect; removed in OAuth 2.1",
			Field: "response_types_supported",
		})
	}

	// The escalation: a removed flow is advertised AND the only OAuth 2.1
	// -permitted interactive flow is absent, so proceeding means using the
	// removed one.
	if len(legacyGrants) > 0 && len(meta.GrantTypesSupported) > 0 && !hasAuthCodeGrant {
		result.Findings = append(result.Findings, OAuthScanFinding{
			Signal: SignalOAuthCodeFlowUnavailable,
			Detail: "grant_types_supported advertises " + strings.Join(legacyGrants, ", ") +
				" but omits authorization_code — an MCP client that proceeds has no OAuth 2.1-compliant flow left",
			Field: "grant_types_supported",
		})
	}
	if hasTokenResponse && !hasCodeResponse {
		result.Findings = append(result.Findings, OAuthScanFinding{
			Signal: SignalOAuthCodeFlowUnavailable,
			Detail: "response_types_supported offers a token-bearing response type but not code — " +
				"an MCP client that proceeds has no OAuth 2.1-compliant flow left",
			Field: "response_types_supported",
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
	// BLOCK if any non-HTTPS endpoint (active credential interception risk),
	// a command-injection payload (pre-authentication RCE risk), or an AS that
	// advertises a removed flow while withholding the compliant one (no
	// legitimate reading — see SignalOAuthCodeFlowUnavailable).
	// AUDIT for domain mismatch, missing PKCE, or a removed flow advertised
	// ALONGSIDE authorization_code — a legacy AS serving non-MCP clients too is
	// a real and common deployment, so the offer is worth recording, not
	// worth breaking discovery over.
	// ALLOW if clean.
	for _, f := range result.Findings {
		if f.Signal == SignalOAuthNonHTTPS || f.Signal == SignalOAuthCommandInjection ||
			f.Signal == SignalOAuthCodeFlowUnavailable {
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
		commandInjection := false
		flowDowngrade := false
		for _, f := range scan.Findings {
			reasons = append(reasons, string(f.Signal)+": "+f.Detail)
			_, _ = fmt.Fprintf(stderr, "[AgentShield MCP-HTTP] %s oauth-as-metadata: [%s] %s\n",
				scan.Decision, f.Signal, f.Detail)
			if f.Signal == SignalOAuthCommandInjection {
				commandInjection = true
			}
			if f.Signal == SignalOAuthCodeFlowUnavailable {
				flowDowngrade = true
			}
		}

		// Command injection is the more severe finding (pre-auth RCE vs.
		// credential interception/downgrade) — attribute the audit entry to
		// its own rule/taxonomy when present, even alongside other findings.
		triggeredRule := "mcp-oauth-as-metadata-spoofing"
		taxonomyRef := "unauthorized-execution/agentic-attacks/mcp-oauth-as-metadata-spoofing"
		blockReason := "OAuth AS metadata contains non-HTTPS endpoints — possible credential interception"
		// blockReason is what the CLIENT is told, so it has to describe the
		// finding that actually caused the block. It was hardcoded to the
		// non-HTTPS text, which was correct while non-HTTPS and command
		// injection were the only blocking signals; a flow-downgrade block
		// would otherwise have reported a transport problem that does not
		// exist, in both the client error and the operator's reading of it.
		if flowDowngrade {
			blockReason = "OAuth AS metadata advertises an OAuth 2.1-removed flow (implicit or ROPC) and omits " +
				"the authorization-code flow — no compliant path remains for an MCP client"
		}
		if commandInjection {
			triggeredRule = "mcp-oauth-endpoint-command-injection"
			taxonomyRef = "unauthorized-execution/agentic-attacks/mcp-oauth-endpoint-command-injection"
			blockReason = "OAuth AS metadata endpoint contains shell metacharacters — possible command-injection payload (CVE-2025-6514 class)"
		}

		if onAudit != nil {
			onAudit(AuditEntry{
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
				ToolName:       "oauth-as-metadata",
				Decision:       scan.Decision,
				Flagged:        true,
				TriggeredRules: []string{triggeredRule},
				Reasons:        reasons,
				Source:         "mcp-proxy-oauth-scanner",
				ServerName:     serverName,
				TaxonomyRef:    taxonomyRef,
			})
		}
		if scan.Decision == "BLOCK" {
			return true, http.StatusForbidden,
				[]byte(fmt.Sprintf(`{"error":"blocked","reason":%q}`, blockReason))
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
