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

func a2aStderr(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}

// A2AScanSignal identifies a type of suspicious signal in an A2A agent card.
type A2AScanSignal string

const (
	// SignalA2AURLMismatch indicates that the agent card's url field resolves
	// to a different hostname than the server that served the card. This is
	// the primary indicator of a forged card redirecting task traffic to an
	// attacker-controlled endpoint (task hijacking).
	SignalA2AURLMismatch A2AScanSignal = "a2a_url_mismatch"

	// SignalA2AAuthMissing indicates that the agent card's authentication field
	// is absent or its schemes list is empty, advertising no authentication
	// requirement. Attackers can strip this field to force auth downgrade so
	// the orchestrator sends tasks without credentials, enabling interception.
	SignalA2AAuthMissing A2AScanSignal = "a2a_auth_missing"
)

// A2AScanFinding records one suspicious signal in an A2A agent card.
type A2AScanFinding struct {
	Signal A2AScanSignal `json:"signal"`
	Detail string        `json:"detail"`
	Field  string        `json:"field,omitempty"`
	Value  string        `json:"value,omitempty"`
}

// A2AScanResult is the result of scanning an A2A agent card.
type A2AScanResult struct {
	Decision string           `json:"decision"` // "BLOCK", "AUDIT", or "ALLOW"
	Findings []A2AScanFinding `json:"findings,omitempty"`
}

// wellKnownA2APath is the discovery path for A2A agent cards.
const wellKnownA2APath = "/.well-known/agent.json"

// ScanA2AAgentCard inspects an A2A agent card for:
//   - URL hostname mismatch vs. the origin that served the card (task hijacking)
//   - Missing or empty authentication schemes (auth downgrade)
//
// Decision is BLOCK for URL mismatch (direct task hijacking), AUDIT for missing
// auth (suspicious but may be an intentionally open agent), ALLOW if clean.
func ScanA2AAgentCard(card *A2AAgentCard, originDomain string) A2AScanResult {
	var result A2AScanResult

	// Check 1: url field hostname must match origin domain.
	// A forged card served by a MITM that redirects url to attacker.example.com
	// causes all subsequent task calls to be routed to the attacker.
	if originDomain != "" && card.URL != "" {
		u, err := url.Parse(card.URL)
		if err == nil {
			cardHost := strings.ToLower(u.Hostname())
			origin := strings.ToLower(originDomain)
			if cardHost != origin && !strings.HasSuffix(cardHost, "."+origin) {
				result.Findings = append(result.Findings, A2AScanFinding{
					Signal: SignalA2AURLMismatch,
					Detail: fmt.Sprintf(
						"A2A agent card url hostname %q differs from serving origin %q — possible MITM redirect to attacker-controlled endpoint",
						cardHost, origin,
					),
					Field: "url",
					Value: card.URL,
				})
			}
		}
	}

	// Check 2: authentication field must be present with non-empty schemes.
	// A forged card with no authentication forces the orchestrator to send
	// tasks without credentials, enabling passive interception.
	if len(card.Authentication.Schemes) == 0 {
		result.Findings = append(result.Findings, A2AScanFinding{
			Signal: SignalA2AAuthMissing,
			Detail: "A2A agent card authentication.schemes is absent or empty — card advertises no authentication, possible auth downgrade attack",
			Field:  "authentication.schemes",
		})
	}

	// Decision: BLOCK for URL mismatch (active redirect), AUDIT for auth downgrade.
	for _, f := range result.Findings {
		if f.Signal == SignalA2AURLMismatch {
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

// interceptA2AAgentCard checks whether an HTTP request is for the A2A agent card
// discovery endpoint (/.well-known/agent.json). If it is, the function:
//  1. Fetches the upstream response via the provided client.
//  2. Parses it as an A2AAgentCard.
//  3. Calls ScanA2AAgentCard.
//  4. Writes an audit entry and optionally rewrites the response.
//
// Returns (true, statusCode, body) if intercepted, or (false, 0, nil) if not.
func interceptA2AAgentCard(
	upstreamURL string,
	reqPath string,
	originDomain string,
	client *http.Client,
	onAudit AuditFunc,
	serverName string,
	stderr io.Writer,
) (intercepted bool, statusCode int, body []byte) {
	if !isA2AAgentCardPath(reqPath) {
		return false, 0, nil
	}

	target := buildA2AAgentCardURL(upstreamURL, reqPath)
	resp, err := client.Get(target) //nolint:noctx // discovery is a fire-and-read
	if err != nil {
		_, _ = fmt.Fprintf(a2aStderr(stderr), "[AgentShield MCP-HTTP] a2a card fetch error: %v\n", err)
		return true, http.StatusBadGateway, []byte(`{"error":"upstream unavailable"}`)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		_, _ = fmt.Fprintf(a2aStderr(stderr), "[AgentShield MCP-HTTP] a2a card read error: %v\n", err)
		return true, http.StatusBadGateway, []byte(`{"error":"read error"}`)
	}

	// Only scan if the response parses as an A2A card with a url field.
	var card A2AAgentCard
	if jsonErr := json.Unmarshal(respBody, &card); jsonErr != nil || card.URL == "" {
		// Not an A2A card (404, HTML, or missing url) — pass through unmodified.
		return true, resp.StatusCode, respBody
	}

	scan := ScanA2AAgentCard(&card, originDomain)

	if scan.Decision != "ALLOW" {
		reasons := make([]string, 0, len(scan.Findings))
		for _, f := range scan.Findings {
			reasons = append(reasons, string(f.Signal)+": "+f.Detail)
			_, _ = fmt.Fprintf(a2aStderr(stderr), "[AgentShield MCP-HTTP] %s a2a-agent-card: [%s] %s\n",
				scan.Decision, f.Signal, f.Detail)
		}
		if onAudit != nil {
			onAudit(AuditEntry{
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
				ToolName:       "a2a-agent-card",
				Decision:       scan.Decision,
				Flagged:        true,
				TriggeredRules: []string{"mcp-a2a-agent-card-spoofing"},
				Reasons:        reasons,
				Source:         "mcp-proxy-a2a-scanner",
				ServerName:     serverName,
				TaxonomyRef:    "unauthorized-execution/agentic-attacks/a2a-agent-card-discovery-spoofing",
			})
		}
		if scan.Decision == "BLOCK" {
			return true, http.StatusForbidden,
				[]byte(`{"error":"blocked","reason":"A2A agent card url field redirects to a different hostname — possible MITM task hijacking"}`)
		}
	}

	return true, resp.StatusCode, respBody
}

// isA2AAgentCardPath reports whether the given HTTP path is a well-known A2A
// agent card discovery path.
func isA2AAgentCardPath(path string) bool {
	return path == wellKnownA2APath || strings.HasSuffix(path, wellKnownA2APath)
}

// buildA2AAgentCardURL constructs the full upstream URL for the discovery request.
func buildA2AAgentCardURL(upstreamBase, reqPath string) string {
	u, err := url.Parse(upstreamBase)
	if err != nil {
		return upstreamBase + reqPath
	}
	u.Path = reqPath
	u.RawQuery = ""
	return u.String()
}
