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

	pkgunicode "github.com/AI-AgentLens/agentshield/internal/unicode"
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

	// SignalA2ACardInjection indicates a prompt-injection / behavioral-takeover
	// directive, forged tokenizer role delimiter, or forged tool-call dispatch
	// syntax embedded in the card `description` or a skill's prose. The agent card
	// is a discovery document the orchestrator LLM reads verbatim before routing;
	// such a directive has no benign reading there, so it is a BLOCK (the
	// confused-deputy / capability-injection half of card-discovery-spoofing).
	SignalA2ACardInjection A2AScanSignal = "a2a_card_injection"

	// SignalA2ACardSuspiciousProse indicates softer capability prose that warrants
	// a receipt but not a block: an exfiltration/redirect phrasing, a concealment
	// instruction, or a reference to a sensitive credential path in a field the
	// orchestrator routes on. AUDIT — these have a small benign reading in longer
	// capability descriptions.
	SignalA2ACardSuspiciousProse A2AScanSignal = "a2a_card_suspicious_prose"

	// SignalA2ACardConfusableName indicates the card `name` or a skill `name`
	// carries Unicode confusables, invisible characters, bidi overrides or tag
	// characters — an identifier impersonating a trusted agent/skill to attract
	// task routing (the A2A analogue of tool-name confusable). AUDIT: a genuinely
	// non-Latin agent name is legitimate, so the receipt is the correct response.
	SignalA2ACardConfusableName A2AScanSignal = "a2a_card_confusable_name"

	// SignalA2AAuthNoop indicates the card's authentication.schemes list is
	// non-empty but every entry names a NO-authentication sentinel ("none",
	// "anonymous", "public", …). SignalA2AAuthMissing catches only the empty
	// list; a forged card that downgrades `["Bearer"]` to `["none"]` is a
	// non-empty list that still means "send tasks without credentials" — the same
	// auth-downgrade impact, past a presence-only check. AUDIT (an intentionally
	// open agent is legitimate — same rationale as SignalA2AAuthMissing).
	SignalA2AAuthNoop A2AScanSignal = "a2a_auth_noop"

	// SignalA2ATransportDowngrade indicates the card's `url` uses cleartext
	// http:// to a non-loopback host. The hostname-match check (SignalA2AURLMismatch)
	// compares only the host, so a card whose url is http://agent.company.com
	// passes it while routing every task payload — user data, context, and any
	// secret passed as a task parameter — over an unauthenticated, unencrypted
	// channel an on-path attacker can read or rewrite. AUDIT: an internal/dev
	// agent may legitimately be plaintext, so the receipt is the right response;
	// loopback hosts are excluded as ordinary local development.
	SignalA2ATransportDowngrade A2AScanSignal = "a2a_transport_downgrade"
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
	} else if a2aSchemesAllNoop(card.Authentication.Schemes) {
		// A non-empty list can still advertise NO authentication: a forged card
		// that downgrades ["Bearer"] to ["none"] passes the emptiness check above
		// while meaning exactly the same thing — send tasks without credentials.
		result.Findings = append(result.Findings, A2AScanFinding{
			Signal: SignalA2AAuthNoop,
			Detail: fmt.Sprintf(
				"A2A agent card authentication.schemes = %v names only no-authentication sentinels — a non-empty list that still advertises no credentials, past a presence-only check (auth downgrade)",
				card.Authentication.Schemes,
			),
			Field: "authentication.schemes",
			Value: strings.Join(card.Authentication.Schemes, ","),
		})
	}

	// Check 2b: transport downgrade — a cleartext http:// url to a non-loopback
	// host routes every task payload over an unencrypted, unauthenticated channel.
	// The hostname-match check compares only the host, so this slips past it.
	if scheme, host := a2aURLSchemeHost(card.URL); scheme == "http" && !a2aIsLoopbackHost(host) {
		result.Findings = append(result.Findings, A2AScanFinding{
			Signal: SignalA2ATransportDowngrade,
			Detail: "A2A agent card url uses cleartext http:// to a non-loopback host — task payloads (including secrets passed as task parameters) are sent unencrypted and unauthenticated over a channel an on-path attacker can read or rewrite",
			Field:  "url",
			Value:  card.URL,
		})
	}

	// Check 3: prose / capability injection in the fields the orchestrator LLM
	// reads to decide whether — and with what privilege — to route tasks to this
	// agent: the card `description`, `name`, and every skill's `name` /
	// `description` / `examples`. This node's own abstract already names "capability
	// injection" and "injecting manipulated capability declarations", but the URL
	// and auth-scheme checks above never look at that prose. A forged (or MITM'd)
	// card can carry an instruction-override, behavioral-takeover, or exfiltration
	// directive straight into the routing decision — a confused-deputy against the
	// orchestrator, not against any single downstream tool.
	result.Findings = append(result.Findings, scanA2ACardProse(card)...)

	// Decision: BLOCK on any blocking-severity finding (URL mismatch or a prose
	// injection directive with no benign reading in a discovery document), AUDIT
	// for the softer signals (auth downgrade, suspicious capability prose, a
	// confusable identifier).
	for _, f := range result.Findings {
		if a2aBlockingSignal(f.Signal) {
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

// a2aBlockingSignal reports whether a finding is severe enough to fail the card
// fetch (HTTP 403). Only two signals qualify: an active task-redirect
// (SignalA2AURLMismatch) and an unambiguous prompt-injection / behavioral-takeover
// directive in the card's prose (SignalA2ACardInjection). Everything else —
// missing auth, softer capability prose, a confusable identifier — is AUDIT, so a
// legitimately non-Latin agent name or a marketing description that merely happens
// to say "send it to your CRM" gets a receipt, never a block.
func a2aBlockingSignal(s A2AScanSignal) bool {
	return s == SignalA2AURLMismatch || s == SignalA2ACardInjection
}

// a2aNoopAuthSchemes is the set of scheme tokens that advertise NO
// authentication. A2A auth schemes are named security schemes (Bearer, OAuth2,
// ApiKey, Basic, mTLS, …); these tokens are the ways a card says "no auth
// required". The empty-string entry covers a `["", ...]` list padded to look
// non-empty.
var a2aNoopAuthSchemes = map[string]bool{
	"":          true,
	"none":      true,
	"anonymous": true,
	"anon":      true,
	"public":    true,
	"open":      true,
	"no-auth":   true,
	"noauth":    true,
	"no_auth":   true,
	"nil":       true,
	"null":      true,
}

// a2aSchemesAllNoop reports whether every scheme in a non-empty list is a
// no-authentication sentinel. A single real scheme (Bearer, …) alongside a
// no-op one means auth IS available, so the list is not flagged — the presence
// of any genuine scheme is what provides the credential requirement.
func a2aSchemesAllNoop(schemes []string) bool {
	if len(schemes) == 0 {
		return false
	}
	for _, s := range schemes {
		if !a2aNoopAuthSchemes[strings.ToLower(strings.TrimSpace(s))] {
			return false
		}
	}
	return true
}

// a2aURLSchemeHost returns the lowercased scheme and hostname of a card url, or
// empty strings when it does not parse.
func a2aURLSchemeHost(rawURL string) (scheme, host string) {
	if rawURL == "" {
		return "", ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", ""
	}
	return strings.ToLower(u.Scheme), strings.ToLower(u.Hostname())
}

// a2aIsLoopbackHost reports whether a host is loopback/local — cleartext to
// these is ordinary local development, not a remotely exploitable downgrade.
func a2aIsLoopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0", "":
		return true
	}
	return strings.HasSuffix(host, ".localhost")
}

// a2aHardInjectionPatterns are directives with no benign reading inside an A2A
// discovery document — each was checked against "would a legitimate agent
// developer ever write this in a capability description?" and none survive it.
// They are deliberately a curated, tighter set than the shared
// behavioralManipulationPatterns used for tool descriptions: because a match here
// fails the whole card fetch (HTTP 403), loose members of that set that have an
// ordinary-English reading ("regardless of", "without question") are demoted to
// the AUDIT tier below rather than blocking a real card. ("Only BLOCK what you
// can justify" — CLAUDE.md.)
var a2aHardInjectionPatterns = []signalPattern{
	{regexp.MustCompile(`(ignore|disregard|discard|forget)\s+(all\s+)?(previous|prior|earlier|the\s+above)\s+(instructions?|prompts?|context|messages?|rules?)`), "instruction override (ignore previous instructions)"},
	{regexp.MustCompile(`ignore\s+(all\s+)?(your\s+)?(safety|security|guardrails?|guidelines?)`), "instruction override (ignore safety)"},
	{regexp.MustCompile(`override\s+(all\s+)?(previous|prior|system|your\s+system)\b`), "instruction override (override system)"},
	{regexp.MustCompile(`<(important|system|instructions?|cmd)>`), "hidden instruction tag"},
	{regexp.MustCompile(`(disable|bypass|circumvent|remove|turn\s+off)\s+(your\s+)?(safety|security|restrictions?|filters?|guardrails?|guidelines?|limits?)`), "behavioral takeover (disable safety controls)"},
	{regexp.MustCompile(`(jailbreak|developer\s+mode|dan\s+mode|unrestricted\s+mode|god\s+mode)`), "behavioral takeover (jailbreak / mode switch)"},
	{regexp.MustCompile(`your\s+(new|real|true|actual)\s+(role|instructions?|goal|objective|purpose|task|mission)\s+(is|are)\b`), "behavioral takeover (role reassignment)"},
	{regexp.MustCompile(`from\s+now\s+on[,\s]+(you|always|never|do\s+not|don'?t)\b`), "behavioral takeover (from-now-on directive)"},
	{regexp.MustCompile(`forget\s+(your|all)\s+(previous|prior|original|default)\s+(instructions?|training|guidelines?|rules?|behavio)`), "behavioral takeover (forget instructions)"},
	{regexp.MustCompile(`you\s+are\s+(now\s+)?(no\s+longer|free\s+from|released\s+from|not\s+bound\s+by)\b`), "behavioral takeover (liberation claim)"},
	{regexp.MustCompile(`(pretend|act)\s+(to\s+be|as\s+if)\s+(you\s+)?(are|have\s+no|don'?t\s+have|a\s+different)`), "behavioral takeover (impersonation / roleplay directive)"},
}

// a2aSuspiciousProseRules are shared pattern sets whose members can appear, with
// an innocent reading, in a longer capability description — an agent that
// genuinely forwards data or references a config path. They are AUDIT: a receipt,
// not a block.
type a2aProseRuleSet struct {
	patterns []signalPattern
	label    string
}

var a2aSuspiciousProseRules = []a2aProseRuleSet{
	{exfiltrationPatterns, "data-exfiltration phrasing"},
	{crossToolPatterns, "cross-agent routing / redirect phrasing"},
	{stealthPatterns, "concealment phrasing"},
	{credentialHarvestPatterns, "sensitive credential-path reference"},
}

// scanA2ACardProse inspects every prose field of the card that an orchestrator
// LLM reads while routing: the card description and name, and each skill's name,
// description and examples.
func scanA2ACardProse(card *A2AAgentCard) []A2AScanFinding {
	var findings []A2AScanFinding

	findings = append(findings, scanA2AProseField("description", card.Description)...)
	findings = append(findings, scanA2AIdentifier("name", card.Name)...)

	for i, raw := range card.Skills {
		sk, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		prefix := fmt.Sprintf("skills[%d]", i)
		if name := a2aString(sk["name"]); name != "" {
			findings = append(findings, scanA2AIdentifier(prefix+".name", name)...)
			findings = append(findings, scanA2AProseField(prefix+".name", name)...)
		}
		if desc := a2aString(sk["description"]); desc != "" {
			findings = append(findings, scanA2AProseField(prefix+".description", desc)...)
		}
		for j, ex := range a2aStringSlice(sk["examples"]) {
			findings = append(findings, scanA2AProseField(fmt.Sprintf("%s.examples[%d]", prefix, j), ex)...)
		}
	}
	return findings
}

// scanA2AProseField runs the injection detectors against one prose field. It uses
// the same render-recovery machinery as the rest of the MCP scanners so a
// fullwidth / homoglyph / zero-width-obfuscated directive is caught, and it stops
// at the first match per severity tier per field to keep the finding list — the
// audit receipt — legible.
func scanA2AProseField(field, text string) []A2AScanFinding {
	if text == "" {
		return nil
	}
	var findings []A2AScanFinding
	forms := newProseForms(text)

	// BLOCK tier — curated, zero-benign-reading directives (recovery-aware).
	for _, p := range a2aHardInjectionPatterns {
		if note, ok := proseMatchNote(p.re, forms); ok {
			findings = append(findings, A2AScanFinding{
				Signal: SignalA2ACardInjection,
				Detail: "A2A agent card prose carries a " + p.description +
					" — the orchestrator reads this field before routing tasks; no legitimate discovery document contains such a directive" + note,
				Field: field,
				Value: a2aSnippet(text),
			})
			break
		}
	}
	// BLOCK tier — tokenizer role delimiters (case-sensitive, raw text) and forged
	// tool-call dispatch syntax. Both reframe the orchestrator's context from a
	// field it treats as trusted metadata.
	for _, p := range llmRoleTokenPatterns {
		if p.re.MatchString(text) {
			findings = append(findings, A2AScanFinding{
				Signal: SignalA2ACardInjection,
				Detail: "A2A agent card prose embeds an LLM tokenizer role delimiter (" + p.description +
					") — forges a conversation turn inside a discovery document read by the orchestrator",
				Field: field,
				Value: a2aSnippet(text),
			})
			break
		}
	}
	for _, pf := range detectToolCallSyntaxInjection(text) {
		findings = append(findings, A2AScanFinding{
			Signal: SignalA2ACardInjection,
			Detail: "A2A agent card prose embeds forged tool-call dispatch syntax — " + pf.Detail,
			Field:  field,
			Value:  a2aSnippet(text),
		})
		break
	}

	// AUDIT tier — softer capability prose (recovery-aware).
	for _, set := range a2aSuspiciousProseRules {
		for _, p := range set.patterns {
			if note, ok := proseMatchNote(p.re, forms); ok {
				findings = append(findings, A2AScanFinding{
					Signal: SignalA2ACardSuspiciousProse,
					Detail: "A2A agent card prose contains " + set.label + " (" + p.description +
						") in a field the orchestrator routes on" + note,
					Field: field,
					Value: a2aSnippet(text),
				})
				break
			}
		}
	}
	return findings
}

// scanA2AIdentifier flags a card/skill NAME carrying Unicode confusables or
// invisibles — an identifier impersonating a trusted agent/skill. AUDIT.
func scanA2AIdentifier(field, name string) []A2AScanFinding {
	if name == "" {
		return nil
	}
	scan := pkgunicode.Scan(name)
	if scan.Clean {
		return nil
	}
	var findings []A2AScanFinding
	seen := make(map[string]bool, len(scan.Threats))
	for _, threat := range scan.Threats {
		if seen[threat.Category] {
			continue
		}
		seen[threat.Category] = true
		findings = append(findings, A2AScanFinding{
			Signal: SignalA2ACardConfusableName,
			Detail: "A2A agent card identifier contains " + threat.Description +
				" — a confusable or invisible character impersonates a trusted agent/skill the orchestrator routes to (confused-deputy)",
			Field: field,
			Value: name,
		})
	}
	return findings
}

// a2aString returns v as a string, or "" if v is not a JSON string.
func a2aString(v interface{}) string {
	s, _ := v.(string)
	return s
}

// a2aStringSlice returns the string elements of v when v is a JSON array. A2A
// skill `examples` is an array of natural-language strings; non-string elements
// (or a non-array value) are skipped.
func a2aStringSlice(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// a2aSnippet truncates prose to a bounded length for the audit receipt.
func a2aSnippet(s string) string {
	const max = 120
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
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
			reason := "A2A agent card failed AgentShield inspection"
			for _, f := range scan.Findings {
				if a2aBlockingSignal(f.Signal) {
					reason = f.Detail
					break
				}
			}
			body, _ := json.Marshal(map[string]string{"error": "blocked", "reason": reason})
			return true, http.StatusForbidden, body
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
