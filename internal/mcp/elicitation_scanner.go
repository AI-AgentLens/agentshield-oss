package mcp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ElicitationSignal identifies a type of abuse detected in an elicitation/create request.
type ElicitationSignal string

const (
	// SignalElicitationCredential is raised when the requested schema includes
	// credential-like field names (password, token, api_key, etc.). BLOCK.
	SignalElicitationCredential ElicitationSignal = "elicitation_credential_field"

	// SignalElicitationSocialEngineering is raised when the elicitation message
	// contains urgency language, threat framing, or explicit credential requests. AUDIT.
	SignalElicitationSocialEngineering ElicitationSignal = "elicitation_social_engineering"

	// SignalElicitationFatigue is raised when an MCP server sends >3 elicitation/create
	// requests within 60 seconds — a rate consistent with fatigue-based desensitization
	// attacks. AUDIT decision.
	SignalElicitationFatigue ElicitationSignal = "elicitation_fatigue"

	// SignalElicitationControlToken is raised when the elicitation/create message
	// embeds an LLM tokenizer ROLE delimiter (<|im_start|>, <<SYS>>, [/INST], …) or
	// forged tool-CALL dispatch control syntax (<function_calls>/<invoke>,
	// <|python_tag|>/<|tool_call|>, [TOOL_REQUEST]/[TOOL_CALLS]). The elicitation
	// message is rendered into the host UI and, with the user's reply, into the
	// agent's conversation context — so a forged role TURN or tool CALL planted here
	// is a high-confidence injection, not mere social engineering. BLOCK.
	//
	// Distinct from SignalElicitationSocialEngineering (natural-language urgency /
	// credential-request prose, AUDIT). These are architecture-specific control
	// tokens with zero legitimate use in an elicitation prompt — the fourth
	// server->agent text surface in the control-token sweep (after tool
	// descriptions, prompt content, and resource metadata).
	SignalElicitationControlToken ElicitationSignal = "elicitation_control_token"
)

// syntheticElicitationFatigue is the virtual tool name injected into the audit log
// when elicitation fatigue is detected. Mirrors the pattern used by other guardian
// scanners (e.g. syntheticApprovalBurst in approval_fatigue.go).
const syntheticElicitationFatigue = "__mcp_elicitation_fatigue__"

const (
	// elicitationFatigueWindow is the sliding window used for rate limiting.
	elicitationFatigueWindow = 60 * time.Second
	// elicitationFatigueThreshold is the maximum number of elicitation requests
	// allowed within elicitationFatigueWindow before fatigue is signalled.
	elicitationFatigueThreshold = 3
	// elicitationFatigueHistoryMax bounds tracker memory in long-running sessions.
	elicitationFatigueHistoryMax = 120
)

// ElicitationFatigueTracker records per-session elicitation/create request timestamps
// and signals when an MCP server exceeds the rate limit. A nil tracker silently
// disables fatigue detection (zero overhead).
//
// In HTTP Streamable proxy mode one MessageHandler serves all clients, so this tracker
// crosses session boundaries; the AUDIT signal remains useful as an aggregate anomaly
// indicator. The primary use case (stdio proxy, one agent = one session) is exact.
type ElicitationFatigueTracker struct {
	history boundedHistory[time.Time]
}

// NewElicitationFatigueTracker returns a ready tracker.
func NewElicitationFatigueTracker() *ElicitationFatigueTracker {
	return &ElicitationFatigueTracker{history: newBoundedHistory[time.Time](elicitationFatigueHistoryMax)}
}

// Record records a new elicitation request at the given time and reports whether
// the fatigue threshold has been exceeded. The count returned is the number of
// requests (including this one) within the sliding window.
func (t *ElicitationFatigueTracker) Record(now time.Time) (exceeded bool, count int) {
	count = t.history.mutate(func(entries []time.Time) []time.Time {
		cutoff := now.Add(-elicitationFatigueWindow)

		// Prune entries outside the window, then record the new request.
		fresh := entries[:0]
		for _, ts := range entries {
			if ts.After(cutoff) {
				fresh = append(fresh, ts)
			}
		}
		return append(fresh, now)
	})
	exceeded = count > elicitationFatigueThreshold
	return
}

// ElicitationFatigueDetail returns the human-readable detail string for a fatigue finding.
func ElicitationFatigueDetail(count int) string {
	return fmt.Sprintf("elicitation fatigue: %d requests within %s (threshold: %d) — server may be desensitizing user to approve dangerous prompts",
		count, elicitationFatigueWindow, elicitationFatigueThreshold)
}

// ElicitationFinding records one detected abuse signal in an elicitation/create request.
type ElicitationFinding struct {
	Signal  ElicitationSignal `json:"signal"`
	Detail  string            `json:"detail"`
	Snippet string            `json:"snippet,omitempty"`
}

// ElicitationScanResult is the result of scanning an elicitation/create request.
type ElicitationScanResult struct {
	// Blocked is true when the request should be blocked outright (BLOCK decision).
	// Blocked requests always have at least one credential-field finding.
	Blocked bool `json:"blocked"`

	// Audited is true when the request should be audit-logged (AUDIT decision).
	// This is set for social-engineering patterns even when Blocked is false.
	Audited bool `json:"audited"`

	Findings []ElicitationFinding `json:"findings,omitempty"`
}

// credentialFieldNames are unambiguous property names in elicitation schemas
// that indicate a credential-harvesting attempt. Matched case-insensitively
// as a substring against the JSON property key and its title/description —
// safe because every entry here is already qualified enough that it has no
// plausible benign reading. Genuine homonyms (bare "token", "pin", "secret",
// "credential") are NOT here — see ambiguousCredentialWords.
var credentialFieldNames = []string{
	"password",
	"passwd",
	"passphrase",
	"secret_key",
	"secretkey",
	"api_key",
	"apikey",
	"api_token",
	"apitoken",
	"access_key",
	"accesskey",
	"access_token",
	"accesstoken",
	"auth_token",
	"authtoken",
	"session_token",
	"sessiontoken",
	"private_key",
	"privatekey",
	"ssn",
	"social_security",
	"credit_card",
	"creditcard",
	"card_number",
	"cvv",
	"pin_code",
	"aws_secret",
	"aws_access_key",
	"github_token",
	"mfa_code",
	"mfa_token",
	"otp",
	"otp_code",
	"totp",
	"totp_code",
	"verification_code",
	"auth_code",
	"2fa_code",
	"two_factor",
}

// ambiguousCredentialWords are short, common words that are genuine
// homonyms: "token" is as often an LLM token (max_tokens, token_count) as an
// auth token; "pin" is as often UI/version pinning (pinned_release) or a
// counter (spin_count) as a PIN code; "secret" and "credential" show up in
// unrelated config prose too. Matched only as a delimiter-bounded whole word
// — never a bare substring — and suppressed for known-benign compounds (see
// benignAmbiguousCompounds). Unqualified substring matching on these words
// BLOCKed ordinary elicitation forms asking for max_tokens / pinned_release /
// spin_count (#3290).
var ambiguousCredentialWords = map[string]bool{
	"token":       true,
	"pin":         true,
	"secret":      true,
	"credential":  true,
	"credentials": true,
}

// benignAmbiguousCompounds are exact property names (or free-text words)
// that contain an ambiguousCredentialWords entry as a delimiter-bounded
// segment but are ordinary, non-credential fields. Exact match only — a
// narrow escape hatch, not a general allowlist.
var benignAmbiguousCompounds = map[string]bool{
	"max_tokens":     true,
	"token_count":    true,
	"input_tokens":   true,
	"output_tokens":  true,
	"token_limit":    true,
	"tokenizer":      true,
	"pinned_release": true,
	"spin_count":     true,
}

// ambiguousWordSplitter breaks a lower-cased property name or text string
// into delimiter-bounded segments for ambiguousCredentialWords matching.
var ambiguousWordSplitter = regexp.MustCompile(`[^a-z0-9]+`)

// socialEngineeringPatterns match urgency/threat language in elicitation messages.
var socialEngineeringPatterns = []signalPattern{
	{regexp.MustCompile(`\burgent(ly)?\b`), "Urgency language in elicitation message"},
	{regexp.MustCompile(`\bimmediately\b`), "Urgency language in elicitation message"},
	{regexp.MustCompile(`or (your )?account will\b`), "Threat-based coercion (account loss)"},
	{regexp.MustCompile(`(confirm|approve) (the )?(deletion|removal|destroy|wipe|purge|drop|reset)\b`), "Approval laundering: framing destructive action as confirmation"},
	{regexp.MustCompile(`(bypass|override|disable|skip) (the )?(safety|check|validation|approval|review|restriction)\b`), "Social engineering: bypass safety controls"},
	{regexp.MustCompile(`enter (your )?(\w+ )?(password|secret|token|key|credentials?|api.?key)\b`), "Explicit credential request in message text"},
	{regexp.MustCompile(`provide (your )?(\w+ )?(password|secret|token|key|credentials?|api.?key)\b`), "Explicit credential request in message text"},
	{regexp.MustCompile(`(required|needed) to (continue|proceed|complete)\b`), "Coercive framing: credential required to proceed"},
	{regexp.MustCompile(`(your )?(aws|gcp|azure|github|gitlab) (credentials?|access.?key|secret)\b`), "Named cloud/service credential request"},
}

// ScanElicitationCreate inspects an elicitation/create request for abuse patterns.
//
// Decision logic:
//   - BLOCK  (Blocked=true):  requestedSchema contains credential-like property names
//   - AUDIT  (Audited=true):  message text contains social-engineering language
//   - ALLOW  (both false):    no suspicious patterns detected
func ScanElicitationCreate(params *ElicitationCreateParams) ElicitationScanResult {
	var result ElicitationScanResult

	// --- Schema property name scan (BLOCK) ---
	reportedProps := map[string]bool{}
	if params.RequestedSchema != nil {
		for propName, prop := range params.RequestedSchema.Properties {
			lower := strings.ToLower(propName)
			reportedProps[lower] = true
			if matched, detail := isCredentialField(lower); matched {
				result.Findings = append(result.Findings, ElicitationFinding{
					Signal:  SignalElicitationCredential,
					Detail:  detail,
					Snippet: "property: " + propName,
				})
				result.Blocked = true
			}

			// Also check property title and description text
			if prop != nil {
				combined := strings.ToLower(prop.Title + " " + prop.Description)
				if combined != " " && matchesCredentialSignal(combined) {
					result.Findings = append(result.Findings, ElicitationFinding{
						Signal:  SignalElicitationCredential,
						Detail:  "credential keyword in property description: " + prop.Title + " " + prop.Description,
						Snippet: "property: " + propName,
					})
					result.Blocked = true
				}
			}
		}

		// --- Raw-schema pass (BLOCK) ---
		//
		// The typed loop above only sees flat, top-level properties, because
		// that is all ElicitationSchema models. Wrapping the same credential
		// field in `allOf`, nesting it one object deep, parking it in `$defs`
		// or naming it only in `required` empties Properties entirely and the
		// loop above runs zero iterations — while the host still renders the
		// form and a human still types their SSH key into it. Re-walk the
		// bytes that actually arrived.
		//
		// Findings are keyed by path, and top-level paths are exactly
		// "."+propName, so anything the typed loop already reported is skipped
		// rather than double-reported.
		for _, p := range elicitationRawSchemaFindings(params.RequestedSchema, reportedProps) {
			result.Findings = append(result.Findings, p)
			result.Blocked = true
		}

		// Also scan the schema title
		if params.RequestedSchema.Title != "" {
			lowerTitle := strings.ToLower(params.RequestedSchema.Title)
			if matchesCredentialSignal(lowerTitle) {
				result.Findings = append(result.Findings, ElicitationFinding{
					Signal:  SignalElicitationCredential,
					Detail:  "credential keyword in schema title: " + params.RequestedSchema.Title,
					Snippet: "schema title",
				})
				result.Blocked = true
			}
		}
	}

	// --- Message text scan (AUDIT) ---
	if params.Message != "" {
		lower := strings.ToLower(params.Message)

		for _, p := range socialEngineeringPatterns {
			if loc := p.re.FindStringIndex(lower); loc != nil {
				result.Findings = append(result.Findings, ElicitationFinding{
					Signal:  SignalElicitationSocialEngineering,
					Detail:  p.description,
					Snippet: safeSnippet(params.Message, loc[0], 80),
				})
				result.Audited = true
				break // one social-engineering finding per message is sufficient
			}
		}

		// Control-token injection (BLOCK) — LLM role delimiters or forged tool-call
		// dispatch syntax in the elicitation message. Matched case-sensitively
		// against the raw message (these tokens are architecture-specific).
		for _, p := range llmRoleTokenPatterns {
			if loc := p.re.FindStringIndex(params.Message); loc != nil {
				result.Findings = append(result.Findings, ElicitationFinding{
					Signal:  SignalElicitationControlToken,
					Detail:  "elicitation message contains LLM tokenizer role delimiter: " + p.description,
					Snippet: safeSnippet(params.Message, loc[0], 80),
				})
				result.Blocked = true
				break
			}
		}
		if loc := toolCallDispatchTokenRE.FindStringIndex(params.Message); loc != nil {
			result.Findings = append(result.Findings, ElicitationFinding{
				Signal:  SignalElicitationControlToken,
				Detail:  "elicitation message contains forged tool-call / function-invocation control syntax (<function_calls>/<invoke>, <|python_tag|>/<|tool_call|>, or [TOOL_REQUEST]/[TOOL_CALLS]) — a harness parsing tool-call syntax from the rendered prompt may dispatch an unsanctioned privileged call",
				Snippet: safeSnippet(params.Message, loc[0], 80),
			})
			result.Blocked = true
		}
	}

	return result
}

// elicitationRawSchemaFindings walks the verbatim requestedSchema JSON and
// reports credential-shaped property names (and property title/description
// text) that the typed ElicitationSchema view cannot represent.
//
// alreadyReported holds the lower-cased top-level property names the typed pass
// handled; those are skipped so the two passes never double-report the same
// field. Everything else — composition branches, nested objects, array item
// schemas, $defs, and `required`-only names — is new coverage.
//
// A schema that fails to parse yields no findings: the request is malformed
// JSON-RPC and the surrounding message/title scans still apply.
func elicitationRawSchemaFindings(schema *ElicitationSchema, alreadyReported map[string]bool) []ElicitationFinding {
	if schema == nil || len(schema.Raw) == 0 {
		return nil
	}
	var root map[string]interface{}
	if err := json.Unmarshal(schema.Raw, &root); err != nil {
		return nil
	}

	var findings []ElicitationFinding
	seen := map[string]bool{}
	forEachSchemaProperty(root, func(p schemaProperty) {
		path := p.Path[1:]
		if alreadyReported[strings.ToLower(p.Name)] && !strings.Contains(path, ".") {
			return // top-level property; the typed pass owns it
		}
		if seen[path] {
			return
		}
		if matched, detail := isCredentialField(strings.ToLower(p.Name)); matched {
			seen[path] = true
			findings = append(findings, ElicitationFinding{
				Signal: SignalElicitationCredential,
				Detail: detail + " (at schema path `" + path + "`, outside the flat top-level" +
					" shape the MCP elicitation schema is specified to use — a human, not the" +
					" agent, fills this field in)",
				Snippet: "property: " + path,
			})
			return
		}
		if p.Schema == nil {
			return
		}
		title, _ := p.Schema["title"].(string)
		desc, _ := p.Schema["description"].(string)
		combined := strings.ToLower(title + " " + desc)
		if strings.TrimSpace(combined) == "" {
			return
		}
		if matchesCredentialSignal(combined) {
			seen[path] = true
			findings = append(findings, ElicitationFinding{
				Signal:  SignalElicitationCredential,
				Detail:  "credential keyword in property description at schema path `" + path + "`: " + title + " " + desc,
				Snippet: "property: " + path,
			})
		}
	})
	return findings
}

// matchesCredentialSignal reports whether lowerText (a property name or a
// title/description string, already lower-cased) contains a credential
// signal: an unambiguous credentialFieldNames entry as a substring, or an
// ambiguousCredentialWords entry as a delimiter-bounded whole word that
// isn't itself a known-benign compound.
func matchesCredentialSignal(lowerText string) bool {
	for _, cred := range credentialFieldNames {
		if strings.Contains(lowerText, cred) {
			return true
		}
	}
	if benignAmbiguousCompounds[lowerText] {
		return false
	}
	for _, seg := range ambiguousWordSplitter.Split(lowerText, -1) {
		if ambiguousCredentialWords[seg] {
			return true
		}
	}
	return false
}

// isCredentialField checks whether a schema property name is a
// credential-like field. Returns (matched, detail).
func isCredentialField(lowerName string) (bool, string) {
	if matchesCredentialSignal(lowerName) {
		return true, "elicitation schema requests credential field: " + lowerName
	}
	return false, ""
}
