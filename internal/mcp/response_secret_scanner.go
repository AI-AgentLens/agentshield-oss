package mcp

import (
	"fmt"
	"regexp"
	"strings"
)

// Tool-response SECRET OVEREXPOSURE scanner (server→agent direction).
//
// content_scanner.go's ScanToolCallContent scans the OUTBOUND direction: does
// an argument the agent is about to SEND to a tool carry a credential? This
// file scans the opposite, previously-uncovered direction: does a tool's
// RESPONSE hand the agent a credential it was never supposed to see?
//
// # Why a tool allowlist cannot work here
//
// Confirmed instance: CVE-2026-67357 / GHSA-p9wc-4fhr-78wm (ArcadeDB, fixed
// 26.7.3). ArcadeDB's MCP `get_server_settings` tool — a read-only, ordinary-
// looking diagnostic — returned `arcadedb.ha.clusterToken` in cleartext as one
// field among general server configuration. ArcadeDB's HTTP API accepts that
// token together with `X-ArcadeDB-Forwarded-User` to impersonate an arbitrary
// principal, including root, for inter-node cluster traffic — so one ordinary,
// successful, non-error tool call converted routine read access into full
// server compromise. No prompt injection and no malformed input: the tool
// worked exactly as designed, and the design was the vulnerability.
//
// The disclosing tool is, by construction, never on a pre-built list of
// "credential tools" — nobody threat-models a settings/status/diagnostics
// endpoint the way they threat-model a write path. So this scanner is
// tool-name-independent: it runs on every tools/call response, the same way
// ScanToolCallResponseForTracebacks and ScanContentRankingChannel do.
//
// Taxonomy: data-exfiltration/llm-data-flow/mcp-tool-response-secret-overexposure
// (AI_risk_compliance#4146). Its own `recommendation` names this scanner.
//
// # Two independent tiers
//
// BLOCK — the value matches one of the same high-confidence credential SHAPES
// content_scanner.go already recognizes for the outbound direction (AWS
// access key, GitHub token, Slack token, Stripe key, PEM private key block,
// a Bearer-prefixed token, basic-auth-in-URL, a credentialed database URI, or
// a `key=value`-shaped generic secret assignment). These regexes are
// vendor-specific and near-zero-FP regardless of which field they appear in —
// reused verbatim via scanArgumentValue rather than re-implemented.
//
// AUDIT — a structuredContent field NAME matches the taxonomy node's own
// suggested vocabulary (`*token*`, `*secret*`, `*password*`, `*credential*`,
// `*api[-_]key*`, `*private[-_]key*`, `*access[-_]key*` — deliberately NOT
// bare `*key*`, which collides with S3 object keys, map/cache/partition keys,
// and primary/foreign-key vocabulary far too often to be useful) AND the
// value is opaque and token-shaped rather than a short enum/boolean/prose
// word. This is the tier that catches the ArcadeDB shape itself: a cluster
// token is not a recognized vendor format, so only the field name gives it
// away.
//
// The taxonomy node's own precision note — corroborated by the paired Comply
// static rule (`ai-mcp-tool-response-secret-overexposure-python`,
// AI_risk_compliance#4146) — is that in agent traffic "token" overwhelmingly
// means an LLM billing unit (`max_tokens`, `prompt_tokens`, `token_count`,
// ...). llmTokenUsageFieldNames excludes that vocabulary so the AUDIT tier
// does not fire on nearly every tool response in existence.
func ScanToolCallResponseForSecrets(content []ContentItem, structuredContent map[string]interface{}) ResponseSecretScanResult {
	var result ResponseSecretScanResult

	for i, item := range content {
		if item.Type != "text" || item.Text == "" {
			continue
		}
		if finding, ok := matchKnownSecretShapeForResponse(item.Text); ok {
			finding.ContentIndex = i
			finding.Blocking = true
			result.Findings = append(result.Findings, finding)
		}
	}

	if len(structuredContent) > 0 {
		scanStructuredContentForSecrets(&result, "", structuredContent)
	}

	result.Found = len(result.Findings) > 0
	for _, f := range result.Findings {
		if f.Blocking {
			result.Blocked = true
			break
		}
	}
	return result
}

// ResponseSecretSignal identifies which tier of the tool-response secret scan
// produced a finding.
type ResponseSecretSignal string

const (
	// SignalResponseSecretConfirmedPattern fires when a response value matches
	// one of content_scanner.go's vendor-specific credential shapes. BLOCK.
	SignalResponseSecretConfirmedPattern ResponseSecretSignal = "response_secret_confirmed_pattern"
	// SignalResponseSecretFieldName fires when a structuredContent field name
	// matches the taxonomy's secret-naming vocabulary and its value is
	// opaque/token-shaped rather than a short enum, boolean, or prose word.
	// AUDIT — the field name is a strong but not certain signal on its own.
	SignalResponseSecretFieldName ResponseSecretSignal = "response_secret_field_name"
)

// ResponseSecretFinding records one detected secret-shaped value in a tool
// call response.
type ResponseSecretFinding struct {
	Signal ResponseSecretSignal `json:"signal"`
	Detail string                `json:"detail"`
	// Field is the dotted structuredContent field path (e.g.
	// "arcadedb.ha.clusterToken"). Empty for a Content text-block finding.
	Field string `json:"field,omitempty"`
	// ContentIndex is the index into the Content array for a text-block
	// finding. Zero (and meaningless) for a structuredContent finding —
	// callers distinguish the two by checking Field.
	ContentIndex int `json:"content_index,omitempty"`
	// Blocking distinguishes the BLOCK-tier signal from the AUDIT-tier one so
	// the call site can act on a mixed-tier result without re-deriving the
	// mapping from the signal name.
	Blocking bool `json:"blocking"`
}

// ResponseSecretScanResult is the outcome of ScanToolCallResponseForSecrets.
type ResponseSecretScanResult struct {
	// Blocked is true when at least one BLOCK-tier finding was produced.
	Blocked bool `json:"blocked"`
	// Found is true when any finding was produced, at any tier.
	Found    bool                     `json:"found"`
	Findings []ResponseSecretFinding `json:"findings,omitempty"`
}

// scanStructuredContentForSecrets walks a structuredContent JSON object
// depth-first, tracking the dotted field path so both the confirmed-pattern
// check and the field-name heuristic can see it. Mirrors the walk shape of
// scanStructuredNode (structured_content_scanner.go), extended to carry the
// key path a field-name heuristic requires.
func scanStructuredContentForSecrets(result *ResponseSecretScanResult, path string, v interface{}) {
	switch val := v.(type) {
	case string:
		if val == "" {
			return
		}
		if finding, ok := matchKnownSecretShapeForResponse(val); ok {
			finding.Field = path
			finding.Blocking = true
			result.Findings = append(result.Findings, finding)
			return
		}
		if path != "" && isSensitiveSecretFieldName(path) && looksLikeOpaqueSecretValue(val) {
			result.Findings = append(result.Findings, ResponseSecretFinding{
				Signal: SignalResponseSecretFieldName,
				Detail: fmt.Sprintf(
					"field %q matches secret-naming convention (token/secret/password/credential/key) and carries an opaque value that is not an LLM token-usage counter",
					path,
				),
				Field:    path,
				Blocking: false,
			})
		}
	case map[string]interface{}:
		for k, child := range val {
			childPath := k
			if path != "" {
				childPath = path + "." + k
			}
			scanStructuredContentForSecrets(result, childPath, child)
		}
	case []interface{}:
		for _, item := range val {
			scanStructuredContentForSecrets(result, path, item)
		}
	}
}

// matchKnownSecretShapeForResponse checks text against the same vendor-
// specific credential shapes content_scanner.go's scanArgumentValue already
// recognizes for the outbound argument direction, reusing the compiled
// patterns rather than duplicating them. Only the confirmed-credential-shape
// signals are surfaced — scanArgumentValue also runs base64/high-entropy/SSTI/
// invisible-Unicode/obfuscated-byte-array checks that are argument-direction
// heuristics tuned for exfiltration payloads an agent is SENDING, not
// credentials a server is unexpectedly HANDING BACK, and would add response-
// scanning noise (large legitimate base64 blobs, high-entropy hashes, etc.
// are common and benign in tool output) far beyond what this scanner's
// higher-precision tier is meant to add.
func matchKnownSecretShapeForResponse(text string) (ResponseSecretFinding, bool) {
	var tmp ContentScanResult
	scanArgumentValue(&tmp, "", text)
	for _, f := range tmp.Findings {
		switch f.Signal {
		case SignalPrivateKey, SignalAWSCredential, SignalGitHubToken, SignalBearerToken,
			SignalBasicAuth, SignalSlackToken, SignalStripeKey, SignalGenericSecret, SignalDatabaseURI:
			return ResponseSecretFinding{
				Signal: SignalResponseSecretConfirmedPattern,
				Detail: f.Detail + " in tool response",
			}, true
		}
	}
	return ResponseSecretFinding{}, false
}

// sensitiveFieldNameRe matches structuredContent field names that
// conventionally carry secret material. Deliberately excludes bare "key" —
// S3 object keys, map/dictionary keys, cache keys, and primary/foreign-key
// database vocabulary make an unqualified "key" match far too noisy to be
// useful; only the compound, unambiguous forms (api_key, private_key,
// access_key) are included.
var sensitiveFieldNameRe = regexp.MustCompile(`(?i)(token|secret|passwd|password|credential|api[_-]?key|private[_-]?key|access[_-]?key|auth[_-]?key)`)

// llmTokenUsageFieldNames excludes field names that are near-universal LLM
// billing/usage counters, normalized (lowercased, non-alphanumeric stripped)
// so "max_tokens" and "maxTokens" match the same entry. Without this, the
// field-name heuristic fires on nearly every tool response in an LLM agent
// pipeline, since "tokens" is the single most common numeric field name in
// that domain — the exact false-positive class the taxonomy node's own
// precision note (corroborated by the paired Comply static rule) calls out.
var llmTokenUsageFieldNames = map[string]bool{
	"maxtokens":        true,
	"prompttokens":     true,
	"completiontokens": true,
	"totaltokens":      true,
	"tokencount":       true,
	"tokenusage":       true,
	"tokenlimit":       true,
	"numtokens":        true,
	"tokenizer":        true,
	"inputtokens":      true,
	"outputtokens":     true,
	"reasoningtokens":  true,
	"cachedtokens":     true,
	"cachereadtokens":  true,
	"cachewritetokens": true,
	"tokensused":       true,
	"contexttokens":    true,
	"tokens":           true,
}

// nonAlnumFieldNameRe strips everything but letters and digits so field-name
// spellings ("max_tokens", "maxTokens", "MAX-TOKENS") normalize identically.
var nonAlnumFieldNameRe = regexp.MustCompile(`[^a-z0-9]+`)

// isSensitiveSecretFieldName reports whether the leaf segment of a dotted
// structuredContent field path matches the secret-naming vocabulary and is
// not an excluded LLM token-usage counter. Only the leaf is checked against
// the exclusion set (a path like "usage.total_tokens" must exclude on
// "total_tokens", not on the unrelated prefix), while the vocabulary regex is
// a plain substring match so it doesn't matter whether the full path or the
// leaf is passed to it.
func isSensitiveSecretFieldName(path string) bool {
	leaf := path
	if idx := strings.LastIndex(path, "."); idx >= 0 {
		leaf = path[idx+1:]
	}
	if !sensitiveFieldNameRe.MatchString(leaf) {
		return false
	}
	normalized := nonAlnumFieldNameRe.ReplaceAllString(strings.ToLower(leaf), "")
	return !llmTokenUsageFieldNames[normalized]
}

// opaqueTokenShapeRe matches the character set a real credential/token value
// is drawn from (base64url-ish, no whitespace), with a 16-character floor. A
// field name alone is not enough — "role": "administrator" would otherwise
// false-positive on no vocabulary match, and neither is a lower floor: a
// 12-15 char kebab-case phrase with a trailing number ("min-length-12" under
// a "password_policy" field) satisfies a digit+lowercase class mix while
// being ordinary config prose, not a secret. Real tokens/keys/hashes are
// almost universally 16+ characters, so the floor alone screens out most of
// that FP class without needing entropy analysis.
var opaqueTokenShapeRe = regexp.MustCompile(`^[A-Za-z0-9_\-./+=]{16,}$`)

// looksLikeOpaqueSecretValue reports whether a string value looks like
// token/secret material rather than a short enum, boolean, or English word:
// token-charset only, at least 16 characters, and either at least 24
// characters (covers all-lowercase-hex hashes and UUIDs) or a mix of at least
// two of {digit, uppercase, lowercase} (excludes plain words like
// "administrator" or "read-only" that happen to be long enough but carry no
// digit or case variation).
func looksLikeOpaqueSecretValue(s string) bool {
	if !opaqueTokenShapeRe.MatchString(s) {
		return false
	}
	if len(s) >= 24 {
		return true
	}
	classes := 0
	if strings.ContainsAny(s, "0123456789") {
		classes++
	}
	if strings.ContainsAny(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		classes++
	}
	if strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyz") {
		classes++
	}
	return classes >= 2
}

// responseSecretSentinelEngine returns the mcp-sentinel.yaml `engine` key that
// gives a signal's finding a stable rule ID, reason, and remediation via
// PolicyEvaluator.LookupSentinel.
func responseSecretSentinelEngine(signal ResponseSecretSignal) string {
	switch signal {
	case SignalResponseSecretConfirmedPattern:
		return "mcp-response-secret-confirmed-pattern"
	case SignalResponseSecretFieldName:
		return "mcp-response-secret-field-name"
	default:
		return ""
	}
}
