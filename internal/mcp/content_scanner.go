package mcp

import (
	"encoding/base64"
	"fmt"
	"math"
	"regexp"
	"strings"
)

// ContentSignal identifies a type of sensitive data found in tool call arguments.
type ContentSignal string

const (
	SignalPrivateKey     ContentSignal = "private_key"
	SignalAWSCredential  ContentSignal = "aws_credential"
	SignalAPIToken       ContentSignal = "api_token"
	SignalGitHubToken    ContentSignal = "github_token"
	SignalGenericSecret  ContentSignal = "generic_secret"
	SignalBase64Blob     ContentSignal = "base64_blob"
	SignalHighEntropy    ContentSignal = "high_entropy"
	SignalBearerToken    ContentSignal = "bearer_token"
	SignalBasicAuth      ContentSignal = "basic_auth"
	SignalSlackToken     ContentSignal = "slack_token"
	SignalStripeKey      ContentSignal = "stripe_key"
	SignalEnvFileContent ContentSignal = "env_file_content"
	SignalDatabaseURI    ContentSignal = "database_uri"
)

// ContentFinding records one detected sensitive data signal in an argument value.
type ContentFinding struct {
	Signal   ContentSignal `json:"signal"`
	Detail   string        `json:"detail"`
	ArgName  string        `json:"arg_name"`
	MatchLen int           `json:"match_len,omitempty"`
}

// ContentScanResult is the result of scanning tool call arguments.
type ContentScanResult struct {
	ToolName string           `json:"tool_name"`
	Blocked  bool             `json:"blocked"`
	Findings []ContentFinding `json:"findings,omitempty"`
}

// ScanToolCallContent checks all argument values of a tool call for
// sensitive data that may indicate exfiltration. Returns findings if any
// secrets, credentials, or suspicious encoded data are detected.
func ScanToolCallContent(toolName string, arguments map[string]interface{}) ContentScanResult {
	result := ContentScanResult{ToolName: toolName}

	for argName, argValue := range arguments {
		text := argValueToString(argValue)
		if text == "" {
			continue
		}

		scanArgumentValue(&result, argName, text)
	}

	result.Blocked = len(result.Findings) > 0
	return result
}

// scanArgumentValue runs all content detection patterns against a single argument value.
func scanArgumentValue(result *ContentScanResult, argName, text string) {
	// Private keys
	if privateKeyRe.MatchString(text) {
		result.Findings = append(result.Findings, ContentFinding{
			Signal:  SignalPrivateKey,
			Detail:  "SSH/PGP private key detected in argument",
			ArgName: argName,
		})
	}

	// AWS access keys
	if awsAccessKeyRe.MatchString(text) {
		result.Findings = append(result.Findings, ContentFinding{
			Signal:  SignalAWSCredential,
			Detail:  "AWS access key ID detected",
			ArgName: argName,
		})
	}

	// AWS secret patterns
	if awsSecretRe.MatchString(text) {
		result.Findings = append(result.Findings, ContentFinding{
			Signal:  SignalAWSCredential,
			Detail:  "AWS credential assignment detected",
			ArgName: argName,
		})
	}

	// GitHub tokens
	if githubTokenRe.MatchString(text) {
		result.Findings = append(result.Findings, ContentFinding{
			Signal:  SignalGitHubToken,
			Detail:  "GitHub token detected",
			ArgName: argName,
		})
	}

	// Bearer tokens
	if bearerTokenRe.MatchString(text) {
		result.Findings = append(result.Findings, ContentFinding{
			Signal:  SignalBearerToken,
			Detail:  "Bearer token detected",
			ArgName: argName,
		})
	}

	// Basic auth in URLs
	if basicAuthRe.MatchString(text) {
		result.Findings = append(result.Findings, ContentFinding{
			Signal:  SignalBasicAuth,
			Detail:  "Basic auth credentials in URL detected",
			ArgName: argName,
		})
	}

	// Slack tokens
	if slackTokenRe.MatchString(text) {
		result.Findings = append(result.Findings, ContentFinding{
			Signal:  SignalSlackToken,
			Detail:  "Slack token detected",
			ArgName: argName,
		})
	}

	// Stripe keys
	if stripeKeyRe.MatchString(text) {
		result.Findings = append(result.Findings, ContentFinding{
			Signal:  SignalStripeKey,
			Detail:  "Stripe secret key detected",
			ArgName: argName,
		})
	}

	// Generic API key/secret assignments
	if genericSecretRe.MatchString(text) {
		result.Findings = append(result.Findings, ContentFinding{
			Signal:  SignalGenericSecret,
			Detail:  "API key or secret assignment detected",
			ArgName: argName,
		})
	}

	// .env file content (multiple KEY=VALUE lines with sensitive names)
	if looksLikeEnvFileContent(text) {
		result.Findings = append(result.Findings, ContentFinding{
			Signal:  SignalEnvFileContent,
			Detail:  "Content resembles .env file with secrets",
			ArgName: argName,
		})
	}

	// Database URIs with embedded credentials (mysql://user:pass@host/db)
	// Catches connection strings passed as tool call arguments that bypass
	// resource-read rules (taxonomy: credential-exposure/database-access).
	if m := dbURIWithCredentialsRe.FindString(text); m != "" {
		result.Findings = append(result.Findings, ContentFinding{
			Signal:  SignalDatabaseURI,
			Detail:  "Database URI with embedded credentials detected in argument",
			ArgName: argName,
		})
	}

	// Large base64 blobs (potential encoded file exfiltration)
	if b64Len := largestBase64Chunk(text); b64Len >= minBase64BlobLen {
		result.Findings = append(result.Findings, ContentFinding{
			Signal:   SignalBase64Blob,
			Detail:   fmt.Sprintf("Large base64-encoded blob (%d chars) — possible encoded file exfiltration", b64Len),
			ArgName:  argName,
			MatchLen: b64Len,
		})
	}

	// High-entropy strings (potential encoded secrets)
	if isHighEntropy(text, minHighEntropyLen) {
		result.Findings = append(result.Findings, ContentFinding{
			Signal:  SignalHighEntropy,
			Detail:  "High-entropy string detected — possible encoded secret",
			ArgName: argName,
		})
	}
}

// ── Compiled patterns ──────────────────────────────────────────────────────

var (
	privateKeyRe    = regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----`)
	awsAccessKeyRe  = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	awsSecretRe     = regexp.MustCompile(`(?i)(aws_secret_access_key|aws_access_key_id|aws_session_token)\s*[=:]\s*\S{16,}`)
	githubTokenRe   = regexp.MustCompile(`gh[ps]_[A-Za-z0-9]{36}`)
	bearerTokenRe   = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_\-.]{20,}`)
	basicAuthRe     = regexp.MustCompile(`https?://[^:]+:[^@]+@`)
	slackTokenRe    = regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`)
	stripeKeyRe     = regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`)
	genericSecretRe = regexp.MustCompile(`(?i)(api_key|apikey|api-key|secret_key|secretkey|secret-key|access_token|auth_token|private_key)\s*[=:]\s*['"]?[A-Za-z0-9_\-/+=]{16,}['"]?`)

	// dbURIWithCredentialsRe matches database connection URIs that contain
	// embedded user:password credentials. Covers MySQL, PostgreSQL, MongoDB
	// (including +srv), Redis (including rediss TLS), MSSQL, and Oracle.
	// The credentials portion ([user]:pass@) must be present — username may be
	// empty (e.g. redis://:password@host) but password must be non-empty — to
	// avoid false positives on bare host:port URIs.
	// Taxonomy: credential-exposure/database-access/database-credential-access
	dbURIWithCredentialsRe = regexp.MustCompile(`(?i)(mysql|postgres(?:ql)?|mongodb(?:\+srv)?|rediss?|mssql|oracle)://[^/\s@:]*:[^/\s@]+@`)

	envLineRe = regexp.MustCompile(`(?i)^[A-Z_]{2,}=\S+`)
)

// Thresholds
const (
	minBase64BlobLen     = 200 // characters — roughly 150 bytes decoded
	minHighEntropyLen    = 100 // characters for standalone high-entropy check
	highEntropyThreshold = 4.5 // bits per character (English text ~3.5, random ~5.5)
)

// ── Helper functions ─────────────────────────────────────────────────────

// argValueToString converts an argument value to a string for scanning.
func argValueToString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case float64, int, int64, bool:
		return fmt.Sprintf("%v", val)
	case map[string]interface{}:
		// Recurse into nested objects — concatenate all string values
		var parts []string
		for _, nested := range val {
			if s := argValueToString(nested); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, "\n")
	case []interface{}:
		var parts []string
		for _, item := range val {
			if s := argValueToString(item); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, "\n")
	default:
		return fmt.Sprintf("%v", v)
	}
}

// largestBase64Chunk finds the longest contiguous base64-looking substring.
// Returns its length, or 0 if none found above threshold.
func largestBase64Chunk(text string) int {
	// Match long runs of base64 characters (with optional line breaks)
	b64Re := regexp.MustCompile(`[A-Za-z0-9+/=\n\r]{100,}`)
	matches := b64Re.FindAllString(text, -1)

	maxLen := 0
	for _, m := range matches {
		clean := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' {
				return -1
			}
			return r
		}, m)

		// Verify it actually decodes as valid base64
		if len(clean) > maxLen {
			if _, err := base64.StdEncoding.DecodeString(padBase64(clean)); err == nil {
				maxLen = len(clean)
			} else if _, err := base64.RawStdEncoding.DecodeString(clean); err == nil {
				maxLen = len(clean)
			}
		}
	}
	return maxLen
}

// padBase64 adds padding if needed.
func padBase64(s string) string {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return s
}

// isHighEntropy checks if the text has suspiciously high Shannon entropy,
// suggesting encoded or encrypted content rather than natural language.
// Only triggers for strings above minLen to avoid false positives on short tokens.
func isHighEntropy(text string, minLen int) bool {
	if len(text) < minLen {
		return false
	}

	// Only check if it looks like a single block of non-whitespace
	// (not natural language with spaces)
	fields := strings.Fields(text)
	if len(fields) > 5 {
		return false // natural language — has many words
	}

	// Compute Shannon entropy on the full text
	freq := make(map[rune]float64)
	total := 0.0
	for _, r := range text {
		freq[r]++
		total++
	}

	entropy := 0.0
	for _, count := range freq {
		p := count / total
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy >= highEntropyThreshold
}

// looksLikeEnvFileContent returns true if the text looks like the contents of
// a .env file (multiple KEY=VALUE lines with sensitive-looking variable names).
func looksLikeEnvFileContent(text string) bool {
	lines := strings.Split(text, "\n")
	if len(lines) < 2 {
		return false
	}

	envLines := 0
	sensitiveNames := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if envLineRe.MatchString(line) {
			envLines++
			upper := strings.ToUpper(line)
			for _, keyword := range []string{"KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "AUTH"} {
				if strings.Contains(upper, keyword) {
					sensitiveNames++
					break
				}
			}
		}
	}

	// At least 2 env-style lines with at least 1 sensitive name
	return envLines >= 2 && sensitiveNames >= 1
}
