package mcp

import (
	"regexp"
	"strings"
)

// ResourceListSignal identifies the type of threat detected in a resources/list response.
type ResourceListSignal string

const (
	// SignalResourceListSensitiveTemplate indicates a resources/list URI template
	// that can expand to a sensitive credential or system path when variables are
	// substituted (RFC 6570 URI template injection).
	SignalResourceListSensitiveTemplate ResourceListSignal = "resource_list_sensitive_template"

	// SignalResourceListMetadataInjection indicates a resources/list entry whose
	// name or description field contains prompt injection directives, credential
	// harvesting instructions, or behavioural manipulation patterns. Malicious
	// servers embed these in resource metadata to influence agent behaviour when
	// the agent processes the resources/list response — the URI may be entirely
	// benign while the metadata carries the adversarial payload.
	//
	// Taxonomy: unauthorized-execution/agentic-attacks/mcp-resource-metadata-injection
	SignalResourceListMetadataInjection ResourceListSignal = "resource_list_metadata_injection"

	// SignalResourceListMimeMismatch indicates a resources/list entry whose declared
	// `mimeType` advertises active or executable content (HTML, JavaScript, SVG-with-
	// script, shell scripts, native executables) on a URI scheme that the host treats
	// as passive (file://, https://, custom MCP schemes). MCP hosts that render
	// resource lists or auto-fetch resources for preview rely on `mimeType` to decide
	// rendering strategy: a server declaring text/html on a file:// resource biases
	// the host toward HTML rendering of attacker-controlled content. The threat is
	// distinct from SignalResourceListDangerousScheme — that signal catches dangerous
	// URI schemes (javascript:, data:, vbscript:) regardless of MIME type; this signal
	// catches the inverse case where the SCHEME is benign but the MIME-TYPE is the lie.
	//
	// Taxonomy: unauthorized-execution/agentic-attacks/mcp-resource-uri-ssrf
	SignalResourceListMimeMismatch ResourceListSignal = "resource_list_mime_mismatch"

	// SignalResourceListDangerousScheme indicates a resources/list URI using a
	// scheme that has no legitimate place in MCP resource discovery and is a known
	// vehicle for code execution, SSRF, or in-context exfiltration when the agent
	// later requests `resources/read` on the listed URI.
	//
	// Detected schemes:
	//   - javascript: / vbscript: — code execution in any host that renders the URI
	//     in a webview, HTML preview, or auto-loaded link.
	//   - data:                  — base64 inline payload smuggling; the agent fetches
	//     the encoded blob as if it were a benign content reference and feeds it back
	//     into its own context.
	//   - blob: / about:         — browser-internal schemes; their presence in an MCP
	//     resource URI indicates the server is trying to inject UI surfaces into a
	//     host that renders resource lists.
	//   - gopher: / dict: / ldap: — well-known SSRF carriers that bypass HTTP allowlists.
	//
	// Taxonomy: unauthorized-execution/agentic-attacks/mcp-resource-uri-ssrf
	// (all dangerous-scheme variants ultimately route through SSRF semantics: the
	// agent makes an unintended request on the server's behalf to a target the
	// host did not authorise.)
	SignalResourceListDangerousScheme ResourceListSignal = "resource_list_dangerous_scheme"
)

// ResourceListFinding records a detected threat in a resources/list entry.
type ResourceListFinding struct {
	Signal ResourceListSignal `json:"signal"`
	Detail string             `json:"detail"`
	URI    string             `json:"uri,omitempty"`   // set for URI-template findings
	Field  string             `json:"field,omitempty"` // "name" or "description" for metadata findings
}

// ResourceListScanResult is the result of scanning a resources/list response.
type ResourceListScanResult struct {
	Blocked  bool                  `json:"blocked"`
	Findings []ResourceListFinding `json:"findings,omitempty"`
}

// ScanResourcesListResponse scans a resources/list result for two threat classes:
//
//  1. URI template injection — RFC 6570 template URIs that expand to sensitive credential
//     or system paths (e.g. file:///home/{username}/.ssh/authorized_keys).
//     Taxonomy: unauthorized-execution/agentic-attacks/mcp-resource-uri-template-injection
//
//  2. Resource metadata injection — name/description fields containing prompt injection
//     directives, credential harvesting instructions, or behavioural manipulation patterns.
//     A malicious server may register resources with a completely benign URI while embedding
//     adversarial payloads in the human-readable metadata fields, which the agent processes
//     when deciding which resources to read.
//     Taxonomy: unauthorized-execution/agentic-attacks/mcp-resource-metadata-injection
func ScanResourcesListResponse(result *ResourcesListResult) ResourceListScanResult {
	var scanResult ResourceListScanResult

	for _, resource := range result.Resources {
		if f := checkResourceListURI(resource.URI); f != nil {
			scanResult.Findings = append(scanResult.Findings, *f)
		}
		if f := checkResourceURIScheme(resource.URI); f != nil {
			scanResult.Findings = append(scanResult.Findings, *f)
		}
		if f := checkResourceListSchemeEvasion(resource.URI); f != nil {
			scanResult.Findings = append(scanResult.Findings, *f)
		}
		if f := checkResourceListAuthoritySpoofing(resource.URI); f != nil {
			scanResult.Findings = append(scanResult.Findings, *f)
		}
		if f := checkResourceListInternalNetwork(resource.URI); f != nil {
			scanResult.Findings = append(scanResult.Findings, *f)
		}
		if f := checkResourceListMetadataSmuggling(resource.URI); f != nil {
			scanResult.Findings = append(scanResult.Findings, *f)
		}
		if f := checkResourceMimeMismatch(resource.URI, resource.MIMEType); f != nil {
			scanResult.Findings = append(scanResult.Findings, *f)
		}
		scanResult.Findings = append(scanResult.Findings, checkResourceEntryMetadata(resource.Name, resource.Description)...)
	}

	scanResult.Blocked = len(scanResult.Findings) > 0
	return scanResult
}

// dangerousURISchemes lists URI schemes that should never appear in a legitimate
// MCP resources/list response. Their presence is a strong adversarial signal:
// every entry below has either active-code or SSRF semantics in a host that
// fetches or renders the URI. The map is keyed by lowercase scheme without the
// trailing colon to keep lookup branchless.
var dangerousURISchemes = map[string]string{
	"javascript": "URI scheme `javascript:` enables code execution when the agent or host renders the resource (auto-load, HTML preview, webview).",
	"vbscript":   "URI scheme `vbscript:` enables legacy code execution in any Windows-side host that renders the resource.",
	"data":       "URI scheme `data:` inlines base64-encoded payloads that the agent ingests into its own context on resources/read — feedback-loop injection vector.",
	"blob":       "URI scheme `blob:` references browser-internal blobs; its presence in an MCP resource list indicates the server is trying to address host-internal UI state.",
	"about":      "URI scheme `about:` addresses browser-internal pages; not a valid MCP resource scheme.",
	"gopher":     "URI scheme `gopher:` is a well-known SSRF carrier that bypasses HTTP allowlists and reaches arbitrary TCP services.",
	"dict":       "URI scheme `dict:` is a well-known SSRF carrier that reaches arbitrary internal TCP services via Dict protocol gadgets.",
	"ldap":       "URI scheme `ldap:` reaches directory services and is a classic SSRF / credential-harvest vector when used as a resource URI.",
	"ldaps":      "URI scheme `ldaps:` reaches directory services over TLS — the secure-transport sibling of `ldap:` and the same JNDI / SSRF gadget; never a legitimate MCP resource URI.",
	"jndi":       "URI scheme `jndi:` triggers a JVM Naming-and-Directory lookup (Log4Shell class). A JVM-side MCP host that resolves the resource performs `jndi:ldap://`/`jndi:rmi://` lookups, loading and deserializing a remote object — remote code execution. No legitimate MCP resource uses jndi.",
	"rmi":        "URI scheme `rmi:` is a Java RMI endpoint and a JNDI service provider; resolving it loads a remote object/stub and deserializes attacker-controlled bytes — remote code execution. No legitimate MCP resource uses rmi.",
	"iiop":       "URI scheme `iiop:` is a CORBA / RMI-over-IIOP endpoint and a JNDI service provider; resolving it deserializes a remote object — the IIOP variant of the JNDI RCE gadget. No legitimate MCP resource uses iiop.",
	"jar":        "URI scheme `jar:` (`jar:<url>!/<entry>`) makes the host fetch and extract a remote archive — a classpath-injection / zip-slip vector when the inner URL is attacker-controlled. No legitimate MCP resource uses jar.",
	"jdbc":       "URI scheme `jdbc:` is a database connection string; JDBC URLs carry RCE-bearing parameters (H2 `INIT=RUNSCRIPT FROM`, MySQL `allowLoadLocalInfile`, queryInterceptors) that execute on connect. No legitimate MCP resource uses jdbc.",
}

// activeContentMIMETypes lists MIME types that MCP hosts treat as executable
// or auto-rendered. Resources advertising one of these via `mimeType` should
// appear only on URI schemes the host already isolates (the dangerous-scheme
// list); declaring active content on a benign-looking scheme is the server
// telling the host "render this as code/HTML" while the URI looks harmless.
//
// The set is intentionally narrow: each entry represents a content-type whose
// host-side processing has real attack surface. Inert content types
// (application/json, text/csv, image/png, etc.) are not flagged regardless of
// scheme because there is no rendering-time code path to exploit.
var activeContentMIMETypes = map[string]string{
	"text/html":                "MIME type text/html declared on a passive-scheme URI — MCP hosts that render resource previews will treat the body as HTML and execute embedded script tags / event handlers.",
	"application/xhtml+xml":    "MIME type application/xhtml+xml declared on a passive-scheme URI — XHTML preview rendering executes script content identically to HTML.",
	"application/javascript":   "MIME type application/javascript declared as a resource — server is asking the host to treat the resource body as JavaScript source.",
	"text/javascript":          "MIME type text/javascript declared as a resource — server is asking the host to treat the resource body as JavaScript source.",
	"application/x-javascript": "MIME type application/x-javascript declared as a resource — non-standard JavaScript MIME used in legacy / circumvention contexts.",
	"application/ecmascript":   "MIME type application/ecmascript declared as a resource — server is requesting ECMAScript-mode execution.",
	"text/ecmascript":          "MIME type text/ecmascript declared as a resource — server is requesting ECMAScript-mode execution.",
	"image/svg+xml":            "MIME type image/svg+xml declared as a resource — SVG documents can carry inline <script> and event handlers; treating one as a passive image is unsafe.",
	"application/x-sh":         "MIME type application/x-sh declared as a resource — server is asking the host to treat the resource body as a shell script.",
	"text/x-shellscript":       "MIME type text/x-shellscript declared as a resource — server is asking the host to treat the resource body as a shell script.",
	"application/x-msdownload": "MIME type application/x-msdownload declared as a resource — Windows executable advertised via MCP resource list; no legitimate MCP use.",
	"application/x-executable": "MIME type application/x-executable declared as a resource — native ELF executable advertised via MCP resource list; no legitimate MCP use.",
	"application/x-dosexec":    "MIME type application/x-dosexec declared as a resource — DOS / Windows executable advertised via MCP resource list; no legitimate MCP use.",
	"application/x-mach-binary": "MIME type application/x-mach-binary declared as a resource — Mach-O executable advertised via MCP resource list; no legitimate MCP use.",
}

// checkResourceMimeMismatch returns a finding when a resource entry's declared
// `mimeType` advertises active content on a URI scheme the host treats as
// passive. Returns nil when no MIME type is declared, when the MIME type is
// inert, when the URI scheme is already in the dangerous list (the scheme
// signal carries the finding instead — avoid double-flagging the same row), or
// when the URI is empty.
//
// Why "no double-flag with dangerous-scheme": a `javascript:` URI already
// trips SignalResourceListDangerousScheme. Adding a MIME-mismatch finding on
// the same row would clutter the audit log without adding evidence. The
// MIME-mismatch signal is the "the SCHEME looks safe but the MIME tells the
// truth" lane — it complements rather than duplicates the scheme signal.
func checkResourceMimeMismatch(uri, mimeType string) *ResourceListFinding {
	if uri == "" || mimeType == "" {
		return nil
	}
	// Normalize MIME type: strip parameters (e.g., "text/html; charset=utf-8")
	// and lowercase. RFC 2045 says the type/subtype is case-insensitive.
	normalized := strings.ToLower(strings.TrimSpace(mimeType))
	if idx := strings.IndexByte(normalized, ';'); idx >= 0 {
		normalized = strings.TrimSpace(normalized[:idx])
	}
	detail, isActive := activeContentMIMETypes[normalized]
	if !isActive {
		return nil
	}
	// Skip when the scheme itself is already in the dangerous list — the
	// scheme signal covers that case and re-flagging adds no new evidence.
	scheme := schemeOf(uri)
	if scheme != "" {
		if _, isDangerous := dangerousURISchemes[scheme]; isDangerous {
			return nil
		}
	}
	return &ResourceListFinding{
		Signal: SignalResourceListMimeMismatch,
		Detail: detail,
		URI:    uri,
	}
}

// checkResourceURIScheme classifies the scheme of a resources/list URI and
// returns a finding when the scheme is unambiguously adversarial in the MCP
// context. Tolerant of empty / scheme-less URIs (those produce no finding here;
// other scanners cover relative-URI shenanigans).
func checkResourceURIScheme(uri string) *ResourceListFinding {
	scheme := schemeOf(uri)
	if scheme == "" {
		return nil
	}
	if detail, blocked := dangerousURISchemes[scheme]; blocked {
		return &ResourceListFinding{
			Signal: SignalResourceListDangerousScheme,
			Detail: detail,
			URI:    uri,
		}
	}
	return nil
}

// schemeOf returns the lowercased URI scheme (without the trailing colon), or
// an empty string when the URI has no recognisable scheme prefix. Whitespace is
// stripped to defeat trivial evasion via leading spaces in the scheme.
func schemeOf(uri string) string {
	trimmed := strings.TrimSpace(uri)
	idx := strings.IndexByte(trimmed, ':')
	if idx <= 0 {
		return ""
	}
	scheme := strings.ToLower(trimmed[:idx])
	for _, r := range scheme {
		// Scheme chars are ALPHA / DIGIT / "+" / "-" / "." per RFC 3986. A
		// space, slash, or other char means this colon is not the scheme delimiter.
		isAlpha := r >= 'a' && r <= 'z'
		isDigit := r >= '0' && r <= '9'
		isPunct := r == '+' || r == '-' || r == '.'
		if !isAlpha && !isDigit && !isPunct {
			return ""
		}
	}
	return scheme
}

// checkResourceEntryMetadata scans a resource's name and description for injection patterns.
// Returns at most one finding per field (first match wins) to avoid noise.
func checkResourceEntryMetadata(name, description string) []ResourceListFinding {
	var findings []ResourceListFinding
	if f := scanMetadataField("name", name); f != nil {
		findings = append(findings, *f)
	}
	if f := scanMetadataField("description", description); f != nil {
		findings = append(findings, *f)
	}
	return findings
}

// scanMetadataField checks a single resource metadata field (name or description) against
// all injection-relevant signal groups from description_scanner.go. Returns the first
// matching finding, or nil if the field is empty or safe.
func scanMetadataField(field, value string) *ResourceListFinding {
	if value == "" {
		return nil
	}
	forms := newProseForms(value)

	// Use the same signal groups as description_scanner.go for consistency.
	// Order matters: hidden-instruction markers first (highest confidence), then
	// credential-harvest references, exfiltration directives, stealth instructions,
	// and finally behavioural-manipulation patterns.
	allGroups := [][]signalPattern{
		hiddenInstructionPatterns,
		credentialHarvestPatterns,
		exfiltrationPatterns,
		stealthPatterns,
		behavioralManipulationPatterns,
	}
	for _, group := range allGroups {
		for _, p := range group {
			if note, ok := proseMatchNote(p.re, forms); ok {
				return &ResourceListFinding{
					Signal: SignalResourceListMetadataInjection,
					Detail: "resource " + field + " contains injection pattern: " + p.description + note,
					Field:  field,
				}
			}
		}
	}

	// LLM tokenizer ROLE delimiters — the prose groups above match natural-language
	// directives, not architecture-specific tokenizer boundaries (<|im_start|>,
	// <<SYS>>, [/INST], …). A resource name/description shown to the agent during
	// resource selection is rendered into its context, so a forged role turn here
	// reframes the conversation. Matched case-sensitively against the raw value.
	for _, p := range llmRoleTokenPatterns {
		if p.re.MatchString(value) {
			return &ResourceListFinding{
				Signal: SignalResourceListMetadataInjection,
				Detail: "resource " + field + " contains LLM tokenizer role delimiter: " + p.description,
				Field:  field,
			}
		}
	}

	// Forged tool-CALL dispatch control syntax (description->tool-call confusion) —
	// <function_calls>/<invoke>, the pipe-delimited Llama tool-call tokens, or the
	// Mistral bracket request markers embedded in a resource name/description. A host
	// that parses tool-call syntax from the rendered listing may dispatch an
	// unsanctioned call. Reuses the high-confidence dispatch-token set from
	// description_scanner.go (generic <tool_call>/<tool_use> XML is excluded).
	if toolCallDispatchTokenRE.MatchString(value) {
		return &ResourceListFinding{
			Signal: SignalResourceListMetadataInjection,
			Detail: "resource " + field + " contains forged tool-call / function-invocation control syntax (<function_calls>/<invoke>, <|python_tag|>/<|tool_call|>, or [TOOL_REQUEST]/[TOOL_CALLS]) — a harness parsing tool-call syntax from the resource listing may dispatch an unsanctioned privileged call",
			Field:  field,
		}
	}
	return nil
}

// rfc6570VarRe matches RFC 6570 template expression syntax including all operators:
// {var}, {+var}, {#var}, {.var}, {/var}, {;var}, {?var}, {&var}
var rfc6570VarRe = regexp.MustCompile(`\{[+#./;?&]?[a-zA-Z_][a-zA-Z0-9_]*\}`)

// sensitiveFileTemplateRe checks file:// URIs for patterns that indicate the template
// would expand to a sensitive credential path when variables are substituted.
// We match on the raw URI (before variable removal) so that both static and
// template-parameterised paths are covered.
var sensitiveFileTemplateRe = regexp.MustCompile(
	`(?i)file://[^?#]*(` +
		`/\.ssh/` + `|` +
		`/\.aws/` + `|` +
		`/\.gnupg/` + `|` +
		`/\.kube/` + `|` +
		`/vault-token` + `|` +
		`/id_rsa\b` + `|` +
		`/id_ecdsa\b` + `|` +
		`/id_ed25519\b` + `|` +
		`/authorized_keys\b` + `|` +
		`/aws_credentials\b` + `|` +
		`/etc/shadow\b` + `|` +
		`/etc/passwd\b` + `|` +
		`/etc/sudoers\b` + `|` +
		`/serviceaccount/token\b` +
		`)`,
)

// etcTemplateRe detects file:// URIs pointing into /etc/ where the path component
// immediately after /etc/ is a template variable, e.g. file:///etc/{config_file}.
// An agent substituting arbitrary filenames under /etc/ gains access to any system file.
var etcTemplateRe = regexp.MustCompile(`(?i)file://[^?#]*/etc/\{[+#./;?&]?[a-zA-Z_][a-zA-Z0-9_]*\}`)

// imdsTemplateRe detects URIs targeting known IMDS endpoints with variable path segments.
// The IMDS at 169.254.169.254 or internal metadata services can leak cloud credentials
// when accessed with attacker-controlled path templates.
var imdsTemplateRe = regexp.MustCompile(
	`(?i)` +
		`(169\.254\.169\.254` + `|` +
		`metadata\.google\.internal` + `|` +
		`metadata\.goog` + `|` +
		`//metadata-service` + `|` +
		`//instance-data` +
		`)`,
)

// checkResourceListURI returns a finding if the URI contains an RFC 6570 template
// variable AND the URI skeleton would resolve to a sensitive path.
// Returns nil if the URI is safe or contains no template variables.
func checkResourceListURI(uri string) *ResourceListFinding {
	// Fast path: skip URIs without any template variables
	if !rfc6570VarRe.MatchString(uri) {
		return nil
	}

	// Check file:// URIs for sensitive credential directory/file patterns
	if strings.HasPrefix(strings.ToLower(uri), "file://") {
		if sensitiveFileTemplateRe.MatchString(uri) {
			return &ResourceListFinding{
				Signal: SignalResourceListSensitiveTemplate,
				Detail: "resources/list URI template expands to sensitive credential path — static path component reveals the target before variable substitution",
				URI:    uri,
			}
		}
		// Separately check /etc/{variable} pattern (arbitrary /etc/ file access)
		if etcTemplateRe.MatchString(uri) {
			return &ResourceListFinding{
				Signal: SignalResourceListSensitiveTemplate,
				Detail: "resources/list URI template targets /etc/ with a variable filename — allows arbitrary system file access via template expansion",
				URI:    uri,
			}
		}
	}

	// Check for IMDS-targeting URIs with variable path segments
	if imdsTemplateRe.MatchString(uri) {
		return &ResourceListFinding{
			Signal: SignalResourceListSensitiveTemplate,
			Detail: "resources/list URI template targets IMDS or internal metadata endpoint — variable path expansion can retrieve cloud credentials",
			URI:    uri,
		}
	}

	return nil
}
