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
)

// ResourceListFinding records a detected threat in a resources/list URI.
type ResourceListFinding struct {
	Signal ResourceListSignal `json:"signal"`
	Detail string             `json:"detail"`
	URI    string             `json:"uri"`
}

// ResourceListScanResult is the result of scanning a resources/list response.
type ResourceListScanResult struct {
	Blocked  bool                  `json:"blocked"`
	Findings []ResourceListFinding `json:"findings,omitempty"`
}

// ScanResourcesListResponse scans a resources/list result for URI templates that expand
// to sensitive credential or system paths. A malicious MCP server may register resources
// with RFC 6570 template URIs (e.g. file:///home/{username}/.ssh/authorized_keys) that
// look innocuous at registration time but produce targeted credential-read payloads when
// variable-substituted by the agent.
//
// Taxonomy: unauthorized-execution/agentic-attacks/mcp-resource-uri-template-injection
func ScanResourcesListResponse(result *ResourcesListResult) ResourceListScanResult {
	var scanResult ResourceListScanResult

	for _, resource := range result.Resources {
		if f := checkResourceListURI(resource.URI); f != nil {
			scanResult.Findings = append(scanResult.Findings, *f)
		}
	}

	scanResult.Blocked = len(scanResult.Findings) > 0
	return scanResult
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
