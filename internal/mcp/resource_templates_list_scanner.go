package mcp

import (
	"regexp"
	"strings"
)

// ResourceTemplatesListSignal identifies the type of threat detected in a
// resources/templates/list response.
type ResourceTemplatesListSignal string

const (
	// SignalResourceTemplatesListVarnameViolation indicates an RFC 6570 URI
	// template variable name containing characters outside the RFC 6570 grammar
	// (varname = varchar *( ["."] varchar ); varchar = ALPHA / DIGIT / "_" /
	// pct-encoded). Any other character — angle brackets, quotes, whitespace,
	// invisible Unicode, mixed-script homoglyphs — is by definition malformed.
	// The variable name becomes content the agent reads when resolving the
	// template, so attacker-controlled non-conforming names function as a
	// prompt-injection vehicle hidden inside the URI structure.
	SignalResourceTemplatesListVarnameViolation ResourceTemplatesListSignal = "resource_templates_list_varname_violation"

	// SignalResourceTemplatesListMetadataInjection indicates the template's
	// `name` or `description` field contains the same injection markers the
	// description-scanner pipeline catches in tool descriptions (hidden-instruction
	// tags, credential-harvest references, exfiltration directives, behavioural
	// manipulation, stealth instructions). Parallel to the metadata-injection
	// signal on resources/list — templates have their own listing surface, so
	// the audit log gets its own signal class.
	SignalResourceTemplatesListMetadataInjection ResourceTemplatesListSignal = "resource_templates_list_metadata_injection"

	// SignalResourceTemplatesListControlToken indicates the template's name or
	// description field contains a forged LLM tokenizer role delimiter
	// (<|im_start|>, [INST], <<SYS>>) or tool-call dispatch syntax
	// (<function_calls>/<invoke>, <|python_tag|>/<|tool_call|>,
	// [TOOL_REQUEST]/[TOOL_CALLS]). These tokens are architecture-specific
	// tokenizer literals with no legitimate use in resource template metadata —
	// their presence is an unambiguous adversarial signal. Parallel to the
	// control-token signal on resources/list (SignalResourceListControlToken).
	SignalResourceTemplatesListControlToken ResourceTemplatesListSignal = "resource_templates_list_control_token"

	// SignalResourceTemplatesListSensitiveExpansion indicates the URI template
	// would expand to a credential or system path when its variables are
	// substituted. Reuses the same sensitiveFileTemplateRe / etcTemplateRe /
	// imdsTemplateRe predicates the resources/list scanner uses — the threat
	// shape is identical (template expands to credentials); the distinction is
	// the response surface (resources/templates/list rather than resources/list).
	SignalResourceTemplatesListSensitiveExpansion ResourceTemplatesListSignal = "resource_templates_list_sensitive_expansion"
)

// ResourceTemplatesListFinding records one detected threat in a
// resources/templates/list entry.
type ResourceTemplatesListFinding struct {
	Signal      ResourceTemplatesListSignal `json:"signal"`
	Detail      string                      `json:"detail"`
	URITemplate string                      `json:"uri_template,omitempty"`
	Field       string                      `json:"field,omitempty"` // "name" or "description" for metadata findings
	Varname     string                      `json:"varname,omitempty"`
}

// ResourceTemplatesListScanResult is the result of scanning a
// resources/templates/list response.
type ResourceTemplatesListScanResult struct {
	Blocked  bool                           `json:"blocked"`
	Findings []ResourceTemplatesListFinding `json:"findings,omitempty"`
}

// rfc6570TemplateExprRe captures everything between `{}` so the scanner can
// dissect the expression body. RFC 6570 expressions take the form
// `{[operator] varspec [, varspec]*}` where operator is one of `+#./;?&` and
// varspec includes the varname plus optional explode (`*`) or prefix (`:N`)
// modifiers. We use a permissive capture (anything except `{}`) and apply
// stricter checks inside checkExpressionBody.
var rfc6570TemplateExprRe = regexp.MustCompile(`\{([^{}]*)\}`)

// rfc6570VarnameRe matches a well-formed RFC 6570 variable name. Per the spec:
//
//	varname = varchar *( ["."] varchar )
//	varchar = ALPHA / DIGIT / "_" / pct-encoded
//
// We approximate pct-encoded as `%[0-9A-Fa-f]{2}` and allow dots as separators.
// A varspec may carry an explode modifier (`*`) or a prefix modifier (`:N`);
// those are stripped before validation.
var rfc6570VarnameRe = regexp.MustCompile(`^([A-Za-z0-9_]|%[0-9A-Fa-f]{2})+(\.([A-Za-z0-9_]|%[0-9A-Fa-f]{2})+)*$`)

// rfc6570OperatorChars is the set of leading characters that introduce an
// RFC 6570 operator. The scanner strips a single leading operator before
// splitting varspecs.
const rfc6570OperatorChars = "+#./;?&"

// ScanResourcesTemplatesListResponse walks a resources/templates/list result and
// emits findings for:
//
//  1. URI templates whose variable names violate RFC 6570 (varname grammar) —
//     a strong adversarial signal because legitimate template authors have no
//     reason to use characters outside `[A-Za-z0-9_.%]`.
//
//  2. Templates whose name/description fields carry the injection markers the
//     description-scanner pipeline detects in tool descriptions.
//
//  3. Templates whose URI body would expand to a credential or system path —
//     same sensitive-template predicates the resources/list scanner uses.
//
// The scanner is intentionally surface-distinct from ScanResourcesListResponse:
// templates and listed resources share metadata structure but the threat
// signals get their own IDs so audit logs disambiguate which response surface
// carried the payload.
func ScanResourcesTemplatesListResponse(result *ResourcesTemplatesListResult) ResourceTemplatesListScanResult {
	var out ResourceTemplatesListScanResult
	for _, tmpl := range result.ResourceTemplates {
		out.Findings = append(out.Findings, checkTemplateVarnames(tmpl.URITemplate)...)
		out.Findings = append(out.Findings, checkTemplateSensitiveExpansion(tmpl.URITemplate)...)
		out.Findings = append(out.Findings, checkTemplateMetadata(tmpl.Name, tmpl.Description)...)
	}
	out.Blocked = len(out.Findings) > 0
	return out
}

// checkTemplateVarnames walks each RFC 6570 expression body in the template
// and emits a finding for any varname that violates the RFC 6570 varname
// grammar. Only the first non-conforming varname per template fires to keep
// audit logs readable when attackers chain multiple bad names.
func checkTemplateVarnames(uriTemplate string) []ResourceTemplatesListFinding {
	if uriTemplate == "" {
		return nil
	}
	var findings []ResourceTemplatesListFinding
	matches := rfc6570TemplateExprRe.FindAllStringSubmatch(uriTemplate, -1)
	for _, m := range matches {
		body := m[1]
		// Strip a single leading operator character. Per RFC 6570 the operator
		// is at most one of `+#./;?&`. Multiple operator-like chars in a row
		// are a varname violation (e.g. `{++name}` is malformed).
		if body != "" && strings.IndexByte(rfc6570OperatorChars, body[0]) >= 0 {
			body = body[1:]
		}
		// A varspec list is comma-separated: {var1,var2*}. Validate each.
		for _, raw := range strings.Split(body, ",") {
			varspec := strings.TrimSpace(raw)
			// Strip the explode `*` modifier and `:N` prefix modifier — both are
			// valid trailing forms. Anything beyond that should be a pure varname.
			varspec = strings.TrimSuffix(varspec, "*")
			if idx := strings.IndexByte(varspec, ':'); idx >= 0 {
				varspec = varspec[:idx]
			}
			if varspec == "" {
				// `{,foo}` or `{}` — malformed but cheaper to leave alone; the
				// non-conforming-name finding below covers `{foo,}` style attacks.
				continue
			}
			if !rfc6570VarnameRe.MatchString(varspec) {
				findings = append(findings, ResourceTemplatesListFinding{
					Signal:      SignalResourceTemplatesListVarnameViolation,
					Detail:      "URI template variable name violates RFC 6570 grammar (must be ALPHA/DIGIT/_/. or pct-encoded) — non-conforming name is a prompt-injection vehicle hidden inside the URI structure",
					URITemplate: uriTemplate,
					Varname:     truncateForSnippet(varspec, 80),
				})
				// One finding per template — multiple bad names in one template
				// share a single audit-log entry.
				return findings
			}
		}
	}
	return findings
}

// checkTemplateSensitiveExpansion reuses the same predicates as
// checkResourceListURI (sensitive file paths, /etc/ template variables, IMDS
// hostnames) — the threat model is identical, the response surface is
// different. Distinct signal so audit logs disambiguate.
func checkTemplateSensitiveExpansion(uriTemplate string) []ResourceTemplatesListFinding {
	if uriTemplate == "" {
		return nil
	}
	// Templates without any RFC 6570 expression body are full static URIs and
	// would fall under resources/list (or resources/read) checks instead.
	if !rfc6570TemplateExprRe.MatchString(uriTemplate) {
		return nil
	}
	var findings []ResourceTemplatesListFinding
	if strings.HasPrefix(strings.ToLower(uriTemplate), "file://") {
		if sensitiveFileTemplateRe.MatchString(uriTemplate) {
			findings = append(findings, ResourceTemplatesListFinding{
				Signal:      SignalResourceTemplatesListSensitiveExpansion,
				Detail:      "URI template expands to sensitive credential path — static path component reveals the target before variable substitution",
				URITemplate: uriTemplate,
			})
			return findings
		}
		if etcTemplateRe.MatchString(uriTemplate) {
			findings = append(findings, ResourceTemplatesListFinding{
				Signal:      SignalResourceTemplatesListSensitiveExpansion,
				Detail:      "URI template targets /etc/ with a variable filename — allows arbitrary system file access via template expansion",
				URITemplate: uriTemplate,
			})
			return findings
		}
	}
	if imdsTemplateRe.MatchString(uriTemplate) {
		findings = append(findings, ResourceTemplatesListFinding{
			Signal:      SignalResourceTemplatesListSensitiveExpansion,
			Detail:      "URI template targets IMDS or internal metadata endpoint — variable path expansion can retrieve cloud credentials",
			URITemplate: uriTemplate,
		})
	}
	return findings
}

// checkTemplateMetadata scans the template's name and description fields for
// the same injection markers the description-scanner pipeline catches in tool
// descriptions. Returns at most one finding per field to keep the audit log
// readable when multiple patterns match.
func checkTemplateMetadata(name, description string) []ResourceTemplatesListFinding {
	var findings []ResourceTemplatesListFinding
	if f := scanTemplateMetadataField("name", name); f != nil {
		findings = append(findings, *f)
	}
	if f := scanTemplateMetadataField("description", description); f != nil {
		findings = append(findings, *f)
	}
	return findings
}

// scanTemplateMetadataField checks a single template metadata field against the
// injection-relevant signal groups. Order matters: hidden-instruction first
// (highest confidence), then credential-harvest, exfiltration, stealth,
// behavioural manipulation, control-token last (case-sensitive, raw value).
// Mirrors scanMetadataField in resource_list_scanner.go.
func scanTemplateMetadataField(field, value string) *ResourceTemplatesListFinding {
	if value == "" {
		return nil
	}
	forms := newProseForms(value)
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
				return &ResourceTemplatesListFinding{
					Signal: SignalResourceTemplatesListMetadataInjection,
					Detail: "resource template " + field + " contains injection pattern: " + p.description + note,
					Field:  field,
				}
			}
		}
	}
	// Control-token check: case-sensitive against raw value because these are
	// tokenizer-architecture literals (role delimiters + dispatch syntax).
	for _, p := range llmRoleTokenPatterns {
		if p.re.MatchString(value) {
			return &ResourceTemplatesListFinding{
				Signal: SignalResourceTemplatesListControlToken,
				Detail: "resource template " + field + " contains LLM tokenizer role delimiter: " + p.description,
				Field:  field,
			}
		}
	}
	if toolCallDispatchTokenRE.MatchString(value) {
		return &ResourceTemplatesListFinding{
			Signal: SignalResourceTemplatesListControlToken,
			Detail: "resource template " + field + " contains forged tool-call dispatch syntax — a harness parsing this metadata may dispatch an unsanctioned call",
			Field:  field,
		}
	}
	return nil
}
