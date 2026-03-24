package mcp

import (
	"regexp"
	"strings"
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
)

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

// credentialFieldNames are property names in elicitation schemas that indicate
// a credential-harvesting attempt. Matched case-insensitively against the
// JSON property key and its title/description.
var credentialFieldNames = []string{
	"password",
	"passwd",
	"passphrase",
	"secret",
	"secret_key",
	"secretkey",
	"token",
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
	"credential",
	"credentials",
	"ssn",
	"social_security",
	"credit_card",
	"creditcard",
	"card_number",
	"cvv",
	"pin",
	"aws_secret",
	"aws_access_key",
	"github_token",
}

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
	if params.RequestedSchema != nil {
		for propName, prop := range params.RequestedSchema.Properties {
			lower := strings.ToLower(propName)
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
				if combined != " " {
					for _, credField := range credentialFieldNames {
						if strings.Contains(combined, credField) {
							result.Findings = append(result.Findings, ElicitationFinding{
								Signal:  SignalElicitationCredential,
								Detail:  "credential keyword in property description: " + prop.Title + " " + prop.Description,
								Snippet: "property: " + propName,
							})
							result.Blocked = true
							break
						}
					}
				}
			}
		}

		// Also scan the schema title
		if params.RequestedSchema.Title != "" {
			lowerTitle := strings.ToLower(params.RequestedSchema.Title)
			for _, credField := range credentialFieldNames {
				if strings.Contains(lowerTitle, credField) {
					result.Findings = append(result.Findings, ElicitationFinding{
						Signal:  SignalElicitationCredential,
						Detail:  "credential keyword in schema title: " + params.RequestedSchema.Title,
						Snippet: "schema title",
					})
					result.Blocked = true
					break
				}
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
	}

	return result
}

// isCredentialField checks whether a schema property name is a credential-like field.
// Returns (matched, detail).
func isCredentialField(lowerName string) (bool, string) {
	for _, cred := range credentialFieldNames {
		if lowerName == cred || strings.Contains(lowerName, cred) {
			return true, "elicitation schema requests credential field: " + lowerName
		}
	}
	return false, ""
}
