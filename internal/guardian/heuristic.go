package guardian

import (
	"regexp"
	"strings"
)

// HeuristicProvider detects prompt injection signals using pattern matching.
// It requires zero external dependencies and runs synchronously.
type HeuristicProvider struct {
	rules []heuristicRule
}

// heuristicRule is a single detection pattern in the heuristic provider.
type heuristicRule struct {
	signal   Signal
	match    func(req GuardianRequest) bool
	escalate string // decision to suggest when this rule fires
}

// NewHeuristicProvider creates a heuristic guardian with built-in detection rules.
func NewHeuristicProvider() *HeuristicProvider {
	p := &HeuristicProvider{}
	p.rules = p.buildRules()
	return p
}

func (p *HeuristicProvider) Name() string { return "heuristic" }

// Analyze runs all heuristic rules against the request and returns matched signals.
func (p *HeuristicProvider) Analyze(req GuardianRequest) (GuardianResponse, error) {
	var signals []Signal
	bestDecision := "ALLOW"

	for _, r := range p.rules {
		if r.match(req) {
			signals = append(signals, r.signal)
			bestDecision = mostRestrictive(bestDecision, r.escalate)
		}
	}

	// Build explanation from signals.
	var parts []string
	for _, s := range signals {
		parts = append(parts, s.Description)
	}
	explanation := strings.Join(parts, "; ")

	return GuardianResponse{
		Signals:           signals,
		SuggestedDecision: bestDecision,
		Explanation:       explanation,
	}, nil
}

func (p *HeuristicProvider) buildRules() []heuristicRule {
	return []heuristicRule{
		// --- Prompt injection: instruction override ---
		{
			signal: Signal{
				ID:          "instruction_override",
				Category:    "prompt-injection",
				Severity:    "high",
				Confidence:  0.85,
				Description: "Command contains instruction override language (e.g., 'ignore previous')",
			},
			match: func(req GuardianRequest) bool {
				return matchesAnyPattern(req.RawCommand, instructionOverridePatterns)
			},
			escalate: "BLOCK",
		},

		// --- Prompt injection: prompt exfiltration ---
		{
			signal: Signal{
				ID:          "prompt_exfiltration",
				Category:    "prompt-injection",
				Severity:    "medium",
				Confidence:  0.75,
				Description: "Command attempts to reveal system prompt or instructions",
			},
			match: func(req GuardianRequest) bool {
				return matchesAnyPattern(req.RawCommand, promptExfilPatterns)
			},
			escalate: "AUDIT",
		},

		// --- Security bypass: disable guards ---
		{
			signal: Signal{
				ID:          "disable_security",
				Category:    "security-bypass",
				Severity:    "critical",
				Confidence:  0.90,
				Description: "Command attempts to disable or bypass security controls",
			},
			match: func(req GuardianRequest) bool {
				return matchesAnyPattern(req.RawCommand, disableSecurityPatterns)
			},
			escalate: "BLOCK",
		},

		// --- Obfuscation: base64 payload ---
		{
			signal: Signal{
				ID:          "obfuscated_base64",
				Category:    "obfuscation",
				Severity:    "high",
				Confidence:  0.80,
				Description: "Command contains a long base64-encoded payload that may hide malicious intent",
			},
			match: func(req GuardianRequest) bool {
				return isBase64Payload(req.RawCommand)
			},
			escalate: "AUDIT",
		},

		// --- Obfuscation: hex escape sequences ---
		{
			signal: Signal{
				ID:          "obfuscated_hex",
				Category:    "obfuscation",
				Severity:    "medium",
				Confidence:  0.70,
				Description: "Command contains hex escape sequences that may hide malicious intent",
			},
			match: func(req GuardianRequest) bool {
				return hexEscapePattern.MatchString(req.RawCommand)
			},
			escalate: "AUDIT",
		},

		// --- Eval risk: dynamic code execution ---
		{
			signal: Signal{
				ID:          "eval_risk",
				Category:    "code-execution",
				Severity:    "high",
				Confidence:  0.80,
				Description: "Command uses eval/exec for dynamic code execution",
			},
			match: func(req GuardianRequest) bool {
				return evalRiskPattern.MatchString(req.RawCommand)
			},
			escalate: "AUDIT",
		},

		// --- Bulk exfiltration: archive + upload ---
		{
			signal: Signal{
				ID:          "bulk_exfiltration",
				Category:    "data-exfiltration",
				Severity:    "high",
				Confidence:  0.85,
				Description: "Command archives and/or uploads a large directory (potential bulk data exfiltration)",
			},
			match: func(req GuardianRequest) bool {
				return matchesBulkExfil(req.RawCommand)
			},
			escalate: "BLOCK",
		},

		// --- Secrets in command: inline API keys/tokens ---
		{
			signal: Signal{
				ID:          "secrets_in_command",
				Category:    "credential-exposure",
				Severity:    "high",
				Confidence:  0.75,
				Description: "Command contains what appears to be an inline API key or secret token",
			},
			match: func(req GuardianRequest) bool {
				return secretsInCommandPattern.MatchString(req.RawCommand)
			},
			escalate: "AUDIT",
		},

		// --- Indirect injection: embedded instructions in data ---
		{
			signal: Signal{
				ID:          "indirect_injection",
				Category:    "prompt-injection",
				Severity:    "critical",
				Confidence:  0.80,
				Description: "Command contains embedded instructions targeting an AI agent (indirect injection)",
			},
			match: func(req GuardianRequest) bool {
				return matchesAnyPattern(req.RawCommand, indirectInjectionPatterns)
			},
			escalate: "BLOCK",
		},
	}
}

// ---------------------------------------------------------------------------
// Pattern definitions
// ---------------------------------------------------------------------------

var instructionOverridePatterns = compilePatterns([]string{
	`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?)`,
	`(?i)disregard\s+(all\s+)?(previous|prior|your)\s+(previous\s+)?(instructions?|rules?|guidelines?)`,
	`(?i)disregard\s+(all\s+)?your\s+(previous\s+)?(instructions?|rules?|guidelines?)`,
	`(?i)forget\s+(all\s+)?(your|previous)\s+(instructions?|rules?)`,
	`(?i)override\s+(all\s+)?(safety|security)\s+(rules?|protocols?|guidelines?)`,
	`(?i)you\s+are\s+now\s+(free|unrestricted|unfiltered)`,
	`(?i)new\s+instructions?:\s+`,
	`(?i)system\s*:\s*(you\s+are|ignore|forget)`,
})

var promptExfilPatterns = compilePatterns([]string{
	`(?i)(show|reveal|display|print|output)\s+(me\s+)?(your|the)\s+(system\s+)?prompt`,
	`(?i)(what\s+are|tell\s+me)\s+(your|the)\s+(instructions?|rules?|guidelines?)`,
	`(?i)repeat\s+(your\s+)?(system\s+)?(prompt|instructions?)`,
})

var disableSecurityPatterns = compilePatterns([]string{
	`(?i)(disable|turn\s+off|bypass|skip|ignore)\s+(agentshield|security|guard|policy|policies)`,
	`(?i)(remove|delete|uninstall)\s+(agentshield|security\s+guard)`,
	`(?i)--no-?(verify|check|security|guard|policy)`,
	`(?i)AGENTSHIELD_DISABLE`,
})

var indirectInjectionPatterns = compilePatterns([]string{
	`(?i)SYSTEM:\s*(ignore|forget|override|you\s+are)`,
	`(?i)\[INST\]`,
	`(?i)<\|im_start\|>system`,
	`(?i)BEGIN\s+HIDDEN\s+INSTRUCTIONS?`,
	`(?i)IMPORTANT:\s*(ignore|disregard|override)`,
})

// base64PayloadPattern matches base64 strings >= 40 chars that appear in
// command arguments (likely encoded payloads, not short values).
// Note: detection is done via isBase64Payload to exclude file path segments.
var base64PayloadPattern = regexp.MustCompile(
	`[A-Za-z0-9+/]{40,}={0,2}`,
)

// isBase64Payload returns true if the command contains a 40+ char base64 string
// that is NOT part of a file path. Excludes:
//   - Matches that start with '/' (absolute paths like /usr/local/lib/...)
//   - Matches preceded by '/' (mid-path segments like foo/bar/baz/...)
//
// This prevents false positives on long file paths like /usr/lib/long/path/file.go.
func isBase64Payload(cmd string) bool {
	locs := base64PayloadPattern.FindAllStringIndex(cmd, -1)
	for _, loc := range locs {
		start := loc[0]
		matched := cmd[start:loc[1]]
		// Skip if the match is itself an absolute path segment (starts with '/').
		if matched[0] == '/' {
			continue
		}
		// Skip if this segment is embedded within a file path (preceded by '/').
		if start > 0 && cmd[start-1] == '/' {
			continue
		}
		return true
	}
	return false
}

// hexEscapePattern matches sequences of 4+ hex escapes like \x41\x42\x43\x44.
// In shell commands the backslash may appear as literal \\ or single \.
var hexEscapePattern = regexp.MustCompile(
	`(\\\\?x[0-9a-fA-F]{2}){4,}`,
)

// evalRiskPattern matches eval/exec calls in scripting one-liners.
var evalRiskPattern = regexp.MustCompile(
	`(?i)\b(eval|exec)\s*\(`,
)

// secretsInCommandPattern matches inline API keys/tokens in commands.
// Targets common patterns: API_KEY=..., Bearer ..., ghp_..., sk-...
var secretsInCommandPattern = regexp.MustCompile(
	`(?i)(` +
		`(api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token)\s*[=:]\s*\S{8,}` +
		`|Bearer\s+[A-Za-z0-9._\-]{20,}` +
		`|ghp_[A-Za-z0-9]{36,}` +
		`|\bsk-[A-Za-z0-9]{20,}` +
		`|AKIA[A-Z0-9]{16}` +
		`)`,
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func compilePatterns(patterns []string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}
	return compiled
}

func matchesAnyPattern(s string, patterns []*regexp.Regexp) bool {
	for _, p := range patterns {
		if p.MatchString(s) {
			return true
		}
	}
	return false
}

// matchesBulkExfil detects patterns like archiving broad directories and uploading.
func matchesBulkExfil(cmd string) bool {
	lower := strings.ToLower(cmd)

	// Archive of broad directories
	hasArchive := (strings.Contains(lower, "tar ") || strings.Contains(lower, "zip ")) &&
		(strings.Contains(lower, "~/") ||
			strings.Contains(lower, "$HOME") ||
			strings.Contains(lower, "/home/") ||
			strings.Contains(lower, ".git") ||
			strings.Contains(lower, "/repo"))

	// Upload to external service
	hasUpload := strings.Contains(lower, "curl") ||
		strings.Contains(lower, "wget") ||
		strings.Contains(lower, "scp ") ||
		strings.Contains(lower, "rsync") ||
		strings.Contains(lower, "transfer.sh") ||
		strings.Contains(lower, "file.io") ||
		strings.Contains(lower, "0x0.st")

	// Both archive and upload in same command = bulk exfil
	if hasArchive && hasUpload {
		return true
	}

	// Or: pipe tar/zip output directly to curl
	if (strings.Contains(lower, "tar ") || strings.Contains(lower, "zip ")) &&
		strings.Contains(lower, "|") &&
		(strings.Contains(lower, "curl") || strings.Contains(lower, "nc ")) {
		return true
	}

	return false
}

func mostRestrictive(a, b string) string {
	order := map[string]int{"ALLOW": 0, "AUDIT": 1, "BLOCK": 2}
	if order[b] > order[a] {
		return b
	}
	return a
}
