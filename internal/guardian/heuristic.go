package guardian

import (
	"math"
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
				return matchesDisableSecurity(req.RawCommand)
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
				return matchesEvalRisk(req.RawCommand)
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
				return matchesSecretsInCommand(req.RawCommand)
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

// disableSecurityTextPatterns are text-based security-bypass patterns that can produce
// false positives when they appear inside quoted arguments of text-sink commands
// (e.g. `gh issue create --body "...bypass security controls..."`).
var disableSecurityTextPatterns = compilePatterns([]string{
	`(?i)(disable|turn\s+off|bypass|skip|ignore)\s+(agentshield|security|guard|policy|policies)`,
	`(?i)(remove|delete|uninstall)\s+(agentshield|security\s+guard)`,
	`(?i)--no-?(verify|check|security|guard|policy)`,
})

// agentshieldDisableRe matches the AGENTSHIELD_DISABLE env var, which is a direct
// bypass attempt and should fire regardless of surrounding context.
var agentshieldDisableRe = regexp.MustCompile(`(?i)AGENTSHIELD_DISABLE`)

// safeCallerRe matches executables that send their arguments to external services
// (not to shell stdout where an AI agent could read them). Only gh and git qualify:
// echo/cat/printf/tee write to stdout which agents may consume and act on.
var safeCallerRe = regexp.MustCompile(`(?i)^\s*(gh|git)\s`)

// catFileWriteRe matches cat commands that write a heredoc body to a file
// (e.g. `cat > /tmp/file << 'EOF'`). These are pure file-write operations
// whose heredoc content is data, not commands — safe to strip.
var catFileWriteRe = regexp.MustCompile(`(?i)^\s*cat\s+>>?\s+\S+\s+<<`)

// catHeredocAnywhereRe is the non-anchored counterpart of catFileWriteRe.
// It matches a cat-file-write heredoc pattern anywhere within a compound command
// (e.g. after `cd dir &&` or `make build &&`). Only redirected forms are matched
// (cat >>? file <<) — bare "cat << EOF" to stdout is intentionally excluded
// because stdout output may be consumed by AI agents.
var catHeredocAnywhereRe = regexp.MustCompile(`(?i)\bcat\s+>>?\s+\S+\s+<<`)

// stripQuotedRe removes double-quoted and single-quoted string literals from a command.
var stripQuotedRe = regexp.MustCompile(`"[^"]*"|'[^']*'`)

// matchesDisableSecurity returns true if the command contains a security-bypass signal.
//
// Context-aware to reduce false positives:
//   - gh/git commands: quoted string arguments are stripped before matching because their
//     arguments are sent to external APIs (GitHub, git servers), not executed by a shell.
//     Example: `gh issue create --body "...bypass security..."` → ALLOW.
//   - cat file-write with heredoc: the heredoc body is stripped because it is file content.
//     Example: `cat > /tmp/file << 'EOF'\ndisable security\nEOF` → ALLOW.
//   - echo/printf/tee/cat to stdout are NOT exempted: their output may be read by AI agents
//     and could constitute indirect injection. Example: `echo "disable agentshield"` → BLOCK.
//   - AGENTSHIELD_DISABLE env-var pattern always fires regardless of context.
func matchesDisableSecurity(cmd string) bool {
	if agentshieldDisableRe.MatchString(cmd) {
		return true
	}
	if safeCallerRe.MatchString(cmd) {
		// Strip quoted string content — these are argument values sent to external APIs.
		stripped := stripQuotedRe.ReplaceAllString(cmd, "")
		// Strip heredoc body if present (the marker and body are data, not commands).
		if idx := strings.Index(stripped, "<<"); idx != -1 {
			stripped = stripped[:idx]
		}
		return matchesAnyPattern(stripped, disableSecurityTextPatterns)
	}
	// Special case: `cat > file << 'MARKER'` writes a heredoc to a file.
	// Strip the heredoc body (everything from << onwards) since it is file content.
	// catHeredocAnywhereRe also handles compound commands like `cd dir && cat > file << EOF`.
	if catFileWriteRe.MatchString(cmd) || catHeredocAnywhereRe.MatchString(cmd) {
		if idx := strings.Index(cmd, "<<"); idx != -1 {
			return matchesAnyPattern(cmd[:idx], disableSecurityTextPatterns)
		}
	}
	return matchesAnyPattern(cmd, disableSecurityTextPatterns)
}

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
// that is NOT part of a file path or a quoted argument to gh/git.
//
// Context-aware to reduce false positives on long text arguments:
//   - gh/git commands: quoted string arguments are stripped before matching because
//     --body, --message, and similar flags carry long prose text (issue bodies, PR
//     descriptions, commit messages) that frequently contains 40+ char alphanumeric
//     sequences without being encoded payloads.
//   - cat > file << BODY heredocs: the heredoc body is stripped since it's file content.
//
// Path exclusions (applied after context stripping):
//   - Matches that start with '/' (absolute paths like /usr/local/lib/...)
//   - Matches preceded by '/' (mid-path segments like foo/bar/baz/...)
//   - Cross-directory path segments preceded by '_' or '-' (e.g. "AI_Agent_Shield/internal/...")
//   - Relative file path arguments: whitespace-preceded token with '/' but no '+'
//     (paths never contain '+'; base64 uses it as the 62nd encoding character)
func isBase64Payload(cmd string) bool {
	// Context-aware stripping: gh/git commands and cat heredoc file writes.
	checkCmd := cmd
	if safeCallerRe.MatchString(cmd) {
		// Strip quoted string content — these are argument values sent to external
		// APIs (GitHub, git servers), not executed by the shell. Issue/PR bodies and
		// commit messages often contain 40+ char runs that are not encoded payloads.
		checkCmd = stripQuotedRe.ReplaceAllString(cmd, "")
	} else if catFileWriteRe.MatchString(cmd) || catHeredocAnywhereRe.MatchString(cmd) {
		// cat > file << BODY writes a heredoc to a file. Strip the heredoc body
		// (everything from << onwards) since it is file content, not a payload.
		// catHeredocAnywhereRe also handles compound commands like `cd dir && cat > file << EOF`.
		if idx := strings.Index(cmd, "<<"); idx != -1 {
			checkCmd = cmd[:idx]
		}
	}

	locs := base64PayloadPattern.FindAllStringIndex(checkCmd, -1)
	for _, loc := range locs {
		start := loc[0]
		matched := checkCmd[start:loc[1]]
		// Skip if the match is itself an absolute path segment (starts with '/').
		if matched[0] == '/' {
			continue
		}
		// Skip if this segment is embedded within a file path (preceded by '/').
		if start > 0 && checkCmd[start-1] == '/' {
			continue
		}
		// Skip cross-directory path segments that follow a word-separator
		// ('_' or '-'). Example: in "AI_Agent_Shield/internal/analyzer/testdata/foo"
		// the token "Shield/internal/analyzer/testdata/foo" is preceded by '_'
		// and contains internal slashes — it's a file path fragment, not base64.
		if strings.Contains(matched, "/") && start > 0 {
			prev := checkCmd[start-1]
			if prev == '_' || prev == '-' {
				continue
			}
		}
		// Skip relative file path arguments: a whitespace-preceded token that
		// contains path separators ('/') but no base64-specific '+' character is
		// a file path, not an encoded payload. File paths never use '+'; base64
		// uses it as the 62nd encoding character.
		// Example: "git add internal/analyzer/testdata/reconnaissance_cases.go"
		// Fixes: https://github.com/security-researcher-ca/AI_Agent_Shield/issues/35
		if strings.Contains(matched, "/") && !strings.Contains(matched, "+") {
			if start == 0 || checkCmd[start-1] == ' ' || checkCmd[start-1] == '\t' {
				continue
			}
		}
		// Skip if the matched string has low Shannon entropy. Real base64 payloads
		// encode binary data, giving character entropy ≥ 4.5 bits/char. Long English
		// words, camelCase identifiers, and markdown prose (e.g. in git commit -m
		// messages) have entropy < 4.0 bits/char and are almost never actual base64.
		// Threshold of 4.5 eliminates these FPs while preserving detection of real
		// base64-encoded payloads (entropy typically 5.5–6.0 bits/char).
		if shannonEntropy(matched) < 4.5 {
			continue
		}
		return true
	}
	return false
}

// shannonEntropy calculates the Shannon entropy of s in bits per character.
// Returns 0.0 for empty or single-character strings.
func shannonEntropy(s string) float64 {
	if len(s) < 2 {
		return 0.0
	}
	freq := make(map[rune]int, 64)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len(s))
	var h float64
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
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

// matchesEvalRisk returns true if the command contains a dynamic eval/exec call.
//
// Context-aware to reduce false positives:
//   - gh/git commands: quoted string arguments (commit messages, PR bodies) are
//     stripped before matching. Prose text may reference eval() or exec() in
//     code examples without any actual dynamic execution.
//     Example: `git commit -m "fix bug where eval() caused crash"` → ALLOW.
//   - cat file-write with heredoc: heredoc body is stripped (file content, not code).
//   - All other commands: full text is matched.
func matchesEvalRisk(cmd string) bool {
	if safeCallerRe.MatchString(cmd) {
		// Strip quoted string content — commit messages and PR bodies are sent to
		// external APIs, not executed by the shell. They may contain eval()/exec()
		// references as code examples.
		stripped := stripQuotedRe.ReplaceAllString(cmd, "")
		// Also strip heredoc body ($(cat <<'EOF' ... EOF) is a multiline string
		// substitution, not dynamic code execution).
		if idx := strings.Index(stripped, "<<"); idx != -1 {
			stripped = stripped[:idx]
		}
		return evalRiskPattern.MatchString(stripped)
	}
	// catHeredocAnywhereRe also handles compound commands like `cd dir && cat > file << EOF`.
	if catFileWriteRe.MatchString(cmd) || catHeredocAnywhereRe.MatchString(cmd) {
		if idx := strings.Index(cmd, "<<"); idx != -1 {
			return evalRiskPattern.MatchString(cmd[:idx])
		}
	}
	return evalRiskPattern.MatchString(cmd)
}

// secretsBroadPattern matches context-sensitive credential patterns that are
// prone to false positives when they appear inside quoted commit messages or
// PR/issue bodies (e.g. code examples, placeholder values, Semgrep patterns).
// These are only applied after stripping quoted strings from gh/git commands.
var secretsBroadPattern = regexp.MustCompile(
	`(?i)(` +
		`(api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token)\s*[=:]\s*\S{8,}` +
		`|Bearer\s+[A-Za-z0-9._\-]{20,}` +
		`)`,
)

// secretsHighConfidencePattern matches known-format tokens that have very low
// false-positive rates and should fire regardless of caller context.
var secretsHighConfidencePattern = regexp.MustCompile(
	`(` +
		`ghp_[A-Za-z0-9]{36,}` +
		`|\bsk-[A-Za-z0-9]{20,}` +
		`|AKIA[A-Z0-9]{16}` +
		`)`,
)

// matchesSecretsInCommand detects inline secrets/tokens in a command.
//
// Context-aware to reduce false positives on commit messages and PR bodies:
//   - gh/git commands: quoted string arguments are stripped before applying
//     broad patterns (api_key=, auth_token=, Bearer) because commit messages
//     and PR bodies commonly contain code examples and placeholder values.
//   - High-confidence token formats (ghp_, sk-, AKIA) always fire regardless
//     of caller, since those are unambiguous real credentials.
func matchesSecretsInCommand(cmd string) bool {
	// High-confidence patterns (known-format tokens) always trigger.
	if secretsHighConfidencePattern.MatchString(cmd) {
		return true
	}
	// For gh/git commands, strip quoted arguments before checking broad patterns.
	// Commit messages and PR/issue bodies are sent to external APIs (not the shell)
	// and frequently contain code examples that resemble credential patterns.
	if safeCallerRe.MatchString(cmd) {
		stripped := stripQuotedRe.ReplaceAllString(cmd, "")
		return secretsBroadPattern.MatchString(stripped)
	}
	return secretsBroadPattern.MatchString(cmd)
}

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
