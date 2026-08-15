package redact

import (
	"regexp"
	"strings"
)

var sensitivePatterns = []*regexp.Regexp{
	// AWS
	regexp.MustCompile(`(?i)(aws_access_key_id|aws_secret_access_key|aws_session_token)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{20,}['"]?`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),

	// GitHub
	regexp.MustCompile(`(?i)(github_token|gh_token|github_pat)\s*[=:]\s*['"]?[A-Za-z0-9_-]{30,}['"]?`),
	regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
	regexp.MustCompile(`gho_[A-Za-z0-9]{36}`),
	regexp.MustCompile(`ghu_[A-Za-z0-9]{36}`),
	regexp.MustCompile(`ghs_[A-Za-z0-9]{36}`),
	regexp.MustCompile(`ghr_[A-Za-z0-9]{36}`),

	// Generic API keys
	regexp.MustCompile(`(?i)(api_key|apikey|api-key|secret_key|secretkey|secret-key|access_token|auth_token)\s*[=:]\s*['"]?[A-Za-z0-9_-]{16,}['"]?`),

	// Private keys
	regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),

	// Bearer tokens
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_-]{20,}`),

	// Basic auth in URLs
	regexp.MustCompile(`https?://[^:]+:[^@]+@`),

	// Slack tokens
	regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`),

	// Stripe
	regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
	regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24}`),

	// Generic high-entropy strings that look like secrets (32+ hex or base64)
	regexp.MustCompile(`(?i)(password|passwd|pwd|secret)\s*[=:]\s*['"]?[^\s'"]{8,}['"]?`),
}

const redactedPlaceholder = "[REDACTED]"

func Redact(input string) string {
	result := input
	for _, pattern := range sensitivePatterns {
		result = pattern.ReplaceAllString(result, redactedPlaceholder)
	}
	return result
}

func RedactEnvVars(envVars []string) []string {
	sensitiveEnvNames := []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"GITHUB_TOKEN",
		"GH_TOKEN",
		"GITHUB_PAT",
		"API_KEY",
		"SECRET_KEY",
		"AUTH_TOKEN",
		"ACCESS_TOKEN",
		"PASSWORD",
		"PASSWD",
		"DATABASE_URL",
		"REDIS_URL",
		"MONGO_URL",
		"STRIPE_SECRET_KEY",
		"SLACK_TOKEN",
		"NPM_TOKEN",
		"PYPI_TOKEN",
	}

	result := make([]string, 0, len(envVars))
	for _, env := range envVars {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			result = append(result, env)
			continue
		}

		name := strings.ToUpper(parts[0])
		isSensitive := false
		for _, sensitive := range sensitiveEnvNames {
			if strings.Contains(name, sensitive) {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			result = append(result, parts[0]+"="+redactedPlaceholder)
		} else {
			result = append(result, env)
		}
	}
	return result
}

func RedactArgs(args []string) []string {
	result := make([]string, len(args))
	for i, arg := range args {
		result[i] = Redact(arg)
	}
	return result
}
