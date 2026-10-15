package redact

import (
	"regexp"
	"strings"
)

var sensitivePatterns = []*regexp.Regexp{
	// AWS
	regexp.MustCompile(`(?i)(aws_access_key_id|aws_secret_access_key|aws_session_token)['"]?\s*[=:]\s*['"]?[A-Za-z0-9/+=]{20,}['"]?`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),

	// GitHub
	regexp.MustCompile(`(?i)(github_token|gh_token|github_pat)['"]?\s*[=:]\s*['"]?[A-Za-z0-9_-]{30,}['"]?`),
	regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
	regexp.MustCompile(`gho_[A-Za-z0-9]{36}`),
	regexp.MustCompile(`ghu_[A-Za-z0-9]{36}`),
	regexp.MustCompile(`ghs_[A-Za-z0-9]{36}`),
	regexp.MustCompile(`ghr_[A-Za-z0-9]{36}`),

	// Generic API keys
	regexp.MustCompile(`(?i)(api_key|apikey|api-key|secret_key|secretkey|secret-key|access_token|auth_token)['"]?\s*[=:]\s*['"]?[A-Za-z0-9_-]{16,}['"]?`),

	// Private keys: the whole block first, so the key material goes with its
	// header (#4340). [\s\S] also spans the literal \n of a JSON string. The
	// header-only form below stays for a truncated block with no END line.
	regexp.MustCompile(`-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )*PRIVATE KEY-----`),
	regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),

	// Bearer tokens
	// The token body takes the JWT and base64 alphabet too: "." separates a
	// JWT's three segments, and the old class stopped at the first one (#4340).
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_.~+/=-]{20,}`),
	// A short token is redacted only as an Authorization value: prose such as
	// "bearer authentication" is no secret, a header value is.
	regexp.MustCompile(`(?i)authorization['"]?\s*[=:]\s*['"]?bearer\s+[^\s'"]{6,}`),

	// Credentials in a URL's userinfo. Any scheme: postgres://, mongodb+srv://,
	// amqp:// and redis:// carry them exactly as http:// does (#4340).
	regexp.MustCompile(`https?://[^:]+:[^@]+@`),
	regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@'"]+:[^\s/@'"]+@`),

	// A credential passed as the NEXT argument (#4340). The name must be followed
	// by whitespace, so --password-file and --token-url are left readable.
	regexp.MustCompile(`(?i)--(?:password|passwd|pwd|token|secret|api-key|apikey)\s+['"]?[^\s'"-][^\s'"]*['"]?`),
	// curl -u / --user user:pass; without a colon there is no password to hide.
	regexp.MustCompile(`(?i)(?:^|\s)(?:-u|--user)\s+['"]?[^\s:'"]+:[^\s'"]+['"]?`),

	// Provider keys that are bare (no "key=" name beside them) (#4340).
	regexp.MustCompile(`sk-(?:ant|proj)-[A-Za-z0-9_-]{20,}`),

	// Slack tokens
	regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`),

	// Stripe
	regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
	regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24}`),

	// Generic high-entropy strings that look like secrets (32+ hex or base64)
	regexp.MustCompile(`(?i)(password|passwd|pwd|secret)['"]?\s*[=:]\s*['"]?[^\s'"]{8,}['"]?`),
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

// RedactArgs redacts a whitespace-split argument list.
//
// Each argument is redacted on its own, and then the list is redacted again
// as the command line it came from. The second pass is what catches a secret
// whose pattern spans a split: in `curl -H "Authorization: Bearer <tok>"` the
// token is its own argument, and `<tok>"` alone matches nothing (#4332). When
// that pass changes something, the result is the redacted line split on
// whitespace again, so the list can come back shorter than it went in;
// otherwise it is the per-argument result, element for element.
func RedactArgs(args []string) []string {
	result := make([]string, len(args))
	for i, arg := range args {
		result[i] = Redact(arg)
	}
	joined := strings.Join(result, " ")
	if redacted := Redact(joined); redacted != joined {
		return strings.Fields(redacted)
	}
	return result
}

// RedactArguments returns a redacted deep copy of a decoded JSON object, such
// as an MCP tool call's arguments. The input is never modified.
//
// A string is redacted with Redact, and also as the assignment its key spells:
// the patterns recognise many secrets by name ("password=…", "api_key: …"),
// and in a JSON object the name is the key, not part of the value. When
// `key=value` redacts where the value alone would not, the whole value is
// replaced. Strings in an array take the array's key. Numbers, booleans and
// nulls are kept as they are, so the object keeps its shape.
func RedactArguments(args map[string]interface{}) map[string]interface{} {
	return redactObject("", args)
}

// redactObject redacts one object. parentKey is the key the object sits under,
// so {"password": {"value": "<s>"}} is judged as password=<s> (#4340). A string
// is redacted under its own key first, then under the parent's.
func redactObject(parentKey string, args map[string]interface{}) map[string]interface{} {
	if args == nil {
		return nil
	}
	// A {"name": "DB_PASSWORD", "value": "<s>"} pair (a k8s env entry) spells the
	// secret's name in a sibling, not in the value's own key.
	name, _ := args["name"].(string)
	out := make(map[string]interface{}, len(args))
	for k, v := range args {
		out[k] = redactJSONValue(k, v, parentKey)
		if s, ok := v.(string); ok && k == "value" && name != "" {
			out[k] = redactKeyedString(name, s)
		}
		if s, ok := out[k].(string); ok && s != redactedPlaceholder && parentKey != "" {
			if _, isStr := v.(string); isStr {
				out[k] = redactKeyedString(parentKey, s)
			}
		}
	}
	return out
}

func redactJSONValue(key string, v interface{}, parentKey string) interface{} {
	switch t := v.(type) {
	case string:
		return redactKeyedString(key, t)
	case map[string]interface{}:
		return redactObject(inheritedKey(key, parentKey), t)
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, e := range t {
			out[i] = redactJSONValue(key, e, parentKey)
		}
		return out
	default:
		return v
	}
}

// inheritedKey is the key a nested object is judged under: its own when that
// names a secret, otherwise the nearest secret key above it.
func inheritedKey(key, parentKey string) string {
	if key != "" && Redact(key+"=xxxxxxxxxxxxxxxxxxxxxxxxxxxx") != key+"=xxxxxxxxxxxxxxxxxxxxxxxxxxxx" {
		return key
	}
	return parentKey
}

func redactKeyedString(key, value string) string {
	redacted := Redact(value)
	if key == "" {
		return redacted
	}
	if Redact(key+"="+value) != key+"="+redacted {
		return redactedPlaceholder
	}
	return redacted
}
