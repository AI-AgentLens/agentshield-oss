package redact

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/datalabel"
	"github.com/AI-AgentLens/agentshield/internal/regexlit"
)

// sensitivePatterns is every secret shape Redact replaces, in order, each
// behind its required-literal prescan (regexlit, #4785). The prescan only
// skips a pattern that provably cannot match the text as it stands at that
// step, so the output is the plain regexp's (TestRedact_PrescanMatchesPlainRegexp).
// It matters on the hook's clock: redaction is linear in the command, and
// without the prescan each of the case-insensitive patterns walked the
// whole command, which on a 4-core host with every CPU busy took 6.5 s for a
// 1 MiB command against Codex's 10 s hook timeout.
var sensitivePatterns = prescanned(rawSensitivePatterns)

// handLiterals are the required literals of the three patterns regexlit
// derives none for: Go's parser factors their alternations ("password|
// passwd|pwd" becomes "p(?:ass(?:word|wd)|wd)") into pieces shorter than a
// selective literal. Each set is read off its pattern, case-insensitively:
//
//   - "--(password|passwd|pwd|token|secret|api-key|apikey)\s+": the match
//     starts with "--" and one of those words, so it holds "--pass", "--pwd",
//     "--token", "--secret" or "--api".
//   - "(^|\s)(-u|--user)\s+": "-u" or "--user" is followed by a whitespace
//     character; "--user" itself holds "--user".
//   - "(password|passwd|pwd|secret)": "passw", "pwd" or "secret".
//
// TestRedact_HandLiteralsAreRequired checks every set against its regexp on
// every input where the regexp matches.
var handLiterals = map[string][]string{
	`(?i)--(?:password|passwd|pwd|token|secret|api-key|apikey)\s+['"]?[^\s'"-][^\s'"]*['"]?`: {"--pass", "--pwd", "--token", "--secret", "--api"},
	`(?i)(?:^|\s)(?:-u|--user)\s+['"]?[^\s:'"]+:[^\s'"]+['"]?`:                               {"-u ", "-u\t", "-u\n", "-u\v", "-u\f", "-u\r", "--user"},
	`(?i)(password|passwd|pwd|secret)['"]?\s*[=:]\s*['"]?[^\s'"]{8,}['"]?`:                   {"passw", "pwd", "secret"},
}

func prescanned(res []*regexp.Regexp) []*regexlit.Matcher {
	out := make([]*regexlit.Matcher, len(res))
	for i, re := range res {
		out[i] = regexlit.NewFromRegexp(re)
		if lits, ok := handLiterals[re.String()]; ok && !out[i].HasPrescan() {
			out[i] = out[i].WithRequiredLiterals(lits, true)
		}
	}
	return out
}

var rawSensitivePatterns = []*regexp.Regexp{
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

	// Generic API keys. The value class is the token pattern's below, dots
	// and base64 characters included (#4816): with [A-Za-z0-9_-] it stopped
	// at a JWT's first dot, and the token pattern could no longer see the
	// key name inside [REDACTED], so the payload and signature were recorded.
	regexp.MustCompile(`(?i)(api_key|apikey|api-key|secret_key|secretkey|secret-key|access_token|auth_token)['"]?\s*[=:]\s*['"]?[A-Za-z0-9_.~+/=-]{16,}['"]?`),

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

	// A bare token name: TOKEN=<v>, "token":"<v>", X-Token: <v>, deploy_token=<v>
	// (#4340). The value must be 12+ credential characters, so prose
	// ("token: refresh"), counters ("token=42") and "tokens"/"token-url" stay readable.
	regexp.MustCompile(`(?i)(?:\b|_)token['"]?\s*[=:]\s*['"]?[A-Za-z0-9_.~+/=-]{12,}['"]?`),

	// Provider keys that are bare (no "key=" name beside them) (#4340).
	regexp.MustCompile(`sk-(?:ant|proj)-[A-Za-z0-9_-]{20,}`),
	// The shapes sec-block-ai-apikey-inline BLOCKs: a legacy or other
	// provider's sk- key (OpenAI before project keys, DeepSeek, ...) and a
	// Google API key. Before these two, the rule BLOCKed the call and the
	// receipt kept the key in plain text, on the line and the wire alike.
	// TestRedact_SecretValueRulesNeverMatchTheRecord holds every such rule to
	// its own redacted TPs.
	regexp.MustCompile(`\bsk-(?:[a-z0-9]+-){0,2}[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),

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
	return redactor{}.object("", args)
}

// redactor is RedactArguments' walk. With labels it is
// RedactArgumentsWithLabels': each string is redacted with RedactWithLabels,
// and its key judged as main judged it, on the value with its label spans
// replaced, and also on the value as written (#4813). A nil labels is
// RedactArguments exactly.
type redactor struct {
	labels func(string) []datalabel.Span
}

// object redacts one object. parentKey is the key the object sits under,
// so {"password": {"value": "<s>"}} is judged as password=<s> (#4340). A string
// is redacted under its own key first, then under the parent's.
func (r redactor) object(parentKey string, args map[string]interface{}) map[string]interface{} {
	if args == nil {
		return nil
	}
	// A {"name": "DB_PASSWORD", "value": "<s>"} pair (a k8s env entry) spells the
	// secret's name in a sibling, not in the value's own key. With labels the
	// name is judged with its label spans replaced, as the scrubber left it
	// before #4813.
	name, _ := args["name"].(string)
	name = r.scrubbed(name, r.spans(name))
	out := make(map[string]interface{}, len(args))
	for k, v := range args {
		rv := r
		if s, ok := v.(string); ok {
			if spans := r.spans(s); len(spans) > 0 {
				out[k] = r.labelledValue(k, s, spans, name, parentKey)
				continue
			}
			// No label in s: main's steps, without scanning it again.
			rv = redactor{}
		}
		out[k] = rv.value(k, v, parentKey)
		if s, ok := v.(string); ok && k == "value" && name != "" {
			out[k] = rv.keyed(name, s)
		}
		if s, ok := out[k].(string); ok && s != redactedPlaceholder && parentKey != "" {
			if _, isStr := v.(string); isStr {
				// s is already redacted, its label spans with it: judged
				// again under the parent's key, as main judged it.
				out[k] = redactor{}.keyed(parentKey, s)
			}
		}
	}
	return out
}

func (r redactor) value(key string, v interface{}, parentKey string) interface{} {
	switch t := v.(type) {
	case string:
		return r.keyed(key, t)
	case map[string]interface{}:
		return r.object(inheritedKey(key, parentKey), t)
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, e := range t {
			out[i] = r.value(key, e, parentKey)
		}
		return out
	case float64, json.Number, int, int64:
		// A number under a secret key is the secret (a PIN, a numeric password).
		if inheritedKey(key, parentKey) != "" {
			return redactedPlaceholder
		}
		return v
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

// keyed redacts value, a string under key: the whole value when key=value
// redacts where value alone would not.
func (r redactor) keyed(key, value string) string {
	spans := r.spans(value)
	redacted := redactSpans(value, spans)
	if key == "" {
		return redacted
	}
	// Main's judgement, on the value as the scrubber left it. With no label
	// in the value that is the value, and its redaction is redacted.
	sv, rsv := value, redacted
	if len(spans) > 0 {
		sv = r.scrubbed(value, spans)
		rsv = Redact(sv)
	}
	if Redact(key+"="+sv) != key+"="+rsv {
		return redactedPlaceholder
	}
	// And on the value as the agent wrote it (#4813): a label inside the
	// value can stop the key's pattern short of what it names.
	if len(spans) > 0 && keyRedacts(key, value) {
		return redactedPlaceholder
	}
	return redacted
}

// labelledValue redacts s, a string value of an object that carries a label
// (spans), under its key k, the object's (scrubbed) name sibling and its
// parent key: the steps object takes for a value with no label, made no
// weaker than main's (#4813).
//
// Main ran those steps on the value with its label spans replaced: its own
// key, then the name sibling for a "value", then the parent key over that
// result, which redacts it a second time. When main replaced the value whole
// so does this, and so it does when one of those keys judges the value as
// written a secret. Otherwise the value is masked as a text whose main-order
// spans come from as many passes as main ran, then judged under the parent
// key as main judged its own result.
func (r redactor) labelledValue(k, s string, spans []datalabel.Span, name, parentKey string) string {
	plain := redactor{}
	sv := r.scrubbed(s, spans)
	mainV := plain.keyed(k, sv)
	if k == "value" && name != "" {
		mainV = plain.keyed(name, sv)
	}
	if mainV != redactedPlaceholder && parentKey != "" {
		mainV = plain.keyed(parentKey, mainV)
	}
	if mainV == redactedPlaceholder {
		return redactedPlaceholder
	}
	for _, key := range []string{k, parentKey} {
		if key != "" && keyRedacts(key, s) {
			return redactedPlaceholder
		}
	}
	if k == "value" && name != "" && keyRedacts(name, s) {
		return redactedPlaceholder
	}
	passes := 1
	if parentKey != "" {
		passes = 2
	}
	ms, _ := maskSpans(s, spans, 0, nil, passes)
	text := Redact(mask(s, ms))
	if parentKey != "" {
		return plain.keyed(parentKey, text)
	}
	return text
}

// keyRedacts reports whether key=value redacts where value alone would not.
func keyRedacts(key, value string) bool {
	return Redact(key+"="+value) != key+"="+Redact(value)
}

// spans returns the label spans of s, nil without labels.
func (r redactor) spans(s string) []datalabel.Span {
	if r.labels == nil || s == "" {
		return nil
	}
	return r.labels(s)
}

// scrubbed returns s with its label spans replaced by their placeholders,
// as the scrubber returned it before #4813, and s itself when there are none.
func (r redactor) scrubbed(s string, spans []datalabel.Span) string {
	if len(spans) == 0 {
		return s
	}
	ms := make([]span, len(spans))
	for i, l := range spans {
		ms[i] = labelSpan(l, 0)
	}
	return mask(s, ms)
}
