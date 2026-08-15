package mcp

import (
	"fmt"
	"regexp"
	"strings"
)

// CoherenceSignal identifies a class of argument-name vs tool-name semantic
// mismatch. The threat model: indirect prompt injection steers the agent to
// invoke a benign-named tool with arguments whose names imply a different
// capability (e.g., `read_file({"command":"rm -rf /"})`); OR a malicious
// server publishes a tool with a benign-sounding name (`read_doc`) but a
// schema that accepts dangerous argument names (`command`, `shell`, `eval`)
// that the tool then executes. Both shapes are equally suspicious — the
// argument name semantically contradicts the tool name's verb intent.
type CoherenceSignal string

const (
	// SignalArgumentCoherenceViolation fires when a read/list/get-verb tool
	// receives an argument whose name implies execution, shell, or outbound-
	// egress semantics. Read-verb tools should accept path/uri/id-shaped args;
	// the presence of `command`, `script`, `eval`, `shell`, `code`, `payload`
	// (exec/shell categories) — or an outbound-push sink such as `webhook_url`,
	// `callback_url`, `forward_to`, `exfil_url` (egress category) — is a
	// behavioural contradiction that almost never appears in legitimate tool
	// calls. The egress category specifically catches the exfiltration-via-
	// benign-reader shape: a trusted reader steered to also push its result out.
	SignalArgumentCoherenceViolation CoherenceSignal = "argument_coherence_violation"

	// SignalArgumentValueInjection fires when a NON-command-typed argument value
	// carries shell command-substitution (`$(...)`, backticks) or a chained shell
	// command. The checks above inspect argument NAMES; this inspects argument
	// VALUES. The threat: indirect prompt injection (or a malicious server) plants
	// `$(cat ~/.ssh/id_rsa|base64)` inside a field a correct tool treats as a
	// literal path/id/recipient — but a tool that shells out (`sh -c "cat "+path`,
	// a common MCP-server bug) then executes it. Command/script/query/content
	// fields are deliberately EXEMPT: shell syntax is legitimate data there
	// (FP #1486), so only fields meant to hold inert values (paths, ids, urls,
	// names) are scanned.
	SignalArgumentValueInjection CoherenceSignal = "argument_value_injection"
)

// CoherenceFinding records one detected coherence violation.
type CoherenceFinding struct {
	Signal      CoherenceSignal `json:"signal"`
	Detail      string          `json:"detail"`
	ToolName    string          `json:"tool_name"`
	ToolVerb    string          `json:"tool_verb"`
	ArgName     string          `json:"arg_name"`
	ArgCategory string          `json:"arg_category"`
}

// CoherenceScanResult is the result of an argument-coherence scan.
type CoherenceScanResult struct {
	Blocked  bool               `json:"blocked"`
	Findings []CoherenceFinding `json:"findings,omitempty"`
}

// ScanArgumentCoherence inspects the argument names of a tool call against
// the verb intent of the tool name. Returns findings if any argument name
// semantically contradicts the tool's declared read/list semantics.
//
// Conservative by design: fires only when the tool name is unambiguously a
// read-verb AND the argument name unambiguously signals execution or shell
// intent. Query/SQL/GraphQL argument names are not flagged because lookup-
// and search-verb tools legitimately accept them; the rule targets the
// dual-surface attack where an agent or a malicious server bridges a
// read-named tool to command execution.
func ScanArgumentCoherence(toolName string, arguments map[string]interface{}) CoherenceScanResult {
	var result CoherenceScanResult

	verb := classifyToolVerb(toolName)
	if verb != "read" {
		// Only read-verb tools are checked. Write/exec/delete tools are
		// expected to take command/script/etc. arguments and have their own
		// rule families for blocking.
		return result
	}

	for argName := range arguments {
		category := classifyArgumentCategory(argName)
		if category == "" {
			continue
		}
		result.Findings = append(result.Findings, CoherenceFinding{
			Signal:      SignalArgumentCoherenceViolation,
			Detail:      fmt.Sprintf("read-verb tool %q invoked with %s-shaped argument %q — argument name semantically contradicts the tool's declared read intent", toolName, category, argName),
			ToolName:    toolName,
			ToolVerb:    verb,
			ArgName:     argName,
			ArgCategory: category,
		})
	}

	result.Blocked = len(result.Findings) > 0
	return result
}

// classifyToolVerb returns "read", "write", "exec", "delete", "network", or
// "" if no verb is identifiable. Match is on tool-name PREFIX after stripping
// any namespace separator (`mcp__server__name` → `name`), case-insensitive.
//
// We intentionally use prefix-match (not substring) so that names like
// `update_get_url` are not misclassified as read. The verbs we recognise are
// the canonical MCP/filesystem set; unknown verbs fall through to "".
func classifyToolVerb(toolName string) string {
	// Strip namespace prefixes used by some hosts (e.g. Claude Desktop
	// prefixes server tools as `mcp__server__tool`).
	name := toolName
	if i := strings.LastIndex(name, "__"); i >= 0 {
		name = name[i+2:]
	}
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	lower := strings.ToLower(name)

	for _, p := range readVerbPrefixes {
		if strings.HasPrefix(lower, p) {
			return "read"
		}
	}
	for _, p := range writeVerbPrefixes {
		if strings.HasPrefix(lower, p) {
			return "write"
		}
	}
	for _, p := range execVerbPrefixes {
		if strings.HasPrefix(lower, p) {
			return "exec"
		}
	}
	for _, p := range deleteVerbPrefixes {
		if strings.HasPrefix(lower, p) {
			return "delete"
		}
	}
	return ""
}

// classifyArgumentCategory returns "exec", "shell", "egress", or "" for a given
// argument name. Matching is case-insensitive and uses both whole-name
// equality and word-boundary substring for compound names (e.g. `shell_cmd`).
//
// We deliberately omit "query"/"sql"/"url"/"endpoint"/"source" categories —
// those argument names appear in legitimate lookup/search/fetch tools and would
// generate false positives. The exec, shell, and egress families are the
// genuinely suspicious shapes: no defensible read-only tool accepts an argument
// named `command`, `cmd`, `script`, `shell`, `bash`, `eval`, `payload`, or an
// outbound-push sink like `webhook_url`, `callback_url`, `forward_to`, or
// `exfil_url`.
func classifyArgumentCategory(argName string) string {
	if argName == "" {
		return ""
	}
	lower := strings.ToLower(argName)

	for _, name := range execArgNames {
		if lower == name {
			return "exec"
		}
	}
	if execArgRe.MatchString(lower) {
		return "exec"
	}
	for _, name := range shellArgNames {
		if lower == name {
			return "shell"
		}
	}
	if shellArgRe.MatchString(lower) {
		return "shell"
	}
	for _, name := range egressArgNames {
		if lower == name {
			return "egress"
		}
	}
	if egressArgRe.MatchString(lower) {
		return "egress"
	}
	return ""
}

// ── Verb prefix tables ───────────────────────────────────────────────────

var (
	// readVerbPrefixes — tool name prefixes that imply read-only semantics.
	// Includes the common natural variants and the MCP-2025 standardised
	// surface (`resources/read`, etc.).
	readVerbPrefixes = []string{
		"read_", "get_", "list_", "show_", "fetch_", "view_",
		"display_", "describe_", "inspect_", "find_", "search_",
		"lookup_", "load_", "open_", "stat_", "head_",
	}

	// writeVerbPrefixes — tools expected to mutate state; not scanned by
	// this rule (their own rule families handle path/content validation).
	writeVerbPrefixes = []string{
		"write_", "create_", "edit_", "update_", "save_", "put_",
		"post_", "patch_", "modify_", "set_", "append_", "insert_",
		"upsert_", "publish_", "send_", "store_",
	}

	// execVerbPrefixes — tools that intentionally execute. Coherence rule
	// does not flag these because command-shaped arguments are expected.
	execVerbPrefixes = []string{
		"exec_", "execute_", "run_", "invoke_", "call_", "spawn_",
		"start_", "launch_", "trigger_", "shell_", "cmd_", "bash_",
		"eval_", "interpret_",
	}

	// deleteVerbPrefixes — destructive ops; out of scope here.
	deleteVerbPrefixes = []string{
		"delete_", "remove_", "destroy_", "drop_", "wipe_", "purge_",
		"unlink_", "rm_", "rmdir_", "truncate_",
	}

	// execArgNames — argument names that unambiguously signal command
	// execution intent. Exact-match list; the compound-name regex below
	// catches names that embed these tokens (e.g. `shell_cmd`, `cmd_string`).
	execArgNames = []string{
		"command", "cmd", "exec", "execute", "argv", "args_string",
	}
	execArgRe = regexp.MustCompile(`(?:^|_)cmd(?:_|$)|(?:^|_)command(?:_|$)|(?:^|_)exec(?:utable)?(?:_|$)`)

	// shellArgNames — shell/script/code execution arguments.
	shellArgNames = []string{
		"shell", "script", "bash", "sh", "code", "snippet", "payload", "eval",
	}
	shellArgRe = regexp.MustCompile(`(?:^|_)shell(?:_|$)|(?:^|_)script(?:_|$)|(?:^|_)bash(?:_|$)|(?:^|_)payload(?:_|$)|(?:^|_)eval(?:_|$)`)

	// egressArgNames — argument names that unambiguously denote an OUTBOUND push
	// destination ("where to deliver the result"). A read/get/list/fetch tool
	// has no reason to push its result anywhere; this is the exfiltration-via-
	// benign-reader shape — indirect prompt injection routes a trusted reader
	// (`read_file`, `get_document`, `list_secrets`) but appends a sink argument
	// so the (malicious or coerced) tool POSTs the read content out of band.
	//
	// FALSE-POSITIVE DISCIPLINE — three structural guarantees keep this near-zero
	// FP, since the rule BLOCKs:
	//   1. Only read-verb tools are scanned (ScanArgumentCoherence early-returns
	//      otherwise). Legitimate webhook/callback registration uses WRITE/CREATE
	//      verbs — `create_webhook`, `register_callback`, `subscribe_events`,
	//      `send_report` — none of which classify as "read".
	//   2. We match only names that denote a PUSH sink, never the resource a
	//      reader reads FROM. Bare `url`, `uri`, `endpoint`, `source`, `host`,
	//      `origin`, `base_url`, `download_url`, `target_url`, and the OAuth
	//      `redirect_uri` are all EXCLUDED — they legitimately appear on
	//      fetch/lookup tools.
	//   3. Sink tokens require a url/uri/endpoint/to suffix unless the token is
	//      itself inherently a push concept (`webhook`, `exfil`, `beacon`), so a
	//      benign boolean like `forward` or a path like `destination` does not
	//      trip the rule.
	egressArgNames = []string{
		"webhook", "webhook_url", "callback_url", "exfil_url", "exfiltrate_url",
		"exfiltrate_to", "beacon_url", "forward_to", "forward_url", "send_to",
		"post_to", "egress_url", "sink_url", "out_url",
	}
	// Token families:
	//   webhook | exfil(trate) | beacon  → inherently push; url/uri/to suffix optional
	//   callback                          → requires url/uri suffix (bare `callback` is ambiguous)
	//   forward | relay | leak            → requires url/uri/to suffix
	//   send | post | deliver | drop      → `_to` push form only
	egressArgRe = regexp.MustCompile(
		`(?:^|_)(?:webhook|exfil(?:trate)?|beacon)(?:_(?:url|uri|endpoint|to))?(?:_|$)` +
			`|(?:^|_)callback_(?:url|uri)(?:_|$)` +
			`|(?:^|_)(?:forward|relay|leak)_(?:url|uri|to)(?:_|$)` +
			`|(?:^|_)(?:send|post|deliver|drop)_to(?:_|$)`,
	)
)

// shellExpectedArgRE matches argument names where shell/code/query/template
// syntax is LEGITIMATE data, so the value-injection scan skips them. This is the
// FP #1486 exemption: a `command`/`script`/`query`/`content` field routinely
// carries `$(...)`, pipes, and `;` as its actual payload.
var shellExpectedArgRE = regexp.MustCompile(
	`^(command|commands|cmd|cmdline|script|scripts|shell|shellcode|bash|sh|zsh|powershell|code|sourcecode|source_code|snippet|program|eval|exec|expression|expr|formula|payload|query|queries|sql|graphql|q|search|searchquery|filter|jq|jsonpath|xpath|regex|pattern|glob|template|templates|content|contents|body|text|message|messages|msg|data|input|stdin|prompt|prompts|instruction|instructions|note|notes|comment|comments|markdown|md|html|yaml|yml|json|args|argv|arguments|params|parameters|value|values)$`,
)

// shellInjectionInValueRE matches shell command-substitution or a chained shell
// command inside an argument value. `$(...)` and backtick substitution are
// unconditional (near-zero FP in an inert field); the chain form requires a
// separator (start / ; | & newline) followed by a recognised command and at
// least one argument token, so a path segment like `rm/cache` (no space) or
// `node_modules` (no word boundary) does not trip it. Bare short tokens (`sh`,
// `nc`, `dd`) are intentionally excluded — too common as path segments.
var shellInjectionInValueRE = regexp.MustCompile(
	"\\$\\([^)]{1,400}\\)" + // $(...) command substitution
		"|`[^`]{1,400}`" + // `...` backtick command substitution
		"|(?:^|[;|&\n])\\s*(?:sudo\\s+)?(?:rm|curl|wget|bash|zsh|ncat|netcat|python[0-9.]*|perl|ruby|chmod|chown|mkfifo|systemctl|crontab|scp|ssh|base64|xxd|powershell|pwsh|telnet|tftp)\\s+\\S",
)

// ScanArgumentValueInjection inspects argument VALUES (not names) for shell
// command-substitution / command-chaining smuggled into an inert field. Exec/run
// tools and command/script/query/content arguments are exempt (shell syntax is
// their legitimate payload). Returns Blocked=true on the first violation.
func ScanArgumentValueInjection(toolName string, arguments map[string]interface{}) CoherenceScanResult {
	var result CoherenceScanResult

	// Exec-verb tools legitimately receive shell syntax in their arguments.
	if classifyToolVerb(toolName) == "exec" {
		return result
	}

	for argName, v := range arguments {
		if shellExpectedArgRE.MatchString(strings.ToLower(argName)) {
			continue
		}
		text := argValueToString(v)
		if text == "" {
			continue
		}
		if shellInjectionInValueRE.MatchString(text) {
			result.Blocked = true
			result.Findings = append(result.Findings, CoherenceFinding{
				Signal:      SignalArgumentValueInjection,
				Detail:      fmt.Sprintf("argument %q on tool %q carries shell command-substitution or a chained shell command in a field meant to hold an inert value (path/id/url/name) — command injection staged for an MCP server that shells out", argName, toolName),
				ToolName:    toolName,
				ArgName:     argName,
				ArgCategory: "value-injection",
			})
		}
	}
	return result
}
