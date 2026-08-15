package mcp

import (
	"fmt"
	"strings"
	"sync"
)

// LethalTrifectaSignal is emitted once per session when all three "lethal
// trifecta" capability classes have been exercised across separate tool calls.
type LethalTrifectaSignal string

const (
	// SignalLethalTrifectaSession fires the first time a session has exercised
	// all three trifecta capability classes (private-data read, untrusted
	// ingest, external egress) — even across separate tool calls. AUDIT.
	SignalLethalTrifectaSession LethalTrifectaSignal = "lethal_trifecta_session"
)

// syntheticLethalTrifecta is the virtual tool name injected into the policy
// engine when the session trifecta completes, mirroring the approval-fatigue /
// sub-agent tracker approach.
const syntheticLethalTrifecta = "__mcp_lethal_trifecta_session__"

// trifectaCap is one of the three lethal-trifecta capability classes.
type trifectaCap int

const (
	capPrivateRead trifectaCap = iota // (1) access to private/sensitive data
	capUntrustedIngest                // (2) exposure to untrusted external content
	capEgress                         // (3) ability to communicate externally
	numTrifectaCaps
)

// LethalTrifectaTracker accumulates, across a session's MCP tool calls, which of
// the three lethal-trifecta capability classes have been exercised. It fires
// SignalLethalTrifectaSession exactly ONCE — on the call that completes the set.
//
// This is the cross-call complement to the single-compound-command
// stateful.chain rules (ts-sf-lethal-trifecta-*, #2598): the trifecta risk lives
// in the *combination available across the session*, not in any one action, so
// the three capabilities can arrive as three separate tool calls and still
// constitute the canonical indirect-injection exfiltration precondition.
//
// AUDIT, not BLOCK: a benign agent session can legitimately read a config
// secret, fetch a page, and send a message. The composite is a review signal
// (all three capabilities are live in one session), not proof of exfiltration.
//
// Session-scoped: one tracker per MessageHandler. In stdio-proxy mode (one agent
// = one session) this is exact; in shared HTTP-proxy mode it aggregates across
// clients — the same documented tradeoff as ApprovalFatigueTracker, acceptable
// for an AUDIT-only aggregate signal.
type LethalTrifectaTracker struct {
	mu    sync.Mutex
	seen  [numTrifectaCaps]bool
	fired bool
}

// NewLethalTrifectaTracker returns a ready tracker with an empty capability set.
func NewLethalTrifectaTracker() *LethalTrifectaTracker {
	return &LethalTrifectaTracker{}
}

// Scan classifies the current tool call, records any capability classes it
// exercises into the session set, and returns SignalLethalTrifectaSession the
// first time all three classes are present. Returns "" otherwise (including all
// calls after the signal has already fired).
func (t *LethalTrifectaTracker) Scan(toolName string, args map[string]interface{}) LethalTrifectaSignal {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fired {
		return ""
	}
	for _, c := range classifyTrifectaCaps(toolName, args) {
		t.seen[c] = true
	}
	if t.seen[capPrivateRead] && t.seen[capUntrustedIngest] && t.seen[capEgress] {
		t.fired = true
		return SignalLethalTrifectaSession
	}
	return ""
}

// classifyTrifectaCaps returns the capability classes a single tool call
// exercises. A call may exercise more than one (e.g. a fetch that also carries a
// payload), or none.
func classifyTrifectaCaps(toolName string, args map[string]interface{}) []trifectaCap {
	lname := strings.ToLower(toolName)
	argText := flattenArgText(args)

	var caps []trifectaCap

	// (1) private-data read: a secret-fetching tool by name, or a read-oriented
	//     tool whose arguments reference a credential/secret path. The
	//     secret-path requirement is the key discriminator that keeps the
	//     composite from firing on every session that merely reads files.
	if isSecretFetchTool(lname) || (isReadOnlyTool(lname) && argsReferenceSecret(argText)) {
		caps = append(caps, capPrivateRead)
	}

	// (2) untrusted ingest: a tool that pulls in external content (browse /
	//     fetch / crawl / download / web search), or a read-oriented tool given
	//     an external URL.
	if isUntrustedIngestTool(lname) || (isReadOnlyTool(lname) && argsReferenceExternalURL(argText)) {
		caps = append(caps, capUntrustedIngest)
	}

	// (3) external egress: a send/upload/post/webhook tool that carries data
	//     (an external URL destination or a payload argument).
	if isEgressTool(lname) && (argsReferenceExternalURL(argText) || hasPayloadArg(args)) {
		caps = append(caps, capEgress)
	}

	return caps
}

// flattenArgText concatenates all string-ish argument values into one
// lowercased string for substring classification.
func flattenArgText(args map[string]interface{}) string {
	if len(args) == 0 {
		return ""
	}
	var b strings.Builder
	for _, v := range args {
		switch s := v.(type) {
		case string:
			b.WriteString(s)
			b.WriteByte(' ')
		case fmt.Stringer:
			b.WriteString(s.String())
			b.WriteByte(' ')
		default:
			_, _ = fmt.Fprintf(&b, "%v ", v)
		}
	}
	return strings.ToLower(b.String())
}

// isSecretFetchTool matches tool names that read secrets/credentials by name
// alone — no path argument needed.
func isSecretFetchTool(lname string) bool {
	needles := []string{
		"get_secret", "read_secret", "fetch_secret", "getsecret", "readsecret",
		"read_credential", "get_credential", "fetch_credential", "read_creds",
		"vault_read", "read_vault", "get_parameter", "getparameter",
		"secretsmanager", "read_env", "get_env", "dump_env", "read_ssh",
		"read_key", "get_key", "dump_secret",
	}
	return containsAny(lname, needles)
}

// argsReferenceSecret reports whether flattened argument text names a canonical
// credential/secret file — the same markers the shipped stateful.chain
// lethal-trifecta rules key on.
func argsReferenceSecret(argText string) bool {
	markers := []string{
		".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_dsa", ".ssh/id_ecdsa",
		"id_rsa", "id_ed25519", ".aws/credentials", ".gnupg", ".kube/config",
		".docker/config.json", ".netrc", ".npmrc", ".pypirc", "vault-token",
		"/etc/shadow", ".pem", ".ppk", ".p12", ".pfx", ".kdbx", ".env",
		"credentials", "private_key", "privatekey", "secret_key", "secretkey",
	}
	return containsAny(argText, markers)
}

// isUntrustedIngestTool matches tools that pull external/attacker-controllable
// content into the session.
func isUntrustedIngestTool(lname string) bool {
	needles := []string{
		"fetch", "browse", "crawl", "scrape", "web_search", "websearch",
		"read_url", "get_url", "open_url", "http_get", "httpget", "download",
		"curl", "wget", "navigate", "visit", "web_fetch", "webfetch",
		"read_page", "readpage", "get_page", "load_url",
	}
	return containsAny(lname, needles)
}

// argsReferenceExternalURL reports whether flattened argument text contains an
// http(s) URL. External-ness is approximated by scheme presence; localhost /
// RFC1918 hosts are excluded to avoid flagging internal-only traffic.
func argsReferenceExternalURL(argText string) bool {
	if !strings.Contains(argText, "http://") && !strings.Contains(argText, "https://") {
		return false
	}
	internal := []string{
		"localhost", "127.0.0.1", "0.0.0.0", "::1",
		"http://10.", "https://10.", "http://192.168.", "https://192.168.",
		"http://172.16.", "https://172.16.", ".local/", ".internal/",
	}
	// If the only URL-ish content is internal, don't count it as egress/ingest.
	// This is a heuristic: presence of any external-looking scheme wins unless
	// an internal marker is what carries the scheme.
	for _, m := range internal {
		if strings.Contains(argText, m) {
			// internal marker present; only suppress if there's no other http(s)
			// occurrence beyond it — conservatively keep the signal when both
			// internal and external URLs appear.
			stripped := strings.ReplaceAll(argText, m, "")
			if !strings.Contains(stripped, "http://") && !strings.Contains(stripped, "https://") {
				return false
			}
		}
	}
	return true
}

// isEgressTool matches tools that send data to an external destination.
func isEgressTool(lname string) bool {
	needles := []string{
		"send_", "sendmessage", "send_message", "post_", "http_post", "httppost",
		"upload", "webhook", "email", "publish", "put_object", "putobject",
		"write_object", "sftp", "scp", "notify", "message_", "slack", "discord",
		"telegram", "exfil", "push_", "transfer", "sync_", "post_message",
		"create_message", "send", "dispatch",
	}
	return containsAny(lname, needles)
}

// hasPayloadArg reports whether the arguments carry a body/data/content payload
// (the thing that would be exfiltrated).
func hasPayloadArg(args map[string]interface{}) bool {
	payloadKeys := []string{
		"body", "data", "content", "payload", "attachment", "message",
		"text", "file", "blob", "form", "json",
	}
	for k := range args {
		lk := strings.ToLower(k)
		for _, p := range payloadKeys {
			if lk == p || strings.Contains(lk, p) {
				return true
			}
		}
	}
	return false
}

// containsAny reports whether haystack contains any of the needles.
func containsAny(haystack string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}
