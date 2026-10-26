package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"sync"
)

// The scanner reads what the client reads (#4407).
//
// # The defect
//
// encoding/json matches an object key to a struct field case-insensitively,
// and when two keys match the same field the LAST one wins. Every MCP client
// reads keys exactly. So a server that sends a scanned field twice — once
// spelled exactly, then a fold variant after it — hands the client one value
// and every scanner here another:
//
//	"description": <poison>, "Description": "Returns weather."
//	"result": {<poison>},    "Result": {"content": []}
//	"method": "sampling/createMessage", "Method": "ping"
//
// The scanners read the decoy, find nothing, and the proxy forwards the
// original bytes: no BLOCK, no AUDIT, no receipt. Measured on all three
// transports, and delivered by the TS SDK client (nested keys) and the Python
// `mcp` client (nested and envelope keys).
//
// # The fix
//
// When a message carries such a pair, it is screened twice: as it decodes
// (exactly what happened before), and as the client reads it — every object
// with the fold variants of a field it also spells exactly reduced to the
// exact one. The client's view wins only when it is more restrictive; on a
// tie the decoded screen's outcome stands, so no decision is lower than
// main's. A message with no such pair, which is every message a conformant
// server sends, takes the first screen only, unchanged.
//
// Four properties are load-bearing:
//
//   - The decoded screen still runs and still decides ties. A fold variant no
//     client reads (an exact `text` beside a poisoned `Text`) is what main
//     scanned, so dropping it would lower a decision main made. Nothing is
//     judged illegitimate here: a tool's structuredContent can carry user data
//     whose keys differ only in case.
//   - A tie between two rewrites keeps main's, because a rewrite re-encodes
//     the fields it decoded: the decoy, not the poison, reaches the client.
//     The raw subtrees a rewrite passes through (inputSchema, outputSchema,
//     _meta) are walked as maps, which read keys exactly as the client does.
//   - The client's view is screened STATELESSLY. Its handler has every
//     session tracker removed, so a message read twice is observed by the
//     trackers once. Otherwise the schema-drift tracker would see the decoy
//     description and the real one as a change between two listings, and
//     attribute it to a rug pull.
//   - Main's receipts are never removed, and none is written twice. Both
//     screens' entries are held; the decoded screen's are all written, and
//     the client view adds its own when it won or when both forwarded (the
//     client then reads exactly what it screened). A receipt only the client's
//     view produced says so.
//
// Residuals, not closed here: the session trackers, and the description and
// annotation caches that tools/call evaluation reads, keep observing the
// decoded form, as they did before. A rewrite that passed a fold pair through
// raw would relay what the decoded screen made of it; no scanner here does.

// clientViewFieldNames holds every key a struct in this package decodes, as
// written in its json tag: the spellings a schema-exact client reads. Only a
// fold group with one of these in it is reduced; a group of keys none of our
// structs decode is decoded by maps, which are case-sensitive, so the scanners
// already read what the client reads.
//
// TestClientViewFieldNamesCoverEveryTag derives this set from the package's
// struct tags and fails when it drifts.
var clientViewFieldNames = toSet(
	"_meta", "annotations", "arg_category", "arg_name", "argument", "arguments",
	"attribution_gated", "audience", "audited", "authentication",
	"authorization_endpoint", "blob", "blocked", "blocking", "capabilities",
	"category", "code", "code_challenge_methods_supported", "completion",
	"confidence", "content", "content_index", "content_type", "contents", "data",
	"decision", "description", "descriptionHash", "destructiveHint", "detail",
	"elicitationId", "error", "field", "findings", "flagged", "found",
	"grant_types_supported", "hasMore", "icons", "id", "idempotentHint",
	"includeContext", "input", "inputSchema", "inputSchemaHash", "instructions",
	"intent", "intents", "introspection_endpoint", "isError", "issuer", "jsonrpc",
	"jwks_uri", "last_seen", "lastModified", "level", "limit", "logger",
	"match_len", "maxTokens", "message", "messages", "method", "mimeType", "mode",
	"modelPreferences", "name", "nextCursor", "openWorldHint", "original_decision",
	"outputSchema", "outputSchemaHash", "params", "path", "pattern", "poisoned",
	"priority", "progress", "progressToken", "prompts", "properties",
	"protocolVersion", "readOnlyHint", "reason", "reasons", "ref",
	"registration_endpoint", "requestedSchema", "required", "resource",
	"resources", "resourceTemplates", "response_types_supported", "result",
	"revocation_endpoint", "role", "roots", "rule_id", "rules", "schema_hash",
	"schemes", "sequence", "server_asserted_failure", "server_name", "serverInfo",
	"signal", "size", "sizes", "skills", "snippet", "source", "src",
	"stopSequences", "structuredContent", "systemPrompt", "task", "taxonomy",
	"taxonomy_ref", "taxonomy_refs", "text", "text_snip", "theme", "timestamp",
	"title", "token_endpoint", "tool_name", "tool_verb", "toolChoice", "toolResult", "tools",
	"toolUseId", "total", "triggered_rules", "type", "uri", "uri_template",
	"uriTemplate", "url", "value", "values", "varname", "version",
)

func toSet(names ...string) map[string]struct{} {
	s := make(map[string]struct{}, len(names))
	for _, n := range names {
		s[n] = struct{}{}
	}
	return s
}

// clientViewReason is added to every receipt that only the client's view
// produced, so the record says why the decoded screen did not see it.
const clientViewReason = "read as the client reads it: the message sent a field twice, spelled exactly and as a case-fold variant the decoder would have read instead (#4407)"

// screenAsClientReads screens one server→client message (not a batch: each
// member of a batch comes through here on its own) with one, and — when the
// message sends a decoded field twice under case folding — again on the
// client's view of it. See the comment at the top of this file.
func (h *MessageHandler) screenAsClientReads(data []byte, one func(*MessageHandler, []byte) ([]byte, bool)) ([]byte, bool) {
	view, ok := clientView(data)
	if !ok {
		return one(h, data)
	}
	var decodedAudits, viewAudits heldAudits
	var viewStderr bytes.Buffer
	out, acted := one(h.withHeldAudits(&decodedAudits), data)
	vout, vacted := one(h.statelessClone(&viewAudits, &viewStderr), view)

	decoded, client := screenRank(out, acted), screenRank(vout, vacted)
	// The client's view wins only when it is more restrictive. Otherwise the
	// decoded screen's outcome stands, exactly as before: on a tie that keeps
	// main's rewrite, and unchanged always forwards the original bytes.
	viewWins := client > decoded
	// Main's receipts are always written. The client view adds its own when
	// they describe what happened: when it won, or when both forwarded, since
	// the client then reads exactly the content the view screened. When the
	// decoded screen rewrote or blocked and won, the view's describe content
	// that was not delivered.
	h.writeHeldAudits(decodedAudits.entries, viewAudits.entries, viewWins || decoded == rankForwarded)
	if viewWins {
		if h.Stderr != nil && viewStderr.Len() > 0 {
			_, _ = h.Stderr.Write(viewStderr.Bytes())
		}
		return vout, vacted
	}
	return out, acted
}

// The outcome of one screen, ordered by restrictiveness.
const (
	rankForwarded = iota
	rankRewritten
	rankBlocked // replaced by a JSON-RPC error, or suppressed
)

func screenRank(out []byte, acted bool) int {
	if !acted {
		return rankForwarded
	}
	if out == nil || isErrorEnvelope(out) {
		return rankBlocked
	}
	return rankRewritten
}

// isErrorEnvelope reports whether a screen's output is a JSON-RPC error
// response: what every BLOCK on a response or a request is replaced with.
func isErrorEnvelope(b []byte) bool {
	var env struct {
		Error  json.RawMessage `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return false
	}
	return len(env.Error) > 0 && string(env.Error) != "null" &&
		(len(env.Result) == 0 || string(env.Result) == "null")
}

// heldAudits collects a clone's audit entries until the caller writes them.
type heldAudits struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (a *heldAudits) add(e AuditEntry) {
	a.mu.Lock()
	a.entries = append(a.entries, e)
	a.mu.Unlock()
}

// withHeldAudits returns a copy of h whose audit entries go to dst instead of
// OnAudit. Everything else, the session trackers included, is shared.
func (h *MessageHandler) withHeldAudits(dst *heldAudits) *MessageHandler {
	c := *h
	if h.OnAudit != nil {
		c.OnAudit = dst.add
	}
	return &c
}

// statelessClone is withHeldAudits with every session tracker and cache
// removed, and Stderr redirected. TestStatelessCloneSharesNoSessionState
// fails when a field is added to MessageHandler without deciding which side
// of this line it is on.
func (h *MessageHandler) statelessClone(dst *heldAudits, stderr io.Writer) *MessageHandler {
	c := h.withHeldAudits(dst)
	c.Stderr = stderr
	c.SchemaDrift = nil
	c.ToolRegistry = nil
	c.ApprovalFatigue = nil
	c.ElicitationFatigue = nil
	c.SubAgentTracker = nil
	c.CapabilityExpansion = nil
	c.AnnotationCache = nil
	c.DescriptionCache = nil
	c.ThresholdPoisoning = nil
	c.CallHistory = nil
	c.LethalTrifecta = nil
	c.BrowserGameJailbreak = nil
	c.TaskAmplification = nil
	c.LateralWrite = nil
	c.GhostSplice = nil
	c.FetchDiversity = nil
	c.CompoSkill = nil
	c.StagedTrust = nil
	return c
}

// writeHeldAudits writes every decoded entry and, when addView is set, each
// view entry that is not one of them (by auditIdentity), marked with
// clientViewReason. A view entry identical to a decoded one is the same
// receipt, already written.
func (h *MessageHandler) writeHeldAudits(decoded, view []AuditEntry, addView bool) {
	if h.OnAudit == nil {
		return
	}
	seen := make(map[string]int, len(decoded))
	for _, e := range decoded {
		seen[auditIdentity(e)]++
		h.OnAudit(e)
	}
	if !addView {
		return
	}
	for _, e := range view {
		if id := auditIdentity(e); seen[id] > 0 {
			seen[id]--
			continue
		}
		e.Reasons = append(append([]string(nil), e.Reasons...), clientViewReason)
		h.OnAudit(e)
	}
}

// auditIdentity is what makes two entries the same receipt: everything but
// the timestamp, which differs between the two screens of one message.
func auditIdentity(e AuditEntry) string {
	e.Timestamp = ""
	b, _ := json.Marshal(e)
	return string(b)
}

// clientView returns data as a schema-exact client reads it, and ok=false
// when that is data itself: when data is not a single JSON object, or no
// object in it sends a decoded field twice under case folding.
func clientView(data []byte) ([]byte, bool) {
	body := bytes.TrimLeft(stripOneBOM(data), " \t\r\n")
	if len(body) == 0 || body[0] != '{' || !hasFoldDuplicateField(body) {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // a number is re-encoded as written, not as a float64
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	reduceToClientView(v)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, false
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), true
}

// reduceToClientView removes, in every object, each key that is a case-fold
// variant of another key in the same object which a struct here decodes
// under that exact spelling. The exact one is what the client reads.
func reduceToClientView(v any) {
	switch t := v.(type) {
	case map[string]any:
		groups := make(map[string][]string, len(t))
		for k := range t {
			fk := foldKey(k)
			groups[fk] = append(groups[fk], k)
		}
		for _, keys := range groups {
			if len(keys) < 2 {
				continue
			}
			exact := ""
			for _, k := range keys {
				if _, ok := clientViewFieldNames[k]; ok {
					exact = k
				}
			}
			if exact == "" {
				continue
			}
			for _, k := range keys {
				if k != exact {
					delete(t, k)
				}
			}
		}
		for _, c := range t {
			reduceToClientView(c)
		}
	case []any:
		for _, c := range t {
			reduceToClientView(c)
		}
	}
}

// hasFoldDuplicateField reports whether body is exactly one JSON object in
// which some object sends two different keys that are equal under the
// decoder's case folding, one of them a key a struct here decodes. It reads
// tokens only, so a message without one costs one pass and no tree.
func hasFoldDuplicateField(body []byte) bool {
	type group struct {
		first    string
		distinct bool
		known    bool
	}
	type frame struct {
		object  bool
		wantKey bool
		groups  map[string]*group
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var stack []*frame
	found := false
	for {
		tok, err := dec.Token()
		if err != nil {
			return false // malformed: the decoded screen alone decides
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{':
				stack = append(stack, &frame{object: true, wantKey: true})
				continue
			case '[':
				stack = append(stack, &frame{})
				continue
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				// One value, then only whitespace: anything after it is a
				// message no client parses, and not one to read two ways.
				rest := body[dec.InputOffset():]
				return found && len(bytes.TrimLeft(rest, " \t\r\n")) == 0
			}
			if top := stack[len(stack)-1]; top.object {
				top.wantKey = true
			}
			continue
		}
		if len(stack) == 0 {
			return false // a top-level scalar
		}
		top := stack[len(stack)-1]
		if !top.object {
			continue
		}
		if !top.wantKey {
			top.wantKey = true // a scalar value ends the member
			continue
		}
		top.wantKey = false
		if found {
			continue
		}
		k, _ := tok.(string)
		if top.groups == nil {
			top.groups = make(map[string]*group)
		}
		_, known := clientViewFieldNames[k]
		fk := foldKey(k)
		g := top.groups[fk]
		if g == nil {
			top.groups[fk] = &group{first: k, known: known}
			continue
		}
		g.distinct = g.distinct || k != g.first
		g.known = g.known || known
		found = g.distinct && g.known
	}
}
