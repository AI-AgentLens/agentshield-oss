package mcp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// ghostSpliceMaxNames bounds the per-session name set. A malicious server
// could otherwise register an unbounded number of tools/params purely to
// grow memory; 200 is far past any real tool schema (the PoC uses 4).
const ghostSpliceMaxNames = 200

// ghostSpliceWindowBytes is how far past a recorded name's assignment
// connector (`=`/`:`) the scan looks for a credential-shaped value. Long
// enough to span "alpha=~/.ssh/id_rsa, beta=src/, gamma=customers.csv" —
// several comma-joined fields, as the reference PoC's single result message
// does — without growing into a whole-message scan that would erase the
// "the name must be immediately followed by its value" requirement below.
const ghostSpliceWindowBytes = 160

// genericParamNames is a curated vocabulary of placeholder names that name
// nothing — the PoC's own alpha/beta/gamma/delta, their numbered/lettered
// siblings, and the generic English placeholders (foo/bar, value, data) that
// recur across schema-fuzzing and templating examples. A name here commits
// its tool to no stated purpose; whatever it holds is defined entirely by
// whichever later message tells the agent what to put there.
var genericParamNames = map[string]bool{
	"alpha": true, "beta": true, "gamma": true, "delta": true,
	"epsilon": true, "zeta": true, "eta": true, "theta": true,
	"foo": true, "bar": true, "baz": true, "qux": true, "quux": true,
	"value": true, "data": true, "input": true, "output": true,
	"item": true, "field": true, "param": true, "arg": true,
	"placeholder": true, "unknown": true,
}

// genericParamNameRe catches the numbered/lettered forms a curated word list
// cannot enumerate: field_1, param2, arg-0, val3, a1, x, b, ... A bare single
// letter is included deliberately — "alpha".."delta" are themselves stand-ins
// for the same idea in the reference PoC, just spelled as words instead of
// letters. This is intentionally permissive; recording a name here is not
// itself a finding (see RecordToolSchemas), so the precision cost is paid
// once, at Scan's compound assignment+credential requirement, not here.
var genericParamNameRe = regexp.MustCompile(`^(?:field|param|arg|val|item|slot|key|prop|attr|input|output)[_-]?\d+$|^[a-z][0-9]?$`)

// ghostSpliceAssignRe matches an assignment-shaped connector immediately
// following a recorded name — "alpha=", "alpha:", "alpha :" — the "populate
// X=Y" shape the GhostSplice PoC uses to hand the agent a value for an
// otherwise-meaningless field. A name that merely appears in prose ("alpha
// and beta are variables") never matches this and is not scored.
var ghostSpliceAssignRe = regexp.MustCompile(`^\s*[:=]\s*`)

// isGenericParamName reports whether name is a semantically empty
// placeholder — see genericParamNames / genericParamNameRe above.
func isGenericParamName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}
	if genericParamNames[lower] {
		return true
	}
	return genericParamNameRe.MatchString(lower)
}

// GhostSpliceTracker detects "GhostSplice" MCP cross-channel instruction
// fragmentation (disclosed August 2026, taxonomy:
// unauthorized-execution/agentic-attacks/mcp-cross-channel-fragment-injection):
// a malicious server registers a tool with generically-named parameters (no
// message alone names anything sensitive), then a later tool-call result maps
// those names onto credential/file-path-shaped values. Detection requires
// correlating a tools/list registration against a later, separate tools/call
// result — the entire point of the technique is that no single message
// contains a complete injection.
//
// Session-scoped: one tracker per MessageHandler, mirroring every other
// cross-call tracker in this package (LethalTrifectaTracker,
// ApprovalFatigueTracker, ToolAnnotationCache). In stdio-proxy mode (one
// agent = one session) this is exact; in shared HTTP-proxy mode it
// aggregates across clients until keyed by Mcp-Session-Id, the same
// documented tradeoff MCPCallHistoryTracker carries.
//
// Deliberately scoped to NAME correlation only, not to which specific tool a
// result came from: FilterToolCallResponse's transport leg carries no
// request/response tool-name correlation today (the audit entry it builds
// already records ToolName: "unknown" for this reason), so keying on "any
// generic name seen this session" rather than "this tool's generic name"
// avoids needing to build that correlation from scratch — and it is also the
// more conservative reading of the taxonomy's sampling-channel variant, where
// the field-filling result and the tool it targets need not even share a
// request in the same message.
type GhostSpliceTracker struct {
	mu    sync.Mutex
	names map[string]bool
}

// NewGhostSpliceTracker returns an initialized, empty tracker.
func NewGhostSpliceTracker() *GhostSpliceTracker {
	return &GhostSpliceTracker{names: make(map[string]bool)}
}

// RecordToolSchemas walks each tool's declared input schema and remembers any
// generically-named parameter for later cross-referencing by Scan. This is a
// silent recorder, not a scanner: registering a tool with vague parameter
// names is common in benign schemas too (terse coordinate/index fields, for
// instance), and is not itself evidence of anything. Folding a finding in
// here — e.g. into ScanToolDescription's PoisonFinding pipeline — would hide
// the tool from tools/list on that basis alone, which is both a guaranteed
// false-positive source and beside the point: the technique is defined by
// what a LATER message does with the name, not by the name's existence.
func (t *GhostSpliceTracker) RecordToolSchemas(tools []ToolDefinition) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, tool := range tools {
		if len(t.names) >= ghostSpliceMaxNames {
			return
		}
		if len(tool.InputSchema) == 0 {
			continue
		}
		var root interface{}
		if err := json.Unmarshal(tool.InputSchema, &root); err != nil {
			continue
		}
		rootMap, ok := root.(map[string]interface{})
		if !ok {
			continue
		}
		forEachSchemaProperty(rootMap, func(p schemaProperty) {
			if len(t.names) >= ghostSpliceMaxNames {
				return
			}
			if !isGenericParamName(p.Name) {
				return
			}
			t.names[strings.ToLower(p.Name)] = true
		})
	}
}

// snapshotNames returns a stable copy of the recorded name set for Scan to
// range over without holding the lock across the (potentially large) content
// scan.
func (t *GhostSpliceTracker) snapshotNames() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(t.names))
	for n := range t.names {
		out = append(out, n)
	}
	return out
}

// Scan checks tool-call result content for a "form-filling" fragment: a
// generic name recorded by an earlier RecordToolSchemas call in the SAME
// session, immediately followed by an assignment connector and a
// credential/file-path-shaped value. Both halves are required — a generic
// name alone (common in benign schemas) and a credential-shaped string alone
// (common in ordinary security tooling output) are each unremarkable; the
// compound is the signal, and it is the reason this returns nothing when
// called without a prior RecordToolSchemas in the same session (see
// TestGhostSplice_SingleMessageInsufficient).
func (t *GhostSpliceTracker) Scan(items []ContentItem) []ResponsePoisonFinding {
	if t == nil {
		return nil
	}
	names := t.snapshotNames()
	if len(names) == 0 {
		return nil
	}

	var findings []ResponsePoisonFinding
	fired := make(map[string]bool)
	for _, item := range items {
		if item.Type != "text" || item.Text == "" {
			continue
		}
		lower := strings.ToLower(item.Text)
		for _, name := range names {
			if fired[name] {
				continue
			}
			searchFrom := 0
			for searchFrom < len(lower) {
				rel := strings.Index(lower[searchFrom:], name)
				if rel < 0 {
					break
				}
				pos := searchFrom + rel
				afterName := pos + len(name)
				searchFrom = afterName
				if afterName >= len(item.Text) {
					break
				}
				tail := item.Text[afterName:]
				loc := ghostSpliceAssignRe.FindStringIndex(tail)
				if loc == nil {
					continue
				}
				windowEnd := loc[1] + ghostSpliceWindowBytes
				if windowEnd > len(tail) {
					windowEnd = len(tail)
				}
				window := strings.ToLower(tail[loc[1]:windowEnd])
				if !argsReferenceSecret(window) {
					continue
				}
				fired[name] = true
				findings = append(findings, ResponsePoisonFinding{
					Signal: SignalResponseFragmentInjection,
					Detail: fmt.Sprintf("tool result maps generic parameter %q (registered with no semantic meaning by an earlier tools/list response this session) to a credential/file-path-shaped value — cross-channel instruction fragmentation (GhostSplice)", name),
					Snippet: safeSnippet(item.Text, pos, 100),
				})
				break
			}
		}
	}
	return findings
}
