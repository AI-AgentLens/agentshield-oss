package mcp

import (
	"fmt"
	"sync"
)

// stagedTrustWindowCalls is the number of tool-call responses that establish
// a session's "clean" baseline before defection checks begin. TrustShiftProbe
// (arXiv 2608.23763) measures effective attacks staging over a handful of
// turns, so this stays low — a signal that waits too long to arm would miss
// the window real attacks exploit.
const stagedTrustWindowCalls = 3

// StagedTrustTracker detects the observable proxy for a "TrustShift" staged
// trust attack (arXiv 2608.23763, "TrustShiftProbe: Characterizing,
// Benchmarking, and Defending Staged Trust Attacks on MCP Servers"): a
// compromised MCP server behaves benignly during an initial conditioning
// phase — building operational reliance and suppressing agent skepticism —
// then switches to an adversarial payload once an interaction threshold is
// reached. The paper's own point is that the evasion is temporal, not
// syntactic: the switched payload can be schema-valid and carry no
// injection-shaped language, so it is invisible to both pre-deployment
// static analysis and to a content-pattern scanner that judges each response
// in isolation. The paper's defense (SHIELD) audits payloads against a
// behavioral baseline learned during a clean trust window; this is a
// session-scoped slice of that idea.
//
// V1 scope is deliberately narrow along two axes:
//
//  1. Tool-name-agnostic. FilterToolCallResponse's transport leg carries no
//     request/response tool-name correlation today (see ghostsplice.go's doc
//     comment — the audit entry this same handler builds already records
//     ToolName: "unknown" for the identical reason), so — like
//     GhostSpliceTracker — this baselines "this session" rather than "this
//     tool". A true per-tool baseline is future work once that correlation
//     exists.
//  2. Content-item KIND, not value. The baseline dimension is text vs.
//     embedded-resource content (MCP content-item types "resource" and
//     "resource_link"), not response field values or domains. Kind is the one
//     structural property stable across almost every simple tool — a
//     status/list/read-style tool returns type:"text" on every call — and a
//     genuine capability/scope change when it first appears: an embedded
//     resource carries a URI the agent will fetch or trust. Value-level
//     baselining (specific domains, field sets) is NOT attempted here: those
//     vary legitimately per call for search/fetch-style tools and would cost
//     precision without the tool identity this transport leg cannot yet
//     provide.
//
// Session-scoped: one tracker per MessageHandler, mirroring every other
// cross-call tracker in this package. In stdio-proxy mode (one agent = one
// session) this is exact; in shared HTTP-proxy mode it aggregates across
// clients until keyed by Mcp-Session-Id, the same documented tradeoff
// MCPCallHistoryTracker and GhostSpliceTracker carry.
type StagedTrustTracker struct {
	mu                sync.Mutex
	responsesObserved int
	seenResourceKind  bool
}

// NewStagedTrustTracker returns an initialized, empty tracker.
func NewStagedTrustTracker() *StagedTrustTracker {
	return &StagedTrustTracker{}
}

// Observe records one tool-call response's content-item kinds and returns a
// finding when embedded-resource content (type "resource" or "resource_link")
// appears for the FIRST time in the session, but only once
// stagedTrustWindowCalls prior responses have already been observed without
// one. That ordering is the entire signal: a session that opens WITH resource
// content (a legitimate document-serving tool) is never flagged — only an
// onset that arrives after an established text-only run is, which is the
// "clean, then defect" temporal shape TrustShift describes rather than an
// ordinary property of the tool.
func (t *StagedTrustTracker) Observe(items []ContentItem) []ResponsePoisonFinding {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	pastWindow := t.responsesObserved >= stagedTrustWindowCalls
	priorResponses := t.responsesObserved
	t.responsesObserved++

	var uri string
	found := false
	for _, item := range items {
		if item.Type != "resource" && item.Type != "resource_link" {
			continue
		}
		found = true
		uri = item.URI
		if uri == "" && item.Resource != nil {
			uri = item.Resource.URI
		}
		break
	}
	if !found {
		return nil
	}

	alreadySeen := t.seenResourceKind
	t.seenResourceKind = true
	if alreadySeen || !pastWindow {
		return nil
	}

	detail := fmt.Sprintf(
		"tool response introduced embedded-resource content (%s) for the first time after %d prior text-only responses this session — staged trust defection pattern (TrustShift, arXiv 2608.23763): a server that behaved consistently, then switched to a new content channel once trust was established",
		safeStagedTrustURI(uri), priorResponses,
	)
	return []ResponsePoisonFinding{{
		Signal: SignalResponseStagedTrustDefection,
		Detail: detail,
	}}
}

// safeStagedTrustURI renders the offending resource URI for the finding
// detail, falling back to a neutral placeholder when the server omitted one
// (malformed but still structurally a resource content item).
func safeStagedTrustURI(uri string) string {
	if uri == "" {
		return "no URI given"
	}
	return uri
}
