package mcp

import (
	"encoding/json"
	"fmt"
	"sort"
)

// SEP-2322 ("Multi Round-Trip Requests", Final in the 2026-07-28 spec) lets a
// server answer tools/call, prompts/get, or resources/read with an in-band
// InputRequiredResult instead of completing the request:
//
//	{"result": {"resultType": "input_required",
//	            "inputRequests": {"<key>": {"method": "sampling/createMessage",
//	                                        "params": {...}}}}}
//
// This replaces the old pattern of sending sampling/createMessage or
// elicitation/create as a standalone, top-level, server-initiated JSON-RPC
// request — the pattern HandleSamplingCreateMessage and HandleElicitationCreate
// are built for. Both are dispatched off ClassifyMessage, which keys on the
// TOP-LEVEL msg.Method (parser.go). An embedded request's method never reaches
// msg.Method: the outer message is a tools/call *response* (msg.Method == "").
//
// DispatchServerResponse's shape discriminator has no case for `inputRequests`
// either, so an InputRequiredResult matches zero discriminators and falls to
// the "ambiguous, run everything" fallback chain — where none of the 12
// existing filters recognizes the shape, so every embedded sampling/elicitation
// request (including credential-harvesting schemas, unaligned-model hints, and
// stop-sequence suppression) is forwarded completely unscanned. This is not an
// attacker trick: it is the protocol-mandated pattern for stateless servers
// under the current Final spec.
//
// # Fix: reuse, don't reinvent
//
// Each inputRequests entry is a {method, params} pair with exactly the shape
// of the request that used to travel standalone. Wrapping it in a synthetic
// Message and calling the existing HandleSamplingCreateMessage /
// HandleElicitationCreate reuses their full detection surface — content scan,
// stop-sequence suppression, model-preference steering, credential/social-
// engineering scan, task-amplification accounting, and taxonomy citation via
// the mcp-sampling-request-abuse / mcp-elicitation-abuse sentinels — with zero
// duplicated logic. Same primitive, same threat mechanism, different wire
// encoding: no new taxonomy ref, no cross-repo dependency.
//
// A BLOCK-tier finding in ANY embedded request replaces the entire outer
// response with that request's own block response (most_restrictive_wins,
// and consistent with how a top-level BLOCK behaves today — the outer result
// can never be trusted to stand alone once one of its required inputs is
// adversarial). AUDIT-tier findings are already logged by the reused handlers'
// own OnAudit calls; the response then forwards unchanged, matching today's
// top-level AUDIT-only behavior.

// embeddedServerRequest is the wire shape of one InputRequiredResult.inputRequests entry.
type embeddedServerRequest struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// scannedEmbeddedMethods is the set of embedded request methods this filter
// dispatches to an existing handler. Any other method (e.g. a future
// extension's ServerRequest shape) is left unscanned rather than guessed at —
// same "only skip what we can prove is irrelevant" posture as
// DispatchServerResponse's own discriminator.
var scannedEmbeddedMethods = map[string]func(*MessageHandler, *Message) (bool, []byte){
	MethodSamplingCreateMessage: (*MessageHandler).HandleSamplingCreateMessage,
	MethodElicitationCreate:     (*MessageHandler).HandleElicitationCreate,
}

// FilterInputRequiredResponse checks whether a response is an InputRequiredResult
// (SEP-2322) and scans each entry of its inputRequests map with the same
// detection already applied when that entry's method arrives as a standalone
// top-level request. Returns a block response if any embedded request is
// BLOCK-tier, or nil to forward the response unchanged (including when only
// AUDIT-tier findings exist — those are already recorded).
func (h *MessageHandler) FilterInputRequiredResponse(data []byte) []byte {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil
	}
	if msg.Method != "" || msg.Result == nil || msg.Error != nil {
		return nil
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(msg.Result, &top); err != nil || len(top) == 0 {
		return nil
	}
	requestsRaw, ok := top["inputRequests"]
	if !ok || len(requestsRaw) == 0 {
		return nil
	}
	var requests map[string]embeddedServerRequest
	if err := json.Unmarshal(requestsRaw, &requests); err != nil || len(requests) == 0 {
		return nil
	}

	// Deterministic order: map iteration is randomized in Go, and this
	// filter's own tests (and any future audit-trail diffing) need a stable
	// "which entry blocked first" answer when more than one is adversarial.
	keys := make([]string, 0, len(requests))
	for k := range requests {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		req := requests[key]
		handle, scanned := scannedEmbeddedMethods[req.Method]
		if !scanned {
			continue
		}
		synthetic := &Message{JSONRPC: "2.0", ID: msg.ID, Method: req.Method, Params: req.Params}
		if blocked, blockResp := handle(h, synthetic); blocked {
			_, _ = fmt.Fprintf(h.Stderr,
				"[AgentShield MCP] BLOCKED embedded %s (inputRequests[%q], SEP-2322 multi-round-trip)\n",
				req.Method, key)
			return blockResp
		}
	}

	return nil
}
