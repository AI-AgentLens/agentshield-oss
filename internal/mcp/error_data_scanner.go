package mcp

import (
	"encoding/json"
	"strings"
)

// The JSON-RPC error object's OTHER prose field (#3908).
//
// # The surface
//
// A JSON-RPC 2.0 error object has three members, and two of them carry prose:
//
//	{"code": -32603, "message": "...", "data": <any JSON>}
//
// The spec is explicit about the division of labour. `message` "SHOULD be
// limited to a concise single sentence"; `data` is "a primitive or structured
// value that contains additional information about the error", and is where
// every real server puts the stack trace, the failing field, the retry hint —
// the detailed narrative. FilterErrorResponse scanned `message` and nothing
// else. `RPCError.Data` was parsed into the struct and read by no one, the
// same signal that found `isError`, `audience`, `priority` and `lastModified`
// before it.
//
// So the attacker's best channel here is also the most protocol-idiomatic
// one. Putting the payload in `data` is not an evasion the attacker has to
// invent — it is what the specification tells a well-behaved server to do
// with a long explanation, which is exactly why a defender scanning "the
// error message" never looks at it.
//
// # Measured before building (2026-09-19)
//
// Eight remediation-steering payloads, each phrased as a real error, through
// the full server→client filter stack:
//
//	                    result.isError   error.message   error.data
//	credential steer    BLOCK            BLOCK           clean
//	remote-exec steer   BLOCK            clean           clean
//	concealment         BLOCK            BLOCK           clean
//	TLS-disable steer   audit            clean           clean
//	exfil redirect      audit            BLOCK           clean
//	path substitution   BLOCK            BLOCK           clean
//	base64-exec steer   BLOCK            clean           clean
//	onward transfer     clean            clean           clean
//
// `error.data` is **0/8**. It is not a weaker channel than `error.message`,
// it is an absent one.
//
// # Two things had to change, not one
//
//  1. `data` is arbitrary JSON, so a payload nested one object deep is
//     invisible to any scan that treats the field as a string. Leaves are
//     walked at every depth — the same lesson schema_walk.go learned on the
//     inputSchema side, where five detectors were zeroed at once by a single
//     `allOf` wrapper.
//  2. The remediation-steering discriminator was wired to `result.isError`
//     ONLY, although its own header measures `error.message` and finds it
//     clean on 6 of 8. A JSON-RPC error IS the server asserting the call
//     failed — that is the whole meaning of the channel — so it is passed
//     with serverAssertedFailure=true. Applying a mitigation to every surface
//     it names is the same gap annotation_schema_coherence had when its
//     "nested-schema evasion pass" was wired to inputSchema and not
//     outputSchema.
//
// # A mention is not evidence on THIS surface
//
// The generic injection groups are not re-run verbatim on `data`.
// credentialHarvestPatterns is entirely mention-based -- its own descriptions
// read "References sensitive dotfile directory", "References API key/token"
// -- and it is calibrated for `message`, which the spec keeps to one concise
// sentence. `data` is where a server puts the failing path, the config key,
// the field name, so on this surface a mention is the NORMAL case:
//
//	"The credentials file ~/.aws/credentials could not be parsed: line 4 is
//	 malformed. Fix the profile block and retry."
//	"Provide your API key via the --api-key flag."
//
// Both are ordinary server errors and both fired. That is the same mistake
// response_indirect_directive_scanner.go's header records -- the description
// patterns flag 7 of 7 realistic benign responses, and the narrower response
// set is a correct calibration rather than an oversight -- arriving on a
// third surface. So on `data`, mention-based patterns require the leaf to
// ALSO read as an agent-directed instruction; directive-shaped groups run
// unconditionally.
//
// # A signal that was designed, measured, and DROPPED
//
// The intended headline signal here was message/data divergence: `message`
// is the field a host renders in a collapsed error row, `data` is the detail
// pane or nothing at all, and the model reads both -- so an instruction in
// `data` while `message` stays a summary looked like the human and the model
// being handed different documents.
//
// Its premise was that ordinary servers do not put instructions in `data`.
// The true-negative corpus assembled for this change falsified that outright:
//
//	"Integrate the remote changes before pushing. Run 'git pull --rebase'..."
//	"Run 'npm install' first, then re-run the build."
//
// A remediation hint in `data` under a summary `message` is the single
// commonest benign shape on this channel, not a rare one. The signal was
// removed rather than tuned, because nothing separated it from that base
// rate except the danger of the target -- which is what the remediation
// scanner already decides. Recording it here so the next person to notice
// the same asymmetry does not spend the same day on it: the asymmetry is
// real, its base rate is enormous, and any future attempt has to clear that
// before it is worth writing.
//
// # Deliberate non-goals
//
// Non-string leaves are not interpreted. A numeric or boolean leaf carries no
// prose, and guessing that a big integer is an encoded payload manufactures
// findings out of ordinary error codes — the same reasoning that keeps bare
// digit strings out of the lastModified epoch check in
// content_ranking_scanner.go.

// errorDataMaxLeaves bounds the walk. A server can nest arbitrarily deep; the
// scan must stay O(payload) and must not become a denial-of-service lever
// against the proxy itself.
const errorDataMaxLeaves = 512

// errorDataMaxDepth bounds recursion for the same reason.
const errorDataMaxDepth = 24

// RPCErrorProseFinding records one detection on a JSON-RPC error object.
type RPCErrorProseFinding struct {
	// Field is the JSON path the prose came from: "error.message", or
	// "error.data" followed by the key path ("error.data.detail.hint").
	Field  string `json:"field"`
	Signal string `json:"signal"`
	Detail string `json:"detail"`
}

// RPCErrorProseScanResult aggregates findings across an error object.
type RPCErrorProseScanResult struct {
	Found    bool                   `json:"found"`
	Findings []RPCErrorProseFinding `json:"findings,omitempty"`
}

// collectErrorDataProse walks an error.data value and returns its string
// leaves with their JSON paths, in document order.
func collectErrorDataProse(raw json.RawMessage) []RPCErrorProseFinding {
	if len(raw) == 0 {
		return nil
	}
	// decodeJSONValue decodes with UseNumber, so a valid-but-unrepresentable
	// number (1e400) beside the payload cannot fail the decode and take
	// every sibling string leaf with it (#4069, the same class #4059/#4067
	// closed on the notification and structuredContent surfaces). A syntax
	// error still returns nothing here: a `data` value that is not valid
	// JSON cannot have been parsed by the host either, so there is nothing
	// the model could read.
	v, ok := decodeJSONValue(raw)
	if !ok {
		return nil
	}
	var out []RPCErrorProseFinding
	walkErrorDataNode(&out, "error.data", v, 0)
	return out
}

func walkErrorDataNode(out *[]RPCErrorProseFinding, path string, v interface{}, depth int) {
	if len(*out) >= errorDataMaxLeaves || depth > errorDataMaxDepth {
		return
	}
	switch val := v.(type) {
	case string:
		if strings.TrimSpace(val) != "" {
			*out = append(*out, RPCErrorProseFinding{Field: path, Detail: val})
		}
	case map[string]interface{}:
		for k, child := range val {
			walkErrorDataNode(out, path+"."+k, child, depth+1)
		}
	case []interface{}:
		for _, item := range val {
			walkErrorDataNode(out, path+"[]", item, depth+1)
		}
	}
}

// ScanRPCErrorObject scans both prose surfaces of a JSON-RPC error object:
// `message`, and every string leaf of `data` at any depth.
//
// Two detections run over the collected prose:
//
//   - the generic injection groups (ScanErrorMessage), which `message`
//     already had and `data` did not;
//   - remediation steering (ScanToolResultErrorRemediation) with
//     serverAssertedFailure=true, which neither field had;
//   - nothing else. The divergence signal that was drafted for this
//     channel is documented above as dropped, with the corpus that killed it.
func ScanRPCErrorObject(message string, data json.RawMessage) RPCErrorProseScanResult {
	var result RPCErrorProseScanResult

	leaves := collectErrorDataProse(data)

	add := func(field, signal, detail string) {
		result.Findings = append(result.Findings, RPCErrorProseFinding{
			Field: field, Signal: signal, Detail: detail,
		})
	}

	// --- generic injection groups, per prose surface -------------------------
	if sig, detail := ScanErrorMessage(message); sig != "" {
		add("error.message", string(sig), detail)
	}
	for _, leaf := range leaves {
		if sig, detail := scanErrorDataLeaf(leaf.Detail); sig != "" {
			add(leaf.Field, string(sig), detail)
		}
	}

	// --- remediation steering ------------------------------------------------
	//
	// Each prose surface is scanned as its own content item rather than as one
	// concatenated blob. Joining them would let an instruction sentence in one
	// field borrow a dangerous target from another, which is the span-across-
	// boundaries shape #3255 rejected on the shell side.
	remItems := make([]ContentItem, 0, len(leaves)+1)
	fields := make([]string, 0, len(leaves)+1)
	if strings.TrimSpace(message) != "" {
		remItems = append(remItems, ContentItem{Type: "text", Text: message})
		fields = append(fields, "error.message")
	}
	for _, leaf := range leaves {
		remItems = append(remItems, ContentItem{Type: "text", Text: leaf.Detail})
		fields = append(fields, leaf.Field)
	}
	// serverAssertedFailure: a JSON-RPC error IS the server asserting the call
	// failed. That is not an inference about the text, it is what the envelope
	// means, so gate A of the remediation scanner is satisfied by construction
	// here exactly as isError satisfies it on the result path.
	if rem := ScanToolResultErrorRemediation(remItems, true); rem.Found {
		for _, f := range rem.Findings {
			field := "error"
			if f.ContentIndex >= 0 && f.ContentIndex < len(fields) {
				field = fields[f.ContentIndex]
			}
			add(field, string(f.Signal), f.Detail)
		}
	}

	result.Found = len(result.Findings) > 0
	return result
}

// scanErrorDataLeaf is the `data`-surface calibration of ScanErrorMessage.
//
// Directive-shaped groups run unconditionally: hidden instructions,
// exfiltration directives, stealth instructions and behavioural manipulation
// all describe something the text TELLS the reader to do, which structured
// failure detail never does.
func scanErrorDataLeaf(text string) (PoisonSignal, string) {
	if text == "" {
		return "", ""
	}
	forms := newProseForms(text)
	for _, p := range hiddenInstructionPatterns {
		if note, ok := proseMatchNote(p.re, forms); ok {
			return SignalHiddenInstructions, p.description + note
		}
	}
	for _, p := range exfiltrationPatterns {
		if note, ok := proseMatchNote(p.re, forms); ok {
			return SignalExfiltrationIntent, p.description + note
		}
	}
	for _, p := range stealthPatterns {
		if note, ok := proseMatchNote(p.re, forms); ok {
			return SignalStealthInstruction, p.description + note
		}
	}
	for _, p := range behavioralManipulationPatterns {
		if note, ok := proseMatchNote(p.re, forms); ok {
			return SignalBehavioralManipulation, p.description + note
		}
	}
	// credentialHarvestPatterns is deliberately absent, and gating it on "is
	// this an instruction" was tried and is not sufficient either:
	//
	//	"Provide your API key via the --api-key flag."
	//
	// is an instruction, is addressed to the reader, and is what a real auth
	// error says all day. Asking the caller to SUPPLY a credential is not
	// harvesting one. The distinction that works is already implemented, in
	// credentialOnwardTransferRE — a concrete on-disk artifact plus a verb
	// that moves its contents ONWARD — and ScanToolResultErrorRemediation
	// runs over these same leaves. A second, weaker credential test here
	// would only re-add the false-positive class that one was built to avoid.
	return "", ""
}
