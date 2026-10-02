package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// A JSON *shape* error is an attacker-chosen off switch.
//
// # The defect
//
// Every extractor and every response filter in this package opens the same
// way: unmarshal the attacker-supplied bytes into a Go struct, and on error
// take the "this is not something I can read" path — `return nil, err`
// upstream of a `return false, nil // fail open`, or a bare `return nil` in a
// Filter*, which means the message is forwarded to the model unscanned.
//
// That treats an unmarshal error as evidence about the DOCUMENT. It is not.
// `encoding/json` reports an error for two entirely different situations:
//
//   - A *json.SyntaxError — the bytes are not JSON. Nothing downstream can
//     read them either, so nothing happens and failing open costs nothing.
//   - A *json.UnmarshalTypeError — the bytes are perfectly good JSON whose
//     VALUES do not fit the Go types we chose. The decoder has already
//     populated every other field; the peer's parser, which is not ours, will
//     read the document fine.
//
// Only the first is a statement about the input. The second is a statement
// about OUR struct, and conflating them hands an attacker a switch: pick any
// declared field, give it a value the Go type cannot hold, and the scan that
// would have blocked the message never runs.
//
// # Measured, before this file existed
//
// One `1e400` — a number `float64` cannot represent, valid JSON by RFC 8259,
// which places no bound on numeric magnitude — placed in a field nothing reads
// switched off 6 of 11 MCP surfaces that had a working control:
//
//	sampling/createMessage      BLOCK -> forwarded   (poison in modelPreferences)
//	tools/call                  BLOCK -> forwarded   (poison in an unused argument)
//	tools/call response         scanned -> forwarded (poison in content annotations)
//	prompts/get response        scanned -> forwarded
//	resources/list response     scanned -> forwarded
//	completion/complete response scanned -> forwarded
//
// The five that held did so by accident of typing, not by design: their
// attacker-reachable sub-documents happen to be `json.RawMessage`, which
// performs no numeric conversion. Nothing recorded the difference.
//
// This is the lesson the ElicitationSchema fail-open already taught in this
// package, at a level below the one it was learned at: never let
// attacker-chosen JSON shape decide whether we scan. There it was one struct;
// here it is the decode idiom every surface shares.
//
// # The fix, and why it cannot itself be turned into a bypass
//
// decodeLenient tolerates *json.UnmarshalTypeError and keeps the partially
// decoded value. `encoding/json` saves the first type error and CONTINUES
// decoding, so every field except the offending one arrives intact — verified
// by TestDecodeLenient_KeepsSiblingFields.
//
// The offending value itself is dropped (an `interface{}` holding it is left
// nil). That is not a hole, and the reason is worth stating: an attacker
// cannot both deliver a payload through a field and destroy that same field's
// decode with the same value. Poisoning field A to hide field B leaves B
// readable, which is the case this closes; poisoning B itself deletes the
// payload. There is no third option.
//
// The anomaly is returned rather than swallowed, because a well-formed
// document whose values contradict the protocol's own type declarations is
// itself worth a receipt — see auditWireShape.

// WireShapeSignal names a class of protocol-type violation.
type WireShapeSignal string

const (
	// SignalWireNumericOverflow is a JSON number outside the range the
	// protocol's declared numeric type can represent — `1e400` into a
	// `float64`, a 400-digit integer into an `int`. RFC 8259 permits the
	// literal; IEEE-754 cannot hold it.
	SignalWireNumericOverflow WireShapeSignal = "wire_numeric_overflow"

	// SignalWireTypeConfusion is a JSON value of the wrong KIND for the
	// field the protocol declares — an array where a string is specified,
	// an object where a number is.
	SignalWireTypeConfusion WireShapeSignal = "wire_type_confusion"
)

// WireShapeAnomaly records one tolerated protocol-type violation.
type WireShapeAnomaly struct {
	Signal WireShapeSignal `json:"signal"`
	// Field is the struct field the offending value landed on, as
	// encoding/json reports it ("arguments", "modelPreferences"). Empty when
	// the violation was at the top level of the decoded value.
	Field string `json:"field,omitempty"`
	// Value is encoding/json's description of the offending value
	// ("number 1e400", "array", "string").
	Value  string `json:"value,omitempty"`
	Detail string `json:"detail"`
}

// decodeLenient unmarshals data into v.
//
// A *json.UnmarshalTypeError is TOLERATED: v keeps every field that decoded,
// the returned error is nil, and the anomaly describes what was dropped. Any
// other error — syntax errors above all — is fatal and returned unchanged,
// because a document that is not JSON is a document no peer can act on.
//
// Callers must keep using the returned error for their "is this the message I
// handle" decision; the anomaly is purely additive.
func decodeLenient(data []byte, v any) (*WireShapeAnomaly, error) {
	err := json.Unmarshal(data, v)
	if err == nil {
		return nil, nil
	}

	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &typeErr) {
		return nil, err
	}
	// A nil anomaly here means "tolerated, and not worth a receipt" — see
	// anomalyFromTypeError. The decode is lenient either way.
	return anomalyFromTypeError(typeErr), nil
}

// anomalyFromTypeError classifies a *json.UnmarshalTypeError, and returns nil
// for the one class that is benign non-conformance rather than evidence.
//
// # The discriminator, and the trap in it
//
// encoding/json writes the offending literal into Value — `"number 1e400"` —
// whenever a numeric conversion fails, and the bare kind — `"number"`,
// `"string"`, `"array"` — for an ordinary kind mismatch. The first cut of this
// function read `HasPrefix(Value, "number ")` as "magnitude overflow". It is
// not: the same spelling is produced when a FRACTIONAL literal lands on an
// integer field, because that path also fails ParseInt.
//
// That mattered, and an adversarial review caught it. `json.dumps` renders
// every Python float with a trailing `.0`, so a Python MCP server computing
// `max_tokens` arithmetically sends `{"maxTokens": 2048.0}` on EVERY sampling
// request. The first cut reported that as a numeric overflow and asserted, in
// the audit line an operator reads, that "no conforming serializer produces
// [this] from a real value". Both halves were false, once per request.
//
// So the test is not the spelling, it is whether the literal is representable
// at all. A literal that round-trips through ParseFloat is a real number a real
// serializer emitted; one that does not is a value no float64 can hold and no
// serializer can produce from one.
//
// # Why the representable case returns NO anomaly
//
// The receipt exists to record "Shield could have been made to fail open here
// and declined". A Python float in an integer field is not that — it is a
// serializer being loose, at a rate of once per request, and an AUDIT line
// emitted that often is an AUDIT line nobody reads. Suppressing it costs
// nothing that matters: decodeLenient is still lenient, so the message is still
// SCANNED. Only the receipt is withheld, and only for the shape whose benign
// explanation is the overwhelmingly likely one.
//
// Kind mismatches (`"arguments": []`, `"content": {}`) keep their receipt: they
// are how four of the measured leak rows are reached, and no mainstream
// serializer emits an array where the protocol declares an object.
//
// Both Value spellings and the fractional case are pinned by
// TestAnomalyFromTypeError. Even if the stdlib wording drifted, the security
// behaviour (tolerate and scan) does not depend on the label.
func anomalyFromTypeError(typeErr *json.UnmarshalTypeError) *WireShapeAnomaly {
	where := "a protocol field"
	if typeErr.Field != "" {
		where = "protocol field `" + typeErr.Field + "`"
	}

	if literal, isNumber := strings.CutPrefix(typeErr.Value, "number "); isNumber {
		if _, err := strconv.ParseFloat(literal, 64); err == nil {
			// Representable — a real number a real serializer emitted, landing
			// on a field whose Go type is narrower. Benign non-conformance.
			return nil
		}
		return &WireShapeAnomaly{
			Signal: SignalWireNumericOverflow,
			Field:  typeErr.Field,
			Value:  typeErr.Value,
			Detail: fmt.Sprintf(
				"%s carries the JSON number %s, which no IEEE-754 double can represent. RFC 8259 places "+
					"no bound on a number literal, so this is well-formed JSON that no conforming serializer "+
					"produces from a real value — its only effect is to make a strict decode fail. The "+
					"message was decoded leniently and scanned anyway; this value was dropped",
				where, literal),
		}
	}

	return &WireShapeAnomaly{
		Signal: SignalWireTypeConfusion,
		Field:  typeErr.Field,
		Value:  typeErr.Value,
		Detail: fmt.Sprintf(
			"%s carries a JSON %s where the protocol declares %s. The message was decoded leniently and "+
				"scanned anyway; this value was dropped. Note that encoding/json reports only the FIRST "+
				"type error in a document, so a message may carry others this line does not name",
			where, typeErr.Value, typeErr.Type),
	}
}
