package mcp

import (
	"bytes"
	"encoding/json"
)

// decodeResponseEnvelope is the one envelope decode every server->client
// response filter opens with (#4570).
//
// The filters used to call a strict json.Unmarshal(data, &msg) and return nil
// (forward unscanned) on any error. A *json.UnmarshalTypeError is a statement
// about OUR struct, not the document (wire_shape.go), so `"error":"x"` or
// `"method":5` beside a normal `result` switched off every scanner while a
// Python `mcp` client delivered the result. This decode is lenient in the same
// way ParseMessage is, and returns nil only for bytes that are not JSON.
//
// One thing a lenient decode does not give for free: encoding/json allocates
// the `*RPCError` before it finds the value does not fit, so a mistyped
// `error` leaves a non-nil zero Error that the filters read as "this is an
// error response" and skip. A client that delivers the result does not treat
// it as one, so the error is dropped unless it is an object whose `code` is a
// JSON number (the `-32603.0` spelling ParseMessage already tolerates, which
// stays an error response).
func decodeResponseEnvelope(data []byte) *Message {
	var msg Message
	strict := json.Unmarshal(data, &msg)
	if strict != nil {
		msg = Message{}
		if _, err := decodeLenient(data, &msg); err != nil {
			return nil
		}
	}
	// A strictly decodable envelope is exactly what main read before.
	if strict != nil && msg.Error != nil && !wellFormedErrorMember(data) {
		msg.Error = nil
	}
	return &msg
}

// wellFormedErrorMember reports whether the envelope's `error` member is an
// object whose `code` is a JSON number. Called only after a lenient decode, so
// the document is known to be JSON.
func wellFormedErrorMember(data []byte) bool {
	var top map[string]json.RawMessage
	if json.Unmarshal(data, &top) != nil {
		return false
	}
	raw, ok := top["error"]
	if !ok {
		return false
	}
	var errObj map[string]json.RawMessage
	if json.Unmarshal(raw, &errObj) != nil {
		return false
	}
	code, ok := errObj["code"]
	if !ok {
		return false
	}
	code = bytes.TrimSpace(code)
	if len(code) == 0 {
		return false
	}
	c := code[0]
	return c == '-' || (c >= '0' && c <= '9')
}
