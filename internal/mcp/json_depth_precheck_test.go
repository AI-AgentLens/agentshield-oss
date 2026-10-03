package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// TestJSONNestingLimitPinnedToEncodingJSON pins jsonMaxNestingDepth to the
// limit encoding/json actually enforces, at the boundary and in both
// directions. The BLOCK in parse_failure.go is justified by "no legitimate
// message comes near the decoder's limit"; if a Go release moves that limit,
// or stops reporting it as the SyntaxError this package documents, this test
// fails loudly instead of the decision drifting.
func TestJSONNestingLimitPinnedToEncodingJSON(t *testing.T) {
	atLimit := strings.Repeat("[", jsonMaxNestingDepth) + strings.Repeat("]", jsonMaxNestingDepth)
	var v any
	if err := json.Unmarshal([]byte(atLimit), &v); err != nil {
		t.Fatalf("encoding/json rejects %d nested arrays; jsonMaxNestingDepth is pinned too high: %v", jsonMaxNestingDepth, err)
	}
	if jsonNestingExceeds([]byte(atLimit), jsonMaxNestingDepth) {
		t.Fatalf("pre-check refuses %d nested arrays, which the decoder accepts", jsonMaxNestingDepth)
	}

	overLimit := "[" + atLimit + "]"
	err := json.Unmarshal([]byte(overLimit), &v)
	if err == nil {
		t.Fatalf("encoding/json accepts %d nested arrays; raise jsonMaxNestingDepth deliberately, with the justification re-read", jsonMaxNestingDepth+1)
	}
	var syntaxErr *json.SyntaxError
	if !errors.As(err, &syntaxErr) || !strings.Contains(err.Error(), "exceeded max depth") {
		t.Fatalf("the depth failure is no longer the SyntaxError parse_failure.go documents; re-read its file comment: %v", err)
	}
	if !jsonNestingExceeds([]byte(overLimit), jsonMaxNestingDepth) {
		t.Fatalf("pre-check accepts %d nested arrays, which the decoder refuses", jsonMaxNestingDepth+1)
	}
}

func TestJSONNestingExceeds(t *testing.T) {
	deep := strings.Repeat("[", jsonMaxNestingDepth+1)
	cases := []struct {
		name string
		data string
		want bool
	}{
		{"short payload cannot exceed", "[[[[", false},
		{"brackets inside a string do not count", `{"a":"` + strings.Repeat("[", 2*jsonMaxNestingDepth) + `"}`, false},
		{"escaped quote keeps the string open", `{"a":"\"` + strings.Repeat("[", 2*jsonMaxNestingDepth) + `"}`, false},
		{"escaped backslash lets the quote close the string", `{"a":"\\"` + `,"x":` + deep, true},
		{"objects count like arrays", strings.Repeat(`{"a":`, jsonMaxNestingDepth+1), true},
		{"mixed containers count together", strings.Repeat(`{"a":[`, (jsonMaxNestingDepth/2)+1), true},
		{"stray closers do not underflow the count", "]]]]" + deep, true},
		{"closed containers free their depth", strings.Repeat("[]", jsonMaxNestingDepth+1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := jsonNestingExceeds([]byte(tc.data), jsonMaxNestingDepth); got != tc.want {
				t.Errorf("jsonNestingExceeds = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestJSONNestingExceeds_AgreesWithDecoderOnWellFormedInput is the second
// half of the pin: on well-formed JSON the pre-check and the decoder must
// reach the same verdict, including when the depth hides inside strings.
func TestJSONNestingExceeds_AgreesWithDecoderOnWellFormedInput(t *testing.T) {
	cases := map[string]string{
		"deep field in an envelope":   depthToolCall("get_weather", 10001),
		"field just under the limit":  depthToolCall("get_weather", 9990),
		"brackets quoted in a string": `{"a":"` + strings.Repeat("[", 2*jsonMaxNestingDepth) + `"}`,
		"escaped quotes then depth":   `{"a":"\\\"\\\\","x":` + strings.Repeat("[", jsonMaxNestingDepth) + strings.Repeat("]", jsonMaxNestingDepth) + `}`,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			var v any
			decoderRefuses := json.Unmarshal([]byte(data), &v) != nil
			if got := jsonNestingExceeds([]byte(data), jsonMaxNestingDepth); got != decoderRefuses {
				t.Errorf("pre-check = %v, decoder refuses = %v; they must agree on well-formed input", got, decoderRefuses)
			}
		})
	}
}

func TestScreenParseFailure(t *testing.T) {
	deep := []byte(depthToolCall("execute_command", 10001))
	parseErr := errors.New("invalid JSON-RPC message: exceeded max depth")

	t.Run("blocks without audit logging enabled", func(t *testing.T) {
		h := &MessageHandler{Stderr: io.Discard}
		blocked, reply := h.ScreenParseFailure(parseTransportStdio, parseDirClientToServer, deep, parseErr)
		if !blocked || reply == nil {
			t.Fatalf("the BLOCK must not depend on OnAudit: blocked=%v reply=%v", blocked, reply)
		}
		assertParseErrorReply(t, string(reply))
	})
	t.Run("whitespace-only payload is silent", func(t *testing.T) {
		sink := &auditSink{}
		h := &MessageHandler{Stderr: io.Discard, OnAudit: sink.fn}
		blocked, reply := h.ScreenParseFailure(parseTransportStdio, parseDirServerToClient, []byte(" \t\r"), errors.New("unexpected end of JSON input"))
		if blocked || reply != nil || len(sink.all()) != 0 {
			t.Fatalf("blank payload: blocked=%v reply=%v audits=%s", blocked, reply, auditSummary(sink.all()))
		}
	})
	t.Run("receipts carry transport and direction", func(t *testing.T) {
		sink := &auditSink{}
		h := &MessageHandler{Stderr: io.Discard, OnAudit: sink.fn, ServerName: "fs"}
		h.ScreenParseFailure(parseTransportHTTP, parseDirServerToClient, []byte(`{"jsonrpc":`), errors.New("unexpected end of JSON input"))
		h.ScreenParseFailure(parseTransportHTTP, parseDirClientToServer, deep, parseErr)
		audits := sink.all()
		if len(audits) != 2 {
			t.Fatalf("want 2 receipts, got %s", auditSummary(audits))
		}
		for _, e := range audits {
			if e.ToolName != unparseableMessageToolName || e.ServerName != "fs" || e.Source != "mcp-proxy" {
				t.Errorf("entry %+v: want ToolName %q, ServerName fs, Source mcp-proxy", e, unparseableMessageToolName)
			}
			if len(e.Reasons) != 1 || !strings.Contains(e.Reasons[0], parseTransportHTTP) {
				t.Errorf("Reasons %v must name the transport", e.Reasons)
			}
		}
		if !strings.Contains(audits[0].Reasons[0], parseDirServerToClient) || !strings.Contains(audits[1].Reasons[0], parseDirClientToServer) {
			t.Errorf("Reasons must name the direction: %v / %v", audits[0].Reasons, audits[1].Reasons)
		}
	})
}

func TestScreenRelayedPayload(t *testing.T) {
	t.Run("a parseable message is left alone", func(t *testing.T) {
		sink := &auditSink{}
		h := &MessageHandler{Stderr: io.Discard, OnAudit: sink.fn}
		blocked, reply := h.ScreenRelayedPayload(parseTransportHTTP, parseDirServerToClient, []byte(depthResponse(9990)))
		if blocked || reply != nil || len(sink.all()) != 0 {
			t.Fatalf("clean message: blocked=%v reply=%v audits=%s", blocked, reply, auditSummary(sink.all()))
		}
	})
	t.Run("a BOM-prefixed message keeps its receipt", func(t *testing.T) {
		// Go refuses the BOM; Response.json() in the TypeScript SDK strips
		// it. That is a parser differential, so it must be recorded.
		sink := &auditSink{}
		h := &MessageHandler{Stderr: io.Discard, OnAudit: sink.fn}
		blocked, _ := h.ScreenRelayedPayload(parseTransportHTTP, parseDirServerToClient, []byte("\xEF\xBB\xBF"+depthResponse(0)))
		if blocked {
			t.Fatal("a BOM is not depth; must fail open")
		}
		assertFailOpenReceipt(t, sink.all())
	})
}

func TestLooksLikeJSONRPCPayload(t *testing.T) {
	cases := map[string]bool{
		"":                           false,
		"   ":                        false,
		"{}":                         true,
		"  [{}]":                     true,
		"[]":                         true,
		"{\n  \"jsonrpc\": \"2.0\"":  true,
		"[\n  {\"jsonrpc\"":          true,
		"\xEF\xBB\xBF{\"a\":1}":      true,
		"\xEF\xBB\xBF  {}":           true,
		"[INFO] 3 tools registered":  false,
		"[1]":                        false,
		"{x}":                        false,
		"{":                          false,
		"[":                          false,
		"<html>":                     false,
		"/messages/?session_id=abc":  false,
		"ping":                       false,
		"\"a string\"":               false,
		"\x1f\x8b\x08\x00gzip bytes": false,
	}
	for data, want := range cases {
		if got := looksLikeJSONRPCPayload([]byte(data)); got != want {
			t.Errorf("looksLikeJSONRPCPayload(%q) = %v, want %v", data, got, want)
		}
	}
}

func TestNewParseErrorResponse_SpellsOutNullID(t *testing.T) {
	reply := newParseErrorResponse("Blocked by AgentShield: test")
	if !strings.Contains(string(reply), `"id":null`) {
		t.Fatalf("Message.ID is omitempty; the parse error must spell out id null, got %s", reply)
	}
	assertParseErrorReply(t, string(reply))
}

// ---- Round 2 (Opus pass 1 on #4161) ----

func TestLooksLikeJSONRPCPayload_BOMRun(t *testing.T) {
	b := "\xEF\xBB\xBF"
	cases := map[string]bool{
		b + b + "{}":            true,
		b + b + b + "[{}]":      true,
		b + b + "[INFO] ready":  false,
		b + " " + b + "\t{}":    true,
		"  " + b + b + "  {}":   true,
		b + b + "<html>":        false,
		b + b + "":              false,
		b + b + "DEBUG payload": false,
	}
	for data, want := range cases {
		if got := looksLikeJSONRPCPayload([]byte(data)); got != want {
			t.Errorf("looksLikeJSONRPCPayload(%q) = %v, want %v", data, got, want)
		}
	}
}

func TestScreenRelayed_DepthBlockIgnoresShapeGate(t *testing.T) {
	b := "\xEF\xBB\xBF"
	for _, prefix := range []string{b + b, b + b + b, "DEBUG payload=", "<html>"} {
		t.Run(fmt.Sprintf("prefix %q", prefix), func(t *testing.T) {
			sink := &auditSink{}
			h := &MessageHandler{Stderr: io.Discard, OnAudit: sink.fn}
			blocked, reply := h.ScreenRelayedPayload(parseTransportHTTP, parseDirServerToClient, []byte(prefix+depthResponse(10001)))
			if !blocked || reply == nil {
				t.Fatalf("depth past the limit must be blocked whatever the prefix: blocked=%v", blocked)
			}
			assertDepthBlockAudit(t, sink.all())
		})
	}
}

func TestScreenRelayedParseFailure_ReceiptGate(t *testing.T) {
	parseErr := errors.New("invalid character")
	t.Run("a line that is not shaped like a message leaves no receipt", func(t *testing.T) {
		for _, line := range []string{"Server running on stdio", "DEBUG handling tools/call id=1", "<html>", "/messages/?session_id=abc"} {
			sink := &auditSink{}
			h := &MessageHandler{Stderr: io.Discard, OnAudit: sink.fn}
			blocked, reply := h.ScreenRelayedParseFailure(parseTransportStdio, parseDirServerToClient, []byte(line), parseErr)
			if blocked || reply != nil || len(sink.all()) != 0 {
				t.Errorf("%q: blocked=%v reply=%v audits=%s", line, blocked, reply, auditSummary(sink.all()))
			}
		}
	})
	t.Run("a message-shaped line keeps its receipt, BOM run included", func(t *testing.T) {
		for _, line := range []string{`{"jsonrpc":"2.0","id":1,"result":`, "\xEF\xBB\xBF\xEF\xBB\xBF" + depthResponse(0), `[{"jsonrpc":`} {
			sink := &auditSink{}
			h := &MessageHandler{Stderr: io.Discard, OnAudit: sink.fn}
			blocked, _ := h.ScreenRelayedParseFailure(parseTransportStdio, parseDirServerToClient, []byte(line), parseErr)
			if blocked {
				t.Errorf("%q: not depth, must fail open", line)
			}
			assertFailOpenReceipt(t, sink.all())
		}
	})
	t.Run("the client-to-server receipt stays unconditional", func(t *testing.T) {
		sink := &auditSink{}
		h := &MessageHandler{Stderr: io.Discard, OnAudit: sink.fn}
		h.ScreenParseFailure(parseTransportStdio, parseDirClientToServer, []byte("not a message"), parseErr)
		assertFailOpenReceipt(t, sink.all())
	})
}
