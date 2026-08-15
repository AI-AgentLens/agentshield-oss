package mcp

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

// newDispatchTestHandler builds a fresh MessageHandler with isolated state so
// that comparing the dispatch path against the legacy chain never leaks scanner
// state (schema-drift baselines, annotation cache, capability tracking) between
// the two calls.
func newDispatchTestHandler(t testing.TB) *MessageHandler {
	t.Helper()
	return NewProxy(ProxyConfig{
		Evaluator:           NewPolicyEvaluator(testProxyPolicy()),
		Stderr:              io.Discard,
		SchemaDriftCacheDir: t.TempDir(),
	}).handler
}

// representativeResponses covers one clean message of every server→client
// response shape the proxy scans, plus the edge cases (error, empty result,
// null result). Each must route through DispatchServerResponse identically to
// the legacy "run every filter" chain.
var representativeResponses = map[string]string{
	"tools/list":              `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_weather","description":"Get the weather","inputSchema":{"type":"object"}}]}}`,
	"tools/call":              `{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"sunny"}]}}`,
	"resources/read":          `{"jsonrpc":"2.0","id":3,"result":{"contents":[{"uri":"file:///a","text":"hello"}]}}`,
	"resources/list":          `{"jsonrpc":"2.0","id":4,"result":{"resources":[{"uri":"file:///a","name":"a"}]}}`,
	"resources/templatesList": `{"jsonrpc":"2.0","id":5,"result":{"resourceTemplates":[{"uriTemplate":"file:///{x}","name":"t"}]}}`,
	"prompts/get":             `{"jsonrpc":"2.0","id":6,"result":{"messages":[{"role":"user","content":{"type":"text","text":"hi"}}]}}`,
	"prompts/list":            `{"jsonrpc":"2.0","id":7,"result":{"prompts":[{"name":"p"}]}}`,
	"completion":              `{"jsonrpc":"2.0","id":8,"result":{"completion":{"values":["a"]}}}`,
	"initialize":              `{"jsonrpc":"2.0","id":9,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"s","version":"1"}}}`,
	"error":                   `{"jsonrpc":"2.0","id":10,"error":{"code":-32000,"message":"something failed"}}`,
	"emptyResult":             `{"jsonrpc":"2.0","id":11,"result":{}}`,
	"nullResult":              `{"jsonrpc":"2.0","id":12,"result":null}`,
}

// TestDispatchServerResponse_MatchesLegacyChain is the safety net for the
// parse-once dispatch optimization: for every response shape, the single-filter
// dispatch must produce byte-identical output to running the full ordered chain.
// If dispatch ever returned nil where the chain transformed/blocked (a silently
// skipped scan), this fails.
func TestDispatchServerResponse_MatchesLegacyChain(t *testing.T) {
	for name, raw := range representativeResponses {
		t.Run(name, func(t *testing.T) {
			data := []byte(raw)

			msg, _, err := ParseMessage(data)
			if err != nil {
				t.Fatalf("ParseMessage failed: %v", err)
			}

			dispatchOut := newDispatchTestHandler(t).DispatchServerResponse(msg, data)
			chainOut := newDispatchTestHandler(t).runResponseFilterChain(data)

			if !bytes.Equal(dispatchOut, chainOut) {
				t.Errorf("dispatch != legacy chain\n dispatch: %q\n chain:    %q", dispatchOut, chainOut)
			}
		})
	}
}

// TestDispatchServerResponse_OversizedToolCallBlocked proves the non-nil routing
// path: an oversized tools/call response must be routed to FilterToolCallResponse
// and blocked, exactly as the legacy chain would. This guards against the
// dispatcher silently skipping a scanner that should fire.
func TestDispatchServerResponse_OversizedToolCallBlocked(t *testing.T) {
	// Build a tools/call response larger than toolResponseBlockBytes (4MB).
	big := strings.Repeat("A", toolResponseBlockBytes+1024)
	data := []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":99,"result":{"content":[{"type":"text","text":%q}]}}`, big))

	msg, _, err := ParseMessage(data)
	if err != nil {
		t.Fatalf("ParseMessage failed: %v", err)
	}

	dispatchOut := newDispatchTestHandler(t).DispatchServerResponse(msg, data)
	chainOut := newDispatchTestHandler(t).runResponseFilterChain(data)

	if dispatchOut == nil {
		t.Fatal("expected oversized tools/call to be blocked (non-nil), got nil — scanner was skipped")
	}
	if !bytes.Equal(dispatchOut, chainOut) {
		t.Errorf("dispatch != legacy chain for oversized response\n dispatch: %q\n chain: %q", dispatchOut, chainOut)
	}
	if !bytes.Contains(dispatchOut, []byte("AgentShield")) {
		t.Errorf("expected AgentShield block response, got: %q", dispatchOut)
	}
}

// TestLockedWriter_ConcurrentWritesNoInterleave verifies the mutex-guarded
// writer used by both proxy directions (Proxy.Run / RunWithIO) serializes
// concurrent writes so JSON-RPC frames cannot interleave. Run with -race.
func TestLockedWriter_ConcurrentWritesNoInterleave(t *testing.T) {
	var buf bytes.Buffer
	lw := &lockedWriter{w: &buf}

	const goroutines = 16
	const perGoroutine = 200
	// Each goroutine writes a distinct fixed line; if writes interleave, lines
	// in the buffer will be corrupted.
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		line := []byte(fmt.Sprintf("LINE-%02d-payload-payload-payload\n", g))
		go func(l []byte) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				writeLineToWriter(lw, l[:len(l)-1]) // writeLineToWriter appends the newline
			}
		}(line)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != goroutines*perGoroutine {
		t.Fatalf("expected %d lines, got %d (writes interleaved/corrupted)", goroutines*perGoroutine, len(lines))
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "LINE-") || !strings.HasSuffix(l, "payload") {
			t.Fatalf("corrupted line detected: %q", l)
		}
	}
}

// benchResponse is a realistically-sized clean tools/call response (~64KB of
// text content) — the common case where the old "run every filter" path paid
// for ~10 redundant envelope parses.
func benchResponse() []byte {
	body := strings.Repeat("the quick brown fox jumps over the lazy dog. ", 1500) // ~64KB
	return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":%q}]}}`, body))
}

func BenchmarkDispatchServerResponse(b *testing.B) {
	h := newDispatchTestHandler(b)
	data := benchResponse()
	msg, _, err := ParseMessage(data)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.DispatchServerResponse(msg, data)
	}
}

func BenchmarkLegacyResponseChain(b *testing.B) {
	h := newDispatchTestHandler(b)
	data := benchResponse()
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.runResponseFilterChain(data)
	}
}
