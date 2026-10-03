package mcp

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// #4154: the HTTP proxy forwarded the client's Accept-Encoding upstream, which
// switched off transparent gzip decoding, so a compressing upstream's bytes
// reached every response scanner unreadable and went on to the client
// unscanned. Both reference SDKs send "gzip, deflate" by default, so this was
// the common case, not an adversarial one.
//
// The fixture is the existing one — fakeUpstreamMCP's tools/list carries
// poisoned_tool, which the proxy filters with one BLOCK record — wrapped by an
// upstream that re-emits the same response under a content coding, as plain
// JSON or as one SSE event. No new attack content. The cut-container and
// polyglot shapes come from the #4157 adversarial pass.
//
// The contract under test: the proxy scans every form of a body a client
// might read, forwards only a form it scanned, and blocks on a scanner hit
// whatever the label says. A body it cannot read in the declared form is
// forwarded with its headers and an AUDIT receipt — never silently.

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

func zlibBytes(b []byte) []byte {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

// rawDeflateBytes is a raw DEFLATE stream; final=false ends it with a sync
// flush instead of a final block, which is a stream cut before its end.
func rawDeflateBytes(b []byte, final bool) []byte {
	var buf bytes.Buffer
	zw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = zw.Write(b)
	if final {
		_ = zw.Close()
	} else {
		_ = zw.Flush()
	}
	return buf.Bytes()
}

// zlibHeaderRawBody is a body whose first two bytes are a valid zlib header
// (0x78 0x01) and which is also a valid raw DEFLATE stream of two stored
// blocks. Read as zlib it fails at once (bad stored-block lengths); read as
// raw it yields plain, space-padded to 257 bytes (JSON-legal whitespace).
// httpx reads it as raw after zlib fails; Node reads nothing.
func zlibHeaderRawBody(plain []byte) []byte {
	p := append([]byte(nil), plain...)
	for len(p) < 257 {
		p = append(p, ' ')
	}
	a, b := p[:257], p[257:]
	n := len(b)
	out := []byte{0x78, 0x01, 0x01, 0xfe, 0xfe}
	out = append(out, a...)
	out = append(out, 0x01, byte(n), byte(n>>8), byte(^n), byte(^n>>8))
	out = append(out, b...)
	return out
}

// encodedBody applies one transform to plain. "opaque" labels gzip bytes with
// a coding the proxy cannot decode: a body it cannot read in any form.
func encodedBody(t *testing.T, transform string, plain []byte) []byte {
	t.Helper()
	switch transform {
	case "":
		return plain
	case "gzip", "opaque":
		return gzipBytes(plain)
	case "gzip-multi-member":
		// Two members: the message, then "x". Node joins them; httpx reads
		// the first alone (#4157 pass 2, C1).
		return append(gzipBytes(plain), gzipBytes([]byte("x"))...)
	case "gzip-then-zlib":
		return zlibBytes(gzipBytes(plain))
	case "zlib-then-gzip":
		return gzipBytes(zlibBytes(plain))
	case "raw-then-gzip":
		return gzipBytes(rawDeflateBytes(plain, true))
	case "gzip-notrailer":
		g := gzipBytes(plain)
		return g[:len(g)-8]
	case "gzip-gzip":
		return gzipBytes(gzipBytes(plain))
	case "gzip-gzip-gzip":
		return gzipBytes(gzipBytes(gzipBytes(plain)))
	case "zlib-zlib-zlib":
		return zlibBytes(zlibBytes(zlibBytes(plain)))
	case "deflate-zlib":
		return zlibBytes(plain)
	case "deflate-zlib-noadler":
		z := zlibBytes(plain)
		return z[:len(z)-4]
	case "deflate-raw":
		return rawDeflateBytes(plain, true)
	case "deflate-raw-nofinal":
		return rawDeflateBytes(plain, false)
	case "deflate-polyglot":
		return zlibHeaderRawBody(plain)
	}
	t.Fatalf("unknown transform %q", transform)
	return nil
}

// upstreamSeen records what the re-encoding upstream received from the proxy
// and the exact bytes it sent back, under a lock because the handler runs on
// the server's goroutine.
type upstreamSeen struct {
	mu             sync.Mutex
	acceptEncoding string
	sent           []byte
}

func (s *upstreamSeen) record(acceptEncoding string, sent []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acceptEncoding = acceptEncoding
	s.sent = append([]byte(nil), sent...)
}

func (s *upstreamSeen) get() (string, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acceptEncoding, s.sent
}

// reencodingUpstream forwards each request to inner and re-emits inner's
// response under the given transform, as JSON or as a single SSE event, with
// one Content-Encoding header line per entry of ce.
func reencodingUpstream(t *testing.T, inner *httptest.Server, sse bool, transform string, ce []string, seen *upstreamSeen) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := http.NewRequest(http.MethodPost, inner.URL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		out, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if sse {
			out = []byte("event: message\ndata: " + string(out) + "\n\n")
			w.Header().Set("Content-Type", "text/event-stream")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		for _, v := range ce {
			w.Header().Add("Content-Encoding", v)
		}
		encoded := encodedBody(t, transform, out)
		seen.record(r.Header.Get("Accept-Encoding"), encoded)
		_, _ = w.Write(encoded)
	}))
}

// newEncodingTestProxy is newTestHTTPProxy with the schema-drift cache
// pointed at a temp dir, so these tests never write the developer's real
// ~/.agentshield/mcp-schema-cache.json (#4156 tracks the shared helper).
func newEncodingTestProxy(t *testing.T, upstreamURL string, audited *[]AuditEntry, mu *sync.Mutex) *HTTPProxy {
	t.Helper()
	return NewHTTPProxy(HTTPProxyConfig{
		UpstreamURL: upstreamURL,
		Evaluator:   NewPolicyEvaluator(testHTTPProxyPolicy()),
		OnAudit: func(e AuditEntry) {
			mu.Lock()
			defer mu.Unlock()
			*audited = append(*audited, e)
		},
		Stderr:              io.Discard,
		SchemaDriftCacheDir: t.TempDir(),
	})
}

// identityClient sees exactly the bytes and headers the proxy sent: it never
// adds an Accept-Encoding of its own and never decodes a response.
func identityClient() *http.Client {
	return &http.Client{Transport: &http.Transport{DisableCompression: true}}
}

// splitAudits separates the encoding receipts from the scanners' own records.
func splitAudits(mu *sync.Mutex, audited *[]AuditEntry) (receipts, scanner []AuditEntry) {
	mu.Lock()
	defer mu.Unlock()
	for _, a := range *audited {
		isReceipt := false
		for _, r := range a.TriggeredRules {
			if r == responseEncodingFailOpenRuleID {
				isReceipt = true
			}
		}
		if isReceipt {
			receipts = append(receipts, a)
		} else {
			scanner = append(scanner, a)
		}
	}
	return receipts, scanner
}

func postToolsList(t *testing.T, url, clientAE string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(`{"jsonrpc":"2.0","id":10,"method":"tools/list","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	if clientAE != "" {
		req.Header.Set("Accept-Encoding", clientAE)
	}
	resp, err := identityClient().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	raw, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("reading the relayed body: %v", err)
	}
	return resp, raw
}

func TestHTTPProxy_CompressedUpstreamResponsesAreScanned(t *testing.T) {
	inner := fakeUpstreamMCP()
	defer inner.Close()

	type row struct {
		name      string
		transform string
		ce        []string // Content-Encoding header lines; nil = none
		clientAE  string
		// opaque: the proxy can read the body in no form. It is relayed under
		// its headers with a receipt, byte-for-byte on the JSON path.
		opaque bool
		// blocked: a chain of more than maxContentCodings decodable codings.
		// Nothing of the body is relayed; JSON gets the parse-error reply,
		// SSE an empty stream; one BLOCK record.
		blocked bool
		// For readable rows: the Content-Encoding the client sees on each path
		// ("keep" = the declared value, "" = identity), and whether a receipt
		// accompanies the one scanner record.
		ceJSON, ceSSE           string
		receiptJSON, receiptSSE bool
	}
	ae := "gzip, deflate" // what both reference SDKs send
	rows := []row{
		{name: "identity-control", clientAE: ae},
		// The #4154 shape: on main this row delivers poisoned_tool with 0 audits.
		{name: "gzip-client-accept-encoding", transform: "gzip", ce: []string{"gzip"}, clientAE: ae},
		{name: "gzip-no-client-accept-encoding", transform: "gzip", ce: []string{"gzip"}},
		{name: "x-gzip-unsolicited", transform: "gzip", ce: []string{"x-gzip"}, clientAE: ae},
		{name: "deflate-zlib-unsolicited", transform: "deflate-zlib", ce: []string{"deflate"}, clientAE: ae},
		{name: "deflate-raw-unsolicited", transform: "deflate-raw", ce: []string{"deflate"}, clientAE: ae},
		{name: "gzip-gzip-chain-of-two", transform: "gzip-gzip", ce: []string{"gzip, gzip"}, clientAE: ae},
		// Mixed chains (#4157 pass 2, D04): the layers must be peeled in the
		// reverse of the order they were applied, or the body goes out raw.
		{name: "gzip-then-deflate-chain", transform: "gzip-then-zlib", ce: []string{"gzip, deflate"}, clientAE: ae},
		{name: "deflate-then-gzip-chain", transform: "zlib-then-gzip", ce: []string{"deflate, gzip"}, clientAE: ae},
		{name: "raw-deflate-then-gzip-chain", transform: "raw-then-gzip", ce: []string{"deflate, gzip"}, clientAE: ae},
		// Multi-member gzip (#4157 pass 2, C1): the members joined are not a
		// message; the first member alone is, and httpx reads exactly that.
		{name: "gzip-multi-member", transform: "gzip-multi-member", ce: []string{"gzip"}, clientAE: ae},
		{name: "gzip-multi-member-no-client-accept-encoding", transform: "gzip-multi-member", ce: []string{"gzip"}},
		{name: "x-gzip-multi-member", transform: "gzip-multi-member", ce: []string{"x-gzip"}, clientAE: ae},

		// Cut containers (#4157 review, C2): Go's decoders stop with an error
		// that the clients' decoders ignore, and the bytes already decoded are
		// the whole message. They are the body: filtered and relayed as
		// identity. The SSE path relays the scanned events and then records
		// the cut with a receipt.
		{name: "zlib-no-adler32", transform: "deflate-zlib-noadler", ce: []string{"deflate"}, clientAE: ae, receiptSSE: true},
		{name: "raw-deflate-no-final-block", transform: "deflate-raw-nofinal", ce: []string{"deflate"}, clientAE: ae, receiptSSE: true},
		{name: "x-gzip-no-trailer", transform: "gzip-notrailer", ce: []string{"x-gzip"}, clientAE: ae, receiptSSE: true},
		{name: "gzip-no-trailer", transform: "gzip-notrailer", ce: []string{"gzip"}, clientAE: ae, receiptSSE: true},
		// zlib fails on its first block; raw decodes cleanly, which is what
		// httpx reads. The raw form is forwarded; no receipt, nothing was cut.
		{name: "zlib-raw-polyglot", transform: "deflate-polyglot", ce: []string{"deflate"}, clientAE: ae},

		// Plaintext under a label the proxy cannot decode (C1, the round-1
		// regression): every client reads it as identity, so the raw bytes get
		// the scan main gave them. The label stays; the scanner's BLOCK is the
		// record, so there is no receipt.
		{name: "plaintext+none", ce: []string{"none"}, clientAE: ae, ceJSON: "keep", ceSSE: "keep"},
		{name: "plaintext+x-unknown", ce: []string{"x-unknown"}, clientAE: ae, ceJSON: "keep", ceSSE: "keep"},
		{name: "plaintext+br", ce: []string{"br"}, clientAE: ae, ceJSON: "keep", ceSSE: "keep"},
		{name: "plaintext+zstd", ce: []string{"zstd"}, clientAE: ae, ceJSON: "keep", ceSSE: "keep"},
		// Plaintext under a decodable label: the decoder fails on the first
		// bytes and the raw form is scanned. The SSE path had already dropped
		// the header before building the decoder (C4, mutant M22), so the
		// client receives the filtered plaintext as identity.
		{name: "plaintext+x-gzip", ce: []string{"x-gzip"}, clientAE: ae, ceJSON: "keep", ceSSE: ""},
		{name: "plaintext+gzip", ce: []string{"gzip"}, clientAE: ae, ceJSON: "keep", ceSSE: ""},

		// Bodies the proxy can read in no form.
		{name: "opaque+br", transform: "opaque", ce: []string{"br"}, clientAE: ae, opaque: true},
		{name: "opaque+x-unknown", transform: "opaque", ce: []string{"x-unknown"}, clientAE: ae, opaque: true},
		// More than maxContentCodings decodable codings is BLOCKed (Gary,
		// 2026-10-02): every SDK decodes a three-layer chain, no real server
		// sends one. Declared on one line or on one line per coding alike;
		// an unknown token in the chain is read as identity and not counted.
		{name: "gzip-gzip-gzip-over-cap", transform: "gzip-gzip-gzip", ce: []string{"gzip, gzip, gzip"}, clientAE: ae, blocked: true},
		{name: "gzip-gzip-gzip-over-cap-three-lines", transform: "gzip-gzip-gzip", ce: []string{"gzip", "gzip", "gzip"}, clientAE: ae, blocked: true},
		{name: "deflate-x3-over-cap", transform: "zlib-zlib-zlib", ce: []string{"deflate, deflate, deflate"}, clientAE: ae, blocked: true},
		{name: "deflate-x3-over-cap-three-lines", transform: "zlib-zlib-zlib", ce: []string{"deflate", "deflate", "deflate"}, clientAE: ae, blocked: true},
		{name: "gzip-gzip-gzip-over-cap-with-unknown", transform: "gzip-gzip-gzip", ce: []string{"gzip, x-unknown, gzip, gzip"}, clientAE: ae, blocked: true},
		{name: "gzip-gzip-over-cap-no-client-accept-encoding", transform: "gzip-gzip-gzip", ce: []string{"gzip, gzip, gzip"}, blocked: true},
		// Exactly two decodable codings still decode and filter, with an
		// unknown token between them read as identity.
		{name: "gzip-x-unknown-gzip-two-known", transform: "gzip-gzip", ce: []string{"gzip, x-unknown, gzip"}, clientAE: ae},

		// A token the proxy does not know is read as identity, as every client
		// reads it: the decodable layer around it is still decoded, scanned and
		// relayed as identity. Two header lines are one list.
		{name: "gzip-then-x-unknown", transform: "gzip", ce: []string{"gzip, x-unknown"}, clientAE: ae},
		{name: "x-unknown-then-gzip", transform: "gzip", ce: []string{"x-unknown, gzip"}, clientAE: ae},
		{name: "two-lines-deflate-then-br", transform: "deflate-zlib", ce: []string{"deflate", "br"}, clientAE: ae},
		{name: "two-lines-gzip-then-br", transform: "gzip", ce: []string{"gzip", "br"}, clientAE: ae},
		// Reading only the first line would decode one gzip layer, find no
		// message in the gzip bytes underneath, and relay them raw with a
		// receipt; reading the whole list decodes both (pins Header.Values).
		{name: "two-lines-gzip-gzip", transform: "gzip-gzip", ce: []string{"gzip", "gzip"}, clientAE: ae},
	}
	paths := []struct {
		name string
		sse  bool
	}{{"json", false}, {"sse", true}}

	for _, path := range paths {
		for _, tc := range rows {
			t.Run(path.name+"/"+tc.name, func(t *testing.T) {
				var seen upstreamSeen
				upstream := reencodingUpstream(t, inner, path.sse, tc.transform, tc.ce, &seen)
				defer upstream.Close()

				var audited []AuditEntry
				var mu sync.Mutex
				hp := newEncodingTestProxy(t, upstream.URL, &audited, &mu)
				ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
				defer ts.Close()

				resp, raw := postToolsList(t, ts.URL, tc.clientAE)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status %d", resp.StatusCode)
				}

				// The mechanism: whatever the client sent, the upstream saw the
				// proxy's own negotiation, never the client's header.
				upstreamAE, upstreamBody := seen.get()
				if upstreamAE != "gzip" {
					t.Errorf("upstream saw Accept-Encoding %q; the proxy must negotiate for itself (want %q)", upstreamAE, "gzip")
				}
				if resp.ContentLength >= 0 && resp.ContentLength != int64(len(raw)) {
					t.Errorf("stale Content-Length %d for a %d-byte body", resp.ContentLength, len(raw))
				}

				clientCE := strings.Join(resp.Header.Values("Content-Encoding"), ",")
				declared := strings.Join(tc.ce, ",")
				receipts, scanned := splitAudits(&mu, &audited)

				if tc.blocked {
					if clientCE != "" {
						t.Errorf("client Content-Encoding = %q for a blocked response", clientCE)
					}
					if bytes.Contains(raw, []byte("poisoned_tool")) || bytes.Contains(raw, []byte("get_weather")) || bytes.HasPrefix(raw, []byte{0x1f, 0x8b}) || bytes.HasPrefix(raw, []byte{0x78}) {
						t.Errorf("body content relayed for a blocked chain: %.80q", raw)
					}
					if path.sse {
						if len(raw) != 0 {
							t.Errorf("SSE relayed %d bytes for a blocked chain: %.80q", len(raw), raw)
						}
					} else {
						assertParseErrorReply(t, string(raw))
						if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
							t.Errorf("Content-Type = %q", ct)
						}
					}
					if len(receipts) != 0 {
						t.Errorf("a fail-open receipt beside a BLOCK: %+v", receipts)
					}
					if len(scanned) != 1 {
						t.Fatalf("want exactly 1 BLOCK record, got %+v", scanned)
					}
					a := scanned[0]
					if a.Decision != "BLOCK" || len(a.TriggeredRules) != 1 || a.TriggeredRules[0] != responseEncodingChainExceededRuleID {
						t.Errorf("record = %s %v, want BLOCK %s", a.Decision, a.TriggeredRules, responseEncodingChainExceededRuleID)
					}
					if len(a.Reasons) != 1 || !strings.Contains(a.Reasons[0], `"`+declared+`"`) {
						t.Errorf("record must name the declared chain %q; reasons = %v", declared, a.Reasons)
					}
					if a.TaxonomyRef != securityMediatorParseFailOpenTaxonomyRef || a.Source != "mcp-proxy" || a.ToolName == "" {
						t.Errorf("record taxonomy/source/tool = %q/%q/%q", a.TaxonomyRef, a.Source, a.ToolName)
					}
					return
				}

				if tc.opaque {
					if clientCE != declared {
						t.Errorf("client Content-Encoding = %q, want the declared %q", clientCE, declared)
					}
					if !path.sse && !bytes.Equal(raw, upstreamBody) {
						t.Errorf("opaque JSON body was not relayed unchanged: got %d bytes, upstream sent %d", len(raw), len(upstreamBody))
					}
					if bytes.Contains(raw, []byte("poisoned_tool")) {
						t.Errorf("poisoned_tool readable in the relayed bytes")
					}
					if len(scanned) != 0 {
						t.Errorf("a scanner acted on bytes the proxy cannot read: %+v", scanned)
					}
					if len(receipts) != 1 {
						t.Fatalf("want exactly 1 receipt, got %d: %+v", len(receipts), receipts)
					}
					a := receipts[0]
					if a.Decision != "AUDIT" {
						t.Errorf("receipt decision = %q, want AUDIT (fail open with a record; BLOCK needs Gary's yes)", a.Decision)
					}
					if len(a.TriggeredRules) != 1 || a.TriggeredRules[0] != responseEncodingFailOpenRuleID {
						t.Errorf("receipt rules = %v", a.TriggeredRules)
					}
					if len(a.Reasons) != 1 || !strings.Contains(a.Reasons[0], `"`+declared+`"`) {
						t.Errorf("receipt must name the declared encoding %q; reasons = %v", declared, a.Reasons)
					}
					if a.TaxonomyRef != securityMediatorParseFailOpenTaxonomyRef || a.Source != "mcp-proxy" || a.ToolName == "" {
						t.Errorf("receipt taxonomy/source/tool = %q/%q/%q", a.TaxonomyRef, a.Source, a.ToolName)
					}
					return
				}

				// Readable: the proxy forwards exactly the form it scanned, so
				// the relayed bytes themselves must be the filtered message.
				if bytes.Contains(raw, []byte("poisoned_tool")) {
					t.Errorf("poisoned_tool was delivered to the client (Content-Encoding %q)", clientCE)
				}
				if !bytes.Contains(raw, []byte("get_weather")) {
					t.Errorf("get_weather missing from the relayed response: %q", raw)
				}
				wantCE, wantReceipt := tc.ceJSON, tc.receiptJSON
				if path.sse {
					wantCE, wantReceipt = tc.ceSSE, tc.receiptSSE
				}
				if wantCE == "keep" {
					wantCE = declared
				}
				if clientCE != wantCE {
					t.Errorf("client Content-Encoding = %q, want %q", clientCE, wantCE)
				}
				if len(scanned) != 1 || scanned[0].Decision != "BLOCK" {
					t.Errorf("want exactly 1 scanner record (the tools/list poisoning BLOCK), got %+v", scanned)
				}
				if got := len(receipts) == 1; got != wantReceipt || len(receipts) > 1 {
					t.Errorf("receipts = %d, want %v: %+v", len(receipts), wantReceipt, receipts)
				}
			})
		}
	}
}

// Plaintext labelled deflate: zlib fails on the header, raw deflate reads the
// JSON text as a Huffman stream and produces garbage or an error. No client
// reads anything from this shape; the proxy must deliver no poison either way.
func TestHTTPProxy_PlaintextUnderDeflateDeliversNoPoison(t *testing.T) {
	inner := fakeUpstreamMCP()
	defer inner.Close()
	for _, sse := range []bool{false, true} {
		var seen upstreamSeen
		upstream := reencodingUpstream(t, inner, sse, "", []string{"deflate"}, &seen)
		var audited []AuditEntry
		var mu sync.Mutex
		hp := newEncodingTestProxy(t, upstream.URL, &audited, &mu)
		ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
		resp, raw := postToolsList(t, ts.URL, "gzip, deflate")
		if resp.StatusCode != http.StatusOK {
			t.Errorf("sse=%v: status %d", sse, resp.StatusCode)
		}
		if bytes.Contains(raw, []byte("poisoned_tool")) {
			t.Errorf("sse=%v: poisoned_tool delivered: %q", sse, raw)
		}
		receipts, scanned := splitAudits(&mu, &audited)
		if len(scanned)+len(receipts) == 0 {
			t.Errorf("sse=%v: no record at all for a body relayed in a form the proxy could not read as declared", sse)
		}
		ts.Close()
		upstream.Close()
	}
}

// An empty body under a coding label is not a fail-open: nothing was relayed.
func TestHTTPProxy_EmptyLabelledBodyGetsNoReceipt(t *testing.T) {
	for _, ct := range []string{"application/json", "text/event-stream"} {
		for _, ce := range []string{"gzip", "x-gzip", "deflate", "br"} {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", ct)
				w.Header().Set("Content-Encoding", ce)
				w.Header().Set("Content-Length", "0")
				w.WriteHeader(http.StatusOK)
			}))
			var audited []AuditEntry
			var mu sync.Mutex
			hp := newEncodingTestProxy(t, upstream.URL, &audited, &mu)
			ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
			resp, raw := postToolsList(t, ts.URL, "gzip, deflate")
			if resp.StatusCode != http.StatusOK || len(raw) != 0 {
				t.Errorf("%s/%s: status %d, %d bytes", ct, ce, resp.StatusCode, len(raw))
			}
			mu.Lock()
			n := len(audited)
			mu.Unlock()
			if n != 0 {
				t.Errorf("%s/%s: %d audit records for an empty body", ct, ce, n)
			}
			ts.Close()
			upstream.Close()
		}
	}
}

// A decode error after events have gone out ends the relay: the events
// already relayed were scanned, the remainder is never read — not even a
// plaintext tail that a lenient client would have parsed — and a receipt
// records the cut (C4).
func TestHTTPProxy_SSEMidStreamDecodeErrorStopsAndRecords(t *testing.T) {
	event1 := []byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"status\":\"first\"}}\n\n")
	cases := []struct {
		name, ce string
		cut      []byte
	}{
		{"deflate", "deflate", zlibBytes(event1)[:len(zlibBytes(event1))-4]},
		{"x-gzip", "x-gzip", gzipBytes(event1)[:len(gzipBytes(event1))-8]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Content-Encoding", tc.ce)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(tc.cut)
				_, _ = io.WriteString(w, "event: message\ndata: RAW-UNSCANNED-TAIL\n\n")
			}))
			defer upstream.Close()
			var audited []AuditEntry
			var mu sync.Mutex
			hp := newEncodingTestProxy(t, upstream.URL, &audited, &mu)
			ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
			defer ts.Close()

			resp, raw := postToolsList(t, ts.URL, "gzip, deflate")
			if ce := resp.Header.Get("Content-Encoding"); ce != "" {
				t.Errorf("client Content-Encoding = %q for a decoded stream", ce)
			}
			if !bytes.Contains(raw, []byte(`"first"`)) {
				t.Errorf("the scanned first event was not relayed: %q", raw)
			}
			if bytes.Contains(raw, []byte("RAW-UNSCANNED-TAIL")) {
				t.Errorf("bytes after the decode error were relayed unscanned: %q", raw)
			}
			receipts, scanned := splitAudits(&mu, &audited)
			if len(scanned) != 0 || len(receipts) != 1 {
				t.Fatalf("want exactly 1 receipt and no scanner record, got receipts=%+v scanned=%+v", receipts, scanned)
			}
			if !strings.Contains(receipts[0].Reasons[0], "remainder not forwarded") {
				t.Errorf("receipt should say the remainder was not forwarded: %v", receipts[0].Reasons)
			}
		})
	}
}

// flushCloser is the common surface of the three standard-library compressors.
type flushCloser interface {
	io.Writer
	Flush() error
	Close() error
}

// readSSEEvent reads lines until the blank line that ends an event, or fails
// the test after the timeout.
func readSSEEvent(t *testing.T, br *bufio.Reader, timeout time.Duration) string {
	t.Helper()
	type result struct {
		event string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		var sb strings.Builder
		for {
			line, err := br.ReadString('\n')
			sb.WriteString(line)
			if err != nil {
				done <- result{sb.String(), err}
				return
			}
			if line == "\n" {
				done <- result{sb.String(), nil}
				return
			}
		}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("reading SSE event: %v (got %q)", r.err, r.event)
		}
		return r.event
	case <-time.After(timeout):
		t.Fatalf("no SSE event relayed within %s: the decoder is holding the stream instead of streaming it", timeout)
		return ""
	}
}

// The SSE decoders must stream. The upstream flushes event 1 through the
// compressor and then waits; the proxy has to relay event 1 before the
// upstream produces event 2. A read-all decoder would hold event 1 until the
// stream closed, and this test times out instead of seeing it.
func TestHTTPProxy_SSEDecodedStreamStaysIncremental(t *testing.T) {
	cases := []struct {
		name            string
		contentEncoding string
		newWriter       func(io.Writer) flushCloser
	}{
		{"gzip", "gzip", func(w io.Writer) flushCloser { return gzip.NewWriter(w) }},
		{"x-gzip", "x-gzip", func(w io.Writer) flushCloser { return gzip.NewWriter(w) }},
		{"deflate-zlib", "deflate", func(w io.Writer) flushCloser { return zlib.NewWriter(w) }},
		{"deflate-raw", "deflate", func(w io.Writer) flushCloser {
			fw, _ := flate.NewWriter(w, flate.DefaultCompression)
			return fw
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Content-Encoding", tc.contentEncoding)
				w.WriteHeader(http.StatusOK)
				f := w.(http.Flusher)
				zw := tc.newWriter(w)
				_, _ = io.WriteString(zw, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"status\":\"first\"}}\n\n")
				_ = zw.Flush()
				f.Flush()
				select {
				case <-release:
				case <-time.After(10 * time.Second):
				}
				_, _ = io.WriteString(zw, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"status\":\"second\"}}\n\n")
				_ = zw.Close()
				f.Flush()
			}))
			defer upstream.Close()

			var audited []AuditEntry
			var mu sync.Mutex
			hp := newEncodingTestProxy(t, upstream.URL, &audited, &mu)
			ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
			defer ts.Close()

			req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept-Encoding", "gzip, deflate")
			resp, err := identityClient().Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if ce := resp.Header.Get("Content-Encoding"); ce != "" {
				t.Fatalf("client got Content-Encoding %q for a decoded stream", ce)
			}

			br := bufio.NewReader(resp.Body)
			first := readSSEEvent(t, br, 5*time.Second)
			if !strings.Contains(first, `"first"`) {
				t.Fatalf("first relayed event = %q", first)
			}
			close(release)
			rest, err := io.ReadAll(br)
			if err != nil {
				t.Fatalf("reading the rest of the stream: %v", err)
			}
			if !strings.Contains(string(rest), `"second"`) {
				t.Fatalf("second event missing after release: %q", rest)
			}
			mu.Lock()
			n := len(audited)
			mu.Unlock()
			if n != 0 {
				t.Errorf("%d audit records for a clean stream", n)
			}
		})
	}
}

func TestContentCodings(t *testing.T) {
	cases := []struct {
		header    string
		want      []string
		decodable bool
	}{
		{"", nil, true},
		{"identity", nil, true},
		{"gzip", []string{"gzip"}, true},
		{" GZip , identity", []string{"gzip"}, true},
		{"x-gzip", []string{"x-gzip"}, true},
		{"deflate", []string{"deflate"}, true},
		{"deflate, gzip", []string{"deflate", "gzip"}, true},
		{"br", []string{"br"}, false},
		{"zstd", []string{"zstd"}, false},
		{"none", []string{"none"}, false},
		{"gzip, br", []string{"gzip", "br"}, false},
	}
	for _, tc := range cases {
		got := contentCodings(tc.header)
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("contentCodings(%q) = %v, want %v", tc.header, got, tc.want)
		}
		if d := decodableCodings(got); d != tc.decodable {
			t.Errorf("decodableCodings(%v) = %v, want %v", got, d, tc.decodable)
		}
	}
}

// The forms a body might decode to, in the order real clients try them, and
// the chain cap. Pinned label by label so a reordering or a dropped variant
// does not pass as a refactor.
func TestDecodersFor(t *testing.T) {
	cases := []struct {
		codings []string
		want    []string
	}{
		{nil, nil},
		{[]string{"gzip"}, []string{"gzip", "gzip-single"}},
		{[]string{"x-gzip"}, []string{"gzip", "gzip-single"}},
		{[]string{"deflate"}, []string{"zlib", "raw"}},
		{[]string{"deflate", "gzip"}, []string{"zlib,gzip", "zlib,gzip-single", "raw,gzip", "raw,gzip-single"}},
		{[]string{"gzip", "deflate"}, []string{"gzip,zlib", "gzip,raw", "gzip-single,zlib", "gzip-single,raw"}},
		{[]string{"deflate", "deflate"}, []string{"zlib,zlib", "zlib,raw", "raw,zlib", "raw,raw"}},
		{[]string{"gzip", "gzip", "gzip"}, nil}, // over maxContentCodings
		{[]string{"br"}, nil},
		{[]string{"x-unknown"}, nil},
		// Unknown tokens read as identity, as every client reads them.
		{[]string{"gzip", "br"}, []string{"gzip", "gzip-single"}},
		{[]string{"gzip", "x-unknown"}, []string{"gzip", "gzip-single"}},
		{[]string{"x-unknown", "gzip"}, []string{"gzip", "gzip-single"}},
		{[]string{"br", "deflate"}, []string{"zlib", "raw"}},
		{[]string{"gzip", "x-unknown", "gzip"}, []string{"gzip,gzip", "gzip,gzip-single", "gzip-single,gzip", "gzip-single,gzip-single"}},
		{[]string{"gzip", "x-unknown", "gzip", "gzip"}, nil}, // three known codings
	}
	for _, tc := range cases {
		var got []string
		for _, d := range decodersFor(tc.codings) {
			got = append(got, d.label)
			if d.single != strings.Contains(d.label, "gzip-single") {
				t.Errorf("decodersFor(%v): %q single=%v", tc.codings, d.label, d.single)
			}
		}
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("decodersFor(%v) = %v, want %v", tc.codings, got, tc.want)
		}
	}
	// The first variant of any list reads every layer the Node way, which is
	// the order relaySSE relies on to relay a whole multi-member stream.
	if d := decodersFor([]string{"gzip", "gzip"}); d[0].single {
		t.Errorf("first variant of gzip,gzip is %q", d[0].label)
	}
	if maxContentCodings != 2 {
		t.Errorf("maxContentCodings = %d; changing it is a decision, not a refactor", maxContentCodings)
	}
}

// The cut-container shapes: Go's decoder reports an error, but the bytes it
// had already produced are the whole message. decodeAttempt must call that
// usable, and a real cut (an empty or partial prefix) not.
func TestDecodeAttempt_CutContainersAreComplete(t *testing.T) {
	plain := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_weather"},{"name":"poisoned_tool","description":"x"}]}}`)
	cases := []struct {
		name, transform, coding string
		form                    int // index into decodersFor(coding)
	}{
		{"zlib-no-adler32", "deflate-zlib-noadler", "deflate", 0},
		{"raw-deflate-no-final-block", "deflate-raw-nofinal", "deflate", 1},
		{"x-gzip-no-trailer", "gzip-notrailer", "x-gzip", 0},
		{"gzip-no-trailer", "gzip-notrailer", "gzip", 0},
	}
	for _, tc := range cases {
		d := decodersFor([]string{tc.coding})[tc.form]
		a := d.decodeAll(encodedBody(t, tc.transform, plain))
		if a.err == nil {
			t.Errorf("%s: expected the decoder to report the cut", tc.name)
		}
		if !a.complete() {
			t.Errorf("%s: decoded %d/%d bytes with err=%v but complete=%v", tc.name, len(a.out), len(plain), a.err, a.complete())
		}
		if !bytes.Equal(bytes.TrimSpace(a.out), plain) {
			t.Errorf("%s: decoded bytes differ from the message", tc.name)
		}
	}

	t.Run("polyglot: zlib fails, raw is clean", func(t *testing.T) {
		body := encodedBody(t, "deflate-polyglot", plain)
		forms := decodersFor([]string{"deflate"})
		if z := forms[0].decodeAll(body); z.complete() {
			t.Errorf("zlib form of the polyglot should not be a message: err=%v out=%q", z.err, z.out)
		}
		r := forms[1].decodeAll(body)
		if r.err != nil || !bytes.Equal(bytes.TrimSpace(r.out), plain) {
			t.Errorf("raw form of the polyglot: err=%v out=%q", r.err, r.out)
		}
	})

	t.Run("a partial prefix is not a message", func(t *testing.T) {
		g := gzipBytes(plain)
		cut := g[:len(g)/2]
		a := decodersFor([]string{"gzip"})[0].decodeAll(cut)
		if a.err == nil || a.complete() {
			t.Errorf("half a gzip stream: err=%v complete=%v out=%q", a.err, a.complete(), a.out)
		}
	})

	t.Run("multi-member gzip: members joined are not a message, the first alone is", func(t *testing.T) {
		body := encodedBody(t, "gzip-multi-member", plain)
		forms := decodersFor([]string{"gzip"})
		joined := forms[0].decodeAll(body)
		if joined.err != nil || joined.complete() || !joined.multiMember || !bytes.HasPrefix(joined.out, plain) {
			t.Errorf("multistream form: err=%v complete=%v multiMember=%v out=%q", joined.err, joined.complete(), joined.multiMember, joined.out)
		}
		first := forms[1].decodeAll(body)
		if first.err != nil || !first.complete() || !bytes.Equal(first.out, plain) {
			t.Errorf("single-member form: err=%v complete=%v out=%q", first.err, first.complete(), first.out)
		}
		// A one-member stream reports no second member, which is what lets
		// relayJSON skip the single-member decode of every ordinary body.
		if one := forms[0].decodeAll(gzipBytes(plain)); one.multiMember || one.err != nil || !bytes.Equal(one.out, plain) {
			t.Errorf("one-member stream: err=%v multiMember=%v", one.err, one.multiMember)
		}
		// Trailing garbage after a member is the error gzip.Reader reports.
		if g := forms[0].decodeAll(append(gzipBytes(plain), []byte("GARBAGE!")...)); g.err == nil || !bytes.Equal(g.out, plain) {
			t.Errorf("trailing garbage: err=%v out=%q", g.err, g.out)
		}
	})

	t.Run("plaintext under a decodable label is not a message in that form", func(t *testing.T) {
		for _, d := range append(decodersFor([]string{"gzip"}), decodersFor([]string{"deflate"})...) {
			// Raw deflate reads JSON text as a Huffman stream and may even
			// finish without an error; what comes out is still not a message.
			if a := d.decodeAll(plain); a.complete() {
				t.Errorf("plaintext read as %s: err=%v out=%q", d.label, a.err, a.out)
			}
		}
	})
}
