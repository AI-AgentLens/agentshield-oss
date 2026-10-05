package mcp

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// #4175: a 2xx answer to the client's GET is the server-initiated SSE stream
// to the TS SDK whatever its Content-Type (1.29.0 and 1.30.0 check response.ok
// and nothing else before parsing the body as SSE), so proxyPassthrough relays
// every 2xx GET through relaySSE and the client receives it scanned, labelled
// text/event-stream. Non-2xx GET answers and other methods are relayed as they
// arrive, as before.

// getUpstream serves one fixed response to every request and records the
// Accept-Encoding header of the last request it saw, per method.
type getUpstream struct {
	*httptest.Server
	mu   sync.Mutex
	seen map[string]string // method → Accept-Encoding received ("" = absent)
}

// newGetUpstream answers every request with status, the given Content-Type
// lines (nil: no Content-Type header at all, net/http's sniffing suppressed),
// any extra headers, and body.
func newGetUpstream(t *testing.T, status int, cts []string, extra http.Header, body []byte) *getUpstream {
	t.Helper()
	u := &getUpstream{seen: map[string]string{}}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		u.mu.Lock()
		u.seen[r.Method] = r.Header.Get("Accept-Encoding")
		u.mu.Unlock()
		if len(cts) == 0 {
			w.Header()["Content-Type"] = nil
		}
		for _, ct := range cts {
			w.Header().Add("Content-Type", ct)
		}
		for k, vs := range extra {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	return u
}

func (u *getUpstream) acceptEncoding(method string) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.seen[method]
}

// sdkGETClient is a client that, like the SDKs' fetch and httpx, names its
// own codings — so Go's transport does not decode on its behalf and the test
// sees exactly what the proxy forwarded.
var sdkGETClient = &http.Client{}

// through sends one bodyless request of the given method through a fresh
// proxy in front of up, with the headers a real SDK sends on the GET stream,
// and returns the response, its body, and the audit entries the proxy wrote.
func through(t *testing.T, up *getUpstream, method string, client *http.Client, ownAcceptEncoding bool) (*http.Response, string, []AuditEntry) {
	t.Helper()
	var audited []AuditEntry
	var mu sync.Mutex
	hp := newTestHTTPProxy(t, up.URL, testHTTPProxyPolicy(), &audited, &mu)
	ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
	defer ts.Close()

	req, _ := http.NewRequest(method, ts.URL, nil)
	req.Header.Set("Accept", "text/event-stream")
	if ownAcceptEncoding {
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s failed: %v", method, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	return resp, string(body), append([]AuditEntry(nil), audited...)
}

func gzipped(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

func assertCanonicalSSELabel(t *testing.T, h http.Header) {
	t.Helper()
	if got := h.Values("Content-Type"); len(got) != 1 || got[0] != "text/event-stream" {
		t.Errorf("forwarded Content-Type = %q, want exactly [text/event-stream]", got)
	}
}

// Kai's probe from the issue body, now a gate: the SSE control and the three
// non-SSE labels all reach the client scanned (poisoned tool gone, benign tool
// kept) and labelled text/event-stream. On main the three non-SSE rows were
// copied verbatim.
func TestHTTPProxy_GETStreamScannedWhateverContentType_4175(t *testing.T) {
	doc := string(bomToolsListBody(t))
	for _, ct := range []string{"text/event-stream", "application/json", "text/plain", ""} {
		name := ct
		var lines []string
		if ct == "" {
			name = "no-content-type"
		} else {
			lines = []string{ct}
		}
		t.Run(name, func(t *testing.T) {
			up := newGetUpstream(t, http.StatusOK, lines, nil, []byte("data: "+doc+"\n\n"))
			defer up.Close()
			resp, body, _ := through(t, up, http.MethodGet, sdkGETClient, true)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			assertCanonicalSSELabel(t, resp.Header)
			if strings.Contains(body, "poisoned_tool") {
				t.Errorf("poisoned tool reached the client on the GET stream: %.200s", body)
			}
			if !strings.Contains(body, "get_weather") {
				t.Errorf("benign tool dropped from the GET stream: %.200s", body)
			}
		})
	}
}

// A non-2xx answer to the GET is relayed as it arrives — status, headers and
// body untouched — because the SDKs cancel or raise on it without reading the
// body (TS _startOrAuthSse: response.body?.cancel(); Python: raise_for_status).
func TestHTTPProxy_GETNon2xxIsRelayedAsItArrives_4175(t *testing.T) {
	doc := string(bomToolsListBody(t))
	for _, tc := range []struct {
		status int
		ct     string
		body   string
		extra  http.Header
	}{
		{http.StatusMethodNotAllowed, "text/plain", "data: " + doc + "\n\n", http.Header{"Allow": {"POST, DELETE"}}},
		{http.StatusUnauthorized, "application/json", `{"error":"unauthorized"}`, http.Header{"Www-Authenticate": {`Bearer realm="mcp"`}}},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			up := newGetUpstream(t, tc.status, []string{tc.ct}, tc.extra, []byte(tc.body))
			defer up.Close()
			resp, body, audited := through(t, up, http.MethodGet, sdkGETClient, true)
			if resp.StatusCode != tc.status {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			if got := resp.Header.Values("Content-Type"); len(got) != 1 || got[0] != tc.ct {
				t.Errorf("Content-Type = %q, want exactly [%s]", got, tc.ct)
			}
			for k, vs := range tc.extra {
				if got := resp.Header.Values(k); strings.Join(got, "|") != strings.Join(vs, "|") {
					t.Errorf("%s = %q, want %q", k, got, vs)
				}
			}
			if body != tc.body {
				t.Errorf("body changed in passthrough:\n got %q\nwant %q", body, tc.body)
			}
			if len(audited) != 0 {
				t.Errorf("passthrough wrote %d audit entries, want 0", len(audited))
			}
		})
	}
}

// DELETE (session termination) is unchanged: relayed as it arrives, no label,
// no scan, no Accept-Encoding of the proxy's own. No SDK reads a DELETE body
// as a message (TS terminateSession, streamableHttp.js:431-; Python
// terminate_session, streamable_http.py:695-707: status only).
func TestHTTPProxy_DELETEIsRelayedAsItArrives_4175(t *testing.T) {
	doc := string(bomToolsListBody(t))
	up := newGetUpstream(t, http.StatusOK, []string{"application/json"}, nil, []byte(doc))
	defer up.Close()
	resp, body, audited := through(t, up, http.MethodDelete, sdkGETClient, true)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Values("Content-Type"); len(got) != 1 || got[0] != "application/json" {
		t.Errorf("Content-Type = %q, want exactly [application/json]", got)
	}
	if body != doc {
		t.Errorf("DELETE body changed in passthrough: %.200s", body)
	}
	if len(audited) != 0 {
		t.Errorf("DELETE passthrough wrote %d audit entries, want 0", len(audited))
	}
	if got := up.acceptEncoding(http.MethodDelete); got != "" {
		t.Errorf("upstream saw Accept-Encoding %q on DELETE, want none", got)
	}
}

// The proxy sends no Accept-Encoding of its own on GET or DELETE, and the
// client's is never forwarded (copyHeaders, #4154): a compliant upstream
// sends the GET stream as identity, which ends without a receipt. The first
// cut of #4175 asked for gzip on GET as forwardPost does, and a benign
// upstream that compresses only on request then gzipped the stream, so every
// ordinary end of it wrote a false fail-open receipt (#4179 review); see
// TestHTTPProxy_GETStreamFromCompressOnRequestUpstreamEndsWithoutReceipt_4175.
func TestHTTPProxy_GETSendsNoAcceptEncodingOfItsOwn_4175(t *testing.T) {
	up := newGetUpstream(t, http.StatusOK, []string{"text/event-stream"}, nil, []byte(": hi\n\n"))
	defer up.Close()
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		through(t, up, method, sdkGETClient, true)
		if got := up.acceptEncoding(method); got != "" {
			t.Errorf("upstream saw Accept-Encoding %q on %s, want none (client sent \"gzip, deflate, br\")", got, method)
		}
	}
}

// compressOnRequestUpstream is a benign server behind a compression
// middleware: it gzips the GET stream only when the request asks for gzip,
// flushes each write, and ends the stream the way mode says.
func compressOnRequestUpstream(t *testing.T, mode string) *getUpstream {
	t.Helper()
	u := &getUpstream{seen: map[string]string{}}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.seen[r.Method] = r.Header.Get("Accept-Encoding")
		u.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		var out io.Writer = w
		var zw *gzip.Writer
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			zw = gzip.NewWriter(w)
			out = zw
		}
		w.WriteHeader(http.StatusOK)
		flush := func() {
			if zw != nil {
				_ = zw.Flush()
			}
			w.(http.Flusher).Flush()
		}
		switch mode {
		case "event-then-hold":
			_, _ = io.WriteString(out, "id: 1\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\",\"data\":\"hi\"}}\n\n")
			flush()
			<-r.Context().Done()
		case "comments-then-close":
			_, _ = io.WriteString(out, ": ping\n\n")
			flush()
			if zw != nil {
				_ = zw.Close()
			}
		case "comments-then-hold":
			_, _ = io.WriteString(out, ": ping\n\n")
			flush()
			<-r.Context().Done()
		}
	}))
	return u
}

// A long-lived GET stream from a benign upstream ends in ordinary ways — the
// client cancels after an event or after comments only, the upstream closes
// after comments only, the relay client times out — and none of them is a
// finding. With the proxy asking for gzip on GET (the first cut of #4175),
// a compress-on-request upstream gzipped the stream and every one of these
// endings wrote a false mcp-response-encoding-fail-open receipt (#4179 review,
// class (c): wrong evidence on the attestation path). With no Accept-Encoding
// of the proxy's own the stream is identity and ends silently, as on main.
func TestHTTPProxy_GETStreamFromCompressOnRequestUpstreamEndsWithoutReceipt_4175(t *testing.T) {
	for _, tc := range []struct {
		mode, end    string // end: "client-cancel", "upstream-close", "relay-timeout"
		relayTimeout time.Duration
		delivered    string // a line the client must have received before the end
	}{
		{"event-then-hold", "client-cancel", 0, "data: "},
		{"comments-then-close", "upstream-close", 0, ": ping"},
		{"comments-then-hold", "client-cancel", 0, ": ping"},
		{"event-then-hold", "relay-timeout", 500 * time.Millisecond, "data: "},
	} {
		t.Run(tc.mode+"/"+tc.end, func(t *testing.T) {
			up := compressOnRequestUpstream(t, tc.mode)
			defer up.Close()
			var audited []AuditEntry
			var mu sync.Mutex
			hp := newTestHTTPProxy(t, up.URL, testHTTPProxyPolicy(), &audited, &mu)
			if tc.relayTimeout > 0 {
				hp.streamIdleTimeout = tc.relayTimeout // the production 5-minute idle bound, shortened
			}
			handlerDone := make(chan struct{})
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hp.handleMCP(w, r)
				close(handlerDone)
			}))
			defer ts.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
			req.Header.Set("Accept", "text/event-stream")
			req.Header.Set("Accept-Encoding", "gzip, deflate")
			resp, err := (&http.Client{Transport: &http.Transport{DisableCompression: true}}).Do(req)
			if err != nil {
				t.Fatalf("GET failed: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			// The first complete SSE block (up to its blank line), or whatever
			// arrived before the stream ended.
			first := make(chan string, 1)
			go func() {
				br := bufio.NewReader(resp.Body)
				var sb strings.Builder
				for {
					line, err := br.ReadString('\n')
					sb.WriteString(line)
					if err != nil || (line == "\n" && sb.Len() > 1) {
						break
					}
				}
				first <- sb.String()
			}()
			var got string
			select {
			case got = <-first:
			case <-time.After(5 * time.Second):
				t.Fatal("no bytes from the GET stream within 5s")
			}
			if tc.end == "client-cancel" {
				cancel()
			}
			select {
			case <-handlerDone:
			case <-time.After(10 * time.Second):
				t.Fatal("proxy handler did not finish within 10s of the stream ending")
			}

			if ae := up.acceptEncoding(http.MethodGet); ae != "" {
				t.Errorf("upstream saw Accept-Encoding %q, want none", ae)
			}
			if ce := resp.Header.Get("Content-Encoding"); ce != "" {
				t.Errorf("stream forwarded under Content-Encoding %q, want identity", ce)
			}
			if !strings.Contains(got, tc.delivered) {
				t.Errorf("client did not receive %q before the end; got %q", tc.delivered, got)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(audited) != 0 {
				var rules []string
				for _, a := range audited {
					rules = append(rules, a.Decision+":"+strings.Join(a.TriggeredRules, "+")+" ("+strings.Join(a.Reasons, "; ")+")")
				}
				t.Errorf("a benign stream ending wrote %d receipt(s), want 0: %v", len(audited), rules)
			}
		})
	}
}

// An unsolicited gzip-coded 2xx GET body (the upstream gzips without being
// asked — the proxy sends no Accept-Encoding on GET) is decoded, scanned and
// relayed as identity, as POST bodies are since #4154 — under the SSE label
// (already so on main) and under a JSON label (on main: copied verbatim,
// still gzip, unscanned; fetch and httpx decode it and the TS SDK parses the
// events).
func TestHTTPProxy_GETStreamUnderGzipIsDecodedAndScanned_4175(t *testing.T) {
	doc := string(bomToolsListBody(t))
	for _, ct := range []string{"text/event-stream", "application/json"} {
		t.Run(ct, func(t *testing.T) {
			up := newGetUpstream(t, http.StatusOK, []string{ct}, http.Header{"Content-Encoding": {"gzip"}}, gzipped(t, []byte("data: "+doc+"\n\n")))
			defer up.Close()
			resp, body, _ := through(t, up, http.MethodGet, sdkGETClient, true)
			assertCanonicalSSELabel(t, resp.Header)
			if got := resp.Header.Get("Content-Encoding"); got != "" {
				t.Errorf("Content-Encoding = %q, want none (relayed as identity)", got)
			}
			if strings.Contains(body, "poisoned_tool") {
				t.Errorf("poisoned tool reached the client through the gzip GET stream: %.200s", body)
			}
			if !strings.Contains(body, "get_weather") {
				t.Errorf("benign tool not delivered in identity form: %.200s", body)
			}
		})
	}
}

// A coding the proxy cannot decode on a 2xx GET gets what it gets on POST
// (#4154): the raw bytes are line-scanned and relayed under their declared
// coding, labelled text/event-stream, with the fail-open receipt. On main the
// same response under a JSON label was copied verbatim with no receipt at all.
func TestHTTPProxy_GETStreamUnderUndecodableCodingGetsReceipt_4175(t *testing.T) {
	// Opaque bytes standing in for a br body; the proxy has no decoder for
	// them either way. Newline-terminated so the line relay round-trips them.
	opaque := []byte("\x0b\x02\x80opaque-coded-bytes\n")
	up := newGetUpstream(t, http.StatusOK, []string{"application/json"}, http.Header{"Content-Encoding": {"br"}}, opaque)
	defer up.Close()
	resp, body, audited := through(t, up, http.MethodGet, sdkGETClient, true)
	assertCanonicalSSELabel(t, resp.Header)
	if got := resp.Header.Get("Content-Encoding"); got != "br" {
		t.Errorf("Content-Encoding = %q, want br kept (the client decodes it, the proxy cannot)", got)
	}
	if body != string(opaque) {
		t.Errorf("undecodable body not relayed as it arrived: %q", body)
	}
	var receipts int
	for _, e := range audited {
		for _, r := range e.TriggeredRules {
			if r == responseEncodingFailOpenRuleID {
				receipts++
			}
		}
	}
	if receipts != 1 {
		t.Errorf("got %d %s receipts, want 1 (audit: %+v)", receipts, responseEncodingFailOpenRuleID, audited)
	}
}

// A non-2xx GET answer the upstream gzips unsolicited (the proxy sends no
// Accept-Encoding on GET) is relayed by passthrough coding and all, and a
// client that negotiated gzip for itself — fetch, httpx, and Go's transport
// when the request names no coding of its own — reads it decoded.
func TestHTTPProxy_GETNon2xxGzipBodyReachesClientReadably_4175(t *testing.T) {
	const text = "no stream here\n"
	up := newGetUpstream(t, http.StatusMethodNotAllowed, []string{"text/plain"}, http.Header{"Content-Encoding": {"gzip"}}, gzipped(t, []byte(text)))
	defer up.Close()

	// What the proxy forwards: the coding label and the coded bytes, intact.
	resp, raw, _ := through(t, up, http.MethodGet, sdkGETClient, true)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip forwarded with the body", got)
	}
	zr, err := gzip.NewReader(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("forwarded body is not the gzip the upstream sent: %v", err)
	}
	if dec, _ := io.ReadAll(zr); string(dec) != text {
		t.Errorf("forwarded body decodes to %q, want %q", dec, text)
	}

	// What a decoding client reads.
	resp, body, _ := through(t, up, http.MethodGet, http.DefaultClient, false)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
	if !resp.Uncompressed || body != text {
		t.Errorf("decoding client read %q (uncompressed=%v), want %q", body, resp.Uncompressed, text)
	}
}
