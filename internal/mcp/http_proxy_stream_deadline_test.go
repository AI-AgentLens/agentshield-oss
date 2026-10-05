package mcp

import (
	"bufio"
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

const streamEvent = "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\",\"data\":\"hi\"}}\n\n"

// streamUpstream answers any request with an SSE stream; mode picks the shape.
// gz makes it gzip the stream (a compress-always upstream).
func streamUpstream(t *testing.T, mode string, gz bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		var out io.Writer = w
		var zw *gzip.Writer
		if gz {
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
		case "steady": // an event every 150ms for ~1s
			for i := 0; i < 7; i++ {
				_, _ = io.WriteString(out, streamEvent)
				flush()
				select {
				case <-time.After(150 * time.Millisecond):
				case <-r.Context().Done():
					return
				}
			}
		case "event-then-hold":
			_, _ = io.WriteString(out, streamEvent)
			flush()
			<-r.Context().Done()
		case "event-then-corrupt": // a real cut: the gzip stream turns to garbage
			_, _ = io.WriteString(out, streamEvent)
			flush()
			_, _ = io.WriteString(w, "\x00\x01garbage-not-deflate\xff\xfe")
			w.(http.Flusher).Flush()
		}
	}))
}

type streamRun struct {
	events  int
	elapsed time.Duration
	audited []AuditEntry
}

// runStream sends one request through a proxy whose deadlines are shortened,
// reads the client side to the end (or cancels after the first event when
// cancelAfterFirst), and returns what happened.
func runStream(t *testing.T, up *httptest.Server, method string, total, idle time.Duration, cancelAfterFirst bool) streamRun {
	t.Helper()
	var audited []AuditEntry
	var mu sync.Mutex
	hp := newTestHTTPProxy(t, up.URL, testHTTPProxyPolicy(), &audited, &mu)
	hp.relayTimeout, hp.streamIdleTimeout = total, idle
	done := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hp.handleMCP(w, r)
		close(done)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	}
	req, _ := http.NewRequestWithContext(ctx, method, ts.URL, body)
	req.Header.Set("Accept", "application/json, text/event-stream")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	start := time.Now()
	resp, err := (&http.Client{Transport: &http.Transport{DisableCompression: true}}).Do(req)
	if err != nil {
		t.Fatalf("%s failed: %v", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out streamRun
	br := bufio.NewReader(resp.Body)
	for {
		line, err := br.ReadString('\n')
		if strings.HasPrefix(line, "data: ") {
			out.events++
			if cancelAfterFirst {
				cancel()
				break
			}
		}
		if err != nil {
			break
		}
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("proxy handler did not finish")
	}
	out.elapsed = time.Since(start)
	mu.Lock()
	out.audited = append(out.audited, audited...)
	mu.Unlock()
	return out
}

// A stream that keeps delivering outlives the overall bound: the 5-minute
// Client.Timeout / WriteTimeout cut every stream, active or not (#4181).
func TestHTTPProxy_ActiveSSEStreamOutlivesRelayTimeout_4181(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		t.Run(m, func(t *testing.T) {
			up := streamUpstream(t, "steady", false)
			defer up.Close()
			r := runStream(t, up, m, 400*time.Millisecond, 400*time.Millisecond, false)
			if r.events != 7 || r.elapsed < 900*time.Millisecond {
				t.Errorf("events=%d elapsed=%v, want all 7 events over >=900ms (total bound 400ms)", r.events, r.elapsed)
			}
			if len(r.audited) != 0 {
				t.Errorf("clean stream wrote receipts: %v", r.audited)
			}
		})
	}
}

// A silent stream is still cut, by the idle bound.
func TestHTTPProxy_SilentSSEStreamIsCutByIdleTimeout_4181(t *testing.T) {
	up := streamUpstream(t, "event-then-hold", false)
	defer up.Close()
	r := runStream(t, up, http.MethodGet, time.Minute, 300*time.Millisecond, false)
	if r.events != 1 || r.elapsed > 5*time.Second {
		t.Errorf("events=%d elapsed=%v, want the one event then a cut near 300ms", r.events, r.elapsed)
	}
}

// A gzip POST stream that ends by client hang-up or by the relay's own idle
// deadline lost nothing unscanned: no fail-open receipt. A gzip stream that
// turns to garbage is a real cut and still gets one (the control that proves
// the skip is not a blanket).
func TestHTTPProxy_GzipStreamEndsByContextWriteNoFalseReceipt_4181(t *testing.T) {
	for _, tc := range []struct {
		name, mode   string
		cancelFirst  bool
		wantReceipts int
	}{
		{"client-cancel", "event-then-hold", true, 0},
		{"idle-deadline", "event-then-hold", false, 0},
		{"corrupt-control", "event-then-corrupt", false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := streamUpstream(t, tc.mode, true)
			defer up.Close()
			r := runStream(t, up, http.MethodPost, time.Minute, 300*time.Millisecond, tc.cancelFirst)
			if r.events < 1 {
				t.Fatalf("no event delivered")
			}
			if len(r.audited) != tc.wantReceipts {
				t.Errorf("receipts=%d, want %d: %v", len(r.audited), tc.wantReceipts, r.audited)
			}
		})
	}
}

// A non-streaming relay stays bounded end to end by relayTimeout, whatever
// the stream idle bound is (#4185 item 2): raising streamIdleTimeout must not
// loosen the plain-JSON path. The upstream holds the response open, so only
// the overall bound can end the request.
func TestHTTPProxy_NonStreamingRelayStaysBoundedByRelayTimeout_4185(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done() // never answers
	}))
	defer up.Close()

	var audited []AuditEntry
	var mu sync.Mutex
	hp := newTestHTTPProxy(t, up.URL, testHTTPProxyPolicy(), &audited, &mu)
	hp.relayTimeout, hp.streamIdleTimeout = 300*time.Millisecond, time.Hour
	ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	start := time.Now()
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status=%d, want 502 from the relay bound", resp.StatusCode)
	}
	if e := time.Since(start); e > 5*time.Second {
		t.Errorf("elapsed=%v, want a cut near the 300ms relay bound, not the 1h idle bound", e)
	}
}

// A ResponseWriter with no Flusher sends relaySSE down the buffered relayJSON
// fallback, which must stay bounded by relayTimeout: idle() used to stop the
// overall timer first, leaving only the (here hour-long) idle bound (#4185
// item 3).
func TestHTTPProxy_NonFlusherSSEFallbackStaysBoundedByRelayTimeout_4185(t *testing.T) {
	up := streamUpstream(t, "event-then-hold", false)
	defer up.Close()
	defer up.CloseClientConnections() // a failing run must not hang Close on the held stream

	var audited []AuditEntry
	var mu sync.Mutex
	hp := newTestHTTPProxy(t, up.URL, testHTTPProxyPolicy(), &audited, &mu)
	hp.relayTimeout, hp.streamIdleTimeout = 300*time.Millisecond, time.Hour

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	var w http.ResponseWriter = struct{ http.ResponseWriter }{httptest.NewRecorder()} // hides Flusher
	if _, ok := w.(http.Flusher); ok {
		t.Fatal("test writer must not be a Flusher")
	}
	done := make(chan struct{})
	start := time.Now()
	go func() { hp.handleMCP(w, req); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("fallback relay still running after %v: only the idle bound applied", time.Since(start))
	}
}

// A real http.Server WriteTimeout is a whole-response deadline; only the
// per-write streamWriter.extend lets an active stream outlive it. httptest's
// default server has no WriteTimeout, so this one sets it (#4185 item 1).
func TestHTTPProxy_StreamOutlivesServerWriteTimeout_4185(t *testing.T) {
	up := streamUpstream(t, "steady", false)
	defer up.Close()
	var audited []AuditEntry
	var mu sync.Mutex
	hp := newTestHTTPProxy(t, up.URL, testHTTPProxyPolicy(), &audited, &mu)
	hp.relayTimeout, hp.streamIdleTimeout = time.Minute, 2*time.Second

	run := func() (events int, elapsed time.Duration) {
		ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hp.handleMCP(w, r)
		}))
		ts.Config.WriteTimeout = 400 * time.Millisecond
		ts.Start()
		defer ts.Close()
		req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
		req.Header.Set("Accept", "text/event-stream")
		start := time.Now()
		resp, err := (&http.Client{Transport: &http.Transport{DisableCompression: true}}).Do(req)
		if err != nil {
			t.Fatalf("GET failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		br := bufio.NewReader(resp.Body)
		for {
			line, err := br.ReadString('\n')
			if strings.HasPrefix(line, "data: ") {
				events++
			}
			if err != nil {
				break
			}
		}
		return events, time.Since(start)
	}

	events, elapsed := run()
	if events != 7 || elapsed < 900*time.Millisecond {
		t.Errorf("events=%d elapsed=%v, want all 7 events over >=900ms despite a 400ms WriteTimeout", events, elapsed)
	}
}
