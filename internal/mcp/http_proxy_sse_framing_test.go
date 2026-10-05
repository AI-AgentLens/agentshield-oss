package mcp

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// #4178, and the bare-CR row of #4070: relaySSE frames the upstream stream as
// the WHATWG EventSource algorithm and the client SDKs do — a line ends at
// CRLF, LF or a bare CR; one BOM at the start of the stream is not content —
// and forwards every line in its own framing (LF, no BOM), so every client
// parses the forwarded stream exactly as the proxy did.
//
// Before, bufio.ScanLines framed the stream: a bare-CR stream was one line
// that no "data:" check matched, and a BOM-led stream's first line was
// "\xEF\xBB\xBFdata: …", not a data line. Both were forwarded unscanned, and
// @modelcontextprotocol/sdk 1.29.0 and 1.30.0 delivered the poisoned tool
// from both (Python mcp 2.3.0 from the bare-CR one), on POST and on the GET
// stream, with no audit record.

// sseFramings wraps one event payload in every framing a spec client reads
// as the same event. The two controls are the framings main already read.
func sseFramings(doc string) []struct{ name, body string } {
	bom := string(utf8BOM)
	return []struct{ name, body string }{
		{"lf (control)", "data: " + doc + "\n\n"},
		{"crlf (control)", "data: " + doc + "\r\n\r\n"},
		{"bare-cr comment-first", ": c\rdata: " + doc + "\r\r: end\n"},
		{"bare-cr data-first", "data: " + doc + "\r\r: end\n"},
		{"bare-cr leading-blank", "\rdata: " + doc + "\r\r: end\n"},
		{"bare-cr event-field", "event: message\rdata: " + doc + "\r\r"},
		{"bom at stream start", bom + "data: " + doc + "\n\n"},
		{"bom then bare-cr", bom + ": c\rdata: " + doc + "\r\r"},
		{"bom then crlf", bom + "data: " + doc + "\r\n\r\n"},
	}
}

// canonicalSSE is the framing the proxy forwards: one leading BOM gone, every
// line ending an LF.
func canonicalSSE(body string) string {
	body = strings.TrimPrefix(body, string(utf8BOM))
	return strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\r", "\n")
}

// benignToolsListBody is bomToolsListBody without the poisoned tool: the
// positive control, which every framing must deliver intact.
func benignToolsListBody(t *testing.T) []byte {
	t.Helper()
	tools := ListToolsResult{Tools: []ToolDefinition{{Name: "get_weather", Description: "Get weather for a location"}}}
	result, _ := json.Marshal(tools)
	id := json.RawMessage("10")
	out, _ := json.Marshal(Message{JSONRPC: "2.0", ID: &id, Result: result})
	return out
}

// framingUpstream serves body as text/event-stream to any request, gzipped
// (unsolicited: the proxy sends no Accept-Encoding on GET) when gz is set.
func framingUpstream(t *testing.T, body string, gz bool) *httptest.Server {
	t.Helper()
	return chunkedFramingUpstream(t, []string{body}, gz)
}

// chunkedFramingUpstream is framingUpstream with the body written and
// flushed one chunk at a time, so the proxy reads it in those pieces (gzip
// is one member over the joined chunks, as a real server would send it).
func chunkedFramingUpstream(t *testing.T, chunks []string, gz bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		if gz {
			var b bytes.Buffer
			zw := gzip.NewWriter(&b)
			_, _ = zw.Write([]byte(strings.Join(chunks, "")))
			_ = zw.Close()
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(b.Bytes())
			return
		}
		for _, c := range chunks {
			_, _ = w.Write([]byte(c))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}))
}

// streamThrough sends a tools/list POST or a bare GET through a fresh proxy
// in front of up, as an SDK would (its own Accept-Encoding, never decoding),
// and returns the forwarded response and body.
func streamThrough(t *testing.T, up *httptest.Server, method string) (*http.Response, string) {
	t.Helper()
	var audited []AuditEntry
	var mu sync.Mutex
	hp := newTestHTTPProxy(t, up.URL, testHTTPProxyPolicy(), &audited, &mu)
	ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
	defer ts.Close()

	var req *http.Request
	if method == http.MethodPost {
		req, _ = http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(`{"jsonrpc":"2.0","id":10,"method":"tools/list","params":{}}`))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, _ = http.NewRequest(http.MethodGet, ts.URL, nil)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	resp, err := identityClient().Do(req)
	if err != nil {
		t.Fatalf("%s failed: %v", method, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(body)
}

// Every framing x {POST, GET} x {identity, gzip}: the poisoned tool never
// reaches the client, the benign one always does, and the forwarded stream
// is in the proxy's framing — no CR, and no BOM at the head since the one
// spec BOM is gone and the first line is a data line — which both SDK
// framings (the reader table's TS and Python mirrors) read as the scanned
// event.
func TestHTTPProxy_SSEStreamFramedPerSpec_4178(t *testing.T) {
	doc := string(bomToolsListBody(t))
	for _, f := range sseFramings(doc) {
		for _, method := range []string{http.MethodPost, http.MethodGet} {
			for _, gz := range []bool{false, true} {
				name := f.name + "/" + method
				if gz {
					name += "/gzip"
				}
				t.Run(name, func(t *testing.T) {
					up := framingUpstream(t, f.body, gz)
					defer up.Close()
					resp, body := streamThrough(t, up, method)
					if resp.StatusCode != http.StatusOK {
						t.Fatalf("status = %d", resp.StatusCode)
					}
					if got := resp.Header.Values("Content-Type"); len(got) != 1 || got[0] != "text/event-stream" {
						t.Errorf("Content-Type = %q, want exactly [text/event-stream]", got)
					}
					if ce := resp.Header.Get("Content-Encoding"); ce != "" {
						t.Errorf("Content-Encoding = %q, want none (decoded and relayed as identity)", ce)
					}
					if strings.Contains(body, "poisoned_tool") {
						t.Errorf("poisoned tool reached the client: %.200s", body)
					}
					if !strings.Contains(body, "get_weather") {
						t.Errorf("benign tool dropped: %.200s", body)
					}
					if strings.Contains(body, "\r") {
						t.Errorf("forwarded stream carries a CR: %q", body)
					}
					if strings.HasPrefix(body, string(utf8BOM)) {
						t.Errorf("forwarded stream starts with a BOM: %.40q", body)
					}
					for _, rd := range []struct {
						name string
						read func(string) string
					}{{"typescript", readSSEEventsTS}, {"python", readSSEEventsPy}} {
						delivered := rd.read(body)
						if strings.Contains(delivered, "poisoned_tool") {
							t.Errorf("%s framing delivers the poisoned tool: %.160s", rd.name, delivered)
						}
						if !strings.Contains(delivered, "get_weather") {
							t.Errorf("%s framing delivers nothing where the proxy relayed a scanned event: %.160s", rd.name, delivered)
						}
					}
				})
			}
		}
	}
}

// Positive control: a benign event in every framing is forwarded as exactly
// its canonical form — the same lines, LF-terminated, BOM gone — on POST and
// GET, identity and gzip. Nothing is dropped, reordered or duplicated by the
// reframing; in particular a CRLF never becomes a line plus an empty line.
func TestHTTPProxy_SSEBenignStreamForwardedCanonically_4178(t *testing.T) {
	doc := string(benignToolsListBody(t))
	for _, f := range sseFramings(doc) {
		for _, method := range []string{http.MethodPost, http.MethodGet} {
			for _, gz := range []bool{false, true} {
				name := f.name + "/" + method
				if gz {
					name += "/gzip"
				}
				t.Run(name, func(t *testing.T) {
					up := framingUpstream(t, f.body, gz)
					defer up.Close()
					_, body := streamThrough(t, up, method)
					if want := canonicalSSE(f.body); body != want {
						t.Errorf("forwarded = %q\nwant      = %q", body, want)
					}
				})
			}
		}
	}
}

// startsWithExactlyOneBOM is the head no forwarded stream may have: a client
// that strips a leading BOM would then read a first line the proxy did not.
func startsWithExactlyOneBOM(body string) bool {
	bom := string(utf8BOM)
	return strings.HasPrefix(body, bom) && !strings.HasPrefix(body, bom+bom)
}

// #4182 pass 1 (confirmed on real TS 1.29.0/1.30.0, which strip one leading
// BOM through TextDecoderStream): two upstream shapes left a forwarded
// stream whose first line began with a BOM the proxy had read as content —
// an upstream opening with two BOMs (the splitter strips exactly one, as the
// spec and every client do), and a first event the scanners suppressed whose
// non-data lines, forwarded as they came, began with a BOM. The client
// stripped that BOM and read a "data:" line the proxy never scanned as one.
// sseHeadGuard writes one more BOM ahead of such a head. So, for every shape
// here, on POST and GET, identity and gzip: the poisoned tool is delivered by
// neither SDK framing, the forwarded stream never begins with exactly one
// BOM, and the rows where a client used to read an unscanned line now read
// as the proxy did, which is nothing. The controls pin what stays delivered:
// a single BOM (stripped, the event is scanned and delivered), a BOM-led
// comment line ahead of a benign event (the guard fires, the event is still
// delivered), and a triple BOM (delivered by nobody on any tree).
func TestHTTPProxy_SSEHeadNeverStripsToAnUnscannedLine_4182(t *testing.T) {
	bom := string(utf8BOM)
	poisoned := string(bomToolsListBody(t))
	benign := string(benignToolsListBody(t))
	suppressed := string(suppressedNotification("evt4182"))         // "data: {…}\n"
	suppressedCRLF := strings.TrimSuffix(suppressed, "\n") + "\r\n" // the same line, CRLF-ended
	cases := []struct {
		name     string
		chunks   []string
		guarded  bool   // the forwarded head must carry the sacrificial BOM
		delivers string // "" = no spec framing delivers anything; else the tool both must deliver
	}{
		{"double bom, lf", []string{bom + bom + "data: " + poisoned + "\n\n"}, true, ""},
		{"double bom, crlf", []string{bom + bom + "data: " + poisoned + "\r\n\r\n"}, true, ""},
		{"double bom, bare cr", []string{bom + bom + "data: " + poisoned + "\r\r: end\n"}, true, ""},
		{"double bom split across reads", []string{bom, bom + "data: " + poisoned + "\n\n"}, true, ""},
		{"suppressed first event, then a bom-led data line in it, lf", []string{suppressed + bom + "data: " + poisoned + "\n\n"}, true, ""},
		{"suppressed first event, then a bom-led data line in it, crlf", []string{suppressedCRLF + bom + "data: " + poisoned + "\r\n\r\n"}, true, ""},
		{"suppressed first event, then a bom-led data line, in two reads", []string{suppressed, bom + "data: " + poisoned + "\n\n"}, true, ""},
		{"triple bom (control: nobody delivers, on any tree)", []string{bom + bom + bom + "data: " + poisoned + "\n\n"}, true, ""},
		{"single bom (control: the spec BOM, stripped and scanned)", []string{bom + "data: " + poisoned + "\n\n"}, false, "get_weather"},
		{"bom-led comment line ahead of a benign event (control)", []string{bom + bom + ": hello\ndata: " + benign + "\n\n"}, true, "get_weather"},
		{"suppressed first event, bom-led data line as the next event (control: mid-stream, no client strips it)", []string{suppressed + "\n" + bom + "data: " + poisoned + "\n\n"}, false, ""},
	}
	for _, tc := range cases {
		for _, method := range []string{http.MethodPost, http.MethodGet} {
			for _, gz := range []bool{false, true} {
				name := tc.name + "/" + method
				if gz {
					name += "/gzip"
				}
				t.Run(name, func(t *testing.T) {
					up := chunkedFramingUpstream(t, tc.chunks, gz)
					defer up.Close()
					resp, body := streamThrough(t, up, method)
					if resp.StatusCode != http.StatusOK {
						t.Fatalf("status = %d", resp.StatusCode)
					}
					if strings.Contains(body, "evt4182") {
						t.Errorf("suppressed notification reached the client: %.200s", body)
					}
					if strings.Contains(body, "\r") {
						t.Errorf("forwarded stream carries a CR: %q", body)
					}
					if startsWithExactlyOneBOM(body) {
						t.Errorf("forwarded stream starts with exactly one BOM, which a client strips: %.60q", body)
					}
					if got := strings.HasPrefix(body, bom+bom); got != tc.guarded {
						t.Errorf("head guard fired = %v, want %v: %.60q", got, tc.guarded, body)
					}
					for _, rd := range []struct {
						name string
						read func(string) string
					}{{"typescript", readSSEEventsTS}, {"python", readSSEEventsPy}} {
						delivered := rd.read(body)
						if strings.Contains(delivered, "poisoned_tool") {
							t.Errorf("%s framing delivers the poisoned tool: %.160s", rd.name, delivered)
						}
						if tc.delivers == "" && delivered != "" {
							t.Errorf("%s framing delivers an event the proxy did not read as one: %.160s", rd.name, delivered)
						}
						if tc.delivers != "" && !strings.Contains(delivered, tc.delivers) {
							t.Errorf("%s framing dropped the scanned event: %.160s", rd.name, delivered)
						}
					}
				})
			}
		}
	}
}

// A stream whose events are framed three different ways is one stream: each
// event is scanned on its own, and the poisoned one is rewritten while its
// neighbours pass untouched.
func TestHTTPProxy_SSEMixedFramingsInOneStream_4178(t *testing.T) {
	poisoned := string(bomToolsListBody(t))
	benign := string(benignToolsListBody(t))
	stream := string(utf8BOM) + "data: " + benign + "\r\n\r\n" + // CRLF
		": comment\rdata: " + poisoned + "\r\r" + // bare CR
		"data: " + benign + "\n\n" // LF
	up := framingUpstream(t, stream, false)
	defer up.Close()
	_, body := streamThrough(t, up, http.MethodPost)
	if strings.Contains(body, "poisoned_tool") {
		t.Errorf("poisoned tool reached the client: %.200s", body)
	}
	if n := strings.Count(body, "get_weather"); n != 3 {
		t.Errorf("benign tool appears %d times, want 3 (one per event): %.300s", n, body)
	}
	if strings.Contains(body, "\r") || strings.HasPrefix(body, string(utf8BOM)) {
		t.Errorf("forwarded stream not canonical: %q", body)
	}
	if got := readSSEEventsTS(body); strings.Count(got, "get_weather") != 3 || strings.Contains(got, "poisoned_tool") {
		t.Errorf("TS framing reads %d benign events and poisoned=%v, want 3 and false", strings.Count(got, "get_weather"), strings.Contains(got, "poisoned_tool"))
	}
	if got := readSSEEventsPy(body); strings.Count(got, "get_weather") != 3 || strings.Contains(got, "poisoned_tool") {
		t.Errorf("Python framing reads %d benign events and poisoned=%v, want 3 and false", strings.Count(got, "get_weather"), strings.Contains(got, "poisoned_tool"))
	}
}
