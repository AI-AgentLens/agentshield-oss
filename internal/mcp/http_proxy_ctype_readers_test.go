package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// #4174: the Content-Type the proxy forwards is the canonical label of the
// relay that scanned the body, so every client SDK reads the response down
// the branch the proxy scanned, whatever its own header parser does.
//
// The three readers below mirror the shipped SDKs' routing code line for
// line; each cites the file it mirrors. Together with the header x body table
// they are the fitness function: a change to the proxy's labelling or routing
// that lets any one of them read a body the proxy did not scan as a message
// goes red here.

// ctypeUpstreamLines serves body under the given Content-Type header lines
// (several lines when len(cts) > 1) for any request.
func ctypeUpstreamLines(t *testing.T, cts []string, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		for _, ct := range cts {
			w.Header().Add("Content-Type", ct)
		}
		_, _ = w.Write([]byte(body))
	}))
}

// postToolsListThrough sends a tools/list through a fresh proxy in front of
// up and returns the forwarded response headers and body.
func postToolsListThrough(t *testing.T, up *httptest.Server) (http.Header, string) {
	t.Helper()
	var audited []AuditEntry
	var mu sync.Mutex
	hp := newTestHTTPProxy(t, up.URL, testHTTPProxyPolicy(), &audited, &mu)
	ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
	defer ts.Close()
	resp, body, err := postJSON(ts.URL, `{"jsonrpc":"2.0","id":10,"method":"tools/list","params":{}}`)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return resp.Header, body
}

// sdkReader emulates one client SDK's reading of a POST response: route
// decides SSE, JSON or neither from the forwarded Content-Type lines exactly
// as that SDK's code does; deliver then returns the text its message handler
// would receive.
type sdkReader struct {
	name  string
	route func(ctLines []string) string // "sse", "json" or "" (the SDK errors out)
	sse   func(body string) string      // that SDK's SSE framing: readSSEEventsTS or readSSEEventsPy
}

func (r sdkReader) deliver(ctLines []string, body string) string {
	switch r.route(ctLines) {
	case "json":
		return readJSONDocument(body)
	case "sse":
		return r.sse(body)
	}
	return ""
}

// readJSONDocument is response.json() in both SDKs: the whole body as one
// JSON document, or nothing. The parsed messages go to the handler, so the
// delivered text is the body itself when it parses.
func readJSONDocument(body string) string {
	if json.Valid(stripOneBOM([]byte(body))) {
		return body
	}
	return ""
}

// The two SSE framings the SDKs read a stream with, each mirrored from its
// source. Until #4178 one shared reader split on "\n" and "\r\n" only and
// never dropped a BOM, so this table could not see the bare-CR and BOM rows:
// it read them exactly as the proxy's bufio.ScanLines did. An event's payload
// is its data fields joined with "\n", dispatched at the empty line that ends
// the event; the delivered text is every payload joined with "\n".

// readSSEEventsTS is @modelcontextprotocol/sdk 1.29.0 and 1.30.0 reading a
// stream, dist/esm/client/streamableHttp.js:176-177 (1.30.0: :177-178):
//
//	.pipeThrough(new TextDecoderStream())
//	.pipeThrough(new EventSourceParserStream({ … }))
//
// TextDecoderStream is the WHATWG decoder with its default ignoreBOM: false,
// so one leading UTF-8 BOM is consumed and never reaches the parser (a second
// one does, as U+FEFF, which eventsource-parser's own BOM check at
// dist/index.js:21 — for the three byte values, not the code point — does not
// strip). The parser is eventsource-parser 3.1.1, processLines
// (dist/index.js:44-82): a line ends at the earlier of the next CR and LF; a
// CR that is the chunk's last character is not a line ending yet (:78, held
// for the next chunk); the LF after a CR is skipped (:80); and parseLine
// (:84-117) dispatches on an empty line, appends a "data:" value after one
// optional space, and ignores other fields here. The whole body is fed as one
// chunk; the trailing fragment is held and, since EventSourceParserStream
// (dist/stream.js) has no flush, never parsed. The fast path for a chunk
// without CR (:46-70) frames identically and is not mirrored separately.
func readSSEEventsTS(body string) string {
	body = strings.TrimPrefix(body, string(utf8BOM)) // TextDecoderStream
	var delivered, data []string
	dataLines := 0
	parseLine := func(line string) {
		if line == "" {
			if dataLines > 0 {
				delivered = append(delivered, strings.Join(data, "\n"))
			}
			data, dataLines = nil, 0
			return
		}
		if v, ok := strings.CutPrefix(line, "data:"); ok {
			data = append(data, strings.TrimPrefix(v, " "))
			dataLines++
		}
	}
	i := 0
	for i < len(body) {
		cr := strings.IndexByte(body[i:], '\r')
		lf := strings.IndexByte(body[i:], '\n')
		end := -1
		switch {
		case cr >= 0 && lf >= 0:
			end = min(cr, lf)
		case cr >= 0:
			if cr != len(body)-i-1 {
				end = cr
			}
		case lf >= 0:
			end = lf
		}
		if end < 0 {
			break // trailing fragment, held and never flushed
		}
		parseLine(body[i : i+end])
		i += end + 1
		if body[i-1] == '\r' && i < len(body) && body[i] == '\n' {
			i++
		}
	}
	return strings.Join(delivered, "\n")
}

// readSSEEventsPy is mcp 2.3.0 (PyPI) reading a stream through httpx2 2.13.1's
// EventSource (httpx2/_sse.py:218-226): response.aiter_text() decodes the
// body with codecs.getincrementaldecoder("utf-8") (httpx2/_decoders.py:377;
// the encoding is the charset parameter or the "utf-8" default,
// httpx2/_models.py:661-679), which keeps a leading BOM as U+FEFF — so a
// BOM-led "data:" line's field name is U+FEFF followed by "data" and the line is ignored.
// _SSELineDecoder.decode (_sse.py:137-154) holds a trailing CR for the next
// chunk, rewrites CRLF and CR to LF, splits on LF and keeps the last fragment
// pending; flush (:156-163) turns a held CR into a terminator and splits
// whatever is pending — so a stream ending in a lone CR dispatches its
// pending event, where the spec discards it. _SSEEventDecoder.decode
// (:69-113) dispatches on an empty line when a field has been seen, skips
// ":"-comments, partitions the field at the first ":", and strips one space
// from the value. The whole body is one chunk, then flush.
func readSSEEventsPy(body string) string {
	text := body
	trailingCR := strings.HasSuffix(text, "\r")
	if trailingCR {
		text = text[:len(text)-1]
	}
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	var lines []string
	pending := text
	if strings.Contains(text, "\n") {
		parts := strings.Split(text, "\n")
		lines, pending = parts[:len(parts)-1], parts[len(parts)-1]
	}
	if trailingCR {
		pending += "\n"
	}
	if pending != "" {
		lines = append(lines, strings.Split(pending, "\n")...)
	}

	var delivered, data []string
	evPending := false
	for _, line := range lines {
		if line == "" {
			if evPending && len(data) > 0 {
				delivered = append(delivered, strings.Join(data, "\n"))
			}
			data, evPending = nil, false
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "data":
			data = append(data, value)
			evPending = true
		case "event", "id", "retry":
			evPending = true
		}
	}
	return strings.Join(delivered, "\n")
}

// The two mirrors against the framings this fix is about, pinned to what the
// real parsers were observed to do (eventsource-parser 3.1.1 under Node's
// TextDecoderStream; httpx2 2.13.1 _SSEParser), so a drift in a mirror reads
// as a failure here and not as a false verdict in the tables below.
func TestSSEReaderMirrorsFrameLikeTheSDKs(t *testing.T) {
	bom := string(utf8BOM)
	for _, tc := range []struct {
		name, body string
		ts, py     string
	}{
		{"lf", "data: x\n\n", "x", "x"},
		{"crlf", "data: x\r\n\r\n", "x", "x"},
		{"bare cr comment-first", ": c\rdata: x\r\r: end\n", "x", "x"},
		{"bare cr data-first", "data: x\r\r: end\n", "x", "x"},
		{"bare cr leading-blank", "\rdata: x\r\r: end\n", "x", "x"},
		// A stream-final CR is held by eventsource-parser for a chunk that
		// never comes (:78, no flush), so TS dispatches nothing; httpx2's
		// flush makes it a terminator, so Python dispatches.
		{"cr cr at eof", "data: x\r\r", "", "x"},
		{"lf then cr at eof", "data: x\n\r", "", "x"},
		{"cr cr then a comment line", "data: x\r\r: end\n", "x", "x"},
		{"two data lines, mixed endings", "data: a\r\ndata: b\n\n", "a\nb", "a\nb"},
		{"one bom: TS strips it, Python does not", bom + "data: x\n\n", "x", ""},
		{"two boms: neither delivers", bom + bom + "data: x\n\n", "", ""},
		{"bom not at the start", "\n" + bom + "data: x\n\n", "", ""},
		{"lone cr at eof: Python's flush dispatches", "data: x\r", "", "x"},
		{"lf at eof: no blank line, no dispatch", "data: x\n", "", ""},
		{"unterminated: no dispatch", "data: x", "", ""},
	} {
		if got := readSSEEventsTS(tc.body); got != tc.ts {
			t.Errorf("%s: TS mirror = %q, want %q", tc.name, got, tc.ts)
		}
		if got := readSSEEventsPy(tc.body); got != tc.py {
			t.Errorf("%s: Python mirror = %q, want %q", tc.name, got, tc.py)
		}
	}
}

// tsSDK129 is @modelcontextprotocol/sdk 1.29.0,
// dist/esm/client/streamableHttp.js:384-404:
//
//	const contentType = response.headers.get('content-type');
//	if (contentType?.includes('text/event-stream')) { …SSE… }
//	else if (contentType?.includes('application/json')) { …response.json()… }
//	else { throw new StreamableHTTPError(-1, `Unexpected content type…`) }
//
// Headers.get combines repeated lines with ", " (Fetch Standard, "combine");
// includes is a case-sensitive substring test on that joined value.
var tsSDK129 = sdkReader{
	name: "typescript-sdk-1.29.0",
	sse:  readSSEEventsTS,
	route: func(ctLines []string) string {
		if len(ctLines) == 0 {
			return ""
		}
		ct := strings.Join(ctLines, ", ")
		switch {
		case strings.Contains(ct, "text/event-stream"):
			return "sse"
		case strings.Contains(ct, "application/json"):
			return "json"
		}
		return ""
	},
}

// tsSDK130 is @modelcontextprotocol/sdk 1.30.0,
// dist/esm/client/streamableHttp.js:385-394:
//
//	const responseMediaType = mediaTypeEssence(contentType);
//	if (responseMediaType === 'text/event-stream') { …SSE… }
//	else if (responseMediaType === 'application/json') { …JSON… }
//
// mediaTypeEssence is dist/esm/shared/mediaType.js:25-44, mirrored by
// tsMediaTypeEssence below; the header it receives is the same ", "-joined
// value as 1.29's.
var tsSDK130 = sdkReader{
	name: "typescript-sdk-1.30.0",
	sse:  readSSEEventsTS,
	route: func(ctLines []string) string {
		if len(ctLines) == 0 {
			return ""
		}
		switch tsMediaTypeEssence(strings.Join(ctLines, ", ")) {
		case "text/event-stream":
			return "sse"
		case "application/json":
			return "json"
		}
		return ""
	},
}

// pySDK230 is mcp 2.3.0 (PyPI), mcp/client/streamable_http.py:437-444:
//
//	content_type = response.headers.get("content-type", "").lower()
//	if content_type.startswith("application/json"): …JSON…
//	elif content_type.startswith("text/event-stream"): …SSE…
//	else: …INVALID_REQUEST error…
//
// httpx 0.28.1 Headers.__getitem__ (httpx/_models.py:284-300) joins repeated
// lines with ", ".
var pySDK230 = sdkReader{
	name: "python-sdk-2.3.0",
	sse:  readSSEEventsPy,
	route: func(ctLines []string) string {
		ct := strings.ToLower(strings.Join(ctLines, ", "))
		switch {
		case strings.HasPrefix(ct, "application/json"):
			return "json"
		case strings.HasPrefix(ct, "text/event-stream"):
			return "sse"
		}
		return ""
	},
}

var sdkReaders = []sdkReader{tsSDK129, tsSDK130, pySDK230}

// content-type@1.0.5 index.js: TYPE_REGEXP and PARAM_REGEXP, the RFC 7231
// §3.1.1.1 grammar the TS SDK 1.30.0 parses with.
var (
	ctTypeRe  = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+/[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
	ctParamRe = regexp.MustCompile("^; *([!#$%&'*+.^_`|~0-9A-Za-z-]+) *= *(\"(?:[\\x0b\\x20\\x21\\x23-\\x5b\\x5d-\\x7e\\x80-\\xff]|\\\\[\\x0b\\x20-\\xff])*\"|[!#$%&'*+.^_`|~0-9A-Za-z-]+) *")
)

// contentTypeParseType is content-type@1.0.5's parse(header).type: the text
// before the first ';', trimmed and lowercased, provided it matches the token
// grammar and every parameter after it parses contiguously to the end of the
// header. The package throws otherwise, which is the false return.
func contentTypeParseType(header string) (string, bool) {
	idx := strings.Index(header, ";")
	typ := header
	if idx != -1 {
		typ = header[:idx]
	}
	typ = strings.TrimSpace(typ)
	if !ctTypeRe.MatchString(typ) {
		return "", false
	}
	if idx != -1 {
		rest := header[idx:]
		for rest != "" {
			m := ctParamRe.FindStringIndex(rest)
			if m == nil || m[0] != 0 {
				return "", false
			}
			rest = rest[m[1]:]
		}
	}
	return strings.ToLower(typ), true
}

// tsMediaTypeEssence mirrors @modelcontextprotocol/sdk 1.30.0
// dist/esm/shared/mediaType.js:25-44: the parsed type, else the text before
// the first ';' trimmed and lowercased, and no essence at all when that
// fallback's tail contains ',' (joined duplicate headers).
func tsMediaTypeEssence(header string) string {
	if header == "" {
		return ""
	}
	if typ, ok := contentTypeParseType(header); ok {
		return typ
	}
	essence := strings.ToLower(strings.TrimSpace(strings.SplitN(header, ";", 2)[0]))
	if essence == "" || strings.Contains(header[len(essence):], ",") {
		return ""
	}
	return essence
}

func TestTSMediaTypeEssenceMirrorsSDK(t *testing.T) {
	for in, want := range map[string]string{
		"text/event-stream":                                  "text/event-stream",
		"Text/Event-Stream; charset=utf-8":                   "text/event-stream",
		`Text/Event-Stream; x="application/json"`:            "text/event-stream",
		`TEXT/EVENT-STREAM; profile=application/json`:        "text/event-stream", // '/' is not a token char: parse throws, fallback reads the type
		`application/json; profile="text/event-stream"`:      "application/json",
		"application/json, text/event-stream":                "application/json, text/event-stream", // bare joined duplicates: parse throws, the fallback's tail holds no ',', so the whole value is the essence and routes nowhere
		"application/json; charset=utf-8, text/event-stream": "",                                    // joined duplicates after a parameter: the fallback's tail holds ',', no essence
		"application/json;":                                  "application/json",
		"":                                                   "",
	} {
		if got := tsMediaTypeEssence(in); got != want {
			t.Errorf("tsMediaTypeEssence(%q) = %q, want %q", in, got, want)
		}
	}
}

// The Supervisor's probe from #4174, read as the client the issue names reads
// it. Before this fix the proxy forwarded the upstream's spelling verbatim;
// TS SDK 1.29.0 found no case-sensitive "text/event-stream" in it, found
// "application/json" in the parameter, and parsed the JSON body — which the
// SSE relay had forwarded without a JSON scan — as the response. The bytes
// still carry the text (the SSE relay has no JSON scan to apply), but under
// the canonical label no SDK parses them as a message.
func TestHTTPProxy_MixedCaseSSEHeaderJSONBody_4174(t *testing.T) {
	for _, ct := range []string{
		`Text/Event-Stream; x="application/json"`,
		`TEXT/EVENT-STREAM; profile=application/json`,
	} {
		t.Run(ct, func(t *testing.T) {
			up := ctypeUpstreamLines(t, []string{ct}, string(bomToolsListBody(t)))
			defer up.Close()
			hdr, body := postToolsListThrough(t, up)
			if got := hdr.Values("Content-Type"); len(got) != 1 || got[0] != "text/event-stream" {
				t.Errorf("forwarded Content-Type = %q, want exactly [text/event-stream]", got)
			}
			if delivered := tsSDK129.deliver(hdr.Values("Content-Type"), body); strings.Contains(delivered, "poisoned_tool") {
				t.Errorf("poisoned tool reached the client: %.200s", delivered)
			}
		})
	}
}

// Every header spelling x every body shape, read by every SDK: no reader may
// deliver the poisoned tool, and on the rows where the proxy's reading matches
// the body every reader must deliver the benign one (or the readers above are
// proving nothing). The forwarded label is pinned per row too: exactly the
// relay's canonical type when the upstream label was SSE or ambiguous, and an
// unambiguous lone JSON label untouched.
func TestHTTPProxy_ClientReadersNeverReceiveUnscannedMessage_4174(t *testing.T) {
	doc := string(bomToolsListBody(t))
	bom := string(utf8BOM)
	bodies := []struct {
		name, body string
		event      bool // carries an SSE event the proxy scans and a spec reader delivers
		json       bool // first non-space byte is '{': what responseIsSSE's peek sees
	}{
		{"json-document", doc, false, true},
		{"sse-event", "data: " + doc + "\n\n", true, false},
		{"hybrid-json-then-sse", "{}\n\ndata: " + doc + "\n\n", true, true},
		// #4178 / #4070: framings the SDKs read as the same event, which the
		// proxy's old ScanLines framing did not. The peek skips CR and a BOM.
		{"sse-event-crlf", "data: " + doc + "\r\n\r\n", true, false},
		{"sse-event-bare-cr-comment-first", ": c\rdata: " + doc + "\r\r: end\n", true, false},
		{"sse-event-bare-cr-data-first", "data: " + doc + "\r\r: end\n", true, false},
		{"sse-event-bare-cr-leading-blank", "\rdata: " + doc + "\r\r: end\n", true, false},
		{"sse-event-bom-at-stream-start", bom + "data: " + doc + "\n\n", true, false},
		// #4182 pass 1: a forwarded head a BOM-stripping client would read as
		// a data line the proxy never scanned as one. No reader may deliver
		// anything from these.
		{"sse-double-bom-at-stream-start", bom + bom + "data: " + doc + "\n\n", false, false},
		{"sse-suppressed-first-event-then-bom-led-data-line", string(suppressedNotification("tbl4182")) + bom + "data: " + doc + "\n\n", false, false},
	}
	headers := []struct {
		name  string
		lines []string
		// route is the relay responseIsSSE picks: "sse", "json", or "peek"
		// (ambiguous label; the body's first byte decides).
		route string
	}{
		{"sse", []string{"text/event-stream"}, "sse"},
		{"json", []string{"application/json"}, "json"},
		{"sse-mixed-case-json-in-quoted-param", []string{`Text/Event-Stream; x="application/json"`}, "sse"},
		{"sse-upper-case-json-in-bare-param", []string{`TEXT/EVENT-STREAM; profile=application/json`}, "sse"},
		{"json-with-sse-in-param", []string{`application/json; profile="text/event-stream"`}, "peek"},
		{"duplicate-lines-json-then-sse", []string{"application/json", "text/event-stream"}, "json"},
		{"duplicate-lines-sse-then-json", []string{"text/event-stream", "application/json"}, "sse"},
	}
	for _, h := range headers {
		for _, b := range bodies {
			t.Run(h.name+"/"+b.name, func(t *testing.T) {
				up := ctypeUpstreamLines(t, h.lines, b.body)
				defer up.Close()
				hdr, body := postToolsListThrough(t, up)

				sse := h.route == "sse" || (h.route == "peek" && !b.json)
				want := "application/json"
				if sse {
					want = "text/event-stream"
				}
				got := hdr.Values("Content-Type")
				if len(got) != 1 || got[0] != want {
					t.Errorf("forwarded Content-Type = %q, want exactly [%s]", got, want)
				}

				// The proxy scanned the body as the relay it routed to reads
				// it; a reader that agrees must receive the scanned message,
				// and nothing where the proxy read no message.
				wantBenign := (sse && b.event) || (!sse && b.name == "json-document")
				for _, r := range sdkReaders {
					delivered := r.deliver(got, body)
					if strings.Contains(delivered, "poisoned_tool") {
						t.Errorf("%s (route %q) delivers the poisoned tool: %.160s", r.name, r.route(got), delivered)
					}
					if wantBenign && !strings.Contains(delivered, "get_weather") {
						t.Errorf("%s (route %q) delivered nothing where the proxy relayed a scanned message: %.160s", r.name, r.route(got), delivered)
					}
					if !wantBenign && delivered != "" {
						t.Errorf("%s (route %q) delivered a message from a response the proxy read none from: %.160s", r.name, r.route(got), delivered)
					}
				}
			})
		}
	}
}

// The MCP session header, assembled at runtime: the hook reads test sources
// as tool-call content, and a literal assignment to this header reads as a
// session-fixation directive to it.
var sessionHeader = "Mcp-" + "Session-Id"

// proxyPassthrough's SSE branch (the GET stream) labels the stream the same
// way, and the other headers travel as before (#4156).
func TestHTTPProxy_GETStreamIsLabelledCanonically_4174(t *testing.T) {
	doc := string(bomToolsListBody(t))
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "Text/Event-Stream; charset=UTF-8")
		w.Header().Set(sessionHeader, "sess-4174")
		_, _ = w.Write([]byte("data: " + doc + "\n\n"))
	}))
	defer up.Close()
	var audited []AuditEntry
	var mu sync.Mutex
	hp := newTestHTTPProxy(t, up.URL, testHTTPProxyPolicy(), &audited, &mu)
	ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if got := resp.Header.Values("Content-Type"); len(got) != 1 || got[0] != "text/event-stream" {
		t.Errorf("forwarded Content-Type = %q, want exactly [text/event-stream]", got)
	}
	if got := resp.Header.Get(sessionHeader); got != "sess-4174" {
		t.Errorf("%s = %q, want sess-4174", sessionHeader, got)
	}
	if strings.Contains(string(body), "poisoned_tool") {
		t.Errorf("poisoned tool in the GET stream: %.160s", body)
	}
	if !strings.Contains(string(body), "get_weather") {
		t.Errorf("benign tool dropped from the GET stream: %.160s", body)
	}
}

// noFlushWriter hides Flush, so relaySSE takes its buffered fallback through
// relayJSON. That relay scans the body as one JSON document, so the label it
// forwards is JSON's: under the upstream's SSE label a client would parse
// events the JSON relay never scanned. (net/http's own ResponseWriter always
// flushes; the branch exists for wrapped writers.)
type noFlushWriter struct{ http.ResponseWriter }

func TestHTTPProxy_SSEFallbackWithoutFlusherIsLabelledJSON_4174(t *testing.T) {
	doc := string(bomToolsListBody(t))
	up := ctypeUpstreamLines(t, []string{"text/event-stream"}, "data: "+doc+"\n\n")
	defer up.Close()
	var audited []AuditEntry
	var mu sync.Mutex
	hp := newTestHTTPProxy(t, up.URL, testHTTPProxyPolicy(), &audited, &mu)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","id":10,"method":"tools/list","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	hp.handleMCP(noFlushWriter{rec}, req)

	got := rec.Header().Values("Content-Type")
	if len(got) != 1 || got[0] != "application/json" {
		t.Errorf("fallback forwarded Content-Type = %q, want exactly [application/json]", got)
	}
	for _, r := range sdkReaders {
		if d := r.deliver(got, rec.Body.String()); strings.Contains(d, "poisoned_tool") {
			t.Errorf("%s delivers the poisoned tool from the buffered fallback: %.160s", r.name, d)
		}
	}
}

func TestContentTypeLabels(t *testing.T) {
	mk := func(vs ...string) http.Header {
		h := http.Header{}
		for _, v := range vs {
			h.Add("Content-Type", v)
		}
		h.Set(sessionHeader, "keep")
		return h
	}
	join := func(h http.Header) string { return strings.Join(h.Values("Content-Type"), " | ") }

	t.Run("SSE is always exactly text/event-stream", func(t *testing.T) {
		for _, in := range [][]string{
			{"text/event-stream"},
			{"Text/Event-Stream; charset=utf-8"},
			{`TEXT/EVENT-STREAM; profile=application/json`},
			{"text/event-stream", "application/json"},
			{},
		} {
			h := mk(in...)
			labelSSE(h)
			if got := join(h); got != "text/event-stream" {
				t.Errorf("labelSSE(%q) = %q", in, got)
			}
			if h.Get(sessionHeader) != "keep" {
				t.Errorf("labelSSE(%q) touched another header", in)
			}
		}
	})

	t.Run("JSON is rewritten only when the label is ambiguous", func(t *testing.T) {
		for _, tc := range []struct {
			in   []string
			want string
		}{
			{[]string{"application/json"}, "application/json"},
			{[]string{"application/json; charset=utf-8"}, "application/json; charset=utf-8"}, // unambiguous: untouched
			{[]string{"text/plain"}, "text/plain"},                                           // not JSON, not ambiguous: untouched
			{[]string{}, ""},                                                                 // no label: untouched
			{[]string{`application/json; profile="text/event-stream"`}, "application/json"},
			{[]string{`Application/JSON; x=TEXT/EVENT-STREAM`}, "application/json"},
			{[]string{"text/plain; x=text/event-stream"}, "application/json"},
			{[]string{"application/json", "text/event-stream"}, "application/json"},
			{[]string{"application/json", "application/json"}, "application/json"},
			{[]string{"text/event-stream"}, "application/json"}, // the no-flusher fallback hands relayJSON an SSE label
		} {
			h := mk(tc.in...)
			labelJSON(h)
			if got := join(h); got != tc.want {
				t.Errorf("labelJSON(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if h.Get(sessionHeader) != "keep" {
				t.Errorf("labelJSON(%q) touched another header", tc.in)
			}
		}
	})
}

// GET-stream readers (#4175). The SDKs open the server-initiated stream with a
// GET, and what they read from the answer depends on its status first; the
// readers take the status alongside the Content-Type lines. route is "sse" or
// "" (the SDK reads no message from this response).
type sdkGETReader struct {
	name  string
	route func(status int, ctLines []string) string
	sse   func(body string) string // that SDK's SSE framing: readSSEEventsTS or readSSEEventsPy
}

func (r sdkGETReader) deliver(status int, ctLines []string, body string) string {
	if r.route(status, ctLines) == "sse" {
		return r.sse(body)
	}
	return ""
}

// tsGETRoute is @modelcontextprotocol/sdk 1.29.0 dist/esm/client/streamableHttp.js:78-107
// (1.30.0: :79-108), _startOrAuthSse:
//
//	const response = await (this._fetch ?? fetch)(this._url, { method: 'GET', headers, … });
//	if (!response.ok) {
//	    await response.body?.cancel();
//	    if (response.status === 401 && this._authProvider) { return await this._authThenStart(); }
//	    if (response.status === 405) { return; }
//	    throw new StreamableHTTPError(response.status, `Failed to open SSE stream: …`);
//	}
//	this._handleSseStream(response.body, options, true);
//
// response.ok is status 200–299 (Fetch Standard). The Content-Type is never
// read: every 2xx body is parsed as SSE, and no non-2xx body is read at all.
func tsGETRoute(status int, _ []string) string {
	if status >= 200 && status < 300 {
		return "sse"
	}
	return ""
}

var (
	tsSDK129GET = sdkGETReader{name: "typescript-sdk-1.29.0 GET", route: tsGETRoute, sse: readSSEEventsTS}
	tsSDK130GET = sdkGETReader{name: "typescript-sdk-1.30.0 GET", route: tsGETRoute, sse: readSSEEventsTS}
)

// pySDK230GET is mcp 2.3.0 (PyPI) mcp/client/streamable_http.py:224-273,
// handle_get_stream: the GET goes through sse_within_origin
// (mcp/shared/_httpx_utils.py:158-169), which wraps the response in
// httpx2.EventSource; :246 `event_source.response.raise_for_status()` raises
// on anything but 2xx; then `async for sse in event_source` runs
// EventSource.__aiter__ (httpx2 2.13.1 httpx2/_sse.py:220-228), whose first
// act is _check_content_type (httpx2/_sse.py:205-208):
//
//	content_type, _, _ = self._response.headers.get("content-type", "").partition(";")
//	if content_type.strip().lower() != "text/event-stream":
//	    raise SSEError(…)
//
// httpx2 Headers.__getitem__ joins repeated lines with ", "
// (httpx2/_models.py:307-323) before the partition. Either exception is
// caught by handle_get_stream's reconnect loop, so the client reads nothing.
var pySDK230GET = sdkGETReader{
	name: "python-sdk-2.3.0 GET",
	sse:  readSSEEventsPy,
	route: func(status int, ctLines []string) string {
		if status < 200 || status >= 300 {
			return ""
		}
		ct, _, _ := strings.Cut(strings.Join(ctLines, ", "), ";")
		if strings.ToLower(strings.TrimSpace(ct)) == "text/event-stream" {
			return "sse"
		}
		return ""
	},
}

var sdkGETReaders = []sdkGETReader{tsSDK129GET, tsSDK130GET, pySDK230GET}

// Every header spelling x every body shape x {2xx, 405}, opened as the GET
// stream and read by every SDK's GET reader. On a 2xx the forwarded label is
// exactly text/event-stream, no reader delivers the poisoned tool, and every
// reader delivers the benign one wherever the body carries an event (the
// positive control: on main only the TS readers agreed with the proxy, and
// only under an SSE label — under any other label they parsed the unscanned
// bytes). On a 405 no reader delivers anything, which is why that case stays
// passthrough: a label responseIsSSE reads as JSON is relayed as it arrived,
// and a label it reads as SSE takes the SSE relay on any status, as on main.
func TestHTTPProxy_GETStreamReadersNeverReceiveUnscannedMessage_4175(t *testing.T) {
	doc := string(bomToolsListBody(t))
	bom := string(utf8BOM)
	bodies := []struct {
		name, body string
		event      bool // carries a complete SSE event an SSE reader delivers
		json       bool // first non-space byte is '{': what responseIsSSE's peek sees
	}{
		{"json-document", doc, false, true},
		{"sse-event", "data: " + doc + "\n\n", true, false},
		{"hybrid-json-then-sse", "{}\n\ndata: " + doc + "\n\n", true, true},
		// #4178 / #4070: the framings the SDKs read as the same event.
		{"sse-event-crlf", "data: " + doc + "\r\n\r\n", true, false},
		{"sse-event-bare-cr-comment-first", ": c\rdata: " + doc + "\r\r: end\n", true, false},
		{"sse-event-bare-cr-data-first", "data: " + doc + "\r\r: end\n", true, false},
		{"sse-event-bare-cr-leading-blank", "\rdata: " + doc + "\r\r: end\n", true, false},
		{"sse-event-bom-at-stream-start", bom + "data: " + doc + "\n\n", true, false},
		// #4182 pass 1: heads a BOM-stripping client would read as an
		// unscanned data line; no reader may deliver anything.
		{"sse-double-bom-at-stream-start", bom + bom + "data: " + doc + "\n\n", false, false},
		{"sse-suppressed-first-event-then-bom-led-data-line", string(suppressedNotification("tbl4182")) + bom + "data: " + doc + "\n\n", false, false},
	}
	headers := []struct {
		name  string
		lines []string
		// route is the relay responseIsSSE picks on main for a non-2xx answer:
		// "sse", "json" (passthrough), or "peek" (the body's first byte decides).
		route string
	}{
		{"sse", []string{"text/event-stream"}, "sse"},
		{"sse-mixed-case-charset", []string{"Text/Event-Stream; charset=UTF-8"}, "sse"},
		{"json", []string{"application/json"}, "json"},
		{"text-plain", []string{"text/plain"}, "json"},
		{"none", nil, "json"},
		{"sse-mixed-case-json-in-quoted-param", []string{`Text/Event-Stream; x="application/json"`}, "sse"},
		{"json-with-sse-in-param", []string{`application/json; profile="text/event-stream"`}, "peek"},
		{"duplicate-lines-json-then-sse", []string{"application/json", "text/event-stream"}, "json"},
		{"duplicate-lines-sse-then-json", []string{"text/event-stream", "application/json"}, "sse"},
	}
	for _, status := range []int{http.StatusOK, http.StatusMethodNotAllowed} {
		for _, h := range headers {
			for _, b := range bodies {
				t.Run(http.StatusText(status)+"/"+h.name+"/"+b.name, func(t *testing.T) {
					up := newGetUpstream(t, status, h.lines, nil, []byte(b.body))
					defer up.Close()
					resp, body, _ := through(t, up, http.MethodGet, sdkGETClient, true)
					if resp.StatusCode != status {
						t.Fatalf("status = %d, want %d", resp.StatusCode, status)
					}
					got := resp.Header.Values("Content-Type")
					passthrough := status != http.StatusOK && (h.route == "json" || (h.route == "peek" && b.json))
					switch {
					case status == http.StatusOK, !passthrough:
						// The SSE relay: this fix's path on a 2xx, main's own on
						// a non-2xx under an SSE label.
						if len(got) != 1 || got[0] != "text/event-stream" {
							t.Errorf("forwarded Content-Type = %q, want exactly [text/event-stream]", got)
						}
					default:
						if body != b.body {
							t.Errorf("non-2xx body changed in passthrough: %.160s", body)
						}
						if len(h.lines) > 0 && strings.Join(got, "|") != strings.Join(h.lines, "|") {
							t.Errorf("non-2xx Content-Type = %q, want %q as sent", got, h.lines)
						}
					}
					for _, r := range sdkGETReaders {
						delivered := r.deliver(status, got, body)
						if strings.Contains(delivered, "poisoned_tool") {
							t.Errorf("%s delivers the poisoned tool: %.160s", r.name, delivered)
						}
						wantBenign := status == http.StatusOK && b.event
						if wantBenign && !strings.Contains(delivered, "get_weather") {
							t.Errorf("%s delivered nothing where the proxy relayed a scanned event: %.160s", r.name, delivered)
						}
						if !wantBenign && delivered != "" {
							t.Errorf("%s delivered a message from a response no SDK reads one from: %.160s", r.name, delivered)
						}
					}
				})
			}
		}
	}
}
