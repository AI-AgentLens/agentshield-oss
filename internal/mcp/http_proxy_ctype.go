package mcp

import (
	"bufio"
	"io"
	"mime"
	"net/http"
	"strings"
)

const sseMediaType = "text/event-stream"

// responseIsSSE decides whether an upstream response is read as an SSE stream
// or as a plain JSON body (#4155). It must reach the verdict the client's SDK
// reaches, because the branch it does not take is the branch nothing scans.
//
// The type is the parsed media type, lowercased (RFC 9110: type names are
// case-insensitive, parameters are not part of the type). The old
// strings.Contains test disagreed with the Python SDK both ways: a JSON body
// under `application/json; profile="text/event-stream"` went to the SSE
// relay, which found no `data:` line and forwarded it unscanned.
//
// A header that names the SSE type only inside a parameter or a malformed
// value is ambiguous. It used to be SSE; to avoid scanning less than before,
// the first non-space byte of the body decides: `{` or `[` is JSON, anything
// else keeps the old SSE reading. The body is peeked, not consumed, so a
// stream stays a stream; resp.Body is replaced with a reader that replays it.
//
// The verdict here decides which relay scans; the label the client sees is
// that relay's canonical type (labelSSE / labelJSON, #4174), so a client
// whose own parser disagrees with this verdict still reads the scanned branch.
func responseIsSSE(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	if mediaTypeOf(ct) == sseMediaType {
		return true
	}
	if !strings.Contains(strings.ToLower(ct), sseMediaType) {
		return false
	}
	br := bufio.NewReaderSize(resp.Body, 4096)
	resp.Body = struct {
		io.Reader
		io.Closer
	}{br, resp.Body}
	peek, _ := br.Peek(4096)
	for i := 0; i < len(peek); i++ {
		switch peek[i] {
		case ' ', '\t', '\r', '\n':
			continue
		case 0xEF: // UTF-8 BOM
			if i+2 < len(peek) && peek[i+1] == 0xBB && peek[i+2] == 0xBF {
				i += 2
				continue
			}
		case '{', '[':
			return false
		}
		return true
	}
	return true
}

// mediaTypeOf returns the lowercased media type of a Content-Type value,
// falling back to the text before the first ';' when the value does not parse.
func mediaTypeOf(ct string) string {
	if mt, _, err := mime.ParseMediaType(ct); err == nil || mt != "" {
		return mt
	}
	head, _, _ := strings.Cut(ct, ";")
	return strings.ToLower(strings.TrimSpace(head))
}

// jsonMediaType is the canonical label of a body the JSON relay scanned.
const jsonMediaType = "application/json"

// The Content-Type the proxy forwards is the canonical label of the relay
// that scanned the body (#4174), so that every client reads the response down
// the branch the proxy scanned, whatever its own header parser does. The SDKs
// parse this header three ways: TS 1.29 a case-sensitive substring test of
// the raw value (SSE first), TS 1.30 the parsed media-type essence, Python a
// prefix test of the lowercased value (JSON first); and fetch and httpx join
// repeated lines with ", " before any of them looks. Forwarding the upstream's
// own spelling let a client disagree with responseIsSSE and read the branch
// nothing scanned: under `Text/Event-Stream; x="application/json"` the proxy
// relayed a JSON body as a stream (no data: line, so nothing to scan) and TS
// 1.29 parsed it as JSON. Same principle as Content-Encoding under #4154: the
// client receives the bytes the scanners saw, labelled as what they saw.

// labelSSE sets the forwarded Content-Type to exactly text/event-stream. The
// SSE spec fixes the encoding at UTF-8, so a charset parameter adds nothing,
// and any other parameter is where the disagreement lived; repeated lines
// collapse to one.
func labelSSE(h http.Header) { h.Set("Content-Type", sseMediaType) }

// labelJSON sets the forwarded Content-Type to exactly application/json when
// the upstream's label is ambiguous — more than one line (joined by the
// client into a value that names both types), or a line that mentions the
// SSE type anywhere — and leaves an unambiguous label such as
// `application/json; charset=utf-8` exactly as upstream sent it.
func labelJSON(h http.Header) {
	vals := h.Values("Content-Type")
	ambiguous := len(vals) > 1
	for _, v := range vals {
		ambiguous = ambiguous || strings.Contains(strings.ToLower(v), sseMediaType)
	}
	if ambiguous {
		h.Set("Content-Type", jsonMediaType)
	}
}
