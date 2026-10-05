package mcp

import (
	"bufio"
	"bytes"
	"io"
)

// The SSE relay's line limits. A line longer than sseMaxLineBytes ends the
// scan with bufio.ErrTooLong: relaySSEStream forwards the lines before it,
// scans the event they were part of, and relays nothing after it (#4178 kept
// the limits and this behaviour; the raw and gzip forms differ only in the
// receipt relaySSE writes for the cut).
const (
	sseLineBufferBytes = 1 << 20
	sseMaxLineBytes    = 10 << 20
)

// newSSELineScanner frames r as the SSE relay reads a stream: spec line
// endings, one leading BOM dropped, the limits above.
func newSSELineScanner(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, sseLineBufferBytes), sseMaxLineBytes)
	s.Split(new(sseLineSplitter).split)
	return s
}

// sseLineSplitter is the bufio.SplitFunc the SSE relay frames an upstream
// stream with. It follows the WHATWG EventSource "parsing an event stream"
// steps, which is what the client SDKs implement (eventsource-parser behind
// @modelcontextprotocol/sdk, httpx2's _sse behind Python mcp), where
// bufio.ScanLines does not:
//
//   - a line ends at CRLF, LF or a bare CR. ScanLines ends one at LF only, so
//     a stream whose lines end in bare CRs read as one line, which no "data:"
//     prefix check matched, and went to the client unscanned (#4070);
//   - one UTF-8 BOM at the very start of the stream is not part of the first
//     line. ScanLines kept it, so "\xEF\xBB\xBFdata: …" was not a data line
//     to the proxy, while the TS SDK's TextDecoder dropped the BOM and parsed
//     it as one (#4178). Only the first three bytes of the stream can be
//     that BOM; a later one, or a second one, is content.
//
// Lines are returned without their terminator, so a CRLF is one line ending
// and never a line followed by an empty line: an empty line dispatches an
// event, and a spurious one would be a framing the client never saw. A CR that
// is the last byte buffered may be the first half of a CRLF split across two
// reads, so the splitter asks for more data before deciding; only at EOF is it
// a bare CR.
type sseLineSplitter struct {
	started bool // the stream's first bytes have been judged; no further BOM is dropped
}

// sseHeadGuard is the writer the SSE relay forwards one response through.
// The first bytes of a response are the one place a client strips a UTF-8
// BOM (the WHATWG TextDecoder with its default ignoreBOM: false, which is
// what @modelcontextprotocol/sdk reads the stream through), so a response
// whose first forwarded line begins with a BOM would be read by that client
// as the line without it — a "data:" line the proxy never scanned as one
// (#4182 pass 1). Two upstream shapes produce such a head: a stream opening
// with two BOMs, of which the splitter strips exactly one as the spec and
// every client do (the second is content, and content is forwarded); and a
// first event the scanners suppressed whose non-data lines, forwarded as they
// came, begin with a BOM. The guard writes one sacrificial BOM ahead of such a
// head, so the forwarded stream never begins with exactly one BOM: a client
// that strips a leading BOM removes the sacrificial one and reads the line as
// the proxy framed it, and a client that keeps BOMs (httpx2 behind Python
// mcp) sees the unknown field it always saw. It is per response, across
// every decoded form relaySSE tries, because the client reads one stream.
type sseHeadGuard struct {
	w       io.Writer
	started bool // a byte has gone out: the head is decided
}

func (g *sseHeadGuard) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !g.started && bytes.HasPrefix(p, utf8BOM) {
		if _, err := g.w.Write(utf8BOM); err != nil {
			return 0, err
		}
	}
	g.started = true
	return g.w.Write(p)
}

func (s *sseLineSplitter) split(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if !s.started {
		if !atEOF && len(data) < len(utf8BOM) && bytes.HasPrefix(utf8BOM, data) {
			return 0, nil, nil // the first bytes may still turn out to be a BOM
		}
		s.started = true
		if bytes.HasPrefix(data, utf8BOM) {
			// Consume the BOM together with whatever line decision follows,
			// never as a bare advance: at EOF a nil token ends the scan.
			advance, token, err = s.split(data[len(utf8BOM):], atEOF)
			return advance + len(utf8BOM), token, err
		}
	}
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	i := bytes.IndexAny(data, "\r\n")
	switch {
	case i < 0:
		if atEOF {
			return len(data), data, nil // the last line, unterminated
		}
		return 0, nil, nil
	case data[i] == '\n':
		return i + 1, data[:i], nil
	case i+1 < len(data):
		if data[i+1] == '\n' {
			return i + 2, data[:i], nil // CRLF: one line ending
		}
		return i + 1, data[:i], nil // bare CR
	case atEOF:
		return i + 1, data[:i], nil // a bare CR ending the stream
	}
	return 0, nil, nil // CR at the end of the buffer: CRLF or bare CR, the next byte decides
}
