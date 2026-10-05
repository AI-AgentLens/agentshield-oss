package mcp

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

// crBoundaryReader returns the input in reads that end exactly after every
// CR, so a CRLF always arrives as "\r" in one read and "\n" in the next: the
// split that makes a CR at the end of the buffer ambiguous.
type crBoundaryReader struct {
	rest []byte
}

func (r *crBoundaryReader) Read(p []byte) (int, error) {
	if len(r.rest) == 0 {
		return 0, io.EOF
	}
	n := len(r.rest)
	if i := bytes.IndexByte(r.rest, '\r'); i >= 0 {
		n = i + 1
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, r.rest[:n])
	r.rest = r.rest[n:]
	return n, nil
}

// sseLines frames in with the relay's own scanner over r and returns the
// lines, or the error that ended the scan.
func sseLines(t *testing.T, r io.Reader) ([]string, error) {
	t.Helper()
	s := newSSELineScanner(r)
	lines := []string{}
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	return lines, s.Err()
}

// The splitter against every way the bytes can arrive: whole, one byte at a
// time, halved, with EOF delivered alongside the final bytes (so the very
// first call can be atEOF), and split exactly between a CR and what follows.
func TestSSELineSplitter(t *testing.T) {
	bom := string(utf8BOM)
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"lf", "a\nb\n", []string{"a", "b"}},
		{"crlf", "a\r\nb\r\n", []string{"a", "b"}},
		{"bare cr", "a\rb\r", []string{"a", "b"}},
		{"cr cr is a line and an empty line", "a\r\rb\n", []string{"a", "", "b"}},
		{"crlf crlf is a line and an empty line", "a\r\n\r\nb\n", []string{"a", "", "b"}},
		{"lf then cr is a line and an empty line", "a\n\rb\n", []string{"a", "", "b"}},
		{"mixed endings", ": c\rdata: x\r\n\ndata: y\n", []string{": c", "data: x", "", "data: y"}},
		{"lone cr at eof ends the line", "a\r", []string{"a"}},
		{"unterminated last line", "a\nb", []string{"a", "b"}},
		{"empty lines only", "\n\r\n\r", []string{"", "", ""}},
		{"bom at stream start is dropped", bom + "a\nb\n", []string{"a", "b"}},
		{"only one bom is dropped", bom + bom + "a\n", []string{bom + "a"}},
		{"bom after the first byte is content", "a\n" + bom + "b\n", []string{"a", bom + "b"}},
		{"bom inside a line is content", "a" + bom + "b\n", []string{"a" + bom + "b"}},
		{"bom then bare cr at eof", bom + "a\r", []string{"a"}},
		{"bom then empty line", bom + "\ndata: x\n", []string{"", "data: x"}},
		{"bom alone", bom, []string{}},
		{"partial bom at eof is content", "\xEF\xBB", []string{"\xEF\xBB"}},
		{"empty stream", "", []string{}},
	}
	readers := []struct {
		name string
		open func(string) io.Reader
	}{
		{"whole", func(s string) io.Reader { return strings.NewReader(s) }},
		{"one byte per read", func(s string) io.Reader { return iotest.OneByteReader(strings.NewReader(s)) }},
		{"half per read", func(s string) io.Reader { return iotest.HalfReader(strings.NewReader(s)) }},
		{"eof with the last bytes", func(s string) io.Reader { return iotest.DataErrReader(strings.NewReader(s)) }},
		{"eof with one byte", func(s string) io.Reader { return iotest.DataErrReader(iotest.OneByteReader(strings.NewReader(s))) }},
		{"split after every cr", func(s string) io.Reader { return &crBoundaryReader{rest: []byte(s)} }},
	}
	for _, tc := range cases {
		for _, r := range readers {
			t.Run(tc.name+"/"+r.name, func(t *testing.T) {
				got, err := sseLines(t, r.open(tc.in))
				if err != nil {
					t.Fatalf("scan error: %v", err)
				}
				if strings.Join(got, "|") != strings.Join(tc.want, "|") {
					t.Errorf("lines = %q, want %q", got, tc.want)
				}
			})
		}
	}
}

// The trap the splitter exists to avoid, pinned on its own: a CRLF whose CR
// is the last byte of one read and whose LF opens the next is one line
// ending. Read as CR then LF it would be a line and an empty line, and the
// empty line would dispatch the event early — a framing the client never saw.
func TestSSELineSplitter_CRLFSplitAcrossReads(t *testing.T) {
	in := "data: a\r\ndata: b\r\n\r\n"
	want := []string{"data: a", "data: b", ""}
	for _, r := range []struct {
		name string
		rd   io.Reader
	}{
		{"split after every cr", &crBoundaryReader{rest: []byte(in)}},
		{"one byte per read", iotest.OneByteReader(strings.NewReader(in))},
		{"two reads, cut inside the final crlf", io.MultiReader(strings.NewReader(in[:len(in)-1]), strings.NewReader(in[len(in)-1:]))},
	} {
		t.Run(r.name, func(t *testing.T) {
			got, err := sseLines(t, r.rd)
			if err != nil {
				t.Fatalf("scan error: %v", err)
			}
			if strings.Join(got, "|") != strings.Join(want, "|") {
				t.Errorf("lines = %q, want %q (a CRLF read as two line endings)", got, want)
			}
		})
	}

	// The split function itself, called as the Scanner calls it when the CR
	// is the last byte buffered and the stream has not ended: no decision.
	var s sseLineSplitter
	if adv, tok, err := s.split([]byte("data: a\r"), false); adv != 0 || tok != nil || err != nil {
		t.Errorf("CR at buffer end before EOF decided (%d, %q, %v); want more data", adv, tok, err)
	}
	if adv, tok, err := s.split([]byte("data: a\r"), true); adv != 8 || string(tok) != "data: a" || err != nil {
		t.Errorf("CR at buffer end at EOF = (%d, %q, %v); want (8, \"data: a\", nil)", adv, tok, err)
	}
}

// The head guard on its own (#4182): it writes one BOM ahead of a BOM-led
// first write, nothing ahead of any other first write, and never again after
// the first write, whatever the later writes begin with.
func TestSSEHeadGuard(t *testing.T) {
	bom := string(utf8BOM)
	for _, tc := range []struct {
		name   string
		writes []string
		want   string
	}{
		{"bom-led head", []string{bom + "x\n", "y\n"}, bom + bom + "x\n" + "y\n"},
		{"plain head", []string{"x\n", bom + "y\n"}, "x\n" + bom + "y\n"},
		{"blank head", []string{"\n", bom + "y\n"}, "\n" + bom + "y\n"},
		{"empty write does not decide the head", []string{"", bom + "x\n"}, bom + bom + "x\n"},
		{"double bom head gets one more", []string{bom + bom + "x\n"}, bom + bom + bom + "x\n"},
		{"bom alone", []string{bom}, bom + bom},
		{"partial bom is not a bom", []string{"\xEF\xBBx\n"}, "\xEF\xBBx\n"},
	} {
		var out strings.Builder
		g := &sseHeadGuard{w: &out}
		for _, w := range tc.writes {
			n, err := g.Write([]byte(w))
			if err != nil || n != len(w) {
				t.Fatalf("%s: Write(%q) = (%d, %v), want (%d, nil)", tc.name, w, n, err, len(w))
			}
		}
		if out.String() != tc.want {
			t.Errorf("%s: forwarded %q, want %q", tc.name, out.String(), tc.want)
		}
	}
}

// The limits relaySSEStream always had: a line that does not fit in
// sseMaxLineBytes together with its terminator ends the scan with
// bufio.ErrTooLong after the lines before it were delivered (bufio.Scanner
// needs the terminator inside the buffer to see the line end; ScanLines on
// main had the same bound, counting a CRLF's CR against it too). The longest
// line that goes through is sseMaxLineBytes-1 bytes ended by LF.
func TestSSELineSplitter_MaxLine(t *testing.T) {
	if sseLineBufferBytes != 1<<20 || sseMaxLineBytes != 10<<20 {
		t.Fatalf("limits = %d/%d; changing them is a decision, not a refactor", sseLineBufferBytes, sseMaxLineBytes)
	}
	t.Run("over the limit", func(t *testing.T) {
		long := strings.Repeat("x", sseMaxLineBytes)
		got, err := sseLines(t, strings.NewReader("data: before\n\n"+long+"\ndata: after\n\n"))
		if !errors.Is(err, bufio.ErrTooLong) {
			t.Fatalf("err = %v, want bufio.ErrTooLong", err)
		}
		if strings.Join(got, "|") != "data: before|" {
			t.Errorf("lines before the cut = %q, want the first event's lines only", got)
		}
	})
	t.Run("longest line through", func(t *testing.T) {
		exact := strings.Repeat("y", sseMaxLineBytes-1)
		got, err := sseLines(t, strings.NewReader(exact+"\ndata: after\n"))
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if len(got) != 2 || got[0] != exact || got[1] != "data: after" {
			t.Errorf("got %d lines; want the %d-byte line and the one after it", len(got), sseMaxLineBytes-1)
		}
	})
	t.Run("crlf counts its cr against the bound, as on main", func(t *testing.T) {
		exact := strings.Repeat("y", sseMaxLineBytes-1)
		_, err := sseLines(t, strings.NewReader(exact+"\r\ndata: after\n"))
		if !errors.Is(err, bufio.ErrTooLong) {
			t.Fatalf("err = %v, want bufio.ErrTooLong (the CR fills the buffer before the LF arrives)", err)
		}
	})
}
