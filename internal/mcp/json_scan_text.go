package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
)

// decodedJSONScanText returns a second rendering of a raw JSON value for text
// scanning — the DECODED view — when, and only when, the raw bytes contain an
// escape. The raw bytes are always scanned as before; this view is scanned in
// addition, and the two scans' findings are merged. Never concatenated.
//
// # Why a second view
//
// A host parses the JSON before any of it reaches the model, so the model
// reads decoded strings. A regex over the raw bytes reads escapes, and they
// differ in exactly the characters an attacker needs:
//
//   - one letter of an instruction-override phrase written as a \u escape
//     (`I` for "I"): the host shows the phrase, the regex sees a
//     backslash, and every text-pattern signal over the value goes quiet;
//   - a tokenizer role delimiter with its angle brackets written as
//     < / >;
//   - an ordinary newline between two words, which is the two characters
//     `\` `n` in raw JSON, so a `\s+` between them never matches;
//   - `\/`, a legal escape for `/`, inside a credential path;
//   - a zero-width character arriving as six ASCII characters, invisible to
//     the invisible-character detectors.
//
// Measured on ScanToolDescription before this: one \u letter escape in an
// outputSchema property description or in `_meta` took the text scan from
// poisoned to zero findings. Go's own json.Marshal causes the same blind spot
// from the other side — it escapes `<`, `>`, `&` and newlines — wherever a
// scanner re-marshals a decoded object (notification `data`, data-label args).
//
// # Why this shape — three Codex passes on #4059
//
// Appending decoded text to the raw bytes (pass 1) mixed two encodings into
// one string: newline-joined strings let `\s+` bridge enum values, escapes
// plus decoded Cyrillic crossed the mixed-script ratio gate, and the appended
// text overflowed a byte budget. REPLACING the raw bytes with a rendering
// (pass 2) lost matches the raw bytes had — a `.*` that spanned an escaped
// `\n` stops at a real newline — and sorting keys moved unrelated fields next
// to each other. Two independent scans, raw and decoded, merged by finding,
// is the only shape under which the raw scan can never lose a match and the
// decoded scan can never see a mixture.
//
// The decoded view is built to add nothing a server could not have sent:
//
//   - it is VALID JSON with the same members in the same order, so the
//     structural schema passes read the same document;
//   - strings are written with only `"` and `\` escaped; every other
//     character appears as itself, except C0 control characters, which become
//     a space — a decoded newline then separates words for `\s+` without
//     ending a `.*` the raw scan already let through;
//   - members and elements are separated by ",\n", so neither `.*` (which does
//     not cross a newline) nor `\s+` (which cannot cross `","`) can bridge two
//     fields into one match.
//
// Malformed JSON yields no decoded view: the raw scan is all there is.
func decodedJSONScanText(raw []byte) (string, bool) {
	if bytes.IndexByte(raw, '\\') < 0 {
		return "", false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// UseNumber: without it one valid but unrepresentable literal (1e400)
	// fails the decode and the decoded view is lost.
	dec.UseNumber()

	type frame struct {
		obj       bool
		n         int
		expectKey bool
	}
	var (
		b     strings.Builder
		stack []frame
	)
	before := func() {
		if len(stack) == 0 {
			return
		}
		f := &stack[len(stack)-1]
		switch {
		case f.obj && !f.expectKey:
			b.WriteByte(':')
		case f.n > 0:
			b.WriteString(",\n")
		}
	}
	after := func() {
		if len(stack) == 0 {
			return
		}
		f := &stack[len(stack)-1]
		if f.obj && f.expectKey {
			f.expectKey = false
			return
		}
		f.expectKey = f.obj
		f.n++
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", false
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				before()
				b.WriteByte(byte(t))
				stack = append(stack, frame{obj: t == '{', expectKey: t == '{'})
			default:
				if len(stack) == 0 {
					return "", false
				}
				stack = stack[:len(stack)-1]
				b.WriteByte(byte(t))
				after()
			}
		case string:
			before()
			writeScanString(&b, t)
			after()
		case json.Number:
			before()
			b.WriteString(t.String())
			after()
		case bool:
			before()
			b.WriteString(strconv.FormatBool(t))
			after()
		case nil:
			before()
			b.WriteString("null")
			after()
		}
	}
	return b.String(), true
}

// decodedValueScanText is decodedJSONScanText for a value that has already
// been decoded: it is marshalled, and a decoded view is returned only when the
// marshalled form carries an escape.
func decodedValueScanText(v interface{}) (string, bool) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", false
	}
	return decodedJSONScanText(raw)
}

// writeScanString writes s as a JSON string with only `"` and `\` escaped and
// C0 control characters replaced by a space (see decodedJSONScanText).
func writeScanString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r < 0x20:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}
