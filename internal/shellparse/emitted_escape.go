package shellparse

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// DecodeEmittedSeparators rewrites the escape sequences a `printf` format
// string or an `echo -e` argument will EXPAND into whitespace, replacing each
// with the character the program actually emits — but only when that text is
// handed to an executor.
//
// Returns "" (the no-op sentinel every candidate-form transform in this package
// uses) when the command does not parse, when no text reaches an executor, or
// when there is nothing to decode.
//
// # The bypass (#3802)
//
// The inertness work of #3796 and #3800 established that text piped into a
// shell, or written to a path the command then executes, is a program rather
// than documentation — so its is_doc_text / in_heredoc label is withdrawn. That
// gets the rule *considered*. It still has to MATCH, and it is matched against
// the raw command text:
//
//	echo "ufw disable" | sh            BLOCK   ts-block-ufw-disable
//	printf '\nufw disable\n' | sh      no rule — and it executes
//
// The shell hands `sh` a real newline either way. In the raw text the two
// characters before the payload are a backslash and an `n`, both word
// characters, so a rule whose `command_regex` opens with `\b` cannot match
// there. Recomputed on this tree at merge time: 285 of 1377 `command_regex`
// lines in packs/ open with `\b` (#3802 said 263; it was measured on an
// earlier checkout). That is the population EXPOSED to a leading-escape
// prefix, not a count of confirmed leaks — the confirmed figure is the
// corpus measurement below.
//
// Measured over the corpus on 2026-09-13, restricted to BLOCKing commands that
// still BLOCK through the `echo '<cmd>' | sh` control (which proves the
// pipe-to-executor machinery already handles them, so the leak isolates the
// anchor and not a rule gap): **403 of 1310 — 30.8% — stopped blocking** when
// the same payload arrived behind a leading `\n`, `\t`, or `echo -e` escape.
// After this transform, 0.
//
// # The executor gate, and an honest account of what it buys
//
// TextReachesExecutor is the same question the two intent.go sites ask before
// honouring an inertness label. Reusing it is not convenience — it is the
// claim: this is #3796/#3800 one layer down. Those two say "when text reaches
// an executor it is not inert"; this says "when text reaches an executor its
// escape sequences are separators, because that is what the producer emits."
// One piece of evidence, two consequences.
//
// What the gate is NOT, measured rather than assumed: it is not currently the
// thing preventing a false positive. Deleting it and running the full analyzer
// corpus regresses NOTHING, and four constructed release-note shapes
// (`printf 'Changes:\nrm -rf support added\n'` and friends) decide identically
// with it and without it — the is_doc_text labels already suppress them. So the
// first version of this comment, which asserted the gate was "the whole safety
// argument", was an overclaim; it is recorded here so nobody re-derives it.
//
// It is kept anyway, for a reason that is about coupling rather than about a
// measured FP. Without it this transform's correctness would rest on the
// doc-text label system continuing to cover these shapes — and that system is
// the single most actively churning boundary in this package (#3792, #3796,
// #3798, #3800 are four consecutive issues about labels not applying where
// someone assumed they did). The gate makes the transform's own claim true
// independently, for the cost of one predicate that is already computed. The
// FP shape it would catch if a label boundary moved is a decode that SPLITS a
// word run in text nothing executes: `printf 'Changes:\nrm -rf ...'` produces a
// `\brm\b` match that the raw text does not contain.
//
// # Why only separators
//
// Decoding is restricted to escapes that yield ASCII whitespace or a control
// character, in every spelling (`\n`, `\x0a`, `\012`). A printable-character
// escape is deliberately left alone.
//
// That restriction is what makes the transform incapable of inventing a threat.
// It can only ever SPLIT a run of characters apart, never join two innocent
// tokens into a dangerous one — so every new match it enables is a match
// against text the shell genuinely produces at that boundary. Hex and octal
// escapes that decode to printable letters are a different class (the `$'...'`
// ANSI-C family, already handled by pathnorm for the executable position) and
// are not guessed at here.
//
// # Scope, and why each edge is where it is
//
//   - `printf`: the FORMAT operand only. Bash processes escapes in the format,
//     not in the interpolated arguments (`printf '%s\n' "$x"` does not decode
//     `$x`), so decoding an argument would rewrite text the shell never touches.
//   - `echo`: only when `-e` is present, and then every operand. Without `-e`
//     bash's builtin echo emits the backslash literally, so there is nothing to
//     decode and pretending otherwise would invent a separator.
//   - A parse failure yields "". Same posture as every sibling transform: a
//     wrong reconstruction of an unparseable blob is a false BLOCK, and the
//     output here is only ever an ADDITIONAL match candidate, so refusing costs
//     a miss while guessing costs a wrong enforcement.
func DecodeEmittedSeparators(command string) string {
	if !strings.ContainsRune(command, '\\') {
		return ""
	}
	if !TextReachesExecutor(command) {
		return ""
	}
	// A second parse, of the RAW text: AnalyzeTextReach parses the
	// IFS-normalized form, whose byte offsets do not address this string.
	// Splicing on offsets from the wrong parse is silent corruption, so the
	// walk below gets its own.
	file := parseBashFile(command)
	if file == nil {
		return ""
	}

	type span struct {
		start, end int
		style      octalStyle
	}
	var targets []span
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		words, style := emittedEscapeWords(call)
		for _, w := range words {
			targets = append(targets, span{int(w.Pos().Offset()), int(w.End().Offset()), style})
		}
		return true
	})
	if len(targets) == 0 {
		return ""
	}

	var b strings.Builder
	b.Grow(len(command))
	prev, changed := 0, false
	for _, t := range targets {
		if t.start < prev || t.end > len(command) || t.start >= t.end {
			continue // defensive: never splice on offsets that do not bracket
		}
		b.WriteString(command[prev:t.start])
		decoded, did := decodeSeparatorEscapes(command[t.start:t.end], t.style)
		b.WriteString(decoded)
		changed = changed || did
		prev = t.end
	}
	b.WriteString(command[prev:])
	if !changed {
		return ""
	}
	return b.String()
}

// octalStyle distinguishes the two programs' octal escapes, which genuinely
// differ — measured against bash 3.2 on 2026-09-13:
//
//	printf 'a\0011b'    -> a 0x01 '1' b     (\ddd: 1-3 octal digits, leading 0 counts)
//	echo -e 'a\0011b'   -> a 0x09 b         (\0ddd: the 0 is a marker, then 1-3 digits)
//	printf 'a\101b'     -> a 'A' b          (no leading 0 needed)
//
// Getting this wrong decodes one byte too many or too few. It is a detail, but
// it is a detail about what the executor actually receives, and this whole
// transform exists because that is the thing the matcher has to see.
type octalStyle int

const (
	octalNone octalStyle = iota
	octalPrintf
	octalEcho
)

// emittedEscapeWords returns the words of call whose escape sequences the
// program expands — printf's format operand, or every operand of `echo -e` —
// along with which octal dialect that program speaks.
func emittedEscapeWords(call *syntax.CallExpr) ([]*syntax.Word, octalStyle) {
	if len(call.Args) == 0 {
		return nil, octalNone
	}
	name := execBaseName(call.Args[0])
	rest := call.Args[1:]
	switch name {
	case "printf":
		// Skip printf's own options and `-v NAME`. The first remaining operand
		// is the format; everything after it is interpolated, not decoded.
		for i := 0; i < len(rest); i++ {
			lit, _ := literalWordValue(rest[i])
			switch {
			case lit == "--":
				if i+1 < len(rest) {
					return []*syntax.Word{rest[i+1]}, octalPrintf
				}
				return nil, octalNone
			case lit == "-v":
				i++ // consume the variable name
			case strings.HasPrefix(lit, "-") && lit != "-":
				// another option; keep scanning
			default:
				return []*syntax.Word{rest[i]}, octalPrintf
			}
		}
		return nil, octalNone
	case "echo":
		var out []*syntax.Word
		sawE, inOptions := false, true
		for _, w := range rest {
			lit, _ := literalWordValue(w)
			if inOptions && len(lit) > 1 && lit[0] == '-' && isEchoOptionCluster(lit) {
				if strings.ContainsRune(lit, 'e') {
					sawE = true
				}
				continue
			}
			inOptions = false
			out = append(out, w)
		}
		if !sawE {
			return nil, octalNone
		}
		return out, octalEcho
	}
	return nil, octalNone
}

// isEchoOptionCluster reports whether tok is one of echo's option clusters
// (-e, -n, -E, and combinations). Anything else beginning with "-" is an
// operand echo will print, not a flag.
func isEchoOptionCluster(tok string) bool {
	for _, r := range tok[1:] {
		if r != 'e' && r != 'n' && r != 'E' {
			return false
		}
	}
	return true
}

// execBaseName resolves a command word to the program it names, stripping
// shell quoting and any directory ("/usr/bin/printf" -> "printf").
func execBaseName(w *syntax.Word) string {
	lit, ok := literalWordValue(w)
	if !ok || lit == "" {
		return ""
	}
	name := NormalizeExecName(lit)
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// decodeSeparatorEscapes replaces every escape sequence in s that yields ASCII
// whitespace or a control character with that character, and reports whether
// anything changed.
//
// The scan consumes BOTH bytes of an escape it declines to decode, `\\`
// included. Without that, `printf 'a\\nb'` — a literal backslash followed by
// the letter n — would decode as a newline, inventing a separator the shell
// never emits. Same lexical discipline, and the same failure mode if dropped,
// as pathnorm.FoldObfuscatingBackslashesUnquoted.
func decodeSeparatorEscapes(s string, style octalStyle) (string, bool) {
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for i := 0; i < len(s); {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		c := s[i+1]
		if simple, ok := simpleSeparatorEscapes[c]; ok {
			b.WriteByte(simple)
			changed = true
			i += 2
			continue
		}
		if c == 'x' {
			if v, n, ok := readHexEscape(s[i+2:]); ok && isSeparatorByte(v) {
				b.WriteByte(v)
				changed = true
				i += 2 + n
				continue
			}
		}
		if v, n, ok := readOctalEscape(s[i+1:], style); ok && isSeparatorByte(v) {
			b.WriteByte(v)
			changed = true
			i += 1 + n
			continue
		}
		// Not a separator escape (`\\`, `\"`, `\$`, `\x41`, ...): emit both
		// bytes untouched so the next iteration cannot re-read the escaped
		// character as the start of a new escape.
		b.WriteByte(s[i])
		b.WriteByte(c)
		i += 2
	}
	if !changed {
		return s, false
	}
	return b.String(), true
}

// simpleSeparatorEscapes is the two-character escape set common to printf(1)
// and `echo -e`, restricted to the ones that produce whitespace or a control
// character. `\e` (ESC) is an echo/GNU extension and is included for the same
// reason: it is a control byte, never part of a word.
var simpleSeparatorEscapes = map[byte]byte{
	'n': '\n', 't': '\t', 'r': '\r', 'v': '\v',
	'f': '\f', 'a': '\a', 'b': '\b', 'e': 0x1b,
}

func isSeparatorByte(v byte) bool {
	return v < 0x20 || v == 0x7f
}

// readHexEscape reads the 1-2 hex digits of a `\xHH` escape, returning the
// byte, how many digits were consumed, and whether any were.
func readHexEscape(s string) (byte, int, bool) {
	v, n := 0, 0
	for n < 2 && n < len(s) {
		d, ok := hexDigit(s[n])
		if !ok {
			break
		}
		v = v*16 + d
		n++
	}
	if n == 0 {
		return 0, 0, false
	}
	return byte(v), n, true
}

// readOctalEscape reads an octal escape body in the dialect style speaks,
// returning the byte, how many characters were consumed after the backslash,
// and whether it read one at all. See octalStyle for the measured difference.
func readOctalEscape(s string, style octalStyle) (byte, int, bool) {
	consumed := 0
	switch style {
	case octalPrintf:
		// \ddd — up to three octal digits, a leading 0 being one of them.
	case octalEcho:
		// \0ddd — the 0 is a required marker and is not part of the value.
		if len(s) == 0 || s[0] != '0' {
			return 0, 0, false
		}
		s, consumed = s[1:], 1
	default:
		return 0, 0, false
	}
	v, n := 0, 0
	for n < 3 && n < len(s) && s[n] >= '0' && s[n] <= '7' {
		v = v*8 + int(s[n]-'0')
		n++
	}
	if n == 0 || v > 0xff {
		return 0, 0, false
	}
	return byte(v), consumed + n, true
}

func hexDigit(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	}
	return 0, false
}
