package shellparse

import (
	"strings"
	"unicode/utf8"

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
	return decodeEmitted(command, false, func(w string, st octalStyle) (string, bool) {
		return decodeEscapes(w, st, false)
	})
}

// DecodeEmittedProse is DecodeEmittedSeparators for a reader that is not a
// shell (#4604): the LLM that later reads the text a command writes to a file
// or to the agent's own stdout. That reader exists whether or not anything
// executes the text, so there is no executor gate. And because zsh (the shell
// Claude Code's Bash tool runs on a stock Mac) and /bin/sh decode escapes in a
// plain `echo` with no -e, an echo operand is decoded with or without the flag.
// Bash's builtin does not, so for bash this reading can differ from what is
// written; it is therefore a PROSE-ONLY candidate form for the guardian (the
// structural signals never see it) and it decodes only whitespace and control
// bytes, so it can split a word run and never join one: it can only add a match.
func DecodeEmittedProse(command string) string {
	if !strings.ContainsRune(command, '\\') {
		return ""
	}
	return decodeEmitted(command, true, func(w string, st octalStyle) (string, bool) {
		return decodeEscapes(w, st, true)
	})
}

// DecodeEmittedInvisible is the byte-escape sibling of DecodeEmittedProse
// (#4604): a printf format, and an echo operand on zsh or /bin/sh, writes
// `\xe2\x80\xae` as the three bytes of U+202E, so the file the LLM reads holds a
// bidi override the command text never spells. Only a run of adjacent escapes
// whose bytes are exactly invisible characters from invisibleSteganoRunes is
// decoded; every other escape is left as written, so the output can add an
// invisible character and never a visible one. A prose-only candidate for the
// guardian's unicode_steganography check.
func DecodeEmittedInvisible(command string) string {
	if !strings.ContainsRune(command, '\\') {
		return ""
	}
	return decodeEmitted(command, true, decodeInvisibleEscapes)
}

// DecodeEmittedInvisibleWrapped is the second reading of DecodeEmittedInvisible
// (#4604, the #4660 fix round): a printf or echo behind an execution wrapper —
// `sudo printf`, `env -i echo`, `nohup printf`, `command printf`, `nice -n 5
// printf` — but emittedEscapeWords keys on Args[0] and so saw a program named
// `sudo`. The wrapper parity sweeps found it once TP-STEG-AI-003 decided BLOCK:
// bare it BLOCKs, behind any wrapper it AUDITed.
//
// What the wrapped program writes depends on which program runs, so every
// decode here must rest on bytes some real target writes (class 4 of the alias
// exception: identical bytes; Gary, 2026-10-30). Measured on macOS that day
// (zsh 5, bash 3.2, /bin/sh = bash in POSIX mode with xpg_echo):
//
//   - printf behind any wrapper: GNU printf decodes \x, octal and \u
//     (documented, not measured here); BSD /usr/bin/printf decodes octal.
//     Decoded as the bare call is.
//   - echo behind a wrapper that runs a program (sudo, env, nohup, nice,
//     exec, ...): that is /bin/echo, and no platform's /bin/echo decodes
//     without -e. Not decoded without -e (Gary's 10-30 decision). With -e, GNU
//     echo decodes \x and \0ddd but has no \u, so \u is not decoded.
//   - `command echo`: the builtin in bash and /bin/sh, but /bin/echo in zsh
//     (zsh's `command` names an external command). /bin/sh's builtin decodes
//     \x and \0ddd without -e; nothing decodes \u. Decoded without \u.
//   - `builtin echo` and zsh's precommand words (`noglob echo`, ...): zsh's
//     builtin, which decodes all three. Decoded as the bare call is.
//
// See wrapperRunner. Prose-only and invisible-only, so it can add a signal and
// never remove one.
//
// Each call whose Args[0] is an exec wrapper is read again from the command
// the wrappers run, located by execWrapperTarget — the isExecWrapper /
// wrapperTargetIndex walk that StripExecWrapperPrefix (regex layer) and
// StripExecWrappers (AST layers) share. So the wrapper set and each wrapper's
// option grammar (`env -i`, `sudo -u x`, `nice -n 5`, `flock -w 5 FILE`) are
// the ones the wrapper parity sweeps already gate; there is no list here.
//
// An ADDITIONAL candidate, never a replacement: DecodeEmittedInvisible is
// unchanged, and this returns "" unless a wrapped call contributed a decoded
// run, so whenever it returns text that text differs from the first reading
// and the caller keeps both. A bare printf/echo in the same command is decoded
// here too, exactly as the first reading decodes it.
func DecodeEmittedInvisibleWrapped(command string) string {
	if !strings.ContainsRune(command, '\\') {
		return ""
	}
	return decodeEmittedReading(command, true, true, decodeInvisibleEscapes)
}

// wrapperRunner is what runs a printf/echo behind a chain of wrappers.
type wrapperRunner int

const (
	// runsShellBuiltin: `builtin` and zsh's precommand words (noglob,
	// nocorrect, -, repeat N) keep the shell's own echo/printf.
	runsShellBuiltin wrapperRunner = iota
	// runsViaCommand: `command` keeps the builtin in bash and /bin/sh but runs
	// the external program in zsh.
	runsViaCommand
	// runsProgram: any other wrapper execs a program (sudo, env, nohup, nice,
	// exec, timeout, a path-qualified `/usr/bin/command`, ...).
	runsProgram
)

// emittedWrapperTarget returns the index in call.Args of the printf/echo that
// call's leading wrappers run (0 when there is none) and what runs it. The
// wrappers are execWrapperHops' (the ExecWrappers walk); `builtin` is not in
// that table, so one `builtin` word on the target is read here too (bash, zsh
// and /bin/sh all run their own builtin behind it). The most external hop
// wins: `command sudo echo` is /bin/echo.
func emittedWrapperTarget(call *syntax.CallExpr) (int, wrapperRunner) {
	target, words, hops := execWrapperHops(call)
	runner := runsShellBuiltin
	for _, h := range hops {
		switch name := NormalizeExecName(words[h]); {
		case isShellWord(name):
		case name == "command":
			if runner == runsShellBuiltin {
				runner = runsViaCommand
			}
		default:
			runner = runsProgram
		}
	}
	if target+1 < len(words) && NormalizeExecName(words[target]) == "builtin" {
		target++
	}
	return target, runner
}

// invisibleSteganoRunes is the set the guardian's unicode_steganography check
// counts (heuristic.go matchesUnicodeSteganography).
var invisibleSteganoRunes = map[rune]bool{
	'\u202e': true, '\u200b': true, '\u200c': true, '\u200d': true,
	'\u2060': true, '\u2061': true, '\u2062': true, '\u2063': true, '\u2064': true,
}

// decodeInvisibleEscapes decodes each maximal run of adjacent \xHH or octal
// escapes whose bytes are all invisibleSteganoRunes, leaving all else as is.
func decodeInvisibleEscapes(s string, style octalStyle) (string, bool) {
	var b strings.Builder
	changed := false
	for i := 0; i < len(s); {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		// Read the run of byte escapes starting here.
		var bytes []byte
		j := i
		for j+1 < len(s) && s[j] == '\\' {
			var v byte
			var n int
			var ok bool
			if (s[j+1] == 'u' || s[j+1] == 'U') && style != octalEchoNoUnicode {
				// bash 4.2+ and zsh: \uHHHH / \UHHHHHHHH write the UTF-8 of one
				// character. Only an invisibleSteganoRunes member is accepted.
				enc, used := readUnicodeEscape(s[j+1:])
				if used == 0 {
					break
				}
				bytes = append(bytes, enc...)
				j += used + 1
				continue
			}
			if s[j+1] == 'x' {
				v, n, ok = readHexEscape(s[j+2:])
				n += 2
			} else {
				v, n, ok = readOctalEscape(s[j+1:], style)
				n++
			}
			if !ok {
				break
			}
			bytes = append(bytes, v)
			j += n
		}
		if len(bytes) > 0 && invisibleOnly(bytes) {
			b.Write(bytes)
			changed = true
			i = j
			continue
		}
		// Not ours: emit both bytes so an escaped backslash is never re-read.
		b.WriteByte(s[i])
		b.WriteByte(s[i+1])
		i += 2
	}
	if !changed {
		return s, false
	}
	return b.String(), true
}

// readUnicodeEscape reads `u` or `U` plus up to 4 or 8 hex digits from s (s
// starts at the u/U). It returns the UTF-8 of the character and the bytes
// consumed from s, or (nil, 0) when there is no digit or the character is not
// one of invisibleSteganoRunes.
func readUnicodeEscape(s string) ([]byte, int) {
	max := 4
	if s[0] == 'U' {
		max = 8
	}
	var v rune
	n := 0
	for n < max && 1+n < len(s) {
		d := hexVal(s[1+n])
		if d < 0 {
			break
		}
		v = v<<4 | rune(d)
		n++
	}
	if n == 0 || !invisibleSteganoRunes[v] {
		return nil, 0
	}
	return []byte(string(v)), 1 + n
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func invisibleOnly(bs []byte) bool {
	str := string(bs)
	for _, r := range str {
		if r == utf8.RuneError || !invisibleSteganoRunes[r] {
			return false
		}
	}
	return str != ""
}

// decodeEmitted is the shared walk. echoAlways decodes echo operands without -e;
// dec rewrites one operand word.
func decodeEmitted(command string, echoAlways bool, dec func(string, octalStyle) (string, bool)) string {
	return decodeEmittedReading(command, echoAlways, false, dec)
}

// decodeEmittedReading is decodeEmitted with an opt-in second reading:
// lookThrough also reads a call whose Args[0] is an exec wrapper from the
// command the wrapper runs (see DecodeEmittedInvisibleWrapped), and then
// returns "" unless such a wrapped call changed something. With lookThrough
// false the walk, the splice and the result are exactly decodeEmitted's.
func decodeEmittedReading(command string, echoAlways, lookThrough bool, dec func(string, octalStyle) (string, bool)) string {
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
		wrapped    bool
	}
	var targets []span
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		words, style := emittedEscapeWords(call, echoAlways)
		wrapped := false
		if len(words) == 0 && lookThrough {
			// Only a call the first reading did not take: a call it did take
			// is a printf/echo already, and is decoded identically below.
			if t, runner := emittedWrapperTarget(call); t > 0 {
				// /bin/echo decodes nothing without -e (Gary, 2026-10-30).
				words, style = emittedEscapeWords(&syntax.CallExpr{Args: call.Args[t:]}, echoAlways && runner != runsProgram)
				if style == octalEcho && runner != runsShellBuiltin {
					style = octalEchoNoUnicode
				}
				wrapped = true
			}
		}
		for _, w := range words {
			targets = append(targets, span{int(w.Pos().Offset()), int(w.End().Offset()), style, wrapped})
		}
		return true
	})
	if len(targets) == 0 {
		return ""
	}

	var b strings.Builder
	b.Grow(len(command))
	prev, changed, wrappedChanged := 0, false, false
	for _, t := range targets {
		if t.start < prev || t.end > len(command) || t.start >= t.end {
			continue // defensive: never splice on offsets that do not bracket
		}
		b.WriteString(command[prev:t.start])
		decoded, did := dec(command[t.start:t.end], t.style)
		b.WriteString(decoded)
		changed = changed || did
		wrappedChanged = wrappedChanged || (did && t.wrapped)
		prev = t.end
	}
	b.WriteString(command[prev:])
	if !changed || (lookThrough && !wrappedChanged) {
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
	// octalEchoNoUnicode is echo's dialect where no runtime decodes \u:
	// the wrapped reading's /bin/echo -e and `command echo` (#4660).
	octalEchoNoUnicode
)

// emittedEscapeWords returns the words of call whose escape sequences the
// program expands — printf's format operand, or every operand of `echo -e` —
// along with which octal dialect that program speaks.
func emittedEscapeWords(call *syntax.CallExpr, echoAlways bool) ([]*syntax.Word, octalStyle) {
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
		if !sawE && !echoAlways {
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
	return decodeEscapes(s, style, false)
}

// decodeEscapes is decodeSeparatorEscapes with an opt-in for the plain space
// (0x20), which the regex-stage reading leaves alone and the prose reading
// (#4604) needs: `\x20` is the escape-spelled space of an injected sentence.
func decodeEscapes(s string, style octalStyle, allowSpace bool) (string, bool) {
	isSep := func(v byte) bool { return isSeparatorByte(v) || (allowSpace && v == ' ') }
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
			if v, n, ok := readHexEscape(s[i+2:]); ok && isSep(v) {
				b.WriteByte(v)
				changed = true
				i += 2 + n
				continue
			}
		}
		if v, n, ok := readOctalEscape(s[i+1:], style); ok && isSep(v) {
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
	case octalEcho, octalEchoNoUnicode:
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
