package shellparse

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
)

// osascript as a shell-source carrier (#4900).
//
// `osascript -e '… do shell script "CMD" …'` runs CMD through /bin/sh -c: the
// interpreter `bash -c` names, under an AppleScript carrier. No layer read
// through it, so the dogfood canary wrapped this way decided a ruleless AUDIT
// while the bare and `bash -c` spellings BLOCKed on four rules.
//
// The reading reuses the shell-source carrier path rather than adding one:
// ShellSourceArg returns the recovered shell source as SourceArg, and
// CarriesShellSource / ExtractInlineCode then hand it to the sub-parse and to
// InlineCodeFragments exactly as they do `man -P` or `env -S`. The outer
// command is still evaluated as written, so its own rules (#4888's
// `with administrator privileges` AUDIT) keep firing, and the combiner takes
// the stricter of outer and inner.
//
// What is read, and what deliberately is not:
//
//   - Every `-e` statement, in order, joined with newlines: that is how
//     osascript(1) assembles a multi-line script from several -e options.
//     Options stop at `--` or at the first operand, as BSD getopt does; an
//     operand is a script FILE, or (after -e) the script's own argv, which
//     is data and never read.
//   - `do shell script` (any case) and its raw event spelling
//     `«event sysoexec»`, outside string literals and comments. The direct
//     parameter is an AppleScript string: `\"` `\\` `\n` `\r` `\t` are its
//     escapes. Literals joined with `&`, parentheses, and `quoted form of` a
//     literal are evaluated; any other operand (a variable, `POSIX path of
//     …`) has no static value and reads as the neutral word
//     appleScriptExprPlaceholder, so the literal text around it is still
//     evaluated. A call whose parameter holds no literal text adds nothing.
//   - `with administrator privileges` changes WHO runs the command, not
//     what runs. The engine has no elevation notion to record it in (a
//     `sudo` prefix would scope to the first statement only), so the command
//     is unwrapped as is; the outer rule records the elevation.
//   - Out of scope (#4900): script files, stdin and heredoc scripts, and
//     JXA (`-l JavaScript`, `doShellScript`). A language other than
//     AppleScript yields no reading, the same as main.
//
// Every `do shell script` call runs in its own /bin/sh. Joining them into one
// shell source can let one call's syntax error hide the next from the
// sub-parse; the regex layer still sees the joined text. Accepted: a call
// that fails stops the AppleScript unless it sits in a `try` block.

// appleScriptExprPlaceholder stands for an AppleScript operand with no static
// value. A plain word, not a shell expansion: an expansion of an unset name
// can fold to nothing (NormalizeUnsetParamExp), and `"rm -rf /" & sub` must
// not read as `rm -rf /`.
const appleScriptExprPlaceholder = "__applescript_expr__"

// maxAppleScriptParenDepth bounds the recursion through nested parentheses in
// a do shell script parameter. Past it the operand reads as the placeholder.
const maxAppleScriptParenDepth = 8

// isOsascript reports whether word names osascript, accepting an absolute or
// home-anchored path the way lookupShellSource does. A relative ./osascript
// is not resolved.
func isOsascript(word string) bool {
	name := NormalizeExecName(word)
	if name == "osascript" {
		return true
	}
	return (strings.HasPrefix(name, "/") || strings.HasPrefix(name, "~/")) && path.Base(name) == "osascript"
}

// osascriptShellSource returns the shell source the `do shell script` calls in
// osascript's -e statements run, as one single-quoted shell word, or "". The
// quoting is what lets ExtractInlineCode's payloadValue recover the source
// byte for byte, the same as it recovers a quoted `bash -c` payload.
func osascriptShellSource(args []string) string {
	cmds := osascriptShellCommands(args, osascriptArgValue)
	if len(cmds) == 0 {
		return ""
	}
	return "'" + strings.ReplaceAll(strings.Join(cmds, "\n"), "'", `'"'"'`) + "'"
}

// identityArgValue is the argValue for an argv that already holds runtime
// values (ShellSourceArgValue): there is no outer quoting left to remove.
func identityArgValue(v string) string { return v }

// osascriptShellCommands returns the command of every `do shell script` call
// in osascript's -e statements, in order. argValue maps one argv word to the
// value osascript receives: osascriptArgValue for raw word text, the identity
// for words that are values already.
func osascriptShellCommands(args []string, argValue func(string) string) []string {
	var stmts []string
	lang := ""
	for i := 0; i < len(args); i++ {
		w := argValue(args[i])
		if w == "--" || len(w) < 2 || w[0] != '-' {
			break
		}
		// A short-option cluster: -i takes no value; -e, -l and -s take the
		// rest of the cluster, or else the next word.
		for j := 1; j < len(w); j++ {
			opt := w[j]
			if opt != 'e' && opt != 'l' && opt != 's' {
				continue
			}
			val := w[j+1:]
			if val == "" {
				if i+1 >= len(args) {
					return nil // osascript refuses a missing value and runs nothing
				}
				i++
				val = argValue(args[i])
			}
			switch opt {
			case 'e':
				stmts = append(stmts, val)
			case 'l':
				lang = val
			}
			break
		}
	}
	if len(stmts) == 0 || (lang != "" && !strings.EqualFold(lang, "AppleScript")) {
		return nil
	}
	return appleScriptShellCommands(strings.Join(stmts, "\n"))
}

// osascriptArgValue is the value osascript receives for one argv word: the
// outer shell's quote removal, done exactly. payloadValue is not enough here:
// it keeps the backslash of `\"` inside a double-quoted word, and in
// `-e "do shell script \"CMD\""` that backslash is what hides the AppleScript
// string delimiter. A part with no static value (`$VAR`) is kept as its
// source text, as unwrapOuterQuotes keeps it for `bash -c "… $VAR"`.
func osascriptArgValue(raw string) string {
	if !strings.ContainsAny(raw, "'\"\\$`") {
		return raw
	}
	word, ok := parseLoneWord(raw)
	if !ok {
		return unwrapOuterQuotes(raw)
	}
	var b strings.Builder
	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(unescapeUnquoted(p.Value))
		case *syntax.SglQuoted:
			if p.Dollar {
				decoded, _ := pathnorm.DecodeANSICEscapes(p.Value)
				b.WriteString(decoded)
				continue
			}
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				if lit, isLit := inner.(*syntax.Lit); isLit {
					b.WriteString(unescapeDblQuoted(lit.Value))
					continue
				}
				b.WriteString(WordToString(&syntax.Word{Parts: []syntax.WordPart{inner}}))
			}
		default:
			b.WriteString(WordToString(&syntax.Word{Parts: []syntax.WordPart{part}}))
		}
	}
	return b.String()
}

// appleScriptShellCommands returns the command of every `do shell script`
// call in script, in order, skipping string literals, comments (`--`, `#`,
// nested `(* … *)`) and |piped identifiers|, where the phrase is not a call.
func appleScriptShellCommands(script string) []string {
	var out []string
	s := script
	for i := 0; i < len(s); {
		switch {
		case s[i] == '"':
			_, i, _ = readAppleScriptString(s, i)
		case strings.HasPrefix(s[i:], "--") || s[i] == '#':
			if nl := strings.IndexByte(s[i:], '\n'); nl >= 0 {
				i += nl + 1
			} else {
				i = len(s)
			}
		case strings.HasPrefix(s[i:], "(*"):
			i = skipAppleScriptBlockComment(s, i)
		case s[i] == '|':
			if end := strings.IndexByte(s[i+1:], '|'); end >= 0 {
				i += end + 2
			} else {
				i = len(s)
			}
		default:
			end := matchDoShellScript(s, i)
			if end < 0 {
				i++
				continue
			}
			r := newAppleScriptReader(s)
			r.concat(end, 0)
			if r.literal && r.ok {
				if cmd := r.b.String(); cmd != "" {
					out = append(out, cmd)
				}
			}
			// Resume right after the phrase, not after the parameter, so a
			// call nested inside it (`… & (do shell script "…")`) is found
			// too. The parameter's own string literals are skipped above.
			i = end
		}
	}
	return out
}

// matchDoShellScript returns the index just past `do shell script` (blank
// between the words, any case) or `«event sysoexec»` at i, or -1. The phrase
// must start a word: `undo shell script` is not a call.
func matchDoShellScript(s string, i int) int {
	if strings.HasPrefix(s[i:], "«event sysoexec»") {
		return i + len("«event sysoexec»")
	}
	if i > 0 && isAppleScriptIdentByte(s[i-1]) {
		return -1
	}
	return matchAppleScriptWords(s, i, "do", "shell", "script")
}

// appleScriptReader evaluates the direct parameter of one do shell script
// call: an `&` chain of operands, written into b.
type appleScriptReader struct {
	s       string
	b       strings.Builder
	literal bool // a string literal contributed text
	ok      bool // every literal read was terminated
}

func newAppleScriptReader(s string) *appleScriptReader {
	return &appleScriptReader{s: s, ok: true}
}

// concat reads an `&` chain starting at j and returns the index after it.
func (r *appleScriptReader) concat(j, depth int) int {
	for {
		j = r.operand(skipAppleScriptBlank(r.s, j), depth)
		k := skipAppleScriptBlank(r.s, j)
		if k >= len(r.s) || r.s[k] != '&' {
			return j
		}
		j = k + 1
	}
}

// operand reads one operand at j into b and returns the index after it.
func (r *appleScriptReader) operand(j, depth int) int {
	s := r.s
	if j >= len(s) {
		return j
	}
	switch {
	case s[j] == '"':
		lit, next, terminated := readAppleScriptString(s, j)
		if !terminated {
			r.ok = false // an unterminated literal never compiles: nothing runs
		}
		r.b.WriteString(lit)
		r.literal = true
		return next
	case s[j] == '(' && depth < maxAppleScriptParenDepth:
		inner := newAppleScriptReader(s)
		next := skipAppleScriptBlank(s, inner.concat(j+1, depth+1))
		if next < len(s) && s[next] == ')' {
			next++
		}
		r.b.WriteString(inner.b.String())
		r.literal = r.literal || inner.literal
		r.ok = r.ok && inner.ok
		return next
	}
	if after := matchAppleScriptWords(s, j, "quoted", "form", "of"); after >= 0 {
		inner := newAppleScriptReader(s)
		next := inner.operand(skipAppleScriptBlank(s, after), depth+1)
		if inner.literal && !strings.Contains(inner.b.String(), appleScriptExprPlaceholder) {
			r.b.WriteString("'" + strings.ReplaceAll(inner.b.String(), "'", `'\''`) + "'")
			r.literal = true
		} else {
			r.b.WriteString(appleScriptExprPlaceholder)
		}
		r.ok = r.ok && inner.ok
		return next
	}
	r.b.WriteString(appleScriptExprPlaceholder)
	return skipAppleScriptOperand(s, j)
}

// skipAppleScriptOperand returns the end of a non-literal operand at j: the
// next `&`, `)`, line break or comment outside parentheses and string
// literals.
func skipAppleScriptOperand(s string, j int) int {
	depth := 0
	for j < len(s) {
		if s[j] == '#' || strings.HasPrefix(s[j:], "--") {
			return j
		}
		switch s[j] {
		case '"':
			_, j, _ = readAppleScriptString(s, j)
			continue
		case '(':
			depth++
		case ')':
			if depth == 0 {
				return j
			}
			depth--
		case '&', '\n', '\r':
			if depth == 0 {
				return j
			}
		}
		j++
	}
	return j
}

// readAppleScriptString reads the string literal whose opening quote is at i
// and returns its value, the index after the closing quote, and whether the
// literal was terminated. The escapes are AppleScript's: \" \\ \n \r \t; any
// other backslash stays as written.
func readAppleScriptString(s string, i int) (string, int, bool) {
	var b strings.Builder
	for j := i + 1; j < len(s); j++ {
		switch c := s[j]; {
		case c == '"':
			return b.String(), j + 1, true
		case c == '\\' && j+1 < len(s):
			j++
			switch s[j] {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case '"', '\\':
				b.WriteByte(s[j])
			default:
				b.WriteByte('\\')
				b.WriteByte(s[j])
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), len(s), false
}

// skipAppleScriptBlockComment returns the index after the (possibly nested)
// `(* … *)` comment opening at i.
func skipAppleScriptBlockComment(s string, i int) int {
	depth := 0
	for i < len(s) {
		switch {
		case strings.HasPrefix(s[i:], "(*"):
			depth++
			i += 2
		case strings.HasPrefix(s[i:], "*)"):
			depth--
			i += 2
			if depth == 0 {
				return i
			}
		default:
			i++
		}
	}
	return i
}

// matchAppleScriptWords returns the index after the words at j (any case,
// separated by spaces or tabs, the last one ending a word), or -1.
func matchAppleScriptWords(s string, j int, words ...string) int {
	for n, kw := range words {
		if n > 0 {
			k := skipAppleScriptBlank(s, j)
			if k == j {
				return -1
			}
			j = k
		}
		if len(s)-j < len(kw) || !strings.EqualFold(s[j:j+len(kw)], kw) {
			return -1
		}
		j += len(kw)
	}
	if j < len(s) && isAppleScriptIdentByte(s[j]) {
		return -1
	}
	return j
}

// skipAppleScriptBlank skips what may separate two tokens of one statement:
// spaces, tabs, `(* … *)` comments, and the `¬` line continuation with its
// line break. Without the last two, `do shell script (* *) "CMD"` and a call
// split across two -e lines with `¬` would hide CMD.
func skipAppleScriptBlank(s string, j int) int {
	for j < len(s) {
		switch {
		case s[j] == ' ' || s[j] == '\t':
			j++
		case strings.HasPrefix(s[j:], "(*"):
			j = skipAppleScriptBlockComment(s, j)
		case strings.HasPrefix(s[j:], "¬"):
			k := j + len("¬")
			for k < len(s) && (s[k] == ' ' || s[k] == '\t') {
				k++
			}
			switch {
			case strings.HasPrefix(s[k:], "\r\n"):
				j = k + 2
			case k < len(s) && (s[k] == '\n' || s[k] == '\r'):
				j = k + 1
			default:
				return j
			}
		default:
			return j
		}
	}
	return j
}

func isAppleScriptIdentByte(c byte) bool {
	return c == '_' || ('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}
