// Package pathnorm centralizes the shell quote/escape stripping that AgentShield
// applies before matching command tokens against protected-path and structural
// argument globs.
//
// A real shell removes single quotes, double quotes and backslash escapes during
// word-splitting/quote-removal before the command ever runs, so two spellings the
// shell treats as identical — cat ~/.ss'h'/id_r'sa' and cat ~/.ssh/id_rsa — must
// collapse to the same token before any glob/path comparison. Otherwise an inline
// quote-splice trivially bypasses the check (issue #2813, the GuardFall class).
//
// Keeping this in one leaf package (imported by shellparse, normalize and the
// structural analyzer) guarantees the executable-name, protected-path and
// argument-glob surfaces all strip quotes identically and can't drift apart.
package pathnorm

import (
	"runtime"
	"strings"
)

// StripShellQuotes removes the single quotes, double quotes and backslashes that
// a shell resolves away during quote-removal, so two spellings the shell treats
// as identical also compare identically here.
//
// Tokens carrying a dynamic expansion ($VAR, $(...), backticks) are returned
// unchanged — their runtime value can't be resolved statically, and blindly
// dropping the quotes would corrupt the expansion syntax. ANSI-C quoting
// ($'...') and locale-translated quoting ($"...") are the two "$"-prefixed
// forms that ARE statically resolvable — their content never depends on
// runtime state — so both are decoded first, via DecodeANSICEscapes and
// decodeDollarDoubleQuotedSpans respectively; only genuinely dynamic content
// left after that falls through to the unchanged-return path.
//
// $"..." (issue #3208): bash looks the enclosed text up in the current
// message catalog and falls back to the literal text when none matches —
// which, for the shell an AI agent drives, is always: no TEXTDOMAIN is set
// and no catalog is installed. So $"rm" runs exactly rm. Verified against
// bash 3.2.
//
// On Windows the quotes are removed by bash's own rules instead (#5049); see
// removeBashQuotes. Everywhere else the output is what it has always been.
func StripShellQuotes(s string) string {
	return stripShellQuotes(s, runtime.GOOS)
}

// StripShellQuotesFor is StripShellQuotes as goos runs it. Production code
// calls StripShellQuotes; this lets a caller's own tests take the Windows
// reading on any OS.
func StripShellQuotesFor(s, goos string) string {
	return stripShellQuotes(s, goos)
}

// MainShellQuotes is the reading StripShellQuotes gave on every OS before
// #5049, and still gives everywhere but Windows: the POSIX reading, which
// deletes every quote and backslash. It is main's half of the analyzer's
// stricter-of-two on Windows (#5049): a comparison whose match adds a finding
// counts if this reading or StripShellQuotes's matches, and one whose match
// takes a finding away needs both, so no decision is weaker than main's.
func MainShellQuotes(s string) string {
	return stripShellQuotes(s, "") // no GOOS is "": the POSIX reading
}

// stripShellQuotes is StripShellQuotes for the given GOOS, split out so the
// Windows reading is testable on every OS.
//
// The POSIX reading deletes every quote and backslash. That is quote removal
// for the spellings it was written for, but not for a backslash inside quotes:
// bash keeps every backslash between single quotes, and one before an ordinary
// character between double quotes. On POSIX that difference only ever reads a
// spliced name (`"~/.ss\h"`) as the name it imitates, so it stays as it is. On
// Windows the backslash is the path separator. Git Bash opens
// `cat 'C:\Users\u\'.aws/credentials`, and the POSIX reading turned the operand
// into the relative C:Usersu.aws/credentials, so protected_paths never saw it.
// Measured with Git Bash 5.2 on Windows 10, in #5049. (A word with no `/` at
// all, `"C:\Users\u\.aws\credentials"`, still reaches no path: normalize's
// looksLikePath requires a `/`.)
//
// The Windows branch is taken only for a word removeBashQuotes reads whole: no
// expansion, every quote closed, no trailing backslash. Any other word keeps
// the POSIX reading, on Windows too.
//
// A kept backslash that does not separate two names is then removed, as the
// POSIX reading removes it (keepSeparatingBackslashes). Git Bash reads one
// beside a `/` as part of a single separator, so `"/usr/bin/\rm"` runs
// /usr/bin/rm: keeping it would have hidden the program name from every rule
// that reads it, where main saw rm.
func stripShellQuotes(s, goos string) string {
	if s == "" {
		return s
	}
	if goos == "windows" && strings.ContainsAny(s, `'"\`) && !strings.ContainsAny(s, "$`") {
		if out, ok := removeBashQuotes(s); ok {
			return keepSeparatingBackslashes(out)
		}
	}
	working := s
	if decoded, ok := decodeDollarQuotedSpans(s); ok {
		working = decoded
	}
	if decoded, ok := decodeDollarDoubleQuotedSpans(working); ok {
		working = decoded
	}
	if strings.ContainsAny(working, "$`") {
		return s
	}
	if !strings.ContainsAny(working, `'"\`) {
		return working
	}
	var b strings.Builder
	b.Grow(len(working))
	for _, r := range working {
		if r == '\'' || r == '"' || r == '\\' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// removeBashQuotes is bash's quote removal for one word with no expansion in
// it (the caller has excluded `$` and backquote):
//
//	unquoted   \x -> x for any x; \<newline> -> nothing
//	'...'      verbatim, backslashes included
//	"..."      \ is removed only before " \ and <newline>; it is kept before
//	           any other character ($ and backquote never get here)
//
// ok is false for a word bash would not end here: an unclosed quote or a
// trailing backslash, which only a word sliced out of a longer one carries.
// The caller then keeps the POSIX reading.
func removeBashQuotes(s string) (string, bool) {
	var b strings.Builder
	b.Grow(len(s))
	n := len(s)
	for i := 0; i < n; i++ {
		switch s[i] {
		case '\\':
			if i+1 >= n {
				return "", false
			}
			i++
			if s[i] != '\n' {
				b.WriteByte(s[i])
			}
		case '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return "", false
			}
			b.WriteString(s[i+1 : i+1+end])
			i += 1 + end
		case '"':
			closed := false
			for i++; i < n; i++ {
				if s[i] == '"' {
					closed = true
					break
				}
				if s[i] == '\\' && i+1 < n {
					switch s[i+1] {
					case '"', '\\':
						i++
					case '\n':
						i++
						continue
					}
				}
				b.WriteByte(s[i])
			}
			if !closed {
				return "", false
			}
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String(), true
}

// keepSeparatingBackslashes removes each run of backslashes that does not sit
// between two names: one beside a `/`, or at either end of the word.
//
// On Windows a backslash is a separator. Beside a `/` it adds nothing: Git
// Bash runs `"/usr/bin/\cat"` and `'/usr/bin/\\cat'` as /usr/bin/cat and
// opens `"sub/\f.txt"` as sub/f.txt (#5049, rows A1, A3, O5). At the end of a
// word it is a trailing separator. At the start it is where a reading that
// cuts a word at its last `/` leaves one: shellparse's basename rendering of
// `"/usr/bin/\rm"` is `'\rm'`. For these backslashes the POSIX reading (delete
// them) names what main named, so they get it. A run between two names
// (`.ss\h` is .ss/h, `C:\Users`) is kept.
func keepSeparatingBackslashes(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	n := len(s)
	for i := 0; i < n; {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := i
		for j < n && s[j] == '\\' {
			j++
		}
		if i > 0 && j < n && s[i-1] != '/' && s[j] != '/' {
			b.WriteString(s[i:j])
		}
		i = j
	}
	return b.String()
}

// FoldHomeVar rewrites a leading $HOME or ${HOME} to ~, the spelling the
// protected-path matcher already expands.
//
// $HOME is the one variable every shell binds before the command runs, and
// the one real scripts spell instead of `~`; the substitution analyzer folds
// it the same way. Kept here so the protected-path token check, the
// consumer-slot walk and the bind-mount source extractor cannot drift apart.
//
// The fold requires a `/` or end-of-string after the name, so $HOMEBREW_PREFIX
// is left alone rather than becoming ~BREW_PREFIX.
func FoldHomeVar(s string) string {
	for _, prefix := range [...]string{"${HOME}", "$HOME"} {
		if !strings.HasPrefix(s, prefix) {
			continue
		}
		rest := s[len(prefix):]
		if rest == "" || rest[0] == '/' {
			return "~" + rest
		}
		return s
	}
	return s
}
