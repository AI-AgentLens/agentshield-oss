package pathnorm

import "strings"

// FoldPathCase returns s with every path-shaped span rewritten to the
// spelling a case-insensitive filesystem treats it as, or "" when that changes
// nothing (#4194).
//
// # Why
//
// macOS's default volume format (APFS) and Windows' NTFS are
// case-INSENSITIVE: a differently cased spelling of a credential path opens the
// very same file. Every layer that decides on a path compares it
// case-sensitively — pack regex literals, structural args_any globs, dataflow
// source classification and protected_paths are byte comparisons — so
// changing a path's letter case lowered 73% of home-path BLOCKs, most of them
// to ALLOW. The fold produces a spelling the packs are written against, so the
// evaluator can decide on it.
//
// # The spelling it produces
//
// ASCII letters in a path span are lowered — credential stores are dotfiles
// and dot-directories, spelled in lower case — except the names macOS itself
// defines with capitals, which are restored to their canonical spelling at the
// position the OS puts them: `/Users`, `/Library`, `/System`, … at the root,
// `Library`, `Documents`, … directly under a home directory, and
// `LaunchAgents`, `Keychains`, `Application Support`, … directly under a
// `Library`. That table is the OS layout (closed and documented), not a list
// of rules; see the level tables below. A vendor's own mixed-case name
// (`accessTokens.json`, Chrome's `Default/Login Data`) is NOT restored: there
// is no closed set of those, and the parity sweep pins them as the residual
// (TestCaseFoldCredentialPathParity).
//
// # What counts as a path span
//
// A span starts after a home anchor — `~/`, `~user/`, `$HOME/`, `${HOME}/` —
// or at a `/` that begins a word or follows `=`, `@`, `:`, `,`, `{` or a quote
// (`--kubeconfig=/…`, `curl -d @/…`, `open('/…')`), and runs to the next
// unquoted word break (whitespace, `;`, `&`, `|`, `(`, `)`, `<`, `>`, or a
// backquote). URLs are not paths and are left alone (`https://…`), except
// `file://`, whose remainder is one.
//
// Inside a span three things keep their case, because changing them would
// change what the shell runs rather than how the filesystem spells it:
//   - variable references (`$KEYFILE`, `${P1}`): shell names are
//     case-sensitive, and `$p` is not `$P`;
//   - the byte after a backslash (`\n` in a printf body, `\X41`);
//   - the user name in `~user/`.
//
// # ASCII only
//
// Go's `(?i)` and strings.ToLower apply Unicode folding, under which U+017F
// (long s) and U+212A (Kelvin sign) become `s` and `k` — the #3771 trap, where
// a fold on an EXCLUSION let a non-ASCII spelling switch a rule off. This fold
// is consumed only by a reading whose verdict can raise a decision and never
// lower one (policy.Engine.EvaluateCaseFold), but keeping it ASCII keeps it
// from being a confusable channel in its own right.
func FoldPathCase(s string) string {
	if !hasASCIIUpper(s) {
		return ""
	}
	b := []byte(s)
	for i := 0; i < len(s); {
		start, level := pathSpanStart(s, i)
		if start < 0 {
			i++
			continue
		}
		end := shellSpanEnd(s, start)
		foldSpan(b, s, start, end, level, true)
		if end <= i {
			end = i + 1
		}
		i = end
	}
	if string(b) == s {
		return ""
	}
	return string(b)
}

// FoldPathValue is FoldPathCase for a value that is not shell text — an MCP
// tool-call argument. Such a value has no word breaks: when it starts with a
// path anchor the WHOLE value is the path, spaces and shell metacharacters
// included (a profile under `Application Support`), so it is folded to its
// end. Variable references keep their case, as in FoldPathCase; a backslash is
// an ordinary byte here, not an escape. A value that does not start with an
// anchor (prose that mentions a path) is folded the shell way. Returns "" when
// there is nothing to change.
func FoldPathValue(s string) string {
	if !hasASCIIUpper(s) {
		return ""
	}
	start, level := pathSpanStart(s, 0)
	if start < 0 {
		return FoldPathCase(s)
	}
	b := []byte(s)
	foldSpan(b, s, start, len(s), level, false)
	if string(b) == s {
		return ""
	}
	return string(b)
}

// spanLevel is where in the filesystem layout a path segment sits, which
// decides whether it has an OS-defined canonical spelling.
type spanLevel int

const (
	levelRoot    spanLevel = iota // first segment of an absolute path
	levelVar                      // directly under /var
	levelSystem                   // directly under /System
	levelUser                     // a user name: directly under /Users or /home
	levelHome                     // directly under a home directory
	levelLibrary                  // directly under a Library directory
	levelOther                    // anywhere else: lower case
)

// The macOS layout names spelled with capitals, by level. Keys are the
// lower-case form. Only names Apple's layout defines belong here; a vendor
// directory (Google/Chrome, JetBrains) does not, however common.
var (
	rootNames = canonicalNames("Applications", "Library", "Network", "System", "Users", "Volumes")
	// /Users/Shared is the one OS-defined name at the user-name level.
	userNames    = canonicalNames("Shared")
	systemNames  = canonicalNames("Library")
	homeNames    = canonicalNames("Applications", "Desktop", "Documents", "Downloads", "Library", "Movies", "Music", "Pictures", "Public")
	libraryNames = canonicalNames(
		"Application Support", "Caches", "Calendars", "Containers", "Cookies",
		"Group Containers", "Keychains", "LaunchAgents", "LaunchDaemons", "Logs",
		"Mail", "Messages", "Mobile Documents", "Preferences",
		"PrivilegedHelperTools", "Safari", "StartupItems",
	)
)

func canonicalNames(names ...string) map[string]string {
	m := make(map[string]string, len(names))
	for _, n := range names {
		m[FoldASCII(n)] = n
	}
	return m
}

// foldSpan rewrites b[start:end) — the bytes of one path span of s — in two
// passes: lower every ASCII letter outside variable references (and, in shell
// text, outside backslash escapes), then restore the canonical spelling of
// each segment the macOS layout defines at its level.
func foldSpan(b []byte, s string, start, end int, level spanLevel, shell bool) {
	for j := start; j < end; {
		switch c := s[j]; {
		case shell && c == '\\':
			j += 2 // the escaped byte keeps its case
		case c == '$':
			j = skipVarRef(s, j)
		default:
			if c >= 'A' && c <= 'Z' {
				b[j] = c + ('a' - 'A')
			}
			j++
		}
	}
	segStart := start
	for j := start; j <= end; j++ {
		if j < end && s[j] != '/' {
			continue
		}
		seg := s[segStart:j]
		key := ""
		if !strings.Contains(seg, "$") {
			key = FoldASCII(strings.ReplaceAll(seg, `\`, ""))
		}
		if canon, ok := namesAt(level)[key]; ok && key != "" {
			restoreCase(b[segStart:j], canon)
		}
		level = nextLevel(level, key)
		segStart = j + 1
	}
}

func namesAt(level spanLevel) map[string]string {
	switch level {
	case levelRoot:
		return rootNames
	case levelUser:
		return userNames
	case levelSystem:
		return systemNames
	case levelHome:
		return homeNames
	case levelLibrary:
		return libraryNames
	}
	return nil
}

// nextLevel is the level of the segment after one whose folded text is key.
func nextLevel(level spanLevel, key string) spanLevel {
	switch level {
	case levelRoot:
		switch key {
		case "users", "home":
			return levelUser
		case "root":
			return levelHome
		case "var":
			return levelVar
		case "system":
			return levelSystem
		case "library":
			return levelLibrary
		}
	case levelVar:
		if key == "root" {
			return levelHome // macOS root's home, /var/root
		}
	case levelSystem, levelHome:
		if key == "library" {
			return levelLibrary
		}
	case levelUser:
		if key == "shared" {
			return levelOther
		}
		return levelHome
	}
	return levelOther
}

// restoreCase gives seg's letters the case of canon's, byte for byte, skipping
// backslashes in seg (an escaped space in `Application\ Support`). seg is
// known to equal canon once backslashes are removed and case folded.
func restoreCase(seg []byte, canon string) {
	c := 0
	for k := 0; k < len(seg) && c < len(canon); k++ {
		if seg[k] == '\\' {
			continue
		}
		seg[k] = canon[c]
		c++
	}
}

// shellSpanEnd is the index of the word break that ends a span starting at
// start in shell text — skipping escaped bytes and variable references, whose
// contents never end a word.
func shellSpanEnd(s string, start int) int {
	j := start
	for j < len(s) && !isPathSpanBreak(s[j]) {
		switch s[j] {
		case '\\':
			j += 2
		case '$':
			j = skipVarRef(s, j)
		default:
			j++
		}
	}
	if j > len(s) {
		j = len(s)
	}
	return j
}

// pathSpanStart reports where a path span opening at s[i] begins (the index of
// its first segment) and that segment's level, or -1 when no span opens at i.
func pathSpanStart(s string, i int) (int, spanLevel) {
	switch s[i] {
	case '~':
		// ~/ and ~user/ — the user name itself is not folded.
		j := i + 1
		for j < len(s) && isUserNameByte(s[j]) {
			j++
		}
		if j < len(s) && s[j] == '/' {
			return j + 1, levelHome
		}
		return -1, levelOther
	case '$':
		for _, anchor := range [...]string{"$HOME/", "${HOME}/"} {
			if strings.HasPrefix(s[i:], anchor) {
				return i + len(anchor), levelHome
			}
		}
		return -1, levelOther
	case '/':
		if i > 0 && !isPathOpener(s[i-1]) {
			return -1, levelOther
		}
		if i > 0 && s[i-1] == ':' && strings.HasPrefix(s[i:], "//") {
			// A URL scheme separator. file:// names a local path, so its
			// remainder is a span; every other scheme is left alone.
			if i >= 5 && strings.EqualFold(s[i-5:i], "file:") && strings.HasPrefix(s[i:], "///") {
				return i + 3, levelRoot
			}
			return -1, levelOther
		}
		return i + 1, levelRoot
	}
	return -1, levelOther
}

// isPathOpener reports whether a `/` directly after c begins a path.
func isPathOpener(c byte) bool {
	if isPathSpanBreak(c) {
		return true
	}
	switch c {
	case '=', '@', ':', ',', '{', '\'', '"':
		return true
	}
	return false
}

// isPathSpanBreak reports whether c ends a word, and so a path span.
func isPathSpanBreak(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', ';', '&', '|', '(', ')', '<', '>', '`':
		return true
	}
	return false
}

// skipVarRef returns the index just past the variable reference starting at
// s[j] == '$' — `$NAME`, `${…}`, or a special parameter (`$1`, `$@`). A lone
// `$` advances one byte.
func skipVarRef(s string, j int) int {
	j++
	if j >= len(s) {
		return j
	}
	if s[j] == '{' {
		if end := strings.IndexByte(s[j:], '}'); end >= 0 {
			return j + end + 1
		}
		return len(s)
	}
	k := j
	for k < len(s) && isVarNameByte(s[k]) {
		k++
	}
	if k == j && k < len(s) && !isPathSpanBreak(s[k]) {
		k++ // $1, $@, $? …
	}
	return k
}

func isVarNameByte(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

func isUserNameByte(c byte) bool {
	return isVarNameByte(c) || c == '.' || c == '-'
}

func hasASCIIUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}

// FoldASCII lowers ASCII upper-case letters only — the comparison key for a
// case-insensitive path match that must not fold non-ASCII confusables (see
// FoldPathCase).
func FoldASCII(s string) string {
	if !hasASCIIUpper(s) {
		return s
	}
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
