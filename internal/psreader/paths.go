package psreader

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/AI-AgentLens/agentshield/internal/facts"
)

// Env is what path resolution needs to know about the machine the text runs
// on. The zero value is usable: the home directory is then known only as `~`
// and environment variables take their Windows defaults.
type Env struct {
	// Home is the user's home directory as the OS spells it, for example
	// `C:\Users\alice` or `/Users/alice`. A path that starts with it is
	// rewritten to start with `~`. Empty when unknown.
	Home string
	// Vars are environment variables by name, matched case-insensitively as
	// Windows does: USERPROFILE, APPDATA, LOCALAPPDATA, TEMP and so on. A
	// variable that is absent takes its Windows default (defaultVars).
	Vars map[string]string
}

// defaultVars are the Windows defaults for variables the caller did not
// supply, keyed in upper case. The user-profile ones are relative to `~`, so
// they resolve the same whatever the home directory is called. A variable in
// neither place is left as written.
var defaultVars = map[string]string{
	"USERPROFILE":       "~",
	"HOME":              "~",
	"APPDATA":           "~/AppData/Roaming",
	"LOCALAPPDATA":      "~/AppData/Local",
	"TEMP":              "~/AppData/Local/Temp",
	"TMP":               "~/AppData/Local/Temp",
	"SYSTEMDRIVE":       "C:",
	"SYSTEMROOT":        "C:/Windows",
	"WINDIR":            "C:/Windows",
	"PROGRAMDATA":       "C:/ProgramData",
	"ALLUSERSPROFILE":   "C:/ProgramData",
	"PROGRAMFILES":      "C:/Program Files",
	"PROGRAMFILES(X86)": "C:/Program Files (x86)",
	"PROGRAMW6432":      "C:/Program Files",
	"PUBLIC":            "C:/Users/Public",
}

// Bounds on path extraction (Opus pass 2 on #4245). A word's suffix
// spellings (after `=`, `,`, `@` or a non-drive `:`) used to be resolved one
// by one to the end of the word, and each became a mention the back end
// matched against every pattern under three readings: an attacker-built word
// of 24 KB took 40 s, past Copilot's 30 s hook timeout, which fails open.
// The bounds only ever touch mentions, never a whole-value path.
const (
	// maxSuffixesPerWord bounds the suffix spellings one word yields. A word
	// with more stops there and the read is marked bounded (a note, so the
	// decision is at least AUDIT).
	maxSuffixesPerWord = 32
	// maxCandidateBytes clips a suffix spelling before it is resolved: longer
	// than any path a filesystem opens (Linux's PATH_MAX). Every shipped
	// protected pattern is anchored at its start (`~/.ssh/**`, `~/.netrc`),
	// so the clip keeps every one of their matches.
	maxCandidateBytes = 4096
)

// clipCandidate is s cut to maxCandidateBytes, on a UTF-8 boundary.
func clipCandidate(s string) string {
	if len(s) <= maxCandidateBytes {
		return s
	}
	cut := maxCandidateBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// resolver is an Env prepared for one Read.
type resolver struct {
	// bounded is set when a word had more suffix spellings than
	// maxSuffixesPerWord, so some were not read.
	bounded bool

	home string            // Env.Home with `/` separators and no trailing `/`
	vars map[string]string // upper-cased names
}

func newResolver(env Env) *resolver {
	r := &resolver{home: strings.TrimRight(slashes(env.Home), "/"), vars: map[string]string{}}
	for k, v := range env.Vars {
		r.vars[strings.ToUpper(k)] = v
	}
	return r
}

func (r *resolver) lookup(name string) (string, bool) {
	up := strings.ToUpper(name)
	if v, ok := r.vars[up]; ok {
		return v, true
	}
	v, ok := defaultVars[up]
	return v, ok
}

// fileSystemProviderRe is PowerShell's FileSystem provider qualifier,
// written short or module-qualified, any letter case:
// `FileSystem::C:\x` and `Microsoft.PowerShell.Core\FileSystem::C:\x` name the
// file `C:\x`. Other providers (`Registry::`, `Env::`, `Cert::`) name no
// file, so their qualifier is kept and the value matches no path pattern.
var fileSystemProviderRe = regexp.MustCompile(`^(?i:(?:microsoft\.powershell\.core[\\/])?filesystem::)`)

// stripFileSystemProvider drops a leading FileSystem provider qualifier.
func stripFileSystemProvider(p string) string {
	if loc := fileSystemProviderRe.FindStringIndex(p); loc != nil {
		return p[loc[1]:]
	}
	return p
}

// bareArgument is v's spelling when v is a bare word handed to a command as
// an argument: one word with no separator, not a parameter (`-x`) and not a
// variable (`$x`), such as `id_rsa` in `Get-Content id_rsa`. It is a path
// relative to the directory the text runs in, so it is a whole value: the
// back end reads it under cwd, where it can match only when cwd is inside a
// protected directory or a protected pattern is itself relative. Bash keeps
// such an operand as a path too (normalize.bareOperandPath, #4381/#4673).
func (r *resolver) bareArgument(v string) (string, bool) {
	w := trimQuotes(v)
	if w == "" || w == facts.Expr || w == facts.Dynamic || strings.ContainsAny(w, `/\`) {
		return "", false
	}
	if c := []rune(w)[0]; isDash(c) || c == '$' || c == '@' {
		return "", false
	}
	// Trailing spaces are not part of the name Windows opens
	// (win32TrimComponents); any other whitespace makes it prose.
	if core := strings.TrimRight(w, " "); core == "" || strings.IndexFunc(core, unicode.IsSpace) >= 0 {
		return "", false
	}
	p := r.resolve(w)
	if p == "" || isPathLike(p) {
		return "", false // a path-like value is wholeValue's
	}
	return p, true
}

// redirectionTarget is a redirection target's path: always a whole value,
// relative to cwd when it is not absolute, because `> x` writes the file x
// however it is spelled. `$null` and `NUL` (any case) discard the output and
// name no file.
func (r *resolver) redirectionTarget(t string) (string, bool) {
	w := trimQuotes(t)
	if w == "" || strings.EqualFold(w, "$null") || strings.EqualFold(w, "nul") {
		return "", false
	}
	p := r.resolve(w)
	return p, p != ""
}

// wholeValue is v's resolved spelling when the whole value is path-like: the
// one spelling of v that is a facts.Facts path rather than a mention.
func (r *resolver) wholeValue(v string) (string, bool) {
	w := trimQuotes(v)
	if w == "" {
		return "", false
	}
	p := r.resolve(w)
	return p, isPathLike(p)
}

// optionValue is the value of an option written as one word,
// `-name=value` or `--name=value`, resolved, when it is path-like. A native
// program receives it exactly as it receives `--name value`, whose value is
// a whole value, so it is one too: the two spellings of one argument decide
// alike (`kubectl --kubeconfig=<path>` is the consumer slot either way). A
// value with whitespace is not an option word, and `@file` or `name=value`
// without a dash stay mentions.
func (r *resolver) optionValue(v string) (string, bool) {
	w := trimQuotes(v)
	m := optionWordRe.FindStringSubmatch(w)
	if m == nil {
		return "", false
	}
	p := r.resolve(m[1])
	return p, isPathLike(p)
}

var optionWordRe = regexp.MustCompile(`^--?[A-Za-z][A-Za-z0-9_-]*=(\S+)$`)

// wholePaths are the whole-value spellings of v: the value itself and, for
// an option word, its value (optionValue).
func (r *resolver) wholePaths(v string) []string {
	return r.wholeSpellings(v, false)
}

// argumentPaths are wholePaths for a command's argument, which a bare word
// is too (bareArgument).
func (r *resolver) argumentPaths(v string) []string {
	return r.wholeSpellings(v, true)
}

func (r *resolver) wholeSpellings(v string, argument bool) []string {
	var out []string
	if p, ok := r.wholeValue(v); ok {
		out = append(out, p)
	} else if p, ok := r.bareArgument(v); ok && argument {
		out = append(out, p)
	}
	if p, ok := r.optionValue(v); ok && (len(out) == 0 || out[0] != p) {
		out = append(out, p)
	}
	return out
}

// valuePaths reports one value's path-like spellings by provenance
// (facts.Facts.Paths and Mentions): its whole-value spellings (wholePaths)
// to whole; every other spelling pathsIn finds in it, a word inside it or a
// suffix after `,`, `@`, `:` or a non-option `=`, to mention.
func (r *resolver) valuePaths(v string, whole, mention func(string)) {
	r.splitPaths(r.wholePaths(v), v, whole, mention)
}

// argumentValuePaths is valuePaths for a command's argument (argumentPaths).
func (r *resolver) argumentValuePaths(v string, whole, mention func(string)) {
	r.splitPaths(r.argumentPaths(v), v, whole, mention)
}

func (r *resolver) splitPaths(wps []string, v string, whole, mention func(string)) {
	isWhole := map[string]bool{}
	for _, p := range wps {
		isWhole[p] = true
		whole(p)
	}
	r.pathsIn(v, func(p string) {
		if !isWhole[p] {
			mention(p)
		}
	})
}

// pathsIn reports the path-like spellings in one value: the whole value and
// each whitespace-separated word, and in each of those the suffix after an
// `=`, `,`, `@` or a non-drive `:` (`--key=$HOME\.ssh\id`, `-Path:C:\x`).
// Each spelling is resolved (resolve) and kept when it is path-like.
func (r *resolver) pathsIn(v string, add func(string)) {
	r.wordPaths(v, add)
	for _, w := range strings.Fields(v) {
		if w != v {
			r.wordPaths(w, add)
		}
	}
}

func (r *resolver) wordPaths(w string, add func(string)) {
	w = trimQuotes(w)
	if w == "" {
		return
	}
	if p := r.resolve(w); isPathLike(p) {
		add(p)
	}
	n := 0
	for i := 1; i < len(w); i++ {
		c := w[i-1]
		if c == '=' || c == ',' || c == '@' || (c == ':' && i-1 != 1) {
			if s := w[i:]; startsPath(s) {
				if n == maxSuffixesPerWord {
					r.bounded = true
					return
				}
				n++
				if p := r.resolve(clipCandidate(s)); isPathLike(p) {
					add(p)
				}
			}
		}
	}
}

// startsPath reports whether s begins the way a path or a reference that
// resolves to one begins.
func startsPath(s string) bool {
	if s == "" {
		return false
	}
	switch s[0] {
	case '~', '$', '/', '\\', '%', '.':
		return true
	}
	return len(s) >= 2 && isASCIILetter(s[0]) && s[1] == ':'
}

// resolve rewrites one spelling the way the filesystem will see it:
// variables replaced (resolveVars), a filesystem provider qualifier and a
// `file://` prefix dropped, `\` read as `/`, repeated separators collapsed,
// trailing spaces and dots dropped from each component as Windows does
// (win32TrimComponents), and the home directory spelled `~`. Letter case is
// kept.
func (r *resolver) resolve(w string) string {
	p := stripFileSystemProvider(r.resolveVars(w))
	if lp := asciiLower(p); strings.HasPrefix(lp, "file:///") && len(p) > 9 && p[9] == ':' {
		p = p[len("file:///"):]
	} else if strings.HasPrefix(lp, "file://") {
		p = p[len("file://"):]
	}
	p, literal := stripWin32Namespace(slashes(p))
	if !literal {
		p = win32TrimComponents(p)
	}
	return r.foldHome(p)
}

// stripWin32Namespace removes a Win32 namespace prefix from a path with `/`
// separators, so the path it names is read as the drive or UNC path it is:
// `\\?\C:\x` and `\\.\C:\x` open `C:\x`, and `\\?\UNC\srv\share\x` and
// `\\.\UNC\srv\share\x` open `\\srv\share\x` (Opus pass 2 on #4245: the
// prefix hid a protected path, and on a managed host the config directory,
// from every check). literal reports a `\\?\` path, which Win32 passes on
// unnormalized, so its components are not trimmed (win32TrimComponents); a
// `\\.\` path is normalized like any other. After the prefix, `~` is the
// home as the reader spells a profile variable it has no value for
// (`\\?\$env:USERPROFILE\…`, defaultVars), which on Windows is a drive
// path. A prefix followed by anything else (a device, a pipe, a volume
// GUID) is left as written: it names no path a pattern spells.
func stripWin32Namespace(p string) (_ string, literal bool) {
	if len(p) < 4 || p[0] != '/' || p[1] != '/' || (p[2] != '?' && p[2] != '.') || p[3] != '/' {
		return p, false
	}
	literal = p[2] == '?'
	rest := p[4:]
	switch {
	case len(rest) >= 4 && strings.EqualFold(rest[:4], "unc/"):
		return "//" + rest[4:], literal
	case len(rest) >= 3 && isDriveLetter(rest[0]) && rest[1] == ':' && rest[2] == '/',
		rest == "~" || strings.HasPrefix(rest, "~/"):
		return rest, literal
	}
	return p, false
}

func isDriveLetter(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// win32TrimComponents drops trailing spaces and dots from each path
// component, as Win32 path normalization does: `Get-Content "x\cred "`,
// `"x\cred."` and `"x\cred. "` all open `x\cred` (measured on Windows 10
// with -LiteralPath, -Path and [IO.File]::ReadAllText). `.` and `..` keep
// their meaning, and a component that would become empty is kept as
// written. A `\\?\` path, which Win32 passes through unnormalized, is left
// alone: resolve skips the trim for one stripWin32Namespace stripped, and
// the check here keeps any other. Applied on every OS: the stricter reading
// costs only a file whose name really ends in a space or a dot.
func win32TrimComponents(p string) string {
	if strings.HasPrefix(p, "//?/") || !strings.ContainsAny(p, " .") {
		return p
	}
	parts := strings.Split(p, "/")
	for i, c := range parts {
		if c == "" || c == "." || c == ".." {
			continue
		}
		if t := strings.TrimRight(c, " ."); t != "" {
			parts[i] = t
		}
	}
	return strings.Join(parts, "/")
}

// foldHome spells a path under the home directory with `~`, comparing case
// the way NTFS and APFS do (insensitively).
func (r *resolver) foldHome(p string) string {
	h := r.home
	if h == "" || h == "~" || len(p) < len(h) || !strings.EqualFold(p[:len(h)], h) {
		return p
	}
	if len(p) == len(h) || p[len(h)] == '/' {
		return "~" + p[len(h):]
	}
	return p
}

// resolveVars replaces, anywhere in w, the references that name a known
// location: $HOME and ${HOME} (PowerShell's automatic variable), $env:NAME
// and ${env:NAME} (both case-insensitive), and %NAME%, which PowerShell
// leaves alone but cmd and the native programs it starts expand. A reference
// to anything else is left as written.
func (r *resolver) resolveVars(w string) string {
	if !strings.ContainsAny(w, "$%") {
		return w
	}
	var b strings.Builder
	for i := 0; i < len(w); {
		c := w[i]
		if c == '$' {
			if val, n, ok := r.dollarRef(w[i:]); ok {
				b.WriteString(val)
				i += n
				continue
			}
		}
		if c == '%' {
			if j := strings.IndexByte(w[i+1:], '%'); j > 0 {
				name := w[i+1 : i+1+j]
				if isEnvName(name) {
					if val, ok := r.lookup(name); ok {
						b.WriteString(val)
						i += j + 2
						continue
					}
				}
			}
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

// dollarRef reads one `$` reference at the start of s and returns its value,
// the bytes it spans, and whether it named a known location.
func (r *resolver) dollarRef(s string) (string, int, bool) {
	if strings.HasPrefix(s, "$(") {
		return r.subexpressionRef(s)
	}
	if strings.HasPrefix(s, "${") {
		end := strings.IndexByte(s, '}')
		if end < 0 {
			return "", 0, false
		}
		inner := s[2:end]
		if len(inner) > 4 && strings.EqualFold(inner[:4], "env:") {
			if v, ok := r.lookup(inner[4:]); ok {
				return v, end + 1, true
			}
			return "", 0, false
		}
		if strings.EqualFold(inner, "home") {
			return "~", end + 1, true
		}
		return "", 0, false
	}
	n := 1
	for n < len(s) && isVarNameByte(s[n]) {
		n++
	}
	name := s[1:n]
	if strings.EqualFold(name, "env") && n < len(s) && s[n] == ':' {
		m := n + 1
		for m < len(s) && isVarNameByte(s[m]) {
			m++
		}
		if v, ok := r.lookup(s[n+1 : m]); ok && m > n+1 {
			return v, m, true
		}
		return "", 0, false
	}
	if strings.EqualFold(name, "home") {
		return "~", n, true
	}
	return "", 0, false
}

// subexpressionRef reads a subexpression whose whole content is one known
// reference, `$($HOME)` or `$( $env:USERPROFILE )`, as that reference: the
// subexpression evaluates to the variable's value, so `"$($HOME)\.ssh\x"`
// names the file `"$HOME\.ssh\x"` does (#4765 item 3). Spaces and tabs may
// surround the reference; anything else in it (a command, an operator, a
// second reference) is computed, and the subexpression is left as written.
func (r *resolver) subexpressionRef(s string) (string, int, bool) {
	i := 2
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i >= len(s) || s[i] != '$' || strings.HasPrefix(s[i:], "$(") {
		return "", 0, false
	}
	v, n, ok := r.dollarRef(s[i:])
	if !ok {
		return "", 0, false
	}
	j := i + n
	for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
		j++
	}
	if j >= len(s) || s[j] != ')' {
		return "", 0, false
	}
	return v, j + 1, true
}

func isVarNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

func isEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isVarNameByte(s[i]) && s[i] != '(' && s[i] != ')' {
			return false
		}
	}
	return true
}

func isASCIILetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// slashes reads `\` as `/` and collapses repeated separators, keeping a
// leading `//` (a UNC path).
func slashes(s string) string {
	if !strings.ContainsAny(s, `\/`) {
		return s
	}
	s = strings.ReplaceAll(s, `\`, "/")
	if !strings.Contains(s, "//") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '/' && i > 1 && s[i-1] == '/' {
			continue
		}
		if s[i] == '/' && i == 1 && s[0] == '/' {
			b.WriteByte('/') // keep the UNC prefix
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// isPathLike is the experiment's predicate (compare.py's path_like): a
// separator anywhere, a leading `~`, or a drive letter. Broad on purpose: the
// back end matches Paths against specific protected paths, so a spelling
// that is not really a path costs nothing, while a path left out is a miss.
func isPathLike(p string) bool {
	if p == "" || p == "/" || p == "//" {
		return false
	}
	return strings.Contains(p, "/") || p[0] == '~' || len(p) >= 2 && isASCIILetter(p[0]) && p[1] == ':'
}

func isQuoteRune(c rune) bool { return isSQ(c) || isDQ(c) }

func trimQuotes(s string) string {
	return strings.TrimFunc(s, isQuoteRune)
}

// rawPaths is the second reading: it finds path-like spans in the raw text
// without the reader's grammar, resolves them the same way, and reports
// them. Its results are only ever added to Paths, so a reader mistake can
// drop a path from Commands or Strings but not from Paths.
//
// Spans are the runs between whitespace, quotes and `;|&<>,(){}` (with a
// `${…}` reference kept whole), plus the whole content of every quoted run,
// so a path with spaces in quotes is seen too. A span holding a backtick is
// also read with the backticks removed, PowerShell's escape character.
func (r *resolver) rawPaths(text string, add func(string)) {
	scan := func(tok string) {
		if tok == "" {
			return
		}
		r.pathsIn(tok, add)
		if strings.ContainsRune(tok, '`') {
			r.pathsIn(strings.ReplaceAll(tok, "`", ""), add)
		}
	}
	rs := []rune(text)
	var tok []rune
	flush := func() {
		scan(string(tok))
		tok = tok[:0]
	}
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == '$' && i+1 < len(rs) && rs[i+1] == '{':
			j := i + 2
			for j < len(rs) && rs[j] != '}' {
				j++
			}
			if j < len(rs) {
				j++
			}
			tok = append(tok, rs[i:j]...)
			i = j - 1
		case unicode.IsSpace(c) || strings.ContainsRune(";|&<>,(){}", c):
			flush()
		case isQuoteRune(c):
			flush()
			j := i + 1
			for j < len(rs) && !(isSQ(c) && isSQ(rs[j]) || isDQ(c) && isDQ(rs[j])) {
				j++
			}
			scan(string(rs[i+1 : j]))
		default:
			tok = append(tok, c)
		}
	}
	flush()
}
