package analyzer

import (
	"path"
	"regexp"
	"strings"
	"unicode/utf8"

	pkgunicode "github.com/AI-AgentLens/agentshield/internal/unicode"
)

// capture_under_cwd (#4850): a regex rule whose evidence is "git ran in a
// directory nested inside the repository the session is in" names the
// capture group that holds the directory, and fires only on a match whose
// directory is strictly under the call's working directory.
//
// The gate can only remove a match main had, so every doubt keeps the match:
// an unknown or relative cwd, a directory this reading cannot resolve (a
// variable other than a leading $HOME, a substitution, a glob, an escape, an
// option word, ~user, a quote that does not wrap the whole word), a text past
// maxCwdCaptureBytes, more than maxCwdCaptureMatches matches, or a form the
// regex does not match at all (it matched through a reading this scan cannot
// see). Each of those returns true, which is main's verdict.

// maxCwdCaptureBytes bounds the text the scan reads. Past it the rule fires
// as on main. A real `cd <dir> && git commit` is a few hundred bytes; the bound
// keeps the submatch scan off adversarial texts the hook budget pays for
// (#4772).
const maxCwdCaptureBytes = 16 << 10

// maxCwdCaptureMatches bounds the overlapping match starts the scan reads.
// Past it the rule fires as on main.
const maxCwdCaptureMatches = 16

// CaptureInScope reports whether rule regexp re, matched against s, has a
// match whose group named `group` names a directory under cwd, or one this
// reading cannot resolve. home resolves a leading `~` or $HOME; empty leaves
// those unresolved. foldSeparators also scans s with Unicode separators
// folded, as command_fold_separators matches it.
//
// It is called only on a form the rule already matched, so a scan that finds
// no match in either reading returns true: the match came from somewhere this
// scan cannot see, and main's verdict stands.
func CaptureInScope(re *regexp.Regexp, s, group, cwd, home string, foldSeparators bool) bool {
	if re == nil || group == "" || !cwdUsable(cwd) {
		return true
	}
	idx := groupIndexes(re, group)
	if len(idx) == 0 {
		return true
	}
	inScope, matched := scanCaptures(re, s, idx, cwd, home)
	if inScope {
		return true
	}
	if foldSeparators {
		if folded, changed := pkgunicode.FoldUnicodeSeparators(s); changed {
			in2, m2 := scanCaptures(re, folded, idx, cwd, home)
			if in2 {
				return true
			}
			matched = matched || m2
		}
	}
	return !matched
}

// CaptureGroupDefined reports whether pattern compiles and defines a capture
// group named group. Load-time validation for capture_under_cwd.
func CaptureGroupDefined(pattern, group string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return len(groupIndexes(re, group)) > 0
}

func groupIndexes(re *regexp.Regexp, group string) []int {
	var idx []int
	for i, name := range re.SubexpNames() {
		if i > 0 && name == group {
			idx = append(idx, i)
		}
	}
	return idx
}

// scanCaptures reads every match START of re in s, overlapping ones too:
// `cd <cwd> && cd sub && git commit` is one leftmost match whose directory is
// cwd itself, and only the match that starts at the second cd names sub.
// matched reports whether re matched s at all.
func scanCaptures(re *regexp.Regexp, s string, idx []int, cwd, home string) (inScope, matched bool) {
	if len(s) > maxCwdCaptureBytes {
		return true, true
	}
	pos := 0
	for n := 0; pos <= len(s); n++ {
		if n == maxCwdCaptureMatches {
			return true, true
		}
		m := re.FindStringSubmatchIndex(s[pos:])
		if m == nil {
			return false, matched
		}
		matched = true
		dir, end, ok := participatingGroup(s[pos:], m, idx)
		if !ok || movesBeforeGit(s[pos+end:pos+m[1]]) || dirInScope(dir, cwd, home) {
			return true, true
		}
		_, size := utf8.DecodeRuneInString(s[pos+m[0]:])
		if size == 0 {
			return false, true
		}
		pos += m[0] + size
	}
	return false, matched
}

// participatingGroup returns the text of the first group in idx that took
// part in the match, and where it ends. ok is false when none did: a branch of
// the regex that holds no directory matched, and the scan cannot judge it.
func participatingGroup(s string, m []int, idx []int) (string, int, bool) {
	for _, i := range idx {
		if 2*i+1 < len(m) && m[2*i] >= 0 {
			return s[m[2*i]:m[2*i+1]], m[2*i+1], true
		}
	}
	return "", 0, false
}

// dirMoveRe finds, in the matched text after the directory word, anything
// that can move the directory git runs in away from that word (#4850 Opus
// pass 1, finding 1): another cd or pushd/popd the regex let sit between the
// cd and git (`cd <cwd> && cd "my dir" && git commit`, `cd sub 2>/dev/null`,
// `cd -P sub`), git's own -C, --git-dir or --work-tree, the GIT_DIR and
// GIT_WORK_TREE variables, and a substitution, eval or source that could run
// one. Over-matching only keeps main's match.
var dirMoveRe = regexp.MustCompile("\\b(?:cd|pushd|popd|eval|source)\\b|(?:^|\\s)-C|--git-dir|--work-tree|GIT_DIR|GIT_WORK_TREE|\\$\\(|`")

// movesBeforeGit reports whether tail, the matched text after the directory
// word, can move git elsewhere. Then the word does not say where git runs,
// and the match is kept.
func movesBeforeGit(tail string) bool {
	return dirMoveRe.MatchString(tail)
}

// dirInScope reports whether the directory word dir names a directory
// strictly under cwd, or one that cannot be resolved. cwd itself is not under
// cwd: `cd . && git commit` runs git where `git commit` does.
func dirInScope(dir, cwd, home string) bool {
	if !cwdUsable(cwd) {
		return true
	}
	if home != "" && !underOrAt(canonicalDir(slashed(home)), canonicalDir(slashed(cwd))) {
		// A cwd outside the engine's home is another machine's or another
		// user's (shield-server evaluates a remote client's call with its
		// own home), so `~` and $HOME are not known here (#4850 Opus pass 1,
		// follow-up 1).
		home = ""
	}
	d, ok := resolveDirWord(dir, cwd, home)
	if !ok {
		return true
	}
	c := canonicalDir(slashed(cwd))
	dd := canonicalDir(d)
	if isAbsDir(c) && !strings.HasPrefix(c, "/") {
		// A drive cwd (Claude Code on Windows) and Git Bash's spellings of a
		// drive path, /c/…, /mnt/c/…, /cygdrive/c/… (#4850 Opus pass 1,
		// finding 2).
		dd = foldDrivePrefix(dd)
	}
	return strictlyUnder(dd, c)
}

// foldDrivePrefix writes Git Bash's, WSL's and Cygwin's spelling of a drive
// path (/c/x, /mnt/c/x, /cygdrive/c/x) as the drive path (c:/x). p is
// lower-cased already.
func foldDrivePrefix(p string) string {
	for _, pre := range [...]string{"/cygdrive/", "/mnt/", "/"} {
		if !strings.HasPrefix(p, pre) {
			continue
		}
		rest := p[len(pre):]
		if len(rest) >= 1 && rest[0] >= 'a' && rest[0] <= 'z' && (len(rest) == 1 || rest[1] == '/') {
			return rest[:1] + ":/" + strings.TrimPrefix(rest[1:], "/")
		}
	}
	return p
}

// underOrAt reports whether d is cwd or under it.
func underOrAt(cwd, d string) bool {
	return d == cwd || strictlyUnder(d, cwd)
}

// resolveDirWord resolves a shell word naming a directory to a clean
// absolute path, or ok=false when the word's value is not literal text.
func resolveDirWord(word, cwd, home string) (string, bool) {
	w := word
	if len(w) >= 2 && (w[0] == '\'' || w[0] == '"') && w[len(w)-1] == w[0] {
		w = w[1 : len(w)-1]
	}
	switch {
	case w == "$HOME" || w == "${HOME}":
		if home == "" {
			return "", false
		}
		w = home
	case strings.HasPrefix(w, "$HOME/"):
		if home == "" {
			return "", false
		}
		w = home + w[len("$HOME"):]
	case strings.HasPrefix(w, "${HOME}/"):
		if home == "" {
			return "", false
		}
		w = home + w[len("${HOME}"):]
	case w == "~" || strings.HasPrefix(w, "~/"):
		if home == "" {
			return "", false
		}
		w = home + w[1:]
	}
	if w == "" || w[0] == '-' || w[0] == '~' || strings.ContainsAny(w, "$`'\"\\*?[{&|;<>()!") {
		return "", false
	}
	if isAbsDir(w) {
		return path.Clean(w), true
	}
	return path.Clean(slashed(cwd) + "/" + w), true
}

func cwdUsable(cwd string) bool {
	return cwd != "" && isAbsDir(slashed(cwd))
}

func isAbsDir(p string) bool {
	if strings.HasPrefix(p, "/") {
		return true
	}
	return len(p) >= 3 && p[1] == ':' && p[2] == '/' &&
		(p[0] >= 'A' && p[0] <= 'Z' || p[0] >= 'a' && p[0] <= 'z')
}

func slashed(p string) string { return strings.ReplaceAll(p, `\`, "/") }

// canonicalDir folds case and macOS's /private alias, on both sides, so a
// spelling difference can only make a directory count as under cwd, which
// keeps main's match.
func canonicalDir(p string) string {
	p = strings.ToLower(path.Clean(p))
	for _, a := range [...]string{"/private/tmp", "/private/var", "/private/etc"} {
		if p == a || strings.HasPrefix(p, a+"/") {
			return p[len("/private"):]
		}
	}
	return p
}

func strictlyUnder(d, cwd string) bool {
	if d == cwd {
		return false
	}
	if cwd == "/" {
		return strings.HasPrefix(d, "/")
	}
	return strings.HasPrefix(d, cwd+"/")
}
