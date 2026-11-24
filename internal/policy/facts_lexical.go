package policy

import (
	"path"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/facts"
)

// factsLexicalReading is the second reading EvaluateFacts gives a dialect
// lane's facts (#4830). It is f with two things the first reading cannot
// see, both ADDED to the lists they belong in, never replacing anything:
//
//   - each path with `.` or `..` segments, also spelled with them removed
//     (lexicalPath): `<home>\x\..\.agentshield\audit.jsonl`, `<dir>\.\x` and
//     `/./<home>/…` name the file the clean spelling does, because Windows
//     path normalization removes them before any file system sees the path,
//     and no pattern is written with them;
//   - each comma-array item's paths (facts.Element.ItemPaths) in its
//     element's Paths, which the pack rules' paths_any reads
//     (psMatcher.anyPath), and in Facts.Paths: `Remove-Item x.txt, <log>`
//     hands the cmdlet both items. A path-like item is in Facts.Paths on main
//     already; a bare name is not, though a lone bare argument is;
//   - each path that starts with `$PWD` (`${PWD}`, `$($PWD.Path)`, any case)
//     also spelled with pwd in its place (pwdPath), when pwd is not empty:
//     the reader keeps the variable as written, so `Set-Content
//     "$PWD\.agentshield\x" …` with cwd at home named no protected path.
//     factsPWD gives the call's cwd, and nothing for a text that changes
//     location, after which `$PWD` is somewhere else.
//
// ok is false when the reading adds nothing, so the text is read once. The
// reading is combined stricter-wins by EvaluateFacts, so it can only raise a
// decision; that is why it is a second reading and not a change to the
// reader (a replacing rewrite is not a parser's call: #4289, #4540).
func factsLexicalReading(f facts.Facts, home, pwd string) (facts.Facts, bool) {
	home = strings.TrimRight(strings.ReplaceAll(home, `\`, "/"), "/")
	changed := false
	// with is list plus extra and every lexical spelling of either, each
	// once, in that order. Linear: whole-value paths are not capped (a cap
	// could drop a BLOCK), so a long text can hold many.
	with := func(list []string, extra ...string) []string {
		seen := make(map[string]bool, len(list))
		for _, p := range list {
			seen[p] = true
		}
		var out []string
		add := func(p string) {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
		for _, p := range extra {
			add(p)
		}
		for _, src := range [][]string{list, extra} {
			for _, p := range src {
				if c, ok := lexicalPath(p, home); ok {
					add(c)
				}
				if c, ok := pwdPath(p, pwd, home); ok {
					add(c)
				}
			}
		}
		if len(out) == 0 {
			return list
		}
		changed = true
		return append(append([]string(nil), list...), out...)
	}

	var items []string
	for _, c := range f.Commands {
		for _, el := range c.Elements {
			items = append(items, el.ItemPaths...)
		}
	}
	g := f
	g.Paths = with(f.Paths, items...)
	g.Mentions = with(f.Mentions)
	g.Commands = make([]facts.Command, len(f.Commands))
	for i, c := range f.Commands {
		if len(c.Elements) > 0 {
			els := make([]facts.Element, len(c.Elements))
			for j, el := range c.Elements {
				el.Paths = with(el.Paths, el.ItemPaths...)
				els[j] = el
			}
			c.Elements = els
		}
		g.Commands[i] = c
	}
	if !changed {
		return f, false
	}
	return g, true
}

// lexicalPath is p, a lane's resolved path (`/` or `\` separators, home as
// `~`), with its `.` and `..` segments removed as Windows path normalization
// removes them: lexically, a `..` at a root dropped (`C:\..\x` is `C:\x`,
// `\\srv\share\..\x` is `\\srv\share\x`). `~` is expanded to home first, so
// `~/../<user>/.ssh` is `~/.ssh`; without a home a `..` above `~` leaves p
// as written. The result has `/` separators and the home folded back to `~`
// (compared case-insensitively, as the reader folds it), so `/./<home>/x`
// is `~/x`. ok is false when p has no such segment.
//
// It reads every path that way, POSIX ones included, where `x/..` goes
// through x's target when x is a symbolic link. That costs only a second
// reading naming a file the call may not open, combined stricter-wins; the
// `\\?\` prefix, under which Windows keeps the segments, is already gone
// from a lane's path, so that one is read the same way.
func lexicalPath(p, home string) (string, bool) {
	s := strings.ReplaceAll(p, `\`, "/")
	if !hasDotSegment(s) {
		return "", false
	}
	if s == "~" || strings.HasPrefix(s, "~/") {
		if home == "" || home == "~" {
			if climbsAboveRoot(s[1:]) {
				return "", false
			}
			c := path.Clean(s[1:])
			if c == "/" {
				c = ""
			}
			return "~" + c, true
		}
		s = home + s[1:]
	}
	c, ok := cleanRooted(s)
	if !ok {
		return "", false
	}
	c = foldHomePrefix(c, home)
	if c == strings.ReplaceAll(p, `\`, "/") {
		return "", false
	}
	return c, true
}

// factsPWD is what `$PWD` is read as in the second reading: the call's cwd
// when it is absolute and no command of f changes location (Set-Location,
// Push-Location, Pop-Location and their aliases, in any reading of the
// name), else "". After a location change `$PWD` names another directory,
// and reading it as cwd could BLOCK a write that never touches cwd.
func factsPWD(f facts.Facts, cwd string) string {
	c := strings.ReplaceAll(cwd, `\`, "/")
	if !strings.HasPrefix(c, "/") && !(len(c) >= 3 && isDriveLetterByte(c[0]) && c[1] == ':' && c[2] == '/') {
		return ""
	}
	for _, cmd := range f.Commands {
		for _, n := range cmd.Names() {
			switch n {
			case "set-location", "push-location", "pop-location", facts.Dynamic:
				return ""
			}
		}
	}
	return strings.TrimRight(c, "/")
}

// pwdSpellings are the leading spellings of the current location the reader
// keeps as written, ASCII lower case: PowerShell's automatic variable, its
// braced form, and its Path property in a subexpression.
var pwdSpellings = []string{"$pwd", "${pwd}", "$($pwd.path)", "$($pwd)"}

// pwdPath is p with a leading `$PWD` spelling replaced by pwd, cleaned at its
// root and with the home folded to `~` (as lexicalPath spells a path). ok is
// false when pwd is empty or p does not start with such a spelling followed
// by a separator or nothing.
func pwdPath(p, pwd, home string) (string, bool) {
	if pwd == "" {
		return "", false
	}
	s := strings.ReplaceAll(p, `\`, "/")
	lower := strings.ToLower(s)
	for _, sp := range pwdSpellings {
		if !strings.HasPrefix(lower, sp) || (len(s) > len(sp) && s[len(sp)] != '/') {
			continue
		}
		c, ok := cleanRooted(pwd + s[len(sp):])
		if !ok {
			return "", false
		}
		return foldHomePrefix(c, home), true
	}
	return "", false
}

// cleanRooted cleans a `/`-separated path at its root: a drive (`C:/`), a
// UNC share (`//srv/share`), `/`, or none for a relative path, whose leading
// `..` is kept (the call's cwd decides it). ok is false for a drive-relative
// path (`C:x`), which has no root to clamp at.
func cleanRooted(s string) (string, bool) {
	switch {
	case len(s) >= 2 && isDriveLetterByte(s[0]) && s[1] == ':':
		if len(s) == 2 || s[2] != '/' {
			return "", false
		}
		return s[:2] + path.Clean(s[2:]), true
	case strings.HasPrefix(s, "//"):
		parts := strings.SplitN(s[2:], "/", 3)
		if len(parts) < 3 {
			return "", false
		}
		root := "//" + parts[0] + "/" + parts[1]
		if c := path.Clean("/" + parts[2]); c != "/" {
			return root + c, true
		}
		return root, true
	}
	return path.Clean(s), true
}

// hasDotSegment reports a `.` or `..` component in a `/`-separated path.
func hasDotSegment(s string) bool {
	for _, c := range strings.Split(s, "/") {
		if c == "." || c == ".." {
			return true
		}
	}
	return false
}

// climbsAboveRoot reports whether a rooted rest (`/a/../..`) climbs above
// its root.
func climbsAboveRoot(rest string) bool {
	depth := 0
	for _, c := range strings.Split(rest, "/") {
		switch c {
		case "", ".":
		case "..":
			depth--
			if depth < 0 {
				return true
			}
		default:
			depth++
		}
	}
	return false
}

// foldHomePrefix spells p under home with `~`, as the reader's foldHome does.
func foldHomePrefix(p, home string) string {
	if home == "" || home == "~" || len(p) < len(home) || !strings.EqualFold(p[:len(home)], home) {
		return p
	}
	if len(p) == len(home) || p[len(home)] == '/' {
		return "~" + p[len(home):]
	}
	return p
}

func isDriveLetterByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}
