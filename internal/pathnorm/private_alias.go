package pathnorm

import "strings"

// CanonicalPrivateAlias returns s with every macOS `/private` alias of a
// system root written as the short path, or "" when s has none (#4387).
//
// # Why
//
// On macOS `/etc`, `/var` and `/tmp` are symlinks into `/private`
// (`/etc -> private/etc`), so `/private/etc/hosts` opens the very same file
// as `/etc/hosts`. The packs are written against the short spelling, and no
// layer resolved the long one: 35 of 43 system-path BLOCK rules the issue
// sampled decided lower (33 AUDIT, 2 ALLOW) for the `/private` spelling. The
// rewrite produces the spelling the packs are written against, so the
// evaluator can decide on it.
//
// # Consumed only by a raise-only reading
//
// The rewrite is never applied to the text a rule sees as written. Several
// pack rules match `/private` literally, and replacing the original would
// switch those off. It feeds policy.Engine.EvaluatePrivateAlias (and the MCP
// twin), whose verdict replaces the as-written one only when strictly more
// restrictive, so it can raise a decision and never lower one.
//
// # What it rewrites
//
// `/private/etc` and `/private/var` where the `/private` begins an absolute
// path and the root segment ends there: the `/` starts the text, a word, or
// follows `=`, `@`, `:`, `,`, `{` or a quote (isPathOpener, the same openers
// the case fold uses, less the `)` and backquote that close a substitution);
// or it follows `file://`. The root segment must be followed by `/`, a word
// break, a quote, `,`, `}`, `:` or the end of the text, so
// `/private/etcetera` is left alone, and so is `./private/etc`,
// `~/private/etc` or `/srv/private/etc` (a directory that happens to be
// called private, not the alias).
//
// # Not /private/tmp — a measured gap, not an oversight
//
// `/tmp -> private/tmp` is the same alias, and reading it short closes 117
// more ratchet variants (`mkfifo /private/tmp/x`, `CARGO_HOME=/private/tmp/x`).
// It is left out because it is the one root real traffic spells long: Claude
// Code's per-user scratch directory is `/private/tmp/claude-501/…`, in ~40% of
// one developer's commands. Replayed over ten days of that traffic, reading it
// short added 22 BLOCKs, every one ts-block-home-redirect on an agent's own
// scratch HOME (`export HOME=/private/tmp/claude-501/…/home`). The short
// spelling already BLOCKs on main, so those are an existing rule's judgement
// carried to a spelling nobody blocked before — and new BLOCKs on real
// traffic need Gary's call (#4387). `/private/var/tmp` IS read short: it is
// under /var, and no traffic spelled it.
//
// `/private` and the root are matched ASCII-case-insensitively (FoldASCII,
// never a Unicode fold: see FoldPathCase), because APFS
// is case-insensitive by default and `/PRIVATE/ETC/hosts` opens the same
// file. Only `/private` is removed; the root keeps the case it was written
// in, and the case-fold reading (#4194), which runs inside this one, decides
// on the case.
//
// On every host, not only darwin: shield-server evaluates macOS clients
// remotely, and on Linux `/private/etc` is an unusual enough directory that
// reading it as `/etc` costs nothing.
func CanonicalPrivateAlias(s string) string {
	if !containsFoldASCII(s, "/private") {
		return ""
	}
	var b strings.Builder
	last := 0
	for i := 0; i < len(s); i++ {
		if s[i] != '/' || !privateAliasAt(s, i) || !privateAliasOpens(s, i) {
			continue
		}
		if b.Len() == 0 {
			b.Grow(len(s))
		}
		b.WriteString(s[last:i])
		last = i + len("/private")
		i = last - 1
	}
	if last == 0 {
		return ""
	}
	b.WriteString(s[last:])
	return b.String()
}

// privateAliasRoots are the macOS system roots, symlinks into /private, that
// are read short. Closed: it is the OS layout, not a list of rules. `tmp` is
// the third such root and is deliberately absent; see CanonicalPrivateAlias.
var privateAliasRoots = [...]string{"etc", "var"}

// privateAliasAt reports whether s[i:] is `/private/<root>` followed by the end
// of the root segment.
func privateAliasAt(s string, i int) bool {
	const prefix = "/private/"
	if len(s)-i < len(prefix) || FoldASCII(s[i:i+len(prefix)]) != prefix {
		return false
	}
	rest := s[i+len(prefix):]
	for _, root := range privateAliasRoots {
		if len(rest) < len(root) || FoldASCII(rest[:len(root)]) != root {
			continue
		}
		if len(rest) == len(root) || privateAliasRootEnds(rest[len(root)]) {
			return true
		}
	}
	return false
}

// privateAliasOpens reports whether the `/` at s[i] begins an absolute path.
func privateAliasOpens(s string, i int) bool {
	if i == 0 {
		return true
	}
	switch s[i-1] {
	case '/':
		// file:///private/etc/… — the scheme's remainder is a local path.
		// Any other `//private` is left alone.
		return i >= len("file://") && FoldASCII(s[i-len("file://"):i]) == "file://"
	case ')', '`':
		// `$(pwd)/private/etc`: the end of a substitution, so the path is
		// relative to whatever it printed, not the alias.
		return false
	}
	return isPathOpener(s[i-1])
}

// privateAliasRootEnds reports whether c ends the root segment of an alias.
func privateAliasRootEnds(c byte) bool {
	if c == '/' || isPathSpanBreak(c) {
		return true
	}
	switch c {
	case '\'', '"', ',', '}', ':':
		return true
	}
	return false
}

// containsFoldASCII reports whether s contains sub under ASCII case folding.
// sub must be lower-case ASCII.
func containsFoldASCII(s, sub string) bool {
	if strings.Contains(s, sub) {
		return true
	}
	if !hasASCIIUpper(s) {
		return false
	}
	return strings.Contains(FoldASCII(s), sub)
}
