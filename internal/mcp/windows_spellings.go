package mcp

import (
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
)

// Windows spellings of a path under HOME (#5060, #5062).
//
// On Windows an agent names AgentShield's config directory, and the other
// self-protection targets, in spellings the guard's unix readings did not
// read:
//   - a drive letter in command text: C:\Users\u\.agentshield, C:/Users/u/...
//     (commandTokens removes a backslash as a shell escape, so the first
//     became C:Usersu.agentshield, and homeAnchored reads neither);
//   - the environment in command text: %USERPROFILE%, $env:USERPROFILE,
//     ${env:USERPROFILE}, PowerShell's $HOME;
//   - a canonical file: URI, file:///C:/Users/u/... (RFC 8089 puts a slash
//     before the drive, and the guard kept it: "/C:/Users/u/..." is no path).
//
// The readings here only turn such a spelling into the path the shell or the
// server resolves. Whether that path is a target is still absNamesTarget's
// identity test, so a spelling blocks only where it names the target on this
// machine. Callers use them only when runtime.GOOS is "windows": on any other
// platform every value takes the reading it took before, unchanged. The
// helpers are pure, so they are tested on every platform.

// driveURIPathRe matches the path of a file: URI that names a Windows drive:
// "/", a drive letter, ":" (RFC 8089 E.2), the legacy "|" or a percent-
// encoded colon (vscode-uri writes file:///c%3A/...), then a separator or
// the end.
var driveURIPathRe = regexp.MustCompile(`^/([A-Za-z])(?::|\||%3[Aa])([/\\]|$)`)

// driveURIPath reads p, the part of a file: URI after its authority, as a
// Windows drive path: "/C:/x" is "C:/x", "/c|/x" is "c:/x". ok is false, and
// p is returned, for any other shape.
func driveURIPath(p string) (string, bool) {
	m := driveURIPathRe.FindStringSubmatchIndex(p)
	if m == nil {
		return p, false
	}
	return p[m[2]:m[3]] + ":" + p[m[4]:], true
}

// driveAuthorityRe matches a file: URI "authority" that is a drive letter,
// file://C:/x. A WHATWG URL parser (Node's URL and fileURLToPath) reads it as
// the path /C:/x, so a Node server resolves it to C:\x.
var driveAuthorityRe = regexp.MustCompile(`^[A-Za-z][:|]([/\\]|$)`)

// resourceGuardPath is the path the config guard reads for a resources/read
// or resources/subscribe URI: what follows "file://", as before. On Windows a
// drive URI's path is read as the drive path (file:///C:/x is C:/x, #5062),
// with the drive letter spelled as HOME spells it: a drive letter is never
// case-sensitive, and main's pattern reading compares case-sensitively, so
// file:///c:/... (as vscode-uri writes it) would otherwise miss.
func resourceGuardPath(uri string) string {
	p := strings.TrimPrefix(uri, "file://")
	if runtime.GOOS != "windows" || p == uri {
		return p
	}
	d, ok := driveURIPath(p)
	if !ok {
		return p
	}
	// A file: URL percent-encodes the path (a profile "John Smith" is
	// John%20Smith), and the server decodes it back (Codex pass on #5064).
	// Decoding here only adds matches: main never matched a drive URI on
	// Windows.
	if dec, err := url.PathUnescape(d); err == nil {
		d = dec
	}
	if h := homeDir(); len(h) >= 2 && h[1] == ':' && strings.EqualFold(h[:1], d[:1]) {
		d = h[:1] + d[1:]
	}
	return d
}

// isDriveAbs reports whether tok is an absolute drive path, C:\... or C:/...
// Only these, of the absolute Windows forms: a UNC path (\\host\share) would
// make the guard's identity walk open a connection to a host the command
// text names.
func isDriveAbs(tok string) bool {
	if len(tok) < 3 || tok[1] != ':' || (tok[2] != '\\' && tok[2] != '/') {
		return false
	}
	c := tok[0]
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

// windowsPlainReadRe is a plain read in cmd or PowerShell, plainReadRe's
// counterpart: one statement that starts with a read-only command (type, more,
// Get-Content, dir, Get-ChildItem, Get-Item, Test-Path, Select-String,
// findstr, and their aliases), with no redirect, pipe, separator,
// subexpression, script block, escape or line break. It exempts only the
// Windows reading below, never main's, so it cannot lower a decision main
// made; without it, reading the audit log with type would be refused.
var windowsPlainReadRe = regexp.MustCompile("(?i)^\\s*(?:type|dir|get-content|gc|get-childitem|gci|get-item|gi|test-path|select-string|sls|(?:findstr|more)(?:\\.exe)?)" +
	"([ \\t]+[^;&|<>\\r\\n`(){}!]*)?$")

// windowsRefRe finds PowerShell's references to the environment and to the
// home directory: ${env:NAME}, $env:NAME, ${HOME} and $HOME, case-insensitive
// as PowerShell is. PowerShell's $HOME is the user's profile, %USERPROFILE%.
var windowsRefRe = regexp.MustCompile(`(?i)\$\{env:(\w+)\}|\$env:(\w+)|\$\{home\}|\$home\b`)

// percentRefRe finds cmd's %NAME%.
var percentRefRe = regexp.MustCompile(`%(\w+)%`)

// windowsQuoteStrip removes the quotes and the escape characters of cmd (^)
// and PowerShell (`), and keeps the backslash: on Windows it is the path
// separator.
var windowsQuoteStrip = strings.NewReplacer("'", "", "\"", "", "`", "", "^", "")

// windowsQuotedRe finds a quoted string: the shell reads it as one word,
// spaces and all (C:\Users\John Smith\...).
var windowsQuotedRe = []*regexp.Regexp{regexp.MustCompile(`"([^"]*)"`), regexp.MustCompile(`'([^']*)'`)}

// canonWindowsRefs rewrites PowerShell's references to cmd's form, %NAME%,
// which is one word to commandTokenSplit (it splits on braces) and is
// expanded after the split, so a value with a space never splits a word.
func canonWindowsRefs(s string) string {
	return windowsRefRe.ReplaceAllStringFunc(s, func(m string) string {
		sm := windowsRefRe.FindStringSubmatch(m)
		switch {
		case sm[1] != "":
			return "%" + sm[1] + "%"
		case sm[2] != "":
			return "%" + sm[2] + "%"
		}
		return "%USERPROFILE%"
	})
}

// expandPercentRefs replaces each %NAME% in tok with its value from lookup. A
// name lookup does not know, or knows as empty, is left as written.
func expandPercentRefs(tok string, lookup func(string) (string, bool)) string {
	return percentRefRe.ReplaceAllStringFunc(tok, func(m string) string {
		if v, ok := lookup(m[1 : len(m)-1]); ok && v != "" {
			return v
		}
		return m
	})
}

// windowsCommandTokens reads command text as cmd or PowerShell does: the
// words of commandTokens, but with the backslash kept, cmd's and PowerShell's
// escapes removed, every quoted string also read as one word, and the
// environment references in each word expanded with lookup.
func windowsCommandTokens(text string, lookup func(string) (string, bool)) []string {
	text = canonWindowsRefs(text)
	var out []string
	add := func(tok string) {
		if tok = strings.TrimSpace(tok); tok != "" {
			out = append(out, expandPercentRefs(tok, lookup))
		}
	}
	for _, re := range windowsQuotedRe {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			add(windowsQuoteStrip.Replace(m[1]))
		}
	}
	for _, tok := range commandTokenSplit.Split(expandAssignments(windowsQuoteStrip.Replace(text)), -1) {
		add(tok)
	}
	return out
}

// windowsCommandNamesTarget is the guard's Windows reading of command text
// (#5060): a word spelled from HOME, from a drive or through the environment
// that names a target. A plain read in cmd or PowerShell is not read.
func windowsCommandNamesTarget(text string) (string, bool) {
	if windowsPlainReadRe.MatchString(text) {
		return "", false
	}
	for _, tok := range windowsCommandTokens(text, os.LookupEnv) {
		if !homeAnchored(tok) && !isDriveAbs(tok) {
			continue
		}
		if rel, ok := namesTargetGuard(tok); ok {
			return rel, true
		}
	}
	return "", false
}
