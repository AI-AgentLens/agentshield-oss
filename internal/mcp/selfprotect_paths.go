package mcp

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"unicode"
)

// Self-protection targets by identity (#4337 review B1/B2, #4352).
//
// The files AgentShield's own enforcement depends on are its configuration
// directory, the agent hook files and the MCP configs `setup mcp` wraps with
// the proxy: the guard's agentshield-config, ide-hooks and ide-mcp-config
// entries (selfProtectTargets). A tool call names one of them when a
// path in it is that file ON THIS MACHINE, whatever the spelling: upper case
// or a Unicode case variant on a case-insensitive volume (U+017F long s, the
// Kelvin sign), an NFD-spelled HOME on APFS, HOME reached through a symlink
// (/tmp is /private/tmp on macOS), the /System/Volumes/Data firmlink, `..`,
// `$HOME`, `${HOME}`, `~`, or a file: URI with one, two or three slashes.
//
// The test is by file identity where the filesystem can answer it (the path's
// existing ancestors are compared with HOME by os.SameFile, as the hook's
// managedConfigToolWrite does), so a spelling counts only where the filesystem
// really resolves it to the target: on a case-sensitive volume ~/.AGENTSHIELD
// is another directory and is not refused. Only the part below HOME that does
// not exist yet is compared by spelling, and case-folded only on a volume that
// folds case.
//
// Two readings use it:
//   - the config guard (every mode): path arguments of write-, delete- and
//     exec-shaped tools, and HOME-anchored tokens in command text. A relative
//     path resolves against the proxy's working directory, which a stdio
//     server inherits. This is the reading that adds BLOCKs, so it is narrow.
//   - the audit-only keep rule (applyToolCallMode): any path-shaped value or
//     command token, and a relative path matched by its tail. It only keeps a
//     BLOCK enforce mode already made, so it cannot add one.

// spTarget is one self-protection target, relative to HOME. dir marks a
// directory: anything below it is the target too.
type spTarget struct {
	rel string
	dir bool
}

// selfProtectTargets returns the guard's agentshield-config, ide-hooks and
// ide-mcp-config entries. Rewriting an MCP config can unwrap a server from
// the proxy, as removing a hook unhooks an agent. Adding a file to one of
// those categories in the guard adds it here.
func selfProtectTargets() []spTarget {
	var out []spTarget
	seen := map[string]bool{}
	for _, c := range protectedConfigs {
		if (c.category == "agentshield-config" || c.category == "ide-hooks" || c.category == "ide-mcp-config") && !seen[c.rel] {
			seen[c.rel] = true
			out = append(out, spTarget{rel: c.rel, dir: c.dir})
		}
	}
	return out
}

// execToolSegmentRe matches an exec-shaped tool name by whole segments:
// execute_command, run_shell, run_terminal_command, shell_exec, run_bash,
// start_process, terminal_run, eval_code. Segments, not substrings:
// update_description, get_transcript and retrieval_search are not exec tools
// (#4337 review pass 2).
var execToolSegmentRe = regexp.MustCompile(`(?i)(?:^|[_\-.])(?:exec|execute|command|cmd|shell|bash|sh|zsh|terminal|powershell|pwsh|process|eval|run_code)(?:[_\-.]|$)`)

// mutatingToolSegmentRe matches a tool name whose verb writes, moves or
// deletes a file.
var mutatingToolSegmentRe = regexp.MustCompile(`(?i)(?:^|[_\-.])(?:write|create|edit|save|update|append|patch|apply|replace|insert|modify|put|upload|move|mv|rename|copy|cp|delete|remove|rm|rmdir|unlink|truncate|mkdir|touch|chmod|chown|symlink|link)(?:[_\-.]|$)|str_replace`)

// pathArgNames are the argument names that carry a file path.
var pathArgNames = map[string]bool{
	"path": true, "paths": true, "filepath": true, "file": true, "filename": true, "files": true,
	"target": true, "targetpath": true, "destination": true, "dest": true, "dst": true,
	"source": true, "src": true, "sourcepath": true, "uri": true, "notebookpath": true,
	"newpath": true, "oldpath": true, "directory": true, "dir": true, "output": true, "outputpath": true,
}

func isPathArg(name string) bool {
	n := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(name))
	return pathArgNames[n]
}

// isExecTool and isMutatingTool classify a tool by name (see the regexes).
func isExecTool(name string) bool     { return execToolSegmentRe.MatchString(name) }
func isMutatingTool(name string) bool { return mutatingToolSegmentRe.MatchString(name) }

// isCommandArg reports whether argName of toolName is command text: an exec-
// or shell-shaped argument name of an exec-shaped tool, or the generic input
// names such a tool takes.
func isCommandArg(toolName, argName string) bool {
	if !isExecTool(toolName) {
		return false
	}
	switch cat := classifyArgumentCategory(argName); cat {
	case "exec", "shell":
		return true
	}
	switch strings.ToLower(argName) {
	case "input", "args", "argv", "arguments", "line":
		return true
	}
	return false
}

// plainReadRe is the shell hook's definition of a plain read (enterprise
// plainReadRe, used by sp-block-config-touch): one simple statement that
// starts with a read-only tool, with no redirect, pipe, separator, subshell
// or backtick. A copy, because internal/mcp may not import the enterprise
// layer; TestPlainReadPattern_MatchesEnterprise in internal/cli fails if the
// two drift.
var plainReadRe = regexp.MustCompile("^\\s*(sudo\\s+)?(cat|head|tail|grep|rg|ls|stat|file|wc|diff|jq|echo|printf|agentshield)(\\s+[^;&|<>\\n`(!]*)?$")

// PlainReadPattern returns plainReadRe's source, for the drift test.
func PlainReadPattern() string { return plainReadRe.String() }

// homeFoldsCase reports whether HOME's volume treats names case-insensitively
// (the macOS default): HOME spelled with its ASCII case swapped is the same
// directory. A variable so a test can pin either answer.
var homeFoldsCase = func(home string) bool {
	swapped := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		case r >= 'A' && r <= 'Z':
			return r - 'A' + 'a'
		}
		return r
	}, home)
	if swapped == home {
		return false
	}
	a, err1 := os.Stat(home)
	b, err2 := os.Stat(swapped)
	return err1 == nil && err2 == nil && os.SameFile(a, b)
}

// foldKey maps every rune to the smallest rune of its Unicode simple case
// folding orbit, so `ſ`, `S` and `s` (and `K`, `K`, `k`) compare equal. Used
// only to RAISE: it decides whether a spelling names a protected file, never
// whether a rule is excluded (the #3771 trap).
func foldKey(s string) string {
	return strings.Map(func(r rune) rune {
		min := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < min {
				min = f
			}
		}
		return min
	}, s)
}

// spellingToPath turns a path value into a plain path: a file: URI's path
// (one, two or three slashes, an optional localhost authority, percent-
// decoded), and a leading `~`, `$HOME` or `${HOME}` expanded. ok is false for
// an empty or multi-line value, or a file: URI naming another host.
func spellingToPath(v, home string) (string, bool) {
	t := strings.TrimSpace(v)
	if t == "" || len(t) > 4096 || strings.ContainsAny(t, "\r\n") {
		return "", false
	}
	if len(t) >= 5 && strings.EqualFold(t[:5], "file:") {
		rest := t[5:]
		if strings.HasPrefix(rest, "//") {
			rest = rest[2:]
			if !strings.HasPrefix(rest, "/") {
				i := strings.IndexByte(rest, '/')
				if i < 0 || !strings.EqualFold(rest[:i], "localhost") {
					return "", false
				}
				rest = rest[i:]
			}
		}
		if dec, err := url.PathUnescape(rest); err == nil {
			rest = dec
		}
		t = rest
	}
	switch {
	case t == "~" || strings.HasPrefix(t, "~/"):
		t = home + t[1:]
	default:
		for _, ref := range []string{"${HOME}", "$HOME"} {
			if strings.HasPrefix(t, ref) && (len(t) == len(ref) || t[len(ref)] == '/') {
				t = home + t[len(ref):]
				break
			}
		}
	}
	return t, true
}

// remNamesTarget reports whether rem, a path below HOME in key form, is a
// target (or inside a directory target).
func remNamesTarget(rem string, key func(string) string) (string, bool) {
	for _, t := range selfProtectTargets() {
		kt := key(t.rel)
		if rem == kt || (t.dir && strings.HasPrefix(rem, kt+"/")) {
			return t.rel, true
		}
		if strings.ContainsAny(rem, "*?[") {
			if m, _ := filepath.Match(rem, kt); m {
				return t.rel, true
			}
		}
	}
	return "", false
}

// absNamesTarget reports whether the absolute path p is a target on this
// machine. fold is whether names below HOME compare case-folded.
func absNamesTarget(p, home string, fold bool) (string, bool) {
	key := func(s string) string { return s }
	if fold {
		key = foldKey
	}
	// The firmlink exists only on macOS. Elsewhere /System/Volumes/Data/...
	// is another path, and identity rightly says it is not the target.
	if runtime.GOOS == "darwin" && len(p) > len(firmlinkPrefix) && strings.EqualFold(p[:len(firmlinkPrefix)], firmlinkPrefix) && p[len(firmlinkPrefix)] == '/' {
		p = p[len(firmlinkPrefix):]
	}
	// Lexical: the cleaned spelling under HOME. HOME reached through a
	// symlink is the identity walk's.
	if kc, kh := key(filepath.Clean(p)), key(filepath.Clean(home)); strings.HasPrefix(kc, kh+"/") {
		if rel, ok := remNamesTarget(kc[len(kh)+1:], key); ok {
			return rel, true
		}
	}
	// By identity: resolve the path as the kernel would, then find HOME among
	// its existing ancestors by os.SameFile. What lies below HOME is compared
	// by spelling (key). An existing target is also compared directly.
	homeInfo, err := os.Stat(home)
	if err != nil {
		return "", false
	}
	res := resolveWritePath(p, 0)
	for _, t := range selfProtectTargets() {
		ti, err := os.Stat(filepath.Join(home, t.rel))
		if err != nil {
			continue
		}
		if !t.dir {
			if fi, err := os.Stat(res); err == nil && os.SameFile(fi, ti) {
				return t.rel, true
			}
			continue
		}
		// A directory target: any existing ancestor that is it (the hook's
		// ancestorIsDir).
		for cur := res; ; {
			if fi, err := os.Stat(cur); err == nil && os.SameFile(fi, ti) {
				return t.rel, true
			}
			parent := filepath.Dir(cur)
			if parent == cur {
				break
			}
			cur = parent
		}
	}
	var below []string
	for cur := res; ; {
		if fi, err := os.Stat(cur); err == nil && os.SameFile(fi, homeInfo) {
			for i, j := 0, len(below)-1; i < j; i, j = i+1, j-1 {
				below[i], below[j] = below[j], below[i]
			}
			return remNamesTarget(key(strings.Join(below, "/")), key)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", false
		}
		below = append(below, filepath.Base(cur))
		cur = parent
	}
}

// relTailNamesTarget reports whether the relative path p ends in a target,
// or passes through a directory target. The audit-only keep rule's reading:
// without the server's working directory, the tail is all there is.
func relTailNamesTarget(p string) (string, bool) {
	c := foldKey(filepath.ToSlash(filepath.Clean(p)))
	for _, t := range selfProtectTargets() {
		kt := foldKey(t.rel)
		if c == kt || strings.HasSuffix(c, "/"+kt) {
			return t.rel, true
		}
		if t.dir && (strings.HasPrefix(c, kt+"/") || strings.Contains(c, "/"+kt+"/")) {
			return t.rel, true
		}
	}
	return "", false
}

// namesTargetGuard is the guard's reading of one path value: identity, with a
// relative path resolved against the proxy's working directory.
func namesTargetGuard(v string) (string, bool) {
	home := os.Getenv("HOME")
	if home == "" {
		return "", false
	}
	p, ok := spellingToPath(v, home)
	if !ok {
		return "", false
	}
	if !filepath.IsAbs(p) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", false
		}
		p = filepath.Join(cwd, p)
	}
	return absNamesTarget(p, home, homeFoldsCase(home))
}

// namesTargetKeep is the audit-only keep rule's reading of one path value:
// as namesTargetGuard, plus a relative path's tail, and case always folded.
func namesTargetKeep(v string) (string, bool) {
	home := os.Getenv("HOME")
	if home == "" {
		return "", false
	}
	p, ok := spellingToPath(v, home)
	if !ok {
		return "", false
	}
	if !filepath.IsAbs(p) {
		return relTailNamesTarget(p)
	}
	return absNamesTarget(p, home, true)
}

// commandTokenSplit separates the words of command text: whitespace and the
// shell's operators. Quotes and backslashes are removed first, so
// `~/.agent”shield` reads as one word.
var commandTokenSplit = regexp.MustCompile("[\\s;|&<>()=,`{}]+")

// assignmentRe finds a simple shell assignment, `NAME=value`, optionally
// after `export`, at the start of a word.
var assignmentRe = regexp.MustCompile(`(?:^|[\s;&|(])(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=([^\s;&|)]*)`)

// expandAssignments substitutes `$NAME` and `${NAME}` with the value of a
// simple assignment made earlier in the same command text, so
// `X=shield; rm -rf ~/.agent$X` reads as the path it removes. Only literal
// values; anything the shell would compute is left as written.
func expandAssignments(text string) string {
	for _, m := range assignmentRe.FindAllStringSubmatch(text, -1) {
		name, value := m[1], m[2]
		if strings.ContainsAny(value, "$`") {
			continue
		}
		text = strings.ReplaceAll(text, "${"+name+"}", value)
		text = regexp.MustCompile(`\$`+name+`\b`).ReplaceAllLiteralString(text, value)
	}
	return text
}

func commandTokens(text string) []string {
	text = strings.NewReplacer("'", "", "\"", "", "\\", "").Replace(text)
	text = expandAssignments(text)
	var out []string
	for _, tok := range commandTokenSplit.Split(text, -1) {
		if tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

// homeAnchored reports whether a command token is spelled from HOME or the
// root: `~`, `$HOME`, `${HOME}`, an absolute path or a file: URI. The guard
// reads only these in command text; a relative word there may be any string
// (`echo .agentshield/ >> .gitignore`).
func homeAnchored(tok string) bool {
	return strings.HasPrefix(tok, "~") || strings.HasPrefix(tok, "$HOME") || strings.HasPrefix(tok, "${HOME}") ||
		strings.HasPrefix(tok, "/") || (len(tok) >= 5 && strings.EqualFold(tok[:5], "file:"))
}

// selfProtectFindings is the guard's self-protection reading of a tools/call
// (every mode). See the file comment.
func selfProtectFindings(toolName string, arguments map[string]interface{}) []ConfigGuardFinding {
	mutating, exec := isMutatingTool(toolName), isExecTool(toolName)
	if !mutating && !exec {
		return nil
	}
	var findings []ConfigGuardFinding
	add := func(argName, value, rel string) {
		findings = append(findings, ConfigGuardFinding{
			Path:     value,
			Pattern:  "~/" + rel + " (any spelling)",
			Category: "agentshield-self-protect",
			Reason:   "Writing, moving or deleting " + "~/" + rel + " could switch off AgentShield's protections.",
			ArgName:  argName,
		})
	}
	for argName, argValue := range arguments {
		switch {
		case isCommandArg(toolName, argName):
			for _, text := range stringLeaves(argValue) {
				if plainReadRe.MatchString(text) {
					continue
				}
				for _, tok := range commandTokens(text) {
					if !homeAnchored(tok) {
						continue
					}
					if rel, ok := namesTargetGuard(tok); ok {
						add(argName, text, rel)
						break
					}
				}
			}
		case isPathArg(argName):
			for _, v := range stringLeaves(argValue) {
				if rel, ok := namesTargetGuard(v); ok {
					add(argName, v, rel)
					break
				}
			}
		}
	}
	return findings
}

// argsNameSelfProtectTarget is the audit-only keep rule's reading: whether
// any path-shaped value or command token of the call names a target (see the
// file comment). A plain read in command text does not count, as in the
// shell hook.
func argsNameSelfProtectTarget(toolName string, arguments map[string]interface{}) bool {
	for argName, argValue := range arguments {
		command := isCommandArg(toolName, argName) || func() bool {
			c := classifyArgumentCategory(argName)
			return c == "exec" || c == "shell"
		}()
		for _, v := range stringLeaves(argValue) {
			if command {
				if plainReadRe.MatchString(v) {
					continue
				}
				for _, tok := range commandTokens(v) {
					if _, ok := namesTargetKeep(tok); ok {
						return true
					}
				}
				continue
			}
			if strings.ContainsAny(strings.TrimSpace(v), " \t") && !looksLikePath(strings.TrimSpace(v)) {
				continue // prose, not a path
			}
			if _, ok := namesTargetKeep(v); ok {
				return true
			}
		}
	}
	return false
}

// resolveWritePath returns the clean path of the file a write to p, spelled
// exactly as written, lands on: the longest existing prefix resolved by
// filepath.EvalSymlinks (which applies a ".." to the resolved prefix as the
// kernel does), the rest appended, and a dangling symlink followed. The same
// algorithm as internal/cli's resolveWritePath (#4260), which the hook's
// managed tool-write check uses; internal/mcp cannot import it. depth bounds
// a chain of dangling links.
func resolveWritePath(p string, depth int) string {
	if depth > 8 {
		return filepath.Clean(p)
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		return real
	}
	sep := string(filepath.Separator)
	i := strings.LastIndex(p, sep)
	if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(p)
		if err != nil || i < 0 {
			return filepath.Clean(p)
		}
		if !filepath.IsAbs(target) {
			target = p[:i] + sep + target
		}
		return resolveWritePath(target, depth+1)
	}
	if i <= 0 {
		return filepath.Clean(p)
	}
	return filepath.Join(resolveWritePath(p[:i], depth), p[i+1:])
}
