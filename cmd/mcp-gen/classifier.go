package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ShellPack represents a parsed shell rule YAML pack.
type ShellPack struct {
	Name     string      `yaml:"name"`
	Defaults Defaults    `yaml:"defaults,omitempty"`
	Rules    []ShellRule `yaml:"rules,omitempty"`
}

// Defaults holds default config like protected paths.
type Defaults struct {
	ProtectedPaths []string `yaml:"protected_paths,omitempty"`
}

// ShellRule represents a single shell policy rule.
type ShellRule struct {
	ID       string    `yaml:"id"`
	Taxonomy string    `yaml:"taxonomy,omitempty"`
	Match    MatchSpec `yaml:"match"`
	Decision string    `yaml:"decision"`
	Reason   string    `yaml:"reason"`
}

// MatchSpec holds the match criteria from a shell rule.
type MatchSpec struct {
	CommandRegex        string `yaml:"command_regex,omitempty"`
	CommandRegexExclude string `yaml:"command_regex_exclude,omitempty"`
}

// Candidate represents a shell rule that can be converted to an MCP rule.
type Candidate struct {
	SourceRule ShellRule
	Category   string   // "path-read", "path-write", "path-readwrite", "config-write", "url"
	Paths      []string // extracted file paths or globs
	URLs       []string // extracted URL patterns
	ToolNames  []string // target MCP tool names
	Decision   string
	Reason     string
}

// LoadShellPack parses a YAML pack file.
func LoadShellPack(path string) (*ShellPack, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pack ShellPack
	if err := yaml.Unmarshal(data, &pack); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &pack, nil
}

// Discovery of the pack set lives in discovery.go (DiscoverShellPacks). It is
// deliberately the only answer to "which directories hold shell packs": the
// previous LoadAllShellPacks(dir) helper encoded that answer at its call site
// in main.go, where a pack reorganisation could — and did — silently invalidate
// it for 96 days (#3359).

// ClassifyRules extracts convertible candidates from shell packs.
func ClassifyRules(packs []*ShellPack) []Candidate {
	var candidates []Candidate

	for _, pack := range packs {
		// Extract path-based candidates from protected_paths defaults.
		candidates = append(candidates, classifyProtectedPaths(pack)...)

		// Classify each rule by examining its regex.
		for _, rule := range pack.Rules {
			if c, ok := classifyRule(rule); ok {
				candidates = append(candidates, c)
			}
		}
	}

	return candidates
}

// projectSafeConfigFiles lists config files that legitimately exist in project
// directories and should NOT be blocked with a broad **/<file> glob pattern.
// These are only dangerous at ~/<file> but MCP glob can't distinguish that.
var projectSafeConfigFiles = map[string]bool{
	"~/.npmrc":  true,
	"~/.yarnrc": true,
}

// classifyProtectedPaths creates candidates from a pack's protected_paths list.
func classifyProtectedPaths(pack *ShellPack) []Candidate {
	var candidates []Candidate
	for _, p := range pack.Defaults.ProtectedPaths {
		// Skip files that commonly exist in project directories — a broad
		// **/<file> pattern would cause false positives on project-level configs.
		if projectSafeConfigFiles[p] {
			continue
		}
		globPaths := tildeToGlob(p)
		if len(globPaths) == 0 {
			continue
		}
		candidates = append(candidates, Candidate{
			SourceRule: ShellRule{
				ID:       fmt.Sprintf("protected-path-%s", pathSlug(p)),
				Taxonomy: "credential-exposure/config-file-access/protected-path",
				Decision: "BLOCK",
				Reason:   fmt.Sprintf("Access to protected path %s is blocked.", p),
			},
			Category:  "path-readwrite",
			Paths:     globPaths,
			ToolNames: AllFileTools,
			Decision:  "BLOCK",
			Reason:    fmt.Sprintf("Access to protected path %s is blocked.", p),
		})
	}
	return candidates
}

// classifyRule attempts to classify a single shell rule as convertible.
func classifyRule(rule ShellRule) (Candidate, bool) {
	regex := rule.Match.CommandRegex
	if regex == "" {
		return Candidate{}, false
	}

	// Skip rules that rely on shell-only constructs.
	if isShellOnly(regex) {
		return Candidate{}, false
	}

	// Try path extraction.
	if paths := extractPaths(regex); len(paths) > 0 {
		cat := classifyPathCategory(regex)
		tools := toolsForCategory(cat)
		return Candidate{
			SourceRule: rule,
			Category:   cat,
			Paths:      paths,
			ToolNames:  tools,
			Decision:   rule.Decision,
			Reason:     rule.Reason,
		}, true
	}

	// Try URL extraction.
	if urls := extractURLs(regex); len(urls) > 0 {
		return Candidate{
			SourceRule: rule,
			Category:   "url",
			URLs:       urls,
			ToolNames:  NetworkTools,
			Decision:   rule.Decision,
			Reason:     rule.Reason,
		}, true
	}

	return Candidate{}, false
}

// isShellOnly returns true if the regex contains patterns that fundamentally
// cannot translate to MCP rules. This is intentionally conservative — we only
// skip rules that require shell execution semantics (pipes, command substitution,
// compound commands, or CLI tools with no file-path component).
//
// Rules that reference file-viewing commands (cat, less) alongside paths are
// NOT shell-only — the path component converts fine to MCP argument_patterns.
func isShellOnly(regex string) bool {
	// Shell operators that indicate the rule depends on command composition.
	// In YAML regex sources, shell pipes appear as `\\|` (escaped pipe literal),
	// not as bare `|` (which is regex alternation and perfectly fine).
	shellOperators := []string{
		"\\|",      // escaped pipe in regex = shell pipe (one backslash + pipe)
		"\\$\\(",   // escaped command substitution in regex
		"(^|&&|;|", // compound command prefix alternation
	}
	for _, s := range shellOperators {
		if strings.Contains(regex, s) {
			return true
		}
	}

	// CLI tools whose threat model is purely about command execution — these
	// have no equivalent in MCP tool calls. We check for the tool name as a
	// substring in the raw regex source. Note: we do NOT list file-access
	// tools (cat, less, cp, etc.) here because the path argument DOES convert.
	shellOnlyTools := []string{
		"keyctl", "secret-tool", "keepassxc", "gpg-connect-agent",
		"gpg2", "gpg\\s", // GPG command (but not .gnupg path)
		"ssh-add",
		"kubectl", "docker",
		"git\\s", "git\\b", // git command (but not .git-credentials path)
		"gcloud", "az\\s",
		"vault\\s", // vault command
		"gh\\s",    // gh CLI
		"terraform", "tofu",
		"base64", "xxd", "hexdump",
		"history",
		"printenv",
		"python", "node\\s", "perl\\s", "ruby\\s",
		"openssl",
		"op\\s", "bw\\s",
		"infisical", "doppler", "sops",
		"ngrok", "cloudflared", "chisel", "frpc",
		"bore\\s", "sshuttle", "devtunnel", "zrok",
		"npm\\s", "pip", "mvn", "dotnet",
		"dig\\s", "nslookup",
		"curl", "wget", "nc\\b", "ncat",

		// Environment-variable assignment rules shaped "ENVVAR=<path>" — the
		// shell threat requires a LATER command to consume the env var (the
		// dynamic linker for LD_PRELOAD/LD_LIBRARY_PATH/LD_AUDIT, a cloud CLI
		// for AWS_CONFIG_FILE/KUBECONFIG/etc). MCP tool calls have no
		// "export"/env-redirect concept, so the path literals extractPaths
		// finds here have no faithful MCP translation. Left unexcluded,
		// classifyPathCategory's write/read-verb heuristic finds neither verb
		// in these regexes and silently defaults to "path-read" — which would
		// emit an MCP BLOCK on *reading* /var/tmp or /var/folders (macOS's
		// live system temp root). See #3465.
		"LD_(PRELOAD|LIBRARY_PATH)", "LD_AUDIT=",
		"AWS_CONFIG_FILE|AWS_SHARED_CREDENTIALS_FILE|KUBECONFIG",
	}
	for _, tool := range shellOnlyTools {
		if strings.Contains(regex, tool) {
			return true
		}
	}

	return false
}

// extractPaths pulls file paths from a regex pattern.
// It looks for common path indicators: /etc/, ~/., **/.
func extractPaths(regex string) []string {
	var paths []string

	// Pattern 1: Explicit absolute paths like /etc/shadow, /etc/wireguard/
	absPathRe := regexp.MustCompile(`(/(?:etc|var|opt|usr|root|home)/[a-zA-Z0-9_./\\-]+)`)
	for _, m := range absPathRe.FindAllStringSubmatch(regex, -1) {
		path := cleanRegexPath(m[1])
		if path != "" {
			paths = append(paths, path)
		}
	}

	// Pattern 2: Dot-file paths like .ssh/, .aws/, .npmrc — anchored to the
	// real home-directory roots (see anchorToHomeDirs), not a bare **/<path>
	// glob, which also matches the same relative path inside any project
	// directory (#3354).
	//
	// Each path segment allows the two-char `\.` escape sequence alongside
	// the plain character class, not just a bare literal dot — otherwise a
	// segment boundary the source regex spells as an escaped dot (e.g.
	// `\.m2/settings\.xml`) truncates at the backslash and silently drops
	// the file extension (#3375 Group C: mcp-gen-protected-path-m2-settingsxml).
	dotPathRe := regexp.MustCompile(`(\.\w+(?:/(?:[a-zA-Z0-9_.*-]|\\\.)+)*)`)
	for _, m := range dotPathRe.FindAllStringSubmatch(regex, -1) {
		raw := m[1]
		// Must start with a known sensitive dot-dir/file.
		if isSensitiveDotPath(raw) {
			if cleaned := cleanRegexPath(raw); cleaned != "" {
				paths = append(paths, anchorToHomeDirs(cleaned)...)
			}
		}
	}

	// Pattern 3: Cloud metadata URLs (treated as paths for MCP network rules).
	metadataRe := regexp.MustCompile(`(169\.254\.169\.254|metadata\.google\.internal)`)
	if metadataRe.MatchString(regex) {
		paths = append(paths, metadataRe.FindAllString(regex, -1)...)
	}

	return dedup(paths)
}

// extractURLs pulls URL patterns from a regex.
func extractURLs(regex string) []string {
	var urls []string
	urlRe := regexp.MustCompile(`https?://[a-zA-Z0-9._/-]+`)
	urls = append(urls, urlRe.FindAllString(regex, -1)...)
	return dedup(urls)
}

// cleanRegexPath strips regex metacharacters to produce a glob-friendly path.
func cleanRegexPath(s string) string {
	// Remove common regex escaping.
	s = strings.ReplaceAll(s, `\.`, ".")
	s = strings.ReplaceAll(s, `\/`, "/")
	// Remove word boundaries and anchors.
	s = strings.ReplaceAll(s, `\b`, "")
	s = strings.ReplaceAll(s, `\s`, "")
	s = strings.ReplaceAll(s, `^`, "")
	s = strings.ReplaceAll(s, `$`, "")
	// Remove character classes and alternations.
	s = regexp.MustCompile(`\([^)]*\)`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`\[[^\]]*\]`).ReplaceAllString(s, "*")
	// Expand a single optional character (`X?`) into a glob wildcard instead
	// of dropping only the `?` — `authorized_keys2?` means "authorized_keys"
	// OR "authorized_keys2"; the blanket quantifier strip below left
	// "authorized_keys2" as the ONLY match, narrowing the glob to the rarely
	// used spelling (#3375 Group C, related extraction defect). This must run
	// before the group-removal step's leftovers are stripped, and only
	// touches a `?` directly after an alphanumeric char — a `?` left behind
	// by a removed `(group)` has no preceding literal to expand and is
	// correctly dropped by the blanket strip below.
	s = regexp.MustCompile(`([a-zA-Z0-9])\?`).ReplaceAllString(s, "$1*")
	// Remove quantifiers.
	s = regexp.MustCompile(`[+?{}]`).ReplaceAllString(s, "")
	// Clean up double slashes.
	s = regexp.MustCompile(`//+`).ReplaceAllString(s, "/")
	s = strings.TrimRight(s, "/")
	if s == "" || s == "/" {
		return ""
	}
	return s
}

// isSensitiveDotPath checks if a dot-path is a known credential/config location.
func isSensitiveDotPath(p string) bool {
	sensitive := []string{
		".ssh", ".aws", ".gnupg", ".kube", ".docker",
		".npmrc", ".pypirc", ".netrc", ".git-credentials",
		".config/gcloud", ".config/gh", ".vault-token",
		".terraform.d", ".azure", ".env", ".envrc", ".yarnrc",
		".cargo/config", ".m2/settings", ".pip",
		".config/pip", ".config/openai", ".config/anthropic",
		".openai", ".anthropic",
		".mozilla/firefox", ".config/chromium",
	}
	for _, s := range sensitive {
		if p == s {
			return true
		}
		// A prefix match alone is not enough — ".env" is a prefix of
		// ".environ" (Python's os.environ, matched by an unrelated rule's
		// `os\.environ\.get\(` text), which is not a file at all. Require a
		// path-segment or extension boundary right after the prefix so
		// "environ"/"dockerignore"-shaped words don't false-match their
		// sensitive stem (#3375 Group C).
		if strings.HasPrefix(p, s) {
			rest := p[len(s):]
			// The candidate is the RAW regex-source capture, not yet run
			// through cleanRegexPath — an extension boundary the source
			// spelled as an escaped dot (`\.xml`) still carries its leading
			// backslash here. dotPathRe's segment grammar only ever admits
			// a bare backslash as the first half of that `\.` atom, so
			// seeing one guarantees an escaped-dot boundary follows.
			if rest[0] == '/' || rest[0] == '.' || rest[0] == '\\' {
				return true
			}
		}
	}
	return false
}

// redirectOperatorRe matches an unambiguous shell write-TARGET signal: a
// literal redirect (`>`, `>>`) or `tee`. Unlike the write-word list below,
// these are positional — the path immediately following one is being
// written to, full stop.
var redirectOperatorRe = regexp.MustCompile(`>>?|\btee\b`)

// writeWordRe matches ambiguous write-ish verbs that can name the path as
// either source or destination (`cp X Y`, `mv X Y`) — presence alone still
// counts toward "this rule cares about writes", but never overrides a read
// verb's own attribution the way a redirect operator does. `chflags` is
// included as an unambiguous write signal: clearing an immutable/append-only
// flag is a file-attribute modification, never a read (#3465).
var writeWordRe = regexp.MustCompile(`\b(cp|mv|scp|rsync|write|edit|save|install|chflags)\b`)

// findFWriteFlag is the literal regex-SOURCE substring shared by both
// find-fwrite shell rules (`-f(print[f0]?|ls)` — find's -fprintf/-fprint/
// -fprint0/-fls flags). These write directly to the operand path without any
// shell redirect operator, so neither redirectOperatorRe nor writeWordRe see
// them — classifyPathCategory silently defaulted such rules to "path-read",
// which would emit an MCP BLOCK on *reading* /var/root and /usr/lib rather
// than the write these flags actually perform (#3465).
const findFWriteFlag = "-f(print"

// readVerbRe matches verbs that view file contents in place.
var readVerbRe = regexp.MustCompile(`\b(cat|less|more|head|tail|bat|strings|xxd|hexdump|od)\b`)

// classifyPathCategory determines what MCP operations are relevant.
//
// Classification is done per top-level regex alternation branch, not over
// the whole pattern text. A rule shaped like "(echo|printf|cat)\b.*(>>|>)\s*
// /etc/hosts" contains the read verb `cat` only as the redirect's data
// SOURCE — the branch as a whole targets the path for a WRITE, and the read
// verb must not count as a read of that path. Whole-pattern keyword
// presence conflated the two and produced "path-readwrite" for a rule whose
// own TN case (`cat /etc/hosts`) proves reading is meant to stay ALLOWed
// (#3375 Group C: ne-block-etc-hosts-write).
func classifyPathCategory(regex string) string {
	hasWrite := false
	hasRead := false

	for _, branch := range splitTopLevelAlternation(regex) {
		if redirectOperatorRe.MatchString(branch) {
			// A redirect operator is present: the branch writes to the
			// path, and any read verb in this branch is upstream of the
			// redirect (its data source), not an operation on the path.
			hasWrite = true
			continue
		}
		if writeWordRe.MatchString(branch) || strings.Contains(branch, findFWriteFlag) {
			hasWrite = true
		}
		if readVerbRe.MatchString(branch) {
			hasRead = true
		}
	}

	if hasWrite && hasRead {
		return "path-readwrite"
	}
	if hasWrite {
		return "config-write"
	}
	return "path-read"
}

// splitTopLevelAlternation splits a regex on `|` alternation operators that
// are not nested inside a parenthesized group, so a group-internal
// alternation like `(echo|printf|cat)` stays a single branch while the
// top-level `A|B` in `A\.\S+|B\.\S+` splits into two. Escaped parens (`\(`,
// `\)`) are literal characters and do not affect nesting depth.
//
// A `|` inside a bracket character class (`[;&|]`) is a literal alternative
// character, not an alternation operator, and must not split or count
// toward paren depth either — `[^;&|\n\r]*` closing at that `|` produced a
// garbled first branch that only classified correctly by coincidence.
func splitTopLevelAlternation(regex string) []string {
	var branches []string
	depth := 0
	inClass := false
	start := 0
	escaped := false
	for i, r := range regex {
		if escaped {
			escaped = false
			continue
		}
		switch r {
		case '\\':
			escaped = true
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '(':
			if !inClass {
				depth++
			}
		case ')':
			if !inClass && depth > 0 {
				depth--
			}
		case '|':
			if !inClass && depth == 0 {
				branches = append(branches, regex[start:i])
				start = i + 1
			}
		}
	}
	branches = append(branches, regex[start:])
	return branches
}

// toolsForCategory returns the appropriate MCP tool names for a category.
func toolsForCategory(cat string) []string {
	switch cat {
	case "path-read":
		return ReadTools
	case "path-write", "config-write":
		return WriteTools
	case "path-readwrite":
		return AllFileTools
	case "url":
		return NetworkTools
	default:
		return ReadWriteTools
	}
}

// homeDirRoots are the real directory roots a user's home-relative dotfile
// can live under, mirroring the shell-side protected_paths anchoring
// convention (CLAUDE.md "Anti-patterns": /home/*/X, /root/X, /var/root/X,
// /Users/*/X) instead of an unanchored **/X glob, which also matches the
// same relative path inside any project directory (#3354).
var homeDirRoots = []string{"/home/*/", "/root/", "/var/root/", "/Users/*/"}

// anchorToHomeDirs converts a home-relative path fragment (no leading "~/" or
// "/", e.g. ".ssh/**" or ".docker/config.json") into globs anchored to the
// real home-directory roots.
func anchorToHomeDirs(rest string) []string {
	rest = strings.TrimPrefix(rest, "/")
	if rest == "" {
		return nil
	}
	globs := make([]string, 0, len(homeDirRoots))
	for _, root := range homeDirRoots {
		globs = append(globs, root+rest)
	}
	return globs
}

// tildeToGlob converts ~/path into globs anchored to the real home-directory
// roots (see anchorToHomeDirs) instead of an unanchored **/path glob.
func tildeToGlob(p string) []string {
	if strings.HasPrefix(p, "~/") {
		return anchorToHomeDirs(p[2:])
	}
	return []string{p}
}

// pathSlug generates a rule ID slug from a path.
func pathSlug(p string) string {
	p = strings.TrimPrefix(p, "~/")
	p = strings.TrimPrefix(p, "/")
	p = strings.ReplaceAll(p, "/", "-")
	p = strings.ReplaceAll(p, ".", "")
	p = strings.ReplaceAll(p, "*", "")
	p = strings.ReplaceAll(p, " ", "-")
	p = strings.TrimRight(p, "-")
	return p
}

func dedup(ss []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
