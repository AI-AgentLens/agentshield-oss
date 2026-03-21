package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ShellPack represents a parsed shell rule YAML pack.
type ShellPack struct {
	Name     string     `yaml:"name"`
	Defaults Defaults   `yaml:"defaults,omitempty"`
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
	CommandRegex string `yaml:"command_regex,omitempty"`
	CommandRegexExclude string `yaml:"command_regex_exclude,omitempty"`
}

// Candidate represents a shell rule that can be converted to an MCP rule.
type Candidate struct {
	SourceRule  ShellRule
	Category    string   // "path-read", "path-write", "path-readwrite", "config-write", "url"
	Paths       []string // extracted file paths or globs
	URLs        []string // extracted URL patterns
	ToolNames   []string // target MCP tool names
	Decision    string
	Reason      string
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

// LoadAllShellPacks loads all shell rule YAML packs from the given directory.
func LoadAllShellPacks(dir string) ([]*ShellPack, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var packs []*ShellPack
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		pack, err := LoadShellPack(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		packs = append(packs, pack)
	}
	return packs, nil
}

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
		globPath := tildeToGlob(p)
		candidates = append(candidates, Candidate{
			SourceRule: ShellRule{
				ID:       fmt.Sprintf("protected-path-%s", pathSlug(p)),
				Taxonomy: "credential-exposure/config-file-access/protected-path",
				Decision: "BLOCK",
				Reason:   fmt.Sprintf("Access to protected path %s is blocked.", p),
			},
			Category:  "path-readwrite",
			Paths:     []string{globPath},
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

	// Pattern 2: Dot-file paths like .ssh/, .aws/, .npmrc
	dotPathRe := regexp.MustCompile(`(\.\w+(?:/[a-zA-Z0-9_.*-]+)*)`)
	for _, m := range dotPathRe.FindAllStringSubmatch(regex, -1) {
		raw := m[1]
		// Must start with a known sensitive dot-dir/file.
		if isSensitiveDotPath(raw) {
			paths = append(paths, "**/"+cleanRegexPath(raw))
		}
	}

	// Pattern 3: Cloud metadata URLs (treated as paths for MCP network rules).
	metadataRe := regexp.MustCompile(`(169\.254\.169\.254|metadata\.google\.internal)`)
	if metadataRe.MatchString(regex) {
		for _, m := range metadataRe.FindAllString(regex, -1) {
			paths = append(paths, m)
		}
	}

	return dedup(paths)
}

// extractURLs pulls URL patterns from a regex.
func extractURLs(regex string) []string {
	var urls []string
	urlRe := regexp.MustCompile(`https?://[a-zA-Z0-9._/-]+`)
	for _, m := range urlRe.FindAllString(regex, -1) {
		urls = append(urls, m)
	}
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
		".terraform.d", ".azure", ".env", ".yarnrc",
		".cargo/config", ".m2/settings", ".pip",
		".config/pip", ".config/openai", ".config/anthropic",
		".openai", ".anthropic",
		".mozilla/firefox", ".config/chromium",
	}
	for _, s := range sensitive {
		if strings.HasPrefix(p, s) {
			return true
		}
	}
	return false
}

// classifyPathCategory determines what MCP operations are relevant.
func classifyPathCategory(regex string) string {
	// If regex contains write-indicating commands (cp, mv, tee, >), it's a write path.
	writeRe := regexp.MustCompile(`\b(cp|mv|tee|scp|rsync|write|edit|save|install)\b|>>?`)
	readRe := regexp.MustCompile(`\b(cat|less|more|head|tail|bat|strings|xxd|hexdump|od)\b`)

	hasWrite := writeRe.MatchString(regex)
	hasRead := readRe.MatchString(regex)

	if hasWrite && hasRead {
		return "path-readwrite"
	}
	if hasWrite {
		return "config-write"
	}
	return "path-read"
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

// tildeToGlob converts ~/path to **/path for MCP glob matching.
func tildeToGlob(p string) string {
	if strings.HasPrefix(p, "~/") {
		return "**/" + p[2:]
	}
	return p
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
