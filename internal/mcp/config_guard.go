package mcp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ConfigGuardFinding records a blocked config file write attempt.
type ConfigGuardFinding struct {
	Path     string `json:"path"`
	Pattern  string `json:"pattern"`
	Category string `json:"category"`
	Reason   string `json:"reason"`
	ArgName  string `json:"arg_name"`
}

// ConfigGuardResult is the result of checking a tool call for config file writes.
type ConfigGuardResult struct {
	Blocked  bool                 `json:"blocked"`
	Findings []ConfigGuardFinding `json:"findings,omitempty"`
}

// protectedConfigPattern defines a pattern and its metadata.
type protectedConfigPattern struct {
	pattern  string
	category string
	reason   string
}

// protectedConfigs is the list of config paths that should never be written by MCP tools.
// These are expanded at init time to replace ~ with the actual home directory.
var protectedConfigs []protectedConfigPattern

func init() {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/root"
	}

	templates := []protectedConfigPattern{
		// AgentShield's own config (tampering disables all protection)
		{"~/.agentshield/**", "agentshield-config", "Writing to AgentShield config could disable security protections."},
		{"~/.agentshield/policy.yaml", "agentshield-config", "Writing to AgentShield policy file could disable security protections."},
		{"~/.agentshield/mcp-policy.yaml", "agentshield-config", "Writing to MCP policy file could disable security protections."},

		// IDE hooks (removing hooks disables command interception)
		{"~/.claude/settings.json", "ide-hooks", "Writing to Claude Code settings could remove AgentShield command interception hooks."},
		{"~/.claude/settings.local.json", "ide-hooks", "Writing to Claude Code local settings could remove AgentShield hooks."},
		{"~/.codeium/windsurf/hooks.json", "ide-hooks", "Writing to Windsurf hooks could disable AgentShield command interception."},
		{"~/.cursor/hooks.json", "ide-hooks", "Writing to Cursor hooks could disable AgentShield command interception."},
		{"~/.openclaw/hooks/agentshield/**", "ide-hooks", "Writing to OpenClaw hooks could disable AgentShield command interception."},
		{"~/.gemini/settings.json", "ide-hooks", "Writing to Gemini CLI settings could remove AgentShield command interception hooks."},
		{"~/.codex/config.json", "ide-hooks", "Writing to Codex CLI config could remove AgentShield command interception hooks."},

		// IDE MCP config (can inject malicious MCP servers)
		{"~/.cursor/mcp.json", "ide-mcp-config", "Writing to Cursor MCP config could inject malicious MCP servers."},

		// Shell dotfiles (can alias commands, modify PATH, run code on shell start)
		{"~/.bashrc", "shell-config", "Writing to shell startup file could execute arbitrary code on every new shell."},
		{"~/.bash_profile", "shell-config", "Writing to shell startup file could execute arbitrary code on login."},
		{"~/.zshrc", "shell-config", "Writing to shell startup file could execute arbitrary code on every new shell."},
		{"~/.zprofile", "shell-config", "Writing to shell startup file could execute arbitrary code on login."},
		{"~/.profile", "shell-config", "Writing to shell startup file could execute arbitrary code on login."},

		// Package manager configs (supply chain attacks)
		{"~/.npmrc", "package-config", "Writing to npm config could redirect package installs to a malicious registry."},
		{"~/.pip/pip.conf", "package-config", "Writing to pip config could redirect package installs to a malicious registry."},
		{"~/.config/pip/pip.conf", "package-config", "Writing to pip config could redirect package installs to a malicious registry."},
		{"~/.pypirc", "package-config", "Writing to PyPI config could leak credentials or redirect uploads."},
		{"~/.yarnrc", "package-config", "Writing to yarn config could redirect package installs to a malicious registry."},
		{"~/.yarnrc.yml", "package-config", "Writing to yarn config could redirect package installs to a malicious registry."},
		{"~/.config/yarn/**", "package-config", "Writing to yarn config could redirect package installs."},
		{"~/.bunfig.toml", "package-config", "Writing to bun config could redirect package installs to a malicious registry."},

		// Git config (can set hooks, aliases)
		{"~/.gitconfig", "git-config", "Writing to git config could set malicious hooks or aliases."},
		{"~/.config/git/config", "git-config", "Writing to git config could set malicious hooks or aliases."},

		// SSH config (can set proxy commands)
		{"~/.ssh/config", "ssh-config", "Writing to SSH config could redirect connections through attacker-controlled proxies."},

		// Docker config (can set insecure registries)
		{"~/.docker/config.json", "docker-config", "Writing to Docker config could leak credentials or set insecure registries."},

		// Kubernetes config
		{"~/.kube/config", "kube-config", "Writing to kubeconfig could redirect cluster access."},

		// Claude Desktop MCP config (macOS)
		{"~/Library/Application Support/Claude/claude_desktop_config.json", "ide-mcp-config", "Writing to Claude Desktop config could inject malicious MCP servers."},
	}

	for _, t := range templates {
		expanded := strings.Replace(t.pattern, "~", home, 1)
		protectedConfigs = append(protectedConfigs, protectedConfigPattern{
			pattern:  expanded,
			category: t.category,
			reason:   t.reason,
		})
	}
}

// CheckConfigGuard scans tool call arguments for attempts to write to
// protected config files. This is a built-in guardrail that runs independently
// of policy rules — it blocks config file writes even if the tool/path would
// otherwise be allowed.
func CheckConfigGuard(toolName string, arguments map[string]interface{}) ConfigGuardResult {
	result := ConfigGuardResult{}

	for argName, argValue := range arguments {
		paths := extractPaths(argValue)
		for _, p := range paths {
			for _, cfg := range protectedConfigs {
				if matchConfigPath(p, cfg.pattern) {
					result.Findings = append(result.Findings, ConfigGuardFinding{
						Path:     p,
						Pattern:  cfg.pattern,
						Category: cfg.category,
						Reason:   cfg.reason,
						ArgName:  argName,
					})
				}
			}
		}
	}

	result.Blocked = len(result.Findings) > 0
	return result
}

// extractPaths finds file-path-like strings in an argument value.
// Returns paths found in strings, recursing into nested objects and arrays.
func extractPaths(v interface{}) []string {
	switch val := v.(type) {
	case string:
		return extractPathsFromString(val)
	case map[string]interface{}:
		var paths []string
		for _, nested := range val {
			paths = append(paths, extractPaths(nested)...)
		}
		return paths
	case []interface{}:
		var paths []string
		for _, item := range val {
			paths = append(paths, extractPaths(item)...)
		}
		return paths
	default:
		s := fmt.Sprintf("%v", v)
		return extractPathsFromString(s)
	}
}

// extractPathsFromString finds file paths in a string value.
// A string is treated as a path if it starts with /, ~/, or contains
// path-like patterns. For multi-line strings, each line is checked.
func extractPathsFromString(s string) []string {
	var paths []string

	// Check if the entire string looks like a path
	trimmed := strings.TrimSpace(s)
	if looksLikePath(trimmed) {
		// Expand ~ to home directory for matching
		paths = append(paths, expandHome(trimmed))
	}

	// Also check individual lines (for content= arguments with embedded paths)
	if strings.Contains(s, "\n") {
		for _, line := range strings.Split(s, "\n") {
			line = strings.TrimSpace(line)
			if looksLikePath(line) {
				paths = append(paths, expandHome(line))
			}
		}
	}

	return paths
}

// looksLikePath returns true if the string looks like a file path.
func looksLikePath(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~/") {
		// Must not be too long (avoid matching entire file contents)
		return len(s) < 512 && !strings.Contains(s, "\n")
	}
	return false
}

// expandHome replaces ~ with the actual home directory.
func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home := os.Getenv("HOME")
		if home != "" {
			return home + path[1:]
		}
	}
	return path
}

// matchConfigPath checks if a path matches a protected config pattern.
// Supports ** for recursive directory matching and * for single level.
func matchConfigPath(path, pattern string) bool {
	// Clean both for consistent comparison
	path = filepath.Clean(path)
	pattern = filepath.Clean(pattern)

	if !strings.Contains(pattern, "**") {
		matched, _ := filepath.Match(pattern, path)
		if matched {
			return true
		}
		// Also check if path is under the pattern (for directory patterns)
		if strings.HasSuffix(pattern, "/*") {
			dir := strings.TrimSuffix(pattern, "/*")
			return strings.HasPrefix(path, dir+"/")
		}
		return false
	}

	// Use the same glob matching as the policy engine
	vParts := splitPath(path)
	pParts := splitPathPattern(pattern)
	return globMatch(vParts, pParts)
}
