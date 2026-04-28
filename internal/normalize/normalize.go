package normalize

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

type NormalizedCommand struct {
	RawCommand string
	Executable string
	Args       []string
	Cwd        string
	Paths      []string
	Domains    []string
	Parsed     *shellparse.ParsedCommand // AST parse result, reusable by downstream analyzers
}

var (
	domainRegex = regexp.MustCompile(`https?://([^/\s'"]+)`)

	// textContentFlags are CLI flags whose values are prose text, not file paths.
	// Used by both the AST-aware path and the fallback tokenizer.
	textContentFlags = map[string]bool{
		"--body":        true,
		"--message":     true,
		"-m":            true,
		"--title":       true,
		"--comment":     true,
		"--description": true,
		"--subject":     true,
		"--notes":       true,
		"--template":    true,
		"--reason":      true,
	}
)

func Normalize(args []string, cwd string) NormalizedCommand {
	if len(args) == 0 {
		return NormalizedCommand{Cwd: cwd}
	}

	nc := NormalizedCommand{
		RawCommand: strings.Join(args, " "),
		Executable: filepath.Base(args[0]),
		Args:       args,
		Cwd:        cwd,
		Paths:      []string{},
		Domains:    []string{},
	}

	homeDir, _ := os.UserHomeDir()

	// Parse the command AST for downstream reuse (structural analyzer).
	// Even if we don't use it for path extraction, we cache it.
	hasHeredoc := containsHeredoc(args)
	if !hasHeredoc {
		nc.Parsed = shellparse.Parse(nc.RawCommand, 2)
	}

	// For path extraction, use AST-aware classification.
	// The AST identifies the command + subcommand, then we walk the original
	// args with a spec-aware state machine that knows which flags are text.
	// This hybrid approach combines AST command identification with the
	// reliable token-order-based flag-value tracking.
	if nc.Parsed != nil && len(nc.Parsed.Segments) > 0 {
		nc.Paths, nc.Domains = astAwareExtract(args, nc.Parsed, cwd, homeDir)
	} else {
		// Fallback: original tokenizer (heredoc + textContentFlags)
		nc.Paths, nc.Domains = fallbackExtract(args, cwd, homeDir)
	}

	// Handle git clone specially for SSH URLs
	if nc.Executable == "git" && len(args) > 2 && args[1] == "clone" {
		repoURL := args[2]
		if strings.HasPrefix(repoURL, "git@") {
			if domain := extractGitDomain(repoURL); domain != "" {
				nc.Domains = append(nc.Domains, domain)
			}
		}
	}

	nc.Domains = uniqueStrings(nc.Domains)
	return nc
}

// astAwareExtract uses the AST parse result to identify the command, then
// walks the original tokenized args with a command-specific state machine
// that knows which flags carry text content.
//
// Compared to the old tokenizer, this approach:
// - Knows specific command semantics (echo args are all text, grep arg[0] is pattern)
// - Handles combined flags like -am by checking each char against spec
// - Still falls back to universal textContentFlags for unknown commands
func astAwareExtract(args []string, parsed *shellparse.ParsedCommand, cwd, homeDir string) ([]string, []string) {
	// Build the set of text flags for this specific command.
	// Start with universal text flags, then overlay command-specific ones.
	cmdTextFlags := make(map[string]bool)
	for k, v := range textContentFlags {
		cmdTextFlags[k] = v
	}

	// Identify the command from the AST
	var allText bool
	var textPositions map[int]bool
	if len(parsed.Segments) > 0 {
		seg := parsed.Segments[0]
		spec, found := lookupSpec(seg)
		if found {
			allText = spec.AllPositionalText
			textPositions = spec.TextPositions

			// Add command-specific text flags in both short (-m) and long (--message) forms
			for flag := range spec.TextFlags {
				if len(flag) == 1 {
					cmdTextFlags["-"+flag] = true
				} else {
					cmdTextFlags["--"+flag] = true
				}
			}
			for flag := range spec.InlineCodeFlags {
				if len(flag) == 1 {
					cmdTextFlags["-"+flag] = true
				} else {
					cmdTextFlags["--"+flag] = true
				}
			}
		}
	}

	var paths []string
	var domains []string

	// Walk original args with state machine (similar to fallback but spec-aware)
	skipTextContent := false
	positionalIdx := 0 // tracks positional arg index (for TextPositions)

	// Skip the executable (args[0]) and any subcommand tokens
	startIdx := 1

	for i := startIdx; i < len(args); i++ {
		arg := args[i]

		// Flag handling
		if strings.HasPrefix(arg, "-") {
			// Check for combined short flags like -am where one char is a text flag
			if !strings.HasPrefix(arg, "--") && len(arg) > 2 {
				found := false
				for _, ch := range arg[1:] {
					if cmdTextFlags["-"+string(ch)] {
						found = true
						break
					}
				}
				if found {
					skipTextContent = true
					continue
				}
			}
			skipTextContent = cmdTextFlags[arg]
			continue
		}

		if skipTextContent {
			// Inside text flag value — extract domains but skip paths
			if d := extractDomains(arg); len(d) > 0 {
				domains = append(domains, d...)
			}
			continue
		}

		// All-text commands: echo, printf — every positional arg is text
		if allText {
			if d := extractDomains(arg); len(d) > 0 {
				domains = append(domains, d...)
			}
			positionalIdx++
			continue
		}

		// Text positions: grep positional[0] is pattern
		if textPositions != nil && textPositions[positionalIdx] {
			if d := extractDomains(arg); len(d) > 0 {
				domains = append(domains, d...)
			}
			positionalIdx++
			continue
		}

		// Normal argument — extract paths and domains
		if looksLikePath(arg) {
			paths = append(paths, expandPath(arg, cwd, homeDir))
		}
		if d := extractDomains(arg); len(d) > 0 {
			domains = append(domains, d...)
		}
		positionalIdx++
	}

	// Also extract paths from AST redirects (these are always real paths)
	for _, seg := range shellparse.AllSegments(parsed) {
		for _, redir := range seg.Redirects {
			if redir.Path != "" && looksLikePath(redir.Path) {
				paths = append(paths, expandPath(redir.Path, cwd, homeDir))
			}
		}
	}
	for _, redir := range parsed.Redirects {
		if redir.Path != "" && looksLikePath(redir.Path) {
			paths = append(paths, expandPath(redir.Path, cwd, homeDir))
		}
	}

	return paths, domains
}

// fallbackExtract is the original tokenizer-based extraction with heredoc and
// textContentFlags support. Used when AST parsing fails or for heredoc commands.
func fallbackExtract(args []string, cwd, homeDir string) ([]string, []string) {
	var paths []string
	var domains []string

	skipTextContent := false
	inHeredoc := false
	heredocDelim := ""
	nextIsHeredocDelim := false

	for _, arg := range args[1:] {
		// ── Heredoc state machine ──────────────────────────────────────────
		if nextIsHeredocDelim {
			heredocDelim = stripHeredocDelimQuotes(arg)
			if heredocDelim != "" {
				inHeredoc = true
			}
			nextIsHeredocDelim = false
			continue
		}

		if inHeredoc {
			if arg == heredocDelim {
				inHeredoc = false
				heredocDelim = ""
			}
			continue
		}

		if strings.HasPrefix(arg, "<<") {
			suffix := arg[2:]
			suffix = strings.TrimPrefix(suffix, "-")
			if suffix == "" {
				nextIsHeredocDelim = true
			} else {
				heredocDelim = stripHeredocDelimQuotes(suffix)
				if heredocDelim != "" {
					inHeredoc = true
				}
			}
			continue
		}

		// ── Normal token processing ────────────────────────────────────────
		if strings.HasPrefix(arg, "-") {
			if !strings.HasPrefix(arg, "--") && len(arg) > 2 {
				found := false
				for _, ch := range arg[1:] {
					if textContentFlags["-"+string(ch)] {
						found = true
						break
					}
				}
				if found {
					skipTextContent = true
					continue
				}
			}
			skipTextContent = textContentFlags[arg]
			continue
		}

		if skipTextContent {
			if d := extractDomains(arg); len(d) > 0 {
				domains = append(domains, d...)
			}
			continue
		}

		if looksLikePath(arg) {
			expanded := expandPath(arg, cwd, homeDir)
			paths = append(paths, expanded)
		}

		if d := extractDomains(arg); len(d) > 0 {
			domains = append(domains, d...)
		}
	}

	return paths, domains
}

func looksLikePath(arg string) bool {
	if strings.HasPrefix(arg, "-") {
		return false
	}

	if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
		return false
	}

	if strings.HasPrefix(arg, "/") ||
		strings.HasPrefix(arg, "./") ||
		strings.HasPrefix(arg, "../") ||
		strings.HasPrefix(arg, "~/") ||
		strings.Contains(arg, "/") {
		return true
	}

	return false
}

func expandPath(path, cwd, homeDir string) string {
	if strings.HasPrefix(path, "~/") && homeDir != "" {
		path = filepath.Join(homeDir, path[2:])
	}

	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}

	cleaned := filepath.Clean(path)
	return cleaned
}

func extractDomains(s string) []string {
	matches := domainRegex.FindAllStringSubmatch(s, -1)
	domains := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			domains = append(domains, match[1])
		}
	}
	return domains
}

func extractGitDomain(repoURL string) string {
	if strings.HasPrefix(repoURL, "git@") {
		parts := strings.SplitN(repoURL, ":", 2)
		if len(parts) > 0 {
			return strings.TrimPrefix(parts[0], "git@")
		}
	}

	if strings.HasPrefix(repoURL, "http://") || strings.HasPrefix(repoURL, "https://") {
		if u, err := url.Parse(repoURL); err == nil {
			return u.Host
		}
	}

	return ""
}

func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(input))
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// containsHeredoc checks if tokenized args contain heredoc syntax (<<, <<-, <<EOF, etc.).
func containsHeredoc(args []string) bool {
	for _, arg := range args {
		if strings.HasPrefix(arg, "<<") {
			return true
		}
	}
	return false
}

// stripHeredocDelimQuotes removes surrounding single or double quotes from a
// heredoc delimiter token.
func stripHeredocDelimQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') ||
			(s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
