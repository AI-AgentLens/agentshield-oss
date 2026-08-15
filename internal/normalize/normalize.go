package normalize

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
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
	return normalize(args, strings.Join(args, " "), cwd)
}

// NormalizeCommand is like Normalize, but parses the AST from the caller's
// original, unmodified command string instead of reconstructing one from
// whitespace-split args.
//
// Normalize(strings.Fields(cmdStr), cwd) round-trips cmdStr through a
// quote-blind tokenizer and back (strings.Fields + strings.Join), which
// collapses every run of whitespace — including newlines inside a multi-line
// quoted argument like `python3 -c "\n...\n"` — into a single space. That can
// silently delete a statement separator the shell parser depends on (e.g. the
// newline before a `done`), turning a valid multi-line script into a syntax
// error. mvdan.cc/sh then falls back to a naive single-segment tokenizer that
// can misattribute a stray quote character from deep in the script to an
// earlier, unrelated command's argument list (issue #2831). Callers that hold
// the true raw command string (the IDE hook, `agentshield check --shell`)
// must use this instead so the AST reflects what the shell actually sees.
func NormalizeCommand(rawCmd string, cwd string) NormalizedCommand {
	return normalize(strings.Fields(rawCmd), rawCmd, cwd)
}

func normalize(args []string, rawCommand string, cwd string) NormalizedCommand {
	if len(args) == 0 {
		return NormalizedCommand{Cwd: cwd}
	}

	nc := NormalizedCommand{
		RawCommand: rawCommand,
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
		nc.Paths, nc.Domains = astAwareExtract(nc.Parsed, cwd, homeDir)
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
func astAwareExtract(parsed *shellparse.ParsedCommand, cwd, homeDir string) ([]string, []string) {
	var paths []string
	var domains []string

	// Walk each pipeline segment independently, with its own spec lookup and
	// its own positional-index counter. "grep X file | grep Y" must not let
	// the first grep's pattern-position rule apply to the second grep's
	// arguments, and a segment boundary must never shift which raw token a
	// later segment's position counting lands on.
	for _, seg := range parsed.Segments {
		p, d := extractSegmentPathsAndDomains(seg, cwd, homeDir)
		paths = append(paths, p...)
		domains = append(domains, d...)
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

// extractSegmentPathsAndDomains walks a single pipeline segment's own argv
// via seg.RawWords — the AST's quote-aware word list, where a single quoted
// argument containing internal whitespace ("'cat ~/.ssh/id_rsa'") stays ONE
// entry. Earlier versions of this function walked a caller-supplied token
// list produced by naively splitting the raw command on whitespace: that
// tokenizer doesn't know about quoting, so it broke a quoted multi-word
// argument into fragments. A designated "text" position (e.g. grep's pattern
// operand) only swallowed the FIRST fragment; the rest landed in the next
// positional slot as if it were a separate, real argument and — if it looked
// like a path — got misclassified as one, producing a protected-path false
// positive on commands like `grep -rn 'cat ~/.ssh/id_rsa' file.go` (#3224).
func extractSegmentPathsAndDomains(seg shellparse.CommandSegment, cwd, homeDir string) ([]string, []string) {
	// Build the set of text flags for this specific command.
	// Start with universal text flags, then overlay command-specific ones.
	cmdTextFlags := make(map[string]bool)
	for k, v := range textContentFlags {
		cmdTextFlags[k] = v
	}

	var allText bool
	var textPositions map[int]bool
	if spec, found := lookupSpec(seg); found {
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

	var paths []string
	var domains []string

	skipTextContent := false
	positionalIdx := 0 // tracks positional arg index (for TextPositions)

	words := seg.RawWords

	// Detect nested-shell-code patterns where a wrapper command (docker run,
	// kubectl exec, ssh host, su -c, env VAR=val, etc.) hands a string of code
	// to an inner interpreter via `bash -c <body>` / `python -c <body>` /
	// `node -e <body>`. Once we cross that body boundary, every remaining word
	// is INSIDE the inner code string — paths there are inert text payload,
	// not the wrapper's own filesystem accesses.
	//
	// FP this guards against (agentshield-oss#9): the host hook sees
	//   docker run --rm bash -c '... agentshield mcp-eval --arg path=/home/user/.ssh/id_rsa'
	// and the path extractor walks docker's args, finds `/home/user/.ssh/id_rsa`
	// inside the bash -c body, and `protected_paths` blocks the docker call.
	// Docker isn't reading the SSH key — it's launching a container that itself
	// runs a dry-run mcp-eval against a path STRING.
	nestedCodeStart := findNestedShellCodeStart(words)

	for i := 0; i < len(words); i++ {
		// Once inside an inner shell interpreter's code body, treat the rest
		// of the line as text (no path extraction). Domains are still extracted
		// since they remain meaningful for network-egress rules.
		if nestedCodeStart >= 0 && i >= nestedCodeStart {
			if d := extractDomains(words[i]); len(d) > 0 {
				domains = append(domains, d...)
			}
			continue
		}
		arg := words[i]

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

	return paths, domains
}

// nestedShellInterpreters lists the executables whose `-c` / `-e` flag carries
// inline source code. When one of these appears as a positional arg to a
// wrapper command (docker run, kubectl exec, env, su, sudo, ssh, time, ...),
// every arg after the body becomes inert text from the path-extractor's
// perspective. Source-of-truth match with argclass.go's commandRegistry.
var nestedShellInterpreters = map[string]string{
	"bash":    "c",
	"sh":      "c",
	"zsh":     "c",
	"dash":    "c",
	"ksh":     "c",
	"python":  "c",
	"python2": "c",
	"python3": "c",
	"ruby":    "e",
	"perl":    "e",
	"node":    "e",
}

// findNestedShellCodeStart returns the args index at which the *body* of an
// inner-shell-interpreter invocation begins, or -1 if no nested shell pattern
// is present. The pattern is `<interp> -<codeFlag> <body>`, optionally
// preceded by interpreter flags (e.g. `python3 -u -c <body>`). args is a
// single segment's own RawWords (executable already excluded), so index 0 is
// this segment's first argument — a wrapper prefix (docker, kubectl, su,
// env, ...) is just an earlier word in the same list and is still
// path-extracted normally.
//
// Returns the smallest such body index across all nested interpreters in args
// — once we cross the *first* nested code boundary, all subsequent args are
// inside that body, even if they happen to contain another interpreter name.
func findNestedShellCodeStart(args []string) int {
	earliest := -1
	for i := 0; i < len(args); i++ {
		// Strip path so `/usr/bin/bash` and `bash` both match.
		exec := args[i]
		if idx := strings.LastIndex(exec, "/"); idx >= 0 {
			exec = exec[idx+1:]
		}
		codeFlag, isInterp := nestedShellInterpreters[exec]
		if !isInterp {
			continue
		}
		// Walk forward looking for `-<codeFlag>` (skip other flags like -u/-x).
		for j := i + 1; j < len(args); j++ {
			a := args[j]
			if a == "-"+codeFlag {
				if j+1 < len(args) {
					if earliest < 0 || j+1 < earliest {
						earliest = j + 1
					}
				}
				break
			}
			// Concatenated short flags (e.g. -uc): consider matched if codeFlag
			// is one of the chars and the body is the next arg.
			if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && len(a) > 2 {
				if strings.ContainsRune(a[1:], rune(codeFlag[0])) {
					if j+1 < len(args) {
						if earliest < 0 || j+1 < earliest {
							earliest = j + 1
						}
					}
					break
				}
				continue // not the code flag, keep looking
			}
			// First non-flag positional arg without seeing -c: this interpreter
			// invocation isn't the inline-code form. Stop scanning for it.
			if !strings.HasPrefix(a, "-") {
				break
			}
		}
	}
	return earliest
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
	// Collapse shell quote-splices (~/.ss'h'/id_r'sa' → ~/.ssh/id_rsa) before
	// tilde/abs resolution so a quoted path resolves to the same location a shell
	// would open. Without this, the extracted token keeps its embedded quotes and
	// silently fails to match a protected_paths glob (issue #2813).
	path = pathnorm.StripShellQuotes(path)
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
