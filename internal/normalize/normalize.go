package normalize

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type NormalizedCommand struct {
	RawCommand string
	Executable string
	Args       []string
	Cwd        string
	Paths      []string
	Domains    []string
}

var (
	domainRegex = regexp.MustCompile(`https?://([^/\s'"]+)`)

	// textContentFlags are CLI flags whose values are prose text, not file paths.
	// When a command contains one of these flags, the subsequent argument(s)
	// (until the next flag) are treated as user-supplied text content and
	// excluded from path extraction. This prevents false positives when a
	// user passes security documentation as --body text.
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

	// skipTextContent is set true when we encounter a text-content flag (e.g.
	// --body, --message). All subsequent non-flag tokens are treated as prose
	// text and excluded from path extraction until the next flag resets the
	// state. This prevents false positives when paths appear inside
	// documentation text passed as flag values.
	skipTextContent := false

	// inHeredoc is set true after a heredoc operator (<<, <<-, <<'EOF', etc.)
	// is seen. All tokens until the closing delimiter are heredoc body content
	// and must not be extracted as paths. This prevents false positives when
	// protected-path strings appear in heredoc bodies (e.g. documentation,
	// generated Go code, multi-line config writes).
	// Reproduces: https://github.com/security-researcher-ca/AI_Agent_Shield/issues/79
	inHeredoc := false
	heredocDelim := ""
	nextIsHeredocDelim := false

	for _, arg := range args[1:] {
		// ── Heredoc state machine ──────────────────────────────────────────
		// Priority: heredoc state is checked before everything else so that
		// flags and paths inside heredoc bodies are never processed.

		if nextIsHeredocDelim {
			// This token is the heredoc delimiter (e.g. EOF, 'EOF', "MY_EOF")
			heredocDelim = stripHeredocDelimQuotes(arg)
			if heredocDelim != "" {
				inHeredoc = true
			}
			nextIsHeredocDelim = false
			continue
		}

		if inHeredoc {
			if arg == heredocDelim {
				// Closing delimiter found — exit heredoc body
				inHeredoc = false
				heredocDelim = ""
			}
			// Skip body tokens (including the closing delimiter itself)
			continue
		}

		// Detect heredoc operator tokens: <<, <<-, <<EOF, <<'EOF', <<"EOF", <<-EOF
		if strings.HasPrefix(arg, "<<") {
			suffix := arg[2:]
			suffix = strings.TrimPrefix(suffix, "-") // strip optional - (<<- indented heredoc)
			if suffix == "" {
				// Operator and delimiter are separate tokens: << EOF
				nextIsHeredocDelim = true
			} else {
				// Operator and delimiter are in one token: <<EOF or <<'EOF'
				heredocDelim = stripHeredocDelimQuotes(suffix)
				if heredocDelim != "" {
					inHeredoc = true
				}
			}
			continue
		}

		// ── Normal token processing ────────────────────────────────────────

		if strings.HasPrefix(arg, "-") {
			// Any new flag resets the text-content skip state.
			// Also handle combined short flags like -am (git commit -a -m shorthand):
			// if any single char in the combined flag is a text-content flag, skip paths.
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
			// Inside a text-content value — still extract domains (safe),
			// but skip path extraction to avoid false positives.
			if domains := extractDomains(arg); len(domains) > 0 {
				nc.Domains = append(nc.Domains, domains...)
			}
			continue
		}

		if looksLikePath(arg) {
			expanded := expandPath(arg, cwd, homeDir)
			nc.Paths = append(nc.Paths, expanded)
		}

		if domains := extractDomains(arg); len(domains) > 0 {
			nc.Domains = append(nc.Domains, domains...)
		}
	}

	// Handle git clone specially for SSH URLs (HTTPS already captured above)
	if nc.Executable == "git" && len(args) > 2 && args[1] == "clone" {
		repoURL := args[2]
		if strings.HasPrefix(repoURL, "git@") {
			if domain := extractGitDomain(repoURL); domain != "" {
				nc.Domains = append(nc.Domains, domain)
			}
		}
	}

	// Deduplicate domains
	nc.Domains = uniqueStrings(nc.Domains)

	return nc
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

// stripHeredocDelimQuotes removes surrounding single or double quotes from a
// heredoc delimiter token. Shell allows quoting the delimiter to suppress
// expansion: <<'EOF', <<"EOF". The closing line must match the unquoted name.
func stripHeredocDelimQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') ||
			(s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
