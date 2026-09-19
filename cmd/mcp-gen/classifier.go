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

// writeCoveredElsewhere lists protected_paths entries whose WRITE access is
// already BLOCKed by a dedicated, more-specifically-taxonomized MCP rule
// elsewhere in the corpus. Without this, classifyProtectedPaths always emits
// AllFileTools (read+write+delete) under the generic
// credential-exposure/config-file-access/protected-path taxonomy, which
// double-fires alongside the dedicated rule on every write — the two-way
// taxonomy disagreement #3735 found for ~/.m2/settings.xml (dedicated rule:
// mcp-sc-block-pkgmgr-config-write, supply-chain/config-tampering/
// package-registry-redirect). Listing a path here scopes the generated rule
// to ReadDeleteTools instead: the write is still BLOCKed, just attributed to
// the rule that actually describes the write threat. This is NOT a coverage
// reduction — read and delete stay covered by the generic rule as before.
var writeCoveredElsewhere = map[string]bool{
	"~/.m2/settings.xml": true,
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
		tools := AllFileTools
		if writeCoveredElsewhere[p] {
			tools = ReadDeleteTools
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
			ToolNames: tools,
			Decision:  "BLOCK",
			Reason:    fmt.Sprintf("Access to protected path %s is blocked.", p),
		})
	}
	return candidates
}

// hazardousConversion lists shell rule IDs the generic path/URL extraction
// converts into an MCP candidate that is either already fully covered by a
// dedicated hand-authored rule, or would carry unacceptable FP risk once the
// shell rule's real gate (a specific verb, or specific keyword content) is
// discarded in favor of a bare path match. This is the classifyRule-side
// counterpart to writeCoveredElsewhere above; that map narrows tool coverage
// on a still-emitted protected-path candidate, this one refuses emission
// entirely. Coverage-based dedup (#3464) does not catch these because it
// compares each candidate's paths against the existing policy independently —
// it never sees that ALL of a multi-path candidate's targets are covered, or
// that the sensitivity here comes from CONTENT the path-only conversion drops.
// Found reviewing #3778's net-new batch:
//   - ts-block-find-fwrite-sensitive-path: extraction keeps only 2 of ~9
//     protected targets from the source regex (/var/root, /usr/lib) — both
//     already BLOCKed by mcp-persist-block-var-root-write and
//     mcp-safety-block-usr-write. Zero net-new coverage.
//   - ts-block-chflags-immutable-writable-tmp: extracted targets /var/tmp and
//     /var/folders — the latter is macOS's live $TMPDIR root, used by
//     essentially every legitimate temp-file operation. The shell rule's
//     precision comes from requiring the chflags lock verb; a bare "any write
//     to this path" MCP conversion loses that gate and would BLOCK ordinary
//     temp-file writes.
//   - sc-block-ai-endpoint-dotenv-write: the shell regex requires specific
//     AI-endpoint env-var names (OPENAI_BASE_URL etc.) in the written content
//     — the sensitivity is the CONTENT, not the .env path. extractPaths keeps
//     only the destination path, producing a candidate that would BLOCK any
//     write to a home-dir .env file regardless of content.
//   - ts-block-chflags-clear-immutable-system: extracted targets /var/db,
//     /var/log, /var/root — the first and third are already BLOCKed
//     (mcp-persist-block-var-db-write, mcp-persist-block-var-root-write); only
//     /var/log is genuinely new. Shipped by hand instead as
//     mcp-persist-block-var-log-write, a sibling of the two existing rules,
//     rather than teaching the classifier to split a multi-path candidate.
//   - ts-block-mfa-seed-replacement: extracted target /root/.google_authenticator
//     is already BLOCKed by mcp-sec-block-google-authenticator-write
//     (packs/premium/mcp/mcp-devtool-creds.yaml, same taxonomy
//     credential-exposure/mfa-bypass/mfa-seed-replacement), whose pattern is
//     "**/.google_authenticator" — broader than anything this conversion would
//     produce. CoverageChecker.Covers() should have caught this and didn't;
//     see the follow-up issue on `**/...`-prefixed glob coverage checks.
//   - sec-block-package-manager-credentials: extracted target .m2/settings.xml
//     (the only one of the source rule's 4 credential files this conversion
//     manages to extract — cargo/credentials, .gem/credentials and
//     gradle.properties all have their own dedicated rules in
//     packs/community/mcp/mcp-secrets.yaml already) is itself fully covered
//     by the combination of mcp-gen-protected-path-m2-settingsxml (read/delete,
//     from this same file's protected_paths handling) and
//     mcp-sc-block-pkgmgr-config-write (write, packs/premium/mcp/
//     mcp-supply-chain.yaml) — see that pack's own comment: "Note:
//     ~/.m2/settings.xml is already blocked via
//     mcp-gen-protected-path-m2-settingsxml." Third confirmed instance of
//     CoverageChecker.Covers() missing a real overlap; see #3817.
var hazardousConversion = map[string]bool{
	"ts-block-find-fwrite-sensitive-path":     true,
	"ts-block-chflags-immutable-writable-tmp": true,
	"sc-block-ai-endpoint-dotenv-write":       true,
	"ts-block-chflags-clear-immutable-system": true,
	"ts-block-mfa-seed-replacement":           true,
	"sec-block-package-manager-credentials":   true,
}

// classifyRule attempts to classify a single shell rule as convertible.
func classifyRule(rule ShellRule) (Candidate, bool) {
	if hazardousConversion[rule.ID] {
		return Candidate{}, false
	}

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

		// `ln` (symlink/hardlink creation) has no MCP tool equivalent: every
		// MCP tool family (read_file/write_file/...) operates on file
		// CONTENT, not filesystem links, so there is no faithful conversion
		// of "create a link pointing at <credential path>". Left unexcluded,
		// extractPaths still finds the credential-path literals in the
		// regex and classifyPathCategory defaults such rules to
		// "path-read" — producing an MCP rule that matches read_file calls
		// against the bare containing directory (no `/**` suffix, since the
		// path text after `ln -s ... ` never appears as a real extractable
		// path) and does not detect the symlink-creation threat the rule's
		// own `reason` field describes. See #3566.
		"ln\\s",
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
//
// A source rule frequently protects several sibling targets behind a shared
// prefix and a parenthesized alternation — "/etc/(cron|sudoers|profile)",
// "/home/[^/]+/\.(ssh|aws)" — rather than one flat regex per target. The
// extraction patterns below are string/char-class based, so a "(" sitting
// directly where they need a path character to continue stops the match
// dead; expandAlternations flattens each such group into one variant per
// branch first, so every alternative gets its own clean run of text to
// extract from (#3817 finding #1 — 3/3 multi-alternative shell regexes
// audited lost real branches this way).
func extractPaths(regex string) []string {
	var paths []string

	for _, variant := range expandAlternations(regex) {
		paths = append(paths, extractPathsFromFlatText(variant)...)
	}

	// Pattern 4: known credential-file locations whose source regex spells
	// the target as a bare relative fragment with no leading dot at all
	// (e.g. "cargo/credentials", relying on a preceding ".*" to match the
	// real "~/.cargo/credentials" path at runtime). No amount of alternation
	// flattening recovers these — Pattern 2 below requires the captured text
	// to itself begin with a literal "." — so they need their own explicit,
	// narrowly curated lookup rather than a broadened Pattern 2. Substring
	// matched against the original (unexpanded) text: these are plain
	// literals, so surrounding "(" / "|" noise doesn't affect the check.
	for fragment, real := range bareCredentialFragments {
		if strings.Contains(regex, fragment) {
			paths = append(paths, anchorToHomeDirs(real)...)
		}
	}

	return dedup(paths)
}

// extractPathsFromFlatText runs the three literal/char-class extraction
// patterns against a single candidate string (either the original regex, or
// one branch of an alternation group flattened into place by
// expandAlternations).
func extractPathsFromFlatText(text string) []string {
	var paths []string

	// Pattern 1: Explicit absolute paths like /etc/shadow, /etc/wireguard/
	for _, idx := range absPathRe.FindAllStringSubmatchIndex(text, -1) {
		if matchTruncatedByGroup(text, idx[3]) {
			continue
		}
		path := cleanRegexPath(text[idx[2]:idx[3]])
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
	for _, idx := range dotPathRe.FindAllStringSubmatchIndex(text, -1) {
		if matchTruncatedByGroup(text, idx[3]) {
			continue
		}
		raw := text[idx[2]:idx[3]]
		// Must start with a known sensitive dot-dir/file.
		if isSensitiveDotPath(raw) {
			if cleaned := cleanRegexPath(raw); cleaned != "" {
				paths = append(paths, anchorToHomeDirs(cleaned)...)
			}
		}
	}

	// Pattern 3: Cloud metadata URLs (treated as paths for MCP network rules).
	if metadataRe.MatchString(text) {
		paths = append(paths, metadataRe.FindAllString(text, -1)...)
	}

	return paths
}

// matchTruncatedByGroup reports whether a Pattern 1/2 match stopped exactly
// where it did only because the next byte is an unexpanded "(" — i.e. the
// match is a truncated fragment of a larger alternation group
// (expandAlternations always retries the fully-unexpanded original regex
// alongside its flattened variants, so a group adjacent to the matched text
// can still be present unexpanded in that pass). A real path never has a
// regex group appended directly with no separator, so this can only ever
// suppress a truncation artifact, never a genuine path (#3817).
func matchTruncatedByGroup(text string, matchEnd int) bool {
	return matchEnd < len(text) && text[matchEnd] == '('
}

var (
	absPathRe  = regexp.MustCompile(`(/(?:etc|var|opt|usr|root|home|Library|proc)/[a-zA-Z0-9_./\\-]+)`)
	dotPathRe  = regexp.MustCompile(`(\.\w+(?:/(?:[a-zA-Z0-9_.*-]|\\\.)+)*)`)
	metadataRe = regexp.MustCompile(`(169\.254\.169\.254|metadata\.google\.internal)`)
)

// bareCredentialFragments maps a known package-manager credential location,
// spelled in shell-rule source text as a bare relative fragment with no
// leading dot, to its real dotted path. See the Pattern 4 comment in
// extractPaths (#3817, sec-block-package-manager-credentials).
//
// The key is matched with strings.Contains against the raw regex SOURCE, so
// it must carry the same escaping the source rule actually uses — the dot in
// "gradle.properties" is spelled `gradle\.properties` in
// sec-block-package-manager-credentials, and a key without the backslash
// silently never matches (caught by
// TestExtractPathsRecoversMultiAlternationBranches/pkgmgr_no_leading_dot_branches).
var bareCredentialFragments = map[string]string{
	"cargo/credentials":  ".cargo/credentials",
	`gradle\.properties`: ".gradle/gradle.properties",
}

// maxAlternationVariants bounds the number of flattened strings a single
// extractPaths call will generate. Expansion is one-group-at-a-time (see
// expandAlternations), so the count grows as the SUM of each group's branch
// count, not their product — a rule with six alternation groups of sizes
// 2,4,3,2,2,3 (the densest one measured in this corpus,
// ts-block-mfa-seed-replacement) produces 16 variants, comfortably inside
// this cap. The cap exists only to keep a future pathological regex from
// stalling `go run ./cmd/mcp-gen`; hitting it degrades to a partial result
// rather than an error.
const maxAlternationVariants = 512

// expandAlternations returns, for every parenthesized alternation group
// found anywhere in regex (at any nesting depth), one variant of the whole
// string per branch of that group with ONLY that group's text replaced by
// its branch — every other group in the string is left exactly as written.
// The original, fully-unexpanded regex is always included too, so text
// outside any group is still covered.
//
// This is deliberately one-group-at-a-time, not a full cartesian product
// across every group in the string. A cartesian product multiplies (2 * 4 *
// 3 * 2 * 2 * 3 = 288 variants for the densest rule measured here); the
// patterns extractPaths runs per-variant only look at a local run of
// characters around a path, so an unrelated sibling group elsewhere in the
// string is inert syntax noise whether or not it has also been expanded —
// there is nothing to gain from expanding it in the same pass.
func expandAlternations(regex string) []string {
	variants := []string{regex}
	for _, g := range findAlternationGroups(regex) {
		branches := splitTopLevelAlternation(strings.TrimPrefix(g.inner, "?:"))
		if len(branches) < 2 {
			continue
		}
		for _, b := range branches {
			if len(variants) >= maxAlternationVariants {
				break
			}
			variants = append(variants, regex[:g.start]+b+regex[g.end+1:])
		}
	}
	return dedup(variants)
}

// alternationGroup is a parenthesized group of the original regex string
// (byte range [start,end], both inclusive of the parens) whose contents
// contain at least one top-level "|".
type alternationGroup struct {
	start, end int
	inner      string // regex[start+1 : end], i.e. without the enclosing parens
}

// findAlternationGroups scans regex for every "(...)" / "(?:...)" group,
// locating each one's byte-offset boundaries by paren-depth tracking (a job
// splitTopLevelAlternation doesn't do — it only ever answers "where are the
// top-level splits of THIS string", never "where do nested groups start and
// end"), and keeps the ones whose contents contain a top-level "|" (checked
// via splitTopLevelAlternation itself, rather than a second hand-rolled
// pipe/bracket-class tracker). Escaped characters (`\(`, `\)`, `\[`) are
// skipped rather than treated as structural.
func findAlternationGroups(regex string) []alternationGroup {
	var stack []int
	var groups []alternationGroup
	inClass := false
	for i := 0; i < len(regex); i++ {
		c := regex[i]
		switch {
		case c == '\\':
			i++ // skip the escaped character, whatever it is
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
		case c == '(':
			stack = append(stack, i)
		case c == ')':
			if len(stack) == 0 {
				continue // unbalanced input — defensive, not expected in practice
			}
			start := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			inner := regex[start+1 : i]
			if len(splitTopLevelAlternation(strings.TrimPrefix(inner, "?:"))) >= 2 {
				groups = append(groups, alternationGroup{start: start, end: i, inner: inner})
			}
		}
	}
	return groups
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
		".gem",
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

// editVerbRe matches interactive editors, which open the operand path for
// BOTH reading and writing. Neither readVerbRe nor writeWordRe recognised
// them, so a branch shaped `(cat|less|vi?|nano)\s+.*<credential path>` set
// neither hasRead nor hasWrite, and classifyPathCategory fell through to its
// default "path-read" — emitting an MCP rule with only ReadTools. The
// write-family tools the shell source plainly intends to cover (an agent
// *editing* the credential file through write_file/str_replace_editor) were
// silently dropped (#3589).
//
// Matching is against the regex SOURCE text, so the sloppy-but-common `vi?`
// spelling (regex for "v" or "vi") must match too: `vim?` tries "vim",
// backtracks to "vi", and the trailing `\b` succeeds because `?` is not a
// word character.
//
// Deliberately NOT included:
//   - `view` / `rview` — vim's read-only mode; a write signal there would be
//     wrong in exactly the direction this fix must not overreach.
//   - `ex` — two letters with no editor-specific shape; too easy to collide
//     with an unrelated regex fragment for a signal that flips tool families.
//   - `sed` — a stream editor that writes to stdout; only `sed -i` writes in
//     place, which is a different (positional) signal than a verb list can
//     express. Out of scope for #3589, which is about interactive editors.
var editVerbRe = regexp.MustCompile(`\b([gmrn]?vim|vi|nano|pico|emacsclient|emacs|ed)\b`)

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
		if editVerbRe.MatchString(branch) {
			// An interactive editor opens the path for both directions.
			hasWrite = true
			hasRead = true
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
//
// "C:/Users/*/" covers the Windows dotfile-under-home layout (#3607) — every
// tool these rules protect (Docker, curl/.netrc, GitHub CLI, Vault,
// Terraform, pip, Cargo, Maven) ships a native Windows build that stores its
// config the same way. Forward-slash spelled per the existing convention
// (#3605's investigation: MCP argument values in this corpus are
// consistently forward-slash); matchGlob's case-fold and separator
// normalisation (#3606/#3610) handle the rest at match time.
var homeDirRoots = []string{"/home/*/", "/root/", "/var/root/", "/Users/*/", "C:/Users/*/"}

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
