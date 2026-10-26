package normalize

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/mountspec"
	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
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

// isCommentOnly reports whether cmd holds at least one bash comment line and
// nothing else: every line is blank or starts, after leading spaces and tabs,
// with `#`. A blank command is not comment-only.
//
// Only space and tab are trimmed, because those are the only blanks bash and
// zsh skip before a word. strings.TrimSpace would also strip \r, \v, \f and
// Unicode spaces, and `\r# $(cat …)` is not a comment: the shell runs a
// command named `\r#` and executes the substitution (#4013 Codex pass 1).
func isCommentOnly(cmd string) bool {
	sawComment := false
	for _, line := range strings.Split(cmd, "\n") {
		line = strings.TrimLeft(line, " \t")
		switch {
		case line == "":
		case strings.HasPrefix(line, "#"):
			sawComment = true
		default:
			return false
		}
	}
	return sawComment
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
	keepDots := !defaultGlobbing(nc.Parsed, rawCommand)

	// For path extraction, use AST-aware classification.
	// The AST identifies the command + subcommand, then we walk the original
	// args with a spec-aware state machine that knows which flags are text.
	// This hybrid approach combines AST command identification with the
	// reliable token-order-based flag-value tracking.
	switch {
	case nc.Parsed != nil && len(nc.Parsed.Segments) > 0:
		nc.Paths, nc.Domains = astAwareExtract(nc.Parsed, cwd, homeDir, keepDots)
	case nc.Parsed != nil && isCommentOnly(nc.RawCommand):
		// Every line is a bash comment (`# cat ~/.ssh/id_rsa`): nothing
		// executes, so leave Paths/Domains empty (#4009). The naive tokenizer
		// below does not know about `#`, and the built-in protected-path check
		// runs on nc.Paths before intent labels like is_bash_comment apply.
		//
		// Keyed on the TEXT, not on the segment count: shellparse also returns
		// zero segments for `export K=$(cat …)`, `local`/`declare`/`readonly`
		// with a command substitution, `[[ … ]]`, and a bare `>`/`>>`
		// redirect. Those execute or write, and their only path extraction is
		// the fallback below (#4013 review).
	default:
		// Fallback: original tokenizer. Required for heredoc commands, where
		// shellparse.Parse is deliberately not called (see hasHeredoc above),
		// and for the zero-segment shapes listed in the case above.
		nc.Paths, nc.Domains = fallbackExtract(args, cwd, homeDir, keepDots)
	}

	// A command substitution's body is a shell program the outer command
	// runs before, or while, doing whatever the outer statement does — a
	// protected path read inside `$(...)` is as much a read as the same
	// command standing alone (#4030). Neither branch above sees it: the
	// AST-aware walker treats the whole `$(...)` word as one opaque dynamic
	// token (it contains "/" so it can even get misclassified and mangled
	// as a bogus literal path by expandPath), and the zero-segment fallback
	// tokenizer only stumbles onto a path here by accident of where
	// whitespace happens to split the substitution syntax. Walk every
	// substitution body — regardless of which branch ran above — and
	// extract its own paths/domains the same way a top-level command would.
	//
	// A heredoc command skips the parse above (nc.Parsed stays nil for the
	// fallback tokenizer's sake), but an unquoted heredoc body still runs its
	// substitutions, so parse it here for this walk only.
	substParsed := nc.Parsed
	if substParsed == nil {
		substParsed = shellparse.Parse(nc.RawCommand, 2)
	}
	subPaths, subDomains := extractSubstitutionPaths(substParsed, cwd, homeDir, keepDots)
	nc.Paths = append(nc.Paths, subPaths...)
	nc.Domains = append(nc.Domains, subDomains...)

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
func astAwareExtract(parsed *shellparse.ParsedCommand, cwd, homeDir string, keepDots bool) ([]string, []string) {
	return astAwareExtractRedirs(parsed, cwd, homeDir, false, keepDots)
}

// isDataRedirect reports whether a redirect's word is data the command reads
// on stdin rather than a file it opens: a here-string's word (`<<<`) or a
// heredoc's delimiter (`<<`, `<<-`).
func isDataRedirect(op string) bool {
	return op == "<<<" || op == "<<" || op == "<<-"
}

// astAwareExtractRedirs is astAwareExtract with a choice about data
// redirects. The top-level call keeps them (skipData false), exactly as main
// always has: `cat<<<'f'` extracts f there today, and removing that is a
// separate narrowing, not part of #4030. The substitution walk skips them
// (#4051 Opus pass 2, F1): `N=$(wc -l <<< 'f')` counts the characters of the
// text "f" and opens nothing, and main never extracted it — the spaced `<<<`
// sent main's whole command to the fallback tokenizer, whose heredoc state
// machine swallows everything after the operator. (An unspaced word inside a
// substitution is still extracted by the top-level walk, as on main.)
func astAwareExtractRedirs(parsed *shellparse.ParsedCommand, cwd, homeDir string, skipData, keepDots bool) ([]string, []string) {
	var paths []string
	var domains []string

	// Walk each pipeline segment independently, with its own spec lookup and
	// its own positional-index counter. "grep X file | grep Y" must not let
	// the first grep's pattern-position rule apply to the second grep's
	// arguments, and a segment boundary must never shift which raw token a
	// later segment's position counting lands on.
	for _, seg := range parsed.Segments {
		p, d := extractSegmentPathsAndDomains(seg, cwd, homeDir, keepDots)
		paths = append(paths, p...)
		domains = append(domains, d...)
	}

	// Also extract paths from AST redirects (these are always real paths)
	for _, seg := range shellparse.AllSegments(parsed) {
		for _, redir := range seg.Redirects {
			if skipData && isDataRedirect(redir.Op) {
				continue
			}
			paths = append(paths, redirectTargetPaths(redir.Op, redir.Path, cwd, homeDir, keepDots)...)
		}
	}
	for _, redir := range parsed.Redirects {
		if skipData && isDataRedirect(redir.Op) {
			continue
		}
		paths = append(paths, redirectTargetPaths(redir.Op, redir.Path, cwd, homeDir, keepDots)...)
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
func extractSegmentPathsAndDomains(seg shellparse.CommandSegment, cwd, homeDir string, keepDots bool) ([]string, []string) {
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
	isTar := tarExecutables[filepath.Base(seg.Executable)]
	tarDir := cwd

	// A container bind mount reads its SOURCE (#3630). The spec is one argv
	// token — `~/.creds:/mnt` — so the trailing `:` defeats every
	// protected-path glob unless the source is extracted separately. Only
	// words before any nested interpreter body count: paths inside
	// `docker run … bash -c '<body>'` are the inner script's text, not
	// docker's own filesystem access (agentshield-oss#9).
	if mountspec.IsContainerRuntime(seg.Executable) {
		limit := len(words)
		if nestedCodeStart >= 0 {
			limit = nestedCodeStart
		}
		for _, src := range mountspec.Sources(words[:limit]) {
			paths = append(paths, expandPath(src, cwd, homeDir))
		}
	}

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

		// tar -C <dir> changes the directory its later operands resolve
		// against (#4381): `tar czf x.tgz -C ~ .ssh` reads ~/.ssh.
		if isTar {
			if dir, skip, ok := tarDirectoryFlag(words, i); ok {
				if pathnorm.StripShellQuotes(dir) == "~" && homeDir != "" {
					dir = homeDir
				}
				tarDir = expandPath(dir, tarDir, homeDir)
				if looksLikePath(dir) {
					paths = append(paths, tarDir)
				}
				i += skip
				continue
			}
			if tarDir != cwd && !strings.HasPrefix(arg, "-") && !skipTextContent {
				if p, ok := tarOperandPath(arg, tarDir, homeDir); ok {
					paths = append(paths, p)
				}
			}
		}

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
		} else if p, ok := bareOperandPath(arg, cwd, seg.Executable); ok {
			paths = append(paths, p)
		} else {
			paths = append(paths, bareGlobPaths(arg, cwd, keepDots)...)
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

// extractSubstitutionPaths extracts the paths and domains every command and
// process substitution in parsed would touch when it runs.
//
// A substitution body always runs, whether or not the outer statement's
// classification is doc-text-shaped or the substitution sits in a position
// no rule would otherwise inspect (shellparse.SubstitutionBodies' own doc
// comment, #3814) — the same reasoning applies one layer down, to path
// extraction: `echo $(cat <protected>)` reads <protected> exactly as
// `cat <protected>` alone would (#4030).
//
// # Why it walks the parsed substitutions instead of reparsing body text
//
// The first version sliced each body's raw text and parsed it as a program
// of its own. Codex pass 1 on #4051 found, and a build confirmed, that this
// loses the enclosing command twice over:
//
//   - Context. `e=echo; echo "$($e cat <protected>)"` prints `cat <path>`: a
//     real shell has e bound when the body runs. Parsed alone, the body had
//     no binding, NormalizeUnsetParamExp folded $e to nothing, the extractor
//     saw `cat <protected>`, and a print-only command BLOCKed. The same loss
//     hit array and positional bindings, and let a body fold `${IFS}` to a
//     space after the outer command had reassigned IFS (`IFS=; …`).
//   - Quoting. Inside backquotes a nested substitution opens and closes with
//     a backslash-escaped backquote; the raw slice keeps the backslashes, so
//     a standalone parse reads them as literal backquotes and never finds the
//     inner read.
//
// parsed.Substitutions is the whole-command walk of each body — same folds,
// same symbol table, the parser's own reading of the escapes — at every
// nesting depth, so there is also no recursion here and no depth cap to fall
// off (the first version stopped silently at level 9).
//
// # The model this mirrors, and where it stops
//
// Each body is extracted exactly as a top-level command would be: segments
// through the AST-aware walker, and a body with no segment through the
// fallback tokenizer over its text, as normalize() does for a zero-segment
// top-level command. It therefore inherits the top-level model's limits
// rather than adding new ones: an IFS reassignment still disables the IFS
// fold (NormalizeIFS's documented residual — `IFS=x; echo $(cat${IFS}/abs/f)`
// reads /abs/f on bash and is not seen, at top level or here; with a `~/f`
// spelling bash reads nothing, because a mid-word ~ never expands), and a
// `bash -c` body inside a substitution is not path-extracted, just as a
// top-level one is not (agentshield-oss#9).
//
// One deliberate difference from the top-level walk: a here-string's word
// and a heredoc's delimiter are skipped (skipData, and isDataRedirect on the
// bare redirects). They are data on stdin. Main extracted one from a
// substitution only when its top-level walk saw it — an unspaced or
// fd-prefixed word in a command that parses to segments (`echo "$(cat<<<'f')"`,
// `echo "$(cat 0<<<'f')"`), which still BLOCKs through that walk. A spaced
// `<<<` sent main's whole command to the fallback tokenizer, which never
// extracted it, so extracting it here would be a new false BLOCK
// (`N=$(wc -l <<< 'f')`, #4051 Opus pass 2 F1). The top-level walk still
// extracts the unspaced ones (`true; cat<<<'f'`); removing that is a separate
// narrowing. A substitution inside the word still runs and is still walked.
//
// It also inherits the top-level model's over-approximations. Each of these
// is a known false BLOCK — bash reads nothing — whose top-level analog main
// already BLOCKs; they are pinned by
// TestNormalizeCommand_Gap_CommandSubstitutionUnfoldedDefaultExecutable and
// TestNormalizeCommand_Gap_CommandSubstitutionModelBoundaries:
//
//   - An unnamed executable. `e=echo; echo "$(${e:-cat} <protected>)"` prints
//     the path, but the exec resolver deliberately does not fold a default
//     operator on a bound variable (shellparse foldExpansionOp), so its
//     path-shaped operand is extracted, as `e=echo; ${e:-cat} <protected>` is
//     at top level. Closing it is a resolver change for every analyzer.
//   - Conditional expansion. `x=1; echo "${x:-$(cat f)}"` never runs the
//     substitution; the walk treats every substitution as run, as the model
//     treats `true || cat f` at top level.
//   - An uncalled function. `f() { echo "$(cat f)"; }` — as `f() { cat f; }`.
//   - The zero-segment fallback. It skips the first token (the executable of
//     a top-level command) and reads quoted text and heredoc/here-string data
//     as paths: `echo "$(export M='cat f')"`, `echo "$(<<< 'f')"` — as
//     `export M='cat f'` and `<<< 'f'` are at top level.
func extractSubstitutionPaths(parsed *shellparse.ParsedCommand, cwd, homeDir string, keepDots bool) ([]string, []string) {
	if parsed == nil {
		return nil, nil
	}
	var paths, domains []string
	for _, s := range parsed.Substitutions {
		switch {
		case s.Parsed != nil && len(s.Parsed.Segments) > 0:
			p, d := astAwareExtractRedirs(s.Parsed, cwd, homeDir, true, keepDots)
			paths = append(paths, p...)
			domains = append(domains, d...)
		default:
			if bodyArgs := strings.Fields(s.Body); len(bodyArgs) > 0 {
				p, d := fallbackExtract(bodyArgs, cwd, homeDir, keepDots)
				paths = append(paths, p...)
				domains = append(domains, d...)
			}
		}
		// `$(<file)`: a command-less statement whose redirect reads the file.
		// The segment walk never sees it, and the fallback tokenizer misses
		// it when no space follows the `<` (the idiomatic spelling).
		for _, r := range s.BareRedirects {
			if isDataRedirect(r.Op) {
				continue
			}
			paths = append(paths, redirectTargetPaths(r.Op, r.Path, cwd, homeDir, keepDots)...)
		}
	}
	return paths, domains
}

// fallbackExtract is the original tokenizer-based extraction with heredoc and
// textContentFlags support. Used when AST parsing fails or for heredoc commands.
func fallbackExtract(args []string, cwd, homeDir string, keepDots bool) ([]string, []string) {
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
		} else if p, ok := bareOperandPath(arg, cwd, ""); ok {
			paths = append(paths, p)
		} else {
			paths = append(paths, bareGlobPaths(arg, cwd, keepDots)...)
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

// tarExecutables are the tar spellings whose -C / --directory moves the
// directory later operands are read from or extracted into.
var tarExecutables = map[string]bool{"tar": true, "gtar": true, "bsdtar": true}

// tarDirectoryFlag recognises tar's directory option at words[i]: `-C dir`,
// `-Cdir`, a short cluster ending in C (`-xC dir`), `--directory dir` and
// `--directory=dir`. skip is how many extra words the option consumed.
func tarDirectoryFlag(words []string, i int) (dir string, skip int, ok bool) {
	arg := words[i]
	switch {
	case arg == "--directory" || arg == "-C":
		if i+1 < len(words) {
			return words[i+1], 1, true
		}
	case strings.HasPrefix(arg, "--directory="):
		return strings.TrimPrefix(arg, "--directory="), 0, true
	case strings.HasPrefix(arg, "-C") && len(arg) > 2:
		return arg[2:], 0, true
	case strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && len(arg) > 2 &&
		strings.HasSuffix(arg, "C") && !strings.ContainsAny(arg[1:len(arg)-1], "fCTX"):
		if i+1 < len(words) {
			return words[i+1], 1, true
		}
	}
	return "", 0, false
}

// tarOperandPath resolves a member operand against tar's current -C directory.
// It is an ADDITIONAL candidate beside the cwd-relative reading, never a
// replacement, so the decision can only rise.
func tarOperandPath(arg, dir, homeDir string) (string, bool) {
	arg = pathnorm.StripShellQuotes(arg)
	if arg == "" || strings.ContainsAny(arg, "$`*?[") || strings.HasPrefix(arg, "~") || filepath.IsAbs(arg) {
		return "", false
	}
	return expandPath(arg, dir, homeDir), true
}

// bareOperandPath resolves a slash-less operand (`cat id_rsa`) against cwd
// when it names an existing entry there (#4381). looksLikePath requires a
// separator, so with cwd=~/.ssh a bare key name never reached the
// protected-path match while `./id_rsa` did. The existence check is what keeps
// ordinary words (`ssh myhost`, `git status`) from becoming paths under the
// cwd. Residual: a bare name that does not exist yet (a create-write of a new
// key from inside the protected directory) is still not extracted.
func bareOperandPath(arg, cwd, exe string) (string, bool) {
	if cwd == "" || !filepath.IsAbs(cwd) {
		return "", false
	}
	arg = pathnorm.StripShellQuotes(arg)
	if arg == "" || arg == "." || arg == ".." ||
		strings.ContainsAny(arg, "/$`=:*?[") || strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "~") {
		return "", false
	}
	full := filepath.Join(cwd, arg)
	if _, err := os.Lstat(full); err != nil && !fileOperandCommands[filepath.Base(exe)] {
		return "", false
	}
	return filepath.Clean(full), true
}

// redirectTargetPaths resolves a redirect target. A target with a separator
// goes through expandPath as before; a bare one (`cat < id_rsa`, `> id_rsa`
// from inside ~/.ssh) is the alias of `./id_rsa`, which already BLOCKs (#4403).
// An output redirect creates its target, so it needs no existing entry; an
// input redirect does, like any other bare operand.
func redirectTargetPaths(op, path, cwd, homeDir string, keepDots bool) []string {
	if path == "" {
		return nil
	}
	if looksLikePath(path) {
		return []string{expandPath(path, cwd, homeDir)}
	}
	if op == ">&" || op == "<&" {
		return nil // `2>&1`, `>&-`: a descriptor, not a name under cwd
	}
	exe := ""
	if strings.Contains(op, ">") {
		exe = "touch"
	}
	if p, ok := bareOperandPath(path, cwd, exe); ok {
		return []string{p}
	}
	return bareGlobPaths(path, cwd, keepDots)
}

// maxBareGlobMatches bounds one glob's contribution to the path list so `*`
// in a huge cwd stays cheap. It is far above any protected directory's size.
const maxBareGlobMatches = 4096

// bareGlobPaths expands a slash-less glob operand (`cat id_*`) against cwd the
// way the shell would, so each entry it names is a candidate path (#4403).
// `cat id_*` from inside ~/.ssh is `cat ~/.ssh/id_*`, which already BLOCKs.
//
// A shell's `*`, `?` and `[...]` never match a leading dot unless the pattern
// itself starts with a literal `.`; Go's filepath.Glob has no such rule, so
// `ls *` from $HOME named ~/.ssh and BLOCKed (#4481). Measured on bash 3.2,
// bash 5.3, zsh 5.9, sh, dash and ksh with no rc files: none expands `*`,
// `?ssh`, `*ssh`, `[.]ssh`, `[!a]ssh` or `[[:punct:]]ssh` to `.ssh`, and all
// expand `.*`, `.ss*` and `.[s]sh` to it. Dot entries are dropped only when
// that rule is all that decides; main's reading is kept when
//   - keepDots: the line is not provably running under the shell's default
//     glob options (defaultGlobbing);
//   - the word is quoted or escaped: the program, not the shell, may get the
//     pattern and match dot-files itself (git pathspecs do);
//   - only dot entries match: the shell then passes the pattern on as-is.
func bareGlobPaths(arg, cwd string, keepDots bool) []string {
	if cwd == "" || !filepath.IsAbs(cwd) {
		return nil
	}
	word := arg
	arg = pathnorm.StripShellQuotes(arg)
	if arg == "" || !strings.ContainsAny(arg, "*?[") ||
		strings.ContainsAny(arg, "/$`=:") || strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "~") {
		return nil
	}
	matches, err := filepath.Glob(filepath.Join(cwd, arg))
	if err != nil {
		return nil
	}
	if !keepDots && !strings.HasPrefix(arg, ".") && !strings.ContainsAny(word, `'"\`) {
		if shown := withoutDotEntries(matches); len(shown) > 0 {
			matches = shown
		}
	}
	if len(matches) > maxBareGlobMatches {
		matches = matches[:maxBareGlobMatches]
	}
	return matches
}

func withoutDotEntries(matches []string) []string {
	shown := make([]string, 0, len(matches))
	for _, m := range matches {
		if !strings.HasPrefix(filepath.Base(m), ".") {
			shown = append(shown, m)
		}
	}
	return shown
}

// optionBuiltins are the commands that can change the current shell's options
// or run text in it: the option builtins of bash, zsh, ksh and dash, zsh's
// precommand modifiers and `repeat` (valid bash, a zsh loop that runs its
// arguments as a command), and the builtins that run text or a file in place,
// history re-execution (`fc`, zsh `r`) among them, and zsh `zstyle`, whose
// -s/-b/-a/-t forms write a named parameter (#4509 Codex pass 2). A
// line that runs one of them by name is not provably under default globbing.
var optionBuiltins = map[string]bool{
	"set": true, "setopt": true, "unsetopt": true, "shopt": true, "emulate": true,
	"enable": true, "disable": true, "noglob": true, "nocorrect": true, "-": true,
	"builtin": true, "command": true, "exec": true, "time": true, "eval": true,
	"source": true, ".": true, "alias": true, "trap": true, "autoload": true,
	"repeat": true, "fc": true, "history": true, "r": true, "zstyle": true,
}

// globStateNames are the option and variable names that change how a glob
// expands: bash dotglob, GLOBIGNORE (non-null enables dotglob), SHELLOPTS and
// BASHOPTS; zsh GLOB_DOTS, its DOT_GLOB alias, NO_GLOB and the options
// parameter; ksh93 FIGNORE. Matched on the folded text (lower case, quotes,
// backslashes, `_` and `-` removed, as zsh ignores case and `_` in option
// names), so a mention anywhere keeps main's reading.
var globStateNames = []string{
	"dotglob", "globdots", "globignore", "shellopts", "bashopts", "noglob",
	"fignore", "options[", "options=", "options+=",
}

// nameBinders take a variable NAME from an argument; printf and zsh print
// do so only with -v. With a dynamic argument they can bind GLOBIGNORE or a
// zsh option parameter whose name never appears in the text.
var nameBinders = map[string]bool{
	"read": true, "mapfile": true, "readarray": true, "getopts": true, "let": true,
	"vared": true, "zparseopts": true,
}

var arithAssignOps = map[syntax.BinAritOperator]bool{
	syntax.Assgn: true, syntax.AddAssgn: true, syntax.SubAssgn: true, syntax.MulAssgn: true,
	syntax.QuoAssgn: true, syntax.RemAssgn: true, syntax.AndAssgn: true, syntax.OrAssgn: true,
	syntax.XorAssgn: true, syntax.ShlAssgn: true, syntax.ShrAssgn: true,
}

// bindsDynamicName reports whether the line can bind a variable whose name is
// not literal in its text: a declaration builtin's bare argument or nameref
// flag, a nameBinders argument, an arithmetic assignment target, or indirect
// expansion, any of them built from an expansion or a brace list. It walks the
// bash AST, so a line continuation or a quoted separator cannot end the
// statement early the way a text scan could (#4509 Codex pass 1). A text that
// does not parse binds unknowably, so it counts.
func bindsDynamicName(text string) bool {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(text), "")
	if err != nil {
		return true
	}
	found := false
	syntax.Walk(file, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.DeclClause:
			for _, a := range x.Args {
				if !a.Naked || a.Value == nil {
					continue
				}
				v, lit := literalWordValue(a.Value)
				if !lit || strings.HasPrefix(v, "-") && strings.Contains(v, "n") {
					found = true // a bare dynamic name, or a nameref flag
				}
			}
		case *syntax.CallExpr:
			if len(x.Args) == 0 {
				break
			}
			cmd, lit := literalWordValue(x.Args[0])
			if !lit {
				break // a dynamic command word fails defaultGlobbing anyway
			}
			binds := nameBinders[cmd]
			if cmd == "printf" || cmd == "print" {
				// -v can arrive through an expansion in option position
				// (#4509 Codex pass 2): a non-literal word before the first
				// non-option counts as a possible -v.
				options := true
				for _, w := range x.Args[1:] {
					v, ok := literalWordValue(w)
					if strings.HasPrefix(v, "-v") || options && !ok {
						binds = true
					}
					if ok && (!strings.HasPrefix(v, "-") || v == "--") {
						options = false
					}
				}
			}
			if binds {
				for _, w := range x.Args[1:] {
					if _, ok := literalWordValue(w); !ok {
						found = true
					}
				}
			}
		case *syntax.BinaryArithm:
			if arithAssignOps[x.Op] && !literalArithm(x.X) {
				found = true
			}
		case *syntax.UnaryArithm:
			if (x.Op == syntax.Inc || x.Op == syntax.Dec) && !literalArithm(x.X) {
				found = true
			}
		case *syntax.ParamExp:
			if x.Excl {
				found = true // ${!v}: indirect, and ${!v:=x} can assign through it
			}
		}
		return !found
	})
	return found
}

// literalWordValue returns a word's value when it is made only of plain text
// and quotes, with no expansion and no brace list (`{a,b}` builds a name too).
func literalWordValue(w *syntax.Word) (string, bool) {
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			if p.Dollar {
				return "", false
			}
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, q := range p.Parts {
				l, ok := q.(*syntax.Lit)
				if !ok {
					return "", false
				}
				b.WriteString(l.Value)
			}
		default:
			return "", false
		}
	}
	v := b.String()
	if strings.Contains(v, "{") && strings.Contains(v, ",") {
		return "", false
	}
	return v, true
}

func literalArithm(x syntax.ArithmExpr) bool {
	w, ok := x.(*syntax.Word)
	if !ok {
		return false
	}
	_, lit := literalWordValue(w)
	return lit
}

// defaultGlobbing reports whether every glob in the line provably expands under
// the shell's default options, so `*`, `?` and `[...]` cannot reach a dot entry
// and cannot reach the program unexpanded (#4481). It is a positive check, and
// every condition it cannot establish keeps main's reading: the line must
// parse as bash, not through fallbackParse (a heredoc command, which normalize
// does not parse for the fallback tokenizer's sake, is parsed here; zsh-only
// syntax such as `() { … }` or `for x (a) cmd` fails here); every command must be named by a static
// word (no
// quote, escape, expansion, brace or glob in it) and none may be an
// optionBuiltin; the folded text may name no globStateNames; and the text may
// bind no variable by a name that is not literal in it (bindsDynamicName).
// ANSI-C and locale quoting (`$'...'`) need no rule of their own: they spell a
// name only inside a word, and a command word holding `$` is not static, an
// option builtin is caught by name whatever its arguments say, and a variable
// binding through a non-literal argument is bindsDynamicName. The spellings of a switch are not
// enumerable (zsh folds case and `_` in option names and inverts letters with
// `+`; quote removal splices a builtin's own name; #4509 passes 1-2). The
// commands that can flip one are. Not covered: an rc file, an alias or function
// from one, or an earlier command in a persistent shell; and bash's recursive
// arithmetic evaluation, where a variable whose VALUE holds an assignment runs
// it when referenced in any arithmetic context (`(( w ))`, `[[ w -eq 0 ]]`,
// a subscript). That one is a documented gap (#4509 Codex pass 2), not modelled:
// every arithmetic reference would have to be refused. It is dominated: main
// itself ALLOWs `grep -r key ~` and `git add -A` from $HOME, which reach the
// same dot entries with no binding at all.
func defaultGlobbing(parsed *shellparse.ParsedCommand, rawCommand string) bool {
	if parsed == nil {
		parsed = shellparse.Parse(rawCommand, 2)
	}
	if parsed == nil || parsed.Fallback || len(parsed.Segments) == 0 {
		return false
	}
	if bindsDynamicName(rawCommand) {
		return false
	}
	// A backslash-newline is removed before the shell reads the line, so a
	// name split across one is still that name.
	text := strings.ReplaceAll(rawCommand, "\\\n", "")
	folded := strings.ToLower(strings.NewReplacer("_", "", "-", "", "'", "", `"`, "", `\`, "").Replace(text))
	for _, n := range globStateNames {
		if strings.Contains(folded, n) {
			return false
		}
	}
	segs := shellparse.AllSegments(parsed)
	for _, sub := range parsed.Substitutions {
		segs = append(segs, shellparse.AllSegments(sub.Parsed)...)
	}
	for _, seg := range segs {
		exe := seg.Executable // as written, path and all
		if exe == "" || exe == "[" || exe == "[[" {
			continue // an assignment-only statement (filepath.Base("") is "."), or test
		}
		if strings.ContainsAny(exe, "$`'\"\\*?[{}") || optionBuiltins[exe] ||
			optionBuiltins[filepath.Base(exe)] || optionBuiltins[seg.Program] {
			return false
		}
	}
	return true
}

// fileOperandCommands take a slash-less word as a file to create or write, so
// a name that does not exist yet is still a path under cwd (#4381): `touch
// id_rsa` from inside ~/.ssh is `touch ./id_rsa`, which already BLOCKs. A
// closed list on purpose: for `ssh myhost` the bare word is a host, and
// resolving it would manufacture a protected-path hit under ~/.ssh.
var fileOperandCommands = map[string]bool{
	"touch": true, "tee": true, "cp": true, "mv": true, "install": true,
	"truncate": true, "ln": true, "rm": true, "unlink": true, "shred": true,
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
