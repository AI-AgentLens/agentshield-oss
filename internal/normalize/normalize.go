package normalize

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
		paths = append(paths, operandPaths(arg, cwd, homeDir, seg.Executable, keepDots)...)
		if d := extractDomains(arg); len(d) > 0 {
			domains = append(domains, d...)
		}
		positionalIdx++
	}

	// A grep-family pattern given by an option leaves every positional word a
	// file (#4676). The walk above cannot see that: -e's text state stays on
	// after its value, and TextPositions still reads the first file as the
	// pattern. A second reading, added to the walk's paths, never replacing
	// them, so it can only raise a decision.
	//
	// grep's max-count -m is the walk's universal -m text flag, so it hid every
	// later word the same way (#4682). grepOperandPaths, a third reading, reads
	// the argv as getopt does, with the tool's value-taking options. It too is
	// only added.
	//
	// A path-qualified grep (`/usr/bin/grep`) has no spec, because lookupSpec
	// reads the exact word, so these two readings fall back to the basename's
	// spec (#4689). The walk above keeps the exact word's spec.
	limit := len(words)
	if nestedCodeStart >= 0 {
		limit = nestedCodeStart
	}
	patternOpts := spec.PatternOptions
	if !found {
		patternOpts = grepReadingSpec(filepath.Base(seg.Executable)).PatternOptions
	}
	if patternOpts != nil {
		readings := patternOptionOperandPaths(words[:limit], patternOpts, cwd, homeDir, seg.Executable, keepDots)
		if patternOpts.Values != nil {
			readings = append(readings, grepOperandPaths(words[:limit], patternOpts, cwd, homeDir, seg.Executable, keepDots)...)
		}
		for _, p := range readings {
			if !slices.Contains(paths, p) {
				paths = append(paths, p)
			}
		}
	}

	// The universal -m text flag hid the operands of the readers whose own -m
	// is a switch the same way (#4689): `wc -m <file>` extracted nothing. For
	// those readers a fourth reading takes every option word as a switch. It
	// too is only added.
	if mSwitchReaders[filepath.Base(seg.Executable)] {
		for _, p := range switchOptionOperandPaths(words[:limit], cwd, homeDir, seg.Executable, keepDots) {
			if !slices.Contains(paths, p) {
				paths = append(paths, p)
			}
		}
	}

	// A long option with its value attached (`sort --output=<file>`) is one
	// option word, so the walk never read the value as a path: the write
	// decided ALLOW (#4692). A fifth reading splits `--name=value` and offers
	// the value as a candidate path. It is only added, and a name the walk
	// treats as prose (--message=, spec text flags) is skipped.
	//
	// The grep family is left to its own readings: `--exclude=NAME` and
	// `--include=GLOB` hold a name to skip, not a file it reads, and #4682
	// pins that (TestGrepValueOptionLeavesFileOperands_4682).
	if patternOpts == nil {
		for _, p := range longOptionValuePaths(words[:limit], cmdTextFlags, cwd, homeDir, seg.Executable, keepDots) {
			if !slices.Contains(paths, p) {
				paths = append(paths, p)
			}
		}
	}

	// Words a zsh construct consumed before its command (repeat's count, the
	// assignments skipped after it) are not argv, but main read them as the
	// arguments of an unknown executable named by the construct. Read them the
	// same way so unwrapping (#4597) never leaves a word unscanned that main
	// scanned. They can only add paths and domains.
	for _, arg := range seg.ZshOperandWords {
		paths = append(paths, operandPaths(arg, cwd, homeDir, seg.ZshShellWord, keepDots)...)
		if d := extractDomains(arg); len(d) > 0 {
			domains = append(domains, d...)
		}
	}

	// ag's and ack's -m is max-count too, so the walk's universal -m text flag
	// hid their file operands (#4689): `ag -m 1 KEY <file>` extracted nothing.
	// A sixth reading reads their argv as their option parsers do. It runs
	// last and is only added, so every path above keeps its place.
	if opts := searchToolReadings[filepath.Base(seg.Executable)]; opts != nil {
		for _, p := range searchToolOperandPaths(words[:limit], opts, cwd, homeDir, seg.Executable, keepDots) {
			if !slices.Contains(paths, p) {
				paths = append(paths, p)
			}
		}
	}

	return paths, domains
}

// searchToolOperandPaths is the getopt reading of an ag or ack argv (#4689).
// An option that takes a value consumes it (`-m 1`, `-m1`, `-im 1`,
// `--max-count 1`, `--ignore NAME`, any `--name=value`); the first remaining
// word is the pattern, unless an option says there is none (ag -g, ack -f,
// ack --match), and every other word is a path to search. A lone `-` and
// every word after `--` are positional, as in getopt and Getopt::Long, and
// both permute, so an option after the pattern is still an option.
//
// It is not grepOperandPaths: that reading keys its pattern options on -e and
// -f, and with neither letter set its zero File letter would match the zero
// letter of every `--name=value` word and read the pattern as a file.
//
// The pattern is never read as a path: `ag -m 1 /etc/shadow docs/` searches
// docs/ for that string (#3780). An option's value is not read as a path
// either. The walk above still reads every word it read on main.
func searchToolOperandPaths(words []string, opts *SearchToolOptions, cwd, homeDir, exe string, keepDots bool) []string {
	var positionals []string
	noPattern, endOfOptions := false, false
	for i := 0; i < len(words); i++ {
		w := words[i]
		if endOfOptions || w == "-" || !strings.HasPrefix(w, "-") {
			positionals = append(positionals, w)
			continue
		}
		if w == "--" {
			endOfOptions = true
			continue
		}
		takes, attached := false, false
		if strings.HasPrefix(w, "--") {
			name, _, eq := strings.Cut(w[2:], "=")
			noPattern = noPattern || opts.NoPatternLong[name]
			takes, attached = eq || opts.Values.Long[name], eq
		} else {
			for j := 1; j < len(w); j++ {
				c := w[j]
				if strings.IndexByte(opts.NoPatternShort, c) >= 0 {
					noPattern = true
				}
				if strings.IndexByte(opts.Values.Short, c) >= 0 {
					takes, attached = true, j+1 < len(w)
					break
				}
			}
		}
		if takes && !attached {
			i++ // the value, even when it starts with "-"
		}
	}
	if !noPattern && len(positionals) > 0 {
		positionals = positionals[1:] // the pattern
	}
	var paths []string
	for _, w := range positionals {
		paths = append(paths, operandPaths(w, cwd, homeDir, exe, keepDots)...)
	}
	return paths
}

// operandPaths reads one word in a file-operand position of exe: a word
// shaped like a path, a bare name bareOperandPath accepts, or a bare glob.
func operandPaths(arg, cwd, homeDir, exe string, keepDots bool) []string {
	if looksLikePath(arg) {
		return []string{expandPath(arg, cwd, homeDir)}
	}
	if p, ok := bareOperandPath(arg, cwd, exe); ok {
		return []string{p}
	}
	return bareGlobPaths(arg, cwd, keepDots)
}

// grepReadingAliases are programs that hand their options to grep unchanged,
// or are GNU grep under another name: Homebrew's `ggrep` and the compressed-file
// wrappers (zgrep, bzgrep, xzgrep, zstdgrep and their e/f variants). Their -m is
// grep's max-count, so the walk's universal -m text flag hid their file operands
// the same way (#4689). They get the grep-family READINGS only, which are added
// to the walk's paths. They are deliberately not in commandRegistry: a spec
// there would also change the walk's TextPositions reading. ag and ack are not
// listed (their option sets are not grep's, #4676); searchToolOperandPaths
// reads them (#4689).
var grepReadingAliases = map[string]string{
	"ggrep": "grep", "gegrep": "egrep", "gfgrep": "fgrep",
	"zgrep": "grep", "zegrep": "egrep", "zfgrep": "fgrep",
	"bzgrep": "grep", "bzegrep": "egrep", "bzfgrep": "fgrep",
	"xzgrep": "grep", "xzegrep": "egrep", "xzfgrep": "fgrep",
	"zstdgrep": "grep",
}

// grepReadingSpec is the registry spec of a program's basename, falling back to
// the grep it wraps.
func grepReadingSpec(base string) CommandArgSpec {
	if spec, ok := commandRegistry[base]; ok {
		return spec
	}
	return commandRegistry[grepReadingAliases[base]]
}

// patternOptionOperandPaths is the second reading of a grep-family argv
// (#4676). When an option supplies the pattern, the tool reads no positional
// pattern, so every non-option word, before or after that option (getopt and
// ripgrep both permute), is a file to search. The -f value names a pattern
// file the tool opens, so it is read as a path too; a pattern value never is.
//
// It returns nil when no option supplies the pattern: the walk's
// TextPositions reading is right then. Its paths are only ever added to the
// walk's, which is why it does not have to know every value-taking option: a
// value read as an operand (`-A 3`, `-g '*.go'`) is one more candidate path,
// exactly as the walk reads it after a positional pattern (`grep KEY -A 3 f`).
// Words after `--` are operands; one that starts with `-` is still not read
// as a path, as on main.
func patternOptionOperandPaths(words []string, opts *PatternOptions, cwd, homeDir, exe string, keepDots bool) []string {
	var operands, patternFiles []string
	supplied, endOfOptions := false, false
	for i := 0; i < len(words); i++ {
		w := words[i]
		if endOfOptions || !strings.HasPrefix(w, "-") {
			operands = append(operands, w)
			continue
		}
		if w == "--" {
			endOfOptions = true
			continue
		}
		letter, value, attached := patternOption(w, opts)
		if letter == 0 {
			continue
		}
		supplied = true
		if !attached {
			if i+1 == len(words) {
				break
			}
			i++
			value = words[i] // the value, even when it starts with "-"
		}
		if letter == opts.File {
			patternFiles = append(patternFiles, value)
		}
	}
	if !supplied {
		return nil
	}
	var paths []string
	for _, w := range append(patternFiles, operands...) {
		paths = append(paths, operandPaths(w, cwd, homeDir, exe, keepDots)...)
	}
	return paths
}

// patternOption reports whether option word w supplies the pattern: the
// option's letter (opts.Text or opts.File; 0 when it does not), and its value
// when it is written in the same word. Spellings: `-e PAT`, `-ePAT`, a
// cluster `-ie PAT` / `-iePAT`, `--regexp PAT`, `--regexp=PAT`, and the same
// for f/--file. getopt_long takes an unambiguous prefix of a long name, and
// for grep that is any prefix of "regexp" from "reg" (`--re` is also
// --recursive); every prefix of "file" below the full name is ambiguous
// (--files-with-matches, --fixed-strings). A cluster ends at a letter that
// takes a value (`rg -tconf`: the f is t's value) or at any other character.
func patternOption(w string, opts *PatternOptions) (byte, string, bool) {
	if strings.HasPrefix(w, "--") {
		name, value, attached := strings.Cut(w[2:], "=")
		switch {
		case name == "file":
			return opts.File, value, attached
		case len(name) >= 3 && strings.HasPrefix("regexp", name):
			return opts.Text, value, attached
		}
		return 0, "", false
	}
	for j := 1; j < len(w); j++ {
		c := w[j]
		switch {
		case c == opts.Text || c == opts.File:
			return c, w[j+1:], j+1 < len(w)
		case strings.IndexByte(opts.ValueLetters, c) >= 0:
			return 0, "", false
		case !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'):
			return 0, "", false
		}
	}
	return 0, "", false
}

// grepOperandPaths is the getopt reading of a grep-family argv (#4682). An
// option that takes a value consumes it (`-m 1`, `-m1`, `-rnm 5`,
// `--max-count 1`, `--exclude GLOB`); the first remaining word is the pattern
// unless a pattern option supplied one; every other word is a file, and so is
// a -f pattern file.
//
// The walk reads every option word as a switch and keeps -m's text state on
// until the next option word, so `grep -m 1 KEY <file>` extracted nothing. On
// a line where the walk sets no text state (no short cluster holding an m or
// an e, `-Dread` included, and no --regexp: the walk's text flags a
// grep-family tool accepts), no `--` and no lone `-`, this reading names a
// subset of the walk's words: both skip the first non-option word, and this
// one also skips option values, which the walk reads as files. So the paths
// it adds come from the span the text state hid, or from words the walk
// misread as options: getopt reads a lone `-` (stdin) as a positional and
// nothing after `--` as an option, so `grep -- -KEY <file>` searches the
// file. It is not a replacement
// for patternOptionOperandPaths, which reads option values as files; dropping
// that reading would lower `grep -e K --exclude <f> x` below main.
//
// Unique prefixes of long names are read as switches (see OptionValues).
func grepOperandPaths(words []string, opts *PatternOptions, cwd, homeDir, exe string, keepDots bool) []string {
	var positionals, patternFiles []string
	supplied, endOfOptions := false, false
	for i := 0; i < len(words); i++ {
		w := words[i]
		if endOfOptions || w == "-" || !strings.HasPrefix(w, "-") {
			positionals = append(positionals, w)
			continue
		}
		if w == "--" {
			endOfOptions = true
			continue
		}
		letter, value, takes, attached := grepOptionWord(w, opts)
		if !takes {
			continue
		}
		if !attached {
			if i+1 == len(words) {
				break
			}
			i++
			value = words[i] // the value, even when it starts with "-"
		}
		switch letter {
		case opts.File:
			patternFiles = append(patternFiles, value)
			supplied = true
		case opts.Text:
			supplied = true
		}
	}
	if !supplied && len(positionals) > 0 {
		positionals = positionals[1:] // the pattern
	}
	var paths []string
	for _, w := range append(patternFiles, positionals...) {
		paths = append(paths, operandPaths(w, cwd, homeDir, exe, keepDots)...)
	}
	return paths
}

// grepOptionWord reads option word w the way getopt does: whether it takes a
// value, the short letter that takes it (opts.Text or opts.File for the long
// --regexp and --file, 0 for any other long option), and the value when it
// sits in the same word. A short cluster ends
// at its first letter that takes a value, and the rest of the word is the
// value (`-rnm5`, `-iePAT`). A long option takes a value when "=" joins one
// or when opts.Values lists its name.
func grepOptionWord(w string, opts *PatternOptions) (letter byte, value string, takes, attached bool) {
	if strings.HasPrefix(w, "--") {
		name, value, attached := strings.Cut(w[2:], "=")
		switch {
		case name == "regexp":
			return opts.Text, value, true, attached
		case name == "file":
			return opts.File, value, true, attached
		case attached:
			return 0, value, true, true
		case opts.Values.Long[name]:
			return 0, "", true, false
		}
		return 0, "", false, false
	}
	for j := 1; j < len(w); j++ {
		c := w[j]
		if c == opts.Text || c == opts.File || strings.IndexByte(opts.Values.Short, c) >= 0 {
			return c, w[j+1:], true, j+1 < len(w)
		}
	}
	return 0, "", false, false
}

// mSwitchReaders are readers whose -m is a switch of their own, not the
// message the walk's universal -m text flag is for (#4689). Each -m was read
// from this Mac's man page (macOS 26.6; less 668) and run on a scratch file:
// none takes a value, and the next word is a file.
var mSwitchReaders = map[string]bool{
	"wc":   true, // -m: count characters
	"sort": true, // -m, --merge: merge files already sorted
	"less": true, // -m, --long-prompt: prompt verbosely
	"pr":   true, // -m: print the files side by side

	// Same collision on commands that name a file, found by the #4716 lane
	// (control without -m BLOCKs protected-path; with -m it decided AUDIT or
	// ALLOW). install and mkdir take a MODE after -m: the reading offers that
	// word as one more candidate, and a mode is never path-shaped.
	"ls":      true, // -m: comma-separated listing
	"zip":     true, // -m: move the files into the archive (deletes the originals)
	"install": true, // -m MODE
	"mkdir":   true, // -m MODE
}

// switchOptionOperandPaths is the reading of an mSwitchReaders argv (#4689).
// Every option word is a switch, and every other word is an operand, as is
// every word after `--`. The walk reads every option word as a switch too,
// but its text flags (-m, or an m in a short cluster, and the long ones in
// textContentFlags) hide the words after them, and these readers have no
// spec. So this reading names a superset of the walk's words, and its paths
// can only add to the walk's. A value an option takes (`sort -k 2`,
// `pr -h HDR`) is one more candidate path, as the walk reads it. A word
// starting with `-` is never a path (looksLikePath, bareOperandPath and
// bareGlobPaths all refuse one), so outside a text flag's span this adds
// nothing.
func switchOptionOperandPaths(words []string, cwd, homeDir, exe string, keepDots bool) []string {
	var paths []string
	endOfOptions := false
	for _, w := range words {
		if !endOfOptions && strings.HasPrefix(w, "-") {
			endOfOptions = w == "--"
			continue
		}
		paths = append(paths, operandPaths(w, cwd, homeDir, exe, keepDots)...)
	}
	return paths
}

// longOptionValuePaths is the reading of `--name=value` words (#4692). The
// value of every such word before `--` is read as an operand, unless the
// option is one of the walk's text flags (`--message=text`). A value that is
// not path-shaped adds nothing (operandPaths refuses it), and the paths are
// only ever added to the walk's.
func longOptionValuePaths(words []string, textFlags map[string]bool, cwd, homeDir, exe string, keepDots bool) []string {
	var paths []string
	for _, w := range words {
		if w == "--" {
			break
		}
		if !strings.HasPrefix(w, "--") {
			continue
		}
		name, value, attached := strings.Cut(w, "=")
		if !attached || value == "" || textFlags[name] {
			continue
		}
		paths = append(paths, operandPaths(value, cwd, homeDir, exe, keepDots)...)
	}
	return paths
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
// cwd. A name that does not exist yet is still a path for two closed lists:
//   - fileOperandCommands create or write it (#4401), so it resolves to
//     <cwd>/<name> and reaches every pattern, as `./name` does;
//   - fileReadOperandCommands read it (#4673). It is kept as written,
//     cwd-relative, so only a relative protected_paths pattern can match it:
//     the reading a file tool gives a relative argument (InWorkingDir, #4653).
//     An absolute or ~ pattern never matches a relative path, so for those
//     main's existence-gated reading is unchanged (#4401 pins `cat
//     nosuchfile` inside ~/.ssh).
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
	if _, err := os.Lstat(full); err != nil {
		name := ""
		if exe != "" {
			name = filepath.Base(exe) // Base("") is ".", the source builtin
		}
		switch {
		case fileOperandCommands[name]: // resolved under cwd, below
		case fileReadOperandCommands[name]:
			return arg, true
		default:
			return "", false
		}
	}
	return filepath.Clean(full), true
}

// redirectTargetPaths resolves a redirect target. A target with a separator
// goes through expandPath as before; a bare one (`cat < id_rsa`, `> id_rsa`
// from inside ~/.ssh) is the alias of `./id_rsa`, which already BLOCKs (#4403).
// An output redirect creates its target, so it needs no existing entry; an
// input redirect reads it, so an absent one is kept cwd-relative like any
// reader's operand (#4673). A heredoc delimiter or a here-string word (`<<`,
// `<<-`, `<<<`) is data, not a file, and keeps main's existence-gated reading.
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
	switch {
	case strings.Contains(op, ">"):
		exe = "touch"
	case op == "<":
		exe = "cat"
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
	file, err := shellparse.ParseText(text, syntax.Variant(syntax.LangBash))
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
		// noglob, nocorrect, - and repeat are in optionBuiltins, and since
		// #4597 the parser reads through them to the command they run. A
		// line that ran one by name keeps main's reading here.
		if seg.ZshShellWord != "" {
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

// fileReadOperandCommands read or copy out a slash-less operand as a file
// (#4673). bareOperandPath keeps such an operand cwd-relative when it does not
// exist at evaluation time, so a relative protected_paths pattern (`.env`)
// decides `cat .env` as it decides `echo x > .env` and the Read tool, whether
// or not the hook can see the file: shield-server evaluates a remote client's
// commands on its own disk, and `git checkout -- .env && cat .env` creates it
// mid-command. Closed for the same reason as fileOperandCommands: each entry
// asserts that a bare word it is given is a file or a harmless flag value (a
// count, a delimiter). Left out on purpose, because a pattern or a name can
// sit in a file slot: the grep family, sed and awk (the walk does not know
// which flags take a value, so in `grep -A 3 .env README.md` the 3 is read as
// the pattern and `.env` as a file), rsync and diff (`--exclude <name>`), and
// jq/yq (a filter such as `.env`). Those keep main's existence-gated reading.
var fileReadOperandCommands = map[string]bool{
	"cat": true, "tac": true, "nl": true, "less": true, "more": true, "bat": true,
	"head": true, "tail": true, "wc": true, "sort": true, "uniq": true, "cut": true,
	"cmp": true, "strings": true, "base64": true, "xxd": true, "od": true, "hexdump": true,
	"md5": true, "md5sum": true, "shasum": true, "sha1sum": true, "sha256sum": true,
	"cksum": true, "source": true, ".": true, "scp": true,
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
