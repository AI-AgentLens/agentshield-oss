package normalize

import "github.com/AI-AgentLens/agentshield/internal/shellparse"

// ArgRole classifies the role of a command argument for path extraction.
type ArgRole int

const (
	// ArgRolePath — argument is a file path and should be extracted.
	ArgRolePath ArgRole = iota
	// ArgRoleText — argument is text content (message, pattern, expression) and should be skipped.
	ArgRoleText
	// ArgRoleUnknown — role is uncertain; treated conservatively as a path.
	ArgRoleUnknown
)

// CommandArgSpec describes which arguments of a command are text vs paths.
type CommandArgSpec struct {
	// TextFlags are flags whose values are text content, not paths.
	// The shell parser may not consume the value — it often ends up in Args.
	TextFlags map[string]bool

	// AllPositionalText means all positional args are text (e.g., echo, printf).
	AllPositionalText bool

	// TextPositions lists 0-based positional arg indices that are text.
	// e.g., [0] for grep (pattern is first positional arg).
	TextPositions map[int]bool

	// InlineCodeFlags are flags whose values are inline code, not paths.
	InlineCodeFlags map[string]bool

	// TextFlagConsumesAllArgs: when any TextFlag or InlineCodeFlag is present
	// in the Flags map (even with empty value), ALL positional args are treated
	// as text. Used for commands like `git commit -m "msg"` where the shell
	// parser doesn't consume the flag value and it leaks into Args.
	TextFlagConsumesAllArgs bool

	// PatternOptions, for a search tool, names the options that supply the
	// pattern in place of the TextPositions operand (#4676).
	PatternOptions *PatternOptions
}

// PatternOptions describes how a grep-family tool takes its pattern from an
// option. With `-e PAT`, `--regexp=PAT` or `-f FILE` anywhere on the line
// (getopt permutes), the tool reads no positional pattern: every positional
// word is a file to search. The path walk's TextPositions slot and its
// sticky text-flag state both assumed otherwise, so the file was never
// extracted (#4676).
type PatternOptions struct {
	// Text and File are short option letters whose value is the pattern
	// (e) or names a pattern file the tool opens and reads (f).
	Text, File byte
	// ValueLetters are the other short options that take a value. They are
	// used only to end a short-option cluster: in `rg -tconf` the t takes
	// "conf", so the f there is not -f. A letter missing from this list can
	// only make the reading extract more (see patternOptionOperandPaths).
	ValueLetters string
	// Values drives the getopt reading, grepOperandPaths (#4682).
	Values *OptionValues
}

// OptionValues lists the options of a grep-family tool that take a value, as
// its option parser reads them (#4682). The path walk reads every option word
// as a switch, and its universal -m text flag (meant for `git commit -m`)
// swallows every later word up to the next option, so grep's max-count
// `-m 1` hid the file operand. grepOperandPaths consumes each value as a value
// instead.
//
// Both lists are measured, not guessed: each option was run as `OPT VAL KEY
// file` against BSD grep 2.6.0 (macOS), GNU grep 3.7 and ripgrep 15.2.0 (PR
// #4682 has the table). Where the tools disagree the option is listed as a
// switch. That is the direction whose error is bounded: the reading then takes
// the value as the pattern and the real pattern as one more candidate path,
// which is how the walk already reads every option. Listing a switch as
// taking a value would make the reading skip the word after it, which may be
// the file.
type OptionValues struct {
	// Short are the letters that take a value, other than the pattern
	// letters: the rest of the word (`-m1`, `-rnm5`), or the next word.
	Short string
	// Long are the names that take the next word as their value when written
	// without "=". An option whose value is optional (grep's --color) is a
	// switch unless "=" joins its value, so it is not listed.
	Long map[string]bool
}

// grepPatternOptions covers GNU and BSD grep, egrep and fgrep (value-taking
// short options: -A -B -C -D -d -m, and GNU's undocumented -X).
var grepPatternOptions = &PatternOptions{Text: 'e', File: 'f', ValueLetters: "ABCDdmX", Values: grepOptionValues}

// grepOptionValues is the union of BSD and GNU grep's value-taking options,
// less two they disagree on: -X takes a matcher name in GNU and is --xz, a
// switch, in BSD; --context takes a required value in GNU and an optional one
// in BSD (`--context 3`: BSD reads 3 as the pattern). --color/--colour take
// an optional value in both. Unique prefixes (`--max 1`) are read as switches.
var grepOptionValues = &OptionValues{
	Short: "ABCDdm",
	Long: map[string]bool{
		"after-context": true, "before-context": true, "binary-files": true,
		"devices": true, "directories": true, "exclude": true, "exclude-dir": true,
		"exclude-from": true, "group-separator": true, "include": true,
		"include-dir": true, "label": true, "max-count": true,
	},
}

// rgPatternOptions covers ripgrep (-A -B -C -E -M -T -d -g -j -m -r -t take
// a value).
var rgPatternOptions = &PatternOptions{Text: 'e', File: 'f', ValueLetters: "ABCEMTdgjmrt", Values: rgOptionValues}

// rgOptionValues is every ripgrep 15 option `rg --help` shows with a value.
// ripgrep takes no prefixes, and its --color requires a value.
var rgOptionValues = &OptionValues{
	Short: "ABCEMTdgjmrt",
	Long: map[string]bool{
		"after-context": true, "before-context": true, "color": true, "colors": true,
		"context": true, "context-separator": true, "dfa-size-limit": true,
		"encoding": true, "engine": true, "field-context-separator": true,
		"field-match-separator": true, "generate": true, "glob": true,
		"hostname-bin": true, "hyperlink-format": true, "iglob": true,
		"ignore-file": true, "max-columns": true, "max-count": true,
		"max-depth": true, "max-filesize": true, "path-separator": true,
		"pre": true, "pre-glob": true, "regex-size-limit": true, "replace": true,
		"sort": true, "sortr": true, "threads": true, "type": true,
		"type-add": true, "type-clear": true, "type-not": true,
	},
}

// SearchToolOptions is the option set of a search tool whose options are not
// grep's: ag and ack (#4689). Their -m is max-count, as grep's is, so the
// walk's universal -m text flag hid their file operands the same way. They
// have no -e, and their -f means something else (ag: --follow; ack: list the
// files, with no pattern), so grep's PatternOptions do not fit them.
//
// The lists are measured, not guessed. Each option was run as `OPT VAL KEY
// file` on ag 2.2.0 and ack v3.6.0 (Debian bookworm), and ag's getopt table
// and ack's Getopt::Long specs were read from their source (PR #4689's table).
// An option counts as taking a value only when it always takes one. -A, -B,
// -C (both tools) and ack's -p take the next word only when it is a number,
// and ack's --pager only when it does not start with "-", so they are listed
// as switches. That is the direction whose error is bounded (see OptionValues).
// Both tools accept a unique prefix of a long name; a prefix is read as a
// switch, as for grep.
type SearchToolOptions struct {
	// Values are the options that take a value.
	Values OptionValues
	// NoPatternShort and NoPatternLong are the options after which the tool
	// reads no positional pattern, so every positional word is a path: ag's
	// -g/--filename-pattern, ack's -f and --match.
	NoPatternShort string
	NoPatternLong  map[string]bool
}

// agOptions is ag 2.2.0's getopt_long table. -A/-B/-C take the next word only
// when strtol reads all of it, and --after/--before/--context take a value
// only after "=".
var agOptions = &SearchToolOptions{
	Values: OptionValues{
		Short: "GgmpW",
		Long: map[string]bool{
			"ackmate-dir-filter": true, "color-line-number": true, "color-match": true,
			"color-path": true, "depth": true, "file-search-regex": true,
			"filename-pattern": true, "ignore": true, "ignore-dir": true,
			"max-count": true, "pager": true, "path-to-ignore": true, "width": true,
			"workers": true,
		},
	},
	NoPatternShort: "g",
	NoPatternLong:  map[string]bool{"filename-pattern": true},
}

// ackOptions is ack v3.6.0's Getopt::Long specs (bundling on, so `-m1` and
// `-im 1` give m the value 1). The `:` specs (-A, -B, -C, -p, --pager and
// their long names) take an optional value and are switches here.
var ackOptions = &SearchToolOptions{
	Values: OptionValues{
		Short: "mtT",
		Long: map[string]bool{
			"ackrc": true, "color-colno": true, "color-filename": true,
			"color-lineno": true, "color-match": true, "files-from": true,
			"ignore-dir": true, "ignore-directory": true, "ignore-file": true,
			"match": true, "max-count": true, "noignore-dir": true,
			"noignore-directory": true, "output": true, "range-end": true,
			"range-start": true, "type": true, "type-add": true, "type-del": true,
			"type-set": true,
		},
	},
	NoPatternShort: "f",
	NoPatternLong:  map[string]bool{"match": true},
}

// searchToolReadings maps a search tool's basename to its option set.
var searchToolReadings = map[string]*SearchToolOptions{"ag": agOptions, "ack": ackOptions}

// commandRegistry maps "executable" or "executable subcommand" to its arg spec.
var commandRegistry = map[string]CommandArgSpec{
	// --- All-text commands (every positional arg is text) ---
	"echo":   {AllPositionalText: true},
	"printf": {AllPositionalText: true},

	// --- Git ---
	"git commit": {
		TextFlags:               map[string]bool{"m": true, "message": true},
		TextFlagConsumesAllArgs: true,
	},

	// --- GitHub CLI ---
	"gh issue create": {
		TextFlags:               map[string]bool{"body": true, "title": true, "b": true, "t": true},
		TextFlagConsumesAllArgs: true,
	},
	"gh pr create": {
		TextFlags:               map[string]bool{"body": true, "title": true, "b": true, "t": true},
		TextFlagConsumesAllArgs: true,
	},
	"gh issue comment": {
		TextFlags:               map[string]bool{"body": true, "b": true},
		TextFlagConsumesAllArgs: true,
	},
	"gh issue edit": {
		TextFlags:               map[string]bool{"body": true, "title": true, "b": true, "t": true},
		TextFlagConsumesAllArgs: true,
	},

	// --- Pattern-first commands (first positional arg is pattern/expression) ---
	// grep-family tools also accept the pattern as the VALUE of -e/--regexp
	// (and a pattern list file via -f/--file) instead of a positional operand
	// — e.g. `grep -e 'cat ~/.ssh/id_rsa' file.go` never has a positional
	// pattern at all, so TextPositions[0] alone would still misclassify the
	// flag value as a path. -f's value is a *file path* (a pattern list),
	// not text, so it's intentionally excluded here (#3224). Once one of
	// these options supplies the pattern, the positional words are files;
	// PatternOptions drives that second reading (#4676). ag and ack are not
	// given one: ag's -f is --follow and ack's -f lists files. They get their
	// own reading, keyed on searchToolReadings, outside this spec (#4689).
	"grep":  {TextPositions: map[int]bool{0: true}, TextFlags: map[string]bool{"e": true, "regexp": true}, PatternOptions: grepPatternOptions},
	"egrep": {TextPositions: map[int]bool{0: true}, TextFlags: map[string]bool{"e": true, "regexp": true}, PatternOptions: grepPatternOptions},
	"fgrep": {TextPositions: map[int]bool{0: true}, TextFlags: map[string]bool{"e": true, "regexp": true}, PatternOptions: grepPatternOptions},
	"rg":    {TextPositions: map[int]bool{0: true}, TextFlags: map[string]bool{"e": true, "regexp": true}, PatternOptions: rgPatternOptions},
	"ag":    {TextPositions: map[int]bool{0: true}},
	"ack":   {TextPositions: map[int]bool{0: true}},
	"sed":   {TextPositions: map[int]bool{0: true}},
	"awk":   {TextPositions: map[int]bool{0: true}},

	// --- Shell interpreters with inline code ---
	"bash":    {InlineCodeFlags: map[string]bool{"c": true}, TextFlagConsumesAllArgs: true},
	"sh":      {InlineCodeFlags: map[string]bool{"c": true}, TextFlagConsumesAllArgs: true},
	"zsh":     {InlineCodeFlags: map[string]bool{"c": true}, TextFlagConsumesAllArgs: true},
	"dash":    {InlineCodeFlags: map[string]bool{"c": true}, TextFlagConsumesAllArgs: true},
	"ksh":     {InlineCodeFlags: map[string]bool{"c": true}, TextFlagConsumesAllArgs: true},
	"python":  {InlineCodeFlags: map[string]bool{"c": true}, TextFlagConsumesAllArgs: true},
	"python3": {InlineCodeFlags: map[string]bool{"c": true}, TextFlagConsumesAllArgs: true},
	"python2": {InlineCodeFlags: map[string]bool{"c": true}, TextFlagConsumesAllArgs: true},
	"ruby":    {InlineCodeFlags: map[string]bool{"e": true}, TextFlagConsumesAllArgs: true},
	"perl":    {InlineCodeFlags: map[string]bool{"e": true}, TextFlagConsumesAllArgs: true},
	"node":    {InlineCodeFlags: map[string]bool{"e": true}, TextFlagConsumesAllArgs: true},
}

// universalTextFlags are flag names that indicate text content regardless
// of the command. This generalizes the old textContentFlags approach.
var universalTextFlags = map[string]bool{
	"message":     true,
	"m":           true,
	"body":        true,
	"title":       true,
	"comment":     true,
	"description": true,
	"subject":     true,
	"notes":       true,
	"reason":      true,
}

// lookupSpec finds the CommandArgSpec for a segment, trying multi-level
// subcommand lookups (e.g., "gh issue create" from exec="gh" sub="issue" args[0]="create").
func lookupSpec(seg shellparse.CommandSegment) (CommandArgSpec, bool) {
	// Try "executable subcommand arg[0]" for 2-level subcommands (gh issue create)
	if seg.SubCommand != "" && len(seg.Args) > 0 {
		key := seg.Executable + " " + seg.SubCommand + " " + seg.Args[0]
		if spec, ok := commandRegistry[key]; ok {
			return spec, true
		}
	}
	// Try "executable subcommand"
	if seg.SubCommand != "" {
		if spec, ok := commandRegistry[seg.Executable+" "+seg.SubCommand]; ok {
			return spec, true
		}
	}
	// Try "executable"
	if spec, ok := commandRegistry[seg.Executable]; ok {
		return spec, true
	}
	return CommandArgSpec{}, false
}

// ClassifyArgs classifies each argument in a command segment as path, text,
// or unknown. The returned slice has the same length as seg.Args.
func ClassifyArgs(seg shellparse.CommandSegment) []ArgRole {
	if len(seg.Args) == 0 {
		return nil
	}

	roles := make([]ArgRole, len(seg.Args))
	for i := range roles {
		roles[i] = ArgRoleUnknown // conservative default
	}

	spec, found := lookupSpec(seg)

	if found {
		// All-positional-text commands (echo, printf)
		if spec.AllPositionalText {
			for i := range roles {
				roles[i] = ArgRoleText
			}
			return roles
		}

		// TextFlagConsumesAllArgs: if any text/inline-code flag is present
		// (even with empty value), mark all positional args as text.
		// This handles the case where the shell parser doesn't consume the
		// flag value and it leaks into Args (e.g., git commit -m "msg").
		if spec.TextFlagConsumesAllArgs {
			consumeAll := false
			for flag := range spec.TextFlags {
				if _, ok := seg.Flags[flag]; ok {
					consumeAll = true
					break
				}
			}
			if !consumeAll {
				for flag := range spec.InlineCodeFlags {
					if _, ok := seg.Flags[flag]; ok {
						consumeAll = true
						break
					}
				}
			}
			if consumeAll {
				for i := range roles {
					roles[i] = ArgRoleText
				}
				return roles
			}
		}

		// Text positions (grep positional[0], sed positional[0])
		for idx := range spec.TextPositions {
			if idx < len(roles) {
				roles[idx] = ArgRoleText
			}
		}
	}

	// Check universal text flags: if any universal text flag is present
	// (with empty value, meaning its value leaked into Args), mark all args as text.
	for flag := range universalTextFlags {
		if _, ok := seg.Flags[flag]; ok {
			for i := range roles {
				roles[i] = ArgRoleText
			}
			return roles
		}
	}

	return roles
}

// ClassifyFlags classifies flag values as text or not.
// Returns a set of flag names whose values should be treated as text content.
func ClassifyFlags(seg shellparse.CommandSegment) map[string]bool {
	textFlags := make(map[string]bool)

	spec, found := lookupSpec(seg)

	// Command-specific text flags
	if found {
		for flag := range spec.TextFlags {
			textFlags[flag] = true
		}
		for flag := range spec.InlineCodeFlags {
			textFlags[flag] = true
		}
	}

	// Universal text flags apply to all commands
	for flag := range universalTextFlags {
		textFlags[flag] = true
	}

	return textFlags
}
