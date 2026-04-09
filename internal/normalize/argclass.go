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
}

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
	"grep": {TextPositions: map[int]bool{0: true}},
	"rg":   {TextPositions: map[int]bool{0: true}},
	"sed":  {TextPositions: map[int]bool{0: true}},
	"awk":  {TextPositions: map[int]bool{0: true}},

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
