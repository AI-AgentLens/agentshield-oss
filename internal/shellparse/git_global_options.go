package shellparse

import (
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
)

// gitValueGlobalOptions are git's global options that take their value as the
// NEXT word (git(1) SYNOPSIS: `-C <path>`, `-c <name>=<value>`; git.c also
// accepts `--git-dir`, `--work-tree`, `--namespace` and `--config-env` with a
// separate-word value). `--opt=value` and flag-only globals (`--no-pager`,
// `-p`, `--bare`) need nothing: the parser already leaves the subcommand where
// the rules read it.
var gitValueGlobalOptions = map[string]bool{
	"-C": true, "-c": true,
	"--git-dir": true, "--work-tree": true, "--namespace": true, "--config-env": true,
}

// StripGitGlobalOptions returns command with every `-C <path>` / `-c k=v` style
// global option (and its value word) removed from a git invocation, or "" when
// the command has none (or does not parse). `git -C /repo commit -n` becomes
// `git commit -n` (#4623).
//
// The parser takes the first positional word as git's subcommand, so a global
// option whose value is a separate word shifts the real subcommand one slot
// right and every rule keyed on `subcommand: commit` stops reading it. The
// rewrite is a READING of the same argv, not a replacement: the caller
// (policy.Engine.EvaluateQuotedFlags) evaluates it as a SECOND reading and
// keeps it only when strictly more restrictive. Every other byte is kept as
// written: spans are cut from the original text, not re-printed.
func StripGitGlobalOptions(command string) string {
	if !strings.Contains(command, "git") {
		return ""
	}
	file, err := ParseText(command, syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	if err != nil {
		return ""
	}
	type span struct{ start, end int }
	var spans []span
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) < 3 {
			return true
		}
		words := make([]string, len(call.Args))
		for i, w := range call.Args {
			words[i] = WordToString(w)
		}
		stripped, _, _ := stripExecWrappers(words)
		if len(stripped) < 3 {
			return true
		}
		// stripExecWrappers returns a suffix of its input.
		base := len(words) - len(stripped)
		if ProgramName(NormalizeExecName(stripped[0])) != "git" {
			return true
		}
		for i := 1; i < len(stripped); i++ {
			w := stripped[i]
			if !strings.HasPrefix(w, "-") && !strings.HasPrefix(pathnorm.StripShellQuotes(w), "-") {
				break // reached the subcommand
			}
			if !gitValueGlobalOptions[pathnorm.StripShellQuotes(w)] {
				continue // flag-only or --opt=value global
			}
			if i+1 >= len(stripped) {
				break
			}
			from := call.Args[base+i]
			to := call.Args[base+i+1]
			start, end := int(from.Pos().Offset()), int(to.End().Offset())
			if start < 0 || end > len(command) || start >= end {
				break
			}
			spans = append(spans, span{start, end})
			i++ // skip the value word
		}
		return true
	})
	if len(spans) == 0 {
		return ""
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start > spans[j].start })
	out := command
	for _, s := range spans {
		// Cut the option, its value and the whitespace after them.
		end := s.end
		for end < len(out) && (out[end] == ' ' || out[end] == '\t') {
			end++
		}
		out = out[:s.start] + out[end:]
	}
	return out
}
