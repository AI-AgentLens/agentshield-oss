package analyzer

import (
	"path/filepath"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// StructuralRule is the analyzer-side representation of a user-defined structural
// rule from YAML. It mirrors the policy.StructuralMatch fields but lives in the
// analyzer package to avoid import cycles (same pattern as RegexRule).
//
// Evaluated against the ParsedCommand produced by the structural analyzer's
// shell AST parser. This is more robust than regex because:
//   - Flag reordering is handled (rm -rf / == rm --recursive --force /)
//   - Sudo wrapping is transparent (sudo rm -rf / matches "rm" rules)
//   - Pipe chains are first-class (pipe_to, pipe_from)
//   - Glob matching on arguments (args_any: ["/etc/**"])
type StructuralRule struct {
	// Rule metadata (copied from policy.Rule at pipeline build time)
	ID         string
	Decision   string
	Confidence float64
	Reason     string
	Taxonomy   string

	// Command identification
	Executable []string // exact match: "rm" or ["rm", "unlink"]
	SubCommand string   // e.g., "install" for "npm install"

	// Flag predicates
	FlagsAll  []string // must have ALL of these
	FlagsAny  []string // must have at least ONE
	FlagsNone []string // must NOT have any of these

	// Argument predicates (glob patterns)
	ArgsAny  []string // any positional arg matches any glob; on an ALLOW (not negated), EVERY arg must (#4595)
	ArgsNone []string // no positional arg matches any of these

	// Pipe analysis
	HasPipe         *bool    // command contains a pipe operator
	PipeTo          []string // RHS of pipe is one of these executables
	PipeToFlagsNone []string // don't match if the pipe_to segment has any of these flags
	PipeFrom        []string // LHS of pipe is one of these executables

	// Modifiers
	Negate bool // invert match result
}

// MatchStructuralRule evaluates a single structural rule against a ParsedCommand.
// Returns true if the command matches all specified predicates (AND logic).
// Empty predicates are skipped (vacuously true).
func MatchStructuralRule(parsed *ParsedCommand, rule StructuralRule) bool {
	if parsed == nil {
		return false
	}

	// A structural rule must match at least one segment.
	// We check all segments (including subcommands) for a matching segment.
	segments := allSegments(parsed)
	if len(segments) == 0 {
		return rule.Negate
	}

	matched := false

	// If pipe predicates are specified, check at the pipeline level first.
	if rule.HasPipe != nil || len(rule.PipeTo) > 0 || len(rule.PipeFrom) > 0 {
		if !matchPipePredicates(parsed, rule) {
			return applyNegate(false, rule.Negate)
		}
	}

	// Check each segment for command-level predicates.
	for _, seg := range segments {
		if matchSegment(seg, rule) {
			matched = true
			break
		}
	}

	return applyNegate(matched, rule.Negate)
}

// matchSegment checks if a single CommandSegment satisfies all command-level
// predicates in the rule. All non-empty predicates must match (AND logic).
// If NO predicates are set the rule has no shell-level constraints; return false
// so that under-specified rules (e.g. MCP-only rules loaded into the shell
// pipeline) do not spuriously match every command.
func matchSegment(seg CommandSegment, rule StructuralRule) bool {
	// Guard: a structural rule with no shell constraints defined should not
	// match any shell command. This prevents MCP-pack rules whose non-shell
	// fields (args_match, tool_name_regex, etc.) are silently dropped by the
	// YAML decoder from becoming catch-all BLOCKs.
	noCommandConstraints := len(rule.Executable) == 0 &&
		rule.SubCommand == "" &&
		len(rule.FlagsAll) == 0 &&
		len(rule.FlagsAny) == 0 &&
		len(rule.FlagsNone) == 0 &&
		len(rule.ArgsAny) == 0 &&
		len(rule.ArgsNone) == 0
	noPipeConstraints := rule.HasPipe == nil &&
		len(rule.PipeTo) == 0 &&
		len(rule.PipeFrom) == 0
	if noCommandConstraints && noPipeConstraints && !rule.Negate {
		return false
	}

	// --- Executable ---
	if len(rule.Executable) > 0 {
		if !stringInList(seg.Executable, rule.Executable) {
			return false
		}
	}

	// --- SubCommand ---
	if rule.SubCommand != "" {
		if !strings.EqualFold(seg.SubCommand, rule.SubCommand) {
			return false
		}
	}

	// --- FlagsAll: must have ALL ---
	if len(rule.FlagsAll) > 0 {
		for _, reqFlag := range rule.FlagsAll {
			if !segmentHasFlag(seg, reqFlag) {
				return false
			}
		}
	}

	// --- FlagsAny: must have at least ONE ---
	if len(rule.FlagsAny) > 0 {
		found := false
		for _, anyFlag := range rule.FlagsAny {
			if segmentHasFlag(seg, anyFlag) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// --- FlagsNone: must NOT have any ---
	if len(rule.FlagsNone) > 0 {
		for _, noneFlag := range rule.FlagsNone {
			if segmentHasFlag(seg, noneFlag) {
				return false
			}
		}
	}

	// --- ArgsAny on an ALLOW: EVERY positional arg matches a glob (#4595) ---
	// An ALLOW vouches for the whole invocation, so its argument predicate
	// must hold for every operand, never for any one. With "at least one",
	// `rm -rf /tmp/x /etc/y` earned ts-allow-rm-tmp from its /tmp operand,
	// and the structural-override tag then dropped the regex BLOCK on the
	// /etc operand. A negated rule keeps the plain reading: inverting "every"
	// would widen the ALLOW instead of narrowing it.
	if len(rule.ArgsAny) > 0 && rule.Decision == "ALLOW" && !rule.Negate {
		if len(seg.Args) == 0 {
			return false
		}
		for _, arg := range seg.Args {
			ok := false
			for _, pattern := range rule.ArgsAny {
				if matchArgGlob(arg, pattern) {
					ok = true
					break
				}
			}
			if !ok {
				return false
			}
		}
	}

	// --- ArgsAny: at least one positional arg matches at least one glob ---
	//
	// On a non-ALLOW rule that pairs args_any with args_none, args_none carves
	// OPERANDS out of args_any instead of vetoing the invocation (#4595):
	// `rm -rf /tmp/x /etc/y` has an /etc operand that no exemption covers, so
	// the BLOCK on it must stand. Only ts-struct-block-rm-system has this
	// shape; an ALLOW keeps the invocation-wide veto below.
	operandCarveOut := len(rule.ArgsAny) > 0 && len(rule.ArgsNone) > 0 &&
		rule.Decision != "ALLOW" && !rule.Negate
	if len(rule.ArgsAny) > 0 {
		found := false
		for _, arg := range seg.Args {
			if operandCarveOut && argMatchesAny(arg, rule.ArgsNone) {
				continue
			}
			if argMatchesAny(arg, rule.ArgsAny) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// --- ArgsNone: no positional arg matches any of these ---
	if len(rule.ArgsNone) > 0 && !operandCarveOut {
		for _, arg := range seg.Args {
			for _, pattern := range rule.ArgsNone {
				if matchArgGlob(arg, pattern) {
					return false
				}
			}
		}
	}

	return true
}

// matchPipePredicates checks pipeline-level predicates against the full
// ParsedCommand structure (operators, segment order).
func matchPipePredicates(parsed *ParsedCommand, rule StructuralRule) bool {
	hasPipeOp := false
	for _, op := range parsed.Operators {
		if op == "|" {
			hasPipeOp = true
			break
		}
	}

	// --- HasPipe ---
	if rule.HasPipe != nil {
		if *rule.HasPipe != hasPipeOp {
			return false
		}
	}

	// --- PipeTo: RHS of any pipe is one of these executables ---
	// PipeToFlagsNone: disqualify a pipe_to match if the RHS segment has any of these flags.
	if len(rule.PipeTo) > 0 {
		if !hasPipeOp {
			return false
		}
		found := false
		for i, op := range parsed.Operators {
			if op == "|" && i+1 < len(parsed.Segments) {
				rhs := parsed.Segments[i+1]
				if stringInList(rhs.Executable, rule.PipeTo) {
					// Check PipeToFlagsNone: if pipe_to segment has any of these flags, skip this match.
					disqualified := false
					for _, flag := range rule.PipeToFlagsNone {
						if shellFlagIsNotProgram(rhs, flag) {
							continue // #4599: errexit / job control, stdin is still the script
						}
						if segmentHasFlag(rhs, flag) {
							disqualified = true
							break
						}
					}
					if !disqualified {
						found = true
						break
					}
				}
			}
		}
		if !found {
			return false
		}
	}

	// --- PipeFrom: LHS of any pipe is one of these executables ---
	if len(rule.PipeFrom) > 0 {
		if !hasPipeOp {
			return false
		}
		found := false
		for i, op := range parsed.Operators {
			if op == "|" && i < len(parsed.Segments) {
				lhs := parsed.Segments[i]
				if stringInList(lhs.Executable, rule.PipeFrom) {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// segmentHasFlag checks if a segment has a flag by short name, long name,
// or common aliases. This handles the fact that users may write "r" to mean
// both -r and --recursive.
func segmentHasFlag(seg CommandSegment, flag string) bool {
	// Direct lookup in the normalized flags map.
	// The structural parser normalizes: --recursive → "recursive", -r → "r"
	if _, ok := seg.Flags[flag]; ok {
		return true
	}

	// Check common short↔long aliases so users can write either form.
	aliases := flagAliases(flag)
	if (flag == "n" || flag == "dry-run") && isGitCommitSegment(seg) {
		// #4612: for `git commit`, -n is the hook-skipping short flag and
		// --dry-run is its own long option, so the generic n <-> dry-run
		// alias is a misread there.
		aliases = nil
	}
	for _, alias := range aliases {
		if _, ok := seg.Flags[alias]; ok {
			return true
		}
	}

	return false
}

// isGitCommitSegment reports whether seg is a `git commit` invocation.
func isGitCommitSegment(seg CommandSegment) bool {
	return (seg.Executable == "git" || seg.Program == "git") && seg.SubCommand == "commit"
}

// flagAliases returns known short↔long aliases for common flags.
// This allows rules to use "r" and match "--recursive", or vice versa.
func flagAliases(flag string) []string {
	// Bidirectional alias map: short → long, long → short
	aliasMap := map[string][]string{
		"r":         {"recursive", "R"},
		"R":         {"recursive", "r"},
		"recursive": {"r", "R"},
		"f":         {"force"},
		"force":     {"f"},
		"v":         {"verbose"},
		"verbose":   {"v"},
		"i":         {"interactive"},
		"n":         {"dry-run"},
		"dry-run":   {"n"},
		"o":         {"output"},
		"output":    {"o"},
		"O":         {"output-document"},
		"q":         {"quiet"},
		"quiet":     {"q"},
		"x":         {"extract"},
		// #4606: git (parse-options) and getopt_long accept any unambiguous
		// prefix of a long option. For git the three-letter stem is ambiguous
		// with the verbose negation and is rejected, so the four-letter stem
		// is the shortest spelling that runs as the hook-skipping flag. Only
		// a rule naming that flag reads these.
		"no-verify": {"no-veri", "no-verif"},
	}
	return aliasMap[flag]
}

// matchArgGlob matches a command argument against a glob pattern.
// Supports:
//   - "/"       → exact match
//   - "/etc/**" → prefix match (recursive)
//   - "/dev/sd*" → filepath.Match glob
//   - "*.py"    → suffix match
func matchArgGlob(arg, pattern string) bool {
	// Collapse shell quote-splices in the argument (tar ... ~/.ss'h'/,
	// cat /etc/pass'w'd) so an inline quote pair can't dodge an args_any /
	// args_none glob the shell itself resolves straight through. seg.Args stays
	// raw for every other predicate; only the glob comparison is normalized
	// (issue #2813).
	arg = pathnorm.StripShellQuotes(arg)
	// Same reasoning, one shell-expansion phase later: a '?'/'*' masking one
	// interior byte of a well-known sensitive path (tar czf k.tgz ~/.?sh/)
	// resolves identically at runtime, so it must not dodge an args_any /
	// args_none glob any more than a quote-splice can (issue #3103).
	arg = shellparse.DeglobPath(arg)

	// Handle recursive glob: "/etc/**"
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return arg == prefix || strings.HasPrefix(arg, prefix+"/")
	}

	// Handle single-level glob: "/etc/*"
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if !strings.HasPrefix(arg, prefix+"/") {
			return false
		}
		remainder := strings.TrimPrefix(arg, prefix+"/")
		return !strings.Contains(remainder, "/")
	}

	// Standard filepath.Match for wildcards
	if strings.ContainsAny(pattern, "*?[") {
		matched, err := filepath.Match(pattern, arg)
		return err == nil && matched
	}

	// Exact match
	return arg == pattern
}

// applyNegate inverts the match result if negate is true.
func applyNegate(matched, negate bool) bool {
	if negate {
		return !matched
	}
	return matched
}

// stringInList checks if s is in the list (case-sensitive).
func stringInList(s string, list []string) bool {
	for _, item := range list {
		if s == item {
			return true
		}
	}
	return false
}

func argMatchesAny(arg string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchArgGlob(arg, pattern) {
			return true
		}
	}
	return false
}
