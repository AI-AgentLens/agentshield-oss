package analyzer

import (
	"path/filepath"
	"strings"
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
	ArgsAny  []string // any positional arg matches any glob
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

	// --- ArgsAny: at least one positional arg matches at least one glob ---
	if len(rule.ArgsAny) > 0 {
		found := false
		for _, arg := range seg.Args {
			for _, pattern := range rule.ArgsAny {
				if matchArgGlob(arg, pattern) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}

	// --- ArgsNone: no positional arg matches any of these ---
	if len(rule.ArgsNone) > 0 {
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
	for _, alias := range aliases {
		if _, ok := seg.Flags[alias]; ok {
			return true
		}
	}

	return false
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
