package mcp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Customer protected_paths on tool calls (#4645).
//
// A customer who adds a path to a pack's defaults.protected_paths gets a shell
// BLOCK for any command naming it. The agent's own file tools (Claude Code
// Read, Write, Edit, MultiEdit, NotebookEdit; Copilot CLI view, create, edit)
// and MCP file tools reach the hook as tool calls, which this evaluator
// decides from MCP policy alone, so the same Read decided AUDIT with no rule.
// The paths AgentShield ships reach those tools through MCP rules of their own;
// a customer's path reached nothing.
//
// SetProtectedPaths hands the evaluator the customer's patterns (assembly
// passes policy.CustomerProtectedPaths of the merged shell policy). A
// file-path argument that names one decides BLOCK with the shell's rule id,
// protected-path, and its taxonomy (foldProtectedPath). It is folded into the
// verdict after the rules' readings, under the same readings: case-folded
// (#4194), Windows separators (#4243) and the macOS /private alias (#4387).

// protectedPathArgKeys are the argument names a tool call carries a file path
// in: Claude Code's file_path (Read, Write, Edit, MultiEdit) and notebook_path
// (NotebookEdit), the path of Glob, Grep, Copilot's tools and most MCP file
// servers (paths for their batch reads), and the filesystem server's
// move_file source and destination. Names resolve as every argument rule's
// do, so filePath, file-path and a confusable spelling resolve too.
var protectedPathArgKeys = []string{"file_path", "notebook_path", "path", "source", "destination"}

// SetProtectedPaths sets the protected_paths patterns a file-path argument
// may not name. Pass only the customer's patterns: the shipped ones reach the
// file tools through MCP rules, with the decisions #4248 chose for them.
func (e *PolicyEvaluator) SetProtectedPaths(patterns []string) {
	if e == nil {
		return
	}
	e.protectedPaths = append([]string(nil), patterns...)
	e.home, _ = os.UserHomeDir()
}

// ProtectedPaths returns the patterns SetProtectedPaths set.
func (e *PolicyEvaluator) ProtectedPaths() []string {
	if e == nil {
		return nil
	}
	return append([]string(nil), e.protectedPaths...)
}

// InWorkingDir returns a view of e whose protected-path check resolves the
// call's file-path arguments against dir, the directory the tool runs in
// (#4653): a relative argument is also read as dir/<argument>, and a relative
// pattern (`secrets/**`, `.env`) also matches a path under dir, made
// dir-relative, exactly as the shell engine's checkProtectedPaths does for a
// command run in dir. Claude Code sends absolute file_path values, so without
// a dir a relative pattern never matched Read, Write or Edit.
//
// Raise-only: every match without a dir is still tried first, unchanged. dir
// must be absolute; anything else leaves the check as it is without one. The
// view shares e's policy and indexes (read-only), so a surface that serves
// many working directories (shield-server) takes one view per request instead
// of building an evaluator.
func (e *PolicyEvaluator) InWorkingDir(dir string) *PolicyEvaluator {
	if e == nil {
		return nil
	}
	view := *e
	view.workDir = ""
	if filepath.IsAbs(dir) {
		view.workDir = dir
	}
	return &view
}

// foldProtectedPath folds a protected-path BLOCK into result, the verdict
// every rule reading decided. It runs once, after evaluateReadings, so the
// rules' own record is kept exactly as main makes it: a BLOCK the rules
// already made gets protected-path appended beside it, a lower verdict is
// replaced (most-restrictive-wins, as for every other rule).
//
// The path is tried under the same readings as the rules: as written,
// case-folded (#4194), Windows separators (#4243), and the /private alias
// written short (#4387), each with the case fold the rules' reading uses.
func (e *PolicyEvaluator) foldProtectedPath(result MCPEvalResult, arguments map[string]interface{}) MCPEvalResult {
	if len(e.protectedPaths) == 0 || len(arguments) == 0 {
		return result
	}
	pattern, argName, hits, hit := e.protectedPathArgument(arguments, false)
	try := func(args map[string]interface{}, foldCase bool) {
		if !hit {
			pattern, argName, hits, hit = e.protectedPathArgument(args, foldCase)
		}
	}
	if folded, ok := foldPathArguments(arguments); ok {
		try(folded, true)
	}
	if slashed, ok := slashWindowsPathArguments(arguments); ok {
		if folded, ok := foldPathArguments(slashed); ok {
			slashed = folded
		}
		try(slashed, true)
	}
	if short, ok := privateAliasArguments(arguments); ok {
		try(short, false)
		if folded, ok := foldPathArguments(short); ok {
			try(folded, true)
		}
	}
	if !hit {
		return result
	}
	reason := fmt.Sprintf("Access to protected path denied: %s (tool argument %q)", pattern, argName)
	taxonomy := policy.ProtectedPathTaxonomyRefs(pattern, hits)
	out := result
	if decisionSeverity(policy.DecisionBlock) > decisionSeverity(result.Decision) {
		out.Decision = policy.DecisionBlock
		out.TriggeredRules = []string{policy.ProtectedPathRuleID}
		out.Reasons = []string{reason}
		out.TaxonomyRef = ""
		out.TaxonomyRefs = taxonomy
		return out
	}
	out.TriggeredRules = append(append([]string{}, result.TriggeredRules...), policy.ProtectedPathRuleID)
	out.Reasons = append(append([]string{}, result.Reasons...), reason)
	out.TaxonomyRefs = analyzer.NormalizeTaxonomyRefs(append(append([]string{}, result.TaxonomyRefs...), taxonomy...))
	return out
}

// protectedPathArgument returns the first protected pattern a file-path
// argument names, the argument's name, and every path value that matched the
// pattern (the receipt's evidence). foldCase is the #4194 folded reading.
func (e *PolicyEvaluator) protectedPathArgument(arguments map[string]interface{}, foldCase bool) (pattern, argName string, hits []string, ok bool) {
	if len(e.protectedPaths) == 0 || len(arguments) == 0 {
		return "", "", nil, false
	}
	type candidate struct{ arg, path string }
	var cands []candidate
	for _, key := range protectedPathArgKeys {
		for _, v := range protectedPathArgValues(arguments, key) {
			p := toolCallPath(v, e.home)
			if p == "" {
				continue
			}
			cands = append(cands, candidate{key, p})
			// #4653: a relative argument names a file under the tool's
			// working directory, as a relative argv path does on the shell.
			if e.workDir != "" && !filepath.IsAbs(p) {
				cands = append(cands, candidate{key, filepath.Join(e.workDir, p)})
			}
		}
	}
	for _, c := range cands {
		pat, hit := policy.MatchProtectedPath(e.protectedPaths, e.home, c.path, e.workDir, foldCase)
		if !hit {
			continue
		}
		for _, d := range cands {
			if _, same := policy.MatchProtectedPath([]string{pat}, e.home, d.path, e.workDir, foldCase); same {
				hits = append(hits, d.path)
			}
		}
		return pat, c.arg, hits, true
	}
	return "", "", nil, false
}

// protectedPathArgValues is every string an argument named key (or its plural,
// or key one level inside an array of objects or an envelope object) holds.
// It is resolveFieldValues without the JSON-inside-a-string form: a JSON
// document an Edit writes as new_string names paths as data, not as the
// target of this call.
func protectedPathArgValues(arguments map[string]interface{}, key string) []string {
	var out []string
	if v, ok := resolveField(arguments, key); ok {
		out = append(out, flattenArgValue(v)...)
	}
	if v, ok := resolveField(arguments, key+"s"); ok {
		out = append(out, flattenArgValue(v)...)
	}
	if vs, ok := resolveNestedArrayObjectField(arguments, key); ok {
		out = append(out, vs...)
	}
	if vs, ok := resolveNestedObjectField(arguments, key); ok {
		out = append(out, vs...)
	}
	return out
}

// toolCallPath is the path a tool call's argument value names, resolved as the
// shell normalizer resolves an argv path: `~/` expanded, then cleaned, so
// `/a/b/../secrets/x` is `/a/secrets/x` and `/a/secrets/../../x` is not under
// /a/secrets. A relative value stays relative here; protectedPathArgument also
// reads it under the working directory when InWorkingDir set one. "" for a
// value that is not a single path (empty, or more than one line).
func toolCallPath(v, home string) string {
	if v == "" || strings.ContainsAny(v, "\n\r\x00") {
		return ""
	}
	if (v == "~" || strings.HasPrefix(v, "~/")) && home != "" {
		v = filepath.Join(home, strings.TrimPrefix(v, "~"))
	}
	return filepath.Clean(v)
}
