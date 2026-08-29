package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"gopkg.in/yaml.v3"
)

// ExistingMCPPack represents the minimal YAML structure we need to read existing MCP rules.
type ExistingMCPPack struct {
	Rules []ExistingMCPRule `yaml:"rules,omitempty"`
}

// ExistingMCPRule captures just the ID and match patterns for dedup.
type ExistingMCPRule struct {
	ID    string              `yaml:"id"`
	Match ExistingMCPMatch    `yaml:"match"`
}

// ExistingMCPMatch captures tool names and argument patterns.
type ExistingMCPMatch struct {
	ToolNameAny      []string          `yaml:"tool_name_any,omitempty"`
	ArgumentPatterns map[string]string `yaml:"argument_patterns,omitempty"`
}

// LoadExistingMCPRules loads all rule IDs and path patterns from existing MCP packs.
func LoadExistingMCPRules(mcpPackDir string) (map[string]bool, map[string]bool, error) {
	ruleIDs := map[string]bool{}
	pathPatterns := map[string]bool{}

	entries, err := os.ReadDir(mcpPackDir)
	if err != nil {
		return ruleIDs, pathPatterns, fmt.Errorf("read MCP pack dir: %w", err)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		// mcp-generated.yaml is read like any other pack: EmitMCPPack (see
		// emit.go) merges into it rather than overwriting, so a rule already
		// shipped there is exactly as "existing" as a hand-authored one. A
		// skip here used to be load-bearing (it kept already-shipped
		// candidates flowing back through as "new" so a full-overwrite Emit
		// wouldn't erase them) but with a merging Emit it only does harm: it
		// makes every rule already in the file permanently invisible to
		// dedup, so `-dry-run` reports it as a gap forever (#3367). Verified
		// live: 10 of the 18 "net-new" candidates on the real corpus were
		// already-shipped mcp-generated.yaml rules the checker couldn't see.
		data, err := os.ReadFile(filepath.Join(mcpPackDir, e.Name()))
		if err != nil {
			continue
		}
		var pack ExistingMCPPack
		if err := yaml.Unmarshal(data, &pack); err != nil {
			continue
		}
		for _, r := range pack.Rules {
			ruleIDs[r.ID] = true
			if p, ok := r.Match.ArgumentPatterns["path"]; ok {
				pathPatterns[p] = true
			}
			if u, ok := r.Match.ArgumentPatterns["url"]; ok {
				pathPatterns[u] = true
			}
		}
	}

	return ruleIDs, pathPatterns, nil
}

// LoadExistingMCPPolicy parses every MCP pack in mcpPackDir — including the
// generator's own output, mcp-generated.yaml; see the comment in
// LoadExistingMCPRules for why that file is no longer excluded — into a
// single merged policy for coverage evaluation. Unlike LoadExistingMCPRules,
// which only extracts ID/pattern strings for textual comparison, this keeps
// the full rule (tool names, decision) so CoverageChecker can ask the real
// MCP evaluator "what would this policy decide" instead of comparing
// pattern spelling (#3464).
func LoadExistingMCPPolicy(mcpPackDir string) (*mcp.MCPPolicy, error) {
	merged := &mcp.MCPPolicy{}

	entries, err := os.ReadDir(mcpPackDir)
	if err != nil {
		return merged, fmt.Errorf("read MCP pack dir: %w", err)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(mcpPackDir, e.Name()))
		if err != nil {
			continue
		}
		var pack mcp.MCPPolicy
		if err := yaml.Unmarshal(data, &pack); err != nil {
			continue
		}
		merged.Rules = append(merged.Rules, pack.Rules...)
		merged.StructuralRules = append(merged.StructuralRules, pack.StructuralRules...)
		merged.ResourceRules = append(merged.ResourceRules, pack.ResourceRules...)
		merged.BlockedTools = append(merged.BlockedTools, pack.BlockedTools...)
		merged.BlockedResources = append(merged.BlockedResources, pack.BlockedResources...)
	}

	return merged, nil
}

// decisionRank orders MCP decisions by restrictiveness so coverage can be
// compared with a plain integer inequality: BLOCK is at least as
// restrictive as AUDIT, which is at least as restrictive as ALLOW.
func decisionRank(d string) int {
	switch strings.ToUpper(d) {
	case "BLOCK", "REQUIRE_APPROVAL":
		return 2
	case "AUDIT":
		return 1
	default: // "ALLOW" or unrecognized
		return 0
	}
}

// representativeTools maps a candidate's category to the tool name(s) whose
// policy decision stands in for the whole alias family (read_file,
// cat_file, get_file_contents, ...). Existing rules in this corpus
// consistently gate a whole family together — see
// mcp-sec-block-ssh-private-key-read's 7-tool tool_name_any — so checking
// the primary verb per direction is enough without demanding every alias
// individually appear in the existing rule's own tool_name_any.
func representativeTools(category string) []string {
	switch category {
	case "path-read":
		return []string{"read_file"}
	case "path-write", "config-write":
		return []string{"write_file"}
	case "path-readwrite":
		return []string{"read_file", "write_file"}
	case "url":
		return []string{"http_request"}
	default:
		return []string{"read_file"}
	}
}

// CoverageChecker answers "does the existing MCP policy already decide this
// candidate's targets at least as restrictively as the candidate itself
// would" by running the real MCP evaluator, not by comparing pattern
// strings. This is what closes the gap textual dedup missed: `**/.aws/**`
// and `/home/*/.aws/**` don't match as strings, but the evaluator sees that
// an example path matching the former is also matched — and BLOCKed — by
// the latter.
type CoverageChecker struct {
	evaluator *mcp.PolicyEvaluator
}

// NewCoverageChecker builds a checker from a merged existing MCP policy
// (see LoadExistingMCPPolicy).
func NewCoverageChecker(existing *mcp.MCPPolicy) *CoverageChecker {
	return &CoverageChecker{evaluator: mcp.NewPolicyEvaluator(existing)}
}

// Covers reports whether every path/URL target of c already resolves to a
// decision at least as restrictive as c.Decision under the existing
// policy, checked against c.Category's representative tool(s). A candidate
// with no path/URL targets is never "covered" — there is nothing to
// compare, so it falls through to the textual/ID checks in
// DeduplicateCandidates.
func (cc *CoverageChecker) Covers(c Candidate) bool {
	if cc == nil || cc.evaluator == nil {
		return false
	}

	type target struct{ argKey, value string }
	var targets []target
	for _, p := range c.Paths {
		targets = append(targets, target{"path", exampleMaliciousPath(p)})
	}
	for _, u := range c.URLs {
		targets = append(targets, target{"url", u})
	}
	if len(targets) == 0 {
		return false
	}

	want := decisionRank(c.Decision)
	tools := representativeTools(c.Category)

	for _, t := range targets {
		for _, tool := range tools {
			args := map[string]interface{}{t.argKey: t.value}
			result := cc.evaluator.EvaluateToolCall(tool, args)
			if decisionRank(string(result.Decision)) < want {
				return false
			}
		}
	}
	return true
}

// fpRiskPaths are glob patterns that would cause false positives if used with
// `**/<file>` because these files legitimately exist in project directories.
// MCP glob matching can't distinguish ~/.<file> from /project/.<file>.
var fpRiskPaths = map[string]bool{
	"**/.npmrc":  true,
	"**/.yarnrc": true,
	"**/.pypirc": true,
}

// DeduplicateCandidates removes candidates that overlap with existing MCP
// rules. coverage may be nil (falls back to the textual-only checks below);
// pass the result of NewCoverageChecker(LoadExistingMCPPolicy(...)) to also
// catch candidates that are already covered by a differently-spelled
// existing pattern (#3464).
func DeduplicateCandidates(candidates []Candidate, existingIDs, existingPatterns map[string]bool, coverage *CoverageChecker) []Candidate {
	var result []Candidate
	seenPaths := map[string]bool{}

	for _, c := range candidates {
		// Skip if source rule ID already has an MCP equivalent.
		mcpID := candidateRuleID(c)
		if existingIDs[mcpID] {
			continue
		}

		// Skip paths that would cause false positives in project directories.
		hasFPRiskPath := false
		for _, p := range c.Paths {
			if fpRiskPaths[p] {
				hasFPRiskPath = true
				break
			}
		}
		if hasFPRiskPath {
			continue
		}

		// Skip if an existing rule already decides this candidate's targets
		// at least as restrictively, regardless of whether its pattern is
		// spelled the same way (coverage-based, not textual).
		if coverage.Covers(c) {
			continue
		}

		// Skip if all paths are already covered by existing patterns.
		allCovered := true
		for _, p := range c.Paths {
			if !existingPatterns[p] && !seenPaths[p] {
				allCovered = false
			}
		}
		for _, u := range c.URLs {
			if !existingPatterns[u] && !seenPaths[u] {
				allCovered = false
			}
		}
		if allCovered && (len(c.Paths) > 0 || len(c.URLs) > 0) {
			continue
		}

		// Mark paths as seen.
		for _, p := range c.Paths {
			seenPaths[p] = true
		}
		for _, u := range c.URLs {
			seenPaths[u] = true
		}

		result = append(result, c)
	}

	return result
}

// candidateRuleID generates the MCP rule ID for a candidate.
func candidateRuleID(c Candidate) string {
	slug := pathSlug(c.SourceRule.ID)
	if slug == "" {
		// Build from paths.
		if len(c.Paths) > 0 {
			slug = pathSlug(c.Paths[0])
		} else if len(c.URLs) > 0 {
			slug = pathSlug(c.URLs[0])
		}
	}
	return "mcp-gen-" + slug
}
