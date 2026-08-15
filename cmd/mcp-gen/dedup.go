package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
		// Skip our own generated output to avoid self-dedup on re-runs.
		if e.Name() == "mcp-generated.yaml" {
			continue
		}
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

// fpRiskPaths are glob patterns that would cause false positives if used with
// `**/<file>` because these files legitimately exist in project directories.
// MCP glob matching can't distinguish ~/.<file> from /project/.<file>.
var fpRiskPaths = map[string]bool{
	"**/.npmrc":  true,
	"**/.yarnrc": true,
	"**/.pypirc": true,
}

// DeduplicateCandidates removes candidates that overlap with existing MCP rules.
func DeduplicateCandidates(candidates []Candidate, existingIDs, existingPatterns map[string]bool) []Candidate {
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
