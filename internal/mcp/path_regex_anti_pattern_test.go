package mcp

import (
	"sort"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/packs"
	"gopkg.in/yaml.v3"
)

// TestNoPathArgumentRegexPatterns is a fitness function for issue #2082.
//
// MCP rules MUST NOT pair argument_regex_patterns with the "path" key. Use
// argument_patterns (single glob) or argument_patterns_any (list of globs)
// instead.
//
// Why: the glob matcher applies filepath.Clean which normalizes ../ traversals
// and other non-canonical forms before matching. Regex matching skips that
// normalization, creating a path-traversal bypass surface — an attacker can
// craft a path the regex doesn't match but resolves to the protected target
// after canonicalization.
//
// First violation of this convention was caught by Supervisor Kai on
// 2026-05-21 (PR #2058 / issue #2082); this gate prevents recurrence.
//
// Scope: limited to the literal "path" key. Other arg names like
// destination/source/dest can legitimately carry URLs or URIs where regex
// is correct (filepath.Clean is not relevant); broaden only if a real
// filesystem-path arg surfaces under a different name.
func TestNoPathArgumentRegexPatterns(t *testing.T) {
	mcpFiles := packs.MCPFiles()
	if len(mcpFiles) == 0 {
		t.Fatal("packs.MCPFiles() returned 0 files — embed regression?")
	}

	type violation struct {
		pack   string
		ruleID string
		arg    string
	}
	var violations []violation

	for name, data := range mcpFiles {
		var pol MCPPolicy
		if err := yaml.Unmarshal(data, &pol); err != nil {
			t.Errorf("%s: failed to parse: %v", name, err)
			continue
		}
		for _, rule := range pol.Rules {
			for argName := range rule.Match.ArgumentRegexPatterns {
				if strings.EqualFold(argName, "path") {
					violations = append(violations, violation{
						pack:   name,
						ruleID: rule.ID,
						arg:    argName,
					})
				}
			}
		}
	}

	if len(violations) > 0 {
		sort.Slice(violations, func(i, j int) bool {
			if violations[i].pack != violations[j].pack {
				return violations[i].pack < violations[j].pack
			}
			return violations[i].ruleID < violations[j].ruleID
		})
		var b strings.Builder
		b.WriteString("argument_regex_patterns paired with a path argument — use argument_patterns_any (glob) instead.\n")
		b.WriteString("Glob matching applies filepath.Clean (normalizes ../ traversals); regex does not, creating a bypass surface.\n")
		b.WriteString("See issue #2082 for context and conversion examples.\n\nViolations:\n")
		for _, v := range violations {
			b.WriteString("  - ")
			b.WriteString(v.pack)
			b.WriteString(" :: ")
			b.WriteString(v.ruleID)
			b.WriteString(" (arg: ")
			b.WriteString(v.arg)
			b.WriteString(")\n")
		}
		t.Fatal(b.String())
	}
}
