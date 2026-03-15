// Command coverage generates COVERAGE.md by parsing pack YAML files and test data.
//
// Usage:
//
//	go run ./cmd/coverage
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// terminalRule mirrors the subset of policy.Rule we need for the report.
type terminalRule struct {
	ID         string `yaml:"id"`
	Taxonomy   string `yaml:"taxonomy,omitempty"`
	Match      match  `yaml:"match"`
	Decision   string `yaml:"decision"`
	Confidence float64 `yaml:"confidence,omitempty"`
	Reason     string `yaml:"reason"`
}

type match struct {
	CommandExact  string      `yaml:"command_exact,omitempty"`
	CommandPrefix interface{} `yaml:"command_prefix,omitempty"`
	CommandRegex  string      `yaml:"command_regex,omitempty"`
	Structural    interface{} `yaml:"structural,omitempty"`
	Dataflow      interface{} `yaml:"dataflow,omitempty"`
	Semantic      interface{} `yaml:"semantic,omitempty"`
	Stateful      interface{} `yaml:"stateful,omitempty"`
}

type terminalPack struct {
	Name  string         `yaml:"name"`
	Rules []terminalRule `yaml:"rules"`
}

// mcpRule mirrors MCP-specific rule structure.
type mcpRule struct {
	ID       string      `yaml:"id"`
	Taxonomy string      `yaml:"taxonomy,omitempty"`
	Match    interface{} `yaml:"match"`
	Decision string      `yaml:"decision"`
	Reason   string      `yaml:"reason"`
}

type mcpPack struct {
	Name           string        `yaml:"name"`
	BlockedTools   []string      `yaml:"blocked_tools,omitempty"`
	Rules          []mcpRule     `yaml:"rules,omitempty"`
	ValueLimits    []mcpRule     `yaml:"value_limits,omitempty"`
	ResourceRules  []mcpRule     `yaml:"resource_rules,omitempty"`
}

// flatRule is the common format used for report output.
type flatRule struct {
	ID        string
	Decision  string
	MatchType string
	Reason    string
	Kingdom   string
	Pack      string
}

func main() {
	root := findRepoRoot()

	// Parse terminal packs
	terminalRules := parseTerminalPacks(filepath.Join(root, "packs"))

	// Parse MCP packs
	mcpRules := parseMCPPacks(filepath.Join(root, "packs", "mcp"))

	// Count test cases by kingdom
	testCounts := countTestCases(filepath.Join(root, "internal", "analyzer", "testdata"))

	// Generate report
	report := generateReport(terminalRules, mcpRules, testCounts)

	outPath := filepath.Join(root, "COVERAGE.md")
	if err := os.WriteFile(outPath, []byte(report), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing COVERAGE.md: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Generated %s (%d terminal rules, %d MCP rules)\n", outPath, len(terminalRules), len(mcpRules))
}

func findRepoRoot() string {
	// Walk up from cwd looking for go.mod
	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot get cwd: %v\n", err)
		os.Exit(1)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			fmt.Fprintf(os.Stderr, "cannot find repo root (no go.mod found)\n")
			os.Exit(1)
		}
		dir = parent
	}
}

func parseTerminalPacks(dir string) []flatRule {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading packs dir: %v\n", err)
		os.Exit(1)
	}

	var rules []flatRule
	for _, e := range entries {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yaml") && !strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: cannot read %s: %v\n", e.Name(), err)
			continue
		}

		var pack terminalPack
		if err := yaml.Unmarshal(data, &pack); err != nil {
			fmt.Fprintf(os.Stderr, "warning: cannot parse %s: %v\n", e.Name(), err)
			continue
		}

		for _, r := range pack.Rules {
			rules = append(rules, flatRule{
				ID:        r.ID,
				Decision:  r.Decision,
				MatchType: detectMatchType(r.Match),
				Reason:    r.Reason,
				Kingdom:   extractKingdom(r.Taxonomy),
				Pack:      pack.Name,
			})
		}
	}
	return rules
}

func parseMCPPacks(dir string) []flatRule {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: no MCP packs dir: %v\n", err)
		return nil
	}

	var rules []flatRule
	for _, e := range entries {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yaml") && !strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: cannot read %s: %v\n", e.Name(), err)
			continue
		}

		var pack mcpPack
		if err := yaml.Unmarshal(data, &pack); err != nil {
			fmt.Fprintf(os.Stderr, "warning: cannot parse %s: %v\n", e.Name(), err)
			continue
		}

		// Blocked tools as synthetic rules
		for _, tool := range pack.BlockedTools {
			rules = append(rules, flatRule{
				ID:        fmt.Sprintf("blocked-tool:%s", tool),
				Decision:  "BLOCK",
				MatchType: "blocked_tool",
				Reason:    fmt.Sprintf("Tool '%s' is blocked by default.", tool),
				Kingdom:   "mcp-safety",
				Pack:      pack.Name,
			})
		}

		for _, r := range pack.Rules {
			rules = append(rules, flatRule{
				ID:        r.ID,
				Decision:  r.Decision,
				MatchType: "mcp_rule",
				Reason:    r.Reason,
				Kingdom:   extractKingdom(r.Taxonomy),
				Pack:      pack.Name,
			})
		}

		for _, r := range pack.ValueLimits {
			rules = append(rules, flatRule{
				ID:        r.ID,
				Decision:  r.Decision,
				MatchType: "value_limit",
				Reason:    r.Reason,
				Kingdom:   extractKingdom(r.Taxonomy),
				Pack:      pack.Name,
			})
		}

		for _, r := range pack.ResourceRules {
			rules = append(rules, flatRule{
				ID:        r.ID,
				Decision:  r.Decision,
				MatchType: "resource_rule",
				Reason:    r.Reason,
				Kingdom:   extractKingdom(r.Taxonomy),
				Pack:      pack.Name,
			})
		}
	}
	return rules
}

func detectMatchType(m match) string {
	if m.Stateful != nil {
		return "stateful"
	}
	if m.Dataflow != nil {
		return "dataflow"
	}
	if m.Semantic != nil {
		return "semantic"
	}
	if m.Structural != nil {
		return "structural"
	}
	if m.CommandRegex != "" {
		return "regex"
	}
	if m.CommandExact != "" {
		return "exact"
	}
	if m.CommandPrefix != nil {
		return "prefix"
	}
	return "unknown"
}

func extractKingdom(taxonomy string) string {
	if taxonomy == "" {
		return "uncategorized"
	}
	parts := strings.SplitN(taxonomy, "/", 2)
	return parts[0]
}

// kingdomTestCounts holds TP/TN counts per kingdom.
type kingdomTestCounts struct {
	TP int
	TN int
}

// countTestCases reads Go test data files and counts TP/TN per kingdom by
// mapping the file name to a kingdom.
func countTestCases(dir string) map[string]kingdomTestCounts {
	fileToKingdom := map[string]string{
		"destructive_ops_cases.go":       "destructive-ops",
		"credential_exposure_cases.go":   "credential-exposure",
		"data_exfiltration_cases.go":     "data-exfiltration",
		"persistence_evasion_cases.go":   "persistence-evasion",
		"privilege_escalation_cases.go":  "privilege-escalation",
		"reconnaissance_cases.go":        "reconnaissance",
		"supply_chain_cases.go":          "supply-chain",
		"unauthorized_execution_cases.go": "unauthorized-execution",
	}

	tpRe := regexp.MustCompile(`Classification:\s*"TP"`)
	tnRe := regexp.MustCompile(`Classification:\s*"TN"`)

	counts := make(map[string]kingdomTestCounts)
	for file, kingdom := range fileToKingdom {
		path := filepath.Join(dir, file)
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		c := kingdomTestCounts{}
		for scanner.Scan() {
			line := scanner.Text()
			if tpRe.MatchString(line) {
				c.TP++
			}
			if tnRe.MatchString(line) {
				c.TN++
			}
		}
		_ = f.Close()
		counts[kingdom] = c
	}
	return counts
}

func generateReport(terminal []flatRule, mcp []flatRule, tests map[string]kingdomTestCounts) string {
	var b strings.Builder

	// --- Section 1: Summary ---
	kingdoms := collectKingdoms(terminal)
	totalTests := 0
	for _, c := range tests {
		totalTests += c.TP + c.TN
	}

	b.WriteString("# AgentShield Coverage Report\n\n")
	fmt.Fprintf(&b,"*Auto-generated on %s by `go run ./cmd/coverage`*\n\n", time.Now().UTC().Format("2006-01-02"))
	b.WriteString("## Summary\n\n")
	b.WriteString("| Metric | Count |\n")
	b.WriteString("|--------|-------|\n")
	fmt.Fprintf(&b,"| Terminal rules | %d |\n", len(terminal))
	fmt.Fprintf(&b,"| MCP rules | %d |\n", len(mcp))
	fmt.Fprintf(&b,"| Total rules | %d |\n", len(terminal)+len(mcp))
	fmt.Fprintf(&b,"| Test cases (TP+TN) | %d |\n", totalTests)
	fmt.Fprintf(&b,"| Kingdoms covered | %d |\n", len(kingdoms))
	b.WriteString("\n")

	// --- Section 2: Runtime Rules by Kingdom ---
	b.WriteString("## Runtime Rules by Kingdom\n\n")
	byKingdom := groupByKingdom(terminal)
	sortedKingdoms := sortedKeys(byKingdom)
	for _, k := range sortedKingdoms {
		rules := byKingdom[k]
		fmt.Fprintf(&b,"### %s (%d rules)\n\n", k, len(rules))
		b.WriteString("| Rule ID | Decision | Match Type | Description |\n")
		b.WriteString("|---------|----------|------------|-------------|\n")
		for _, r := range rules {
			reason := strings.ReplaceAll(r.Reason, "|", "\\|")
			reason = strings.ReplaceAll(reason, "\n", " ")
			fmt.Fprintf(&b,"| `%s` | %s | %s | %s |\n", r.ID, r.Decision, r.MatchType, reason)
		}
		b.WriteString("\n")
	}

	// --- Section 3: MCP Rules ---
	b.WriteString("## MCP Rules\n\n")
	mcpByKingdom := groupByKingdom(mcp)
	sortedMCPKingdoms := sortedKeys(mcpByKingdom)
	for _, k := range sortedMCPKingdoms {
		rules := mcpByKingdom[k]
		fmt.Fprintf(&b,"### %s (%d rules)\n\n", k, len(rules))
		b.WriteString("| Rule ID | Decision | Match Type | Description |\n")
		b.WriteString("|---------|----------|------------|-------------|\n")
		for _, r := range rules {
			reason := strings.ReplaceAll(r.Reason, "|", "\\|")
			reason = strings.ReplaceAll(reason, "\n", " ")
			fmt.Fprintf(&b,"| `%s` | %s | %s | %s |\n", r.ID, r.Decision, r.MatchType, reason)
		}
		b.WriteString("\n")
	}

	// --- Section 4: Test Coverage ---
	b.WriteString("## Test Coverage\n\n")
	b.WriteString("| Kingdom | TP | TN | Total |\n")
	b.WriteString("|---------|----|----|-------|\n")
	sortedTestKingdoms := sortedKeys(tests)
	grandTP, grandTN := 0, 0
	for _, k := range sortedTestKingdoms {
		c := tests[k]
		fmt.Fprintf(&b,"| %s | %d | %d | %d |\n", k, c.TP, c.TN, c.TP+c.TN)
		grandTP += c.TP
		grandTN += c.TN
	}
	fmt.Fprintf(&b,"| **Total** | **%d** | **%d** | **%d** |\n", grandTP, grandTN, grandTP+grandTN)
	b.WriteString("\n")

	return b.String()
}

func collectKingdoms(rules []flatRule) []string {
	seen := make(map[string]bool)
	for _, r := range rules {
		seen[r.Kingdom] = true
	}
	return sortedKeys(seen)
}

func groupByKingdom(rules []flatRule) map[string][]flatRule {
	m := make(map[string][]flatRule)
	for _, r := range rules {
		m[r.Kingdom] = append(m[r.Kingdom], r)
	}
	return m
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
