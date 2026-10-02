// Command coverage generates COVERAGE.md by parsing pack YAML files and test data.
//
// The Summary totals come from internal/rulecount — the one rule-count
// definition — and the per-kingdom catalog below them is reconciled against
// it before anything is written: if the catalog lists a different number of
// YAML rules than the count, the tool fails instead of publishing two numbers.
// MCP blocked_tools and the Go-implemented roots intercepts still appear in
// the catalog (they are enforcement), but they are listed as what they are and
// are not counted as rules.
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

	"github.com/AI-AgentLens/agentshield/internal/rulecount"
	"gopkg.in/yaml.v3"
)

// terminalRule mirrors the subset of policy.Rule we need for the report.
type terminalRule struct {
	ID         string  `yaml:"id"`
	Taxonomy   string  `yaml:"taxonomy,omitempty"`
	Match      match   `yaml:"match"`
	Decision   string  `yaml:"decision"`
	Confidence float64 `yaml:"confidence,omitempty"`
	Reason     string  `yaml:"reason"`
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
	Name            string    `yaml:"name"`
	BlockedTools    []string  `yaml:"blocked_tools,omitempty"`
	Rules           []mcpRule `yaml:"rules,omitempty"`
	StructuralRules []mcpRule `yaml:"structural_rules,omitempty"`
	ValueLimits     []mcpRule `yaml:"value_limits,omitempty"`
	ResourceRules   []mcpRule `yaml:"resource_rules,omitempty"`
	SemanticRules   []mcpRule `yaml:"semantic_rules,omitempty"`
}

// Catalog match types that are enforcement but NOT rules under the
// rulecount definition. They are reported on their own Summary rows.
const (
	matchBlockedTool = "blocked_tool"
	matchGoIntercept = "go-intercept"
)

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

	// Parse terminal packs (community + premium)
	var terminalRules []flatRule
	terminalRules = append(terminalRules, parseTerminalPacks(filepath.Join(root, "packs", "community"))...)
	terminalRules = append(terminalRules, parseTerminalPacks(filepath.Join(root, "packs", "premium"))...)

	// Parse MCP packs (community + premium)
	var mcpRules []flatRule
	mcpRules = append(mcpRules, parseMCPPacks(filepath.Join(root, "packs", "community", "mcp"))...)
	mcpRules = append(mcpRules, parseMCPPacks(filepath.Join(root, "packs", "premium", "mcp"))...)
	mcpRules = append(mcpRules, goMCPIntercepts()...)

	// Count test cases by kingdom
	testCounts := countTestCases(filepath.Join(root, "internal", "analyzer", "testdata"))

	// The Summary numbers. The catalog above must agree with them or the
	// report would carry two answers to "how many rules".
	counts, err := rulecount.Count(filepath.Join(root, "packs"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error counting rules: %v\n", err)
		os.Exit(1)
	}
	if err := reconcile(terminalRules, mcpRules, counts); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Generate report
	report := generateReport(terminalRules, mcpRules, testCounts, counts)

	outPath := filepath.Join(root, "COVERAGE.md")
	if err := os.WriteFile(outPath, []byte(report), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing COVERAGE.md: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Generated %s (%d terminal rules, %d MCP rules, %d total, %d unique ids)\n",
		outPath, counts.Counts.Shell.Total, counts.Counts.MCP.Total, counts.Counts.Total, counts.Counts.UniqueIDs)
}

// reconcile checks that the catalog's YAML-rule rows equal the rulecount
// totals per surface. The catalog is parsed by a struct with named sections;
// rulecount reads every id-bearing section generically. If the struct falls
// behind (as it did for semantic_rules until 2026-09-28) the two disagree
// and the report must not be written.
func reconcile(terminal, mcp []flatRule, counts *rulecount.Report) error {
	if got, want := len(terminal), counts.Counts.Shell.Total; got != want {
		return fmt.Errorf("catalog lists %d terminal rules but rulecount says %d — a pack section the catalog struct does not parse?", got, want)
	}
	if got, want := countYAMLRules(mcp), counts.Counts.MCP.Total; got != want {
		return fmt.Errorf("catalog lists %d MCP YAML rules but rulecount says %d — a pack section the catalog struct does not parse?", got, want)
	}
	return nil
}

// countYAMLRules counts catalog rows that are rules under the definition,
// i.e. excludes blocked tools and Go intercepts.
func countYAMLRules(rules []flatRule) int {
	n := 0
	for _, r := range rules {
		if r.MatchType != matchBlockedTool && r.MatchType != matchGoIntercept {
			n++
		}
	}
	return n
}

// kingdomHeading counts rules under the definition and names the rows that
// are enforcement but not rules, so a section heading can never disagree with
// the Summary the way "(N rules)" over len(rows) did (2074 vs 2064 on
// 2026-09-28).
func kingdomHeading(kingdom string, rules []flatRule) string {
	n := countYAMLRules(rules)
	extra := len(rules) - n
	if extra == 0 {
		return fmt.Sprintf("%s (%d rules)", kingdom, n)
	}
	return fmt.Sprintf("%s (%d rules + %d enforcement entries — blocked tools / Go intercepts, not counted as rules)", kingdom, n, extra)
}

func countMatchType(rules []flatRule, matchType string) int {
	n := 0
	for _, r := range rules {
		if r.MatchType == matchType {
			n++
		}
	}
	return n
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
				MatchType: matchBlockedTool,
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

		for _, r := range pack.StructuralRules {
			rules = append(rules, flatRule{
				ID:        r.ID,
				Decision:  r.Decision,
				MatchType: "structural",
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

		for _, r := range pack.SemanticRules {
			rules = append(rules, flatRule{
				ID:        r.ID,
				Decision:  r.Decision,
				MatchType: "semantic",
				Reason:    r.Reason,
				Kingdom:   extractKingdom(r.Taxonomy),
				Pack:      pack.Name,
			})
		}
	}

	return rules
}

// goMCPIntercepts are the Go-implemented MCP intercepts (not in YAML packs —
// hardcoded in internal/mcp/policy.go). Appended ONCE: the previous report
// appended them per pack directory and listed each twice.
func goMCPIntercepts() []flatRule {
	return []flatRule{
		{
			ID:        "mcp-roots-block-sensitive-cred-dir",
			Decision:  "BLOCK",
			MatchType: matchGoIntercept,
			Reason:    "Blocks roots/list responses that expose credential directories (MITRE T1078, T1083, OWASP LLM08).",
			Kingdom:   "unauthorized-execution",
			Pack:      "mcp-roots-guard (Go)",
		},
		{
			ID:        "mcp-roots-audit-broad-dir",
			Decision:  "AUDIT",
			MatchType: matchGoIntercept,
			Reason:    "Audits roots/list responses with broad directories that encompass credential paths (OWASP LLM08).",
			Kingdom:   "unauthorized-execution",
			Pack:      "mcp-roots-guard (Go)",
		},
	}
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
		"destructive_ops_cases.go":        "destructive-ops",
		"credential_exposure_cases.go":    "credential-exposure",
		"data_exfiltration_cases.go":      "data-exfiltration",
		"governance_risk_cases.go":        "governance-risk",
		"persistence_evasion_cases.go":    "persistence-evasion",
		"privilege_escalation_cases.go":   "privilege-escalation",
		"reconnaissance_cases.go":         "reconnaissance",
		"supply_chain_cases.go":           "supply-chain",
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

func generateReport(terminal []flatRule, mcp []flatRule, tests map[string]kingdomTestCounts, counts *rulecount.Report) string {
	var b strings.Builder

	// --- Section 1: Summary ---
	kingdoms := collectKingdoms(terminal)
	totalTests := 0
	for _, c := range tests {
		totalTests += c.TP + c.TN
	}

	b.WriteString("# AgentShield Coverage Report\n\n")
	fmt.Fprintf(&b, "*Auto-generated on %s by `go run ./cmd/coverage`*\n\n", time.Now().UTC().Format("2006-01-02"))
	c := counts.Counts
	b.WriteString("## Summary\n\n")
	b.WriteString("| Metric | Count |\n")
	b.WriteString("|--------|-------|\n")
	fmt.Fprintf(&b, "| Terminal rules (community %d + premium %d) | %d |\n", c.Shell.Community, c.Shell.Premium, c.Shell.Total)
	fmt.Fprintf(&b, "| MCP rules (community %d + premium %d) | %d |\n", c.MCP.Community, c.MCP.Premium, c.MCP.Total)
	fmt.Fprintf(&b, "| Total rules | %d |\n", c.Total)
	fmt.Fprintf(&b, "| Unique rule ids | %d |\n", c.UniqueIDs)
	fmt.Fprintf(&b, "| Rule ids defined more than once | %d |\n", len(counts.Duplicates))
	fmt.Fprintf(&b, "| MCP blocked tools (enforcement, not rules) | %d |\n", countMatchType(mcp, matchBlockedTool))
	fmt.Fprintf(&b, "| Go-implemented MCP intercepts (enforcement, not rules) | %d |\n", countMatchType(mcp, matchGoIntercept))
	fmt.Fprintf(&b, "| Test cases (TP+TN) | %d |\n", totalTests)
	fmt.Fprintf(&b, "| Kingdoms covered | %d |\n", len(kingdoms))
	b.WriteString("\n")
	fmt.Fprintf(&b, "Rule count definition (`internal/rulecount`, also published as `counts` in the premium manifest): %s\n\n", c.Definition)

	// --- Section 2: Runtime Rules by Kingdom ---
	b.WriteString("## Runtime Rules by Kingdom\n\n")
	byKingdom := groupByKingdom(terminal)
	sortedKingdoms := sortedKeys(byKingdom)
	for _, k := range sortedKingdoms {
		rules := byKingdom[k]
		fmt.Fprintf(&b, "### %s\n\n", kingdomHeading(k, rules))
		b.WriteString("| Rule ID | Decision | Match Type | Description |\n")
		b.WriteString("|---------|----------|------------|-------------|\n")
		for _, r := range rules {
			reason := strings.ReplaceAll(r.Reason, "|", "\\|")
			reason = strings.ReplaceAll(reason, "\n", " ")
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", r.ID, r.Decision, r.MatchType, reason)
		}
		b.WriteString("\n")
	}

	// --- Section 3: MCP Rules ---
	b.WriteString("## MCP Rules\n\n")
	mcpByKingdom := groupByKingdom(mcp)
	sortedMCPKingdoms := sortedKeys(mcpByKingdom)
	for _, k := range sortedMCPKingdoms {
		rules := mcpByKingdom[k]
		fmt.Fprintf(&b, "### %s\n\n", kingdomHeading(k, rules))
		b.WriteString("| Rule ID | Decision | Match Type | Description |\n")
		b.WriteString("|---------|----------|------------|-------------|\n")
		for _, r := range rules {
			reason := strings.ReplaceAll(r.Reason, "|", "\\|")
			reason = strings.ReplaceAll(reason, "\n", " ")
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", r.ID, r.Decision, r.MatchType, reason)
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
		fmt.Fprintf(&b, "| %s | %d | %d | %d |\n", k, c.TP, c.TN, c.TP+c.TN)
		grandTP += c.TP
		grandTN += c.TN
	}
	fmt.Fprintf(&b, "| **Total** | **%d** | **%d** | **%d** |\n", grandTP, grandTN, grandTP+grandTN)
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
