// Package main implements a CI guardrail that enforces the project's
// "every policy pack rule must have at least one TP and one TN test"
// requirement, documented in CLAUDE.md → "Rule Test Coverage Requirement".
//
// Shield rules link to test cases via the `taxonomy:` field on the rule and
// the `TaxonomyRef:` field on the test struct (see internal/analyzer/testdata).
// This tool checks coverage at the taxonomy-ref level: every taxonomy ref
// used by ≥1 terminal pack rule must have ≥1 TP and ≥1 TN test case.
//
// Scope:
//   - Terminal pack rules: packs/community/*.yaml + packs/premium/*.yaml
//   - Test fixtures:       internal/analyzer/testdata/*.go (TestCase struct literals)
//
// MCP rules (packs/*/mcp/*.yaml) are intentionally NOT enforced here. MCP
// has its own test framework (internal/mcp/scenarios/) and is validated by
// `make mcp-verify` / TestMCPScenarios. Coverage there is tracked separately.
//
// A baseline file (cmd/check-rule-coverage/baseline.txt) lists currently-known
// gaps that pre-date the guardrail. Each line is one taxonomy ref. Anything
// listed there is allowed to be uncovered. New gaps fail CI; cleanup PRs
// chip the baseline down toward zero.
//
// This tool also enforces a second, narrower guardrail (agentshield-oss#3118):
// every BLOCK-decision terminal rule must carry a `taxonomy:` field, since an
// untagged BLOCK cannot be attested to a compliance control. Deliberate
// exceptions are allowlisted by rule ID in
// cmd/check-rule-coverage/untaxed-block-baseline.txt.
//
// Exits 0 when:
//   - every non-baselined taxonomy has TP+TN, AND
//   - no orphan TaxonomyRefs (test refs to a deleted/renamed taxonomy), AND
//   - no non-allowlisted BLOCK rule is missing a taxonomy ref.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type packFile struct {
	Name  string `yaml:"name"`
	Rules []struct {
		ID       string `yaml:"id"`
		Taxonomy string `yaml:"taxonomy"`
		Decision string `yaml:"decision"`
	} `yaml:"rules"`
}

// untaxedBlockRule records a BLOCK rule with no taxonomy field, for the
// untaxed-BLOCK-rule guardrail.
type untaxedBlockRule struct {
	ID   string
	Pack string
}

// Capture TaxonomyRef + Classification pairs from Go struct literals, in
// either field order. Group 1/4 = TaxonomyRef, group 2/3 = Classification.
var testCaseRE = regexp.MustCompile(
	`TaxonomyRef:\s*"([^"]+)"[\s\S]*?Classification:\s*"([^"]+)"` +
		`|Classification:\s*"([^"]+)"[\s\S]*?TaxonomyRef:\s*"([^"]+)"`,
)

// orphanScopeRE matches taxonomies not in pack rules but tracked elsewhere
// (e.g., MCP-only taxonomies referenced by terminal documentation FN tests,
// or guardian-detector taxonomies that don't have pack rules). Loaded from
// the baseline file so the tool stays declarative.

func main() {
	rulesDirs := flag.String("rules", "packs/community,packs/premium",
		"Comma-separated rule pack directories (terminal only — exclude mcp/)")
	testsDir := flag.String("tests", "internal/analyzer/testdata",
		"Directory containing TestCase Go struct literals")
	baselineFile := flag.String("baseline", "cmd/check-rule-coverage/baseline.txt",
		"Allowlist of known-uncovered taxonomy refs (one per line, # comments)")
	untaxedBlockBaselineFile := flag.String("untaxed-block-baseline", "cmd/check-rule-coverage/untaxed-block-baseline.txt",
		"Allowlist of BLOCK rule IDs deliberately shipped without a taxonomy field (one per line, # comments)")
	verbose := flag.Bool("v", false, "Print summary even when coverage is complete")
	flag.Parse()

	rules, untaxedBlockRules, err := collectRules(strings.Split(*rulesDirs, ","))
	if err != nil {
		fmt.Fprintln(os.Stderr, "rule scan:", err)
		os.Exit(2)
	}
	tp, tn, err := collectTestRefs(*testsDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "test scan:", err)
		os.Exit(2)
	}
	baseline, err := loadBaseline(*baselineFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "baseline load:", err)
		os.Exit(2)
	}
	untaxedBlockBaseline, err := loadBaseline(*untaxedBlockBaselineFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "untaxed-block baseline load:", err)
		os.Exit(2)
	}

	var unallowedUntaxedBlocks []untaxedBlockRule
	for _, r := range untaxedBlockRules {
		if !untaxedBlockBaseline[r.ID] {
			unallowedUntaxedBlocks = append(unallowedUntaxedBlocks, r)
		}
	}
	sort.Slice(unallowedUntaxedBlocks, func(i, j int) bool {
		return unallowedUntaxedBlocks[i].ID < unallowedUntaxedBlocks[j].ID
	})

	// Coverage check — per-taxonomy
	missingTP, missingTN := []string{}, []string{}
	for tax := range rules {
		if baseline[tax] {
			continue
		}
		if !tp[tax] {
			missingTP = append(missingTP, tax)
		}
		if !tn[tax] {
			missingTN = append(missingTN, tax)
		}
	}
	sort.Strings(missingTP)
	sort.Strings(missingTN)

	// Orphan check — test refs that don't exist in any pack rule
	orphans := []string{}
	for tax := range tp {
		if _, ok := rules[tax]; !ok && !baseline[tax] {
			orphans = append(orphans, tax)
		}
	}
	for tax := range tn {
		if _, ok := rules[tax]; !ok && !baseline[tax] && !contains(orphans, tax) {
			orphans = append(orphans, tax)
		}
	}
	sort.Strings(orphans)

	gaps := len(missingTP) + len(missingTN) + len(orphans) + len(unallowedUntaxedBlocks)
	if gaps == 0 {
		if *verbose {
			fmt.Printf("✓ Rule coverage OK: %d terminal taxonomy refs (TP+TN). %d baselined. Every BLOCK rule carries a taxonomy ref (%d exempted).\n",
				len(rules), len(baseline), len(untaxedBlockBaseline))
		}
		return
	}

	fmt.Println("Rule coverage check FAILED.")
	fmt.Printf("Terminal taxonomies: %d  |  Missing TP: %d  |  Missing TN: %d  |  Orphan: %d  |  Baselined: %d  |  Untaxed BLOCK rules: %d\n\n",
		len(rules), len(missingTP), len(missingTN), len(orphans), len(baseline), len(unallowedUntaxedBlocks))

	if len(missingTP) > 0 {
		fmt.Println("Taxonomies missing TP test case:")
		for _, t := range missingTP {
			ids := rules[t]
			fmt.Printf("  - %s   [rules: %s]\n", t, joinShort(ids, 3))
		}
		fmt.Println()
	}
	if len(missingTN) > 0 {
		fmt.Println("Taxonomies missing TN test case:")
		for _, t := range missingTN {
			ids := rules[t]
			fmt.Printf("  - %s   [rules: %s]\n", t, joinShort(ids, 3))
		}
		fmt.Println()
	}
	if len(orphans) > 0 {
		fmt.Println("Orphan TaxonomyRefs (in tests but not in any terminal pack rule —")
		fmt.Println("either rename the test ref to the current taxonomy, remove the test,")
		fmt.Println("or add to baseline.txt with a one-line reason):")
		for _, t := range orphans {
			fmt.Printf("  - %s\n", t)
		}
		fmt.Println()
	}
	if len(unallowedUntaxedBlocks) > 0 {
		fmt.Println("BLOCK rules with no taxonomy field (unattestable — see agentshield-oss#3118):")
		fmt.Println("either add a `taxonomy:` ref, or add the rule ID to")
		fmt.Println("untaxed-block-baseline.txt with a one-line reason (requires Gary + Kai sign-off):")
		for _, r := range unallowedUntaxedBlocks {
			fmt.Printf("  - %s   [%s]\n", r.ID, r.Pack)
		}
		fmt.Println()
	}
	if len(missingTP)+len(missingTN)+len(orphans) > 0 {
		fmt.Println("Fix instructions (missing TP/TN, orphans):")
		fmt.Println("  1. Add a TestCase{Classification: \"TP\", TaxonomyRef: \"<taxonomy>\", ...}")
		fmt.Println("     under internal/analyzer/testdata/<kingdom>_cases.go")
		fmt.Println("  2. Same for TN. Use IDs like TP-<CATEGORY>-NNN / TN-<CATEGORY>-NNN.")
		fmt.Println("  3. Run `go test -v -run TestAccuracy ./internal/analyzer/` to verify.")
		fmt.Println("  4. See CLAUDE.md → \"Rule Test Coverage Requirement\".")
	}
	if len(unallowedUntaxedBlocks) > 0 {
		fmt.Println("Fix instructions (untaxed BLOCK rules):")
		fmt.Println("  1. Preferred: add the most specific `taxonomy:` ref that genuinely")
		fmt.Println("     covers what the rule stops, then give that ref a TP + TN.")
		fmt.Println("  2. If the rule fires across several kingdoms by design, split it into")
		fmt.Println("     per-intent rules that each carry their own ref.")
		fmt.Println("  3. Only if neither works: add the ID to untaxed-block-baseline.txt with")
		fmt.Println("     the reasoning. Never attach a vague catch-all node to clear this gate —")
		fmt.Println("     an acknowledged gap beats a mapping that fails the auditor test.")
	}
	os.Exit(1)
}

func collectRules(dirs []string) (map[string][]string, []untaxedBlockRule, error) {
	out := map[string][]string{} // taxonomy -> []rule_id (terminal-only)
	var untaxedBlocks []untaxedBlockRule
	for _, dir := range dirs {
		dir = strings.TrimSpace(dir)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, nil, fmt.Errorf("read %s: %w", dir, err)
		}
		for _, e := range entries {
			// Stay terminal-only: skip subdirectories (the mcp/ subdirs).
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasPrefix(name, "_") {
				continue // disabled legacy packs
			}
			if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
				continue
			}
			path := filepath.Join(dir, name)
			b, err := os.ReadFile(path)
			if err != nil {
				return nil, nil, err
			}
			var pf packFile
			if err := yaml.Unmarshal(b, &pf); err != nil {
				// Skip malformed packs — Shield's loader will surface those errors.
				continue
			}
			for _, r := range pf.Rules {
				if r.ID == "" {
					continue
				}
				if r.Taxonomy != "" {
					out[r.Taxonomy] = append(out[r.Taxonomy], r.ID)
					continue
				}
				// EqualFold, not ==: the guardrail must not be bypassable by
				// writing `decision: block` in a new pack.
				if strings.EqualFold(strings.TrimSpace(r.Decision), "BLOCK") {
					untaxedBlocks = append(untaxedBlocks, untaxedBlockRule{ID: r.ID, Pack: path})
				}
			}
		}
	}
	return out, untaxedBlocks, nil
}

func collectTestRefs(dir string) (map[string]bool, map[string]bool, error) {
	tp, tn := map[string]bool{}, map[string]bool{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range testCaseRE.FindAllSubmatch(b, -1) {
			tax := string(m[1])
			cls := string(m[2])
			if tax == "" {
				tax = string(m[4])
				cls = string(m[3])
			}
			if tax == "" {
				continue
			}
			switch cls {
			case "TP":
				tp[tax] = true
			case "TN":
				tn[tax] = true
				// FP and FN are intentionally not counted as coverage —
				// FP is a regression marker, FN is a known-gap marker.
			}
		}
		return nil
	})
	return tp, tn, err
}

func loadBaseline(path string) (map[string]bool, error) {
	out := map[string]bool{}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil // baseline is optional
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Allow trailing inline comments: "tax/ref  # reason"
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		out[line] = true
	}
	return out, sc.Err()
}

func joinShort(ids []string, max int) string {
	sort.Strings(ids)
	if len(ids) <= max {
		return strings.Join(ids, ", ")
	}
	return strings.Join(ids[:max], ", ") + fmt.Sprintf(", +%d more", len(ids)-max)
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}
