// check-mcp-tool-symmetry flags MCP credential-exposure rules that are
// path-based (match a `path` argument) and list read-family tool names in
// `tool_name_any` but zero write-family tool names.
//
// # Why this is a distinct question from the gates that already exist
//
// check-taxonomy-refs asks whether a rule's taxonomy ref resolves.
// check-pack-taxonomy-fit asks whether the node's prose describes the rule.
// check-surface-agreement asks whether the shell and MCP implementations of
// one detection agree on a taxonomy node. None of them look INSIDE a single
// rule's tool_name_any list to ask whether read coverage and write coverage
// are symmetric.
//
// That gap was real: #3513/#3524 found 10 of 12
// `mcp-sec-block-<provider>-credentials-read` rules listed only
// read_file/cat_file/get_file_contents/open_file/view_file, so any
// write-capable MCP tool (write_file, create_file, str_replace_editor, ...)
// bypassed the BLOCK entirely — an agent could overwrite
// ~/.openai/credentials with an attacker-controlled value and nothing
// caught it. It existed silently until a manual mcp-eval probe compared two
// providers side by side. This gate is the fitness function so the defect
// class does not silently regenerate the next time a provider-credential
// rule is added.
//
// # What it checks
//
// For every MCP rule under packs/*/mcp/*.yaml whose taxonomy starts with
// "credential-exposure/" and whose match predicate is path-based
// (argument_patterns["path"] or argument_patterns_any["path"] is set) and
// whose match sets tool_name_any: does that list contain at least one
// read-family tool name and zero write-family tool names?
//
// # Scope, stated honestly
//
// A flag here is NOT automatically a bug. Some credential-exposure rules are
// deliberately read-only — e.g. a rule guarding a read-only audit log where
// there is no realistic write threat. That is a human call per rule, not
// something this gate can decide (the issue that requested it, #3525, says
// so explicitly). So this is REPORT-gated-by-baseline, mirroring the tier-2
// pattern in check-taxonomy-refs.sh and the baseline pattern in
// check-surface-agreement: a NEW unbaselined finding fails CI; an existing
// baselined finding is a recorded, reviewed decision that "this one really
// is read-only, on purpose." Clearing a baseline line means broadening
// tool_name_any, exactly as #3524 did.
//
// It also only looks at tool_name_any — rules that gate on tool_name_regex
// (e.g. the ".*" structural fallback) or a bare tool_name are a different
// mechanism and out of scope; and it only looks at credential-exposure/*,
// since that is the taxonomy kingdom where write access is at least as
// dangerous as read (overwriting a credential with an attacker-controlled
// value, or redirecting an endpoint).
//
// Deliberately reads packs/ and nothing else — no taxonomy tree, so it runs
// in the ordinary Test job with no coupling to AI_risk_compliance
// (workspace CLAUDE.md, invariant 3).
//
// Usage:
//
//	go run ./cmd/check-mcp-tool-symmetry
//	go run ./cmd/check-mcp-tool-symmetry -write-baseline
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"gopkg.in/yaml.v3"
)

// readFamily / writeFamily mirror the tool-name families documented in
// CLAUDE.md → "MCP rule development guide". Kept as a local, explicit list
// rather than importing one from elsewhere — CLAUDE.md is the source of
// truth for what counts as a family member, and any future family growth
// should update both in the same PR.
var (
	readFamily = map[string]bool{
		"read_file":         true,
		"cat_file":          true,
		"get_file_contents": true,
		"open_file":         true,
		"view_file":         true,
	}
	writeFamily = map[string]bool{
		"write_file":                  true,
		"create_file":                 true,
		"edit_file":                   true,
		"save_file":                   true,
		"update_file":                 true,
		"append_file":                 true,
		"str_replace_editor":          true,
		"str_replace_based_edit_tool": true,
		"write_to_file":               true,
	}
)

type finding struct {
	Rule string
	File string
}

func (f finding) key() string { return f.Rule }

// isPathBased reports whether the rule's match predicate constrains a `path`
// argument via glob (argument_patterns or argument_patterns_any). Rules that
// match on other argument keys (e.g. `url`, `content`) or on tool name alone
// are out of scope: a read/write asymmetry only matters when the SAME path
// is reachable through both a read tool and a write tool.
func isPathBased(m mcp.MCPMatch) bool {
	if _, ok := m.ArgumentPatterns["path"]; ok {
		return true
	}
	if _, ok := m.ArgumentPatternsAny["path"]; ok {
		return true
	}
	return false
}

func hasFamily(tools []string, family map[string]bool) bool {
	for _, t := range tools {
		if family[t] {
			return true
		}
	}
	return false
}

// scanPacks walks dirs for *.yaml files (skipping disabled `_`-prefixed
// packs) and returns every flagged rule, plus the total number of
// credential-exposure/*, path-based rules examined — the denominator, so a
// scan that silently finds nothing cannot be mistaken for a clean corpus.
func scanPacks(dirs []string) (findings []finding, examined int, err error) {
	for _, dir := range dirs {
		walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			ext := filepath.Ext(path)
			if ext != ".yaml" && ext != ".yml" {
				return nil
			}
			if strings.HasPrefix(filepath.Base(path), "_") {
				return nil // disabled pack
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			var pack mcp.MCPPack
			if unmarshalErr := yaml.Unmarshal(data, &pack); unmarshalErr != nil {
				return fmt.Errorf("parse %s: %w", path, unmarshalErr)
			}
			base := filepath.Base(path)
			for _, rule := range pack.Rules {
				if !strings.HasPrefix(rule.Taxonomy, "credential-exposure/") {
					continue
				}
				if !isPathBased(rule.Match) {
					continue
				}
				if len(rule.Match.ToolNameAny) == 0 {
					continue
				}
				examined++
				if hasFamily(rule.Match.ToolNameAny, readFamily) && !hasFamily(rule.Match.ToolNameAny, writeFamily) {
					findings = append(findings, finding{Rule: rule.ID, File: base})
				}
			}
			return nil
		})
		if walkErr != nil {
			return nil, 0, walkErr
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Rule < findings[j].Rule })
	return findings, examined, nil
}

func loadBaseline(path string) (map[string]bool, error) {
	out := map[string]bool{}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line != "" {
			out[line] = true
		}
	}
	return out, nil
}

const baselineHeader = `# baseline.txt — MCP credential-exposure rules that are path-based, list a
# read-family tool_name_any entry, and list zero write-family entries.
#
# Read by cmd/check-mcp-tool-symmetry. A line here is a rule someone
# reviewed and judged genuinely read-only-by-design (no realistic write
# threat) — see that package's doc comment for what this gate checks and
# why it cannot make that call itself. Any rule NOT listed here is new and
# fails CI.
#
# Format: <rule id>. One rule per line. Comments after '#'.
#
# Adding a NEW line requires the same review #3525 asked for: read the rule,
# decide the write path is not a realistic threat, and say why in the PR
# description (not on this line — -write-baseline discards comments here on
# rewrite). The default fix is to broaden tool_name_any to the write family
# (see #3524), NOT to baseline the finding.
#
# Bootstrap: go run ./cmd/check-mcp-tool-symmetry -write-baseline
#
`

func main() {
	packsFlag := flag.String("packs", "packs/community/mcp,packs/premium/mcp", "Comma-separated MCP pack directories")
	baselinePath := flag.String("baseline", "cmd/check-mcp-tool-symmetry/baseline.txt", "Baseline of reviewed, accepted read-only rules")
	writeBaseline := flag.Bool("write-baseline", false, "Rewrite the baseline from the current corpus")
	verbose := flag.Bool("v", false, "Print a summary even when clean")
	flag.Parse()

	var dirs []string
	for _, d := range strings.Split(*packsFlag, ",") {
		if d = strings.TrimSpace(d); d != "" {
			dirs = append(dirs, d)
		}
	}

	findings, examined, err := scanPacks(dirs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan packs:", err)
		os.Exit(2)
	}

	// A gate that cannot fail loudly is worse than no gate (#3130). Assert a
	// floor on the denominator: "0 findings" from a scan that examined 0
	// rules means the scan is broken (wrong dir, renamed field), not that
	// the corpus is clean.
	if examined == 0 {
		fmt.Fprintf(os.Stderr, "FAIL: examined 0 credential-exposure/* path-based MCP rules under %s.\n", strings.Join(dirs, ", "))
		fmt.Fprintln(os.Stderr, "      Expected dozens. Either this ran outside the repo root, the pack")
		fmt.Fprintln(os.Stderr, "      dirs moved, or the taxonomy/argument_patterns shape changed.")
		os.Exit(2)
	}

	if *writeBaseline {
		var sb strings.Builder
		sb.WriteString(baselineHeader)
		for _, f := range findings {
			fmt.Fprintf(&sb, "%s\n", f.key())
		}
		if err := os.WriteFile(*baselinePath, []byte(sb.String()), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write baseline:", err)
			os.Exit(2)
		}
		fmt.Printf("wrote %d finding(s) to %s\n", len(findings), *baselinePath)
		return
	}

	baseline, err := loadBaseline(*baselinePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read baseline:", err)
		os.Exit(2)
	}

	var fresh []finding
	seen := map[string]bool{}
	for _, f := range findings {
		seen[f.key()] = true
		if !baseline[f.key()] {
			fresh = append(fresh, f)
		}
	}
	var stale []string
	for k := range baseline {
		if !seen[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)

	for _, f := range fresh {
		fmt.Printf("ASYMMETRIC  %s  [%s]\n", f.Rule, f.File)
		fmt.Println("    tool_name_any has a read-family tool and zero write-family tools,")
		fmt.Println("    but the rule is credential-exposure/* and path-based. Either broaden")
		fmt.Println("    tool_name_any to the write family (see #3524), or — if the write path")
		fmt.Println("    is genuinely not a threat here — add the rule id to the baseline with")
		fmt.Println("    a reviewed reason in the PR description.")
		fmt.Println()
	}
	for _, k := range stale {
		fmt.Printf("STALE  %s\n", k)
		fmt.Println("    No longer flagged (tool_name_any was broadened, or the rule was renamed/removed).")
		fmt.Println("    Delete this baseline line.")
		fmt.Println()
	}

	if len(fresh) > 0 || len(stale) > 0 {
		fmt.Fprintf(os.Stderr, "FAIL: %d new asymmetric rule(s), %d stale baseline entr(y/ies). %d rule(s) examined.\n",
			len(fresh), len(stale), examined)
		os.Exit(1)
	}

	if *verbose || len(baseline) > 0 {
		fmt.Printf("OK: %d rule(s) examined, %d baselined, 0 new, 0 stale\n", examined, len(baseline))
	} else {
		fmt.Printf("OK: %d rule(s) examined, all read/write-symmetric\n", examined)
	}
}
