// Command mcp-gen converts shell security rules to MCP rules.
//
// It reads shell rule YAML packs, identifies rules whose threat model applies
// equally to MCP tool calls (file path access, URL access), deduplicates against
// existing MCP rules, and outputs:
//
//  1. packs/community/mcp/mcp-generated.yaml — new MCP rules
//  2. internal/mcp/scenarios/generated_scenarios.go — TP scenarios
//  3. packs/community/mcp/tn-pool.json — TN work queue for Baby Kai
//
// Usage:
//
//	go run ./cmd/mcp-gen              # generate
//	go run ./cmd/mcp-gen -dry-run     # discover + classify + dedup, write nothing
//	go run ./cmd/mcp-gen -widen-only  # only widen already-shipped rules' tool
//	                                  # coverage; emit no new rules/scenarios
//
// Two properties are load-bearing, and both exist because the tool's default
// output was quietly wrong once already:
//
//   - Shell-pack discovery is floor-checked (discovery.go): a scan that finds
//     no packs exits non-zero rather than printing "No new rules to generate."
//     (#3359)
//   - Emission into mcp-generated.yaml MERGES rather than overwrites
//     (emit.go): an id already shipped there stays shipped even if this run's
//     dedup no longer proposes it. Rule removal from that file is a human
//     editing the YAML, never a side effect of running the generator. (#3367)
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// ID ranges reserved for generator output. These were bumped to 2000+ during
// the issue #1174 split: prior to the split, the generator started at 173, but
// hand-curated scenarios in the 173-194 range had been interleaved into the
// same file. The split moved all existing scenarios into curated_scenarios.go
// under their original IDs. Starting at 2000 ensures that future generator
// runs cannot collide with any committed curated ID (max curated ID today is
// ~1120).
const (
	startTPID = 2000
	startTNID = 2000
)

func main() {
	dryRun := flag.Bool("dry-run", false,
		"Discover, classify and dedup, print the counts, and write no files")
	// -widen-only exists so a classifier fix can be delivered to rules that
	// are already shipped WITHOUT also landing whatever net-new candidates
	// have accumulated since the last full run. Those are separate decisions:
	// widening an existing rule's tool coverage is a correctness fix to a rule
	// already reviewed; emitting a brand-new BLOCK/AUDIT rule into a pack
	// every community user embeds is a product change that wants its own
	// review, TP/TN cases and TN-pool entry.
	widenOnly := flag.Bool("widen-only", false,
		"Only widen already-shipped generated rules' tool_name_any from the current "+
			"classification; emit no new rules, scenarios or TN-pool entries")
	flag.Parse()

	// Resolve project root from the binary location.
	root := findProjectRoot()

	mcpPacksDir := filepath.Join(root, "packs", "community", "mcp")
	scenariosDir := filepath.Join(root, "internal", "mcp", "scenarios")

	// Dedup must see every MCP rule that could already cover a candidate, not
	// just the community ones this tool emits into. packs/premium/mcp holds
	// hand-authored rules that frequently cover the same targets a shell-rule
	// conversion would re-derive — three confirmed instances in #3817, all
	// invisible to dedup before this list existed. Output emission (mcpOutPath
	// below) stays community-only; this is read-only input.
	existingMCPDirs := []string{mcpPacksDir, filepath.Join(root, "packs", "premium", "mcp")}

	// Step 1: Discover shell packs. A discovery that comes back empty is a
	// hard error, not an empty work queue — see discovery.go for why.
	fmt.Println("Discovering shell rule packs...")
	disc, err := DiscoverShellPacks(root, shellPackSources)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(disc.Summary())
	packs := disc.Packs

	// Step 2: Classify convertible rules. `classified` is kept as-is
	// alongside the deduped set: dedup drops every id already shipped in
	// mcp-generated.yaml, so it is the only view that still holds the
	// current classification of an ALREADY-shipped rule — which is what
	// EmitMCPPack needs to widen stale tool coverage (#3589).
	fmt.Println("Classifying convertible rules...")
	classified := ClassifyRules(packs)
	candidates := classified
	fmt.Printf("  Found %d raw candidates\n", len(candidates))

	// Step 3: Load existing MCP rules for dedup.
	fmt.Println("Loading existing MCP rules for dedup...")
	existingIDs, existingPatterns, err := LoadExistingMCPRulesFromDirs(existingMCPDirs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not load existing MCP rules: %v\n", err)
	}
	fmt.Printf("  Existing MCP rule IDs: %d\n", len(existingIDs))
	fmt.Printf("  Existing path patterns: %d\n", len(existingPatterns))

	existingPolicy, err := LoadExistingMCPPolicyFromDirs(existingMCPDirs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not load existing MCP policy for coverage dedup: %v\n", err)
	}
	coverage := NewCoverageChecker(existingPolicy)

	// Step 4: Deduplicate.
	candidates = DeduplicateCandidates(candidates, existingIDs, existingPatterns, coverage)
	fmt.Printf("  After dedup: %d net new candidates\n", len(candidates))

	if *dryRun {
		fmt.Println("\n-dry-run: no files written.")
		return
	}

	mcpOutPath := filepath.Join(mcpPacksDir, "mcp-generated.yaml")

	if *widenOnly {
		fmt.Printf("Widening shipped tool coverage in %s (no new rules)...\n", mcpOutPath)
		if err := EmitMCPPack(nil, classified, mcpOutPath); err != nil {
			fmt.Fprintf(os.Stderr, "error writing MCP pack: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("-widen-only: no new rules, scenarios or TN-pool entries written.")
		return
	}

	// Step 5: Emit artifacts. The pack write runs even when dedup found
	// nothing net-new, because it also carries the tool-coverage widening for
	// already-shipped rules — the only path by which a classifier fix reaches
	// a rule that is already in the file (#3589). Returning early on
	// "0 net new" is what made that fix undeliverable.
	fmt.Printf("Emitting MCP pack to %s...\n", mcpOutPath)
	if err := EmitMCPPack(candidates, classified, mcpOutPath); err != nil {
		fmt.Fprintf(os.Stderr, "error writing MCP pack: %v\n", err)
		os.Exit(1)
	}

	if len(candidates) == 0 {
		// Trustworthy only because discovery cleared its floor above.
		fmt.Println("No new rules to generate; shipped tool coverage refreshed.")
		return
	}

	scenarioOutPath := filepath.Join(scenariosDir, "generated_scenarios.go")
	fmt.Printf("Emitting TP scenarios to %s...\n", scenarioOutPath)
	if err := EmitScenarios(candidates, scenarioOutPath, startTPID, startTNID); err != nil {
		fmt.Fprintf(os.Stderr, "error writing scenarios: %v\n", err)
		os.Exit(1)
	}

	tnPoolPath := filepath.Join(mcpPacksDir, "tn-pool.json")
	fmt.Printf("Emitting TN pool to %s...\n", tnPoolPath)
	if err := EmitTNPool(candidates, tnPoolPath, startTPID); err != nil {
		fmt.Fprintf(os.Stderr, "error writing TN pool: %v\n", err)
		os.Exit(1)
	}

	// Summary.
	fmt.Println()
	fmt.Printf("=== Generation Complete ===\n")
	fmt.Printf("  New MCP rules:  %d\n", len(candidates))
	fmt.Printf("  TP scenarios:   %d (MCP-TP-%03d to MCP-TP-%03d)\n",
		len(candidates), startTPID, startTPID+len(candidates)-1)
	fmt.Printf("  TN pool items:  %d\n", len(candidates))
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  1. Review %s\n", mcpOutPath)
	fmt.Printf("  2. go test ./cmd/mcp-gen/...                    # unit tests\n")
	fmt.Printf("  3. go test ./internal/mcp/ -run TestMCPScenarios # full scenario test\n")
	fmt.Printf("  4. go test ./internal/mcp/ -run TestMCPScenarioIDsAreUnique\n")
}

// findProjectRoot walks up from cwd to find the project root (has go.mod).
func findProjectRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot determine working directory: %v\n", err)
		os.Exit(1)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Fallback: assume cwd is root.
			cwd, _ := os.Getwd()
			return cwd
		}
		dir = parent
	}
}
