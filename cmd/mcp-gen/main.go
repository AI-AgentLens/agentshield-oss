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
//	go run ./cmd/mcp-gen
package main

import (
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
	// Resolve project root from the binary location.
	root := findProjectRoot()

	packsDir := filepath.Join(root, "packs")
	mcpPacksDir := filepath.Join(root, "packs", "community", "mcp")
	scenariosDir := filepath.Join(root, "internal", "mcp", "scenarios")

	// Step 1: Load shell packs.
	fmt.Println("Loading shell rule packs...")
	packs, err := LoadAllShellPacks(packsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading shell packs: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Loaded %d shell packs\n", len(packs))

	totalRules := 0
	for _, p := range packs {
		totalRules += len(p.Rules)
	}
	fmt.Printf("  Total shell rules: %d\n", totalRules)

	// Step 2: Classify convertible rules.
	fmt.Println("Classifying convertible rules...")
	candidates := ClassifyRules(packs)
	fmt.Printf("  Found %d raw candidates\n", len(candidates))

	// Step 3: Load existing MCP rules for dedup.
	fmt.Println("Loading existing MCP rules for dedup...")
	existingIDs, existingPatterns, err := LoadExistingMCPRules(mcpPacksDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not load existing MCP rules: %v\n", err)
	}
	fmt.Printf("  Existing MCP rule IDs: %d\n", len(existingIDs))
	fmt.Printf("  Existing path patterns: %d\n", len(existingPatterns))

	// Step 4: Deduplicate.
	candidates = DeduplicateCandidates(candidates, existingIDs, existingPatterns)
	fmt.Printf("  After dedup: %d net new candidates\n", len(candidates))

	if len(candidates) == 0 {
		fmt.Println("No new rules to generate.")
		return
	}

	// Step 5: Emit artifacts.
	mcpOutPath := filepath.Join(mcpPacksDir, "mcp-generated.yaml")
	fmt.Printf("Emitting MCP pack to %s...\n", mcpOutPath)
	if err := EmitMCPPack(candidates, mcpOutPath); err != nil {
		fmt.Fprintf(os.Stderr, "error writing MCP pack: %v\n", err)
		os.Exit(1)
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
