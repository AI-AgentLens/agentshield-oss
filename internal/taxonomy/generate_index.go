//go:build ignore

// This program generates compliance index markdown files from taxonomy entries.
// Usage: go run generate_index.go
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/security-researcher-ca/agentshield/internal/taxonomy"
)

func main() {
	rootDir := findProjectRoot()

	standardsDir := filepath.Join(rootDir, "compliance", "standards")
	taxonomyDir := filepath.Join(rootDir, "taxonomy")
	indexesDir := filepath.Join(rootDir, "compliance", "indexes")

	// Load standards
	standards, err := taxonomy.LoadStandards(standardsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading standards: %v\n", err)
		os.Exit(1)
	}

	// Load taxonomy
	cat, err := taxonomy.LoadCatalog(taxonomyDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading taxonomy: %v\n", err)
		os.Exit(1)
	}

	// Ensure indexes dir exists
	os.MkdirAll(indexesDir, 0755)

	// Generate index for each standard
	for _, std := range standards {
		idx := taxonomy.BuildComplianceIndex(std, cat.Entries)
		md := taxonomy.GenerateIndexMarkdown(idx, cat.ByID)

		outPath := filepath.Join(indexesDir, std.ID+".md")
		if err := os.WriteFile(outPath, []byte(md), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", outPath, err)
			os.Exit(1)
		}
		fmt.Printf("Generated %s (%d weakness mappings)\n", outPath, countMappings(idx))
	}
}

func countMappings(idx taxonomy.ComplianceIndex) int {
	total := 0
	for _, weaknesses := range idx.Mappings {
		total += len(weaknesses)
	}
	return total
}

func findProjectRoot() string {
	// Walk up from current dir to find go.mod
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			fmt.Fprintln(os.Stderr, "could not find project root (go.mod)")
			os.Exit(1)
		}
		dir = parent
	}
}
