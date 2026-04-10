// Command mcp-verify runs the MCP proxy self-test scenarios and outputs
// a Markdown report with accuracy metrics.
package main

import (
	"fmt"
	"os"

	"github.com/AI-AgentLens/agentshield/internal/mcp"
)

func main() {
	// Determine packs directory. When run from repo root, packs/community/mcp/
	// is the default. Allow override via environment variable.
	packsDir := os.Getenv("MCP_PACKS_DIR")
	if packsDir == "" {
		packsDir = "packs/community/mcp"
	}

	results := mcp.RunMCPSelfTest(packsDir)

	fmt.Println(results.FormatMarkdown())

	if results.FP > 0 || results.FN > 0 {
		os.Exit(1)
	}
}
