// Package packs exposes the built-in AgentShield policy packs as an embedded
// filesystem so they can be distributed inside the binary without duplicating
// the YAML content as Go string literals.
//
// Community MCP packs are always embedded. Premium MCP packs are provided by
// packs_premium.go (excluded from the open-source build).
package packs

import (
	"embed"
	"io/fs"
)

// communityMCP contains the community MCP packs.
//
//go:embed community/mcp/*.yaml
var communityMCP embed.FS

// premiumMCPFiles is populated by packs_premium.go in the full build.
// In the open-source build, this remains nil (no premium packs).
var premiumMCPFiles map[string][]byte

// MCPFiles returns a map of filename → YAML bytes for all MCP packs
// (community + premium if available). Keys are bare filenames.
func MCPFiles() map[string][]byte {
	files := make(map[string][]byte)

	// Load community packs
	entries, err := fs.ReadDir(communityMCP, "community/mcp")
	if err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			data, err := communityMCP.ReadFile("community/mcp/" + e.Name())
			if err != nil {
				continue
			}
			files[e.Name()] = data
		}
	}

	// Merge premium packs (if available)
	for name, data := range premiumMCPFiles {
		files[name] = data
	}

	return files
}
