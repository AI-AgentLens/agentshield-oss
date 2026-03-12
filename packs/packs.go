// Package packs exposes the built-in AgentShield policy packs as an embedded
// filesystem so they can be distributed inside the binary without duplicating
// the YAML content as Go string literals.
//
// Usage:
//
//	for name, data := range packs.MCPFiles() {
//	    // name is "mcp-safety.yaml", data is the YAML bytes
//	}
package packs

import (
	"embed"
	"io/fs"
)

// mcp is the embedded filesystem rooted at the packs/ directory,
// containing all mcp/*.yaml files.
//
//go:embed mcp/*.yaml
var mcp embed.FS

// MCPFiles returns a map of filename → YAML bytes for every file in packs/mcp/.
// The map keys are bare filenames (e.g. "mcp-safety.yaml"), not full paths.
func MCPFiles() map[string][]byte {
	files := make(map[string][]byte)
	entries, err := fs.ReadDir(mcp, "mcp")
	if err != nil {
		return files
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := mcp.ReadFile("mcp/" + e.Name())
		if err != nil {
			continue
		}
		files[e.Name()] = data
	}
	return files
}
