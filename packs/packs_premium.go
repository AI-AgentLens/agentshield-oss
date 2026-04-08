// packs_premium.go provides premium MCP packs for the full (non-OSS) build.
// This file is excluded from the open-source repository.
package packs

import (
	"embed"
	"io/fs"
)

//go:embed premium/mcp/*.yaml
var premiumMCP embed.FS

func init() {
	premiumMCPFiles = make(map[string][]byte)
	entries, err := fs.ReadDir(premiumMCP, "premium/mcp")
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := premiumMCP.ReadFile("premium/mcp/" + e.Name())
		if err != nil {
			continue
		}
		premiumMCPFiles[e.Name()] = data
	}
}
