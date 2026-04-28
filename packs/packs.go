// Package packs exposes the built-in AgentShield policy packs as an embedded
// filesystem so they can be distributed inside the binary without duplicating
// the YAML content as Go string literals.
//
// Community shell packs (terminal-safety.yaml, secrets-pii.yaml, ...) and
// community MCP packs (community/mcp/*.yaml) are always embedded. Premium MCP
// packs are provided by packs_premium.go (excluded from the open-source build).
package packs

import (
	"embed"
	"io/fs"
)

// communityShell contains the community shell-rule packs. These are top-level
// YAML files inside packs/community/ (e.g. terminal-safety.yaml, secrets-pii.yaml).
//
//go:embed community/*.yaml
var communityShell embed.FS

// communityMCP contains the community MCP packs.
//
//go:embed community/mcp/*.yaml
var communityMCP embed.FS

// premiumMCPFiles is populated by packs_premium.go in the full build.
// In the open-source build, this remains nil (no premium packs).
var premiumMCPFiles map[string][]byte

// ShellFiles returns a map of filename → YAML bytes for all community shell
// packs embedded in the binary. Keys are bare filenames (e.g. "terminal-safety.yaml").
//
// Having shell packs embedded means the engine has working rules even when
// ~/.agentshield/packs/ is empty — critical for fresh installs where the cask
// postflight or release tarball hasn't populated the user's packs directory
// (notably on Linuxbrew, where cask postflight is unreliable).
func ShellFiles() map[string][]byte {
	files := make(map[string][]byte)

	entries, err := fs.ReadDir(communityShell, "community")
	if err != nil {
		return files
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := communityShell.ReadFile("community/" + e.Name())
		if err != nil {
			continue
		}
		files[e.Name()] = data
	}
	return files
}

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
