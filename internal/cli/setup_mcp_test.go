package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMatchesTarget(t *testing.T) {
	cases := []struct {
		locName string
		target  string
		want    bool
	}{
		{"Claude Desktop", "all", true},
		{"Claude Desktop", "claude-desktop", true},
		{"Claude Desktop", "claude", true},
		{"Claude Desktop", "cursor", false},
		{"Cursor", "cursor", true},
		{"Cursor", "claude-desktop", false},
		{"Cursor", "all", true},
		{"Cursor (project)", "cursor", true},
		{"Cursor (project)", "claude-desktop", false},
	}
	for _, c := range cases {
		got := matchesTarget(mcpConfigLocation{Name: c.locName}, c.target)
		if got != c.want {
			t.Errorf("matchesTarget(%q, %q) = %v, want %v", c.locName, c.target, got, c.want)
		}
	}
}

// TestWrapMCPConfig_WritesAbsolutePath verifies the fix for the Claude Desktop
// disruption: wrapped servers must use the absolute agentshield path (GUI apps
// launch with a minimal PATH and cannot resolve the bare name), and the wrap
// must round-trip cleanly back to the original via unwrap.
func TestWrapMCPConfig_WritesAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "claude_desktop_config.json")
	original := `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}}}`
	if err := os.WriteFile(cfgPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	loc := mcpConfigLocation{Name: "Claude Desktop", Path: cfgPath}
	const binPath = "/opt/homebrew/bin/agentshield"

	if err := wrapMCPConfig(loc, binPath); err != nil {
		t.Fatalf("wrapMCPConfig: %v", err)
	}

	fs := readServer(t, cfgPath, "fs")
	if got := fs["command"]; got != binPath {
		t.Errorf("command = %v, want absolute path %q", got, binPath)
	}
	args, ok := fs["args"].([]interface{})
	if !ok || len(args) < 3 {
		t.Fatalf("args malformed: %v", fs["args"])
	}
	if args[0] != "mcp-proxy" || args[1] != "--" || args[2] != "npx" {
		t.Errorf("args = %v, want [mcp-proxy -- npx ...]", args)
	}

	// Round-trip: unwrap must recognize the absolute path and restore the original.
	if err := unwrapMCPConfig(loc); err != nil {
		t.Fatalf("unwrapMCPConfig: %v", err)
	}
	fs = readServer(t, cfgPath, "fs")
	if got := fs["command"]; got != "npx" {
		t.Errorf("after unwrap command = %v, want npx", got)
	}
	args, _ = fs["args"].([]interface{})
	if len(args) != 3 || args[0] != "-y" {
		t.Errorf("after unwrap args = %v, want original [-y ...]", args)
	}
}

func readServer(t *testing.T, path, name string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	servers, ok := cfg["mcpServers"].(map[string]interface{})
	if !ok {
		t.Fatalf("no mcpServers in %s", path)
	}
	srv, ok := servers[name].(map[string]interface{})
	if !ok {
		t.Fatalf("no server %q in %s", name, path)
	}
	return srv
}
