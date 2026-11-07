package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// status counts a wrapped server as proxied in every spelling setup writes:
// the bare name, or the absolute path it writes today (agentshield.exe on
// Windows). It used to count only the bare name, so every server setup had
// wrapped was reported as unprotected (#4717).
func TestProxiedServerCount(t *testing.T) {
	bin := "/opt/homebrew/bin/agentshield"
	if runtime.GOOS == "windows" {
		bin = `C:\Users\u\AppData\Local\Programs\AgentShield\agentshield.exe`
	}
	wrapped := func(cmd string) map[string]interface{} {
		return map[string]interface{}{"command": cmd, "args": []interface{}{"mcp-proxy", "--", "server"}}
	}
	servers := map[string]interface{}{
		"bare":      wrapped("agentshield"),
		"absolute":  wrapped(bin),
		"unwrapped": map[string]interface{}{"command": "npx"},
		"lookalike": wrapped("/usr/local/bin/agentshield-echo"),
	}
	if got := proxiedServerCount(servers); got != 2 {
		t.Fatalf("proxiedServerCount = %d, want 2 (bare + absolute)", got)
	}
}

// On Windows setup writes agentshield.exe, and --disable must find it there
// when no backup exists. It used to compare the base name with
// "agentshield", so it unwrapped nothing on Windows (#4717).
func TestUnwrapMCPConfig_WindowsExe(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("agentshield.exe is the Windows spelling")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "claude_desktop_config.json")
	original := `{"mcpServers":{"echo":{"command":"C:\\tools\\echo.exe","args":["--flag"]}}}`
	if err := os.WriteFile(cfgPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	loc := mcpConfigLocation{Name: "Claude Desktop", Path: cfgPath}
	if err := wrapMCPConfig(loc, filepath.Join(dir, "AgentShield", "agentshield.exe")); err != nil {
		t.Fatalf("wrapMCPConfig: %v", err)
	}
	if err := unwrapMCPConfig(loc); err != nil {
		t.Fatalf("unwrapMCPConfig: %v", err)
	}
	echo := readServer(t, cfgPath, "echo")
	if got := echo["command"]; got != `C:\tools\echo.exe` {
		t.Fatalf("after unwrap command = %v, want the original server", got)
	}
}
