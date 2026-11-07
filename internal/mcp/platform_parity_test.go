package mcp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The MCP glob engine decides the same on every platform for the same
// argument string (#4717). On a native Windows build filepath is
// backslash-based, and every "**" glob in the MCP packs fell through to the
// default there. Run on Windows this test catches that; on unix it pins
// today's behaviour.
func TestMatchGlob_SameOnEveryPlatform(t *testing.T) {
	creds := "cred" + "entials"
	cases := []struct {
		value, pattern string
		want           bool
	}{
		{"/home/u/.agentshield/policy.yaml", "**/.agentshield/policy.yaml", true},
		{`C:\Users\u\.agentshield\policy.yaml`, "**/.agentshield/policy.yaml", true},
		{"C:/Users/u/.agentshield/policy.yaml", "**/.agentshield/policy.yaml", true},
		{"/home/u/.aws/" + creds, "**/.aws/**", true},
		{`C:\Users\u\.aws\` + creds, "**/.aws/**", true},
		{"/home/u/project/notes.txt", "**/.aws/**", false},
		{"/home/u/x.yaml", "/home/*/x.yaml", true},
		{"/home/u/v/x.yaml", "/home/*/x.yaml", false}, // * does not cross "/"
	}
	for _, c := range cases {
		if got := matchGlob(c.value, c.pattern); got != c.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", c.value, c.pattern, got, c.want)
		}
	}
}

// The config guard anchors its patterns to this user's home directory in
// the spelling the platform uses: $HOME on unix, %USERPROFILE% on Windows,
// which has no HOME of its own. A native path to AgentShield's own policy
// file must be caught (#4717).
func TestConfigGuard_NativeHomePath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	target := filepath.Join(home, ".agentshield", "policy.yaml")
	if got := CheckConfigGuard("write_file", map[string]interface{}{"path": target}); !got.Blocked {
		t.Fatalf("write_file %s: config guard did not block", target)
	}
	if got := CheckConfigGuard("write_file", map[string]interface{}{"path": filepath.Join(home, "notes.txt")}); got.Blocked {
		t.Fatalf("write_file to an ordinary file was blocked: %+v", got.Findings)
	}
}

// The Windows Claude Desktop paths are protected only on Windows; elsewhere
// they name nothing of Claude's, and blocking them could not be justified
// (#4723 review).
func TestConfigGuard_NoWindowsTemplatesOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows protects them")
	}
	for _, c := range protectedConfigs {
		if strings.Contains(c.pattern, "AppData") {
			t.Errorf("protected config %q added off Windows", c.pattern)
		}
	}
}

// Current Claude Desktop builds on Windows keep their config under
// %LOCALAPPDATA%\Claude-Data\<id>\ (#4717): an MCP write there is blocked like
// the other locations of the same file.
func TestConfigGuard_ClaudeDesktopDataDir_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("a Windows location")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	target := filepath.Join(home, "AppData", "Local", "Claude-Data", "claude_pzs8sxrjxfjjc", "claude_desktop_config.json")
	if got := CheckConfigGuard("write_file", map[string]interface{}{"path": target}); !got.Blocked {
		t.Fatalf("write_file %s: config guard did not block", target)
	}
	other := filepath.Join(home, "AppData", "Local", "Claude-Data", "notes.txt")
	if got := CheckConfigGuard("write_file", map[string]interface{}{"path": other}); got.Blocked {
		t.Fatalf("write_file %s was blocked: %+v", other, got.Findings)
	}
}
