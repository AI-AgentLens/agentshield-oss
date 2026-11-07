package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Current Claude Desktop builds keep their config in %LOCALAPPDATA%\Claude-Data
// (seen on Windows 11), older Microsoft Store builds inside their MSIX package
// folder, and the classic installer in AppData\Roaming. All are found on
// Windows, newest first, and none anywhere else (#4717).
func TestClaudeDesktopConfigsFor(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, "AppData", "Local", "Claude-Data", "claude_pzs8sxrjxfjjc")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(dataDir, "claude_desktop_config.json")
	if err := os.WriteFile(data, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	msixDir := filepath.Join(home, "AppData", "Local", "Packages", "Claude_pzs8sxrjxfjjc", "LocalCache", "Roaming", "Claude")
	if err := os.MkdirAll(msixDir, 0o700); err != nil {
		t.Fatal(err)
	}
	msix := filepath.Join(msixDir, "claude_desktop_config.json")
	if err := os.WriteFile(msix, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	classic := filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json")

	if got, want := claudeDesktopConfigsFor("windows", home), []string{data, msix, classic}; !reflect.DeepEqual(got, want) {
		t.Errorf("windows: got %q, want %q", got, want)
	}
	for _, goos := range []string{"darwin", "linux"} {
		if got := claudeDesktopConfigsFor(goos, home); got != nil {
			t.Errorf("%s: got %q, want nil", goos, got)
		}
	}
}

// Off Windows the wrapper adds nothing, so the macOS and Linux lists stay as
// they were (#4723 review).
func TestWindowsClaudeDesktopConfigs_NilOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows lists both locations")
	}
	if got := windowsClaudeDesktopConfigs(t.TempDir()); got != nil {
		t.Fatalf("got %q, want nil off Windows", got)
	}
}

// "No MCP config files found" lists where setup actually looked on this
// platform. It used to print the macOS paths on Windows too (#4717).
func TestMCPConfigSearchPaths_PerPlatform(t *testing.T) {
	win := strings.Join(mcpConfigSearchPaths("windows"), "\n")
	for _, want := range []string{`Claude-Data\*\claude_desktop_config.json`, `Packages\Claude_*`, `%APPDATA%\Claude\claude_desktop_config.json`} {
		if !strings.Contains(win, want) {
			t.Errorf("windows list lacks %s:\n%s", want, win)
		}
	}
	if strings.Contains(win, "Library/Application Support") {
		t.Errorf("windows list names the macOS path:\n%s", win)
	}
	mac := strings.Join(mcpConfigSearchPaths("darwin"), "\n")
	if !strings.Contains(mac, "~/Library/Application Support/Claude/claude_desktop_config.json") || strings.Contains(mac, "%") {
		t.Errorf("darwin list = %s", mac)
	}
}
