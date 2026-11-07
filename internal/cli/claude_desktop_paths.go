package cli

import (
	"path/filepath"
	"runtime"
)

// windowsClaudeDesktopConfigs lists where Claude Desktop keeps
// claude_desktop_config.json on Windows, under home (#4717), newest first:
//   - current builds keep the account's Claude data in
//     %LOCALAPPDATA%\Claude-Data\<id>\ (the README.txt Claude writes there
//     says so; seen on Windows 11 as Claude-Data\claude_pzs8sxrjxfjjc);
//   - older Microsoft Store (MSIX) builds keep AppData inside their package
//     folder, where %APPDATA%\Claude does not exist;
//   - the classic installer uses %APPDATA%\Claude.
//
// Nil on every other platform, so the macOS and Linux lists are unchanged.
func windowsClaudeDesktopConfigs(home string) []string {
	return claudeDesktopConfigsFor(runtime.GOOS, home)
}

func claudeDesktopConfigsFor(goos, home string) []string {
	if goos != "windows" {
		return nil
	}
	local := filepath.Join(home, "AppData", "Local")
	found, _ := filepath.Glob(filepath.Join(local, "Claude-Data", "*", "claude_desktop_config.json"))
	msix, _ := filepath.Glob(filepath.Join(local, "Packages", "Claude_*", "LocalCache", "Roaming", "Claude", "claude_desktop_config.json"))
	found = append(found, msix...)
	return append(found, filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json"))
}
