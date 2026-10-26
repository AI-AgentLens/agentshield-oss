package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

const launchdBaseLabel = "com.aiagentlens.agentshield"

// launchdLabel is the launchd job label for this HOME (#4476). The machine's real
// user keeps the bare label, so an existing install is not migrated. Any other HOME
// (a scratch HOME, a test harness) gets a suffix derived from the path: launchd
// labels are global to the user session, and a shared label let a stop from one
// HOME unload the other's daemon.
func launchdLabel() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return launchdBaseLabel
	}
	if u, err := user.Current(); err != nil || u.HomeDir == "" || filepath.Clean(u.HomeDir) == filepath.Clean(home) {
		return launchdBaseLabel
	}
	sum := sha256.Sum256([]byte(filepath.Clean(home)))
	return launchdBaseLabel + "." + hex.EncodeToString(sum[:4])
}

// launchctlLoadRefused reports whether `launchctl load` output means the job was not
// loaded. The legacy `load` verb prints these and can still exit 0 (#4476).
func launchctlLoadRefused(out string) bool {
	o := strings.ToLower(out)
	return strings.Contains(o, "already loaded") || strings.Contains(o, "load failed") ||
		strings.Contains(o, "service already") || strings.Contains(o, "could not find")
}

func plistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", launchdLabel()+".plist")
}

func pidFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".agentshield", "heartbeat.pid")
}

// startHeartbeatDaemon installs and starts a persistent heartbeat service.
// On macOS: launchd agent (survives reboots, brew updates, auto-restarts).
// On Linux: falls back to detached process with PID file.
func startHeartbeatDaemon() error {
	stopHeartbeatDaemon()

	if runtime.GOOS == "darwin" {
		return installLaunchd()
	}
	return startDetachedProcess()
}

// stopHeartbeatDaemon removes the heartbeat service.
func stopHeartbeatDaemon() {
	if runtime.GOOS == "darwin" {
		uninstallLaunchd()
	}
	killPidFile()
}

// isHeartbeatRunning checks if the daemon is alive.
func isHeartbeatRunning() bool {
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("launchctl", "list", launchdLabel()).Output()
		if err == nil && len(out) > 0 {
			return true
		}
	}
	return isPidAlive()
}

// --- macOS launchd ---

func installLaunchd() error {
	// Find agentshield binary — use a stable path that survives brew updates
	binPath, err := exec.LookPath("agentshield")
	if err != nil {
		// Fallback to current executable
		binPath, err = os.Executable()
		if err != nil {
			return fmt.Errorf("find agentshield binary: %w", err)
		}
	}

	home, _ := os.UserHomeDir()
	logPath := filepath.Join(home, ".agentshield", "heartbeat.log")

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>connect</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>30</integer>
    <key>StandardOutPath</key>
    <string>%s</string>
    <key>StandardErrorPath</key>
    <string>%s</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/usr/sbin:/bin</string>
    </dict>
</dict>
</plist>`, launchdLabel(), binPath, logPath, logPath)

	plistFile := plistPath()
	_ = os.MkdirAll(filepath.Dir(plistFile), 0755)

	if err := os.WriteFile(plistFile, []byte(plist), 0644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}

	// Load the service
	cmd := exec.Command("launchctl", "load", plistFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl load: %s: %w", string(out), err)
	}
	if launchctlLoadRefused(string(out)) {
		return fmt.Errorf("launchctl load refused: %s", strings.TrimSpace(string(out)))
	}

	return nil
}

func uninstallLaunchd() {
	plistFile := plistPath()
	_ = exec.Command("launchctl", "unload", plistFile).Run()
	_ = os.Remove(plistFile)
}

// --- Fallback: detached process ---

func startDetachedProcess() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable: %w", err)
	}

	cmd := exec.Command(exe, "connect")
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}

	pidFile := pidFilePath()
	_ = os.MkdirAll(filepath.Dir(pidFile), 0700)
	_ = os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0600)
	_ = cmd.Process.Release()

	return nil
}

func killPidFile() {
	pidFile := pidFilePath()
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		_ = os.Remove(pidFile)
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		_ = os.Remove(pidFile)
		return
	}
	_ = proc.Signal(syscall.SIGTERM)
	_ = os.Remove(pidFile)
}

func isPidAlive() bool {
	data, err := os.ReadFile(pidFilePath())
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}
