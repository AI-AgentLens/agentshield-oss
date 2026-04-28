package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

const launchdLabel = "com.aiagentlens.agentshield"

func plistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist")
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
		out, err := exec.Command("launchctl", "list", launchdLabel).Output()
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
</plist>`, launchdLabel, binPath, logPath, logPath)

	plistFile := plistPath()
	_ = os.MkdirAll(filepath.Dir(plistFile), 0755)

	if err := os.WriteFile(plistFile, []byte(plist), 0644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}

	// Load the service
	cmd := exec.Command("launchctl", "load", plistFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl load: %s: %w", string(out), err)
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
