package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func pidFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".agentshield", "heartbeat.pid")
}

// startHeartbeatDaemon spawns `agentshield connect` as a detached background process.
func startHeartbeatDaemon() error {
	// Kill existing daemon if running
	stopHeartbeatDaemon()

	// Find our own binary
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable: %w", err)
	}

	cmd := exec.Command(exe, "connect")
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil
	// Detach from parent process
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}

	// Write PID file
	pidFile := pidFilePath()
	os.MkdirAll(filepath.Dir(pidFile), 0700)
	os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0600)

	// Release the process so it runs independently
	cmd.Process.Release()

	return nil
}

// stopHeartbeatDaemon kills the background heartbeat process if running.
func stopHeartbeatDaemon() {
	pidFile := pidFilePath()
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		os.Remove(pidFile)
		return
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		os.Remove(pidFile)
		return
	}

	// Check if process is still running
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		os.Remove(pidFile)
		return
	}

	proc.Signal(syscall.SIGTERM)
	os.Remove(pidFile)
}

// isHeartbeatRunning checks if the daemon is alive.
func isHeartbeatRunning() bool {
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
