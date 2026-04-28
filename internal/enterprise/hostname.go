package enterprise

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// StableHostname returns a consistent machine name that doesn't change with networks.
func StableHostname() string {
	if runtime.GOOS == "darwin" {
		// Use absolute path — /usr/sbin is not in PATH when running as a launchd daemon.
		if out, err := exec.Command("/usr/sbin/scutil", "--get", "ComputerName").Output(); err == nil {
			name := strings.TrimSpace(string(out))
			if name != "" {
				return name
			}
		}
	}
	name, _ := os.Hostname()
	return name
}

// MachineID returns a stable, unique identifier for this physical machine.
// On macOS: IOPlatformUUID from the hardware registry.
// On Linux: /etc/machine-id.
// Falls back to a hash of the hostname if neither is available.
func MachineID() string {
	if runtime.GOOS == "darwin" {
		// ioreg -rd1 -c IOPlatformExpertDevice outputs IOPlatformUUID
		// Use absolute path — /usr/sbin is not in PATH when running as a launchd daemon.
		if out, err := exec.Command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "IOPlatformUUID") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						uuid := strings.TrimSpace(parts[1])
						uuid = strings.Trim(uuid, `"`)
						if uuid != "" {
							return uuid
						}
					}
				}
			}
		}
	}

	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/etc/machine-id"); err == nil {
			id := strings.TrimSpace(string(data))
			if id != "" {
				return id
			}
		}
	}

	// Fallback: hash the hostname so we at least have something stable per boot
	h := sha256.Sum256([]byte(StableHostname()))
	return fmt.Sprintf("fallback-%x", h[:8])
}
