package enterprise

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// StableHostname returns a consistent machine name that doesn't change with networks.
func StableHostname() string {
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("scutil", "--get", "ComputerName").Output(); err == nil {
			name := strings.TrimSpace(string(out))
			if name != "" {
				return name
			}
		}
	}
	name, _ := os.Hostname()
	return name
}
