//go:build windows

package mcp

import (
	"os"

	"github.com/AI-AgentLens/agentshield/internal/winlock"
)

// lockRegistry takes the registry file's exclusive lock, waiting for it.
func lockRegistry(f *os.File) error {
	return winlock.Lock(f)
}

func unlockRegistry(f *os.File) {
	_ = winlock.Unlock(f)
}
