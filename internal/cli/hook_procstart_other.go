//go:build !windows

package cli

import "time"

// processCreated reports no creation time outside Windows: the budget counts
// from Go's package initialisation there (hookProcessStart), which measured
// 18 ms after spawn on a warm macOS binary (#4772).
func processCreated() (time.Time, bool) {
	return time.Time{}, false
}
