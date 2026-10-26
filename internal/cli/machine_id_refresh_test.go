package cli

import (
	"os"
	"testing"
)

const testForeignHardwareID = "4475FFFF-0000-4111-8222-999988887777"

// #4475: a cache carried from another machine is repaired by the heartbeat's
// live read, and only by a hardware id.
func TestRefreshingMachineID_RepairsForeignCache(t *testing.T) {
	newRedactionHome(t, "")
	writeCachedMachineID(testForeignHardwareID)

	got := refreshingMachineID(func() string { return testHardwareID })
	if got != testHardwareID {
		t.Fatalf("returned %q, want the live id %q", got, testHardwareID)
	}
	if cached, ok := readCachedMachineID(); !ok || cached != testHardwareID {
		t.Fatalf("cache = %q (ok=%v), want %q after one heartbeat read", cached, ok, testHardwareID)
	}
}

func TestRefreshingMachineID_WritesWhenCacheAbsent(t *testing.T) {
	newRedactionHome(t, "")
	refreshingMachineID(func() string { return testHardwareID })
	if cached, ok := readCachedMachineID(); !ok || cached != testHardwareID {
		t.Fatalf("cache = %q (ok=%v), want %q", cached, ok, testHardwareID)
	}
}

// A fallback id (hostname hash after a failed ioreg) must not replace a good
// cached hardware id: that would flip the machine to a second id.
func TestRefreshingMachineID_FallbackNeverOverwrites(t *testing.T) {
	newRedactionHome(t, "")
	writeCachedMachineID(testHardwareID)

	got := refreshingMachineID(func() string { return "fallback-abc123" })
	if got != "fallback-abc123" {
		t.Fatalf("returned %q, want the live read passed through", got)
	}
	if cached, ok := readCachedMachineID(); !ok || cached != testHardwareID {
		t.Fatalf("cache = %q (ok=%v), want %q untouched", cached, ok, testHardwareID)
	}
	refreshingMachineID(func() string { return "" })
	if cached, _ := readCachedMachineID(); cached != testHardwareID {
		t.Fatalf("an empty read changed the cache to %q", cached)
	}
}

// A matching cache is left alone (no rewrite on every heartbeat).
func TestRefreshingMachineID_MatchingCacheNotRewritten(t *testing.T) {
	newRedactionHome(t, "")
	writeCachedMachineID(testHardwareID)
	before, err := os.Stat(machineIDCachePath())
	if err != nil {
		t.Fatal(err)
	}
	refreshingMachineID(func() string { return testHardwareID })
	after, err := os.Stat(machineIDCachePath())
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Error("cache file was replaced although the id matched")
	}
}
