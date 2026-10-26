package safefile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestReadFile_NoSizeCap pins "no cap" as deliberate (#4478, Gary's call 1):
// policy.yaml and packs read through here, and a cap that truncated or
// dropped a large pack would lower decisions. A 1 MiB-cap mutant survived
// the suite before this test, since every other test reads a few bytes.
func TestReadFile_NoSizeCap(t *testing.T) {
	const size = 3<<20 + 7 // over 1, 2 and 3 MiB, and not a power of two
	want := bytes.Repeat([]byte("rules:\n"), size/7+1)[:size]
	p := filepath.Join(t.TempDir(), "big-pack.yaml")
	if err := os.WriteFile(p, want, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFile(p)
	if err != nil {
		t.Fatalf("ReadFile(%d-byte regular file): %v", size, err)
	}
	if len(got) != size || !bytes.Equal(got, want) {
		t.Fatalf("ReadFile returned %d bytes, want all %d: a cap here would drop part of a large pack", len(got), size)
	}
}
