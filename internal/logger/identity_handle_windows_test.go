//go:build windows

package logger

import (
	"os"
	"path/filepath"
	"testing"
)

// The Codex pass on #5040: VerifyChain's identity snapshot must never block a
// rotation. With the snapshot handle open, renaming the live file away (what
// rotateIfNeeded does) must succeed. The control shows that a plain os.Open
// handle does block the same rename on Windows, so this test can tell them apart.
func TestIdentityHandleNeverBlocksRotation(t *testing.T) {
	dir := t.TempDir()

	live := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(live, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := openIdentity(live)
	if err != nil {
		t.Fatalf("openIdentity: %v", err)
	}
	before, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat through the identity handle: %v", err)
	}
	if err := os.Rename(live, live+".1"); err != nil {
		f.Close()
		t.Fatalf("a rotation's rename was blocked by the open identity handle: %v", err)
	}
	if err := os.WriteFile(live, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.Close()
	after := liveIdentity(live)
	if after == nil || sameIdentity(before, after) {
		t.Fatalf("the new live file must not read as the file the snapshot held")
	}

	// Control: os.Open (openTail's open) does refuse the rename on Windows.
	ctl := filepath.Join(dir, "control.jsonl")
	if err := os.WriteFile(ctl, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := os.Open(ctl)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if err := os.Rename(ctl, ctl+".1"); err == nil {
		t.Fatalf("control: os.Open did not block the rename, so this test cannot tell the two opens apart")
	}
}

// openIdentity reports a missing file as ErrNotExist, which liveIdentity relies
// on to return "no file".
func TestIdentityHandleMissingFileIsNotExist(t *testing.T) {
	_, err := openIdentity(filepath.Join(t.TempDir(), "absent.jsonl"))
	if !os.IsNotExist(err) {
		t.Fatalf("openIdentity(absent) = %v; want a not-exist error", err)
	}
}
