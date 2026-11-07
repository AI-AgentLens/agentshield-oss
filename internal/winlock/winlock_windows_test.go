//go:build windows

package winlock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// openTwice returns two handles on one file, standing in for two agentshield
// processes. LockFileEx locks belong to the handle, so two handles in one
// process contend exactly as two processes do.
func openTwice(t *testing.T, content string) (path string, a, b *os.File) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "x.lock")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	open := func() *os.File {
		f, err := os.OpenFile(path, os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	return path, open(), open()
}

func TestTryLockExcludesAnotherHandleUntilUnlock(t *testing.T) {
	_, a, b := openTwice(t, "")
	if err := TryLock(a); err != nil {
		t.Fatalf("first TryLock: %v", err)
	}
	if err := TryLock(b); !errors.Is(err, ErrBusy) {
		t.Fatalf("second handle while held: got %v, want ErrBusy", err)
	}
	if err := Unlock(a); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := TryLock(b); err != nil {
		t.Fatalf("second handle after Unlock: %v", err)
	}
}

// The reason the lock sits past end of file: a held lock must not stop
// anyone reading or appending to the file's contents.
func TestHeldLockLeavesContentsReadableAndWritable(t *testing.T) {
	path, a, b := openTwice(t, "registry contents")
	if err := TryLock(a); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "registry contents" {
		t.Fatalf("ReadFile while locked: %q, %v", got, err)
	}
	if _, err := b.WriteAt([]byte("R"), 0); err != nil {
		t.Fatalf("write through another handle while locked: %v", err)
	}
}

func TestLockWaitsForRelease(t *testing.T) {
	_, a, b := openTwice(t, "")
	if err := Lock(a); err != nil {
		t.Fatal(err)
	}
	acquired := make(chan error, 1)
	go func() { acquired <- Lock(b) }()
	select {
	case err := <-acquired:
		t.Fatalf("Lock returned while another handle held the lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := Unlock(a); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-acquired:
		if err != nil {
			t.Fatalf("Lock after release: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Lock still waiting 5s after release")
	}
}

func TestCloseReleasesTheLock(t *testing.T) {
	_, a, b := openTwice(t, "")
	if err := TryLock(a); err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	// Windows documents that a close releases locks "depending upon available
	// system resources", so poll briefly rather than assert at once.
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := TryLock(b)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("lock not released 2s after Close: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
