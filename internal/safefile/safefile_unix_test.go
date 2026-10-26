//go:build unix

package safefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// readUnderGuard fails if ReadFile has not returned in 5 s: the failure this
// package exists for is a read that never does.
func readUnderGuard(t *testing.T, path string) ([]byte, error) {
	t.Helper()
	type res struct {
		b   []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		b, err := ReadFile(path)
		ch <- res{b, err}
	}()
	select {
	case r := <-ch:
		return r.b, r.err
	case <-time.After(5 * time.Second):
		// Release a reader stuck in open(2) so the goroutine ends.
		if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
		t.Fatalf("ReadFile(%s) did not return in 5 s", path)
		return nil, nil
	}
}

func TestReadFile_RegularAndSymlinkAreRead(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.yaml")
	if err := os.WriteFile(real, []byte("version: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{real, link} {
		b, err := readUnderGuard(t, p)
		if err != nil || string(b) != "version: x\n" {
			t.Errorf("ReadFile(%s) = %q, %v; want the file's bytes", p, b, err)
		}
	}
}

func TestReadFile_MissingStaysNotExist(t *testing.T) {
	_, err := readUnderGuard(t, filepath.Join(t.TempDir(), "nope.yaml"))
	if !errors.Is(err, fs.ErrNotExist) || os.IsNotExist(err) != true {
		t.Fatalf("err = %v; want ErrNotExist (loaders branch on it)", err)
	}
}

func TestReadFile_NonRegularIsAnErrorNotAHang(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	fifoLink := filepath.Join(dir, "fifo-link")
	if err := os.Symlink(fifo, fifoLink); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(dir, "d")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{"fifo": fifo, "symlink to fifo": fifoLink, "directory": subdir} {
		_, err := readUnderGuard(t, p)
		if !errors.Is(err, ErrNotRegular) {
			t.Errorf("%s: err = %v; want ErrNotRegular", name, err)
		}
		if errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: reported as missing; a planted non-file must not read as absent", name)
		}
	}
}
