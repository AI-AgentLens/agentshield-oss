//go:build unix

package auth

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// #4474: Load runs before the hook returns its verdict (sendRemoteAudit).
// With os.ReadFile, a FIFO at the credentials path blocked open(2) with no
// writer and the hook never answered. Any same-user process can plant one
// (#4393). Every case runs under a guard, because the failure this exists
// to prevent is a read that never returns.

type loadResult struct {
	creds *Credentials
	err   error
}

// loadUnderGuard runs Load and fails the test if it has not returned
// within guard.
func loadUnderGuard(t *testing.T, guard time.Duration) loadResult {
	t.Helper()
	done := make(chan loadResult, 1)
	go func() {
		c, err := Load()
		done <- loadResult{c, err}
	}()
	select {
	case r := <-done:
		return r
	case <-time.After(guard):
		t.Fatalf("auth.Load did not return in %v", guard)
		return loadResult{}
	}
}

// releaseFIFOReader opens path for writing without blocking, at cleanup.
// When a Load is stuck in open(2) on the FIFO (the unfixed code), that
// open gives it a writer, so the stuck goroutine sees EOF and ends instead
// of outliving its test. With no reader waiting it fails with ENXIO, which
// is the fixed code's case and is ignored.
func releaseFIFOReader(t *testing.T, path string) {
	t.Cleanup(func() {
		if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
}

func TestLoad_FIFOReadsAsNoCredentials(t *testing.T) {
	scratchHome(t)
	path := CredentialsPath()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	releaseFIFOReader(t, path)

	start := time.Now()
	r := loadUnderGuard(t, 5*time.Second)
	if r.creds != nil || r.err != nil {
		t.Errorf("Load() = %+v, %v; want nil, nil for a FIFO", r.creds, r.err)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("Load took %v with a FIFO at the credentials path; want well under a second", took)
	}
}

// TestLoad_NonRegularReadsAsNoCredentials: a directory, an endless device
// behind a symlink, and a FIFO behind a symlink all read as no credentials.
func TestLoad_NonRegularReadsAsNoCredentials(t *testing.T) {
	cases := map[string]func(t *testing.T, path string) error{
		"directory": func(_ *testing.T, p string) error { return os.Mkdir(p, 0o700) },
		"symlink to /dev/zero": func(_ *testing.T, p string) error {
			if _, err := os.Stat("/dev/zero"); err != nil {
				return err
			}
			return os.Symlink("/dev/zero", p)
		},
		"symlink to a FIFO": func(t *testing.T, p string) error {
			fifo := filepath.Join(filepath.Dir(p), "creds.fifo")
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				return err
			}
			releaseFIFOReader(t, fifo)
			return os.Symlink(fifo, p)
		},
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			scratchHome(t)
			if err := plant(t, CredentialsPath()); err != nil {
				t.Skipf("cannot plant %s: %v", name, err)
			}
			r := loadUnderGuard(t, 5*time.Second)
			if r.creds != nil || r.err != nil {
				t.Errorf("Load() = %+v, %v; want nil, nil", r.creds, r.err)
			}
		})
	}
}

// TestLoad_SymlinkToRegularFileLoads is the positive control for the kind
// check: it is taken from the open descriptor, which follows the link, so
// a symlink to a valid credentials file still loads.
func TestLoad_SymlinkToRegularFileLoads(t *testing.T) {
	home := scratchHome(t)
	real := filepath.Join(home, "creds.real.json")
	if err := os.WriteFile(real, []byte(`{"server":"https://saas.example","token":"tok-4474","user":{"id":3}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, CredentialsPath()); err != nil {
		t.Fatal(err)
	}
	r := loadUnderGuard(t, 5*time.Second)
	if r.err != nil || r.creds == nil {
		t.Fatalf("Load() = %+v, %v; want the credentials behind the symlink", r.creds, r.err)
	}
	if r.creds.Token != "tok-4474" || r.creds.Server != "https://saas.example" || r.creds.User.ID != 3 {
		t.Errorf("Load() = %+v; want server, token and user id from the target", r.creds)
	}
}
