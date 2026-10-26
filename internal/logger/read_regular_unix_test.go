//go:build unix

package logger

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// ReadRegularFileCapped is how a small file under ~/.agentshield is read
// when a same-user process can replace it with anything (#4208: the
// machine-id cache). Each case runs under a guard: the failure this exists
// to prevent is a read that never returns.
func TestReadRegularFileCapped(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small")
	if err := os.WriteFile(small, []byte("4208ABCD\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exact := filepath.Join(dir, "exact")
	if err := os.WriteFile(exact, make([]byte, 16), 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, 17), 0o600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "dir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	linkSmall := filepath.Join(dir, "link-small")
	if err := os.Symlink(small, linkSmall); err != nil {
		t.Fatal(err)
	}
	linkFifo := filepath.Join(dir, "link-fifo")
	if err := os.Symlink(fifo, linkFifo); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, path string
		want       string
		ok         bool
	}{
		{"small regular file", small, "4208ABCD\n", true},
		{"exactly max bytes", exact, string(make([]byte, 16)), true},
		{"one byte over max", big, "", false},
		{"FIFO with no writer", fifo, "", false},
		{"directory", sub, "", false},
		{"symlink to a regular file", linkSmall, "4208ABCD\n", true},
		{"symlink to a FIFO", linkFifo, "", false},
		{"missing", filepath.Join(dir, "nope"), "", false},
	}
	if _, err := os.Stat("/dev/zero"); err == nil {
		cases = append(cases, struct {
			name, path string
			want       string
			ok         bool
		}{"endless device", "/dev/zero", "", false})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			type res struct {
				data []byte
				ok   bool
			}
			done := make(chan res, 1)
			go func() {
				d, ok := ReadRegularFileCapped(tc.path, 16)
				done <- res{d, ok}
			}()
			select {
			case r := <-done:
				if r.ok != tc.ok || string(r.data) != tc.want {
					t.Errorf("ReadRegularFileCapped(%s) = %q, %v; want %q, %v", tc.name, r.data, r.ok, tc.want, tc.ok)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("ReadRegularFileCapped(%s) did not return in 5 s", tc.name)
			}
		})
	}
}
