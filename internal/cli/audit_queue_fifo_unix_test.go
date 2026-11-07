//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestAuditQueue_NonRegularQueueFilesFallBackToSync: a FIFO at queue.jsonl or
// at state.jsonl must neither swallow the event nor hang the hook; the hook
// uploads directly. Pass 2: without the state.jsonl kind check the hook hung
// reading the FIFO (killed at 10 s, against 76 ms), and the queue.jsonl
// regular-file check was unpinned (U1/U2/S2).
func TestAuditQueue_NonRegularQueueFilesFallBackToSync(t *testing.T) {
	for _, name := range []string{auditQueueFileName, auditStateFileName} {
		t.Run(name, func(t *testing.T) {
			saas := newFakeSaaS(t, nil)
			dir := newQueueHome(t, saas.srv.URL)
			spawns := stubFlusher(t, nil)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			fifo := filepath.Join(dir, name)
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
			// Release anything left blocked on the FIFO, so a failure ends.
			t.Cleanup(func() {
				if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
					_ = f.Close()
				}
			})

			done := make(chan struct{})
			go func() {
				defer close(done)
				sendRemoteAudit(queueEvent("echo past a fifo"), nil)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("the hook hung on a FIFO at %s", name)
			}
			if got := len(flatten(saas.requests())); got != 1 || spawns() != 0 {
				t.Fatalf("FIFO at %s: %d direct uploads, %d uploader starts; want 1 and 0", name, got, spawns())
			}
		})
	}
}
