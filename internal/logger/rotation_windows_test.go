//go:build windows

package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRotation_WindowsForeignHandleBlocksRotationKeepsPredecessor pins what
// is left of #5038. A handle opened without FILE_SHARE_DELETE (Go's default
// os.OpenFile, used here with the MCP proxy's own flags from
// internal/cli/mcp_proxy.go; a verifier or `agentshield log` mid-read;
// another program) still blocks the rename of the live file: while it is
// held, every write retries the rotation, fails, warns and appends, and the
// live file grows past maxLogBytes. No entry is lost and the chain verifies.
//
// What changed: the rename is tried before <path>.1 is touched, and a
// sharing violation on the source is not a reason to remove it, so the
// retained predecessor survives. Before #5038 the first failed attempt
// deleted it. Once the handle closes, the next write rotates normally.
func TestRotation_WindowsForeignHandleBlocksRotationKeepsPredecessor(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	rotated := p + rotatedSuffix

	seedLogAtThreshold(t, p, 4)
	hookWrite(t, p, "gen1-0")
	if got := countLines(t, rotated, "seed-"); got != 4 {
		t.Fatalf("control: a rotation with no other handle open should move the 4 seed entries to %s, found %d", filepath.Base(rotated), got)
	}
	gen1 := 1 + fillGeneration(t, p, "gen1")

	holder, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = holder.Close() })

	const blocked = 5
	for i := 0; i < blocked; i++ {
		hookWrite(t, p, fmt.Sprintf("blocked-%d", i))
	}

	if got := countLines(t, rotated, "seed-"); got != 4 {
		t.Errorf("the failed rotations must keep %s: %d of its 4 seed entries left", filepath.Base(rotated), got)
	}
	if got := countLines(t, p, "gen1-"); got != gen1 {
		t.Errorf("generation 1 entries in the live file: %d, want %d (none lost)", got, gen1)
	}
	if got := countLines(t, p, "blocked-"); got != blocked {
		t.Errorf("entries written while the rotation was blocked: %d in the live file, want %d", got, blocked)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= maxLogBytes {
		t.Errorf("pinned gap changed: the live file is %d bytes, want it past the %d-byte threshold", info.Size(), maxLogBytes)
	}
	if r := VerifyChain(p); r.State != ChainStateVerified || r.Note != "linked to audit.jsonl.1" {
		t.Errorf("while blocked: got %q note %q: %s", r.State, r.Note, r.Message)
	}

	if err := holder.Close(); err != nil {
		t.Fatal(err)
	}
	hookWrite(t, p, "after-release")
	if got := countLines(t, rotated, "gen1-") + countLines(t, rotated, "blocked-"); got != gen1+blocked {
		t.Errorf("after the handle closed, %s should hold every earlier entry: %d of %d", filepath.Base(rotated), got, gen1+blocked)
	}
	if got := countLines(t, p, "after-release"); got != 1 {
		t.Errorf("the write after the release should open a fresh live file, found it %d times", got)
	}
	r := VerifyChain(p)
	if r.State != ChainStateVerified || r.Note != "linked to audit.jsonl.1" {
		t.Errorf("after the release: got %q note %q: %s", r.State, r.Note, r.Message)
	}
	if strings.Contains(r.Message, "predecessor unavailable") {
		t.Errorf("after the release: %s", r.Message)
	}
}
