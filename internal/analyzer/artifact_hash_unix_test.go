//go:build unix

package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// #4478 leftover: the artifact-hash stage (on only when
// AGENTSHIELD_ARTIFACT_MANIFEST is set) read the manifest and the script a
// command names with os.ReadFile. A FIFO at either, with no writer, blocked
// open(2), so the hook gave no verdict. Both now read through
// safefile.ReadFile and keep the branch they already had for an unreadable
// file: no analyzer for the manifest, no finding for the script.

// mkfifoReleased makes a FIFO at path and, at cleanup, opens it for writing
// so a reader the unfixed code left blocked in open(2) sees EOF and ends.
func mkfifoReleased(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	t.Cleanup(func() {
		if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
}

// underGuard fails the test if fn has not returned in 5 s.
func underGuard(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return in 5 s (blocking read on a FIFO)", what)
	}
}

func TestArtifactHash_FIFOAtScriptIsSkippedNotAHang(t *testing.T) {
	cwd := t.TempDir()
	rel := "skills/s/run.sh"
	mpath := writeManifest(t, cwd, map[string]string{rel: strings.Repeat("a", 64)})
	mkfifoReleased(t, filepath.Join(cwd, filepath.FromSlash(rel)))

	a := newArtifactHashAnalyzerFromPath(mpath, "block")
	if a == nil {
		t.Fatal("analyzer should be configured")
	}
	var findings []Finding
	underGuard(t, "Analyze with a FIFO at a manifest-declared script", func() {
		findings = a.Analyze(ctxFor(cwd, "bash "+rel))
	})
	// Unreadable means "can't confirm tampering": no finding, as for a
	// missing file (TestArtifactHash_MissingFileFailsSafe).
	if len(findings) != 0 {
		t.Fatalf("FIFO script: want no finding (unreadable is skipped), got %+v", findings)
	}
}

func TestArtifactHash_FIFOAtManifestDisablesNotAHang(t *testing.T) {
	mpath := filepath.Join(t.TempDir(), "artifacts.yaml")
	mkfifoReleased(t, mpath)

	var a *ArtifactHashAnalyzer
	underGuard(t, "newArtifactHashAnalyzerFromPath with a FIFO manifest", func() {
		a = newArtifactHashAnalyzerFromPath(mpath, "block")
	})
	// Unreadable manifest means the stage stays out of the pipeline.
	if a != nil {
		t.Fatalf("FIFO manifest: want nil analyzer (unreadable is off), got %+v", a)
	}
}
