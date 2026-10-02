//go:build unix

package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The tests in this file are the Codex pass 1 finding on #4057 (critical
// set (a)), reproduced by Kai: a degraded writer D completes followRotation,
// a healthy sibling H rotates twice, then D's head read and write run. The
// write succeeds into the inode H's second rotation unlinked, Log returns
// nil, VerifyChain(live) says verified, and the event is in no file. With
// ONE rotation in the window D's line lands in .1, retained, and the chain
// break is visible; that case must not be "fixed" by a second copy.

// windowFixture sets up D (degraded) and H (healthy) sharing one log whose
// live file is already at the rotation threshold, with D's last line the
// last line of it. That last part is deliberate: D's knownSize then equals
// the held file's size, so D's head read before the paused write keeps D's
// own stale head. A retry that failed to re-read the head (mutation c)
// would therefore carry a prev_hash the live file does not have.
func windowFixture(t *testing.T) (D, H *AuditLogger, logPath string) {
	t.Helper()
	smallRotation(t, 1500)
	D, H, logPath = newDegradedThenHealthy(t)
	fillToRotationThreshold(t, H, logPath)
	if err := D.Log(windowEvent("D-before")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { afterDegradedFollow = nil })
	return D, H, logPath
}

// rotateOnce drives H through one rotation: the live file is at the
// threshold, so H's next Log rotates it to .1 and lands cmd as the first
// line of the fresh file.
func rotateOnce(t *testing.T, H *AuditLogger, logPath, cmd string) {
	t.Helper()
	before, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := H.Log(windowEvent(cmd)); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatalf("control: H.Log(%s) did not rotate", cmd)
	}
}

// TestDegradedFollower_TwoRotationsInWindow_ReappendsToLive is Codex's
// deterministic regression: two rotations between D's follow and its write.
// D's event must be in the live file exactly once, chained onto the head
// the live file had when D re-appended, and never "absent + verified".
func TestDegradedFollower_TwoRotationsInWindow_ReappendsToLive(t *testing.T) {
	D, H, logPath := windowFixture(t)

	headAtReappend := ""
	afterDegradedFollow = func() {
		afterDegradedFollow = nil
		rotateOnce(t, H, logPath, "H-mid-1")
		fillToRotationThreshold(t, H, logPath)
		rotateOnce(t, H, logPath, "H-mid-2")
		headAtReappend = ChainHead(logPath)
	}
	if err := D.Log(windowEvent("D-in-window")); err != nil {
		t.Fatalf("Log = %v; want nil (the re-append succeeded)", err)
	}
	if afterDegradedFollow != nil {
		t.Fatal("control: the seam never fired; the rotations did not happen inside D's window")
	}
	// D's NEXT line must chain onto the re-appended one, not onto the copy
	// that went to the unlinked inode (Opus pass 5, m6): with no sibling
	// write in between, nothing but D's own head decides that prev_hash.
	if err := D.Log(windowEvent("D-next")); err != nil {
		t.Fatal(err)
	}
	// One healthy write after: the four lines stay under the test's
	// rotation threshold, so the live file H-mid-2 opened is still live.
	if err := H.Log(windowEvent("H-after")); err != nil {
		t.Fatal(err)
	}

	if live, old := countIn(logPath, "D-in-window"), countIn(logPath+rotatedSuffix, "D-in-window"); live != 1 || old != 0 {
		t.Fatalf("D-in-window is in live=%d .1=%d; want live=1 .1=0 (absent from both is the silent loss)", live, old)
	}
	evs := readEvents(t, logPath)
	if len(evs) != 4 || evs[0].Command != "H-mid-2" || evs[1].Command != "D-in-window" || evs[2].Command != "D-next" {
		t.Fatalf("live file = %d events; want exactly H-mid-2, D-in-window, D-next, H-after", len(evs))
	}
	if evs[1].PrevHash != headAtReappend {
		t.Errorf("re-appended line prev_hash = %q, want the live head at re-append %q (the retry did not re-read the head)", evs[1].PrevHash, headAtReappend)
	}
	if evs[2].PrevHash == evs[1].PrevHash || evs[2].PrevHash == "" {
		t.Errorf("D-next prev_hash = %q; want the re-appended line's hash, not its predecessor's or a genesis", evs[2].PrevHash)
	}
	if lockNote(evs[1].Notes) == nil {
		t.Errorf("re-appended line lost the lock note: %+v", evs[1].Notes)
	}
	r := VerifyChain(logPath)
	if r.State != ChainStateVerified || r.Note != "linked to "+filepath.Base(logPath+rotatedSuffix) {
		t.Errorf("VerifyChain(live) = %s note=%q: %s; want verified and linked to .1", r.State, r.Note, r.Message)
	}
}

// rotateTwice drives H through two full rotations from wherever the live
// file is: fill, rotate, fill, rotate. After it the inode a writer held
// before the call has no name left.
func rotateTwice(t *testing.T, H *AuditLogger, logPath, tag string) {
	t.Helper()
	fillToRotationThreshold(t, H, logPath)
	rotateOnce(t, H, logPath, tag+"-1")
	fillToRotationThreshold(t, H, logPath)
	rotateOnce(t, H, logPath, tag+"-2")
}

// captureStderr runs fn with os.Stderr redirected to a pipe and returns
// what was written. The logger's warnings for callers that discard Log
// errors (the MCP path, the watchdog) go there and are part of the
// contract.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = old })
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	os.Stderr = old
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// TestDegradedFollower_TwoRotationsInFirstRetry_SecondRetryRetains pins the
// retry bound (Opus pass 5, m1): two rotations in the first window AND two
// more inside the first retry's window put the first re-append in an
// unlinked inode too; the second retry lands the event. A bound of one
// would report it lost while a retry was still available.
func TestDegradedFollower_TwoRotationsInFirstRetry_SecondRetryRetains(t *testing.T) {
	D, H, logPath := windowFixture(t)
	t.Cleanup(func() { afterReappendFollow = nil })

	afterDegradedFollow = func() {
		afterDegradedFollow = nil
		rotateOnce(t, H, logPath, "H-mid-1")
		fillToRotationThreshold(t, H, logPath)
		rotateOnce(t, H, logPath, "H-mid-2")
	}
	var attempts []int
	afterReappendFollow = func(attempt int) {
		attempts = append(attempts, attempt)
		if attempt == 0 {
			rotateTwice(t, H, logPath, "H-retry")
		}
	}
	if err := D.Log(windowEvent("D-in-window")); err != nil {
		t.Fatalf("Log = %v; want nil (the second retry retained the event)", err)
	}
	if len(attempts) != 2 || attempts[0] != 0 || attempts[1] != 1 {
		t.Fatalf("retry attempts = %v; want [0 1] (the first re-append was unlinked, the second ran)", attempts)
	}
	if err := H.Log(windowEvent("H-after")); err != nil {
		t.Fatal(err)
	}
	if live, old := countIn(logPath, "D-in-window"), countIn(logPath+rotatedSuffix, "D-in-window"); live != 1 || old != 0 {
		t.Fatalf("D-in-window is in live=%d .1=%d; want live=1 .1=0", live, old)
	}
	if r := VerifyChain(logPath); r.State != ChainStateVerified {
		t.Errorf("VerifyChain(live) = %s: %s; want verified", r.State, r.Message)
	}
}

// TestDegradedFollower_RotationsOutrunEveryRetry_ReportsLoss is the
// exhausted path (Opus pass 5, m2 and m9): two rotations in the first
// window and two more inside every retry's window. Nothing D wrote is in a
// retained file, and that must be said in both places callers look: the
// error for the hook, the stderr line for the callers that discard it.
func TestDegradedFollower_RotationsOutrunEveryRetry_ReportsLoss(t *testing.T) {
	D, H, logPath := windowFixture(t)
	t.Cleanup(func() { afterReappendFollow = nil })

	afterDegradedFollow = func() {
		afterDegradedFollow = nil
		rotateOnce(t, H, logPath, "H-mid-1")
		fillToRotationThreshold(t, H, logPath)
		rotateOnce(t, H, logPath, "H-mid-2")
	}
	attempts := 0
	afterReappendFollow = func(attempt int) {
		attempts++
		rotateTwice(t, H, logPath, fmt.Sprintf("H-retry%d", attempt))
	}
	var err error
	stderr := captureStderr(t, func() { err = D.Log(windowEvent("D-in-window")) })
	if attempts != maxUnlinkedReappends {
		t.Fatalf("control: %d retries ran, want %d", attempts, maxUnlinkedReappends)
	}
	if err == nil || !strings.Contains(err.Error(), "audit event lost") {
		t.Fatalf("Log = %v; want the loss error (nil would claim a persistence that did not happen)", err)
	}
	if !strings.Contains(stderr, "[AgentShield] warning: audit event lost") {
		t.Errorf("stderr = %q; want the loss warning for callers that discard Log errors", stderr)
	}
	if err := H.Log(windowEvent("H-after")); err != nil {
		t.Fatal(err)
	}
	if got := countIn(logPath, "D-in-window") + countIn(logPath+rotatedSuffix, "D-in-window"); got != 0 {
		t.Fatalf("D-in-window occurs %d times across live and .1; the fixture did not exhaust the retries", got)
	}
	// D recovers: its next write lands in the live file, chained.
	if err := D.Log(windowEvent("D-after-loss")); err != nil {
		t.Fatal(err)
	}
	if countIn(logPath, "D-after-loss") != 1 {
		t.Error("D's next event after the loss did not land in the live file")
	}
	if r := VerifyChain(logPath); r.State != ChainStateVerified {
		t.Errorf("VerifyChain(live) = %s: %s; want verified", r.State, r.Message)
	}
}

// TestDegradedFollower_OneRotationInWindow_StaysInRotatedOnce pins the
// no-duplicate rule. One rotation between follow and write leaves D's line
// in .1: retained, so it is NOT appended to the live file as well. The
// price is a visible prev_hash break at the rotation link (H's first line
// links to .1's head as it was before D's line landed there). That break
// is the lockless append's accepted, documented cost; asserting it keeps
// any later change to it deliberate.
func TestDegradedFollower_OneRotationInWindow_StaysInRotatedOnce(t *testing.T) {
	D, H, logPath := windowFixture(t)

	afterDegradedFollow = func() {
		afterDegradedFollow = nil
		rotateOnce(t, H, logPath, "H-mid-1")
	}
	if err := D.Log(windowEvent("D-in-window")); err != nil {
		t.Fatalf("Log = %v; want nil (the line is retained in .1)", err)
	}
	if afterDegradedFollow != nil {
		t.Fatal("control: the seam never fired")
	}
	for i := 0; i < 3; i++ {
		if err := H.Log(windowEvent(fmt.Sprintf("H-after-%d", i))); err != nil {
			t.Fatal(err)
		}
	}

	if live, old := countIn(logPath, "D-in-window"), countIn(logPath+rotatedSuffix, "D-in-window"); live != 0 || old != 1 {
		t.Fatalf("D-in-window is in live=%d .1=%d; want live=0 .1=1 (a copy in live duplicates a retained event)", live, old)
	}
	if r := VerifyChain(logPath + rotatedSuffix); r.State != ChainStateVerified {
		t.Errorf("VerifyChain(.1) = %s: %s; want verified (D's line chains onto .1's tail)", r.State, r.Message)
	}
	if r := VerifyChain(logPath); r.State != ChainStateBroken {
		t.Errorf("VerifyChain(live) = %s: %s; want broken at the rotation link, the visible accepted cost", r.State, r.Message)
	}
}

// TestDegradedFollower_NoRotationInWindow_WritesOnce is the control: with
// nothing in the window the degraded write is not touched by the check.
func TestDegradedFollower_NoRotationInWindow_WritesOnce(t *testing.T) {
	D, H, logPath := windowFixture(t)
	fired := false
	afterDegradedFollow = func() { fired = true }
	if err := D.Log(windowEvent("D-in-window")); err != nil {
		t.Fatal(err)
	}
	if !fired {
		t.Fatal("control: the seam never fired")
	}
	if err := H.Log(windowEvent("H-after")); err != nil {
		t.Fatal(err)
	}
	if got := countIn(logPath, "D-in-window") + countIn(logPath+rotatedSuffix, "D-in-window"); got != 1 {
		t.Fatalf("D-in-window occurs %d times across live and .1; want exactly 1", got)
	}
}
