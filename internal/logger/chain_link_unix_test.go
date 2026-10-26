//go:build unix

package logger

import (
	"fmt"
	"testing"
)

// The degraded writer's two outcomes that the healthy path never reaches
// (#4057 Codex pass 1): its first write lands in an inode a sibling's two
// rotations unlinked, and it re-appends the same event to the live file.
// The link LogLinked returns must be the re-append (a different line: new
// prev_hash), and on loss there must be none.

// TestLogLinked_ReappendReturnsTheLineThatStuck: the lost copy's link
// would name a line no file holds, so the receiver would wait forever for
// a successor that links to it and flag the next real line as a break.
func TestLogLinked_ReappendReturnsTheLineThatStuck(t *testing.T) {
	D, H, logPath := windowFixture(t)

	afterDegradedFollow = func() {
		afterDegradedFollow = nil
		rotateOnce(t, H, logPath, "H-mid-1")
		fillToRotationThreshold(t, H, logPath)
		rotateOnce(t, H, logPath, "H-mid-2")
	}
	link, err := D.LogLinked(windowEvent("D-in-window"))
	if err != nil {
		t.Fatalf("LogLinked = %v; want nil (the re-append succeeded)", err)
	}
	if afterDegradedFollow != nil {
		t.Fatal("control: the seam never fired; no rotation happened inside D's window")
	}
	if link == nil {
		t.Fatal("re-appended write returned no link")
	}

	lines := diskLines(t, logPath)
	if len(lines) != 2 {
		t.Fatalf("live file holds %d lines, want H-mid-2 then D-in-window", len(lines))
	}
	if countIn(logPath, "D-in-window") != 1 {
		t.Fatal("control: D's event is not in the live file exactly once")
	}
	if want := sha256Hex(lines[1]); link.LineHash != want {
		t.Errorf("line_hash = %s, want the re-appended line on disk %s (a link to the unlinked copy names a line no file holds)", link.LineHash, want)
	}
	if want := sha256Hex(lines[0]); link.PrevHash != want {
		t.Errorf("prev_hash = %s, want the live head at re-append %s", link.PrevHash, want)
	}
	// And the next line D writes links to it, so the receiver joins them.
	next, err := D.LogLinked(windowEvent("D-next"))
	if err != nil || next == nil || next.PrevHash != link.LineHash {
		t.Errorf("D's next link = %+v, err %v; want prev_hash = %s", next, err, link.LineHash)
	}
}

// TestLogLinked_LostEventReturnsNoLink: when every retry is outrun the
// event is in no file, LogLinked reports the loss, and returns no link.
func TestLogLinked_LostEventReturnsNoLink(t *testing.T) {
	D, H, logPath := windowFixture(t)
	t.Cleanup(func() { afterReappendFollow = nil })

	afterDegradedFollow = func() {
		afterDegradedFollow = nil
		rotateOnce(t, H, logPath, "H-mid-1")
		fillToRotationThreshold(t, H, logPath)
		rotateOnce(t, H, logPath, "H-mid-2")
	}
	afterReappendFollow = func(attempt int) {
		rotateTwice(t, H, logPath, fmt.Sprintf("H-retry%d", attempt))
	}
	var link *ChainLink
	var err error
	_ = captureStderr(t, func() { link, err = D.LogLinked(windowEvent("D-in-window")) })
	if err == nil {
		t.Fatal("control: LogLinked reported no loss; the fixture did not exhaust the retries")
	}
	if got := countIn(logPath, "D-in-window") + countIn(logPath+rotatedSuffix, "D-in-window"); got != 0 {
		t.Fatalf("control: D-in-window occurs %d times in retained files", got)
	}
	if link != nil {
		t.Errorf("lost event returned link %+v, want nil", *link)
	}
}
