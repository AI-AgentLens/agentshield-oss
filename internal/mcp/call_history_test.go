package mcp

import (
	"fmt"
	"sync"
	"testing"
)

// TestRecordAndHistory_EndsInTheRecordedCall: the history returned is the
// session up to and including the call just recorded, as a copy (#5011).
func TestRecordAndHistory_EndsInTheRecordedCall(t *testing.T) {
	var nilTracker *MCPCallHistoryTracker
	if h := nilTracker.RecordAndHistory("x", nil); h != nil {
		t.Errorf("nil tracker returned %v, want nil", h)
	}

	tr := NewMCPCallHistoryTracker()
	tr.Record("fetch_url", nil)
	h := tr.RecordAndHistory("shell", map[string]interface{}{"command": "ls"})
	if len(h) != 2 || h[0].ToolName != "fetch_url" || h[1].ToolName != "shell" {
		t.Fatalf("history = %v, want [fetch_url shell]", recordedToolNames(h))
	}
	h[1].ToolName = "tampered"
	if tr.History()[1].ToolName != "shell" {
		t.Error("RecordAndHistory must return a copy")
	}

	// Bounded like Record: the window keeps the newest callHistoryMax calls.
	for i := 0; i < callHistoryMax+5; i++ {
		tr.Record("noise", nil)
	}
	h = tr.RecordAndHistory("last", nil)
	if len(h) != callHistoryMax || h[len(h)-1].ToolName != "last" {
		t.Errorf("history len %d ending %q, want %d ending \"last\"", len(h), h[len(h)-1].ToolName, callHistoryMax)
	}
}

// TestRecordAndHistory_ConcurrentCallersEachSeeTheirOwnCallLast: Record then
// History is two steps, and a call another goroutine records in between becomes
// the last element. RecordAndHistory is one. Run with -race.
func TestRecordAndHistory_ConcurrentCallersEachSeeTheirOwnCallLast(t *testing.T) {
	const workers, perWorker = 16, 50
	tr := NewMCPCallHistoryTracker()
	var wg sync.WaitGroup
	var mu sync.Mutex
	wrong := 0
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				name := fmt.Sprintf("tool_%d_%d", w, i)
				h := tr.RecordAndHistory(name, nil)
				if len(h) == 0 || h[len(h)-1].ToolName != name {
					mu.Lock()
					wrong++
					mu.Unlock()
				}
			}
		}(w)
	}
	wg.Wait()
	if wrong != 0 {
		t.Errorf("%d of %d calls got a history ending in another call", wrong, workers*perWorker)
	}
	if got := len(tr.History()); got != callHistoryMax {
		t.Errorf("history len = %d, want %d", got, callHistoryMax)
	}
}

func recordedToolNames(h []RecordedCall) []string {
	out := make([]string, len(h))
	for i, c := range h {
		out[i] = c.ToolName
	}
	return out
}
