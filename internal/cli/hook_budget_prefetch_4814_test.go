package cli

// #4814 item 5: a shell call that has not published its data labels by half
// its budget starts the watchdog's own read of them then (prefetchLabels), so
// a budget answer waits on a read already done instead of starting one on
// its tail, where a busy host ran it past budgetLabelReadLimit and the record
// withheld the command. What is withheld, when and why is #4805's; only when
// the read starts changes.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/route"
)

// recordReads points hookLabelReadSeen at a list for the rest of the test.
func recordReads(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var reads []string
	prev := hookLabelReadSeen
	hookLabelReadSeen = func(by string) {
		mu.Lock()
		reads = append(reads, by)
		mu.Unlock()
	}
	t.Cleanup(func() { hookLabelReadSeen = prev })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), reads...)
	}
}

// setSlowPoints sets hookSlowPoints for the rest of the test.
func setSlowPoints(t *testing.T, points map[string]time.Duration) {
	t.Helper()
	prev := hookSlowPoints
	hookSlowPoints = points
	t.Cleanup(func() { hookSlowPoints = prev })
}

// TestHookBudgetPrefetch_ReadsOnlyWhenTheAnswerNeedsIt_4814: at half the
// budget the prefetch reads the labels only when nothing has published them
// and nobody holds the call. Published labels are what the answer uses; an
// evaluation that claimed the call answers itself; a watchdog that holds it
// reads for itself.
func TestHookBudgetPrefetch_ReadsOnlyWhenTheAnswerNeedsIt_4814(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, c := range []struct {
		name   string
		before func(b *hookBudget)
		want   []string
	}{
		// Control: the one state that reads.
		{"nothing published, unclaimed", func(*hookBudget) {}, []string{"prefetch"}},
		{"labels published", func(b *hookBudget) { b.publishLabels(&recordLabels{}) }, nil},
		{"evaluation holds the call", func(b *hookBudget) { b.claimForEvaluation() }, nil},
		{"watchdog holds the call", func(b *hookBudget) { b.owner = budgetWatchdog }, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			reads := recordReads(t)
			b := &hookBudget{park: func() { t.Error("the evaluation parked") }}
			c.before(b)
			b.prefetchLabels()
			if got := reads(); !reflect.DeepEqual(got, c.want) {
				t.Errorf("reads %v, want %v", got, c.want)
			}
			if (b.prefetched != nil) != (c.want != nil) {
				t.Errorf("prefetched channel set = %v, want %v", b.prefetched != nil, c.want != nil)
			}
		})
	}
}

// TestHookBudgetPrefetch_AnswerWaitsOnThePrefetch_4814: the answer uses the
// prefetch's read and starts none of its own, waits for it within the read
// limit, and past the limit withholds on time, as #4805's answer did for its
// own read. With no prefetch it reads for itself.
//
// The limit here is 1 s, not budgetLabelReadLimit: each row's read is the
// slow point plus the real read of the embedded packs, which took over 60 ms
// on a loaded CI runner, so at 100 ms the "within the limit" row failed on
// main (e210c480). The rows test the wait and the bound, not this host's
// read speed.
func TestHookBudgetPrefetch_AnswerWaitsOnThePrefetch_4814(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const limit = time.Second
	prevLimit := hookLabelReadLimit
	hookLabelReadLimit = limit
	t.Cleanup(func() { hookLabelReadLimit = prevLimit })
	started := func(b *hookBudget) bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.prefetched != nil
	}
	for _, c := range []struct {
		name         string
		read         time.Duration // the read's own time (the read-labels point)
		prefetch     bool
		wantWithheld bool
		wantReads    []string
	}{
		{"prefetch done before the answer", 0, true, false, []string{"prefetch"}},
		{"prefetch still reading, done within the limit", 40 * time.Millisecond, true, false, []string{"prefetch"}},
		{"prefetch still reading past the limit", 4 * time.Second, true, true, []string{"prefetch"}},
		{"no prefetch: the answer reads for itself", 0, false, false, []string{"watchdog"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			reads := recordReads(t)
			setSlowPoints(t, map[string]time.Duration{"read-labels": c.read})
			b := &hookBudget{}
			if c.prefetch {
				done := make(chan struct{})
				go func() { b.prefetchLabels(); close(done) }()
				// Registered after recordReads and setSlowPoints, so it runs
				// before they restore what the read still uses.
				t.Cleanup(func() { <-done })
				if c.read == 0 {
					<-done
				}
				for deadline := time.Now().Add(5 * time.Second); !started(b); time.Sleep(time.Millisecond) {
					if time.Now().After(deadline) {
						t.Fatal("the prefetch did not hand its read to the answer within 5 s")
					}
				}
			}
			b.mu.Lock()
			b.owner = budgetWatchdog
			b.mu.Unlock()
			start := time.Now()
			l := b.answerLabels(nil)
			took := time.Since(start)
			if (l.withheld != "") != c.wantWithheld {
				t.Errorf("withheld %q, want withheld = %v", l.withheld, c.wantWithheld)
			}
			if took > limit+time.Second {
				t.Errorf("the answer waited %s, past its %s limit", took, limit)
			}
			if got := reads(); !reflect.DeepEqual(got, c.wantReads) {
				t.Errorf("reads %v, want %v", got, c.wantReads)
			}
		})
	}
}

// TestHookBudgetPrefetch_HookStartsTheReadOnlyForASlowPolicyLoad_4814 runs
// the hook as Codex does and counts the label reads it starts (the test
// binary's read log): none when the policy publishes its labels before half
// the budget, none for a tool call, none on a fast call, and one prefetch
// (the control) when the policy load outlasts the budget.
func TestHookBudgetPrefetch_HookStartsTheReadOnlyForASlowPolicyLoad_4814(t *testing.T) {
	mcp := func(t *testing.T) string {
		return claudeShaped(t, "PreToolUse", "mcp__notes__append", map[string]interface{}{"text": "hello"}, map[string]interface{}{"turn_id": "turn-4814"})
	}
	for _, c := range []struct {
		name      string
		env       []string
		payload   func(t *testing.T) string
		want      []string
		scrubbed  bool // the record is the budget's, scrubbed with the labels
		fastCall  bool // the record is the evaluation's own
		toolCall  bool
		wantNotes string
	}{
		{name: "policy published before half the budget", env: budgetEnv("2s", "evaluate=4s"), want: nil, scrubbed: true},
		{name: "policy load past the budget (control)", env: budgetEnv("2s", "load=5s"), want: []string{"prefetch"}, scrubbed: true},
		{name: "tool call past the budget", env: budgetEnv("2s", "evaluate=5s"), payload: mcp, want: nil, toolCall: true},
		{name: "fast call, Codex's own budget", env: nil, want: nil, fastCall: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			wire := newWireCapture(t)
			home, configDir := newFailSafeHome(t, false, labelledPolicy4805)
			wire.enroll(t)
			log := filepath.Join(t.TempDir(), "reads")
			payload := codexPayload4805(t, labelCmd4805())
			if c.payload != nil {
				payload = c.payload(t)
			}
			r := runChild4805(t, home, configDir, wire, payload, append(c.env, envTestHookReadLog+"="+log)...)
			if got := readLog4814(t, log); !reflect.DeepEqual(got, c.want) {
				t.Errorf("label reads %v, want %v", got, c.want)
			}
			switch {
			case c.scrubbed:
				checkRecord4805(t, r, "AUDIT", "scrubbed", true)
			case c.fastCall:
				if strings.Contains(r.line+r.wireText(), labelValue4805()) || strings.Contains(r.line, withheldKind) || len(budgetNotesOf(r.line)) != 0 {
					t.Errorf("the fast call's record is not the evaluation's scrubbed one:\n%s", r.line)
				}
			case c.toolCall:
				if !strings.Contains(r.line, "analysis_budget_exceeded") {
					t.Errorf("the tool call was not answered by the budget:\n%s", r.line)
				}
			}
		})
	}
}

// budgetNotesOf reports the analysis_budget_exceeded mentions in a line.
func budgetNotesOf(line string) []string {
	var out []string
	for _, l := range strings.Split(line, "\n") {
		if strings.Contains(l, "analysis_budget_exceeded") {
			out = append(out, l)
		}
	}
	return out
}

// readLog4814 is the label reads a hook child started, in order.
func readLog4814(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(b))
}

// TestFailSafeRecord_PrefetchedLabels_CodexBudget_4814 is #4814 item 5's
// scenario: Codex's own budget (10 s timeout), a policy load that outlasts
// it, and a label read slower than budgetLabelReadLimit, as on a host whose
// CPUs are busy (about 130 ms there; 500 ms here, so the row does not depend
// on this host's load). Before #4814 the read started when the budget fired
// and ran past the limit, so both rows withheld the command. Now it starts
// at half the budget and is done when the budget fires: the no-label host
// records the command and the labelled host scrubs it, on time.
func TestFailSafeRecord_PrefetchedLabels_CodexBudget_4814(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out Codex's real budget")
	}
	cmd := labelCmd4805()
	for _, c := range []struct {
		name, policy string
	}{
		{"no labels", failSafePolicyGood},
		{"labels in policy.yaml", labelledPolicy4805},
	} {
		t.Run(c.name, func(t *testing.T) {
			wire := newWireCapture(t)
			home, configDir := newFailSafeHome(t, false, c.policy)
			wire.enroll(t)
			budget, timeout, ok := hookBudgetFor(route.Codex, len(cmd), true)
			if !ok {
				t.Fatal("Codex has no budget")
			}
			start := time.Now()
			r := runChild4805(t, home, configDir, wire, codexPayload4805(t, cmd), envTestHookSlow+"=load=30s,read-labels=500ms")
			took := time.Since(start)
			t.Logf("answered after %s (budget %s, timeout %s)", took, budget, timeout)
			if took < budget || took >= timeout {
				t.Errorf("answered after %s; want after the %s budget and before the %s timeout", took, budget, timeout)
			}
			if c.policy == labelledPolicy4805 {
				checkRecord4805(t, r, "AUDIT", "scrubbed", true)
				return
			}
			if r.decision != "AUDIT" || r.exit != 0 || len(r.wire) != 1 {
				t.Fatalf("decision %s exit %d wire entries %d, want the budget's AUDIT, exit 0, one entry", r.decision, r.exit, len(r.wire))
			}
			var line logger.AuditEvent
			if err := json.Unmarshal([]byte(strings.TrimSpace(r.line)), &line); err != nil {
				t.Fatalf("line: %v", err)
			}
			if got := fmt.Sprint(r.wire[0]["command"]); got != cmd || line.Command != cmd {
				t.Errorf("wire command %q, line command %q; want %q, as main records it on a no-label host", got, line.Command, cmd)
			}
			if strings.Contains(r.line+r.wireText(), withheldKind) {
				t.Errorf("a no-label host's record carries %s:\n%s", withheldKind, r.line)
			}
		})
	}
}
