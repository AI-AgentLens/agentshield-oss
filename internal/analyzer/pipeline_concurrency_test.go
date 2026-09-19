package analyzer_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// TestPipelineEngineIsConcurrencySafe exercises the shape cmd/shield-server
// actually runs, which nothing tested before (#3285).
//
// server.go builds ONE engine via policy.NewEngineWithAnalyzers and shares it
// across concurrent HTTP requests, documenting that as safe: "that path is
// read-only after construction". #3286/#3542 made the two regex caches honour
// that sentence and guarded them — but both guards, and the concurrency test
// that shipped with them (policy.TestEngineEvaluateIsConcurrencySafe), run the
// REGEX-FALLBACK path over a three-rule hand-written policy. The pipeline path
// the server actually uses — eight analyzer stages over the full shipped rule
// corpus — had no concurrency coverage at all.
//
// That is the gap this closes. It is deliberately NOT a re-guard of the
// regexCache store: that store was unreachable (measured at 0 misses in
// 19,340,781 cachedRegex/compiledRegex calls across TestAccuracy and
// TestPipeline), so a concurrency probe cannot observe it, and the invariant
// assertions in regex_cache_readonly_test.go remain the primary guard. What
// this catches is a FUTURE change that makes some genuinely reachable part of
// the pipeline mutate shared state.
//
// Two independent failure signals, so the test is not merely "did it crash":
//
//  1. A concurrent map write is a runtime `fatal error`, which aborts the test
//     binary with or without -race. Reaching the end of the test is that
//     assertion.
//  2. Every verdict must match the single-threaded baseline. Shared state that
//     is corrupted without being a map write (a mutated slice, a reused buffer,
//     a stage-level memo) shows up as a WRONG DECISION, which -race alone can
//     miss and which matters more: a security gateway that returns ALLOW under
//     load because of a data race is worse than one that crashes.
//
// Signal 2 is what keeps this meaningful in CI, which runs `go test` without
// -race (.github/workflows/ci-cd.yml).
func TestPipelineEngineIsConcurrencySafe(t *testing.T) {
	engine := newPipelineEngine(t)

	// Commands come from the shipped corpus at RUNTIME and are never written
	// into this file. Two reasons: the corpus is the realistic input mix (all
	// kingdoms, every analyzer stage), and these are attack strings — pasting
	// them into source trips AgentShield's own dogfooding hooks.
	all := testdata.AllTestCases()
	if len(all) < 100 {
		t.Fatalf("vacuous: corpus has %d cases, too few to exercise the pipeline concurrently", len(all))
	}

	const sampleSize = 200
	stride := len(all) / sampleSize
	if stride < 1 {
		stride = 1
	}
	var commands []string
	for i := 0; i < len(all); i += stride {
		if c := all[i].Command; c != "" {
			commands = append(commands, c)
		}
	}
	if len(commands) < 50 {
		t.Fatalf("vacuous: sampled only %d commands from a corpus of %d", len(commands), len(all))
	}

	// Single-threaded baseline, taken before any goroutine starts.
	want := make([]string, len(commands))
	for i, c := range commands {
		want[i] = string(engine.Evaluate(c, nil).Decision)
	}

	// Denominator guard. If every sampled command produced the same verdict,
	// a no-op Evaluate would satisfy the comparison below and this test would
	// be a guard in name only.
	distinct := map[string]struct{}{}
	for _, d := range want {
		distinct[d] = struct{}{}
	}
	if len(distinct) < 2 {
		t.Fatalf("vacuous: all %d sampled commands returned the same decision (%v) — "+
			"the determinism assertion cannot distinguish a working engine from a broken one",
			len(commands), distinct)
	}
	t.Logf("sampled %d commands from %d corpus cases; %d distinct baseline decisions",
		len(commands), len(all), len(distinct))

	const goroutines = 12

	var wg sync.WaitGroup
	mismatches := make(chan string, goroutines*len(commands))
	start := make(chan struct{})

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			<-start // maximise overlap: all goroutines enter Evaluate together
			for i := range commands {
				// Offset per goroutine so they work on different commands at
				// the same moment rather than marching in lockstep.
				idx := (i + g) % len(commands)
				got := string(engine.Evaluate(commands[idx], nil).Decision)
				if got != want[idx] {
					mismatches <- fmt.Sprintf(
						"goroutine %d: command #%d returned %s under concurrency, want %s (single-threaded)",
						g, idx, got, want[idx])
				}
			}
		}(g)
	}
	close(start)
	wg.Wait()
	close(mismatches)

	n := 0
	for m := range mismatches {
		if n < 10 {
			t.Error(m)
		}
		n++
	}
	if n > 0 {
		t.Fatalf("%d/%d concurrent evaluations disagreed with the single-threaded baseline — "+
			"Engine.Evaluate is NOT safe to share across goroutines on the analyzer-pipeline "+
			"path, which is the path cmd/shield-server shares across HTTP requests (#3285)",
			n, goroutines*len(commands))
	}
}
