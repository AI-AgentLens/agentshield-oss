package policy

import (
	"sync"
	"testing"
)

// The regex cache must be read-only after construction (#3286).
//
// cmd/shield-server shares ONE *policy.Engine across concurrent HTTP requests
// and documents that as safe: "that path is read-only after construction
// (regex caches are fully precompiled in the constructors)". That sentence was
// true of the constructors and false of compiledRegex, which wrote to the map
// on its miss path. Nothing enforced it and nothing tested it.
//
// WHY THIS IS NOT A `-race` TEST. Two reasons, and both matter:
//
//  1. CI runs `go test` without `-race` (.github/workflows/ci-cd.yml), so a
//     race-detector-only guard would never run where it counts.
//  2. More importantly, a concurrency test here would be VACUOUS. The store was
//     unreachable — every pattern a caller passes is pre-compiled in NewEngine
//     — so hammering Evaluate from N goroutines passes identically with and
//     without the bug. It would look like a guard and prove nothing, which is
//     the exact failure shape this repo keeps cataloguing.
//
// So the guard asserts the INVARIANT (calling compiledRegex never grows the
// map) rather than trying to observe its violation. That fails deterministically
// the moment someone re-adds the store, on the first run, without -race.
func TestEngineRegexCacheIsReadOnlyAfterConstruction(t *testing.T) {
	pol := &Policy{
		Version: "0.1",
		Rules: []Rule{{
			ID:       "t-regex",
			Match:    Match{CommandRegex: `^echo\s+hello$`},
			Decision: DecisionBlock,
		}},
	}
	eng, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	before := len(eng.regexCache)
	if before == 0 {
		// Denominator guard: if the constructor stopped pre-compiling, the
		// assertion below would hold trivially while the property it protects
		// had already been lost.
		t.Fatal("vacuous: NewEngine pre-compiled nothing, so this test cannot detect a cache write")
	}

	// A syntactically valid pattern that no rule declares, i.e. the miss path.
	// It compiles, so execution reaches the point where the store used to be.
	if m := eng.compiledRegex(`^never-declared-by-any-rule-[0-9]+$`); m == nil {
		t.Fatal("setup: the probe pattern must compile, or the miss path is not exercised")
	}

	if after := len(eng.regexCache); after != before {
		t.Errorf("compiledRegex grew regexCache from %d to %d entries — the cache is no "+
			"longer read-only after construction, so Engine.Evaluate is unsafe to share "+
			"across goroutines and cmd/shield-server can die with "+
			"`fatal error: concurrent map writes` (#3286)", before, after)
	}
}

// TestEngineEvaluateIsConcurrencySafe is the defence-in-depth half: it exercises
// the shape cmd/shield-server actually runs — one engine, many goroutines.
//
// It cannot catch the unreachable store above (see the comment there), so it is
// deliberately not the primary guard. What it does catch is a FUTURE change that
// makes some genuinely reachable part of Evaluate mutate shared state: a
// concurrent map write is a runtime `fatal error`, which aborts the test binary
// with or without -race.
func TestEngineEvaluateIsConcurrencySafe(t *testing.T) {
	pol := &Policy{
		Version:  "0.1",
		Defaults: Defaults{Decision: DecisionAudit},
		Rules: []Rule{
			{ID: "t-regex", Match: Match{CommandRegex: `^rm\s+-rf\s+/$`}, Decision: DecisionBlock},
			{ID: "t-prefix", Match: Match{CommandPrefix: []string{"git status"}}, Decision: DecisionAllow},
			{ID: "t-excl", Match: Match{CommandRegex: `^curl\s`, CommandRegexExclude: `localhost`}, Decision: DecisionBlock},
		},
	}
	eng, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	commands := []string{
		"rm -rf /",
		"git status --short",
		"curl https://example.com",
		"curl https://localhost:8080/health",
		"echo hello",
	}

	const goroutines = 16
	const iterations = 200

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				eng.Evaluate(commands[(g+i)%len(commands)], nil)
			}
		}(g)
	}
	wg.Wait()

	// Reaching here without a fatal error is the assertion. Also confirm the
	// engine still answers correctly, so a no-op Evaluate could not pass this.
	if got := eng.Evaluate("rm -rf /", nil).Decision; got != DecisionBlock {
		t.Errorf("after concurrent use, Evaluate(%q) = %v, want %v", "rm -rf /", got, DecisionBlock)
	}
}
