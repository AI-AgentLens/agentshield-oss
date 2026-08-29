package analyzer

import (
	"testing"
)

// Twin of TestEngineRegexCacheIsReadOnlyAfterConstruction in internal/policy.
//
// Both caches had the same dead store on their miss path, and fixing one while
// leaving the other is this repo's most-repeated latent trap: a match field
// wired to one evaluation path but not the other (#3232, #3234). The analyzer
// cache is reachable through the pipeline path, the engine cache through the
// regex-fallback path, and cmd/shield-server shares one engine across HTTP
// requests either way.
//
// See the policy-side test for why this asserts the invariant instead of
// running a `-race` concurrency probe: the store is unreachable, so a
// concurrency test would pass identically with and without the bug.
func TestRegexCacheIsReadOnlyAfterConstruction(t *testing.T) {
	a := NewRegexAnalyzer([]RegexRule{{
		ID:       "t-regex",
		Regex:    `^echo\s+hello$`,
		Decision: "BLOCK",
	}})

	before := len(a.regexCache)
	if before == 0 {
		// Denominator guard: without this, a constructor that stopped
		// pre-compiling would make the assertion below hold trivially while
		// the property it protects had already been lost.
		t.Fatal("vacuous: NewRegexAnalyzer pre-compiled nothing, so this test cannot detect a cache write")
	}

	// A valid pattern no rule declares — the miss path, which compiles and
	// therefore reaches the point where the store used to be.
	if m := a.cachedRegex(`^never-declared-by-any-rule-[0-9]+$`); m == nil {
		t.Fatal("setup: the probe pattern must compile, or the miss path is not exercised")
	}

	if after := len(a.regexCache); after != before {
		t.Errorf("cachedRegex grew regexCache from %d to %d entries — the cache is no longer "+
			"read-only after construction, so the analyzer pipeline is unsafe to share across "+
			"goroutines and cmd/shield-server can die with "+
			"`fatal error: concurrent map writes` (#3286)", before, after)
	}
}
