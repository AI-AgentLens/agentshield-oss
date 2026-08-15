package mcp

import (
	"regexp"
	"sync"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// TestCachedRegexp_ReturnsSameInstance pins the core invariant: two calls
// for the same pattern return the exact same compiled *regexp.Regexp
// pointer. If a future refactor accidentally drops the sync.Map and we
// fall back to per-call regexp.Compile, this test fails.
func TestCachedRegexp_ReturnsSameInstance(t *testing.T) {
	clearRegexCacheForTest()
	pattern := `^test_(read|write)_file$`

	r1, err := cachedRegexp(pattern)
	if err != nil {
		t.Fatalf("cachedRegexp(%q) returned error: %v", pattern, err)
	}
	r2, err := cachedRegexp(pattern)
	if err != nil {
		t.Fatalf("second cachedRegexp(%q) returned error: %v", pattern, err)
	}
	if r1 != r2 {
		t.Fatalf("cachedRegexp must return the cached pointer; got %p and %p", r1, r2)
	}
}

// TestCachedRegexp_DifferentPatternsIsolated guards against a hash-collision
// or key-mixup bug in the cache: different patterns must yield different
// compiled regexes (and obviously different match semantics).
func TestCachedRegexp_DifferentPatternsIsolated(t *testing.T) {
	clearRegexCacheForTest()

	r1, err := cachedRegexp(`^foo$`)
	if err != nil {
		t.Fatalf("cachedRegexp(^foo$): %v", err)
	}
	r2, err := cachedRegexp(`^bar$`)
	if err != nil {
		t.Fatalf("cachedRegexp(^bar$): %v", err)
	}
	if r1 == r2 {
		t.Fatal("different patterns must compile to different cached entries")
	}
	if r1.MatchString("bar") {
		t.Error("^foo$ must not match \"bar\"")
	}
	if !r2.MatchString("bar") {
		t.Error("^bar$ must match \"bar\"")
	}
}

// TestCachedRegexp_MalformedPatternCached verifies that bad patterns
// return an error AND the error is itself cached (so repeated bad input
// doesn't re-attempt regexp.Compile every time).
func TestCachedRegexp_MalformedPatternCached(t *testing.T) {
	clearRegexCacheForTest()
	bad := `(unclosed`

	_, err1 := cachedRegexp(bad)
	if err1 == nil {
		t.Fatal("expected compile error for malformed pattern")
	}
	_, err2 := cachedRegexp(bad)
	if err2 == nil {
		t.Fatal("expected compile error on second call too")
	}
	if err1.Error() != err2.Error() {
		t.Fatalf("cached error mismatch: first=%q second=%q", err1, err2)
	}
	// Sanity: should be a single cache entry, not two.
	count := 0
	regexCache.Range(func(k, v interface{}) bool {
		if k.(string) == bad {
			count++
		}
		return true
	})
	if count != 1 {
		t.Errorf("malformed pattern must produce exactly one cache entry, got %d", count)
	}
}

// TestCachedRegexp_ConcurrentSafety hammers the cache from many goroutines
// to flush out any data-race regression introduced by future refactoring.
// Run with `go test -race` to be useful — the cache is a sync.Map which
// is safe by construction, but a refactor to (e.g.) a plain map + RWMutex
// could regress this.
func TestCachedRegexp_ConcurrentSafety(t *testing.T) {
	clearRegexCacheForTest()
	patterns := []string{
		`^read_[a-z]+$`,
		`^write_[0-9]+_(file|dir)$`,
		`https?://[^/]+/.*`,
		`(?i)(api|secret|token)_key`,
		`^get_.*_metadata$`,
	}

	var wg sync.WaitGroup
	const goroutines = 32
	const iter = 50
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iter; i++ {
				p := patterns[i%len(patterns)]
				re, err := cachedRegexp(p)
				if err != nil || re == nil {
					t.Errorf("cachedRegexp(%q) failed: re=%v err=%v", p, re, err)
					return
				}
				// Verify the cached regex still produces the same outcome
				// as a fresh compile, so a bad cache entry can't poison
				// the rest of the test.
				fresh := regexp.MustCompile(p)
				if re.MatchString("read_file") != fresh.MatchString("read_file") {
					t.Errorf("cached regex %q diverged from fresh compile", p)
				}
			}
		}()
	}
	wg.Wait()
}

// TestPolicyEvaluator_RegexEquivalence_BeforeAfterCache pins that the
// behavioral output of EvaluateToolCall is identical whether the regex
// is hot in the cache or compiled fresh on first call. If a future
// refactor of cachedRegexp accidentally returns a different regex flavor
// (e.g. POSIX vs Go's RE2), this test fails on the first matched rule.
func TestPolicyEvaluator_RegexEquivalence_BeforeAfterCache(t *testing.T) {
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules: []MCPRule{
			{
				ID:       "block-sql-tools",
				Match:    MCPMatch{ToolNameRegex: `^(query_|run_)?(sql|database).*`},
				Decision: policy.DecisionBlock,
				Reason:   "SQL tools blocked.",
			},
			{
				ID:       "audit-arg-secret",
				Match:    MCPMatch{ToolName: "fetch_url", ArgumentRegexPatterns: map[string]string{"url": `(?i)(secret|token|api[_-]?key)`}},
				Decision: policy.DecisionAudit,
				Reason:   "Secret-like URL flagged.",
			},
		},
	}
	clearRegexCacheForTest()
	evaluator := NewPolicyEvaluator(pol)

	// First call: cache is cold — exercises the Compile + Store path.
	res1 := evaluator.EvaluateToolCall("run_sql_admin", nil)
	if res1.Decision != policy.DecisionBlock {
		t.Fatalf("first eval: want BLOCK, got %s", res1.Decision)
	}
	// Second call: cache is hot — exercises the Load path. Must produce
	// the same decision and trigger the same rule.
	res2 := evaluator.EvaluateToolCall("run_sql_admin", nil)
	if res2.Decision != policy.DecisionBlock {
		t.Fatalf("second eval (cached): want BLOCK, got %s", res2.Decision)
	}
	if len(res1.TriggeredRules) != len(res2.TriggeredRules) ||
		(len(res1.TriggeredRules) > 0 && res1.TriggeredRules[0] != res2.TriggeredRules[0]) {
		t.Errorf("cached vs uncached eval triggered different rules: %v vs %v",
			res1.TriggeredRules, res2.TriggeredRules)
	}

	// Argument regex path — same cold-then-hot check.
	args := map[string]interface{}{"url": "https://example.com/?api_key=abc"}
	res3 := evaluator.EvaluateToolCall("fetch_url", args)
	res4 := evaluator.EvaluateToolCall("fetch_url", args)
	if res3.Decision != res4.Decision {
		t.Errorf("argument-regex cache divergence: cold=%s hot=%s", res3.Decision, res4.Decision)
	}
	if res3.Decision != policy.DecisionAudit {
		t.Errorf("expected AUDIT on api_key match; got %s (cold) %s (hot)",
			res3.Decision, res4.Decision)
	}
}

// BenchmarkPolicyEvaluator_RegexHeavy is a load-bearing perf signal for the
// cache. With 50 ToolNameRegex rules and the cache cold-then-hot, the hot
// run should be substantially faster than the cold run. Use `go test
// -bench=. -benchmem ./internal/mcp/` to inspect numbers; the actual ratio
// depends on regex complexity. The test exists so a future refactor that
// reintroduces per-call regexp.Compile shows up as an order-of-magnitude
// regression.
func BenchmarkPolicyEvaluator_RegexHeavy(b *testing.B) {
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
	}
	for i := 0; i < 50; i++ {
		pol.Rules = append(pol.Rules, MCPRule{
			ID:       "r-" + string(rune('a'+i%26)),
			Match:    MCPMatch{ToolNameRegex: `^prefix_[0-9]+_suffix_(read|write|delete)_.*$`},
			Decision: policy.DecisionAudit,
			Reason:   "bench",
		})
	}
	evaluator := NewPolicyEvaluator(pol)
	clearRegexCacheForTest()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = evaluator.EvaluateToolCall("prefix_42_suffix_read_anything", nil)
	}
}

// clearRegexCacheForTest empties the module-level regex cache so each test
// case starts from a known-clean state. Keep this test-only — production
// callers must never wipe the cache, since concurrent in-flight evaluations
// could see a transiently nil entry.
func clearRegexCacheForTest() {
	regexCache.Range(func(k, _ interface{}) bool {
		regexCache.Delete(k)
		return true
	})
}
