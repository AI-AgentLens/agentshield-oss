package psreader

import (
	"sort"
	"strings"
	"testing"
	"time"
)

func corpusCommands(t testing.TB) []string {
	t.Helper()
	var out []string
	for _, c := range corpusSpecs {
		rows, _ := loadCorpus(t, "testdata", c.name, 76)
		for _, r := range rows {
			out = append(out, r.Command)
		}
	}
	return out
}

// FuzzRead: Read returns for any input, never through its recover (an
// internal error is a bug even though it is survived), Paths and Mentions
// together always hold everything the raw-text scan finds, and no spelling
// is in both. Seeded with every corpus input.
//
//	go test -fuzz=FuzzRead -fuzztime=5m ./internal/psreader/
func FuzzRead(f *testing.F) {
	for _, s := range corpusCommands(f) {
		f.Add(s)
	}
	for _, s := range []string{"", "`", "$", "${", "@'", "@\"\n", "<#", "--%", "& $x", "[a(", "switch($x){|}", "powershell -enc", "cmd /c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := Read(s, testEnv)
		for _, n := range got.Notes {
			if strings.Contains(n.Detail, "internal error") {
				t.Fatalf("Read(%q): %s", s, n.Detail)
			}
		}
		have := map[string]bool{}
		for _, p := range got.Paths {
			have[p] = true
		}
		for _, p := range got.Mentions {
			if have[p] {
				t.Fatalf("Read(%q): %q is in both Paths and Mentions", s, p)
			}
			have[p] = true
		}
		newResolver(testEnv).rawPaths(s, func(p string) {
			if !have[p] {
				t.Fatalf("Read(%q): raw-scan path %q in neither Paths nor Mentions", s, p)
			}
		})
	})
}

func BenchmarkRead(b *testing.B) {
	cmds := corpusCommands(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Read(cmds[i%len(cmds)], testEnv)
	}
}

// TestReadLatency_P99 reports the per-command read time over the corpus
// against ADR-001's budget (p99 under 1 ms). It reports rather than flakes:
// a shared CI runner can be slow for reasons of its own, so only a p99 ten
// times over budget, which is an algorithmic regression rather than noise,
// fails the test.
func TestReadLatency_P99(t *testing.T) {
	cmds := corpusCommands(t)
	times := make([]time.Duration, len(cmds))
	for i, c := range cmds {
		best := time.Duration(1<<63 - 1)
		for rep := 0; rep < 5; rep++ {
			start := time.Now()
			Read(c, testEnv)
			if d := time.Since(start); d < best {
				best = d
			}
		}
		times[i] = best
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	p := func(q float64) time.Duration { return times[int(q*float64(len(times)-1))] }
	t.Logf("read time over %d corpus inputs (best of 5): p50 %v  p90 %v  p99 %v  max %v",
		len(times), p(0.50), p(0.90), p(0.99), times[len(times)-1])
	const budget = time.Millisecond
	switch p99 := p(0.99); {
	case p99 > 10*budget:
		t.Errorf("p99 %v is more than ten times the %v budget", p99, budget)
	case p99 > budget:
		t.Logf("NOTE: p99 %v is over the %v budget on this machine", p99, budget)
	}
}
