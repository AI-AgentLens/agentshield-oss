package mcp

import "testing"

// Regression tests for #3740 -- the post-merge review of #3727. #3727 made every
// folded candidate of a colliding argument name VISIBLE to the five fixed-key
// sites, which is the fail-closed direction for a STATELESS predicate. Three
// places were still not monotonic in that direction: a candidate could SUPPRESS
// a detection the same session produces without it.
//
// Every case carries a VACUITY control: the same session WITHOUT the colliding
// candidate must produce the signal, or the regression measures nothing.

// --- finding 1: a decoy candidate must not suppress the enumerable BLOCK ---

// fetchRes is a (host, namespace, resource) URL under one attacker namespace.
func fetchRes(name string) string {
	return "https://huggingface.co/attacker/" + name + "/resolve/main/config.json"
}

var enumerableNames = []string{"char-a", "char-b", "char-c", "char-d", "char-e"}

// TestFetchDiversityDecoy_DoesNotSuppressEnumerableBlock is the #3740 finding-1
// regression. Each call carries TWO disguised spellings of `url`: a constant
// non-enumerable decoy (`/attacker/documentation`) that sorts FIRST, and the
// varying enumerable resource that sorts second. Before the fix the decoy joined
// history, commonStringPrefix collapsed to "", and the fifth fetch produced no
// signal at all.
//
// Putting the decoy FIRST is deliberate: it also kills the suspected mutation
// "truncate FetchDiversityTracker.Record to its first candidate" (#3740 item 5),
// which would keep the enumerable resources out of history entirely.
func TestFetchDiversityDecoy_DoesNotSuppressEnumerableBlock(t *testing.T) {
	nbsp := sepRune(0x00A0) // sorts before U+200D
	zwj := sepRune(0x200D)
	if len(enumerableNames) != fetchDiversityEnumerableThreshold {
		t.Fatalf("test setup: need exactly %d enumerable names, got %d",
			fetchDiversityEnumerableThreshold, len(enumerableNames))
	}

	// VACUITY CONTROL: the same five resources with no decoy must BLOCK, or the
	// case below cannot distinguish "the decoy suppressed it" from "it never fires".
	t.Run("control/five varying alone still BLOCKs", func(t *testing.T) {
		tr := NewFetchDiversityTracker()
		var last FetchDiversitySignal
		for _, n := range enumerableNames {
			args := map[string]interface{}{"url": fetchRes(n)}
			last = tr.Scan("fetch_url", args)
			tr.Record("fetch_url", args)
		}
		if last != SignalFetchEnumerablePattern {
			t.Fatalf("control: five varying enumerable resources gave %q, want %q",
				last, SignalFetchEnumerablePattern)
		}
	})

	t.Run("constant decoy must not suppress the BLOCK", func(t *testing.T) {
		tr := NewFetchDiversityTracker()
		var last FetchDiversitySignal
		for _, n := range enumerableNames {
			args := map[string]interface{}{
				"url" + nbsp: fetchRes("documentation"), // constant, non-enumerable, sorts first
				"url" + zwj:  fetchRes(n),               // the varying enumerable stream
			}
			last = tr.Scan("fetch_url", args)
			tr.Record("fetch_url", args)
		}
		if last != SignalFetchEnumerablePattern {
			t.Fatalf("decoy suppressed detection: got %q, want %q — an unrelated candidate must not invalidate the cluster",
				last, SignalFetchEnumerablePattern)
		}
	})

	t.Run("negative control/decoy alone does not BLOCK", func(t *testing.T) {
		tr := NewFetchDiversityTracker()
		var last FetchDiversitySignal
		for range enumerableNames {
			args := map[string]interface{}{"url": fetchRes("documentation")}
			last = tr.Scan("fetch_url", args)
			tr.Record("fetch_url", args)
		}
		if last != "" {
			t.Fatalf("negative control: repeated fetches of ONE resource gave %q, want no signal", last)
		}
	})
}

// TestEnumerableClusterSize pins the per-candidate cluster semantics the #3740
// finding-1 fix chose, including the false-positive guards: the cluster is
// derived from the ANCHOR's own template, so ordinary long resource names under
// one namespace still cluster with nothing.
func TestEnumerableClusterSize(t *testing.T) {
	cases := []struct {
		name      string
		resources []string
		anchor    string
		want      int
	}{
		{
			name:      "the PoC template",
			resources: []string{"char-a", "char-b", "char-c", "char-d", "char-e"},
			anchor:    "char-e",
			want:      5,
		},
		{
			name:      "a decoy does not shrink the cluster",
			resources: []string{"char-a", "char-b", "char-c", "char-d", "char-e", "documentation"},
			anchor:    "char-e",
			want:      5,
		},
		{
			name:      "the decoy itself clusters with nothing",
			resources: []string{"char-a", "char-b", "char-c", "char-d", "char-e", "documentation"},
			anchor:    "documentation",
			want:      1,
		},
		{
			name:      "bare single characters, the PoC's other spelling",
			resources: []string{"a", "b", "c", "d", "e"},
			anchor:    "e",
			want:      5,
		},
		{
			name:      "ordinary model names cluster with nothing",
			resources: []string{"llama-3-8b-instruct", "mistral-7b-v0.3", "gemma-2-9b-it", "phi-3-medium", "qwen2-7b-chat"},
			anchor:    "qwen2-7b-chat",
			want:      1,
		},
		{
			name:      "long shared prefix with long tails does not cluster",
			resources: []string{"microservice-auth", "microservice-billing", "microservice-gateway", "microservice-inventory", "microservice-search"},
			anchor:    "microservice-search",
			want:      1,
		},
		{
			name:      "a lone resource is its own cluster of one",
			resources: []string{"char-a"},
			anchor:    "char-a",
			want:      1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := enumerableClusterSize(tc.resources, tc.anchor); got != tc.want {
				t.Errorf("enumerableClusterSize(%v, %q) = %d, want %d", tc.resources, tc.anchor, got, tc.want)
			}
		})
	}
}
