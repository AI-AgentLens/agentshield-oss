package mcp

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// --- extractFetchResource ---

func TestExtractFetchResource(t *testing.T) {
	tests := []struct {
		name          string
		args          map[string]interface{}
		wantHost      string
		wantNamespace string
		wantResource  string
		wantOK        bool
	}{
		{
			name:          "url with two path segments",
			args:          map[string]interface{}{"url": "https://huggingface.co/attacker/char-a/resolve/main/config.json"},
			wantHost:      "huggingface.co",
			wantNamespace: "attacker",
			wantResource:  "char-a",
			wantOK:        true,
		},
		{
			name:          "uri argument fallback",
			args:          map[string]interface{}{"uri": "https://github.com/torvalds/linux"},
			wantHost:      "github.com",
			wantNamespace: "torvalds",
			wantResource:  "linux",
			wantOK:        true,
		},
		{
			name:          "path argument fallback",
			args:          map[string]interface{}{"path": "https://registry.npmjs.org/@scope/pkg"},
			wantHost:      "registry.npmjs.org",
			wantNamespace: "@scope",
			wantResource:  "pkg",
			wantOK:        true,
		},
		{
			name:   "single path segment — no namespace to track",
			args:   map[string]interface{}{"url": "https://example.com/about"},
			wantOK: false,
		},
		{
			name:   "no path — bare host",
			args:   map[string]interface{}{"url": "https://example.com/"},
			wantOK: false,
		},
		{
			name:   "no url/uri/path argument",
			args:   map[string]interface{}{"query": "hello"},
			wantOK: false,
		},
		{
			name:   "not a URL (no host)",
			args:   map[string]interface{}{"url": "/local/relative/path"},
			wantOK: false,
		},
		{
			name:          "host is case-folded",
			args:          map[string]interface{}{"url": "https://HuggingFace.CO/org/repo"},
			wantHost:      "huggingface.co",
			wantNamespace: "org",
			wantResource:  "repo",
			wantOK:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, ns, res, ok := extractFetchResource(tt.args)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if host != tt.wantHost || ns != tt.wantNamespace || res != tt.wantResource {
				t.Errorf("got (%q, %q, %q), want (%q, %q, %q)", host, ns, res, tt.wantHost, tt.wantNamespace, tt.wantResource)
			}
		})
	}
}

// --- isFetchTool ---

func TestIsFetchTool(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"WebFetch", true}, // Claude Code's built-in tool name
		{"web_fetch", true},
		{"web-fetch", true},
		{"fetch_url", true},
		{"http_get", true},
		{"read_resource", true},
		{"write_file", false},
		{"delete_file", false},
		{"send_email", false},
	}
	for _, tt := range tests {
		if got := isFetchTool(tt.name); got != tt.want {
			t.Errorf("isFetchTool(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// --- looksEnumerable ---

func TestLooksEnumerable(t *testing.T) {
	tests := []struct {
		name      string
		resources []string
		want      bool
	}{
		{
			name:      "char-a..char-e template",
			resources: []string{"char-a", "char-b", "char-c", "char-d", "char-e"},
			want:      true,
		},
		{
			name:      "bare single characters",
			resources: []string{"a", "b", "c", "d", "e"},
			want:      true,
		},
		{
			name:      "real project names — no common template",
			resources: []string{"django", "flask", "pytest", "numpy", "requests"},
			want:      false,
		},
		{
			name:      "related microservice repos — long suffixes",
			resources: []string{"microservice-auth", "microservice-billing", "microservice-gateway", "microservice-inventory", "microservice-search"},
			want:      false,
		},
		{
			name:      "mostly enumerable with one long outlier stays below 80%",
			resources: []string{"char-a", "char-b", "char-c", "documentation-overview"},
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksEnumerable(tt.resources); got != tt.want {
				t.Errorf("looksEnumerable(%v) = %v, want %v", tt.resources, got, tt.want)
			}
		})
	}
}

// --- FetchDiversityTracker ---

func fetchArgs(pathSuffix string) map[string]interface{} {
	return map[string]interface{}{"url": "https://huggingface.co/attacker/" + pathSuffix}
}

// TestFetchDiversityTracker_EnumerableFiresAtThreshold verifies the stronger
// BLOCK-tier signal fires exactly once distinct enumerable-named resources
// under one namespace reach fetchDiversityEnumerableThreshold.
func TestFetchDiversityTracker_EnumerableFiresAtThreshold(t *testing.T) {
	tr := NewFetchDiversityTracker()
	names := []string{"char-a", "char-b", "char-c", "char-d", "char-e", "char-f"}
	var fires int
	for i, n := range names[:fetchDiversityEnumerableThreshold] {
		sig := tr.Scan("WebFetch", fetchArgs(n+"/resolve/main/config.json"))
		tr.Record("WebFetch", fetchArgs(n+"/resolve/main/config.json"))
		if sig == SignalFetchEnumerablePattern {
			fires++
			if i != fetchDiversityEnumerableThreshold-1 {
				t.Errorf("fired early on fetch %d (want fire only at %d)", i, fetchDiversityEnumerableThreshold-1)
			}
		} else if sig != "" {
			t.Errorf("fetch %d: unexpected signal %q", i, sig)
		}
	}
	if fires != 1 {
		t.Errorf("expected exactly one enumerable-pattern fire, got %d", fires)
	}
}

// TestFetchDiversityTracker_BurstFiresWithoutEnumerableNaming verifies the
// weaker AUDIT-tier signal fires when cardinality alone crosses the burst
// threshold with names that do NOT look enumerable (so the enumerable-tier
// BLOCK check never trips first).
func TestFetchDiversityTracker_BurstFiresWithoutEnumerableNaming(t *testing.T) {
	tr := NewFetchDiversityTracker()
	names := []string{"llama-3-8b-instruct", "mistral-7b-v0.3", "gemma-2-9b-it", "phi-3-medium",
		"qwen2-7b-chat", "falcon-40b-instruct", "starcoder2-15b", "codellama-34b"}
	if len(names) != fetchDiversityBurstThreshold {
		t.Fatalf("test setup: need exactly %d names, got %d", fetchDiversityBurstThreshold, len(names))
	}
	var sig FetchDiversitySignal
	for _, n := range names {
		sig = tr.Scan("WebFetch", fetchArgs(n+"/resolve/main/config.json"))
		tr.Record("WebFetch", fetchArgs(n+"/resolve/main/config.json"))
	}
	if sig != SignalFetchDiversityBurst {
		t.Errorf("expected burst signal on the final fetch, got %q", sig)
	}
}

// TestFetchDiversityTracker_BelowThresholdNoFire ensures ordinary occasional
// multi-repo fetching (well under either threshold) never fires.
func TestFetchDiversityTracker_BelowThresholdNoFire(t *testing.T) {
	tr := NewFetchDiversityTracker()
	names := []string{"llama-3-8b", "mistral-7b", "gemma-2-9b"}
	for _, n := range names {
		if sig := tr.Scan("WebFetch", fetchArgs(n)); sig != "" {
			t.Fatalf("fetch %q: unexpected signal %q below threshold", n, sig)
		}
		tr.Record("WebFetch", fetchArgs(n))
	}
}

// TestFetchDiversityTracker_RepeatedResourceNotCounted verifies re-fetching
// the SAME resource repeatedly never grows the distinct-resource cardinality.
func TestFetchDiversityTracker_RepeatedResourceNotCounted(t *testing.T) {
	tr := NewFetchDiversityTracker()
	for i := 0; i < fetchDiversityBurstThreshold+5; i++ {
		if sig := tr.Scan("WebFetch", fetchArgs("same-repo")); sig != "" {
			t.Fatalf("iteration %d: repeated single resource must never fire, got %q", i, sig)
		}
		tr.Record("WebFetch", fetchArgs("same-repo"))
	}
}

// TestFetchDiversityTracker_DifferentNamespaceNotCounted verifies distinct
// resources under DIFFERENT namespaces on the same host don't combine into
// one tally — the attack's namespace confinement is load-bearing.
func TestFetchDiversityTracker_DifferentNamespaceNotCounted(t *testing.T) {
	tr := NewFetchDiversityTracker()
	for i := 0; i < fetchDiversityBurstThreshold+5; i++ {
		args := map[string]interface{}{"url": "https://huggingface.co/org-" + string(rune('a'+i)) + "/repo"}
		if sig := tr.Scan("WebFetch", args); sig != "" {
			t.Fatalf("iteration %d: distinct namespaces must never combine into one tally, got %q", i, sig)
		}
		tr.Record("WebFetch", args)
	}
}

// TestFetchDiversityTracker_NonFetchToolIgnored verifies calls to tools that
// aren't fetch-shaped never contribute to or trigger tracking.
func TestFetchDiversityTracker_NonFetchToolIgnored(t *testing.T) {
	tr := NewFetchDiversityTracker()
	for i := 0; i < fetchDiversityBurstThreshold+5; i++ {
		args := map[string]interface{}{"url": "https://huggingface.co/attacker/char-" + string(rune('a'+i))}
		if sig := tr.Scan("write_file", args); sig != "" {
			t.Fatalf("iteration %d: non-fetch tool must never fire, got %q", i, sig)
		}
		tr.Record("write_file", args)
	}
	// Confirm nothing was recorded: a subsequent real fetch call starts clean.
	if sig := tr.Scan("WebFetch", fetchArgs("char-z")); sig != "" {
		t.Errorf("non-fetch calls must not have polluted history, got %q", sig)
	}
}

// TestFetchDiversityTracker_NilSafe verifies a nil tracker no-ops rather than
// panicking, matching every other optional MessageHandler tracker.
func TestFetchDiversityTracker_NilSafe(t *testing.T) {
	var tr *FetchDiversityTracker
	if sig := tr.Scan("WebFetch", fetchArgs("char-a")); sig != "" {
		t.Errorf("nil tracker Scan must return \"\", got %q", sig)
	}
	tr.Record("WebFetch", fetchArgs("char-a")) // must not panic
}

// --- Authored YAML rule resolution ---

// TestFetchDiversityRules_EvaluateCorrectDecisions validates both authored
// synthetic-tool rules resolve to their intended decision and do not match an
// unrelated real tool call.
func TestFetchDiversityRules_EvaluateCorrectDecisions(t *testing.T) {
	rules := loadPremiumPackRules(t, "mcp-agentic-attacks.yaml")
	burstRule := findRuleByID(t, rules, "mcp-agentic-audit-fetch-diversity-burst")
	enumerableRule := findRuleByID(t, rules, "mcp-agentic-block-fetch-enumerable-pattern")

	e := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules:    []MCPRule{*burstRule, *enumerableRule},
	})

	burstRes := e.EvaluateToolCall(syntheticFetchDiversityBurst, map[string]interface{}{"context": "burst"})
	if burstRes.Decision != policy.DecisionAudit {
		t.Errorf("synthetic burst tool should evaluate AUDIT; got %v", burstRes.Decision)
	}

	enumerableRes := e.EvaluateToolCall(syntheticFetchEnumerablePattern, map[string]interface{}{"context": "enumerable"})
	if enumerableRes.Decision != policy.DecisionBlock {
		t.Errorf("synthetic enumerable-pattern tool should evaluate BLOCK; got %v", enumerableRes.Decision)
	}

	benign := e.EvaluateToolCall("web_fetch", map[string]interface{}{"url": "https://huggingface.co/meta-llama/Llama-3-8B"})
	for _, id := range benign.TriggeredRules {
		if id == burstRule.ID || id == enumerableRule.ID {
			t.Error("fetch-diversity rules must only match their synthetic tool names")
		}
	}
}

// --- End-to-end HandleToolCall ---

// newFetchDiversityTestHandler builds a handler wired with a fresh
// FetchDiversityTracker plus the two authored composite rules loaded from
// their real YAML.
func newFetchDiversityTestHandler(t *testing.T) (*MessageHandler, *strings.Builder) {
	t.Helper()
	rules := loadPremiumPackRules(t, "mcp-agentic-attacks.yaml")
	burstRule := findRuleByID(t, rules, "mcp-agentic-audit-fetch-diversity-burst")
	enumerableRule := findRuleByID(t, rules, "mcp-agentic-block-fetch-enumerable-pattern")

	policyDef := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules:    []MCPRule{*burstRule, *enumerableRule},
	}

	var buf strings.Builder
	return &MessageHandler{
		Evaluator:      NewPolicyEvaluator(policyDef),
		Stderr:         &buf,
		FetchDiversity: NewFetchDiversityTracker(),
	}, &buf
}

// TestHandleToolCall_FetchEnumerablePattern_Blocks drives HandleToolCall
// end-to-end with the exact CVE-2026-54316 PoC shape (single-character-name
// repos under one namespace) and confirms the call that completes the
// threshold is BLOCKed.
func TestHandleToolCall_FetchEnumerablePattern_Blocks(t *testing.T) {
	h, buf := newFetchDiversityTestHandler(t)
	names := []string{"char-a", "char-p", "char-i", "char-e", "char-r"}
	if len(names) != fetchDiversityEnumerableThreshold {
		t.Fatalf("test setup: need exactly %d names, got %d", fetchDiversityEnumerableThreshold, len(names))
	}

	for i, n := range names[:len(names)-1] {
		msg := toolCallMessage(t, "WebFetch", fetchArgs(n+"/resolve/main/config.json"), nil)
		if blocked, _ := h.HandleToolCall(msg); blocked {
			t.Fatalf("fetch %d (%s) unexpectedly blocked before threshold", i, n)
		}
	}

	final := toolCallMessage(t, "WebFetch", fetchArgs(names[len(names)-1]+"/resolve/main/config.json"), nil)
	blocked, resp := h.HandleToolCall(final)
	if !blocked {
		t.Fatalf("expected the threshold-completing fetch to be BLOCKed, got not-blocked. stderr:\n%s", buf.String())
	}
	if resp == nil {
		t.Error("expected a non-nil block response")
	}
	if !strings.Contains(buf.String(), "fetch-diversity composite") {
		t.Errorf("expected fetch-diversity composite audit line, got:\n%s", buf.String())
	}
}

// TestHandleToolCall_FetchDiversityBurst_Audits verifies the weaker
// cardinality-only signal reaches AUDIT (not BLOCK) end-to-end when resource
// names do not look enumerable.
func TestHandleToolCall_FetchDiversityBurst_Audits(t *testing.T) {
	h, buf := newFetchDiversityTestHandler(t)
	names := []string{"llama-3-8b-instruct", "mistral-7b-v0.3", "gemma-2-9b-it", "phi-3-medium",
		"qwen2-7b-chat", "falcon-40b-instruct", "starcoder2-15b", "codellama-34b"}
	if len(names) != fetchDiversityBurstThreshold {
		t.Fatalf("test setup: need exactly %d names, got %d", fetchDiversityBurstThreshold, len(names))
	}

	var lastBlocked bool
	for _, n := range names {
		msg := toolCallMessage(t, "WebFetch", fetchArgs(n+"/resolve/main/config.json"), nil)
		lastBlocked, _ = h.HandleToolCall(msg)
	}
	if lastBlocked {
		t.Fatal("burst-only (non-enumerable naming) signal must AUDIT, not BLOCK")
	}
	if !strings.Contains(buf.String(), "fetch-diversity composite") {
		t.Errorf("expected fetch-diversity composite audit line, got:\n%s", buf.String())
	}
}

// TestHandleToolCall_FetchDiversity_OrdinaryUsageNotFlagged verifies a small
// number of ordinary WebFetch calls to different, unrelated hosts is never
// flagged — the common case must stay quiet.
func TestHandleToolCall_FetchDiversity_OrdinaryUsageNotFlagged(t *testing.T) {
	h, buf := newFetchDiversityTestHandler(t)
	urls := []string{
		"https://docs.python.org/3/library/os.html",
		"https://github.com/golang/go/blob/master/README.md",
		"https://pypi.org/project/requests/",
	}
	for _, u := range urls {
		msg := toolCallMessage(t, "WebFetch", map[string]interface{}{"url": u}, nil)
		if blocked, _ := h.HandleToolCall(msg); blocked {
			t.Fatalf("ordinary fetch to %s unexpectedly blocked", u)
		}
	}
	if strings.Contains(buf.String(), "fetch-diversity composite") {
		t.Errorf("ordinary low-volume fetching across unrelated namespaces must not be flagged, got:\n%s", buf.String())
	}
}

// TestHandleToolCall_FetchDiversity_NilTrackerNoOp verifies a nil tracker on
// the handler no-ops rather than panicking.
func TestHandleToolCall_FetchDiversity_NilTrackerNoOp(t *testing.T) {
	h := &MessageHandler{
		Evaluator: NewPolicyEvaluator(&MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAllow}}),
		Stderr:    &strings.Builder{},
	}
	msg := toolCallMessage(t, "WebFetch", fetchArgs("char-a"), nil)
	if blocked, _ := h.HandleToolCall(msg); blocked {
		t.Fatal("nil FetchDiversity tracker must not block")
	}
}
