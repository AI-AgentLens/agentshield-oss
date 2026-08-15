package mcp

import "testing"

// rc is a terse RecordedCall constructor for tests.
func rc(tool string, args map[string]interface{}) RecordedCall {
	return RecordedCall{ToolName: tool, Args: args}
}

func TestMatchSequence(t *testing.T) {
	// The #2468 "Rule C" chain: ≥3 OSINT reads → an LLM generation → a bulk
	// send_email with array recipients and no AI-disclosure marker.
	chain := &MCPSequenceMatch{
		WithinCalls: 20,
		Steps: []MCPSequenceStep{
			{ToolNameRegex: "^(web_search|fetch)", MinCount: 3},
			{ToolNameRegex: "(generate|complete|chat)"},
			{
				ToolNameRegex:         "send_email",
				ArgumentRegexPatterns: map[string]string{"to": `^\[`},
				ArgumentNotContains:   map[string][]string{"body": {"ai-generated", "automated message"}},
			},
		},
	}

	bulkSend := rc("send_email", map[string]interface{}{"to": "[a@x.com, b@y.com]", "body": "hello"})

	tests := []struct {
		name    string
		history []RecordedCall
		want    bool
	}{
		{
			name: "full chain fires",
			history: []RecordedCall{
				rc("web_search", nil), rc("web_search", nil), rc("fetch_url", nil),
				rc("generate_text", nil), bulkSend,
			},
			want: true,
		},
		{
			name: "gaps between steps are allowed",
			history: []RecordedCall{
				rc("web_search", nil), rc("list_files", nil), rc("web_search", nil),
				rc("read_file", nil), rc("fetch_page", nil), rc("chat_complete", nil),
				rc("log_event", nil), bulkSend,
			},
			want: true,
		},
		{
			name: "too few OSINT reads — min_count not met",
			history: []RecordedCall{
				rc("web_search", nil), rc("fetch_url", nil),
				rc("generate_text", nil), bulkSend,
			},
			want: false,
		},
		{
			name: "missing generation step",
			history: []RecordedCall{
				rc("web_search", nil), rc("web_search", nil), rc("fetch_url", nil),
				bulkSend,
			},
			want: false,
		},
		{
			name: "send has AI-disclosure marker — absence predicate fails",
			history: []RecordedCall{
				rc("web_search", nil), rc("web_search", nil), rc("fetch_url", nil),
				rc("generate_text", nil),
				rc("send_email", map[string]interface{}{"to": "[a@x.com]", "body": "This is an AI-generated summary."}),
			},
			want: false,
		},
		{
			name: "single recipient — arg regex (array) fails",
			history: []RecordedCall{
				rc("web_search", nil), rc("web_search", nil), rc("fetch_url", nil),
				rc("generate_text", nil),
				rc("send_email", map[string]interface{}{"to": "a@x.com", "body": "hi"}),
			},
			want: false,
		},
		{
			name: "out of order — send before generation",
			history: []RecordedCall{
				rc("web_search", nil), rc("web_search", nil), rc("fetch_url", nil),
				bulkSend, rc("generate_text", nil),
			},
			want: false,
		},
		{
			name:    "empty history",
			history: nil,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchSequence(chain, tt.history); got != tt.want {
				t.Errorf("matchSequence() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchSequence_WithinCallsWindow(t *testing.T) {
	seq := &MCPSequenceMatch{
		WithinCalls: 3,
		Steps: []MCPSequenceStep{
			{ToolName: "read_secret"},
			{ToolName: "send_email"},
		},
	}
	// read_secret is older than the 3-call window → should not match.
	history := []RecordedCall{
		rc("read_secret", nil), rc("noise", nil), rc("noise", nil), rc("send_email", nil),
	}
	if matchSequence(seq, history) {
		t.Error("expected no match: read_secret is outside the within_calls window")
	}
	// Within the window → matches.
	history2 := []RecordedCall{
		rc("noise", nil), rc("read_secret", nil), rc("send_email", nil),
	}
	if !matchSequence(seq, history2) {
		t.Error("expected match within the within_calls window")
	}
}

func TestMatchSequence_Degenerate(t *testing.T) {
	if matchSequence(nil, []RecordedCall{rc("x", nil)}) {
		t.Error("nil sequence must not match")
	}
	if matchSequence(&MCPSequenceMatch{}, []RecordedCall{rc("x", nil)}) {
		t.Error("sequence with no steps must not match")
	}
	// A step with no tool predicate can never match.
	noTool := &MCPSequenceMatch{Steps: []MCPSequenceStep{{MinCount: 1}}}
	if matchSequence(noTool, []RecordedCall{rc("anything", nil)}) {
		t.Error("step with no tool-name predicate must not match")
	}
}

func TestMCPCallHistoryTracker(t *testing.T) {
	var nilTracker *MCPCallHistoryTracker
	if nilTracker.History() != nil {
		t.Error("nil tracker History() must be nil")
	}
	nilTracker.Record("x", nil) // must not panic

	tr := NewMCPCallHistoryTracker()
	tr.Record("web_search", map[string]interface{}{"q": "acme execs"})
	tr.Record("send_email", map[string]interface{}{"to": "[a@x.com]"})
	h := tr.History()
	if len(h) != 2 {
		t.Fatalf("history len = %d, want 2", len(h))
	}
	if h[0].ToolName != "web_search" || h[1].ToolName != "send_email" {
		t.Errorf("unexpected history order: %v", []string{h[0].ToolName, h[1].ToolName})
	}

	// Bounded to callHistoryMax (oldest trimmed).
	tr2 := NewMCPCallHistoryTracker()
	for i := 0; i < callHistoryMax+25; i++ {
		tr2.Record("noise", nil)
	}
	tr2.Record("last", nil)
	h2 := tr2.History()
	if len(h2) != callHistoryMax {
		t.Errorf("history len = %d, want %d (bounded)", len(h2), callHistoryMax)
	}
	if h2[len(h2)-1].ToolName != "last" {
		t.Error("most recent call must be retained after trimming")
	}

	// History() returns a copy — mutating it must not affect the tracker.
	h2[0].ToolName = "tampered"
	if tr2.History()[0].ToolName == "tampered" {
		t.Error("History() must return a defensive copy")
	}
}

// TestMatchSequence_ActionWithoutPrecheck exercises the negative-lookback
// pattern (#2785 perceive-act TOCTOU): a high-impact action call is only a
// match when NONE of the calls immediately preceding it satisfy the precheck
// step — the inverse of the presence-only Steps matcher above.
func TestMatchSequence_ActionWithoutPrecheck(t *testing.T) {
	seq := &MCPSequenceMatch{
		ActionStep: &MCPSequenceStep{
			ToolNameAny:           []string{"click", "computer_use"},
			ArgumentRegexPatterns: map[string]string{"text": "(?i)confirm|transfer"},
		},
		PrecheckStep: &MCPSequenceStep{
			ToolNameAny: []string{"screenshot", "get_dom_snapshot"},
		},
		PrecheckWithinCalls: 2,
	}

	confirmClick := rc("click", map[string]interface{}{"text": "Confirm Transfer"})

	tests := []struct {
		name    string
		history []RecordedCall
		want    bool
	}{
		{
			name:    "action with no precheck anywhere in history fires",
			history: []RecordedCall{rc("list_files", nil), confirmClick},
			want:    true,
		},
		{
			name:    "action with no history at all fires",
			history: []RecordedCall{confirmClick},
			want:    true,
		},
		{
			name:    "fresh precheck immediately before — does not fire",
			history: []RecordedCall{rc("screenshot", nil), confirmClick},
			want:    false,
		},
		{
			name:    "fresh precheck two calls before (within lookback) — does not fire",
			history: []RecordedCall{rc("get_dom_snapshot", nil), rc("move_mouse", nil), confirmClick},
			want:    false,
		},
		{
			name:    "precheck outside the lookback window — fires",
			history: []RecordedCall{rc("screenshot", nil), rc("move_mouse", nil), rc("hover", nil), confirmClick},
			want:    true,
		},
		{
			name:    "trigger call does not match action step — does not fire",
			history: []RecordedCall{rc("screenshot", nil), rc("click", map[string]interface{}{"text": "Cancel"})},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchSequence(seq, tt.history); got != tt.want {
				t.Errorf("matchSequence() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("nil PrecheckStep never fires", func(t *testing.T) {
		broken := &MCPSequenceMatch{ActionStep: seq.ActionStep}
		if matchSequence(broken, []RecordedCall{confirmClick}) {
			t.Error("expected no match with nil PrecheckStep")
		}
	})

	t.Run("PrecheckWithinCalls defaults to 1 when unset", func(t *testing.T) {
		defaulted := &MCPSequenceMatch{ActionStep: seq.ActionStep, PrecheckStep: seq.PrecheckStep}
		history := []RecordedCall{rc("screenshot", nil), rc("move_mouse", nil), confirmClick}
		if !matchSequence(defaulted, history) {
			t.Error("expected match: precheck is 2 calls back, default lookback is only 1")
		}
	})
}
