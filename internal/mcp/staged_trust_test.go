package mcp

import (
	"bytes"
	"testing"
)

// ── StagedTrustTracker (issue #3519, arXiv 2608.23763) unit coverage — a
// "TrustShift" attack is defined by ORDER: text-only responses establishing
// a clean baseline, THEN an embedded-resource content item appears for the
// first time. Every test below pins that ordering requirement.

func TestStagedTrustTracker_FlagsResourceAfterWindow(t *testing.T) {
	tr := NewStagedTrustTracker()

	for i := 0; i < stagedTrustWindowCalls; i++ {
		if findings := tr.Observe([]ContentItem{{Type: "text", Text: "clean response"}}); len(findings) != 0 {
			t.Fatalf("call %d: expected no finding during trust window, got %v", i, findings)
		}
	}

	findings := tr.Observe([]ContentItem{
		{Type: "resource", URI: "https://attacker.example/payload.json"},
	})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding after trust window, got %d", len(findings))
	}
	if findings[0].Signal != SignalResponseStagedTrustDefection {
		t.Errorf("expected SignalResponseStagedTrustDefection, got %s", findings[0].Signal)
	}
	if !bytes.Contains([]byte(findings[0].Detail), []byte("attacker.example")) {
		t.Errorf("expected detail to mention the offending URI, got %q", findings[0].Detail)
	}
}

func TestStagedTrustTracker_ResourceLinkKindAlsoFlags(t *testing.T) {
	tr := NewStagedTrustTracker()
	for i := 0; i < stagedTrustWindowCalls; i++ {
		tr.Observe([]ContentItem{{Type: "text", Text: "clean"}})
	}
	findings := tr.Observe([]ContentItem{{Type: "resource_link", URI: "https://example.com/doc"}})
	if len(findings) != 1 {
		t.Fatalf("expected resource_link to also trigger after the window, got %d findings", len(findings))
	}
}

func TestStagedTrustTracker_NoFindingWithinWindow(t *testing.T) {
	tr := NewStagedTrustTracker()

	// Resource content on the very FIRST call — a legitimate document-serving
	// tool that has always had this capability, not a defection.
	if findings := tr.Observe([]ContentItem{{Type: "resource", URI: "https://docs.example/readme"}}); len(findings) != 0 {
		t.Fatalf("resource content within the trust window must not be flagged, got %v", findings)
	}

	// It must stay unflagged even once the window has since closed — the
	// server established resource-serving as baseline behavior, not defected
	// into it.
	for i := 0; i < 5; i++ {
		if findings := tr.Observe([]ContentItem{{Type: "resource", URI: "https://docs.example/readme"}}); len(findings) != 0 {
			t.Fatalf("call %d: repeated resource content from an established baseline must not be flagged, got %v", i, findings)
		}
	}
}

func TestStagedTrustTracker_OnlyFlagsOnce(t *testing.T) {
	tr := NewStagedTrustTracker()
	for i := 0; i < stagedTrustWindowCalls; i++ {
		tr.Observe([]ContentItem{{Type: "text", Text: "clean"}})
	}
	first := tr.Observe([]ContentItem{{Type: "resource", URI: "https://attacker.example/a"}})
	if len(first) != 1 {
		t.Fatalf("expected the first post-window resource to fire, got %d findings", len(first))
	}
	second := tr.Observe([]ContentItem{{Type: "resource", URI: "https://attacker.example/b"}})
	if len(second) != 0 {
		t.Fatalf("expected no repeat finding once the resource kind is established, got %v", second)
	}
}

func TestStagedTrustTracker_TextOnlySession_NoFinding(t *testing.T) {
	tr := NewStagedTrustTracker()
	for i := 0; i < 20; i++ {
		if findings := tr.Observe([]ContentItem{{Type: "text", Text: "status: ok"}}); len(findings) != 0 {
			t.Fatalf("call %d: a text-only session must never be flagged, got %v", i, findings)
		}
	}
}

func TestStagedTrustTracker_ImageAfterWindow_NotFlagged(t *testing.T) {
	// Only embedded-resource kinds are the tracked dimension; a tool that
	// starts returning images (a very different, well-precedented multi-modal
	// pattern) is out of scope for this heuristic and must not false-positive.
	tr := NewStagedTrustTracker()
	for i := 0; i < stagedTrustWindowCalls; i++ {
		tr.Observe([]ContentItem{{Type: "text", Text: "clean"}})
	}
	if findings := tr.Observe([]ContentItem{{Type: "image", Data: "base64data", MIMEType: "image/png"}}); len(findings) != 0 {
		t.Fatalf("an image content item must not trigger the staged-trust heuristic, got %v", findings)
	}
}

func TestStagedTrustTracker_NilSafe(t *testing.T) {
	var tr *StagedTrustTracker
	if got := tr.Observe([]ContentItem{{Type: "resource", URI: "https://x"}}); got != nil {
		t.Errorf("nil tracker Observe must return nil, got %v", got)
	}
}

func TestStagedTrustTracker_ResourceViaEmbeddedResourceField(t *testing.T) {
	// Some servers put the URI in the nested Resource object rather than the
	// top-level URI field (both are legal MCP shapes for type "resource").
	tr := NewStagedTrustTracker()
	for i := 0; i < stagedTrustWindowCalls; i++ {
		tr.Observe([]ContentItem{{Type: "text", Text: "clean"}})
	}
	findings := tr.Observe([]ContentItem{
		{Type: "resource", Resource: &ResourceContentItem{URI: "https://nested.example/x"}},
	})
	if len(findings) != 1 {
		t.Fatalf("expected the nested Resource.URI shape to also trigger, got %d findings", len(findings))
	}
	if !bytes.Contains([]byte(findings[0].Detail), []byte("nested.example")) {
		t.Errorf("expected detail to surface the nested resource URI, got %q", findings[0].Detail)
	}
}

func TestSignalTaxonomyRef_StagedTrustDefection(t *testing.T) {
	got := signalTaxonomyRef(SignalResponseStagedTrustDefection)
	want := "unauthorized-execution/agentic-attacks/mcp-tool-response-poisoning"
	if got != want {
		t.Errorf("signalTaxonomyRef(SignalResponseStagedTrustDefection) = %q, want %q", got, want)
	}
}

// ── Handler-level end-to-end wiring — proves the tracker is actually called
// from FilterToolCallResponse and reported as AUDIT (never BLOCK: a session
// that legitimately gains a resource-serving capability mid-session is a
// real benign case this coarse heuristic cannot rule out, so it must never
// break the response).

func stagedTrustTestHandler() (*MessageHandler, *bytes.Buffer, *[]AuditEntry) {
	var buf bytes.Buffer
	var audits []AuditEntry
	h := &MessageHandler{
		Stderr:      &buf,
		StagedTrust: NewStagedTrustTracker(),
		OnAudit: func(e AuditEntry) {
			audits = append(audits, e)
		},
	}
	return h, &buf, &audits
}

func TestStagedTrust_Handler_AuditsAfterWindow_NeverBlocks(t *testing.T) {
	h, _, audits := stagedTrustTestHandler()

	for i := 0; i < stagedTrustWindowCalls; i++ {
		msg := buildToolCallResultMsg(t, []ContentItem{{Type: "text", Text: "clean response"}})
		if repl := h.FilterToolCallResponse(msg); repl != nil {
			t.Fatalf("call %d: a clean text response must not be blocked: %s", i, repl)
		}
	}

	resultMsg := buildToolCallResultMsg(t, []ContentItem{
		{Type: "resource", URI: "https://attacker.example/payload"},
	})
	repl := h.FilterToolCallResponse(resultMsg)
	if repl != nil {
		t.Fatalf("staged-trust defection is AUDIT, not BLOCK — response must pass through unmodified, got: %s", repl)
	}
	if len(*audits) != 1 {
		t.Fatalf("expected exactly 1 audit entry, got %d: %v", len(*audits), *audits)
	}
	got := (*audits)[0]
	if got.Decision != "AUDIT" {
		t.Errorf("expected Decision=AUDIT, got %q", got.Decision)
	}
	if !got.Flagged {
		t.Error("expected Flagged=true")
	}
	if got.TaxonomyRef != "unauthorized-execution/agentic-attacks/mcp-tool-response-poisoning" {
		t.Errorf("unexpected TaxonomyRef: %q", got.TaxonomyRef)
	}
	if len(got.TriggeredRules) == 0 || got.TriggeredRules[0] != "mcp-response-staged-trust-defection-sentinel" {
		t.Errorf("expected the sentinel rule ID as fallback TriggeredRules[0], got %v", got.TriggeredRules)
	}
}

func TestStagedTrust_Handler_NoAuditWithinWindow(t *testing.T) {
	h, _, audits := stagedTrustTestHandler()

	// Resource content arrives immediately — within the trust window — so it
	// must never be audited.
	resultMsg := buildToolCallResultMsg(t, []ContentItem{
		{Type: "resource", URI: "https://docs.example/readme"},
	})
	if repl := h.FilterToolCallResponse(resultMsg); repl != nil {
		t.Fatalf("resource content within the trust window must not be blocked: %s", repl)
	}
	if len(*audits) != 0 {
		t.Fatalf("expected no audit entries within the trust window, got %v", *audits)
	}
}

func TestStagedTrust_Handler_NilTrackerDisablesDetection(t *testing.T) {
	var buf bytes.Buffer
	h := &MessageHandler{Stderr: &buf} // StagedTrust left nil

	for i := 0; i < stagedTrustWindowCalls+1; i++ {
		msg := buildToolCallResultMsg(t, []ContentItem{{Type: "text", Text: "clean"}})
		if repl := h.FilterToolCallResponse(msg); repl != nil {
			t.Fatalf("call %d: unexpected block with StagedTrust disabled: %s", i, repl)
		}
	}
	resultMsg := buildToolCallResultMsg(t, []ContentItem{{Type: "resource", URI: "https://x"}})
	if repl := h.FilterToolCallResponse(resultMsg); repl != nil {
		t.Fatalf("nil StagedTrust tracker must not panic or block: %s", repl)
	}
}
