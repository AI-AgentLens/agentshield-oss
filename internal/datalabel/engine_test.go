package datalabel

import (
	"strings"
	"testing"
)

func TestNewEngine_NilOnEmpty(t *testing.T) {
	engine, err := NewEngine(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if engine != nil {
		t.Fatal("expected nil engine for empty configs")
	}
}

func TestNewEngine_InvalidRegex(t *testing.T) {
	_, err := NewEngine([]DataLabelConfig{
		{
			ID:       "bad",
			Decision: "BLOCK",
			Patterns: []PatternConfig{{Regex: "[invalid"}},
		},
	})
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestNewEngine_InvalidContextRegex(t *testing.T) {
	_, err := NewEngine([]DataLabelConfig{
		{
			ID:       "bad-ctx",
			Decision: "BLOCK",
			Patterns: []PatternConfig{{Regex: `\d+`, Context: "[invalid"}},
		},
	})
	if err == nil {
		t.Fatal("expected error for invalid context regex")
	}
}

func TestEngine_NilSafe(t *testing.T) {
	var e *Engine
	matches := e.ScanText("hello", "", "")
	if matches != nil {
		t.Fatal("expected nil from nil engine")
	}
}

func TestEngine_RegexMatch(t *testing.T) {
	engine, err := NewEngine([]DataLabelConfig{
		{
			ID:         "pii-ssn",
			Name:       "SSN",
			Decision:   "BLOCK",
			Confidence: 0.90,
			Reason:     "SSN detected",
			Patterns:   []PatternConfig{{Regex: `\b\d{3}-\d{2}-\d{4}\b`}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	matches := engine.ScanText("my ssn is 123-45-6789 ok", "", "")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].LabelID != "pii-ssn" {
		t.Errorf("wrong label ID: %s", matches[0].LabelID)
	}
	if matches[0].Decision != "BLOCK" {
		t.Errorf("wrong decision: %s", matches[0].Decision)
	}
	if matches[0].MatchText != "123-45-6789" {
		t.Errorf("wrong match text: %s", matches[0].MatchText)
	}
}

func TestEngine_RegexNoMatch(t *testing.T) {
	engine, err := NewEngine([]DataLabelConfig{
		{
			ID:       "pii-ssn",
			Decision: "BLOCK",
			Patterns: []PatternConfig{{Regex: `\b\d{3}-\d{2}-\d{4}\b`}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	matches := engine.ScanText("no sensitive data here", "", "")
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}

func TestEngine_ContextRequired(t *testing.T) {
	engine, err := NewEngine([]DataLabelConfig{
		{
			ID:       "pii-ssn",
			Decision: "BLOCK",
			Patterns: []PatternConfig{
				{Regex: `\b\d{3}-\d{2}-\d{4}\b`, Context: "ssn|social.security"},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// With context
	matches := engine.ScanText("SSN: 123-45-6789", "", "")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match with context, got %d", len(matches))
	}

	// Without context — regex matches but context doesn't
	matches = engine.ScanText("phone: 123-45-6789", "", "")
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches without context, got %d", len(matches))
	}
}

func TestEngine_ValidatorFilters(t *testing.T) {
	engine, err := NewEngine([]DataLabelConfig{
		{
			ID:       "pii-cc",
			Decision: "BLOCK",
			Patterns: []PatternConfig{
				{Regex: `\b\d{15,16}\b`, Validator: "luhn"},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Valid Luhn
	matches := engine.ScanText("card: 4532015112830366", "", "")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match for valid card, got %d", len(matches))
	}

	// Invalid Luhn
	matches = engine.ScanText("card: 1234567890123456", "", "")
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for invalid card, got %d", len(matches))
	}
}

func TestEngine_KeywordMatch(t *testing.T) {
	engine, err := NewEngine([]DataLabelConfig{
		{
			ID:       "codenames",
			Name:     "Project Codenames",
			Decision: "AUDIT",
			Patterns: []PatternConfig{
				{Keywords: []string{"PHOENIX", "TITAN"}, CaseSensitive: true},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	matches := engine.ScanText("launching project PHOENIX now", "", "")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].LabelID != "codenames" {
		t.Errorf("wrong label: %s", matches[0].LabelID)
	}

	// Case mismatch
	matches = engine.ScanText("launching project phoenix now", "", "")
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for wrong case, got %d", len(matches))
	}
}

func TestEngine_ScopeFiltering_ToolName(t *testing.T) {
	engine, err := NewEngine([]DataLabelConfig{
		{
			ID:       "scoped",
			Decision: "BLOCK",
			Patterns: []PatternConfig{{Regex: `secret`}},
			ScanScope: ScanScopeConfig{
				Tools: []string{"write_*", "send_message"},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Matching tool
	matches := engine.ScanText("the secret", "write_file", "outbound")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match for scoped tool, got %d", len(matches))
	}

	// Non-matching tool
	matches = engine.ScanText("the secret", "read_file", "outbound")
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for out-of-scope tool, got %d", len(matches))
	}

	// Shell command — BUG-DL-004 fix: labels with a Tools filter are
	// MCP-scoped by default; shell commands do not match unless the
	// customer sets scope.Shell=true explicitly.
	matches = engine.ScanText("the secret", "", "")
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for shell (tools filter = MCP-scoped), got %d", len(matches))
	}
}

func TestEngine_ScopeFiltering_ShellOptIn(t *testing.T) {
	// Customer explicitly opts shell commands into an MCP-scoped label.
	shellOn := true
	engine, err := NewEngine([]DataLabelConfig{
		{
			ID:       "shell-and-write",
			Decision: "BLOCK",
			Patterns: []PatternConfig{{Regex: `secret`}},
			ScanScope: ScanScopeConfig{
				Tools: []string{"write_*"},
				Shell: &shellOn,
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Shell context matches because Shell=true
	if matches := engine.ScanText("the secret", "", ""); len(matches) != 1 {
		t.Fatalf("expected 1 match for shell (opt-in), got %d", len(matches))
	}
	// Non-matching MCP tool still filtered
	if matches := engine.ScanText("the secret", "read_file", "outbound"); len(matches) != 0 {
		t.Fatalf("expected 0 matches for out-of-scope MCP tool, got %d", len(matches))
	}
}

func TestEngine_ScopeFiltering_ShellOptOut(t *testing.T) {
	// Customer explicitly excludes shell commands even from an otherwise
	// unscoped label.
	shellOff := false
	engine, err := NewEngine([]DataLabelConfig{
		{
			ID:       "no-shell",
			Decision: "BLOCK",
			Patterns: []PatternConfig{{Regex: `secret`}},
			ScanScope: ScanScopeConfig{
				Shell: &shellOff,
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if matches := engine.ScanText("the secret", "", ""); len(matches) != 0 {
		t.Fatalf("expected 0 matches for shell (opt-out), got %d", len(matches))
	}
	if matches := engine.ScanText("the secret", "any_tool", "outbound"); len(matches) != 1 {
		t.Fatalf("expected 1 match for MCP context, got %d", len(matches))
	}
}

func TestEngine_ScopeFiltering_Direction(t *testing.T) {
	engine, err := NewEngine([]DataLabelConfig{
		{
			ID:       "outbound-only",
			Decision: "BLOCK",
			Patterns: []PatternConfig{{Regex: `secret`}},
			ScanScope: ScanScopeConfig{
				Directions: []string{"outbound"},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Matching direction
	matches := engine.ScanText("the secret", "", "outbound")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match for outbound, got %d", len(matches))
	}

	// Wrong direction
	matches = engine.ScanText("the secret", "", "inbound")
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for inbound, got %d", len(matches))
	}
}

func TestEngine_MaxScanBytes(t *testing.T) {
	engine, err := NewEngine([]DataLabelConfig{
		{
			ID:       "truncated",
			Decision: "BLOCK",
			Patterns: []PatternConfig{{Regex: `SECRET_AT_END`}},
			ScanScope: ScanScopeConfig{
				MaxScanBytes: 100,
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Pattern is beyond truncation point
	text := strings.Repeat("x", 90) + "SECRET_AT_END"
	matches := engine.ScanText(text, "", "")
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches beyond truncation, got %d", len(matches))
	}

	// Pattern is within truncation point
	text = "SECRET_AT_END" + strings.Repeat("x", 90)
	matches = engine.ScanText(text, "", "")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match within truncation, got %d", len(matches))
	}
}

// BUG-DL-001 regression: context regex must match a window around the
// primary match, not the full text. Context words far away must not confirm.
func TestEngine_ContextWindow(t *testing.T) {
	engine, err := NewEngine([]DataLabelConfig{
		{
			ID:       "pii-ssn",
			Decision: "BLOCK",
			Patterns: []PatternConfig{
				{Regex: `\b\d{3}-\d{2}-\d{4}\b`, Context: "ssn|social.security"},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Context within the window — should fire.
	matches := engine.ScanText("SSN: 123-45-6789", "", "")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match with nearby context, got %d", len(matches))
	}

	// Context far away (> contextWindowBytes bytes). The pre-fix behavior
	// would falsely fire because MatchString scanned the full text.
	padding := strings.Repeat(".", contextWindowBytes*2+50)
	text := "social security office" + padding + "phone: 123-45-6789"
	matches = engine.ScanText(text, "", "")
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches with context outside window, got %d (BUG-DL-001 regression)", len(matches))
	}
}

// BUG-DL-002 regression: when the regex tier triggers a BLOCK, prior
// keyword-tier AUDIT findings must not leak into the returned slice.
func TestEngine_BlockReplacesPriorAudits(t *testing.T) {
	engine, err := NewEngine([]DataLabelConfig{
		{
			ID:       "codenames",
			Decision: "AUDIT",
			Patterns: []PatternConfig{
				{Keywords: []string{"PHOENIX"}, CaseSensitive: true},
			},
		},
		{
			ID:       "pii-ssn",
			Decision: "BLOCK",
			Patterns: []PatternConfig{
				{Regex: `\b\d{3}-\d{2}-\d{4}\b`},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	matches := engine.ScanText("project PHOENIX customer ssn 123-45-6789", "", "")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match (BLOCK only), got %d", len(matches))
	}
	if matches[0].Decision != "BLOCK" || matches[0].LabelID != "pii-ssn" {
		t.Errorf("expected BLOCK pii-ssn, got %s %s", matches[0].Decision, matches[0].LabelID)
	}
}

// BUG-DL-003 regression: case-insensitive keyword search must preserve
// byte offsets so MatchText slicing is valid for non-ASCII input.
func TestEngine_KeywordCaseInsensitiveUnicodeOffsets(t *testing.T) {
	engine, err := NewEngine([]DataLabelConfig{
		{
			ID:       "keyword-ci",
			Decision: "AUDIT",
			Patterns: []PatternConfig{
				{Keywords: []string{"secret"}, CaseSensitive: false},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// "İ" is a multi-byte Unicode char; before the fix, strings.ToLower
	// would rewrite this and invalidate byte offsets produced by AC.
	// After the fix (asciiLower), offsets are valid — no panic, correct
	// MatchText from the original string.
	matches := engine.ScanText("İstanbul SECRET İzmir", "", "")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	// MatchText is sliced from the original (non-lowered) text.
	if matches[0].MatchText != "SECRET" {
		t.Errorf("expected match text 'SECRET', got %q", matches[0].MatchText)
	}
}

// BUG-DL-005 regression: unknown validator name must fail NewEngine rather
// than silently disabling the check at scan time.
func TestEngine_UnknownValidatorFailsInit(t *testing.T) {
	_, err := NewEngine([]DataLabelConfig{
		{
			ID:       "pii-cc",
			Decision: "BLOCK",
			Patterns: []PatternConfig{{Regex: `\d{16}`, Validator: "lhun"}}, // typo
		},
	})
	if err == nil {
		t.Fatal("expected error for unknown validator name (BUG-DL-005 regression)")
	}
	if !strings.Contains(err.Error(), "unknown validator") {
		t.Errorf("expected 'unknown validator' in error, got: %v", err)
	}
}

func TestEngine_EarlyTerminationOnBlock(t *testing.T) {
	engine, err := NewEngine([]DataLabelConfig{
		{
			ID:       "blocker",
			Decision: "BLOCK",
			Patterns: []PatternConfig{{Regex: `aaa`}},
		},
		{
			ID:       "auditer",
			Decision: "AUDIT",
			Patterns: []PatternConfig{{Regex: `bbb`}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Both patterns present, but BLOCK should terminate early
	matches := engine.ScanText("aaa bbb", "", "")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match (early termination), got %d", len(matches))
	}
	if matches[0].LabelID != "blocker" {
		t.Errorf("wrong label: %s", matches[0].LabelID)
	}
}

func TestEngine_MultipleLabels(t *testing.T) {
	engine, err := NewEngine([]DataLabelConfig{
		{
			ID:       "label-a",
			Decision: "AUDIT",
			Patterns: []PatternConfig{{Regex: `alpha`}},
		},
		{
			ID:       "label-b",
			Decision: "AUDIT",
			Patterns: []PatternConfig{{Regex: `beta`}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	matches := engine.ScanText("alpha and beta", "", "")
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
}

func TestEngine_MatchTextTruncation(t *testing.T) {
	engine, err := NewEngine([]DataLabelConfig{
		{
			ID:       "long",
			Decision: "AUDIT",
			Patterns: []PatternConfig{{Regex: `x{100}`}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	matches := engine.ScanText(strings.Repeat("x", 200), "", "")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if len(matches[0].MatchText) > maxMatchTextLen {
		t.Errorf("match text too long: %d > %d", len(matches[0].MatchText), maxMatchTextLen)
	}
}

// Benchmarks

func BenchmarkEngine_NilEngine(b *testing.B) {
	var e *Engine
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e.ScanText("test string with data", "", "")
	}
}

func BenchmarkEngine_5Labels_ShortText(b *testing.B) {
	engine := benchEngine(b)
	text := `echo "user SSN is 123-45-6789 and card 4532015112830366"`

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		engine.ScanText(text, "", "")
	}
}

func BenchmarkEngine_5Labels_256KB(b *testing.B) {
	engine := benchEngine(b)
	// 256KB text with a match near the end
	text := strings.Repeat("the quick brown fox jumps over the lazy dog ", 5800) + "SSN: 123-45-6789"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		engine.ScanText(text, "", "")
	}
}

func BenchmarkEngine_5Labels_NoMatch(b *testing.B) {
	engine := benchEngine(b)
	text := strings.Repeat("absolutely nothing sensitive here at all ", 100)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		engine.ScanText(text, "", "")
	}
}

func benchEngine(tb testing.TB) *Engine {
	tb.Helper()
	engine, err := NewEngine([]DataLabelConfig{
		{
			ID: "pii-ssn", Decision: "BLOCK", Confidence: 0.90,
			Patterns: []PatternConfig{
				{Regex: `\b\d{3}-\d{2}-\d{4}\b`, Context: "ssn|social.security"},
			},
		},
		{
			ID: "pii-cc", Decision: "BLOCK", Confidence: 0.95,
			Patterns: []PatternConfig{
				{Regex: `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`, Validator: "luhn"},
			},
		},
		{
			ID: "pii-email", Decision: "AUDIT", Confidence: 0.70,
			Patterns: []PatternConfig{
				{Regex: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`},
			},
		},
		{
			ID: "codenames", Decision: "AUDIT", Confidence: 0.80,
			Patterns: []PatternConfig{
				{Keywords: []string{"PHOENIX", "TITAN", "AURORA", "ECLIPSE", "ORION"}, CaseSensitive: true},
			},
		},
		{
			ID: "internal-ids", Decision: "AUDIT", Confidence: 0.80,
			Patterns: []PatternConfig{
				{Regex: `\bEMP-\d{6}\b`},
			},
		},
	})
	if err != nil {
		tb.Fatalf("failed to create bench engine: %v", err)
	}
	return engine
}
