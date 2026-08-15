package mcp

import (
	"strings"
	"testing"
)

// TestThresholdPoisoningTracker_CheckToolVolume verifies session-level tool
// count accumulation and the AUDIT threshold at ThresholdToolCount.
func TestThresholdPoisoningTracker_CheckToolVolume(t *testing.T) {
	t.Run("below threshold not exceeded", func(t *testing.T) {
		tracker := NewThresholdPoisoningTracker()
		tools := make([]ToolDefinition, 7)
		count, exceeded := tracker.CheckToolVolume(tools)
		if exceeded {
			t.Errorf("expected not exceeded for %d tools, got exceeded", count)
		}
		if count != 7 {
			t.Errorf("expected count=7, got %d", count)
		}
	})

	t.Run("exactly at threshold is exceeded", func(t *testing.T) {
		tracker := NewThresholdPoisoningTracker()
		tools := make([]ToolDefinition, ThresholdToolCount)
		count, exceeded := tracker.CheckToolVolume(tools)
		if !exceeded {
			t.Errorf("expected exceeded at ThresholdToolCount=%d, got count=%d exceeded=%v", ThresholdToolCount, count, exceeded)
		}
	})

	t.Run("accumulates across multiple calls", func(t *testing.T) {
		tracker := NewThresholdPoisoningTracker()

		// First call: 4 tools (below threshold)
		_, exceeded := tracker.CheckToolVolume(make([]ToolDefinition, 4))
		if exceeded {
			t.Error("expected not exceeded after 4 tools")
		}

		// Second call: 4 more tools → total 8 = ThresholdToolCount
		count, exceeded := tracker.CheckToolVolume(make([]ToolDefinition, 4))
		if !exceeded {
			t.Errorf("expected exceeded after accumulating 8 tools, got count=%d", count)
		}
		if count != 8 {
			t.Errorf("expected total count=8, got %d", count)
		}
	})

	t.Run("empty tool list does not trigger", func(t *testing.T) {
		tracker := NewThresholdPoisoningTracker()
		count, exceeded := tracker.CheckToolVolume([]ToolDefinition{})
		if exceeded {
			t.Errorf("empty list should not exceed threshold, count=%d", count)
		}
	})
}

// TestScanDescriptionForFragment verifies ShareLock encoded-fragment detection.
func TestScanDescriptionForFragment(t *testing.T) {
	tpCases := []struct {
		name string
		desc string
	}{
		{
			// 64-char base64 token — looks like a Shamir share
			name: "pure base64 block",
			desc: "Yjk5Y2JjZjZjNTU3MjQ0YmY5MTkxMDcxMzQ1Njc4OTAxMjM0NTY3ODkwMTIz",
		},
		{
			// Single long base64 blob masquerading as tool description
			name: "base64 fragment posing as tool description",
			desc: "c2hhcmVsb2NrLWZyYWdtZW50LWRhdGEtaGVyZS1mb3ItdGhlLWF0dGFjaw==",
		},
		{
			// Hex-encoded fragment — 64 hex chars (32 bytes), even length, diverse charset
			name: "hex encoded fragment 64 chars",
			desc: "a3f4b2c1d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1",
		},
		{
			// Multiple base64 tokens, all encoded (≥80% of content)
			name: "two long base64 tokens with short label",
			desc: "A Yjk5Y2JjZjZjNTU3MjQ0YmY5MTkxMDcxMzQ1Njc4OTAxMjM0NTY3ODkwMTIz Yjk5Y2JjZjZjNTU3MjQ0YmY5MTkxMDcxMzQ1Njc4OTAxMjM0NTY3ODkwMTIz",
		},
	}

	for _, tc := range tpCases {
		t.Run("TP_"+tc.name, func(t *testing.T) {
			if !ScanDescriptionForFragment(tc.desc) {
				t.Errorf("expected ShareLock fragment detected for: %q", tc.desc)
			}
		})
	}

	tnCases := []struct {
		name string
		desc string
	}{
		{
			name: "normal human-readable description",
			desc: "Reads a file from the filesystem and returns its contents as a string.",
		},
		{
			name: "description with version number and path",
			desc: "Executes a shell command in the sandbox environment. Returns stdout, stderr, and exit code.",
		},
		{
			name: "short description",
			desc: "List files",
		},
		{
			name: "description with one small base64 token mixed in",
			desc: "Encodes input data to base64 format. Example: aGVsbG8= is the base64 of 'hello'. Returns a string.",
		},
		{
			name: "mostly natural language with a short hash",
			desc: "Fetch the latest commit. Hash: abc123. Returns branch info and author.",
		},
		{
			name: "empty description",
			desc: "",
		},
		{
			name: "very short description",
			desc: "OK",
		},
		{
			name: "URL-like token in description",
			desc: "Calls the internal API endpoint at https://api.example.com/v1/data to retrieve records.",
		},
		{
			name: "markdown parameter documentation",
			desc: "Write content to a file.\n\nParameters:\n- path (string): The file path\n- content (string): The content to write\n\nReturns: success boolean",
		},
	}

	for _, tc := range tnCases {
		t.Run("TN_"+tc.name, func(t *testing.T) {
			if ScanDescriptionForFragment(tc.desc) {
				t.Errorf("expected NO ShareLock fragment for benign description: %q", tc.desc)
			}
		})
	}
}

// TestLooksEncoded verifies the token-level encoding detector.
func TestLooksEncoded(t *testing.T) {
	encoded := []string{
		// Real base64 values (≥24 chars, high entropy — diverse character distribution)
		// 32 unique chars from the base64 alphabet → entropy ≈ 5 bits
		"qTwErTyUiOpAsDfGhJkLzXcVbNm01234",
		// Base64 of "sharelock-fragment-data" → long enough with balanced distribution
		"c2hhcmVsb2NrLWZyYWdtZW50LWRhdGE=",
		// Large diverse base64 token (56 chars) as found in real Shamir shares
		"SGVsbG9Xb3JsZFRoaXNJc0FUZXh0V2l0aEhpZ2hFbnRyb3B5Rg==",
	}
	for _, s := range encoded {
		if !looksEncoded(s) {
			t.Errorf("looksEncoded(%q) = false, expected true", s)
		}
	}

	notEncoded := []string{
		"hello",                      // too short
		"ReadFile",                   // regular word
		"path/to/some/file.txt",      // filepath — has slash but low entropy in letter distribution
		strings.Repeat("a", 32),      // high base64 coverage but zero entropy
		"This is a normal sentence.", // natural language
		"abc",                        // too short
		"12345",                      // too short
	}
	for _, s := range notEncoded {
		if looksEncoded(s) {
			t.Errorf("looksEncoded(%q) = true, expected false", s)
		}
	}
}

// TestShannonEntropy verifies entropy computation on known inputs.
func TestShannonEntropy(t *testing.T) {
	cases := []struct {
		s    string
		minE float64
		maxE float64
	}{
		{s: "", minE: 0, maxE: 0},
		{s: "aaaa", minE: 0, maxE: 0.01},      // all same char: zero entropy
		{s: "ab", minE: 0.99, maxE: 1.01},     // two equal chars: 1 bit
		{s: "abcd", minE: 1.99, maxE: 2.01},   // four equal chars: 2 bits
	}
	for _, tc := range cases {
		e := shannonEntropy(tc.s)
		if e < tc.minE || e > tc.maxE {
			t.Errorf("shannonEntropy(%q) = %.4f, want [%.2f, %.2f]", tc.s, e, tc.minE, tc.maxE)
		}
	}
}
