package mcp

import (
	"math"
	"strings"
	"sync"
	"unicode"
)

// ThresholdPoisoningTracker detects multi-tool threshold poisoning (ShareLock pattern).
//
// ShareLock (arXiv 2606.27027) distributes malicious instructions across N tool
// descriptions using Shamir's Secret Sharing. No single tool looks poisoned; only
// when the agent loads ≥ threshold tools does the instruction reconstruct in context.
//
// This tracker operates at two levels:
//  1. Session-level tool volume: when a single tools/list response delivers
//     ≥ ThresholdToolCount tools, emit an AUDIT signal (high tool density is a
//     precondition for threshold reconstruction).
//  2. Per-description encoded-fragment detection: descriptions that are entirely
//     or mostly base64/hex-encoded content (no readable natural language) are
//     abnormal for legitimate MCP servers and indicate a possible ShareLock shard.
type ThresholdPoisoningTracker struct {
	mu        sync.Mutex
	totalSeen int // cumulative tools seen this session
}

// ThresholdToolCount is the minimum tools/list count that triggers an AUDIT signal.
// ShareLock needs k≥2 tools; effective attacks use k=4–8 for reliability. ≥8 is
// a conservative threshold that allows legitimate tool-rich servers while catching attacks.
const ThresholdToolCount = 8

// NewThresholdPoisoningTracker returns a ready tracker.
func NewThresholdPoisoningTracker() *ThresholdPoisoningTracker {
	return &ThresholdPoisoningTracker{}
}

// CheckToolVolume records the tool count from a tools/list response and returns
// (totalSeen, exceeded) where exceeded is true when totalSeen ≥ ThresholdToolCount.
// First tools/list response in the session is always checked.
func (t *ThresholdPoisoningTracker) CheckToolVolume(tools []ToolDefinition) (int, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.totalSeen += len(tools)
	return t.totalSeen, t.totalSeen >= ThresholdToolCount
}

// ScanDescriptionForFragment checks whether a tool description looks like a
// ShareLock fragment — a description that is entirely or predominantly a
// base64/hex-encoded blob with no readable natural-language words.
//
// Returns true when the description contains a standalone encoded fragment
// that occupies >80% of the description text, indicating the description was
// generated to hold a cryptographic share rather than explain a tool's function.
func ScanDescriptionForFragment(desc string) bool {
	desc = strings.TrimSpace(desc)
	if len(desc) < 16 {
		// Too short to be a meaningful fragment or a real description.
		return false
	}

	// Split into whitespace-delimited tokens and check each for encoding patterns.
	tokens := strings.Fields(desc)
	if len(tokens) == 0 {
		return false
	}

	// Count how many tokens look like encoded data vs natural language.
	encodedBytes := 0
	totalBytes := 0
	for _, tok := range tokens {
		totalBytes += len(tok)
		if looksEncoded(tok) {
			encodedBytes += len(tok)
		}
	}

	if totalBytes == 0 {
		return false
	}

	encodedFraction := float64(encodedBytes) / float64(totalBytes)
	// Flag when >80% of the description content is encoded-looking tokens.
	return encodedFraction > 0.80
}

// looksEncoded returns true when a token has characteristics of a base64 or hex-encoded
// cryptographic value: high entropy, no natural language, correct alphabet usage.
func looksEncoded(s string) bool {
	if len(s) < 16 {
		return false
	}

	// Must be pure base64 or hex — no common English word characters
	base64Alphabet := 0
	hexAlphabet := 0
	for _, r := range s {
		if isBase64Char(r) {
			base64Alphabet++
		}
		if isHexChar(r) {
			hexAlphabet++
		}
	}

	// For base64: ≥95% of chars must be in the base64 alphabet (A-Za-z0-9+/=)
	base64Coverage := float64(base64Alphabet) / float64(len(s))
	if base64Coverage >= 0.95 && len(s) >= 24 {
		// Additionally verify: natural language words have low entropy compared to
		// base64-encoded bytes. A base64 share will have balanced character distribution.
		if shannonEntropy(s) >= 4.0 {
			return true
		}
	}

	// For hex: ≥95% of chars in [0-9a-fA-F] and length is a multiple of 2
	hexCoverage := float64(hexAlphabet) / float64(len(s))
	if hexCoverage >= 0.95 && len(s) >= 32 && len(s)%2 == 0 {
		if shannonEntropy(s) >= 3.0 {
			return true
		}
	}

	return false
}

func isBase64Char(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '+' || r == '/' || r == '='
}

func isHexChar(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

// shannonEntropy computes the Shannon entropy of a string in bits per character.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}
	n := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}
