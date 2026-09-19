package mcp

import (
	"encoding/json"
	"testing"
)

// Coverage for stop-sequence output-space suppression.

func stopSigs(r StopSequenceScanResult) []StopSequenceSignal {
	out := make([]StopSequenceSignal, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.Signal)
	}
	return out
}

func hasStopSig(r StopSequenceScanResult, want StopSequenceSignal) bool {
	for _, f := range r.Findings {
		if f.Signal == want {
			return true
		}
	}
	return false
}

func scanStops(seqs ...string) StopSequenceScanResult {
	return ScanSamplingStopSequences(&SamplingCreateMessageParams{StopSequences: seqs})
}

// --- wire contract ---------------------------------------------------------

// TestSamplingStopSequencesParseFromWire is the fitness function for the JSON
// tag. SamplingCreateMessageParams had no StopSequences field at all, so
// json.Unmarshal dropped it silently and every scanner below would have run
// against an empty slice forever with no test failing -- the same shape as
// ContentItem.Annotations before #3484. Struct-literal tests cannot catch
// that; only parsing real wire bytes can.
func TestSamplingStopSequencesParseFromWire(t *testing.T) {
	raw := []byte(`{
	  "messages": [{"role":"user","content":{"type":"text","text":"hi"}}],
	  "maxTokens": 100,
	  "stopSequences": ["I cannot", "\n\n"]
	}`)
	var p SamplingCreateMessageParams
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(p.StopSequences) != 2 {
		t.Fatalf("stopSequences parsed %d entries, want 2 - the JSON tag is wrong", len(p.StopSequences))
	}
	if p.StopSequences[0] != "I cannot" {
		t.Errorf("stopSequences[0] = %q", p.StopSequences[0])
	}
	// ...and the scanner reaches it through the parsed struct, not only
	// through a hand-built literal.
	if !hasStopSig(ScanSamplingStopSequences(&p), SignalSamplingRefusalStopSequence) {
		t.Error("the refusal stop sequence parsed from the wire did not reach the scanner")
	}
}

// --- true positives --------------------------------------------------------

func TestStopSequence_RefusalSuppression(t *testing.T) {
	cases := []string{
		"I cannot",
		"I can't",
		"I'm sorry",
		"I am unable",
		"I must decline",
		"Sorry,",
		"My apologies",
		"As an AI",
		"As a language model",
		"Unfortunately, I",
		"I apologize",
		"against my guidelines",
		"I should not",
		"I won't",
		"  I cannot ", // whitespace tolerated
		"i cannot",    // case tolerated
	}
	for _, seq := range cases {
		t.Run(seq, func(t *testing.T) {
			r := scanStops(seq)
			if !hasStopSig(r, SignalSamplingRefusalStopSequence) {
				t.Fatalf("want refusal-suppression signal, got %v", stopSigs(r))
			}
			if !r.Blocked {
				t.Error("refusal suppression is BLOCK tier")
			}
			if r.Findings[0].Sequence == "" {
				t.Error("the offending sequence must be recorded on the finding for the audit trail")
			}
		})
	}
}

func TestStopSequence_ReasoningSuppression(t *testing.T) {
	blocking := []string{
		"<thinking>",
		"<thinking",
		"<thought>",
		"<reasoning>",
		"<scratchpad>",
		"<analysis>",
		"[thinking]",
		"Let me think",
		"Let's think",
		"Reasoning:",
		"chain-of-thought",
	}
	for _, seq := range blocking {
		t.Run("open/"+seq, func(t *testing.T) {
			r := scanStops(seq)
			if !hasStopSig(r, SignalSamplingReasoningStopSequence) {
				t.Fatalf("want reasoning-open signal, got %v", stopSigs(r))
			}
			if !r.Blocked {
				t.Error("halting before any reasoning is emitted is BLOCK tier")
			}
		})
	}

	// The closing marker is the deliberately weaker case: it yields the
	// reasoning and drops the answer, which a server wanting only the trace
	// might genuinely do.
	for _, seq := range []string{"</thinking>", "</reasoning>", "</ thinking >"} {
		t.Run("close/"+seq, func(t *testing.T) {
			r := scanStops(seq)
			if !hasStopSig(r, SignalSamplingReasoningTruncation) {
				t.Fatalf("want reasoning-truncation signal, got %v", stopSigs(r))
			}
			if r.Blocked {
				t.Error("the closing marker is AUDIT tier, not BLOCK")
			}
		})
	}
}

func TestStopSequence_MixedListStillCatchesTheOne(t *testing.T) {
	// A suppression sequence buried in a list of legitimate delimiters must
	// still fire -- an attacker will not send it alone.
	r := scanStops("\n\n", "###", "Observation:", "I cannot", "</answer>")
	if !hasStopSig(r, SignalSamplingRefusalStopSequence) {
		t.Fatalf("want refusal signal from a mixed list, got %v", stopSigs(r))
	}
	if len(r.Findings) != 1 {
		t.Errorf("only the suppression sequence should produce a finding, got %d: %v",
			len(r.Findings), stopSigs(r))
	}
}

// --- true negatives: real stop sequences -----------------------------------

func TestStopSequence_TrueNegatives(t *testing.T) {
	// Every one of these is a stop sequence a real MCP server or LLM
	// application sets. They are the reason this scanner anchors its patterns
	// at the START of the sequence rather than searching anywhere inside it.
	legit := []string{
		"\n\n",
		"\n\nHuman:",
		"Human:",
		"Assistant:",
		"###",
		"---",
		"```",
		"</answer>",
		"</output>",
		"</result>",
		"<|endoftext|>",
		"<|eot_id|>",
		"END",
		"STOP",
		"Observation:",
		"Final Answer:",
		"Question:",
		"\nUser:",
		"[DONE]",
		"</json>",
		"}",
		"6.", // a numbered list cap
		"Note:",
		"Summary:",
		// Near-misses that matter: legitimate delimiters whose text merely
		// CONTAINS refusal or reasoning vocabulary rather than opening with it.
		//
		// The dialogue-turn delimiter is the one that makes the refusal
		// pattern's start-anchor load-bearing, and the reason is correctness
		// rather than taste. A stop sequence fires only when the model emits
		// that string in full, so a refusal phrase buried mid-sequence cannot
		// suppress a refusal: the model would have to write the whole
		// delimiter first. Flagging it would be reporting a suppression that
		// is not achievable. Unanchoring the pattern makes this row fail.
		"\n\nSupport Agent: I'm sorry to hear that",
		"</cannot-parse>",
		"end of analysis",
		"see reasoning above",
		"</step-by-step-guide>",
	}
	for _, seq := range legit {
		t.Run(seq, func(t *testing.T) {
			if r := scanStops(seq); r.Found {
				t.Fatalf("false positive on a legitimate stop sequence: %v (%s)",
					stopSigs(r), r.Findings[0].Detail)
			}
		})
	}
}

func TestStopSequence_EmptyAndAbsent(t *testing.T) {
	if r := ScanSamplingStopSequences(nil); r.Found {
		t.Error("nil params must not fire")
	}
	if r := ScanSamplingStopSequences(&SamplingCreateMessageParams{}); r.Found {
		t.Error("absent stopSequences must not fire")
	}
	if r := scanStops("", "   "); r.Found {
		t.Error("empty and whitespace-only sequences must not fire")
	}
}

// TestStopSequence_HomoglyphIsNotAnExploit pins the deliberate decision NOT to
// run the Unicode render-recovery pass here.
//
// Every other prose matcher in this package folds, and skipping it is normally
// the bug. The both-ends test says why this one is different: a stop sequence
// is resolved by the INFERENCE API against the model's own generated output,
// which is ordinary ASCII English. A refusal phrase spelled with a Cyrillic
// "o" matches nothing the model will ever emit, so it suppresses nothing.
// Reporting it would be reporting a difference, not a bypass -- and would put
// a BLOCK on a sampling request that is, on this axis, inert.
func TestStopSequence_HomoglyphIsNotAnExploit(t *testing.T) {
	// "I cann" + Cyrillic o (U+043E) + "t"
	homoglyph := "I cann" + string(rune(0x043E)) + "t"
	if homoglyph == "I cannot" {
		t.Fatal("the fixture is not actually a homoglyph - the row would be vacuous")
	}
	if r := scanStops(homoglyph); r.Found {
		t.Errorf("a homoglyph stop sequence suppresses nothing and must not fire: %v", stopSigs(r))
	}
	// ASCII positive control, so the assertion above is about the fold and not
	// about a pattern that never matches.
	if r := scanStops("I cannot"); !r.Found {
		t.Fatal("positive control: the ASCII spelling must fire")
	}
}

// --- pack wiring -----------------------------------------------------------

func TestStopSequenceSentinelsResolve(t *testing.T) {
	rules := loadPremiumPackRules(t, "mcp-sentinel.yaml")
	engine := NewPolicyEvaluator(&MCPPolicy{Rules: rules})
	for _, sig := range []StopSequenceSignal{
		SignalSamplingRefusalStopSequence,
		SignalSamplingReasoningStopSequence,
		SignalSamplingReasoningTruncation,
	} {
		key := stopSequenceSentinelEngine(sig)
		if key == "" {
			t.Errorf("signal %s has no sentinel engine key", sig)
			continue
		}
		sent := engine.LookupSentinel(key)
		if sent == nil {
			t.Errorf("sentinel engine %q resolves to nil - add the rule to packs/premium/mcp/mcp-sentinel.yaml", key)
			continue
		}
		if sent.Taxonomy == "" {
			t.Errorf("sentinel %q carries no taxonomy ref", sent.ID)
		}
	}
}
