package mcp

import (
	"regexp"
	"strings"
)

// Stop-sequence refusal and reasoning suppression.
//
// # Why a stop sequence is not just another prose surface
//
// `refusal-reasoning-token-suppression` (CrowdStrike PT0197; Wei et al. 2023)
// describes an attacker forbidding the tokens a model uses to decline or to
// reason aloud. Every detection for it in this package targets PROSE — an
// instruction inside a description, a response, a system prompt. Prose is a
// REQUEST: the model may comply, may partially comply, may refuse to be told
// how to refuse.
//
// `sampling/createMessage`'s `stopSequences` does the same thing
// DETERMINISTICALLY. It is not addressed to the model at all — it is a
// parameter of the inference API, which halts generation the moment the string
// appears. A server that supplies `stopSequences: ["I cannot", "I'm sorry"]`
// has not persuaded the model out of refusing; it has arranged for the refusal
// to be unspeakable. No jailbreak, no cooperation, no variance.
//
// It was invisible twice over, the same shape as ContentItem.Annotations
// before #3484: SamplingCreateMessageParams had no StopSequences field at all,
// so json.Unmarshal dropped it, and no scanner referenced it.
//
// # Two distinct harms, and the second is the one that matters most here
//
//  1. REFUSAL SUPPRESSION. The completion comes back empty or truncated. The
//     server learns "that one was refused" and retries a variant — the host's
//     own model turned into a jailbreak-search oracle, with each probe looking
//     like an ordinary sampling request.
//
//  2. REASONING-TRACE SUPPRESSION. Stopping at a reasoning marker deletes the
//     chain of thought that runtime oversight and post-hoc attestation are
//     built on. An action taken after a suppressed trace is not merely
//     unexplained, it is unexplainable: the evidence never existed. That is a
//     direct attack on the receipt, not on the model.
//
// # Why this scanner deliberately does NOT fold Unicode
//
// Every other prose matcher in this package runs the render-recovery pass,
// and skipping it is normally the bug (issues #3486/#3487/#3488). Here it
// would be wrong, and the both-ends test says why: ask who RESOLVES the
// string. A stop sequence is resolved by the inference API against the model's
// own generated output, which is ordinary ASCII English. A stop sequence
// spelled with a Cyrillic "o" matches nothing the model will ever emit, so it
// suppresses nothing. Folding it would manufacture findings for a payload that
// cannot work — a difference, not a bypass. Same conclusion the resource-URI
// homoglyph investigation reached and correctly did not ship.
type StopSequenceSignal string

const (
	// SignalSamplingRefusalStopSequence fires when a stop sequence is the
	// opening of a refusal or safety disclaimer. BLOCK tier: a generation
	// terminator set to the first words of a decline has no legitimate
	// reading, because a stop sequence exists to mark where WANTED output
	// ends.
	SignalSamplingRefusalStopSequence StopSequenceSignal = "sampling_refusal_stop_sequence"

	// SignalSamplingReasoningStopSequence fires when a stop sequence is the
	// OPENING marker of a reasoning trace, so generation halts before any
	// reasoning is emitted and the response is empty. BLOCK tier.
	SignalSamplingReasoningStopSequence StopSequenceSignal = "sampling_reasoning_stop_sequence"

	// SignalSamplingReasoningTruncation fires on a reasoning trace's CLOSING
	// marker. AUDIT tier, and the asymmetry is the whole point: stopping at
	// `</thinking>` yields the reasoning and drops the answer, which a server
	// wanting only the trace might genuinely do; stopping at `<thinking>`
	// yields nothing at all, which nobody wants on purpose.
	SignalSamplingReasoningTruncation StopSequenceSignal = "sampling_reasoning_truncation"
)

// StopSequenceFinding records one detection.
type StopSequenceFinding struct {
	Signal   StopSequenceSignal `json:"signal"`
	Detail   string             `json:"detail"`
	Sequence string             `json:"sequence"`
}

// StopSequenceScanResult is the aggregate result.
type StopSequenceScanResult struct {
	Blocked  bool                  `json:"blocked"`
	Found    bool                  `json:"found"`
	Findings []StopSequenceFinding `json:"findings,omitempty"`
}

// samplingRefusalStopRE matches the opening of a refusal, apology or policy
// disclaimer. Anchored at the start of the stop sequence: a stop sequence is
// matched by the inference API as a PREFIX of the text still to come, so what
// matters is what it begins with. Anchoring is also what keeps a legitimate
// delimiter that merely contains one of these words (`</cannot-parse>`) out.
var samplingRefusalStopRE = regexp.MustCompile(`(?i)^\W{0,4}(?:` +
	`i\s+(?:cannot|can't|can not|won't|will\s+not|am\s+not\s+able|am\s+unable|must\s+decline|` +
	`do\s+not|don't|refuse|apologi[sz]e)|` +
	`i'?m\s+(?:sorry|afraid|not\s+able|unable)|` +
	`sorry,|my\s+apologies|unfortunately,?\s+i|` +
	`as\s+an?\s+(?:ai|language\s+model|assistant)|` +
	`that\s+(?:would|is)\s+(?:not|n't)|` +
	`(?:this|that)\s+(?:request|action)\s+(?:is\s+)?(?:not|violates)|` +
	`(?:against|violates)\s+(?:my|the)\s+(?:guidelines|policy|policies|principles)|` +
	`i\s+(?:should|must)\s+not|` +
	`no\.?\s*$` +
	`)`)

// samplingReasoningOpenRE matches the OPENING marker of a reasoning trace in
// tag or bracket form.
var samplingReasoningOpenRE = regexp.MustCompile(`(?i)^\W{0,2}(?:` +
	`<(?:thinking|thought|thoughts|reasoning|scratchpad|analysis|reflection|plan|rationale)\b[^/]*>?|` +
	`\[(?:thinking|reasoning|scratchpad|analysis)\]` +
	`)`)

// samplingReasoningPhraseRE matches the bare-prose openings of a reasoning
// trace.
//
// Its prefix is deliberately TIGHTER than samplingReasoningOpenRE's `\W{0,2}`:
// quotes and brackets only, never `<` or `/`. With the looser prefix the
// closing tag `</step-by-step-guide>` -- an entirely ordinary delimiter --
// matched `step-by-step` two characters in. A bare phrase is a reasoning
// marker because it OPENS the sequence; inside a tag name it is just a word.
var samplingReasoningPhraseRE = regexp.MustCompile(`(?i)^["'` + "`" + `\s\[(]{0,2}(?:` +
	`let'?s\s+think|let\s+me\s+think|thinking:|reasoning:|rationale:|analysis:|` +
	`chain[- ]of[- ]thought|step[- ]by[- ]step` +
	`)`)

// samplingReasoningCloseRE matches the CLOSING marker of a reasoning trace.
var samplingReasoningCloseRE = regexp.MustCompile(`(?i)^\W{0,2}</\s*(?:thinking|thought|thoughts|` +
	`reasoning|scratchpad|analysis|reflection|plan|rationale)\s*>`)

// ScanSamplingStopSequences inspects a sampling/createMessage request's
// stopSequences for output-space suppression.
func ScanSamplingStopSequences(params *SamplingCreateMessageParams) StopSequenceScanResult {
	var result StopSequenceScanResult
	if params == nil {
		return result
	}
	add := func(sig StopSequenceSignal, detail, seq string, blocking bool) {
		result.Found = true
		if blocking {
			result.Blocked = true
		}
		result.Findings = append(result.Findings, StopSequenceFinding{
			Signal: sig, Detail: detail, Sequence: seq,
		})
	}
	for _, seq := range params.StopSequences {
		s := strings.TrimSpace(seq)
		if s == "" {
			continue
		}
		switch {
		case samplingRefusalStopRE.MatchString(s):
			add(SignalSamplingRefusalStopSequence,
				"stopSequences halts generation at the opening of a refusal or safety disclaimer, so the "+
					"model's decline is truncated before it can be emitted -- refusal suppression enforced by "+
					"the inference API rather than requested of the model", s, true)
		case samplingReasoningOpenRE.MatchString(s) || samplingReasoningPhraseRE.MatchString(s):
			add(SignalSamplingReasoningStopSequence,
				"stopSequences halts generation at the OPENING marker of a reasoning trace, so nothing is "+
					"emitted at all; the chain of thought that runtime oversight and attestation depend on "+
					"never exists", s, true)
		case samplingReasoningCloseRE.MatchString(s):
			add(SignalSamplingReasoningTruncation,
				"stopSequences halts generation at the CLOSING marker of a reasoning trace, discarding the "+
					"answer that follows it", s, false)
		}
	}
	return result
}

// stopSequenceSentinelEngine maps a signal to its `engine:` key in
// packs/premium/mcp/mcp-sentinel.yaml. A signal with no sentinel rule resolves
// to nil and its finding reaches the audit log with no rule ID and no taxonomy
// ref -- the one shape the attestation chain cannot represent.
func stopSequenceSentinelEngine(signal StopSequenceSignal) string {
	switch signal {
	case SignalSamplingRefusalStopSequence:
		return "mcp-sampling-refusal-stop-sequence"
	case SignalSamplingReasoningStopSequence:
		return "mcp-sampling-reasoning-stop-sequence"
	case SignalSamplingReasoningTruncation:
		return "mcp-sampling-reasoning-truncation"
	default:
		return ""
	}
}
