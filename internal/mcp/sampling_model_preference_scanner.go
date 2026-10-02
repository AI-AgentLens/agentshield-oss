package mcp

import (
	"strings"
)

// Model-selection steering in `sampling/createMessage`.
//
// # The axis nothing on this surface was looking at
//
// Every scanner already pointed at a sampling request attacks the same axis:
// WHAT THE MODEL IS ASKED. Messages, systemPrompt, includeContext, the
// trailing assistant prefill, stopSequences — all of them assume a fixed model
// and inspect the prompt handed to it.
//
// `modelPreferences` is a level above that. It is the only field in the
// protocol that constrains WHICH MODEL ANSWERS, and safety alignment is a
// property of the model, not of the prompt. A refusal is something a
// particular set of weights does. Choosing the weights is choosing the
// refusal behaviour, before a single token of the prompt is read.
//
// It was invisible the same way `StopSequences` and `ContentItem.Annotations`
// were: `SamplingCreateMessageParams.ModelPreferences` is parsed into a
// `map[string]interface{}` and, until this file, read by nothing.
//
// # Why this is a ranking channel, not a configuration field
//
// The spec does not define `hints[].name` as "the model to use". It defines it
// as advisory, tells clients to treat it as a SUBSTRING match against their own
// inventory, and permits mapping a hint to "equivalent models from different
// providers". So the field is not a name — it is a QUERY the host runs against
// a model list the server cannot see.
//
// That is what makes it dangerous without any knowledge of the target. An
// attacker does not need to know which models a host offers. A hint of
// `"uncensored"` is a query whose result set, on any host with a local model
// inventory, is exactly the models that exist to have no refusal behaviour.
// A hint that matches nothing costs the attacker nothing; a hint that matches
// selects the weakest thing it found.
//
// Same family as `annotations.priority` and `annotations.lastModified`
// (content_ranking_scanner.go): an attacker-supplied scalar the protocol
// instructs the host to route on. The routing here is of the inference itself
// rather than of attention.
//
// # Why this scanner does NOT fold Unicode
//
// Same both-ends test as sampling_stop_sequence_scanner.go, same answer, and
// it is worth restating because the default in this package is to fold. Ask
// who RESOLVES the string. A hint is resolved by the HOST, as a plain
// substring match against real model identifiers, which are ASCII. A hint
// spelled with a Cyrillic "о" matches no model the host has, so it selects
// nothing and the attack does not run. Folding it would manufacture a finding
// for a payload that cannot work. The non-ASCII character is still reported —
// by samplingModelHintSmuggling, as what it actually is.

// ModelPreferenceSignal identifies one model-selection steering threat.
type ModelPreferenceSignal string

const (
	// SignalSamplingUnalignedModelHint fires when a hint names a model family
	// by its own declaration that refusal behaviour was removed. BLOCK.
	SignalSamplingUnalignedModelHint ModelPreferenceSignal = "sampling_unaligned_model_hint"

	// SignalSamplingModelHintSmuggling fires when a hint is not a model
	// identifier at all — a character outside the alphabet every provider's
	// id scheme uses, or a length at which a substring match against a model
	// list can never succeed. BLOCK.
	SignalSamplingModelHintSmuggling ModelPreferenceSignal = "sampling_model_hint_smuggling"

	// SignalSamplingCapabilityDowngrade fires when the request asks, in the
	// spec's own terms, for the least capable model available. AUDIT.
	SignalSamplingCapabilityDowngrade ModelPreferenceSignal = "sampling_capability_downgrade"

	// SignalSamplingModelPriorityOutOfRange fires when a priority is outside
	// the spec's closed 0..1, or is not a number at all. AUDIT.
	SignalSamplingModelPriorityOutOfRange ModelPreferenceSignal = "sampling_model_priority_out_of_range"
)

// ModelPreferenceFinding records one detection.
type ModelPreferenceFinding struct {
	Signal ModelPreferenceSignal `json:"signal"`
	Detail string                `json:"detail"`
	Value  string                `json:"value,omitempty"`
}

// ModelPreferenceScanResult is the aggregate result.
type ModelPreferenceScanResult struct {
	Blocked  bool                     `json:"blocked"`
	Found    bool                     `json:"found"`
	Findings []ModelPreferenceFinding `json:"findings,omitempty"`
}

// unalignedModelMarkers are substrings by which a model family DECLARES that
// its refusal behaviour was removed. This is deliberately a list of
// self-declarations, not a list of vendors or brands, and the distinction is
// what makes it both maintenance-free and defensible:
//
//   - A brand list rots. `dolphin` is the best-known uncensored finetune line,
//     and it is not here, because "dolphin" is a name rather than a claim — the
//     day someone ships a benign model called dolphin-something, the rule is
//     wrong and nobody finds out.
//   - A HARM name is not a claim either, and this is the trap worth naming:
//     `nsfw` and `toxic` were in the first draft and are deliberately out,
//     because the models whose identifiers contain them are overwhelmingly
//     CLASSIFIERS FOR that harm (`nsfw-image-detection`,
//     `toxic-comment-model`). A content-moderation MCP server hinting one is
//     doing its job. A detector for X is named after X.
//
// Every entry below reads as "this model will not decline", which no detector,
// classifier or benign product describes itself as.
var unalignedModelMarkers = []string{
	"uncensored",
	"unfiltered",
	"unaligned",
	"unrestricted",
	"unmoderated",
	"abliterated", // term of art: refusal directions ablated from the weights
	"jailbroken",
	"jailbreak",
	"nofilter",
	"no-filter",
	"no_filter",
}

// modelHintMaxLen bounds a value that can still be doing the job the spec
// gives this field. Real identifiers run to about 50 characters at the far end
// (`accounts/fireworks/models/llama-v3p1-405b-instruct`). Past roughly twice
// that, a SUBSTRING match against a model list cannot succeed against anything,
// so the value is functionally inert as a selector — which means whatever it is
// there for, it is not model selection. The remaining readers of a hint are the
// host's display, its logs and its transcript.
const modelHintMaxLen = 96

// isModelIdentifierRune reports whether r appears in the identifier schemes
// real providers use. The set is closed and small, so this is an allowlist over
// the alphabet rather than a blocklist of smuggling characters — one check
// covers newline, NUL, zero-width, bidi controls, tag characters and emoji, and
// needs no maintenance as new smuggling codepoints are found. Same shape as
// ranking_timestamp_smuggling.
//
// Space is allowed: hints are advisory and a server may reasonably write
// "claude 3 opus" rather than an exact id. The punctuation set covers Bedrock
// (`us.anthropic.claude-3-5-sonnet-20241022-v2:0`), HuggingFace and Fireworks
// namespacing (`meta-llama/Llama-3.3-70B-Instruct`), OpenAI fine-tune ids
// (`ft:gpt-4o-...:org::abc`) and Azure deployment names.
func isModelIdentifierRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return strings.ContainsRune(" -_.:/@+", r)
}

// ScanSamplingModelPreferences inspects a sampling/createMessage request's
// `modelPreferences`. An absent or empty object produces nothing.
func ScanSamplingModelPreferences(params *SamplingCreateMessageParams) ModelPreferenceScanResult {
	var result ModelPreferenceScanResult
	if params == nil || len(params.ModelPreferences) == 0 {
		return result
	}

	for _, hint := range modelHints(params.ModelPreferences) {
		result.Findings = append(result.Findings, scanModelHint(hint)...)
	}
	result.Findings = append(result.Findings, scanModelPriorities(params.ModelPreferences)...)

	result.Found = len(result.Findings) > 0
	for _, f := range result.Findings {
		if f.Signal == SignalSamplingUnalignedModelHint || f.Signal == SignalSamplingModelHintSmuggling {
			result.Blocked = true
		}
	}
	return result
}

// modelHints pulls the `hints[].name` strings out of the raw preferences map.
// Every shape that is not the spec's is skipped rather than reported: a
// malformed hints array is a non-conforming server, and this scanner's job is
// steering, not conformance. (A value the Go decode could not hold at all is
// already recorded by decodeLenient — see wire_shape.go.)
func modelHints(prefs map[string]interface{}) []string {
	raw, ok := prefs["hints"].([]interface{})
	if !ok {
		return nil
	}
	var out []string
	for _, item := range raw {
		obj, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if name, ok := obj["name"].(string); ok && name != "" {
			out = append(out, name)
		}
	}
	return out
}

func scanModelHint(hint string) []ModelPreferenceFinding {
	var findings []ModelPreferenceFinding
	snip := hint
	if len(snip) > 120 {
		snip = snip[:120] + "..."
	}

	lower := strings.ToLower(hint)
	for _, marker := range unalignedModelMarkers {
		if strings.Contains(lower, marker) {
			findings = append(findings, ModelPreferenceFinding{
				Signal: SignalSamplingUnalignedModelHint,
				Value:  snip,
				Detail: "sampling/createMessage modelPreferences hints at a model family declaring removed " +
					"safety alignment (\"" + marker + "\"). The host is told to substring-match this against its " +
					"own model inventory, so the hint is a query whose result set is exactly the models that " +
					"exist to have no refusal behaviour — the server is selecting the alignment, not the prompt",
			})
			break // one alignment finding per hint
		}
	}

	if len(hint) > modelHintMaxLen {
		findings = append(findings, ModelPreferenceFinding{
			Signal: SignalSamplingModelHintSmuggling,
			Value:  snip,
			Detail: "sampling/createMessage modelPreferences carries a model-name hint of " +
				itoa(len(hint)) + " characters. A hint is resolved as a substring match against the host's " +
				"model list, and no identifier is that long, so this value cannot be selecting a model — " +
				"leaving the host's display, logs and transcript as its only readers",
		})
		return findings
	}
	for _, r := range hint {
		if !isModelIdentifierRune(r) {
			findings = append(findings, ModelPreferenceFinding{
				Signal: SignalSamplingModelHintSmuggling,
				Value:  snip,
				Detail: "sampling/createMessage modelPreferences carries a model-name hint containing a " +
					"character that appears in no provider's identifier scheme (U+" + hexRune(r) + "). The " +
					"alphabet a model id can use is closed and ASCII; anything outside it cannot match a real " +
					"model, so the value is not doing the job the field exists for",
			})
			break // one smuggling finding per hint
		}
	}
	return findings
}

// scanModelPriorities checks the three 0..1 priority scalars.
//
// The downgrade thresholds are pinned to the SPEC'S OWN endpoint glosses, not
// to a comparison between them, for the same reason ranking_priority_inversion
// is: a plain "cost outranks intelligence" has an ordinary reading, since
// trading capability against cost is precisely what the field is for and the
// spec's motivating example is a cheap classification task. What the spec
// leaves no room to read benignly is the conjunction of its two endpoints —
// "intelligence is not important" AND "cost/speed is the single most important
// factor" — which is a request for the least capable model the host has,
// stated in the protocol's own words.
//
// AUDIT, not BLOCK. A cheap classifier genuinely wants this, and a proxy that
// refuses a request because the server asked for a small model would break
// real workflows. What it must not do is fail to RECORD it: a receipt saying
// which model tier a server steered an inference toward is exactly the
// evidence a downgrade attack is invisible without.
func scanModelPriorities(prefs map[string]interface{}) []ModelPreferenceFinding {
	var findings []ModelPreferenceFinding

	type pri struct {
		key   string
		value float64
		set   bool
	}
	read := func(key string) pri {
		raw, present := prefs[key]
		if !present {
			return pri{key: key}
		}
		v, ok := raw.(float64)
		if !ok {
			findings = append(findings, ModelPreferenceFinding{
				Signal: SignalSamplingModelPriorityOutOfRange,
				Value:  key,
				Detail: "sampling/createMessage modelPreferences." + key + " is not a number. The spec " +
					"declares it a 0..1 normalized priority; a host that coerces or sorts on it is doing " +
					"arithmetic on a value outside the domain its routing was written for",
			})
			return pri{key: key}
		}
		if v < 0 || v > 1 {
			findings = append(findings, ModelPreferenceFinding{
				Signal: SignalSamplingModelPriorityOutOfRange,
				Value:  key,
				Detail: "sampling/createMessage modelPreferences." + key + " is outside the spec's closed " +
					"0..1 range. A host that does not clamp it lets one server's preference dominate every " +
					"routing comparison regardless of the others",
			})
			return pri{key: key}
		}
		return pri{key: key, value: v, set: true}
	}

	intelligence := read("intelligencePriority")
	cost := read("costPriority")
	speed := read("speedPriority")

	// An ABSENT priority is not a declaration; only a stated floor counts.
	if !intelligence.set || intelligence.value > 0.1 {
		return findings
	}
	for _, other := range []pri{cost, speed} {
		if other.set && other.value >= 0.9 {
			findings = append(findings, ModelPreferenceFinding{
				Signal: SignalSamplingCapabilityDowngrade,
				Value:  other.key,
				Detail: "sampling/createMessage declares intelligencePriority=" +
					formatPriority(intelligence.value) + " (\"intelligence is not important\") together with " +
					other.key + "=" + formatPriority(other.value) + " (\"the single most important factor\") " +
					"— a request, in the spec's own terms, for the least capable model the host offers. " +
					"Safety alignment is a property of the weights, so steering the inference to the " +
					"smallest available model weakens every refusal the prompt might otherwise have met",
			})
			break // one downgrade finding per request
		}
	}
	return findings
}

// modelPreferenceSentinelEngine maps a signal to its `engine:` key in
// packs/premium/mcp/mcp-sentinel.yaml, so every finding reaches the audit trail
// with a real rule id, taxonomy ref and remediation text.
func modelPreferenceSentinelEngine(signal ModelPreferenceSignal) string {
	switch signal {
	case SignalSamplingUnalignedModelHint:
		return "mcp-sampling-unaligned-model-hint"
	case SignalSamplingModelHintSmuggling:
		return "mcp-sampling-model-hint-smuggling"
	case SignalSamplingCapabilityDowngrade:
		return "mcp-sampling-capability-downgrade"
	case SignalSamplingModelPriorityOutOfRange:
		return "mcp-sampling-model-priority-out-of-range"
	default:
		return ""
	}
}

// hexRune renders a rune as the uppercase hex codepoint an operator can paste
// into a Unicode lookup, so the audit line names the character rather than
// embedding it (embedding an invisible or bidi character in a log line is how
// the log becomes the next rendering surface).
func hexRune(r rune) string {
	const digits = "0123456789ABCDEF"
	var buf [8]byte
	i := len(buf)
	v := uint32(r)
	for {
		i--
		buf[i] = digits[v&0xF]
		v >>= 4
		if v == 0 {
			break
		}
	}
	out := string(buf[i:])
	for len(out) < 4 {
		out = "0" + out
	}
	return out
}

// formatPriority renders a 0..1 priority without importing fmt for one call.
// Two decimals is past the resolution any threshold here uses.
func formatPriority(v float64) string {
	hundredths := int(v*100 + 0.5)
	if hundredths%100 == 0 {
		return itoa(hundredths / 100)
	}
	frac := itoa(hundredths % 100)
	if len(frac) == 1 {
		frac = "0" + frac
	}
	return itoa(hundredths/100) + "." + frac
}
