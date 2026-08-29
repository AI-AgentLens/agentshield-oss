package mcp

import (
	"regexp"

	"github.com/AI-AgentLens/agentshield/internal/unicode"
)

// VerificationLoopSignal identifies a fabricated multi-turn "verification
// protocol" status token in an MCP tool call response.
//
// Taxonomy: unauthorized-execution/ai-resource-abuse/skill-verification-protocol-token-drain
//
// Threat model (Clawdrain, arXiv:2603.00902): a trojanized agent "skill"
// (instruction file + companion script) tells the agent that every task must
// pass a fabricated multi-turn "verification protocol" before it can be
// considered complete. A bundled helper script the skill instructs the agent
// to invoke after each work step returns a status token (PROGRESS, REPAIR,
// TERMINAL) that the skill's own instructions say the agent must obey. The
// agent, acting in good faith on what looks like a legitimate quality gate,
// loops through extra reasoning/tool-calling cycles — 6-9x token
// amplification over a benign baseline with no additional useful output.
//
// This is structurally different from a jailbreak/instruction-override
// directive: there is no moment telling the model to discard its prior
// guidance. The signal here is a fabricated incompleteness/progress claim
// combined with a directive to continue, retry, or re-run — exactly the
// shape a legitimate CI/build tool or task tracker also uses for real status
// reporting. Precision therefore requires BOTH:
//   (a) the specific PROGRESS/REPAIR/TERMINAL-style fabricated-protocol
//       vocabulary from the taxonomy's own worked examples, AND
//   (b) a directive-like continuation element telling the agent to repeat,
//       retry, or re-run a verification step rather than just reporting status.
// A bare status word ("PROGRESS: 3/10 files migrated") is a legitimate
// build-tool progress log and must not fire this signal alone.
type VerificationLoopSignal string

const (
	// SignalVerificationLoopTokenDrain fires when a tool response contains a
	// fabricated verification-protocol status token (PROGRESS/REPAIR/TERMINAL-
	// style marker naming a "verification" round or protocol) AND a
	// directive-like element instructing the agent to continue, retry, or
	// re-run — the combination that distinguishes a token-drain loop from a
	// legitimate CI/build/task-tracker status update.
	SignalVerificationLoopTokenDrain VerificationLoopSignal = "verification_loop_token_drain"
)

// VerificationLoopFinding records one detected fabricated-verification-loop
// signal in a tool response.
type VerificationLoopFinding struct {
	Signal  VerificationLoopSignal
	Detail  string
	Snippet string
}

// VerificationLoopScanResult is the outcome of ScanToolCallResponseForVerificationLoop.
type VerificationLoopScanResult struct {
	Found    bool
	Findings []VerificationLoopFinding
}

// ScanToolCallResponseForVerificationLoop inspects tool response text content
// for a skill-delivered verification-protocol token-drain pattern: a
// fabricated PROGRESS/REPAIR/TERMINAL-style status marker for a named
// "verification" round/protocol, co-occurring with a directive telling the
// agent to continue, retry, or re-run rather than simply reporting status.
//
// AUDIT-tier only (does not set Blocked) — this is a resource-abuse /
// denial-of-wallet pattern, not credential or data theft, and the combined
// signal still carries meaningful FP risk against unusual-but-legitimate
// task-runner phrasing. Call sites should surface findings as AUDIT and fall
// through, mirroring ScanToolCallResponseForTracebacks.
func ScanToolCallResponseForVerificationLoop(items []ContentItem) VerificationLoopScanResult {
	var result VerificationLoopScanResult
	for _, item := range items {
		if item.Type != "text" || item.Text == "" {
			continue
		}
		scanVerificationLoopText(&result, item.Text)
		scanVerificationLoopSeparatorFolded(&result, item.Text)
	}
	result.Found = len(result.Findings) > 0
	return result
}

// scanVerificationLoopSeparatorFolded re-runs the verification-loop scan
// against a separator-normalized rendering of the text, appending only
// findings the raw pass did not already produce.
//
// Both verificationStatusTokenRE and verificationContinueDirectiveRE are
// spelled with `\s`/`\s+`/`\s*`, and Go's RE2 `\s` class is ASCII-only — a
// skill's helper script can render its status-drain payload with a Unicode
// separator (e.g. "segmented" + U+00A0 + "verification" + U+00A0 +
// "protocol") and the whole-word tokens still read as ordinary English to
// the model while matching neither regex. See unicode.FoldUnicodeSeparators
// and scanResponseSeparatorFolded (response_scanner.go) for the fold
// rationale and false-positive-safety argument this mirrors.
func scanVerificationLoopSeparatorFolded(result *VerificationLoopScanResult, text string) {
	folded, changed := unicode.FoldUnicodeSeparators(text)
	if !changed {
		return
	}

	seen := make(map[string]bool, len(result.Findings))
	for _, f := range result.Findings {
		seen[string(f.Signal)+"\x00"+f.Detail] = true
	}

	var foldedResult VerificationLoopScanResult
	scanVerificationLoopText(&foldedResult, folded)

	for _, f := range foldedResult.Findings {
		key := string(f.Signal) + "\x00" + f.Detail
		if seen[key] {
			continue
		}
		seen[key] = true
		f.Detail = f.Detail + " — recovered by folding non-ASCII Unicode separator characters " +
			"(NBSP / thin / ideographic space and siblings) to ASCII; RE2's `\\s` class is ASCII-only, " +
			"so the text as sent matched no pattern while rendering and tokenizing identically"
		result.Findings = append(result.Findings, f)
	}
}

func scanVerificationLoopText(result *VerificationLoopScanResult, text string) {
	statusLoc := verificationStatusTokenRE.FindStringIndex(text)
	if statusLoc == nil {
		return
	}
	if !verificationContinueDirectiveRE.MatchString(text) {
		return
	}
	result.Findings = append(result.Findings, VerificationLoopFinding{
		Signal: SignalVerificationLoopTokenDrain,
		Detail: "tool response contains a fabricated verification-protocol status token " +
			"(PROGRESS/REPAIR/TERMINAL-style marker for a named verification round or " +
			"protocol) combined with a directive to continue, retry, or re-run — the " +
			"signature of a skill-delivered verification-protocol token-drain loop " +
			"rather than a genuine one-shot status report",
		Snippet: safeSnippet(text, statusLoc[0], 100),
	})
}

// verificationStatusTokenRE matches fabricated multi-turn "verification
// protocol" status tokens: a PROGRESS/REPAIR/REPAIR_NEEDED/TERMINAL/
// VERIFICATION_INCOMPLETE-style label attached to a named verification round
// or protocol. Anchored on the taxonomy's own worked vocabulary
// (Segmented Verification Protocol) rather than generic CI words like
// "progress" or "build" alone, which are common in legitimate tool output.
var verificationStatusTokenRE = regexp.MustCompile(
	`(?i)\b(PROGRESS|REPAIR(?:_NEEDED)?|TERMINAL|VERIFICATION_INCOMPLETE)\s*:\s*` +
		`.{0,80}\b(verification|re-?verif\w*)\b` +
		`|\bverification\s+(?:round|protocol)\b.{0,40}\b(PROGRESS|REPAIR(?:_NEEDED)?|TERMINAL|VERIFICATION_INCOMPLETE)\b` +
		`|\bsegmented\s+verification\s+protocol\b`,
)

// verificationContinueDirectiveRE matches a directive-like continuation
// element: phrasing instructing the agent to make another pass, redo/retry
// work, or re-run a verification step, or asserting that only a further
// status means the task is complete. This is what separates a control-flow
// fiction from a plain status report — a legitimate progress log reports
// state, it does not tell the reader to loop.
var verificationContinueDirectiveRE = regexp.MustCompile(
	`(?i)(make\s+(?:one\s+more|another)\s+(?:improvement\s+)?pass\s+and\s+re-?run` +
		`|undo\s+the\s+last\s+change.{0,20}retry.{0,20}re-?run` +
		`|(?:retry|redo|repeat)\s+(?:the\s+)?(?:last\s+)?(?:step|work|change)s?\s+and\s+re-?run` +
		`|re-?run\s+(?:the\s+)?verif\w*` +
		`|only\s+a\s+terminal\s+status\s+means\s+the\s+task\s+is\s+complete` +
		`|continue\s+to\s+the\s+next\s+verification\s+round` +
		`|(?:round\s+)?\d+\s+of\s+unknown\s+total)`,
)
