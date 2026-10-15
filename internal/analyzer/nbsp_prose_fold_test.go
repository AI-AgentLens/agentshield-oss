package analyzer_test

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// quotedSpacesTo swaps the ASCII spaces inside quoted strings for r, leaving
// the spaces bash splits words on alone. Same construction as the guardian
// parity test (#4294): NBSP is not a separator to bash, so only quoted prose
// is a fair probe.
func quotedSpacesTo(cmd string, r rune) string {
	var b strings.Builder
	var quote rune
	escaped := false
	for _, c := range cmd {
		switch {
		case escaped:
			escaped = false
		case c == '\\' && quote != '\'':
			escaped = true
		case quote == 0 && (c == '\'' || c == '"'):
			quote = c
		case quote != 0 && c == quote:
			quote = 0
		case quote != 0 && c == ' ':
			b.WriteRune(r)
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

// Measured for #4310 on c1b64b30-era main (every BLOCK corpus command with a
// quoted space, spaces swapped for U+00A0): 732 commands; 144 decided lower
// (a), 69 lost rule attribution only (b). The (a) set is overwhelmingly shell,
// SQL and config text, where NBSP is not a separator and the drop is correct.
// The prose subset below is what carries command_fold_separators; after it,
// 128 (a) remain, none of them prose an LLM reads.

// proseFoldRules are the pack rules whose pattern matches prose an LLM later
// reads (#4310), so they carry command_fold_separators. The rest of the
// measured drops (SQL, shell bodies, config values) are not prose to a model:
// NBSP is not a word separator to bash, mysql or YAML, so folding them would
// invent commands nothing runs.
var proseFoldRules = []string{
	"ts-block-self-propagating-injection",
	"ts-block-jailbreak-compliance-prefix",
	"ts-block-indirect-injection-html-comment",
	"ts-block-indirect-injection-markdown-alt",
	"ts-block-pr-description-ai-reviewer-bypass",
	"ts-block-instruction-file-exfil-embed",
	"ts-block-refusal-vocabulary-suppression",
	"ts-block-best-of-n-jailbreak-meta",
	"ts-block-roleplay-jailbreak-activation",
	"ts-block-mcp-tool-description-poisoning-write",
}

// TestProseRulesSurviveNBSP is the ratchet for #4310: every corpus command on
// which a prose rule fires keeps that rule, and the BLOCK, when the spaces in
// its quoted strings become U+00A0. The floor keeps an emptied corpus or a
// broken transform from passing as "0 leaked".
func TestProseRulesSurviveNBSP(t *testing.T) {
	// The >= 25 floor is sized to the full corpus (31 commands measured
	// 2026-10-12); the community corpus has 9.
	ossbuild.SkipPremiumSized(t)
	engine, baseline := blockingBaseline(t)
	prose := map[string]bool{}
	for _, id := range proseFoldRules {
		prose[id] = true
	}
	tested := 0
	for _, tc := range baseline {
		probe := quotedSpacesTo(tc.Command, '\u00a0')
		if probe == tc.Command {
			continue
		}
		want := []string{}
		for _, r := range engine.Evaluate(tc.Command, nil).TriggeredRules {
			if prose[r] {
				want = append(want, r)
			}
		}
		if len(want) == 0 {
			continue
		}
		tested++
		got := engine.Evaluate(probe, nil)
		have := map[string]bool{}
		for _, r := range got.TriggeredRules {
			have[r] = true
		}
		for _, r := range want {
			if !have[r] || string(got.Decision) != "BLOCK" {
				t.Errorf("%s: %s lost under NBSP (decision %s): %q", tc.ID, r, got.Decision, probe)
			}
		}
	}
	// Measured 2026-10-12: 31 commands.
	if tested < 25 {
		t.Fatalf("only %d corpus commands exercise a prose rule; want >= 25 (vacuous probe?)", tested)
	}
}
