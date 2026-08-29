package guardian

import "testing"

// Regression coverage for Shield#3516: signalToTaxonomy used to build a
// taxonomy-shaped string by concatenating sig.Category and sig.ID (e.g.
// "unauthorized-execution/prompt-injection/" + sig.ID). None of the 18
// resulting paths resolved to a real taxonomy node, and because the string
// was concatenation-built rather than a literal, check-taxonomy-refs.sh's
// Go-source scanner structurally excludes it — so every Guardian finding
// shipped a dangling ref into the audit log with no gate able to see it.
// These tests lock in the corrected per-signal mapping and guard against a
// future rule being added to heuristic.go without a matching case here.

func TestSignalToTaxonomy(t *testing.T) {
	cases := []struct {
		id   string
		want string
	}{
		{"instruction_override", "unauthorized-execution/agentic-attacks/tool-argument-injection"},
		{"prompt_exfiltration", "reconnaissance/llm-introspection/system-prompt-recovery-via-jailbreak"},
		{"disable_security", "persistence-evasion/defense-evasion/security-tool-tampering"},
		{"obfuscated_base64", "unauthorized-execution/obfuscation/interpreter-encoding-evasion"},
		{"obfuscated_hex", "unauthorized-execution/obfuscation/interpreter-encoding-evasion"},
		{"obfuscated_decoder_eval", "unauthorized-execution/obfuscation/interpreter-encoding-evasion"},
		{"eval_risk", "unauthorized-execution/remote-code-exec/indirect-code-exec"},
		{"bulk_exfiltration", "data-exfiltration/file-exfiltration/archive-credential-bypass"},
		{"secrets_in_command", ""},
		{"indirect_injection", "unauthorized-execution/agentic-attacks/indirect-prompt-injection"},
		{"html_comment_injection", "unauthorized-execution/agentic-attacks/indirect-prompt-injection"},
		{"unicode_steganography", "unauthorized-execution/agentic-attacks/invisible-unicode-prompt-injection"},
		{"code_steganography", "data-exfiltration/steganography/ai-code-steganography"},
		{"roleplay_persona_jailbreak", "unauthorized-execution/agentic-attacks/roleplay-persona-jailbreak"},
		{"jailbreak_response_signature", "unauthorized-execution/agentic-attacks/roleplay-persona-jailbreak"},
		{"authority_claim_bypass", "unauthorized-execution/agentic-attacks/authority-framed-verification-bypass"},
		{"policy_puppetry_jailbreak", "unauthorized-execution/agentic-attacks/policy-puppetry-jailbreak"},
		{"best_of_n_jailbreak_meta", "unauthorized-execution/agentic-attacks/best-of-n-jailbreak"},
		// Unknown signal — no fabricated claim, not a panic.
		{"some_future_signal_nobody_mapped_yet", ""},
	}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			sig := Signal{ID: tc.id}
			if got := signalToTaxonomy(sig); got != tc.want {
				t.Errorf("signalToTaxonomy(Signal{ID: %q}) = %q, want %q", tc.id, got, tc.want)
			}
		})
	}
}

// TestSignalToTaxonomy_EveryBuiltInRuleIsMapped guards against the class of
// bug this test file exists to prevent: a new heuristic rule added to
// buildRules() without a corresponding case in signalToTaxonomy silently
// falls to the "" default instead of failing loudly. Every signal ID that
// ships in the built-in provider must resolve to a non-empty ref UNLESS it
// is explicitly and deliberately unmapped (see the secrets_in_command
// comment in signalToTaxonomy).
func TestSignalToTaxonomy_EveryBuiltInRuleIsMapped(t *testing.T) {
	deliberatelyUnmapped := map[string]bool{
		"secrets_in_command": true,
	}

	p := NewHeuristicProvider()
	seen := map[string]bool{}
	for _, r := range p.rules {
		id := r.signal.ID
		if seen[id] {
			continue
		}
		seen[id] = true
		got := signalToTaxonomy(r.signal)
		if got == "" && !deliberatelyUnmapped[id] {
			t.Errorf("signal %q has no taxonomy mapping and is not in the deliberately-unmapped list — add a case to signalToTaxonomy or document why not", id)
		}
	}
	if len(seen) == 0 {
		t.Fatal("no rules found in HeuristicProvider — buildRules() may have changed shape")
	}
}
