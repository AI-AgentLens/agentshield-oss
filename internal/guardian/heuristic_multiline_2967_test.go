package guardian

import "testing"

// Issue #2967: guardian-eval_risk fired on newline-joined commands whose
// quoted arguments / inert heredoc bodies quote eval()/exec() as documentation.
// Both TN shapes below are reconstructed from the live audit-log blocks that
// hit Baby Remedy on 2026-07-15.
func TestHeuristicProvider_EvalRisk_MultilineFP2967(t *testing.T) {
	p := NewHeuristicProvider()

	issueBody := "## Finding\n" +
		"```python\n" +
		"def run_decoded(encoded):\n" +
		"    # ruleid: ai-unsafe-eval-on-dynamic-input-python\n" +
		"    exec(base64.b64decode(encoded))\n" +
		"```\n" +
		"\n" +
		"> eval() or exec() called on dynamic input. Replace eval() with ast.literal_eval().\n" +
		"\n" +
		"But at runtime; for any realistic payload:\n" +
		"```\n" +
		"ValueError: malformed node or string\n" +
		"```\n"

	benign := []struct {
		name string
		cmd  string
	}{
		{
			// The exact live-FP shape: cd on its own line, backslash
			// continuations, exec() prose in the quoted --title, and the body
			// via $(cat <<'EOF' ... EOF).
			name: "newline-joined gh issue create with continuations and heredoc body",
			cmd: "cd ~/dev/baby-kai/comply-workspace\n" +
				"gh issue create --repo AI-AgentLens/AI_risk_compliance \\\n" +
				"  --title \"Remediation quality: ast.literal_eval advice crashes on exec() sub-cases\" \\\n" +
				"  --label \"remediation-quality\" --label \"rule-request\" \\\n" +
				"  --body \"$(cat <<'EOF'\n" + issueBody + "EOF\n)\"",
		},
		{
			// Second live-FP shape: python stdin heredoc whose bare
			// double-quoted string literals mention eval()/exec() as data.
			name: "newline-joined python3 - heredoc with eval/exec prose in DQ strings",
			cmd: "cd ~/dev/baby-kai/comply-workspace\n" +
				"python3 - <<'PYEOF'\n" +
				"import json\n" +
				"with open(\"/tmp/state.json\") as f:\n" +
				"    state = json.load(f)\n" +
				"state[\"note\"] = \"eval() sub-cases PASS; exec() sub-cases FALSE_FIX per literal advice\"\n" +
				"with open(\"/tmp/state.json\", \"w\") as f:\n" +
				"    json.dump(state, f)\n" +
				"PYEOF",
		},
		{
			// gh stdin heredoc: body is API payload data. Guard against the
			// newline normalization fragmenting it into unprotected segments.
			name: "gh issue create --body-file - with heredoc quoting exec()",
			cmd: "gh issue create --title \"FP report\" --body-file - <<'EOF'\n" +
				"The advice rewrites exec(base64.b64decode(x)) and crashes.\n" +
				"EOF",
		},
		{
			name: "newline-joined git commit mentioning exec() in message",
			cmd:  "cd ~/dev/repo\ngit commit -m \"docs: explain why exec() is dangerous\"",
		},
		{
			name: "newline-joined grep for eval pattern",
			cmd:  "cd ~/dev/repo\ngrep -rn 'eval(' rules/",
		},
	}
	for _, tt := range benign {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := p.Analyze(GuardianRequest{RawCommand: tt.cmd})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if hasSignal(resp.Signals, "eval_risk") {
				t.Errorf("FP: eval_risk fired on benign multiline command: %s", tt.name)
			}
		})
	}

	malicious := []struct {
		name string
		cmd  string
	}{
		{
			name: "newline-joined python -c with real exec call",
			cmd:  "cd /tmp\npython3 -c \"exec(input())\"",
		},
		{
			// Latent FN closed by newline normalization: the git fast path
			// previously swallowed the whole command and quote-stripped the
			// live bash payload.
			name: "git commit then newline then bash -c eval payload",
			cmd:  "git commit -m \"msg\"\nbash -c \"eval(dynamic_payload)\"",
		},
		{
			name: "python stdin heredoc with real exec call site outside strings",
			cmd: "python3 - <<'PYEOF'\n" +
				"import base64\n" +
				"payload = get_remote()\n" +
				"exec(base64.b64decode(payload))\n" +
				"PYEOF",
		},
		{
			// FN guard for body-scoped DQ stripping: a live eval elsewhere in
			// the same command must stay visible even when a python heredoc
			// is present.
			name: "clean python heredoc followed by bash -c eval",
			cmd: "python3 - <<'PYEOF'\n" +
				"print(\"hello\")\n" +
				"PYEOF\n" +
				"bash -c \"eval(injected)\"",
		},
	}
	for _, tt := range malicious {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := p.Analyze(GuardianRequest{RawCommand: tt.cmd})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !hasSignal(resp.Signals, "eval_risk") {
				t.Errorf("FN: eval_risk missed real dynamic execution: %s", tt.name)
			}
		})
	}
}
