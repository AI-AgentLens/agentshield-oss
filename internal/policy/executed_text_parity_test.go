package policy

import "testing"

// anchoredRule is the #3938 shape: a leading-anchor alternation that lists
// every separator but a quote. 78 shipped BLOCK rules open this way.
func anchoredRule() Rule {
	return Rule{
		ID:       "test-anchored-pkexec-shell",
		Taxonomy: "privilege-escalation/command-execution/sudo-invocation",
		Match: Match{
			CommandRegex: `(?:^|[\s;&|])pkexec\s+bash(?:\s|$)`,
			// The shape every shipped shell rule carries since #3937: the
			// labels DOWNGRADE a doc position, and are withdrawn when the
			// text reaches an executor.
			CommandIntentExclude:   []string{"is_bash_comment", "is_self_mgmt"},
			CommandIntentDowngrade: []string{"is_doc_text", "in_heredoc"},
		},
		Decision: DecisionBlock,
		Reason:   "test",
	}
}

// TestExecutedTextParityAcrossEvaluationPaths pins #3938 on both the
// regex-only fallback and the analyzer pipeline: text the shell will run is
// retried as a command of its own, so a quote glued to the payload no longer
// hides it from a leading anchor. The refusal rows matter as much as the
// bypass rows — emitted text that nothing executes must stay unmatched.
func TestExecutedTextParityAcrossEvaluationPaths(t *testing.T) {
	pol := &Policy{Defaults: Defaults{Decision: DecisionAudit}, Rules: []Rule{anchoredRule()}}
	fallback, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	pipeline, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}

	cases := []struct {
		name    string
		command string
		want    Decision
		named   bool // the rule appears in TriggeredRules
		why     string
	}{
		{"control: bare", `pkexec bash`, DecisionBlock, true, "if this stops blocking the table proves nothing"},
		{"control: after a separator the anchor lists", `cd /tmp; pkexec bash`, DecisionBlock, true, ""},

		{"the #3938 bypass: single-quoted echo piped into bash", `echo 'pkexec bash' | bash`, DecisionBlock, true, "executes identically to the control; the char before the payload is a quote"},
		{"double-quoted echo piped into sh", `echo "pkexec bash" | sh`, DecisionBlock, true, ""},
		{"printf piped into bash", `printf 'pkexec bash\n' | bash`, DecisionBlock, true, ""},
		{"heredoc piped into bash", "cat <<'EOF' | bash\npkexec bash\nEOF", DecisionBlock, true, ""},
		{"write then execute", `echo 'pkexec bash' > /tmp/r.sh; bash /tmp/r.sh`, DecisionBlock, true, "#3800's route, same evidence"},
		{"command substitution in an echo argument", `echo "$(pkexec bash)"`, DecisionBlock, true, "the body runs before echo prints"},
		{"backquote substitution", "echo \"`pkexec bash`\"", DecisionBlock, true, ""},
		{"substitution inside a commit message", `git commit -m "$(pkexec bash)"`, DecisionBlock, true, "a $( ) in a message argument still executes"},

		{"printed, never executed: no executor, no candidate, no match", `echo 'pkexec bash'`, DecisionAudit, false, "the quote still hides the payload from the anchor when nothing runs it"},
		{"piped into a non-executor", `echo 'pkexec bash' | grep pk`, DecisionAudit, false, ""},
		{"written to notes, nothing runs it", `echo 'pkexec bash' >> notes.md`, DecisionAudit, false, ""},
		{"single-quoted substitution is a literal", `echo '$(pkexec bash)'`, DecisionAudit, false, "no CmdSubst node, nothing executes"},
		{"commit message the anchor DOES match: attested downgrade, not a block", `git commit -m "docs: pkexec bash spawns a root shell"`, DecisionAudit, true, "spaces on both sides satisfy the anchor; is_doc_text downgrades and the rule is still named (#2843)"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, e := range []struct {
				label  string
				engine *Engine
			}{{"regex-only fallback", fallback}, {"analyzer pipeline", pipeline}} {
				res := e.engine.Evaluate(tc.command, nil)
				if res.Decision != tc.want {
					t.Errorf("%s: Evaluate(%q) = %v, want %v %s", e.label, tc.command, res.Decision, tc.want, tc.why)
				}
				named := false
				for _, id := range res.TriggeredRules {
					named = named || id == "test-anchored-pkexec-shell"
				}
				if named != tc.named {
					t.Errorf("%s: Evaluate(%q) named the rule = %v, want %v (rules=%v) %s", e.label, tc.command, named, tc.named, res.TriggeredRules, tc.why)
				}
			}
		})
	}
}

// startAnchoredRule is the ts-block-frida-name-attach shape: a bare "^"
// anchor, so the payload must be the FIRST word of the text retried. A
// leading-alternation rule (anchoredRule above) already matches a heredoc
// line after its newline; this one matches only a candidate that starts
// with the payload. Synthetic token, so no shipped rule interferes.
func startAnchoredRule() Rule {
	return Rule{
		ID:       "test-start-anchored-attach",
		Taxonomy: "credential-exposure/process-credential/ptrace-process-attach",
		Match: Match{
			CommandRegex:           `^(?:sudo\s+)?zqattach\b(?:\s+\S+)*?\s+(?:-n|--name)\s+\S+`,
			CommandIntentExclude:   []string{"is_bash_comment", "is_self_mgmt"},
			CommandIntentDowngrade: []string{"is_doc_text", "in_heredoc"},
		},
		Decision: DecisionBlock,
		Reason:   "test",
	}
}

// TestExecutedSubstitutionOutputParity pins the substitution-output channel
// of ExecutedText on both evaluation paths: when a substitution's OUTPUT is
// run (bash -c "$(…)", eval "$(…)", bash <(…), x=$(…); eval "$x"), the text
// its cat-heredoc / echo / printf emits is retried as a command. Before this,
// a "^"-anchored rule BLOCKed the heredoc piped into bash and AUDITed the same
// heredoc run through a substitution, naming no rule — 16 probes of
// TestPositionExclusionCannotBeLaundered's "lower-but-not-position" count on
// ts-block-frida-name-attach (#3979). The refusal rows are the other half: output
// that is printed, redirected, piped onward, or never the heredoc text at
// all must not become a candidate.
func TestExecutedSubstitutionOutputParity(t *testing.T) {
	pol := &Policy{Defaults: Defaults{Decision: DecisionAudit}, Rules: []Rule{startAnchoredRule()}}
	fallback, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	pipeline, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	const payload = "zqattach -n target"
	hd := func(prefix, suffix string) string { return prefix + "\n" + payload + "\nEOF\n" + suffix }

	cases := []struct {
		name    string
		command string
		want    Decision
		why     string
	}{
		{"control: bare", payload, DecisionBlock, "if this stops blocking the table proves nothing"},
		{"control: heredoc piped into bash", "cat <<'EOF' | bash\n" + payload + "\nEOF", DecisionBlock, "the pre-existing emitted-text channel"},

		{"bash -c of a heredoc cmdsub", hd(`bash -c "$(cat <<'EOF'`, `)"`), DecisionBlock, "bash -c runs exactly the heredoc text"},
		{"eval of a heredoc cmdsub", hd(`eval "$(cat <<'EOF'`, `)"`), DecisionBlock, ""},
		{"bash of a heredoc procsub", hd(`bash <(cat <<'EOF'`, `)`), DecisionBlock, ""},
		{"capture then eval", hd(`x=$(cat <<'EOF'`, ")\neval \"$x\""), DecisionBlock, "#3976's captured-variable route"},
		{"unquoted delimiter, literal body", hd(`bash -c "$(cat <<EOF`, `)"`), DecisionBlock, "no expansion in the body, so the text is static"},
		{"eval of an echo cmdsub", `eval "$(echo '` + payload + `')"`, DecisionBlock, ""},

		{"printed, not run", hd(`echo "$(cat <<'EOF'`, `)"`), DecisionAudit, "the output is echoed, nothing executes it"},
		{"cat reads a file, not the heredoc", hd(`bash -c "$(cat notes.txt <<'EOF'`, `)"`), DecisionAudit, "bash -c runs notes.txt's content"},
		{"cat -n rewrites the text", hd(`bash -c "$(cat -n <<'EOF'`, `)"`), DecisionAudit, "the executor receives numbered lines"},
		{"stdout redirected to a file", hd(`bash -c "$(cat <<'EOF' > /tmp/n`, `)"`), DecisionAudit, "the substitution's output is empty"},
		{"heredoc piped onward", hd(`bash -c "$(cat <<'EOF' | wc -l`, `)"`), DecisionAudit, "bash -c runs wc's output"},
		{"interpreter heredoc", "bash -c \"$(python3 - <<'PY'\n" + payload + "\nPY\n)\"", DecisionAudit, "python runs the body; its output is not the body"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, e := range []struct {
				label  string
				engine *Engine
			}{{"regex-only fallback", fallback}, {"analyzer pipeline", pipeline}} {
				res := e.engine.Evaluate(tc.command, nil)
				if res.Decision != tc.want {
					t.Errorf("%s: Evaluate(%q) = %v (rules=%v), want %v %s", e.label, tc.command, res.Decision, res.TriggeredRules, tc.want, tc.why)
				}
			}
		})
	}
}
