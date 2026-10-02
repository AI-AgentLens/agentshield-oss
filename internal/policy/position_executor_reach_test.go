package policy

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
)

// positionRule is a synthetic BLOCK rule excused at one data-text position.
// The payload tokens are nonsense on purpose: the test is about where the
// match lands and whether that text is executed, not about any real technique.
func positionRule(id, re, label string) Rule {
	return Rule{
		ID:       id,
		Taxonomy: "unauthorized-execution/command-execution/test",
		Match: Match{
			CommandRegex:           re,
			CommandPositionExclude: []string{label},
		},
		Decision: DecisionBlock,
		Reason:   "test",
	}
}

// TestPositionExclusionWithdrawnWhenTextReachesExecutor pins #3967 on both
// evaluation paths: a data-text position exclusion (heredoc_body,
// quoted_program_arg, interp_heredoc_literal) is withdrawn when the command
// hands that text to a shell — the same shellparse.TextReachesExecutor
// evidence that withdraws the in_heredoc / is_doc_text labels — and is kept
// when nothing executes it.
//
// The `${ZQ}` payload is load-bearing. shellparse.ExecutedText refuses emitted
// text carrying an unexpanded `$`, so for that payload the regex-only
// fallback has no executed-text candidate to fall back on and the withdrawal
// in analyzer.PositionExcluded is the ONLY thing that restores the BLOCK. The
// static payload rows are there because the pipeline path never had that
// fallback: it applies the exclusion to the raw command after any candidate
// matched, so it leaked even static text (15 of 19 shipped TPs, #3967).
func TestPositionExclusionWithdrawnWhenTextReachesExecutor(t *testing.T) {
	t.Run("heredoc_body, payload with an unexpanded $", func(t *testing.T) {
		pol := &Policy{Defaults: Defaults{Decision: DecisionAudit}, Rules: []Rule{
			positionRule("test-heredoc-dollar", `zqxpayload\s+\$\{ZQ\}`, analyzer.LabelPosHeredocBody),
		}}
		body := "zqxpayload ${ZQ}"
		testPositionExcludeParity(t, pol, []struct {
			name    string
			command string
			want    Decision
		}{
			{"control: bare", body, DecisionBlock},
			{"control: the note heredoc_body exists for", "cat > /tmp/notes.md <<'EOF'\n" + body + "\nEOF", DecisionAudit},
			{"piped into bash", "cat <<'EOF' | bash\n" + body + "\nEOF", DecisionBlock},
			{"piped into sh", "cat <<'EOF' | sh\n" + body + "\nEOF", DecisionBlock},
			{"written then run", "cat > /tmp/x.sh <<'EOF'\n" + body + "\nEOF\nbash /tmp/x.sh", DecisionBlock},
			{"written then sourced", "cat > /tmp/x.sh <<'EOF'\n" + body + "\nEOF\nsource /tmp/x.sh", DecisionBlock},
			{"written then dot-sourced", "cat > /tmp/x.sh <<'EOF'\n" + body + "\nEOF\n. /tmp/x.sh", DecisionBlock},
			{"tee-written then run", "tee /tmp/x.sh <<'EOF'\n" + body + "\nEOF\nbash /tmp/x.sh", DecisionBlock},
			{"piped into a non-executor stays excused", "cat <<'EOF' | grep zqx\n" + body + "\nEOF", DecisionAudit},
			// #3798 strict purity: bash is in the line, so the exemption is void
			// even though y.sh is not the written file. Accepted cost (Gary,
			// 2026-09-23); was AUDIT under #3967's per-channel withdrawal.
			{"written, a DIFFERENT path run: strict purity voids the exemption", "cat > /tmp/x.sh <<'EOF'\n" + body + "\nEOF\nbash /tmp/y.sh", DecisionBlock},
		})
	})

	t.Run("heredoc_body, static payload", func(t *testing.T) {
		pol := &Policy{Defaults: Defaults{Decision: DecisionAudit}, Rules: []Rule{
			positionRule("test-heredoc-static", `zqxstatic\s+run`, analyzer.LabelPosHeredocBody),
		}}
		body := "zqxstatic run"
		testPositionExcludeParity(t, pol, []struct {
			name    string
			command string
			want    Decision
		}{
			{"control: bare", body, DecisionBlock},
			{"control: note", "cat > /tmp/notes.md <<'EOF'\n" + body + "\nEOF", DecisionAudit},
			{"piped into bash", "cat <<'EOF' | bash\n" + body + "\nEOF", DecisionBlock},
			{"written then run", "cat > /tmp/x.sh <<'EOF'\n" + body + "\nEOF\nbash /tmp/x.sh", DecisionBlock},
			{"written then sourced", "cat > /tmp/x.sh <<'EOF'\n" + body + "\nEOF\nsource /tmp/x.sh", DecisionBlock},
		})
	})

	t.Run("quoted_program_arg", func(t *testing.T) {
		pol := &Policy{Defaults: Defaults{Decision: DecisionAudit}, Rules: []Rule{
			positionRule("test-quoted-program", `zqxglob:\$\{ZQ\}`, analyzer.LabelPosQuotedProgramArg),
		}}
		testPositionExcludeParity(t, pol, []struct {
			name    string
			command string
			want    Decision
		}{
			{"control: bare", `print zqxglob:${ZQ}`, DecisionBlock},
			{"control: an awk program that only mentions it", `awk '{print "zqxglob:${ZQ}"}' notes.txt`, DecisionAudit},
			{"awk output piped into bash", `awk 'BEGIN{print "zqxglob:${ZQ}"}' | bash`, DecisionBlock},
			{"sed output piped into sh", `sed -n 's/^/zqxglob:${ZQ} /p' notes.txt | sh`, DecisionBlock},
			{"awk output piped into a non-executor stays excused", `awk 'BEGIN{print "zqxglob:${ZQ}"}' | sort -u`, DecisionAudit},
		})
	})

	t.Run("interp_heredoc_literal", func(t *testing.T) {
		pol := &Policy{Defaults: Defaults{Decision: DecisionAudit}, Rules: []Rule{
			positionRule("test-interp-literal", `zqxinterp\s+go`, analyzer.LabelPosInterpHeredocLiteral),
		}}
		testPositionExcludeParity(t, pol, []struct {
			name    string
			command string
			want    Decision
		}{
			{"control: bare", `zqxinterp go now`, DecisionBlock},
			{"control: a python literal nothing runs", "python3 - <<'PY'\nx = \"zqxinterp go now\"\nprint(x)\nPY", DecisionAudit},
			{"python output piped into bash", "python3 - <<'PY' | bash\nprint(\"zqxinterp go now\")\nPY", DecisionBlock},
			{"python output piped into sh", "python3 - <<'PY' | sh\nprint(\"zqxinterp go now\")\nPY", DecisionBlock},
			{"python output redirected to a file nothing runs stays excused", "python3 - <<'PY' > out.txt\nprint(\"zqxinterp go now\")\nPY", DecisionAudit},
		})
	})
}
