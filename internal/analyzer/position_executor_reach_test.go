package analyzer_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// heredocShape wraps a rule's inline TP in one heredoc shape. ok=false when
// the TP would terminate or break the heredoc, so the probe is skipped and
// counted rather than silently measuring a different command.
type heredocShape struct {
	name     string
	executes bool // the body reaches an executor — the position exclusion must be withdrawn
	wrap     func(tp string) (string, bool)
}

func heredocFits(tp string) bool {
	for _, line := range strings.Split(tp, "\n") {
		if strings.TrimSpace(line) == "EOF" {
			return false
		}
	}
	return true
}

// heredocLaunderingShapes are the #3967 channels: the body of a quoted
// `cat` heredoc — the exact position heredoc_body exists to excuse — handed
// to a shell by each route TextReachesExecutor recognises, plus the note
// shape heredoc_body is FOR, which must keep being excused.
func heredocLaunderingShapes() []heredocShape {
	body := func(head, tail string) func(string) (string, bool) {
		return func(tp string) (string, bool) {
			if !heredocFits(tp) {
				return "", false
			}
			return head + "\n" + tp + "\nEOF" + tail, true
		}
	}
	return []heredocShape{
		{"bare", true, func(tp string) (string, bool) { return tp, true }},
		{"heredoc-pipe-to-bash", true, body("cat <<'EOF' | bash", "")},
		{"heredoc-write-then-bash", true, body("cat > /tmp/x.sh <<'EOF'", "\nbash /tmp/x.sh")},
		{"heredoc-write-then-source", true, body("cat > /tmp/x.sh <<'EOF'", "\nsource /tmp/x.sh")},
		{"note (control: stays excused)", false, body("cat > /tmp/notes.md <<'EOF'", "")},
	}
}

func named(res policy.EvalResult, id string) bool {
	for _, r := range res.TriggeredRules {
		if r == id {
			return true
		}
	}
	return false
}

// TestHeredocBodyExclusionWithdrawnWhenBodyExecutes pins #3967 against the
// shipped packs: every inline TP of every BLOCK rule carrying
// command_position_exclude: [heredoc_body] must still BLOCK — and still name
// the rule — when the TP is the body of a heredoc that is piped into bash,
// or written to a script that the same command then runs or sources. Before
// the fix 15 of 19 went BLOCK→AUDIT on each laundered shape: the exclusion
// excused text the shell was about to execute.
//
// The note row is the positive control, and it is what makes this a fix and
// not "turn the exclusion off": the same TP written to /tmp/notes.md and run
// by nothing must still be excused — the rule must NOT be named.
//
// Both evaluation paths are asserted on every row (the regex-only fallback
// and the analyzer pipeline both call analyzer.PositionExcluded; #3232/#3234
// are the times a match field worked on one path only).
func TestHeredocBodyExclusionWithdrawnWhenBodyExecutes(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	t.Parallel()
	pol := loadTestPolicy(t)
	pipeline, err := policy.NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	fallback, err := policy.NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// The population is derived, but the #3967 set is pinned so a pack that
	// fails to load (premium ne-block-nohup-network-exfil loads from disk)
	// fails loudly instead of shrinking the table.
	want := map[string]bool{
		"ts-block-paramexp-prompt-transform":  false,
		"ne-block-nohup-network-exfil":        false,
		"ts-block-python-sitecustomize-write": false,
		"ts-block-ansic-hex-escape":           false,
		"ts-block-mcp-socket-hijack":          false,
	}
	tps, rows, skipped := 0, 0, 0
	var ruleIDs []string
	blocked := map[string]int{} // "shape/path" -> rows that BLOCK naming the rule
	shapeRows := map[string]int{}
	for _, r := range pol.Rules {
		if r.Decision != policy.DecisionBlock || r.Tests == nil || !hasPosition(r, analyzer.LabelPosHeredocBody) {
			continue
		}
		want[r.ID] = true
		ruleIDs = append(ruleIDs, r.ID)
		for _, tp := range r.Tests.TP {
			tps++
			for _, sh := range heredocLaunderingShapes() {
				cmd, ok := sh.wrap(tp)
				if !ok {
					skipped++
					continue
				}
				rows++
				shapeRows[sh.name]++
				for _, e := range []struct {
					label  string
					engine *policy.Engine
				}{{"pipeline", pipeline}, {"fallback", fallback}} {
					res := e.engine.Evaluate(cmd, nil)
					if res.Decision == policy.DecisionBlock && named(res, r.ID) {
						blocked[sh.name+"/"+e.label]++
					}
					if sh.executes {
						if res.Decision != policy.DecisionBlock || !named(res, r.ID) {
							t.Errorf("%s [%s] %s: got %s rules=%v, want BLOCK naming the rule\n  cmd: %q", r.ID, sh.name, e.label, res.Decision, res.TriggeredRules, cmd)
						}
					} else if named(res, r.ID) {
						t.Errorf("%s [%s] %s: rule fired (%s) on a heredoc nothing executes — heredoc_body must still excuse it\n  cmd: %q", r.ID, sh.name, e.label, res.Decision, cmd)
					}
				}
			}
		}
	}
	sort.Strings(ruleIDs)
	for _, sh := range heredocLaunderingShapes() {
		t.Logf("  %-30s rows=%-3d BLOCK naming the rule: pipeline=%d fallback=%d", sh.name, shapeRows[sh.name], blocked[sh.name+"/pipeline"], blocked[sh.name+"/fallback"])
	}
	t.Logf("heredoc_body executor-reach: %d rules %v, %d TPs, %d rows × 2 paths, %d skipped (TP is itself an EOF heredoc)", len(ruleIDs), ruleIDs, tps, rows, skipped)
	for id, found := range want {
		if !found {
			t.Errorf("rule %s not loaded with heredoc_body — pack load failed or the rule changed; the table is not measuring #3967", id)
		}
	}
	// 19 inline TPs on 09a1762a; two are themselves `<<'EOF'` heredocs and
	// run bare only (8 skipped rows), so 87 rows. Fewer means the table shrank.
	if tps < 19 || rows < 87 {
		t.Errorf("only %d TPs / %d rows ran; the #3967 population is 19 TPs / 87 rows — the table shrank", tps, rows)
	}
}

func hasPosition(r policy.Rule, label string) bool {
	for _, l := range r.Match.CommandPositionExclude {
		if l == label {
			return true
		}
	}
	return false
}
