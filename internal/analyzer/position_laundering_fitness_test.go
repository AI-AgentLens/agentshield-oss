package analyzer_test

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// TestPositionExclusionCannotBeLaundered is the command_position_exclude twin
// of TestDocTextDowngradeCannotBeLaundered (#3967). That test probes rules
// whose inertness LABEL is withdrawn when text reaches an executor; this one
// probes rules whose inert POSITION must be withdrawn for the same reason.
// Every inline TP of every rule carrying command_position_exclude is placed in
// a data-text position and then handed to a shell, by each route
// shellparse.TextReachesExecutor recognises:
//
//	cat <<'EOF' | bash … EOF                           heredoc_body, piped
//	cat > /tmp/x.sh <<'EOF' … EOF; bash /tmp/x.sh       heredoc_body, write-then-exec
//	cat > /tmp/x.sh <<'EOF' … EOF; source /tmp/x.sh     heredoc_body, write-then-source
//	python3 - <<'PY' | bash / print("<tp>") / PY        interp_heredoc_literal, piped
//	awk 'BEGIN{print "<tp>"}' | bash                    quoted_program_arg, piped
//
// Every channel is applied to every such rule, whatever label it carries: a
// rule with loop_wordlist or search_needle is not excused in these positions
// at all, so it contributes a probe that must hold trivially — a cheap check
// that no future position label quietly extends into them.
//
// A wrapped command must decide at or above the bare decision. Leaks that are
// open today are recorded in knownPositionLaunderingGapsFile with the same
// ratchet as the label test: a new leak fails, and a recorded leak that stops
// leaking must be deleted in the PR that fixed it.
func TestPositionExclusionCannotBeLaundered(t *testing.T) {
	t.Parallel()
	engine := newPipelineEngine(t)
	pol := loadTestPolicy(t)

	// Attribution control: the same policy with every command_position_exclude
	// stripped. A leak that ALSO leaks here is not a position leak — the rule's
	// pattern cannot see the wrapped text, or the channel is not one the engine
	// treats as execution — and is counted separately rather than ratcheted,
	// because this test's claim is about position exclusions only.
	stripped := *pol
	stripped.Rules = make([]policy.Rule, len(pol.Rules))
	for i, r := range pol.Rules {
		r.Match.CommandPositionExclude = nil
		stripped.Rules[i] = r
	}
	control, err := policy.NewEngineWithAnalyzers(&stripped, 2)
	if err != nil {
		t.Fatalf("stripped engine: %v", err)
	}

	sev := map[policy.Decision]int{
		policy.DecisionAllow:           0,
		policy.DecisionAudit:           1,
		policy.DecisionRequireApproval: 2,
		policy.DecisionBlock:           3,
	}
	lineFree := func(tp, delim string) bool {
		for _, line := range strings.Split(tp, "\n") {
			if strings.TrimSpace(line) == delim {
				return false
			}
		}
		return true
	}
	type channel struct {
		name string
		wrap func(string) (string, bool)
	}
	channels := []channel{
		{"heredoc-pipe-to-bash", func(c string) (string, bool) {
			return "cat <<'EOF' | bash\n" + c + "\nEOF", lineFree(c, "EOF")
		}},
		{"heredoc-write-then-bash", func(c string) (string, bool) {
			return "cat > /tmp/x.sh <<'EOF'\n" + c + "\nEOF\nbash /tmp/x.sh", lineFree(c, "EOF")
		}},
		{"heredoc-write-then-source", func(c string) (string, bool) {
			return "cat > /tmp/x.sh <<'EOF'\n" + c + "\nEOF\nsource /tmp/x.sh", lineFree(c, "EOF")
		}},
		{"python-print-pipe-to-bash", func(c string) (string, bool) {
			// strconv.Quote of printable ASCII is a valid Python string literal.
			for _, r := range c {
				if r > 0x7e || (r < 0x20 && r != '\n' && r != '\t') {
					return "", false
				}
			}
			// Trailing space, as in the label test: a rule anchored on
			// `(\s|$)` must see the boundary it saw bare, or the probe measures
			// the #3802 quote-glued anchor class instead of the position.
			return "python3 - <<'PY' | bash\nprint(" + strconv.Quote(c+" ") + ")\nPY", lineFree(c, "PY")
		}},
		{"awk-print-pipe-to-bash", func(c string) (string, bool) {
			if strings.ContainsAny(c, "'\"\\\n") {
				return "", false
			}
			return "awk 'BEGIN{print \"" + c + " \"}' | bash", true
		}},
		// #3976: a substitution whose OUTPUT runs. The heredoc body reaches
		// the executor through the substitution, not a pipe or a written path.
		{"heredoc-cmdsub-bash-c", func(c string) (string, bool) {
			return "bash -c \"$(cat <<'EOF'\n" + c + "\nEOF\n)\"", lineFree(c, "EOF")
		}},
		{"heredoc-cmdsub-eval", func(c string) (string, bool) {
			return "eval \"$(cat <<'EOF'\n" + c + "\nEOF\n)\"", lineFree(c, "EOF")
		}},
		{"heredoc-procsub-bash", func(c string) (string, bool) {
			return "bash <(cat <<'EOF'\n" + c + "\nEOF\n)", lineFree(c, "EOF")
		}},
		{"heredoc-capture-then-eval", func(c string) (string, bool) {
			return "x=$(cat <<'EOF'\n" + c + "\nEOF\n)\neval \"$x\"", lineFree(c, "EOF")
		}},
		{"python-print-procsub-bash", func(c string) (string, bool) {
			for _, r := range c {
				if r > 0x7e || (r < 0x20 && r != '\n' && r != '\t') {
					return "", false
				}
			}
			return "bash <(python3 - <<'PY'\nprint(" + strconv.Quote(c+" ") + ")\nPY\n)", lineFree(c, "PY")
		}},
		{"awk-print-procsub-bash", func(c string) (string, bool) {
			if strings.ContainsAny(c, "'\"\\\n") {
				return "", false
			}
			return "bash <(awk 'BEGIN{print \"" + c + " \"}')", true
		}},
	}

	known := loadKnownPositionLaunderingGaps(t)
	seen := map[string]bool{}
	var newLeaks []string
	perLabel := map[string]int{}

	rules, probes, skipped, laundered, notPosition := 0, 0, 0, 0, 0
	for _, r := range pol.Rules {
		if len(r.Match.CommandPositionExclude) == 0 || r.Tests == nil {
			continue
		}
		rules++
		for _, l := range r.Match.CommandPositionExclude {
			perLabel[l]++
		}
		for _, tp := range r.Tests.TP {
			bare := engine.Evaluate(tp, nil)
			if sev[bare.Decision] < sev[policy.DecisionRequireApproval] {
				continue // nothing to launder
			}
			for _, ch := range channels {
				wrapped, ok := ch.wrap(tp)
				if !ok {
					skipped++
					continue
				}
				probes++
				got := engine.Evaluate(wrapped, nil)
				if sev[got.Decision] < sev[bare.Decision] {
					if ctl := control.Evaluate(wrapped, nil); sev[ctl.Decision] < sev[bare.Decision] {
						notPosition++ // leaks with no position exclusion at all — not this test's class
						t.Logf("not a position leak (also lower with positions stripped): %s via %s bare=%s wrapped=%s stripped=%s", r.ID, ch.name, bare.Decision, got.Decision, ctl.Decision)
						continue
					}
					laundered++
					key := launderingKey(r.ID, ch.name, tp)
					seen[key] = true
					if known[key] {
						continue
					}
					newLeaks = append(newLeaks, key)
					t.Errorf("%s laundered via %s: bare=%s wrapped=%s rules=%v positions=%v\n  bare:    %q\n  wrapped: %q",
						r.ID, ch.name, bare.Decision, got.Decision, got.TriggeredRules, r.Match.CommandPositionExclude, tp, wrapped)
				}
			}
		}
	}
	labels := make([]string, 0, len(perLabel))
	for l, n := range perLabel {
		labels = append(labels, l+"="+strconv.Itoa(n))
	}
	sort.Strings(labels)
	t.Logf("position-exclusion laundering fitness: %d rules %v, %d probes, %d skipped (quoting/delimiter), %d laundered by a position exclusion (%d recorded, %d new), %d lower-but-not-position (leak with positions stripped too)", rules, labels, probes, skipped, laundered, laundered-len(newLeaks), len(newLeaks), notPosition)
	// 09a1762a + #3967: 14 rules, 261 probes. A shrinking denominator means a
	// pack failed to load (premium rules load from disk) or the wrappers broke.
	if rules < 12 || probes < 100 {
		t.Fatalf("only %d rules / %d probes — the position-excluded population or a wrapper is broken, not clean", rules, probes)
	}
	// The not-position class is not this test's claim, but it IS executed
	// text scoring below its bare TP, so it gets a ceiling rather than no
	// gate at all: a new leak of that class fails here instead of hiding in
	// a log line (#3979). 44 on 9e2c7c33; 28 once ExecutedText retried the text a
	// substitution emits when its output runs (frida via bash -c / eval /
	// procsub / capture-then-eval, 16). The 28 left, by cause:
	//   16 sec-block-ssh-private: is_self_mgmt (not an inertness label, so
	//      executor reach never withdraws it) excuses the wrapped statement
	//      because its executed text mentions agentshield mcp-eval;
	//   12 frida (python/awk print, 10) and ts-block-sudo-alternatives-shell
	//      (python print whose \n escape is glued to the payload, 2): text an
	//      INTERPRETER prints into a shell is never recovered as a command.
	// Both remaining classes are ACCEPTED gaps, not a queue (2026-09-24,
	// #3979; rationale, rejected fixes and revisit trigger in
	// docs/architecture.md -> Known gaps). A new shape of either class is
	// recorded here, not fixed, until a revisit trigger fires.
	// Lower the ceiling in the PR that closes one; never raise it to pass.
	const maxNotPosition = 28
	if notPosition > maxNotPosition {
		t.Errorf("%d lower-but-not-position leaks, ceiling %d: executed text now scores below its bare TP on a new probe — see the \"not a position leak\" lines above", notPosition, maxNotPosition)
	}
	var fixed []string
	for key := range known {
		if !seen[key] {
			fixed = append(fixed, key)
		}
	}
	sort.Strings(fixed)
	for _, key := range fixed {
		t.Errorf("recorded position-laundering gap no longer leaks — remove it from %s: %s", knownPositionLaunderingGapsFile, key)
	}
}

// knownPositionLaunderingGapsFile is the position-exclusion twin of
// knownLaunderingGapsFile, same line format and same reading: every line is a
// BLOCK an agent can turn into an AUDIT by wrapping the command.
const knownPositionLaunderingGapsFile = "testdata/position_laundering_known_gaps.txt"

func loadKnownPositionLaunderingGaps(t *testing.T) map[string]bool {
	t.Helper()
	known := map[string]bool{}
	f, err := os.Open(knownPositionLaunderingGapsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return known
		}
		t.Fatalf("open %s: %v", knownPositionLaunderingGapsFile, err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 4)
		if len(parts) < 3 {
			t.Fatalf("%s: malformed line %q (want rule<TAB>channel<TAB>hash[<TAB>note])", knownPositionLaunderingGapsFile, line)
		}
		known[strings.Join(parts[:3], "\t")] = true
	}
	return known
}
