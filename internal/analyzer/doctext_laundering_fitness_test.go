package analyzer_test

import (
	"bufio"
	"fmt"
	"hash/fnv"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// TestDocTextDowngradeCannotBeLaundered is the fleet-wide fitness function for
// the #2983 sweep: every rule that carries an inertness label
// (is_doc_text / in_heredoc / in_interpreter_heredoc) on
// command_intent_downgrade must still reach its bare decision when the same
// command is fed to an executor through a channel the label must not excuse.
//
// Why a generic test and not 462 hand-written cases: the withdrawal of the
// label is an engine property (#3797 pipe, #3801 write-then-execute, #3928
// command substitution), so one probe per (rule, TP, channel) derived from the
// rules' own inline TPs covers every rule that exists today AND every rule the
// squad adds tomorrow. The #3796 comment on #2983 asked for a pipe-to-shell TP
// on every rule the sweep touches — this is that, without the corpus bloat.
//
// A wrapped command must decide at or above the bare decision. Wrapping can
// legitimately RAISE a decision (a pipe into bash is itself a signal); it must
// never lower one. Probes whose quoting would change the command's meaning are
// skipped and counted, so the denominator is printed rather than implied.
func TestDocTextDowngradeCannotBeLaundered(t *testing.T) {
	t.Parallel()
	engine := newPipelineEngine(t)
	pol := loadTestPolicy(t)

	sev := map[policy.Decision]int{
		policy.DecisionAllow:           0,
		policy.DecisionAudit:           1,
		policy.DecisionRequireApproval: 2,
		policy.DecisionBlock:           3,
	}
	labelled := func(r policy.Rule) bool {
		for _, l := range r.Match.CommandIntentDowngrade {
			if l == "is_doc_text" || l == "in_heredoc" || l == "in_interpreter_heredoc" {
				return true
			}
		}
		return false
	}
	type channel struct {
		name string
		wrap func(string) (string, bool)
	}
	channels := []channel{
		{"pipe-to-bash", func(c string) (string, bool) {
			if strings.Contains(c, "'") {
				return "", false
			}
			// Trailing space: a rule anchored on `(\s|$)` must see the same
			// boundary it saw bare. A quote glued to the payload is the #3802
			// anchoring class, a different defect from label laundering.
			return "echo '" + c + " ' | bash", true
		}},
		{"cmdsubst-in-echo", func(c string) (string, bool) {
			if strings.ContainsAny(c, "\"`\n") || strings.Contains(c, "$(") {
				return "", false
			}
			return "echo \"$(" + c + " )\"", true
		}},
		{"here-string-suffix", func(c string) (string, bool) {
			// #3964: a here-string/heredoc SUFFIX, not a wrapper — `cat FILE
			// <<< x` still reads FILE (cat ignores stdin when it has a file
			// operand), but the in_heredoc regex matches straight through
			// the operand to the "<<" and mislabels the statement inert.
			if strings.Contains(c, "<<") {
				return "", false // already heredoc/here-string-shaped; a different probe
			}
			// #3971: a trailing redirect on a PIPELINE binds to the pipe's
			// last command and overrides its stdin — it does not "also" feed
			// that command, it REPLACES what the pipe was carrying. Verified
			// in bash: `echo pwned | bash <<< x` runs "x", not "pwned", and
			// `curl url | deno run - <<< x` reads "x" as deno's program, not
			// curl's response — the very payload flow the rule exists to
			// catch never happens. That is a real behavior change, unlike
			// cat/copy/python-with-file-operand above, whose result is
			// identical with or without the suffix because they never read
			// their data from stdin at all. Probing a pipe TP with this
			// channel would report a decision drop for a command that is no
			// longer the attack it started as, so skip it here rather than
			// let the fitness test call a severed pipe a "leak".
			if strings.Contains(c, "|") {
				return "", false
			}
			return c + " <<< x", true
		}},
	}

	known := loadKnownLaunderingGaps(t)
	seen := map[string]bool{}
	var newLeaks []string

	rules, probes, skipped, laundered := 0, 0, 0, 0
	for _, r := range pol.Rules {
		if !labelled(r) || r.Tests == nil {
			continue
		}
		rules++
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
					laundered++
					key := launderingKey(r.ID, ch.name, tp)
					seen[key] = true
					if known[key] {
						continue // recorded gap — see the baseline file
					}
					newLeaks = append(newLeaks, key)
					// Does the rule's own pattern still match the wrapped text?
					// false = the wrapper's punctuation defeated an anchor (#3802
					// class); true = the pattern matched and a label excused it.
					pm := "n/a"
					if r.Match.CommandRegex != "" {
						if re, err := regexp.Compile(r.Match.CommandRegex); err == nil {
							pm = strconv.FormatBool(re.MatchString(wrapped))
						}
					}
					t.Errorf("%s laundered via %s: bare=%s wrapped=%s rules=%v patternMatchesWrapped=%s\n  bare:    %q\n  wrapped: %q",
						r.ID, ch.name, bare.Decision, got.Decision, got.TriggeredRules, pm, tp, wrapped)
				}
			}
		}
	}
	t.Logf("doc-text-downgrade laundering fitness: %d rules, %d probes, %d skipped (quoting), %d laundered (%d recorded, %d new)", rules, probes, skipped, laundered, laundered-len(newLeaks), len(newLeaks))
	if probes == 0 {
		t.Fatal("no probes ran — the rule population or the TP wrapper is broken, not clean")
	}
	// Ratchet: a recorded gap that no longer leaks must be removed from the
	// baseline in the same PR that fixed it, so the file stays a true list.
	var fixed []string
	for key := range known {
		if !seen[key] {
			fixed = append(fixed, key)
		}
	}
	sort.Strings(fixed)
	for _, key := range fixed {
		t.Errorf("recorded laundering gap no longer leaks — remove it from %s: %s", knownLaunderingGapsFile, key)
	}
}

// knownLaunderingGapsFile records probes that leak TODAY. It exists so this
// test can land while the gap it measures is still open, and so a fix has
// to touch the list deliberately. Every line here is a BLOCK that an agent
// can turn into an AUDIT by wrapping the command — read it as a bug list,
// not as an allowance.
const knownLaunderingGapsFile = "testdata/doctext_laundering_known_gaps.txt"

// launderingKey identifies a probe by rule, channel and a hash of the inline
// TP text, so reordering a rule's tp: list does not move the key.
func launderingKey(ruleID, channel, tp string) string {
	h := fnv.New32a()
	h.Write([]byte(tp))
	return fmt.Sprintf("%s\t%s\t%08x", ruleID, channel, h.Sum32())
}

// loadKnownLaunderingGaps reads the baseline. Lines are
// rule<TAB>channel<TAB>hash<TAB>note; only the first three fields are the key,
// the note is for the reader. `#` lines and blank lines are ignored.
func loadKnownLaunderingGaps(t *testing.T) map[string]bool {
	t.Helper()
	known := map[string]bool{}
	f, err := os.Open(knownLaunderingGapsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return known
		}
		t.Fatalf("open %s: %v", knownLaunderingGapsFile, err)
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
			t.Fatalf("%s: malformed line %q (want rule<TAB>channel<TAB>hash[<TAB>note])", knownLaunderingGapsFile, line)
		}
		known[strings.Join(parts[:3], "\t")] = true
	}
	return known
}
