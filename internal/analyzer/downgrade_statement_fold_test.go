package analyzer

import (
	"regexp"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// #3717 — per-statement downgrade/exclude attribution must consider the same
// text renderings the top-level match does.
//
// IntentExcludedForStatements attributes a match to the statements that
// independently satisfy the rule's own predicate, and excuses the finding only
// when every one of them carries a downgrade/exclude label. The predicate used
// to be the plain matcher over RAW statement text, while the top-level match
// folded ${IFS} separators, unset-parameter splices, quote splices and friends.
//
// So a compound command pairing an obfuscated REAL invocation with an
// unobfuscated doc-text sibling that happens to repeat the rule's pattern
// verbatim attributed the whole decision to the doc-text statement: the real
// statement did not match raw, so it was skipped rather than counted. The
// executed BLOCK became AUDIT. Fail-open — the attestation records "no
// violation" for a statement that ran.
//
// foldAttributionPattern is packs/community/terminal-safety.yaml's
// ts-block-systemd-run-system verbatim; it carries
// command_intent_downgrade: [is_doc_text, in_heredoc].
const foldAttributionPattern = `systemd-run\s+.*--system`

// foldAwareMatcher is the shape both production call sites now use: raw text
// first (a short-circuit), then every rendering StatementMatchCandidates
// produces for that statement.
func foldAwareMatcher(cmd, pattern string) func(string) bool {
	re := regexp.MustCompile(pattern)
	fc := NewStatementFoldContext(cmd)
	return func(stmt string) bool {
		if re.MatchString(stmt) {
			return true
		}
		for _, cand := range StatementMatchCandidates(stmt, fc) {
			if re.MatchString(cand) {
				return true
			}
		}
		return false
	}
}

// rawOnlyMatcher is the pre-#3717 predicate, kept so the test below can show
// the mechanism rather than merely asserting the fixed outcome.
func rawOnlyMatcher(pattern string) func(string) bool {
	re := regexp.MustCompile(pattern)
	return func(stmt string) bool { return re.MatchString(stmt) }
}

// TestRegexAnalyzer_DowngradeWiringIsFoldAware_3717 drives the REAL production
// path — IntentClassifier.Analyze then RegexAnalyzer.Analyze, exactly as
// BuildAnalyzerPipeline orders them — instead of composing the predicate in the
// test.
//
// Without it this package's other _3717 tests all stay green when
// Analyze's fold-aware statementMatcher is reverted, because they build the
// predicate themselves; only internal/policy's parity test and the corpus
// caught that mutation. Found by adversarial review of #3724.
func TestRegexAnalyzer_DowngradeWiringIsFoldAware_3717(t *testing.T) {
	rule := RegexRule{
		ID:              "test-fold-wiring-3717",
		Decision:        "BLOCK",
		Regex:           foldAttributionPattern,
		IntentDowngrade: []string{LabelIsDocText, LabelInHeredoc},
	}
	for _, tt := range foldAttributionCases {
		t.Run(tt.probe+"/"+tt.name, func(t *testing.T) {
			want := "BLOCK"
			if tt.wantExcluded {
				want = "AUDIT"
			}
			f := runRegexAnalyzer(rule, tt.cmd)
			if f == nil {
				t.Fatalf("rule did not fire on %q — the decision assertion would be vacuous", tt.cmd)
			}
			if f.Decision != want {
				t.Errorf("RegexAnalyzer.Analyze(%q) decision = %s, want %s\n  reason: %s", tt.cmd, f.Decision, want, f.Reason)
			}
		})
	}
}

// TestRegexAnalyzer_ExcludeWiringIsFoldAware_3717 is the command_intent_exclude
// mirror of the test above. Reverting either exclude call site alone survived
// every test in the first cut of #3724 — every rule added there used the
// downgrade label.
func TestRegexAnalyzer_ExcludeWiringIsFoldAware_3717(t *testing.T) {
	rule := RegexRule{
		ID:            "test-fold-wiring-exclude-3717",
		Decision:      "BLOCK",
		Regex:         foldAttributionPattern,
		IntentExclude: []string{LabelIsDocText, LabelInHeredoc},
	}
	for _, tt := range foldAttributionCases {
		t.Run(tt.probe+"/"+tt.name, func(t *testing.T) {
			f := runRegexAnalyzer(rule, tt.cmd)
			if tt.wantExcluded {
				if f != nil {
					t.Errorf("RegexAnalyzer.Analyze(%q) fired %s, want suppressed by command_intent_exclude", tt.cmd, f.Decision)
				}
				return
			}
			if f == nil {
				t.Errorf("RegexAnalyzer.Analyze(%q) suppressed by command_intent_exclude, want BLOCK", tt.cmd)
			}
		})
	}
}

// foldAttributionCases is the #3717 probe table, shared by the tests below and
// mirrored 1:1 by the corpus cases TP/TN-SYSTEMD-RUN-010..017.
//
// N1/N2 are the FP rows adversarial review of #3724 found: bash resolves shell
// parameters against the whole shell, not one statement, so a fold applied to
// an isolated statement can invent an invocation that never runs. With
// `IFS=` the `${IFS}` is empty (one concatenated word, not two), and with
// `x=:` the default `${x:-...}` never fires. Both must stay AUDIT — the
// doc-text sibling is then the only statement that legitimately matches. They
// are wantExcluded:true rather than "no match at all" on purpose: the rule DOES
// fire, on the doc-text statement, and the downgrade is the correct outcome.
//
// Every row pairs the SAME real invocation with the SAME doc-text sibling; only
// the obfuscation of the real statement changes. That is the whole point: the
// decision must not depend on a rendering the shell erases before execution.
var foldAttributionCases = []struct {
	probe string
	name  string
	cmd   string
	// wantExcluded is IntentExcludedForStatements' verdict: true means "every
	// statement that makes this rule fire is doc-text", i.e. the downgrade
	// BLOCK->AUDIT applies.
	wantExcluded bool
}{
	{
		probe:        "P1",
		name:         "IFS-obfuscated real statement + verbatim doc-text sibling",
		cmd:          `systemd-run${IFS}--system /tmp/payload.sh; git commit -m \"deploying via systemd-run --system for persistence, documented here\"`,
		wantExcluded: false,
	},
	{
		probe:        "P2",
		name:         "unset-param-splice real statement + verbatim doc-text sibling",
		cmd:          `s${zqx}ystemd-run --system /tmp/payload.sh; git commit -m \"deploying via systemd-run --system for persistence, documented here\"`,
		wantExcluded: false,
	},
	{
		probe:        "P3",
		name:         "unobfuscated real invocation alone (positive control)",
		cmd:          `systemd-run --system /tmp/payload.sh`,
		wantExcluded: false,
	},
	{
		probe:        "P4",
		name:         "doc-text statement alone keeps its downgrade (FP protection)",
		cmd:          `git commit -m \"deploying via systemd-run --system for persistence, documented here\"`,
		wantExcluded: true,
	},
	{
		probe:        "P5",
		name:         "doc-text statement chained with an unrelated benign command",
		cmd:          `git commit -m \"deploying via systemd-run --system for persistence, documented here\"; echo done`,
		wantExcluded: true,
	},
	{
		probe:        "P6",
		name:         "IFS-obfuscated real invocation alone (no doc-text sibling)",
		cmd:          `systemd-run${IFS}--system /tmp/payload.sh`,
		wantExcluded: false,
	},
	{
		probe:        "N1",
		name:         "empty IFS assigned in a sibling statement invalidates the IFS fold",
		cmd:          `IFS=; : systemd-run${IFS}--system; git commit -m "using systemd-run --system"`,
		wantExcluded: true,
	},
	{
		probe:        "N2",
		name:         "default-value expansion whose name IS assigned in a sibling statement",
		cmd:          `x=:; ${x:-systemd-run} --system /tmp/payload.sh; git commit -m "using systemd-run --system"`,
		// #3798 strict purity: a command word carrying an expansion is
		// impure, so the whole line loses its doc-text exemption. Strict
		// does not resolve `x=:`; this FP is the accepted cost (Gary,
		// 2026-09-23). Corpus mirror: TN-SYSTEMD-RUN-017, now FP.
		wantExcluded: false,
	},
}

// TestIntentExcludedForStatements_FoldAwareAttribution_3717 is the regression
// test: with the fold-aware predicate, an obfuscated real statement is counted
// during attribution, so its non-doc-text label defeats the downgrade.
func TestIntentExcludedForStatements_FoldAwareAttribution_3717(t *testing.T) {
	c := NewIntentClassifier()
	for _, tt := range foldAttributionCases {
		t.Run(tt.probe+"/"+tt.name, func(t *testing.T) {
			statements, parsed := shellparse.SplitTopLevelStatementsChecked(tt.cmd)
			got := IntentExcludedForStatements(c, tt.cmd, statements, parsed, docContextLabels, foldAwareMatcher(tt.cmd, foldAttributionPattern))
			if got != tt.wantExcluded {
				t.Errorf("IntentExcludedForStatements(%q) = %v, want %v\n  statements: %q", tt.cmd, got, tt.wantExcluded, statements)
			}
		})
	}
}

// TestIntentExcludedForStatements_RawMatcherReproducesTheBug_3717 pins the
// CAUSE, not just the cured symptom: the identical table run with the
// pre-#3717 raw-text-only predicate must still mis-attribute P1 and P2.
//
// It is the built-in mutation check. If someone reverts the fold-aware
// predicate, the test above turns red; if someone instead "fixes" this by
// changing the classifier or the pattern, this test turns red because the
// documented mechanism no longer reproduces — and a fix whose mechanism cannot
// be reproduced is a fix nobody can reason about.
func TestIntentExcludedForStatements_RawMatcherReproducesTheBug_3717(t *testing.T) {
	c := NewIntentClassifier()
	// P1 and P2 are the two rows where the raw predicate is WRONG (it excuses
	// an executed statement); every other row must agree with the fold-aware
	// verdict, which is what keeps the fix's blast radius honest.
	//
	// Since #3798 (strict purity) P1 and P2 never reach a matcher: a line
	// with `systemd-run` or an expanded command word is impure, so the
	// labels are dropped first and both predicates agree. The mechanism is
	// still live on PURE lines, where the fold sits in an argument; see
	// TestIntentExcludedForStatements_RawMatcherReproducesTheBugOnPureLines_3717.
	rawWrongOn := map[string]bool{}
	for _, tt := range foldAttributionCases {
		t.Run(tt.probe+"/"+tt.name, func(t *testing.T) {
			statements, parsed := shellparse.SplitTopLevelStatementsChecked(tt.cmd)
			got := IntentExcludedForStatements(c, tt.cmd, statements, parsed, docContextLabels, rawOnlyMatcher(foldAttributionPattern))
			want := tt.wantExcluded
			if rawWrongOn[tt.probe] {
				want = !tt.wantExcluded
			}
			if got != want {
				t.Errorf("raw-only predicate on %q = %v, want %v (the #3717 mechanism no longer reproduces as documented)", tt.cmd, got, want)
			}
		})
	}
}

// TestIntentExcludedForStatements_RawMatcherReproducesTheBugOnPureLines_3717
// keeps the #3717 built-in mutation check alive after #3798. Strict purity
// removes the doc-text exemption from any line with an expanded command word,
// which is where P1/P2 obfuscate. The fold-aware predicate still decides the
// verdict when the obfuscation is in an ARGUMENT of a pure command: the raw
// predicate misses the folded real read and excuses the line on the doc-text
// sibling alone, the fold-aware one does not.
func TestIntentExcludedForStatements_RawMatcherReproducesTheBugOnPureLines_3717(t *testing.T) {
	c := NewIntentClassifier()
	pattern := `cat\s+\S*zqsecret`
	cmd := `cat /tmp/zq${zqx}secret; git commit -m "docs: cat /tmp/zqsecret is what the rule catches"`
	statements, parsed := shellparse.SplitTopLevelStatementsChecked(cmd)
	if !shellparse.CommandLineIsPure(cmd, interpHeredocExecFree) {
		t.Fatalf("control: %q must be a pure line, or this row cannot reach the attribution", cmd)
	}
	if got := IntentExcludedForStatements(c, cmd, statements, parsed, docContextLabels, rawOnlyMatcher(pattern)); !got {
		t.Errorf("raw-only predicate on %q = false, want true (the #3717 mechanism no longer reproduces on a pure line)", cmd)
	}
	if got := IntentExcludedForStatements(c, cmd, statements, parsed, docContextLabels, foldAwareMatcher(cmd, pattern)); got {
		t.Errorf("fold-aware predicate on %q = true, want false (the folded real read must keep its BLOCK)", cmd)
	}
}

// TestStatementMatchCandidates_IncludesRawFirst pins the contract the two
// production statementMatcher closures rely on: candidates[0] is the statement
// itself, so iterating the candidate list is a superset of the raw check and
// the raw-first short-circuit can never change a verdict.
func TestStatementMatchCandidates_IncludesRawFirst(t *testing.T) {
	for _, tt := range foldAttributionCases {
		for _, stmt := range shellparse.SplitSequencedStatements(tt.cmd) {
			cands := StatementMatchCandidates(stmt, nil)
			if len(cands) == 0 || cands[0] != stmt {
				t.Errorf("StatementMatchCandidates(%q)[0] = %q, want the statement itself", stmt, firstOrEmpty(cands))
			}
		}
	}
	if got := StatementMatchCandidates("", nil); got != nil {
		t.Errorf("StatementMatchCandidates(\"\") = %q, want nil", got)
	}
}

func firstOrEmpty(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}
