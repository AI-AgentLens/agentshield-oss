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

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
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
	ossbuild.SkipPremiumSized(t)
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
	// stdinTargets/stdinBases/stdinProbes count the #4965 generator below:
	// operands taken from live TPs, the plain `< TARGET` reads that decide at
	// or above REQUIRE_APPROVAL, and the heredoc-carrying forms built on them.
	stdinTargets, stdinBases, stdinProbes := 0, 0, 0
	// leak records one probe whose decision dropped below its comparison
	// form's. bareCmd is what it is compared against: the inline TP for the
	// wrapper channels, the plain `< TARGET` read for the #4965 channels.
	leak := func(r policy.Rule, channel, keyText, bareCmd string, bare policy.Decision, wrapped string, got policy.EvalResult) {
		laundered++
		key := launderingKey(r.ID, channel, keyText)
		seen[key] = true
		if known[key] {
			return // recorded gap — see the baseline file
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
			r.ID, channel, bare, got.Decision, got.TriggeredRules, pm, bareCmd, wrapped)
	}
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
					// The key hashes the TP, as it always has, so the
					// recorded lines keep their keys.
					leak(r, ch.name, tp, tp, bare.Decision, wrapped, got)
				}
			}

			// #4965: a here-string or heredoc on a cat/tee statement whose
			// stdin an input redirect on the same statement points at a
			// file. bash keeps the LAST input redirect on fd 0 and zsh
			// (MULTIOS, on by default) reads every one in turn, so the file
			// is read whichever of the two comes first — yet on main the
			// statement was labelled in_heredoc, "body written to a file",
			// and its BLOCK lowered to AUDIT. None of the wrapper channels
			// above builds this shape: they wrap the TP, while this one has
			// to move the TP's file operand into an input redirect.
			//
			// So each file-like operand of a live TP is read through `<` by
			// cat and by tee. Where that plain read decides at or above
			// REQUIRE_APPROVAL, the same read with a dummy here-string or
			// quoted heredoc, before and after the `<`, must not decide
			// lower. Comparing against the plain read, not the TP, keeps a
			// rule whose pattern cannot see a redirected path (it anchors
			// on `cat FILE`, say) from reading as a laundering leak.
			for _, target := range stdinRedirectTargets(tp) {
				stdinTargets++
				for _, sink := range stdinSinks {
					base := sink.read(target)
					baseDec := engine.Evaluate(base, nil).Decision
					if sev[baseDec] < sev[policy.DecisionRequireApproval] {
						continue // not a read any rule stops; nothing to launder
					}
					stdinBases++
					for _, form := range stdinHeredocForms {
						wrapped := sink.withHeredoc(target, form)
						stdinProbes++
						probes++
						got := engine.Evaluate(wrapped, nil)
						if sev[got.Decision] < sev[baseDec] {
							// Keyed on the probe text: one TP yields several
							// targets, and each target several probes.
							leak(r, "stdin-redirect:"+sink.name+":"+form.name, wrapped, base, baseDec, wrapped, got)
						}
					}
				}
			}
		}
	}
	t.Logf("doc-text-downgrade laundering fitness: %d rules, %d probes, %d skipped (quoting), %d laundered (%d recorded, %d new)", rules, probes, skipped, laundered, laundered-len(newLeaks), len(newLeaks))
	t.Logf("  of which stdin-redirect (#4965): %d file-like TP operands, %d live plain reads, %d heredoc-carrying probes", stdinTargets, stdinBases, stdinProbes)
	if stdinProbes == 0 {
		t.Fatal("the #4965 stdin-redirect generator built no probes — the operand filter or the sinks are broken, not clean")
	}
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

// stdinSink is a command that reads its stdin and writes it somewhere: the
// two the in_heredoc label names (cat, tee).
type stdinSink struct {
	name string
	// read is the plain form: the sink reading target through `<`.
	read func(target string) string
	// withHeredoc is the same read carrying a dummy here-string or heredoc.
	withHeredoc func(target string, form stdinHeredocForm) string
}

// stdinHeredocForm is where the dummy body sits relative to `< target`.
type stdinHeredocForm struct {
	name    string
	heredoc bool // quoted heredoc <<'EOF' (body x); false = here-string <<< x
	before  bool // the heredoc/here-string precedes `< target`
}

var stdinHeredocForms = []stdinHeredocForm{
	{"herestring-before", false, true},
	{"herestring-after", false, false},
	{"heredoc-before", true, true},
	{"heredoc-after", true, false},
}

// redirs renders the two input redirects in form's order, plus the heredoc
// body to append after the command line ("" for a here-string).
func (f stdinHeredocForm) redirs(target string) (line, body string) {
	dummy := "<<< x"
	if f.heredoc {
		dummy, body = "<<'EOF'", "\nx\nEOF"
	}
	if f.before {
		return dummy + " < " + target, body
	}
	return "< " + target + " " + dummy, body
}

var stdinSinks = []stdinSink{
	{
		name: "cat",
		read: func(target string) string { return "cat < " + target + " > /tmp/out" },
		withHeredoc: func(target string, f stdinHeredocForm) string {
			line, body := f.redirs(target)
			return "cat " + line + " > /tmp/out" + body
		},
	},
	{
		name: "tee",
		read: func(target string) string { return "tee /tmp/out < " + target },
		withHeredoc: func(target string, f stdinHeredocForm) string {
			line, body := f.redirs(target)
			return "tee /tmp/out " + line + body
		},
	},
}

// stdinRedirectTargets returns the words of tp that could name a file to
// read through `<`: whitespace-separated, not a flag, carrying a `/` or `.`
// or starting with `~`, and free of anything that would change meaning as a
// redirect target (operators, substitutions, globs, embedded quotes). A word
// that is one whole single- or double-quoted string is kept as written. The
// filter is deliberately loose — the plain read in the caller decides which
// targets any rule actually stops.
func stdinRedirectTargets(tp string) []string {
	var out []string
	seen := map[string]bool{}
	for _, w := range strings.Fields(tp) {
		inner := w
		if len(w) >= 2 && (w[0] == '\'' || w[0] == '"') && w[len(w)-1] == w[0] {
			inner = w[1 : len(w)-1]
		}
		switch {
		case inner == "" || strings.HasPrefix(inner, "-"):
			continue
		case strings.ContainsAny(inner, "|&;<>()`'\"\\{}*?[]=\n"):
			continue
		case strings.Contains(inner, "://"):
			continue // a URL, not a file
		case !strings.ContainsAny(inner, "/.") && !strings.HasPrefix(inner, "~"):
			continue
		}
		if !seen[w] {
			seen[w] = true
			out = append(out, w)
		}
	}
	return out
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
