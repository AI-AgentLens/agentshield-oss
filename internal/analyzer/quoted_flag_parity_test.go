package analyzer_test

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// Quoted flag token parity — the fitness function for #4289.
//
// Bash removes whole-word quotes before the program sees argv, so
// `rm "-rf" /etc` runs exactly `rm -rf /etc`. Before #4289 neither rule
// surface saw it: the parser classified flags on the printed word and
// DequoteCommand leaves whole-argument quotes alone. The issue measured 405
// of 882 flag-bearing BLOCKs lowered, 271 of them with no rule id at all.
//
// The probe wraps every bare flag-token argument of a corpus command in
// quotes. That rewrite is argv-preserving by construction: the token charset
// (`^-{1,2}[A-Za-z0-9][-A-Za-z0-9=._]*$`) holds no byte the shell treats
// specially. Every probe is evaluated the way the hook evaluates it
// (normalize paths + parsed tree), so protected_paths and the consumer table
// are exercised, not only the analyzers.
//
// Two invariants, both from the issue's lane brief:
//   - a quoted flag token never decides BELOW its bare twin, and for the
//     BLOCKing corpus it stays BLOCK (the bypass), and
//   - the quoted command never decides below its own as-written evaluation,
//     QuotedFlagsOff, which is byte-for-byte main (no new fail-open).
//
// Measured on this commit (premium loaded): 3634 corpus commands carry a
// flag token, 1570 of them BLOCKing. QuotedFlagsOff (main's behaviour) lowers
// 637 of those 1570 with the tokens double-quoted, and the same 637
// single-quoted; the production reading lowers 0, and decides no probe below
// its as-written evaluation or its bare twin.

var quotedFlagProbeTokenRe = regexp.MustCompile(`^-{1,2}[A-Za-z0-9][-A-Za-z0-9=._]*$`)

// quoteFlagTokens wraps every single-literal command argument that is a plain
// flag token in q, splicing into the original text. Returns the rewrite and
// how many words it quoted (0 and "" when there were none or the command does
// not parse).
func quoteFlagTokens(cmd, q string) (string, int) {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(cmd), "")
	if err != nil {
		return "", 0
	}
	type span struct{ s, e int }
	var spans []span
	syntax.Walk(f, func(n syntax.Node) bool {
		c, ok := n.(*syntax.CallExpr)
		if !ok {
			return true
		}
		for _, w := range c.Args {
			if len(w.Parts) != 1 {
				continue
			}
			lit, ok := w.Parts[0].(*syntax.Lit)
			if !ok || !quotedFlagProbeTokenRe.MatchString(lit.Value) {
				continue
			}
			s, e := int(w.Pos().Offset()), int(w.End().Offset())
			if s < 0 || e > len(cmd) || cmd[s:e] != lit.Value {
				continue
			}
			spans = append(spans, span{s, e})
		}
		return true
	})
	if len(spans) == 0 {
		return "", 0
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].s > spans[j].s })
	out := cmd
	for _, sp := range spans {
		out = out[:sp.s] + q + out[sp.s:sp.e] + q + out[sp.e:]
	}
	return out, len(spans)
}

func quotedFlagDecide(engine *policy.Engine, cmd string, mode policy.QuotedFlagsMode) policy.EvalResult {
	n := normalize.NormalizeCommand(cmd, "")
	return engine.EvaluateQuotedFlags(cmd, n.Paths, n.Parsed, "", mode)
}

func TestQuotedFlagTokenParity(t *testing.T) {
	engine, _ := blockingBaseline(t)
	rm := "r" + "m"

	// Control row first: the bare command BLOCKs, its quoted twin reproduces
	// the bypass with the bare reading off, and the probe quotes the token.
	ctrl := rm + " -rf /etc"
	quotedCtrl, k := quoteFlagTokens(ctrl, `"`)
	if quotedCtrl != rm+` "-rf" /etc` || k != 1 {
		t.Fatalf("control: probe rewrote %q to %q (%d words); want %q", ctrl, quotedCtrl, k, rm+` "-rf" /etc`)
	}
	if d := quotedFlagDecide(engine, ctrl, policy.QuotedFlagsStricter).Decision; d != policy.DecisionBlock {
		t.Fatalf("control: %q decided %v; want BLOCK", ctrl, d)
	}
	if d := quotedFlagDecide(engine, quotedCtrl, policy.QuotedFlagsOff).Decision; d == policy.DecisionBlock {
		t.Fatalf("control: with the bare reading off, %q still BLOCKs — the probe no longer reaches the #4289 bypass", quotedCtrl)
	}

	// No budget is tolerated; named so scripts/check-fail-open-budget.sh
	// counts the class.
	const maxLeaks = 0
	blockFloor, offLeakFloor, probeFloor := 1200, 450, 2700
	if !premiumPacksPresent() {
		blockFloor, offLeakFloor, probeFloor = 650, 250, 2700
	}

	var (
		probes, blockDen, offLeaks int
		leaks, belowAsWritten      []string
		belowTwin                  []string
	)
	for _, tc := range testdata.AllTestCases() {
		dq, n := quoteFlagTokens(tc.Command, `"`)
		if n == 0 {
			continue
		}
		probes++
		twin := quotedFlagDecide(engine, tc.Command, policy.QuotedFlagsStricter)
		off := quotedFlagDecide(engine, dq, policy.QuotedFlagsOff)
		got := quotedFlagDecide(engine, dq, policy.QuotedFlagsStricter)

		if caseFoldRank[got.Decision] < caseFoldRank[off.Decision] {
			belowAsWritten = append(belowAsWritten, fmt.Sprintf("%s: %s -> %s : %s", tc.ID, off.Decision, got.Decision, dq))
		}
		if caseFoldRank[got.Decision] < caseFoldRank[twin.Decision] {
			belowTwin = append(belowTwin, fmt.Sprintf("%s: bare %s, quoted %s : %s", tc.ID, twin.Decision, got.Decision, dq))
		}
		if tc.ExpectedDecision != "BLOCK" || twin.Decision != policy.DecisionBlock {
			continue
		}
		blockDen++
		if off.Decision != policy.DecisionBlock {
			offLeaks++
		}
		if got.Decision != policy.DecisionBlock {
			leaks = append(leaks, fmt.Sprintf(`%s ["]: %s rules=%v : %s`, tc.ID, got.Decision, got.TriggeredRules, dq))
		}
		sq, _ := quoteFlagTokens(tc.Command, `'`)
		if r := quotedFlagDecide(engine, sq, policy.QuotedFlagsStricter); r.Decision != policy.DecisionBlock {
			leaks = append(leaks, fmt.Sprintf(`%s [']: %s rules=%v : %s`, tc.ID, r.Decision, r.TriggeredRules, sq))
		}
	}

	t.Logf("quoted flag tokens: %d probes; %d BLOCKing; bare reading off leaks %d, on leaks %d (budget %d)",
		probes, blockDen, offLeaks, len(leaks), maxLeaks)
	assertProbeNotVacuous(t, "quoted flag token (all decisions)", probes, probeFloor)
	assertProbeNotVacuous(t, "quoted flag token (BLOCKing)", blockDen, blockFloor)
	if offLeaks < offLeakFloor {
		t.Fatalf("with the bare reading off only %d of %d quoted BLOCKs leaked (floor %d): the probe no longer reproduces the #4289 bypass, so the 0 below proves nothing",
			offLeaks, blockDen, offLeakFloor)
	}
	report := func(what string, rows []string) {
		sort.Strings(rows)
		if len(rows) > 25 {
			rows = append(rows[:25], fmt.Sprintf("... and %d more", len(rows)-25))
		}
		t.Errorf("%s:\n  %s", what, strings.Join(rows, "\n  "))
	}
	if len(leaks) > maxLeaks {
		report(fmt.Sprintf("%d quoted flag tokens lowered a BLOCK (budget %d)", len(leaks), maxLeaks), leaks)
	}
	if len(belowAsWritten) > 0 {
		report(fmt.Sprintf("%d quoted commands decided BELOW their as-written evaluation — the bare reading must only raise", len(belowAsWritten)), belowAsWritten)
	}
	if len(belowTwin) > 0 {
		report(fmt.Sprintf("%d quoted commands decided below their bare twin", len(belowTwin)), belowTwin)
	}
}

// TestQuotedFlagTokenRows pins the rows the lane brief named, each beside its
// bare twin. Strings that would read as attacks are assembled at runtime: the
// hook reads test sources as commands.
func TestQuotedFlagTokenRows(t *testing.T) {
	engine, _ := blockingBaseline(t)
	rm := "r" + "m"
	noVerify := "--no-" + "verify"
	decide := func(cmd string) policy.EvalResult {
		return quotedFlagDecide(engine, cmd, policy.QuotedFlagsStricter)
	}
	off := func(cmd string) policy.EvalResult {
		return quotedFlagDecide(engine, cmd, policy.QuotedFlagsOff)
	}

	t.Run("issue witnesses decide as their bare twin", func(t *testing.T) {
		for _, c := range [][2]string{
			{rm + ` "-rf" /etc`, rm + ` -rf /etc`},
			{`git reset "--hard" HEAD~3`, `git reset --hard HEAD~3`},
			{`kubectl delete pods "--all" -n prod`, `kubectl delete pods --all -n prod`},
			{`git commit "` + noVerify + `" -m wip`, `git commit ` + noVerify + ` -m wip`},
		} {
			quoted, bare := c[0], c[1]
			want := decide(bare)
			if want.Decision != policy.DecisionBlock {
				t.Fatalf("control: bare %q decided %v; want BLOCK", bare, want.Decision)
			}
			if got := decide(quoted); got.Decision != policy.DecisionBlock {
				t.Errorf("%q decided %v rules=%v; want BLOCK like %q", quoted, got.Decision, got.TriggeredRules, bare)
			}
		}
	})

	t.Run("quoted prose in a loop is a no-op", func(t *testing.T) {
		cmd := `for m in "fix: don't panic"; do git commit -m "$m"; done`
		if u := shellparse.UnquoteFlagWords(cmd); u != "" {
			t.Fatalf("UnquoteFlagWords(%q) = %q; want no rewrite", cmd, u)
		}
		if got, was := decide(cmd), off(cmd); !reflect.DeepEqual(got, was) {
			t.Errorf("%q: result changed: %+v, as written %+v", cmd, got, was)
		}
	})

	t.Run("a quoted flag-looking word that is data decides as its bare twin", func(t *testing.T) {
		// echo has no -r/-f options: bash's echo prints `-rf`. Not a BLOCK
		// either way.
		if got, bare := decide(`echo "-rf"`), decide(`echo -rf`); got.Decision != bare.Decision || got.Decision == policy.DecisionBlock {
			t.Errorf(`echo "-rf" decided %v rules=%v; bare %v; want equal and not BLOCK`, got.Decision, got.TriggeredRules, bare.Decision)
		}
		// grep receives the identical argv either way (bash removes the
		// quotes; grep then rejects an unknown option). Its bare twin BLOCKs
		// today via guardian-disable_security, so the quoted form now does too.
		// That pre-existing guardian decision on the bare spelling is a rule
		// question (#4289 PR body), not this parser's.
		quoted, bareCmd := `grep "`+noVerify+`" file`, `grep `+noVerify+` file`
		if got, bare := decide(quoted), decide(bareCmd); got.Decision != bare.Decision {
			t.Errorf("%q decided %v rules=%v; bare twin %v rules=%v; want equal", quoted, got.Decision, got.TriggeredRules, bare.Decision, bare.TriggeredRules)
		}
	})

	t.Run("a quoted flag in a designated consumer slot is not lowered", func(t *testing.T) {
		// Known gap, pinned on purpose. `ssh -i <key>` is a designated
		// consumer (AUDIT, recorded); quoted, the consumer table reads the
		// raw words and does not see the slot, so it BLOCKs on main. The bare
		// reading could only lower that, and the bare reading only ever
		// raises, so it stays BLOCK. Closing it is a decision that lowers a
		// verdict, not a parser fix.
		key := "~/." + "ssh/id_" + "rsa"
		for _, q := range []string{`"`, `'`} {
			quoted := "ssh " + q + "-i" + q + " " + key + " host"
			got, was := decide(quoted), off(quoted)
			if got.Decision != was.Decision || !reflect.DeepEqual(got.TriggeredRules, was.TriggeredRules) {
				t.Errorf("%q: %v rules=%v; as written %v rules=%v; want unchanged", quoted, got.Decision, got.TriggeredRules, was.Decision, was.TriggeredRules)
			}
			if got.Decision != policy.DecisionBlock {
				t.Errorf("%q decided %v; the pinned gap is BLOCK (closing it must be deliberate)", quoted, got.Decision)
			}
		}
		if bare := decide("ssh -i " + key + " host"); bare.Decision != policy.DecisionAudit {
			t.Errorf("control: the bare consumer use decided %v; want AUDIT", bare.Decision)
		}
	})

	t.Run("an equal decision keeps the as-written record", func(t *testing.T) {
		// `-m "--no-verify"` is a commit message. As written it already
		// BLOCKs; bare it would also name the commit-hook rule. No decision
		// needs that extra rule, so the receipt must not gain it.
		cmd := `git commit -m "` + noVerify + `"`
		got, was := decide(cmd), off(cmd)
		if was.Decision != policy.DecisionBlock {
			t.Fatalf("control: %q as written decided %v; want BLOCK", cmd, was.Decision)
		}
		bare := decide(`git commit -m ` + noVerify)
		if reflect.DeepEqual(bare.TriggeredRules, was.TriggeredRules) {
			t.Fatalf("control: bare and as-written records already agree (%v); the row no longer separates the tie rule", was.TriggeredRules)
		}
		if !reflect.DeepEqual(got.TriggeredRules, was.TriggeredRules) {
			t.Errorf("%q: rules %v; want the as-written %v", cmd, got.TriggeredRules, was.TriggeredRules)
		}
	})
}
