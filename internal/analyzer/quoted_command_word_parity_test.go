package analyzer_test

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// Quoted command word after an earlier statement — the fitness function for
// #4873.
//
// Bash removes the quotes, so `"cp" a b` runs cp. The regex stage folded a
// quoted command word only when it was the whole command's first word
// (FoldLeadingExecWord), so the same word after any earlier statement was
// never read bare: `echo CLAUDE.md; "cp" /tmp/x CLAUDE.md` decided AUDIT
// naming no rule where the copy alone BLOCKs.
//
// The probe takes every BLOCKing corpus command whose first word is a plain
// program name, quotes that word, and puts an unrelated statement in front of
// it. Its twin is the same prefix in front of the bare command. Quoting a
// plain name is argv-preserving by construction (the name charset holds no
// byte the shell treats specially, and a reserved word never reaches here:
// it parses as a clause, not a CallExpr).
//
// Two invariants:
//   - with the twin BLOCKing, the quoted probe BLOCKs too (the bypass), and
//   - no probe decides below its own as-written evaluation,
//     QuotedCommandWordsOff, which is byte-for-byte main.
//
// Measured 2026-11-14 (3 prefixes x the BLOCKing corpus, twin BLOCKing):
// premium loaded, 6,968 probes, 2,691 lowered with the reading off, 0 on;
// OSS tree, 4,549 probes, 1,872 off, 0 on. No probe below its as-written
// evaluation in either tree.

var quotedCommandWordNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._+-]*$`)

// quoteLeadingCommandWord returns cmd with its first statement's command word
// wrapped in q, when that word is a plain program name starting the text, and
// "" otherwise (no assignment prefix, no negation, nothing to quote).
func quoteLeadingCommandWord(cmd, q string) string {
	f, err := shellparse.ParseText(cmd, syntax.Variant(syntax.LangBash))
	if err != nil || len(f.Stmts) == 0 {
		return ""
	}
	call, ok := f.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) > 0 || len(call.Args) == 0 {
		return ""
	}
	w := call.Args[0]
	if len(w.Parts) != 1 {
		return ""
	}
	lit, ok := w.Parts[0].(*syntax.Lit)
	if !ok || !quotedCommandWordNameRe.MatchString(lit.Value) {
		return ""
	}
	s, e := int(w.Pos().Offset()), int(w.End().Offset())
	if s != 0 || e > len(cmd) || cmd[s:e] != lit.Value {
		return ""
	}
	return q + lit.Value + q + cmd[e:]
}

// quotedCommandWordPrefixes are unrelated leading statements, one per
// separator the issue measured. Each is a no-op on its own.
var quotedCommandWordPrefixes = []struct{ label, text string }{
	{"newline", "echo CLAUDE.md\n"},
	{"semicolon", "echo CLAUDE.md; "},
	{"and", "true && "},
}

func quotedCommandWordDecide(engine *policy.Engine, cmd string, mode policy.QuotedCommandWordsMode) policy.EvalResult {
	n := normalize.NormalizeCommand(cmd, "")
	return engine.EvaluateQuotedCommandWords(cmd, n.Paths, n.Parsed, "", mode)
}

func TestQuotedCommandWordParity(t *testing.T) {
	engine, baseline := blockingBaseline(t)

	// Control row first: the issue's command reproduces the bypass with the
	// reading off, and the probe builds the issue's text.
	ctrl := "cp /tmp/" + "injected.md CLAUDE.md"
	quoted := quoteLeadingCommandWord(ctrl, `"`)
	if quoted != `"cp" /tmp/`+"injected.md CLAUDE.md" {
		t.Fatalf("control: probe rewrote %q to %q", ctrl, quoted)
	}
	probe := quotedCommandWordPrefixes[1].text + quoted
	if d := quotedCommandWordDecide(engine, probe, policy.QuotedCommandWordsOff).Decision; d == policy.DecisionBlock {
		t.Fatalf("control: with the reading off, %q still BLOCKs; the probe no longer reaches the #4873 bypass", probe)
	}
	if d := quotedCommandWordDecide(engine, probe, policy.QuotedCommandWordsStricter).Decision; d != policy.DecisionBlock {
		t.Fatalf("control: %q decided %v; want BLOCK", probe, d)
	}

	// No budget is tolerated; named so scripts/check-fail-open-budget.sh
	// counts the class.
	const maxLeaks = 0
	blockFloor, offLeakFloor := 6000, 2200
	if !premiumPacksPresent() {
		blockFloor, offLeakFloor = 3800, 1500
	}

	var (
		blockDen, offLeaks    int
		leaks, belowAsWritten []string
	)
	for _, tc := range baseline {
		dq := quoteLeadingCommandWord(tc.Command, `"`)
		if dq == "" {
			continue
		}
		sq := quoteLeadingCommandWord(tc.Command, `'`)
		for _, p := range quotedCommandWordPrefixes {
			twin := quotedCommandWordDecide(engine, p.text+tc.Command, policy.QuotedCommandWordsStricter)
			if twin.Decision != policy.DecisionBlock {
				continue
			}
			blockDen++
			off := quotedCommandWordDecide(engine, p.text+dq, policy.QuotedCommandWordsOff)
			if off.Decision != policy.DecisionBlock {
				offLeaks++
			}
			for _, v := range []struct{ q, text string }{{`"`, p.text + dq}, {`'`, p.text + sq}} {
				got := quotedCommandWordDecide(engine, v.text, policy.QuotedCommandWordsStricter)
				if got.Decision != policy.DecisionBlock {
					leaks = append(leaks, fmt.Sprintf("%s [%s %s]: %s rules=%v : %q", tc.ID, p.label, v.q, got.Decision, got.TriggeredRules, v.text))
				}
				was := off
				if v.q == `'` {
					was = quotedCommandWordDecide(engine, v.text, policy.QuotedCommandWordsOff)
				}
				if caseFoldRank[got.Decision] < caseFoldRank[was.Decision] {
					belowAsWritten = append(belowAsWritten, fmt.Sprintf("%s [%s %s]: %s -> %s : %q", tc.ID, p.label, v.q, was.Decision, got.Decision, v.text))
				}
			}
		}
	}

	t.Logf("quoted command word after a statement: %d BLOCKing twins; reading off leaks %d, on leaks %d (budget %d)",
		blockDen, offLeaks, len(leaks), maxLeaks)
	assertProbeNotVacuous(t, "quoted command word (BLOCKing twins)", blockDen, blockFloor)
	if offLeaks < offLeakFloor {
		t.Fatalf("with the reading off only %d of %d probes leaked (floor %d): the probe no longer reproduces the #4873 bypass, so the count below proves nothing",
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
		report(fmt.Sprintf("%d quoted command words after a statement lowered a BLOCK (budget %d)", len(leaks), maxLeaks), leaks)
	}
	if len(belowAsWritten) > 0 {
		report(fmt.Sprintf("%d probes decided BELOW their as-written evaluation; the reading must only raise", len(belowAsWritten)), belowAsWritten)
	}
}
