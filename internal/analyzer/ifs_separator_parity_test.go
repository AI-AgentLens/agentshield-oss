package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// ifsParityOSSIncidental lists the corpus cases this sweep leaves out in the
// community-only tree (a clone of agentshield-oss, packs/premium/ stripped).
// Each one BLOCKs there through a rule that is not meant for it, while the
// rules that are meant for it are premium. The sweep's baseline is "what
// BLOCKs today", so in that tree an incidental BLOCK joins it, and losing that
// BLOCK under ${IFS} is not the bypass #3044 is about.
//
// It is test-only. In the OSS build the ${IFS} spelling of a listed command
// still decides lower than its plain spelling; the list records that, it does
// not cause it. The full tree ignores the list, so its budget stays 0.
//
// Every entry is pinned in the OSS tree (checkIFSParityOSSIncidental): the
// plain spelling must still BLOCK through exactly `rule` and nothing else, and
// the ${IFS} spelling must still decide lower at every position the sweep
// tries. When either stops being true, the sweep fails and the entry has to
// come out on purpose.
var ifsParityOSSIncidental = map[string]struct{ rule, why string }{
	// #4827. Its rules, ts-block-registry-hive-copy and
	// ps-block-registry-hive-copy, are premium (#4798); the community tier has
	// no hive-copy rule. Unquoted, bash drops the path's backslashes, and
	// guardian's base64 heuristic BLOCKs the run of letters left
	// (TN-WIN-HIVE-COPY-001 is quoted to avoid the same thing). With ${IFS}
	// in the command, that word holds a ParamExp, DequoteCommand leaves it
	// alone, and the heuristic no longer sees the run.
	"TP-WIN-HIVE-COPY-001": {
		rule: "guardian-obfuscated_base64",
		why:  "its rules are premium; the OSS tree BLOCKs it only through guardian's base64 heuristic on the backslash-stripped path",
	},
}

// checkIFSParityOSSIncidental pins each ifsParityOSSIncidental entry in the
// community-only tree. leaked[id] counts the positions at which the entry's
// ${IFS} spelling decided lower; tried[id] counts the positions it was tried at.
func checkIFSParityOSSIncidental(t *testing.T, decide func(string) (string, []string), baselineIDs map[string]string, leaked, tried map[string]int) {
	t.Helper()
	for id, e := range ifsParityOSSIncidental {
		cmd, ok := baselineIDs[id]
		if !ok {
			t.Errorf("ifsParityOSSIncidental lists %s, which does not BLOCK in this tree, so the entry exempts nothing; remove it", id)
			continue
		}
		decision, rules := decide(cmd)
		if decision != "BLOCK" || len(rules) != 1 || rules[0] != e.rule {
			t.Errorf("ifsParityOSSIncidental lists %s because only %s BLOCKs it here (%s); it now decides %s with rules %v. Re-check the entry: if a rule meant for this command BLOCKs it, remove the entry so the sweep grades it", id, e.rule, e.why, decision, rules)
		}
		if tried[id] == 0 {
			t.Errorf("ifsParityOSSIncidental lists %s, but the sweep tried no ${IFS} spelling of it; remove the entry", id)
		}
		if leaked[id] != tried[id] {
			t.Errorf("ifsParityOSSIncidental lists %s, but its ${IFS} spelling now keeps the BLOCK at %d of %d positions; remove the entry so the sweep grades it", id, tried[id]-leaked[id], tried[id])
		}
	}
}

// TestIFSSeparatorParity is the fitness function for issue #3044
// (taxonomy: unauthorized-execution/agentic-attacks/pre-expansion-command-guard-bypass),
// in the same shape as TestCompoundWrappingParity (#3045),
// TestLineContinuationParity (#3055) and TestExecWrapperParity (#3057).
//
// The invariant: $IFS defaults to space/tab/newline in every POSIX shell, so
// swapping a literal space for an unquoted ${IFS} reference does not change
// WHICH command runs — `rm${IFS}-rf${IFS}/` is exactly as destructive as
// `rm -rf /`. A guard that matches pre-expansion text sees no whitespace in
// the source and silently stops matching.
//
// This had to be measured corpus-wide to be seen at all, the same way #3045
// and #3055 were: nothing failed, nothing was logged. Before the fix
// (internal/shellparse/ifs_normalize.go, wired into shellparse.Parse for
// every AST-based analyzer and into RegexAnalyzer/SubstitutionAnalyzer's
// text-matching candidates), swapping the FIRST space of every BLOCKing
// corpus command for ${IFS} downgraded 1,657 of 2,414 commands (68.6%) — the
// largest single bypass class found in this codebase, well past the 20.8%
// compound-wrapping gap (#3045) and the 52.5% line-continuation gap (#3055).
func TestIFSSeparatorParity(t *testing.T) {
	t.Parallel()
	// Zero leaks at both probed positions. Getting there took three fixes
	// beyond the base shellparse.Parse canonicalization: RegexAnalyzer and
	// SubstitutionAnalyzer needed their own IFS-normalized text candidates
	// (they match/re-parse raw text independently of ctx.Parsed);
	// SemanticAnalyzer's built-in Go checks needed the same, since several
	// (e.g. sem-block-pip-config-index) match via strings.Contains(raw, ...)
	// rather than through the AST; and NormalizeIFS itself needed a trailing
	// TrimSpace, since a substitution at the very start of a statement
	// ("...;${IFS}dd ..." after a ";") produced a leading space that
	// defeated every "^"-anchored regex. See internal/shellparse/ifs_normalize.go
	// and its call sites in regex.go/substitution.go/semantic.go.
	const maxLeaks = 0

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}

	positions := []struct {
		name string
		n    int // substitute the nth space (1-based)
	}{
		{"first-space", 1},
		{"second-space", 2},
	}

	// Engine and BLOCK baseline are shared across every parity sweep in this
	// package (see parity_baseline_test.go); only the per-transform filter is
	// local.
	engine, baseline := blockingBaseline(t)

	// Only the community-only tree reads ifsParityOSSIncidental (#4827).
	oss := !ossbuild.PremiumPacksPresent()
	incidentalLeaked := map[string]int{}
	incidentalTried := map[string]int{}

	for _, p := range positions {
		t.Run(p.name, func(t *testing.T) {
			var leaks []string
			tried, exempted := 0, 0
			for _, tc := range baseline {
				substituted, ok := ifsAtSpace(tc.Command, p.n)
				if !ok {
					continue
				}
				_, incidental := ifsParityOSSIncidental[tc.ID]
				incidental = incidental && oss
				got := string(engine.Evaluate(substituted, nil).Decision)
				if incidental {
					exempted++
					incidentalTried[tc.ID]++
					if rank[got] < rank["BLOCK"] {
						incidentalLeaked[tc.ID]++
					}
					continue
				}
				tried++
				if rank[got] < rank["BLOCK"] {
					leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, got, substituted))
				}
			}

			if len(leaks) > maxLeaks {
				t.Errorf("substituting ${IFS} for the %s lowered the decision for %d/%d commands (budget %d).\n"+
					"$IFS defaults to whitespace — swapping it in must never weaken enforcement (see #3044).\n%s",
					p.name, len(leaks), tried, maxLeaks, joinLines(leaks))
			}
			t.Logf("%s: %d/%d leaked (budget %d); %d left out as OSS-tree incidental BLOCKs", p.name, len(leaks), tried, maxLeaks, exempted)
		})
	}

	if oss {
		baselineIDs := map[string]string{}
		for _, tc := range baseline {
			baselineIDs[tc.ID] = tc.Command
		}
		checkIFSParityOSSIncidental(t, func(cmd string) (string, []string) {
			r := engine.Evaluate(cmd, nil)
			return string(r.Decision), r.TriggeredRules
		}, baselineIDs, incidentalLeaked, incidentalTried)
	}
}

// ifsAtSpace replaces the nth UNQUOTED space on the first line of cmd with
// "${IFS}", the documented pattern-guard bypass that swaps a literal
// separator for the shell's default word-splitting variable. Reports false
// when there is no such space, or when the substitution doesn't round-trip
// to valid, equivalent shell — not every space position is a legal swap. Two
// guards, mirroring the same honesty requirement continueAtSpace applies to
// line continuation:
//
//   - Heredoc delimiters are matched as literal text, never expanded, so a
//     space immediately before one ("<< 'EOF'") is a DIFFERENT terminator
//     once swapped, not an equivalent rewrite. Skipped explicitly.
//   - Reserved-word boundaries ("function name", "if cmd", ...) and some
//     operator-adjacent gaps aren't lexically valid with $IFS glued on
//     (`function${IFS}sudo` is a syntax error in real bash, verified with
//     `bash -n`) — mvdan.cc/sh rejects the same shapes real bash does, so
//     re-parsing the candidate and requiring success catches these without
//     having to enumerate every reserved word by hand.
func ifsAtSpace(cmd string, n int) (string, bool) {
	var inSingle, inDouble bool
	seen := 0
	for i := 0; i < len(cmd); i++ {
		switch c := cmd[i]; {
		case c == '\n':
			return "", false // heredoc bodies and later lines are out of scope
		case c == '\\' && !inSingle:
			i++ // escaped character, never a separator
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == ' ' && !inSingle && !inDouble:
			if seen++; seen != n {
				continue
			}
			if i >= 2 && cmd[i-2:i] == "<<" {
				return "", false // heredoc delimiter boundary — not equivalent
			}
			if prefixWordBoundary(cmd, i) {
				return "", false // assignment/negation prefix gap — not equivalent
			}
			candidate := cmd[:i] + "${IFS}" + cmd[i+1:]
			if !parsesAsShell(candidate) {
				return "", false
			}
			return candidate, true
		}
	}
	return "", false
}

func parsesAsShell(cmd string) bool {
	_, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(cmd), "")
	return err == nil
}

// prefixWordBoundary reports whether the space at cmd[i] immediately follows
// a leading env-assignment ("LC_ALL=C") or "!" negation token. Gluing that
// token to what follows via ${IFS} doesn't leave the command equivalent: an
// assignment's value can itself contain a ParamExp, so "LC_ALL=C${IFS}dd"
// parses as ONE assignment (LC_ALL="C<IFS-value>dd") with no command at all,
// not "LC_ALL=C dd" (verified with `bash -c 'set -x; ...'` — the "dd" is
// swallowed into the assignment value and never runs). parsesAsShell alone
// can't catch this, the same way it can't catch the heredoc-delimiter case:
// both stay syntactically valid while meaning something else entirely.
func prefixWordBoundary(cmd string, i int) bool {
	start := strings.LastIndexByte(cmd[:i], ' ') + 1 // 0 if no earlier space
	word := cmd[start:i]
	return word == "!" || strings.Contains(word, "=")
}
