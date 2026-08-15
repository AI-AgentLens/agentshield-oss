package analyzer_test

import (
	"fmt"
	"strings"
	"testing"
)

// TestBraceWordListParity is the fitness function for the whole-word brace
// expansion bypass class (shellparse.NormalizeBraceWordList), in the same shape
// as TestCompoundWrappingParity (#3045), TestIFSSeparatorParity (#3044),
// TestLineContinuationParity (#3055), TestExecWrapperParity (#3057) and
// TestUnsetParamExpParity (#3206).
//
// The invariant: brace expansion turns ONE word into N words, so `{rm,-rf,/}`
// runs exactly `rm -rf /`. Verified against real bash before the fix was
// written — `printf "[%s]" {echo,-n,hello}` prints `[echo][-n][hello]`, and
// `{printf,"%s\n",hi}` runs printf. `{` is only the compound-command reserved
// word when a blank follows it, so `{rm,...` is an ordinary word.
//
// This measured 916/1172 (78.2%) of BLOCKing corpus commands before the fix —
// larger than the 75.1% unset-parameter class (#3206) that previously held the
// record here, and for the same underlying reason: mvdan.cc/sh has no brace
// node at all (brace expansion is not POSIX), so `{rm,-rf,/}` reached every
// analyzer as a single Lit word whose executable name was the literal text
// "{rm,-rf,/}". Nothing failed and nothing was logged.
//
// What makes this class distinct from #3085/#3087 — which ALSO resolve brace
// groups — is worth stating, because the overlap makes it easy to assume it
// was already covered. ExpandBraces resolves a group to its ALTERNATIVES, one
// per item, which is the right model for `cat ~/.{ssh,x}/id_rsa` (hiding a
// credential directory: does any single alternative name a protected path?).
// The word-list reading is the opposite: the items are a conjunction, and for
// `{rm,-rf,/}` the three alternatives are "rm", "-rf" and "/" — none of which
// is the command that runs. Same syntax, opposite semantics.
func TestBraceWordListParity(t *testing.T) {
	t.Parallel()
	// Zero residual: the fold is wired into addStatementForms (regex.go) ahead
	// of the existing StripCommandPrefixes/StripExecWrapperPrefix peels, and
	// into SemanticAnalyzer's raw-substring rules alongside ifsNormalizedRaw/
	// unsetFoldedRaw (semantic.go), so a brace-wrapped `LC_ALL=C dd ...`,
	// `env dd ...`, `! dd ...` and `pip config set ...` all resolve to the
	// text those layers already expect. Ratchet DOWN further only if a new
	// zero-leak composition is measured; never up without recording why here.
	maxLeaks := 0

	// The denominator is a property of the LOADED RULE SET, so the vacuity
	// floor cannot be one number across two rule sets — see the same split in
	// heredoc_shell_exec_parity_test.go and unset_paramexp_parity_test.go.
	// Measured: 1172 candidates with premium loaded, 758 against a
	// packs/premium/-stripped tree. Each floor sits ~5% under its measurement.
	floor := 1100
	if !premiumPacksPresent() {
		floor = 715
	}

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}

	// Engine and BLOCK baseline are shared across every parity sweep in this
	// package (see parity_baseline_test.go); only the per-transform filter is
	// local.
	engine, baseline := blockingBaseline(t)

	var leaks []string
	tried := 0
	for _, tc := range baseline {
		fields := strings.Fields(tc.Command)
		if len(fields) < 2 {
			continue
		}
		// A command already carrying quoting, its own braces, a comma, or any
		// operator that survives word splitting would be a DIFFERENT command
		// once wrapped in a brace list, not the same one spelled differently.
		// Counting those would inflate the denominator with candidates whose
		// meaning the transform does not preserve — the measurement error
		// assertProbeNotVacuous exists to catch one level up.
		if strings.ContainsAny(tc.Command, "'\"$`\\{}(),<>|&;\n") {
			continue
		}
		tried++
		mutated := "{" + strings.Join(fields, ",") + "}"
		if got := string(engine.Evaluate(mutated, nil).Decision); rank[got] < rank["BLOCK"] {
			leaks = append(leaks, fmt.Sprintf("[%s] %q -> %q = %s", tc.ID, tc.Command, mutated, got))
		}
	}

	assertProbeNotVacuous(t, "brace-wordlist", tried, floor)

	t.Logf("brace-wordlist: %d/%d leaked (budget %d, premium packs present: %v)",
		len(leaks), tried, maxLeaks, premiumPacksPresent())
	if len(leaks) > maxLeaks {
		for i, l := range leaks {
			if i >= 20 {
				t.Logf("  ... +%d more", len(leaks)-20)
				break
			}
			t.Logf("  %s", l)
		}
		t.Errorf("wrapping the command in a brace word list lowered the decision for %d/%d commands (budget %d).\n"+
			"A whole-word brace group expands to ALL of its items as adjacent words — see #3217.",
			len(leaks), tried, maxLeaks)
	}
}

// TestBraceWordListFalsePositiveBoundary is the counterpart to the parity sweep
// above: the shapes a developer actually types must be untouched by the
// expansion.
//
// The expansion is exact rather than heuristic — it produces precisely the
// words bash produces — so it cannot fabricate a command. That makes the FP
// surface narrow, but not empty: what it CAN do is surface a path that the raw
// text did not spell out, and these assert that doing so does not turn ordinary
// build and version-control work into a BLOCK.
func TestBraceWordListFalsePositiveBoundary(t *testing.T) {
	t.Parallel()
	engine := newPipelineEngine(t)

	for _, cmd := range []string{
		"mkdir -p build/{bin,lib}",
		"cp src/{a,b}.txt /tmp/",
		"git checkout {main,dev}",
		"ls -la {src,test}/",
		"mv {old,new}.json ./config/",
		"go build ./{cmd,internal}/...",
		"tar -czf out.tgz {src,docs}",
		"diff {before,after}.log",
		// Quoted groups are literal to a shell and must stay literal here.
		`echo "the {credentials,secrets} directory"`,
		`find . -name '*.{js,ts}'`,
		`grep -r "{alpha,beta}" ./docs`,
	} {
		t.Run(cmd, func(t *testing.T) {
			if got := string(engine.Evaluate(cmd, nil).Decision); got == "BLOCK" {
				t.Errorf("ordinary brace-expansion developer workflow was BLOCKed:\n  %s", cmd)
			}
		})
	}
}
