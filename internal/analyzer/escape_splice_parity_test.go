package analyzer_test

import (
	"fmt"
	"strings"
	"testing"
	"unicode"
)

// TestEscapeSpliceParity is the fitness function for issue #3208: a
// backslash escaping an ASCII alphanumeric character, or bash's $"..."
// locale-translated quoting, both survive quote/escape removal in a real
// shell but previously survived unresolved in AgentShield's guard, so the
// command it inspected was not the command bash actually ran.
//
// Measured before the fix on this corpus: exec-backslash 60.5% (1391/2300),
// exec-locale-quote 58.9% (1355/2300), arg2-backslash 50.6% (963/1905) —
// close to the issue's own numbers (60.5%/58.9%/52.5%), the small deltas
// being corpus drift since the issue was filed. For scale this sits directly
// behind the 75.1% unset-parameter class (#3206) and ahead of the 68.6%
// ${IFS} gap (#3044).
//
// Three positions are probed, mirroring TestUnsetParamExpParity's shape:
// exec-backslash and exec-locale-quote exercise shellparse.Parse's
// executable-position canonicalization plus DequoteCommand's regex-visible
// reconstruction (the bulk of the corpus is command_regex rules that never
// consult the AST); arg2-backslash exercises the same DequoteCommand
// surface on an argument word.
//
// usableExecWord excludes bash reserved words (while, for, if, case,
// coproc, ...) from candidate generation: escaping a reserved word defeats
// the shell's *recognition* of it as a keyword at all (POSIX: "a reserved
// word that is quoted... does not fetch that reserved word"), so
// "w\hile true; do ...; done" is a syntax error in real bash, not a working
// bypass — verified empirically (`bash -c 'w\hile true; do echo hi; done'`
// -> "syntax error near unexpected token `do'"). Counting that as a leak
// would be the same probe-validity error assertProbeNotVacuous and the
// tilde exclusion in TestUnsetParamExpParity guard against: the mutation
// changes what the command DOES, so it isn't evidence of anything.
func TestEscapeSpliceParity(t *testing.T) {
	t.Parallel()
	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}

	usable := func(tok string) bool {
		return len(tok) >= 2 && !strings.ContainsAny(tok, "'\"$`\\=(){}<>|&;") && !reservedWords[tok]
	}

	// Per-position budget, not a single shared constant: the residue's
	// COMPOSITION differs by position, not just its size. exec-backslash
	// and exec-locale-quote measure ~1-2% post-fix (41/2275, 30/2275) —
	// mostly genuinely different, unrelated gaps a static transform can't
	// recover. arg2-backslash measures ~5% (100/1905) because it's
	// dominated by one specific, already-tracked, deliberately out-of-scope
	// shape: a backslash escaping a non-alphanumeric, non-shell-special
	// character two words in (--\-force, ~\/.consul/token — issue #3209's
	// exact title). This fix's own gate leaves those untouched on purpose
	// (folding a punctuation escape could corrupt a downstream
	// re-tokenization of the reconstructed candidate; see
	// pathnorm.FoldObfuscatingBackslashes's doc comment) — #3209 tracks
	// closing that separately. Ratchet DOWN as either residue shrinks; never
	// up without recording why here.
	//
	// exec-backslash 60 → 62 (2026-09-15, #3830/#3823, tracked as #3848): the
	// two new BLOCK corpus cases TP-DEFEXFIL-017/-020 are `sleep`-first and
	// leak under `s\leep`. Not a new gap — `s\leep 600; curl X` reaches no
	// sleep-anchored rule at all, the pre-existing ne-audit-sleep-chain
	// included, because DequoteCommand's fold runs only when the parser has
	// failed and a cross-statement regex has no joined candidate to match.
	// Main measured 59/2550 before the branch; the +2 are these two cases.
	//
	// exec-backslash 62 → 55 (2026-09-17, #3848 class A): measured 61 → 54. The
	// builtin recognisers in shellparse (set, shift, read, mapfile, readarray)
	// compared literalWordValue's raw output — backslash included — to the
	// builtin name, so a spliced `r\ead` dropped the stdin binding and all 13
	// TP-READ-* cases fell to AUDIT. They now go through literalExecName. The
	// harness shows 7 closed, not 13: the other 6 are heredoc-bound, and this
	// position's strings.Fields/Join mutation flattens their newlines, so they
	// read as leaks whether or not the engine handles them. Of the remaining 54,
	// 18 are that artifact (12 that already were, plus those 6), 1 is
	// whitespace-sensitive, and 35 leak under an in-place splice too:
	// 35 + 18 + 1 = 54. TestExecNameSpliceBindingParity pins the heredoc
	// spelling with its newlines intact. The 35 are classified on #3848; two of
	// them (TP-DECLBIND-001/-002) are ALSO a builtin-name miss, of a different
	// kind — a spliced `export`/`readonly` parses as a plain call rather than a
	// DeclClause — and are not closed here.
	//
	// 2026-09-18 (#3848, harness only — no engine change): the mutation is
	// now spliced IN PLACE. Each position names the FIELD it mutates and the
	// spelling it wants there, and the harness writes that spelling into the
	// original command at the field's own byte span (spliceField), so
	// separators, heredocs and line continuations survive. Until now the
	// mutation was strings.Fields + strings.Join, which flattened every
	// multi-line command into one line — so those cases read as leaks whether
	// or not the engine handled the splice, and every budget below carried
	// that artifact (the 18 + 1 rows the paragraph above accounts for on
	// exec-backslash; the +2 and +1 the punct-escape-slash comments below
	// record). Measured on this corpus, Fields/Join → in place:
	//   exec-backslash    54 → 35   (the 35 the #3848 classification predicted)
	//   exec-locale-quote 47 → 28
	//   arg2-backslash    39 → 35   (budget was 120, last measured at 100)
	//   punct-escape-flag  5 →  1
	//   punct-escape-slash 14 → 9
	// Denominators unchanged (2559 / 2559 / 2094 / 410 / 1302): a command is
	// tried or skipped on exactly the same test as before. Budgets are set to
	// the measured residue, so a new leak fails here on the day it lands.
	// The alternative — skipping multi-line commands the way continueAtSpace
	// / ifsAtSpace do — was rejected: it would have dropped every
	// heredoc-bound BLOCK from the probe instead of measuring it.
	//
	// exec-backslash 35 → 6, exec-locale-quote 28 → 5 (2026-09-21, #3848 class
	// B + bonus): dequotedCommand re-renders the WHOLE command through
	// mvdan/sh's printer, which turns a top-level ";" into a newline, so
	// "s\leep 120; curl ..." dequoted to "sleep 120\ncurl ..." — no rule
	// pattern written with ";" between two statements (ne-block-deferred-
	// exfil-sleep, ts-block-printf-v-exec, ts-block-nameref-eval-chain, the
	// adb rule) can match a "\n". shellparse.FoldLeadingExecWord folds only
	// the first word's own bytes in place, leaving every separator untouched,
	// and regex.go adds it as its own whole-command candidate. It closed all
	// 11 of the #3848 "class B" cases the issue named, plus 18 more (classes
	// C/D and part of G) that shared the same root cause once traced —
	// NormalizeExecName strips both the backslash AND the $"..." locale-quote
	// form, so exec-locale-quote improved for free. The 6/5 residuals are
	// TWO other, independent mechanisms, both pre-existing and out of scope
	// here: (a) three semantic-stage rules (FSDESTR-005, SYSDIR-001,
	// NSREG-007 — class E) resolve the executable themselves via their own
	// AST walk, never consulting regex.go's candidates; (b) DECLBIND-001/-002
	// and PATHHIJACK-ESCSPLICE-001 (classes F/G) need the *parser* to
	// recognise a spliced "export"/"readonly" as a DeclClause, or a SECOND
	// splice elsewhere in the same statement folded too — both a level below
	// what a whole-command regex candidate can fix. Leak sets confirmed
	// strict subsets of the pre-fix ones (diffed by hand); no new leak
	// appeared on either position.
	//
	// exec-backslash 6 → 3, exec-locale-quote 5 → 4 (2026-09-21, #3848 class
	// E): closed FSDESTR-005/SYSDIR-001/NSREG-007. These three built-in
	// semantic.go rules key off ctx.RawCommand as literal text — a
	// strings.Contains(raw, "find")/"pip config set" prefilter, or (for
	// sem-block-python-rmtree's heredoc form) interpreterHeredocIntroPattern's
	// \bpython3\b regex against raw — rather than through ctx.Parsed's
	// already-folded seg.Executable, so "f\ind /etc -delete" and
	// "p\ython3 - <<'PY'" contained no literal "find"/"python3" substring to
	// match. The analyzer already tries three folded copies of raw (IFS,
	// unset-param, brace-list) for exactly this shape of gap; it was missing
	// the fourth, shellparse.FoldLeadingExecWord (the same transform class B
	// added to regex.go). Leak set confirmed a strict subset (diffed by
	// hand); the exec-locale-quote improvement (one of the same three cases)
	// came for free from the same candidate — NormalizeExecName folds both
	// forms. The 3/4 residuals are DECLBIND-001/-002 and
	// PATHHIJACK-ESCSPLICE-001 (classes F/G) — unrelated to raw-text
	// prefiltering: mvdan/sh only recognizes "export"/"readonly" as a
	// DeclClause on an exact literal spelling, so a spliced "e\xport" parses
	// as a plain CallExpr and the assignment (x=rm) is never extracted for
	// $x substitution. Left open on #3848 — a parser-shape fix, not a
	// raw-text-candidate one.
	positions := []struct {
		name     string
		maxLeaks int
		floor    int
		ossFloor int
		fn       func([]string) (int, string, bool)
	}{
		{"exec-backslash", 3, 1900, 1200, func(f []string) (int, string, bool) {
			if !usable(f[0]) {
				return 0, "", false
			}
			return 0, f[0][:1] + `\` + f[0][1:], true
		}},
		{"exec-locale-quote", 4, 1900, 1200, func(f []string) (int, string, bool) {
			if !usable(f[0]) {
				return 0, "", false
			}
			return 0, `$"` + f[0] + `"`, true
		}},
		{"arg2-backslash", 35, 1500, 1000, func(f []string) (int, string, bool) {
			if len(f) < 2 || !usable(f[1]) {
				return 0, "", false
			}
			return 1, f[1][:1] + `\` + f[1][1:], true
		}},
		// punct-escape-flag / punct-escape-slash (#3209): a backslash escaping
		// a non-alphanumeric, non-shell-special character — the residue
		// `arg2-backslash` deliberately left open above, per its own comment.
		// FoldObfuscatingBackslashes's gate now extends to `- / . : , _ + @`
		// (still excludes anything with syntactic weight), so these measure
		// the closed gap rather than the open one the comment above describes.
		//
		// Measured after the fix: punct-escape-flag 6/382 (1.6%), punct-escape-slash
		// 15/1201 (1.2%). Issue #3322 closed the two architectural gaps behind most
		// of that residue (verified NOT to be punctuation-class-specific — an
		// equivalent ASCII-alphanumeric escape, already folded since #3208, leaked
		// the exact same way):
		//   - internal/guardian's own Analyze never added a DequoteCommand-folded
		//     form to its candidate list (only NormalizeIFS/NormalizeUnsetParamExp/
		//     InlineCodeFragments), so any escape inside a guardian-only heuristic's
		//     match (e.g. guardian-disable_security on "--no-verify") survived
		//     regardless of which character class the fold covers. Fixed by adding
		//     the DequoteCommand form (TestGuardianDequoteSpliceParity).
		//   - shellparse.DequoteCommand's AST walk switched on
		//     CallExpr/DeclClause/Redirect only, never *syntax.TestClause, so a
		//     "[[ -f /dev/shm/x ]] && source ..." condition's own words were never
		//     visited at all — same "AST walker omits a node type" shape as #3045.
		//     Fixed via dequoteTestExpr, recursing BinaryTest/UnaryTest/ParenTest
		//     down to their Word operands (TestDequoteCommand_TestClauseSpliceCollapses).
		// Measured after #3322: punct-escape-flag 4/382 (1.0%), punct-escape-slash
		// 13/1202 (1.1%) — both layers were only ever the SOLE detector for a narrow
		// slice of the corpus (most BLOCK rules are also reachable through
		// regex/structural analyzers that already saw CallExpr/DeclClause/Redirect
		// words correctly), so the remainder is a distinct, smaller residue, not yet
		// root-caused. Ratcheted down with the fix; do not raise without recording why.
		//
		// 2026-08-22 (#3314), punct-escape-slash +2: TP-SSHKEY-WRAPPERFUNC-GUARD/
		// -OVERLAP-GUARD are multi-statement (a function definition, newline, then
		// the call) for the same underlying reason as this file's mutation always
		// costs a multi-statement command here — this position's fields.Join
		// reconstruction has no notion of a statement boundary, so it collapses the
		// newline separator into a single space with no terminator ("} evil"), a
		// real bash syntax error. shellparse.Parse then falls back to treating the
		// whole mutated command as ONE opaque statement, and
		// IntentExcludedForStatements' single-statement branch reverted to
		// classifying that whole blob — which finds "agentshield mcp-eval" anywhere
		// in it and wrongly excused the real `cat "$1"` these two cases exist to
		// guard against.
		//
		// Fixed by #3467: shellparse.SplitTopLevelStatementsChecked now reports
		// whether a split reflects a genuine parse or the single-element
		// parse-failure fallback (the two are byte-for-byte indistinguishable by
		// shape alone), and IntentExcludedForStatements' single-statement branch
		// fails closed — refuses to exclude — when it's the fallback, matching the
		// fail-safe posture the spanning-match case above already has. Ratcheted
		// back down to 13/1218 (1.1%), the #3322 baseline this +2 was layered onto.
		//
		// 2026-09-14 (#3829), punct-escape-slash +1: TP-READ-HEREDOC-SCALAR-EXEC-002
		// is a heredoc (`read -r c <<"EOF"`, a curl line, `EOF`, `$c | bash`), and
		// this position's fields.Join reconstruction collapses its newlines into
		// one line, so the mutant is not a heredoc at all: `EOF` becomes an
		// argument and `$c` is never bound. Measured 13/1295 -> 14/1296 against
		// origin/main 1b1c3ca2 (the one new BLOCK case with a `/` inside a later
		// word). Verified on the built binary: the UNMUTATED flattened form
		// already AUDITs, so the leak is the reconstruction, not the `\/` splice,
		// the same artifact unset_paramexp_parity_test.go records for its heredoc
		// rows. Ratchets back to 13 if this position ever learns to skip
		// multi-line commands the way continueAtSpace / ifsAtSpace do.
		// 2026-09-18: it learned to preserve them instead (in-place splice,
		// see above), and measured 9 — below the 13, because the flattening
		// had been costing more rows than the two comments above attributed to
		// it. Same for punct-escape-flag: 5 → 1.
		{"punct-escape-flag", 1, 280, 170, func(f []string) (int, string, bool) {
			for i := 1; i < len(f); i++ {
				w := f[i]
				if len(w) > 3 && strings.HasPrefix(w, "--") && usable(w) {
					return i, w[:1] + `\` + w[1:], true
				}
			}
			return 0, "", false
		}},
		{"punct-escape-slash", 9, 900, 550, func(f []string) (int, string, bool) {
			for i := 1; i < len(f); i++ {
				w := f[i]
				idx := strings.Index(w, "/")
				if idx < 0 || !usable(w) {
					continue
				}
				return i, w[:idx] + `\/` + w[idx+1:], true
			}
			return 0, "", false
		}},
	}

	engine, baseline := blockingBaseline(t)

	for _, p := range positions {
		t.Run(p.name, func(t *testing.T) {
			var leaks []string
			tried := 0
			for _, tc := range baseline {
				spans := fieldSpans(tc.Command)
				if len(spans) < 2 {
					continue
				}
				fields := make([]string, len(spans))
				for i, s := range spans {
					fields[i] = tc.Command[s[0]:s[1]]
				}
				idx, word, ok := p.fn(fields)
				if !ok {
					continue
				}
				mutated := spliceField(tc.Command, spans, idx, word)
				tried++
				if got := string(engine.Evaluate(mutated, nil).Decision); rank[got] < rank["BLOCK"] {
					leaks = append(leaks, fmt.Sprintf("[%s] %q -> %q = %s", tc.ID, tc.Command, mutated, got))
				}
			}
			floor := p.floor
			if !premiumPacksPresent() {
				floor = p.ossFloor
			}
			assertProbeNotVacuous(t, "escape-splice/"+p.name, tried, floor)

			t.Logf("%s: %d/%d leaked (budget %d)", p.name, len(leaks), tried, p.maxLeaks)
			if len(leaks) > p.maxLeaks {
				for i, l := range leaks {
					if i >= 20 {
						t.Logf("  ... +%d more", len(leaks)-20)
						break
					}
					t.Logf("  %s", l)
				}
				t.Errorf("%s: %d commands lost their BLOCK to an escape-splice mutation (budget %d)",
					p.name, len(leaks), p.maxLeaks)
			}
		})
	}
}

// reservedWords are bash keywords recognized only by their exact unquoted
// spelling — escaping any character within one prevents the shell from
// recognizing it as a keyword at all, so splicing one is not a bypass, it's
// a syntax error. Excluded from probe candidate generation for the same
// reason TestUnsetParamExpParity's splice() refuses a leading '~': a
// probe whose mutation doesn't preserve the command's meaning isn't
// evidence of anything.
var reservedWords = map[string]bool{
	"if": true, "then": true, "elif": true, "else": true, "fi": true,
	"for": true, "in": true, "until": true, "while": true, "do": true,
	"done": true, "case": true, "esac": true, "coproc": true, "select": true,
	"function": true, "time": true,
}

// TestEscapeSpliceFPBoundary is the false-positive counterpart to
// TestEscapeSpliceParity: legitimate developer commands that escape a
// shell-special character (glob, separator, statement terminator, expansion
// marker, the escape character itself) must not be reinterpreted or BLOCKed
// as a result of this fix. Asserted end-to-end through the engine, because
// that's where a regression would actually bite a developer.
func TestEscapeSpliceFPBoundary(t *testing.T) {
	t.Parallel()
	engine := newPipelineEngine(t)

	for _, cmd := range []string{
		`find . -name \*.go`,
		`echo hello\ world`,
		`find . -type f -exec cat {} \;`,
		`grep foo\$bar README.md`,
		`echo a\\b`,
		`git log --pretty=format:\%H`,
		// #3209: punctuation-escape FP boundary. Bash removes each of these
		// backslashes too, so folding them is faithful — but they must still
		// resolve to an ordinary, benign command.
		`grep foo\.bar file.txt`,
		`sed -e 's/a\/b/c/' f.txt`,
		`cat ~\/.config/app.conf`,
	} {
		t.Run(cmd, func(t *testing.T) {
			if got := string(engine.Evaluate(cmd, nil).Decision); got == "BLOCK" {
				t.Errorf("legitimate non-alphanumeric escape usage was BLOCKed:\n  %s", cmd)
			}
		})
	}
}

// fieldSpans returns the byte spans of cmd's whitespace-delimited fields —
// exactly the words strings.Fields would return, but with their positions,
// so a mutation can be applied where the word actually sits instead of into
// a single-space re-join that has lost every newline.
func fieldSpans(cmd string) [][2]int {
	var spans [][2]int
	start := -1
	for i, r := range cmd {
		if unicode.IsSpace(r) {
			if start >= 0 {
				spans = append(spans, [2]int{start, i})
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		spans = append(spans, [2]int{start, len(cmd)})
	}
	return spans
}

// spliceField replaces the idx-th field of cmd (per spans) with word,
// leaving every other byte — including the separators — untouched.
func spliceField(cmd string, spans [][2]int, idx int, word string) string {
	s := spans[idx]
	return cmd[:s[0]] + word + cmd[s[1]:]
}

// TestSpliceField pins the two properties the parity probe relies on: the
// spans agree with strings.Fields, and a splice into a multi-line command
// keeps its newlines (the property the Fields/Join reconstruction lacked).
func TestSpliceField(t *testing.T) {
	t.Parallel()
	for _, cmd := range []string{
		"echo -n hello",
		"  sleep  3;\tcurl -sS https://app.example.com/api/packs ",
		"read zc <<'EOF'\nls -la\nEOF\n$zc",
		"printf -v c 'ls -la' \\\n  && $c",
	} {
		spans := fieldSpans(cmd)
		want := strings.Fields(cmd)
		if len(spans) != len(want) {
			t.Fatalf("%q: %d spans, strings.Fields gives %d", cmd, len(spans), len(want))
		}
		for i, s := range spans {
			if got := cmd[s[0]:s[1]]; got != want[i] {
				t.Fatalf("%q: field %d = %q, want %q", cmd, i, got, want[i])
			}
		}
	}
	heredoc := "read zc <<'EOF'\nls -la\nEOF\n$zc"
	got := spliceField(heredoc, fieldSpans(heredoc), 0, `r\ead`)
	if want := "r\\ead zc <<'EOF'\nls -la\nEOF\n$zc"; got != want {
		t.Fatalf("heredoc splice:\n got %q\nwant %q", got, want)
	}
	two := "  sleep  3; curl x"
	if got, want := spliceField(two, fieldSpans(two), 1, `3\;`), "  sleep  3\\; curl x"; got != want {
		t.Fatalf("arg splice: got %q want %q", got, want)
	}
}
