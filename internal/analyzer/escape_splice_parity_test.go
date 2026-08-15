package analyzer_test

import (
	"fmt"
	"strings"
	"testing"
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
	positions := []struct {
		name     string
		maxLeaks int
		floor    int
		ossFloor int
		fn       func([]string) (string, bool)
	}{
		{"exec-backslash", 60, 1900, 1200, func(f []string) (string, bool) {
			if !usable(f[0]) {
				return "", false
			}
			return f[0][:1] + `\` + f[0][1:] + " " + strings.Join(f[1:], " "), true
		}},
		{"exec-locale-quote", 50, 1900, 1200, func(f []string) (string, bool) {
			if !usable(f[0]) {
				return "", false
			}
			return `$"` + f[0] + `"` + " " + strings.Join(f[1:], " "), true
		}},
		{"arg2-backslash", 120, 1500, 1000, func(f []string) (string, bool) {
			if len(f) < 2 || !usable(f[1]) {
				return "", false
			}
			return f[0] + " " + f[1][:1] + `\` + f[1][1:] + " " + strings.Join(f[2:], " "), true
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
		{"punct-escape-flag", 6, 280, 170, func(f []string) (string, bool) {
			for i := 1; i < len(f); i++ {
				w := f[i]
				if len(w) > 3 && strings.HasPrefix(w, "--") && usable(w) {
					mutated := append(append([]string{}, f[:i]...), w[:1]+`\`+w[1:])
					mutated = append(mutated, f[i+1:]...)
					return strings.Join(mutated, " "), true
				}
			}
			return "", false
		}},
		{"punct-escape-slash", 16, 900, 550, func(f []string) (string, bool) {
			for i := 1; i < len(f); i++ {
				w := f[i]
				idx := strings.Index(w, "/")
				if idx < 0 || !usable(w) {
					continue
				}
				mutated := append(append([]string{}, f[:i]...), w[:idx]+`\/`+w[idx+1:])
				mutated = append(mutated, f[i+1:]...)
				return strings.Join(mutated, " "), true
			}
			return "", false
		}},
	}

	engine, baseline := blockingBaseline(t)

	for _, p := range positions {
		t.Run(p.name, func(t *testing.T) {
			var leaks []string
			tried := 0
			for _, tc := range baseline {
				fields := strings.Fields(tc.Command)
				if len(fields) < 2 {
					continue
				}
				mutated, ok := p.fn(fields)
				if !ok {
					continue
				}
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
