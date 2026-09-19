package analyzer_test

import (
	"fmt"
	"strings"
	"testing"
)

// TestUnsetParamExpParity is the fitness function for the unset-parameter
// expansion bypass class (shellparse.NormalizeUnsetParamExp), in the same
// shape as TestCompoundWrappingParity (#3045), TestLineContinuationParity
// (#3055), TestExecWrapperParity (#3057) and TestIFSSeparatorParity (#3044).
//
// The invariant: an unset variable expands to nothing, in every POSIX shell.
// So `r${zqx}m -rf /` runs exactly `rm -rf /`, and `${zqx:-rm} -rf /` runs it
// again by the default-value route — while a guard matching pre-expansion
// text sees an executable named "r${zqx}m" and stops matching. Verified
// against real bash and real dash before the fix was written: `e${zqx}cho hi`
// and `${zqx:-echo} hi` both print.
//
// Before the fix this was the largest bypass class measured on this codebase:
// splicing an empty expansion into the executable name downgraded 75.1% of
// BLOCKing corpus commands (1724/2297), past the 68.6% ${IFS} gap (#3044),
// the 52.5% line-continuation gap (#3055) and the 20.8% compound-wrapping
// gap (#3045). Like all of those, nothing failed and nothing was logged until
// it was measured corpus-wide.
//
// Four positions are probed because they exercise different halves of the
// fix. The two exec-position probes ride shellparse.Parse's canonicalization;
// the two argument-position probes mostly ride the per-statement and
// whole-command text candidates in RegexAnalyzer, since the bulk of the packs
// are command_regex rules that never consult the AST. The arg-2 splice in
// particular lands on flags (`rm -${zqx}rf /`), which is what forced the
// adjacency class in shellparse.isAdjacencyByte to include '-'.
// TestUnsetParamExpCarrierComposition pins the composition that the corpus
// sweep found the hard way: a splice inside a SINGLE-QUOTED carrier body.
//
// Single quotes are fully literal to the parser, so `trap 'cat
// /${zqx}etc/shadow' EXIT` contains no ParamExp node at all and the
// whole-command fold is a complete no-op on it. The splice only becomes
// visible once the carrier body is re-read as code — and the per-statement
// candidates that do that are consulted only for position-sensitive
// (anchored) rules, so an UNANCHORED rule matching a substring of the body
// silently never saw the folded text.
//
// Each case below is BLOCKed in its bare form; the assertion is that
// wrapping it in a carrier does not lose that.
func TestUnsetParamExpCarrierComposition(t *testing.T) {
	t.Parallel()
	engine := newPipelineEngine(t)

	cases := []struct{ name, command string }{
		{"trap body", `trap 'cat /${zqx}etc/shadow' EXIT`},
		{"trap body, err signal", `trap 'r${zqx}m -rf /' ERR`},
		{"eval argument", `eval 'cat /${zqx}etc/shadow'`},
		{"bash -c body", `bash -c 'cat /${zqx}etc/shadow'`},
		{"sh -c body, default form", `sh -c '${zqx:-rm} -rf /'`},
		{"exec wrapper", `/usr/bin/env r${zqx}m -rf /`},
		{"wrapper plus default form", `nohup ${zqx:-dd} if=/dev/zero of=/dev/sda`},
		{"leading assignment", `LC_ALL=C r${zqx}m -rf /`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(engine.Evaluate(tc.command, nil).Decision); got != "BLOCK" {
				t.Errorf("carrier composition lost the BLOCK:\n  %s\n  got %s, want BLOCK", tc.command, got)
			}
		})
	}
}

// TestUnsetParamExpLeadingFormBoundary is the false-positive counterpart to
// the exec-lead parity position. `${zqx}rm -rf /` folds because a command
// name prefixed by a vanishing expansion has no benign reading; the identical
// shape in ARGUMENT position is the most common form of ordinary
// parameterization there is, and must survive untouched.
//
// Asserted end-to-end through the engine rather than on the normalizer alone,
// because that is where a regression would actually bite a developer.
func TestUnsetParamExpLeadingFormBoundary(t *testing.T) {
	t.Parallel()
	engine := newPipelineEngine(t)

	for _, cmd := range []string{
		"ls ${PREFIX}bin",
		"cp ${SRC}file.txt /tmp/",
		"docker build -t ${REGISTRY}myapp .",
		"echo hi > ${LOGDIR}out.log",
		"tar -czf ${NAME}archive.tar.gz ./src",
		"go build -o ${OUT}binary ./cmd/app",
	} {
		t.Run(cmd, func(t *testing.T) {
			if got := string(engine.Evaluate(cmd, nil).Decision); got == "BLOCK" {
				t.Errorf("ordinary argument-position parameterization was BLOCKed:\n  %s", cmd)
			}
		})
	}
}

func TestUnsetParamExpParity(t *testing.T) {
	t.Parallel()
	// Measured after the fix: exec-splice 32/2300, exec-default 28/2308,
	// arg2-splice 26/1795, arg2-default 16/1936, exec-lead 23/2308 — every
	// position at or under 1.4%, down from 75.1%/59.2%/53.2%/47.9%/26.2%.
	//
	// Non-zero because the residue is a genuinely different problem from the
	// one this closes. The leftovers are commands whose only matching rule
	// keys on a spelling no static transform can recover, plus splices landing
	// next to a character deliberately outside the adjacency class. '+'
	// joined the class in #3207 (`chmod a${zqx}+rwx`, `chmod +${zqx}s`,
	// `set +${zqx}o history`), dropping arg2-splice 23->16 with zero
	// regressions on TestAccuracy — it is a flag/mode character with no
	// benign reading glued to a word run, unlike '/' which stays a
	// version/path separator excluded everywhere except the LEFT (a leading
	// separator can only start a path component, never end one). '.' joined
	// the LEFT class the same way in #3341 (`cat .${zqx}env`, a leading dot
	// glued to an expansion can only start a dotfile's name, never its
	// extension) — arg2-splice 12/1855 and arg2-default 14/1997 after that
	// fix, again zero regressions on TestAccuracy. '.' stays excluded on the
	// RIGHT (`file${N}.txt` is the common shape there). Ratchet DOWN as those
	// are closed; never up without recording why here.
	//
	// Raised 40 -> 43 by three of the four compound-word-position corpus cases
	// (TP-SHADOW-FORLIST-SPLICE-001, TP-SSHKEY-DECLARRAY-SPLICE-001,
	// TP-SHADOW-SELECT-ANSIC-001). Same residue class the FN-FORKBMB-003 and
	// TP-CRYPTODENY-00[34] rows above already sit in: the exec-splice mutation
	// targets the first word, and splicing a bash KEYWORD (`f${zqx}or`,
	// `s${zqx}elect`, `d${zqx}eclare`) does not produce a working command —
	// bash recognises keywords on the literal token, so the mutant is a syntax
	// error rather than an evasion. Not a bypass, an artifact of the sweep.
	//
	// Raised 43 -> 45 by TP-MACOS-SEC-005/006 (#3697), the same shape as
	// TP-FSDESTR-005 already sitting in this residue: the exec-splice probe
	// reconstructs its mutant with `strings.Join(fields, " ")`, which
	// collapses the heredoc body's real newlines into a single line —
	// "p${zqx}ython3 - <<'PY' import os os.system(...) PY" is not valid
	// heredoc syntax at all, so no real shell would run it this way. The
	// probe's own reconstruction breaks the command, not our detection —
	// see TP-FSDESTR-005's identical leak just above for the same finding.
	//
	// Raised 45 -> 46 by TN-MACOS-SEC-007 (#3755), the exact same artifact.
	// That case (`print("os.system('csrutil disable')")` in a python heredoc)
	// is a benign printed example that the extractor recovers from and the
	// rule BLOCKs — an accepted FP recorded with its real BLOCK decision, so
	// it enters this BLOCK baseline. Its exec-splice mutant collapses the
	// heredoc to one line exactly as above, and was measured AUDIT for that
	// reason (orig BLOCK, mutant AUDIT — verified directly against the built
	// binary). One more measurement artifact, not one more bypass.
	//
	// Raised 46 -> 52 by the six TP-READ-HEREDOC-* cases (#3829), the same
	// artifact a third time: measured exec-splice 46/2579 -> 52/2585 and
	// exec-default 42/2587 -> 48/2593 against origin/main 1b1c3ca2, so the
	// delta is exactly those six BLOCK cases in both positions (the other
	// three positions absorbed them inside their existing headroom). Verified
	// on the built binary: with the heredoc's newlines KEPT, every mutant
	// still BLOCKs (`r${zqx}ead zc <<'EOF'\nrm -rf /\nEOF\n$zc` and
	// `${zqx:-read} …` both fire st-block-rm-recursive-root) — the fold and
	// the #3829 resolver compose. Flattened by this probe's fields.Join they
	// AUDIT, and so does the UNMUTATED flattened control (`read zc <<'EOF' rm
	// -rf / EOF $zc`, no ${zqx} at all), which pins the leak on the
	// reconstruction rather than on either transform.
	const maxLeaks = 52

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}

	// "zqx" is deliberately a name no real environment exports and no corpus
	// command assigns — the whole premise of the transform is a variable that
	// is genuinely unset, which is also exactly what an attacker picks.
	const v = "zqx"

	fallback := func(tok string) string { return "${" + v + ":-" + tok + "}" }

	// splice inserts the empty expansion after the token's first character.
	// It refuses to do so when that character is '~', and the refusal is the
	// interesting part: bash performs TILDE expansion before PARAMETER
	// expansion, so in `~${zqx}/.aws/credentials` the tilde-prefix is the
	// literal text "${zqx}", which is not a login name. The tilde does not
	// expand, the path stays relative, and the read fails — verified in bash.
	//
	// That mutation therefore does not preserve the command's meaning, and a
	// probe that counted it would report a "bypass" for a command that no
	// longer does anything. This is the same family of measurement error that
	// assertProbeNotVacuous guards (a probe whose denominator lies), one level
	// up: here the denominator is real but individual candidates are invalid.
	// It mattered — ~12 of the pre-fix residual leaks were this artifact.
	splice := func(tok string) (string, bool) {
		if tok[0] == '~' {
			return "", false
		}
		return tok[:1] + "${" + v + "}" + tok[1:], true
	}

	// A token carrying its own quoting, expansion or assignment syntax would
	// make the mutation a different command rather than the same one spelled
	// differently, so those are skipped rather than counted.
	usable := func(tok string, minLen int) bool {
		return len(tok) >= minLen && !strings.ContainsAny(tok, "'\"$`\\=(){}<>|&;")
	}

	// Two floors per position, because the denominator is a property of the
	// LOADED RULE SET, not of the transform: the shared BLOCK baseline is
	// ~2456 commands with premium loaded and ~1589 in the OSS-stripped tree
	// (scripts/publish-oss.sh removes packs/premium/), so a floor calibrated
	// on the premium corpus fails the OSS build unconditionally — the same
	// tier-blind-constant defect as the heredoc budget in
	// heredoc_shell_exec_parity_test.go, and it made all four of these
	// subtests permanently red in the OSS Distribution job (#3207).
	//
	// ossFloor is measured, not scaled: exec-splice 1484, exec-default 1492,
	// arg2-splice 1113, exec-lead 1492, arg2-default 1219 on a local
	// `git archive HEAD` copy with packs/premium/ stripped. Each is set ~5%
	// below its measurement, matching the headroom the premium floors carry,
	// so the guard still catches a corpus that shrank by accident.
	positions := []struct {
		name     string
		floor    int
		ossFloor int
		fn       func([]string) (string, bool)
	}{
		{"exec-splice", 1500, 1400, func(f []string) (string, bool) {
			if !usable(f[0], 2) {
				return "", false
			}
			s, ok := splice(f[0])
			if !ok {
				return "", false
			}
			return s + " " + strings.Join(f[1:], " "), true
		}},
		{"exec-default", 1500, 1400, func(f []string) (string, bool) {
			if !usable(f[0], 1) {
				return "", false
			}
			return fallback(f[0]) + " " + strings.Join(f[1:], " "), true
		}},
		{"arg2-splice", 1200, 1050, func(f []string) (string, bool) {
			if !usable(f[1], 2) {
				return "", false
			}
			s, ok := splice(f[1])
			if !ok {
				return "", false
			}
			return f[0] + " " + s + " " + strings.Join(f[2:], " "), true
		}},
		// Token-initial splice on the executable. There is no character
		// before the expansion, so the word-run gate cannot see this shape at
		// all; it is covered by the executable-position rule instead
		// (shellparse.opensExecWord). Measured at 26.2% (605/2308) before
		// that rule existed — the obvious next move for anyone who reads the
		// interior fix.
		{"exec-lead", 1500, 1400, func(f []string) (string, bool) {
			if !usable(f[0], 1) {
				return "", false
			}
			return "${" + v + "}" + f[0] + " " + strings.Join(f[1:], " "), true
		}},
		{"arg2-default", 1200, 1150, func(f []string) (string, bool) {
			if !usable(f[1], 1) {
				return "", false
			}
			return f[0] + " " + fallback(f[1]) + " " + strings.Join(f[2:], " "), true
		}},
	}

	// Engine and BLOCK baseline are shared across every parity sweep in this
	// package (see parity_baseline_test.go); only the per-transform filter is
	// local.
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
			// strings.Fields is a stdlib primitive, not a production transform
			// this package can regress, so the denominator cannot silently
			// collapse the way it can in the glob/brace sweeps — but the floor
			// costs nothing and catches a corpus that shrank by accident.
			floor := p.floor
			if !premiumPacksPresent() {
				floor = p.ossFloor
			}
			assertProbeNotVacuous(t, "unset-paramexp/"+p.name, tried, floor)

			t.Logf("%s: %d/%d leaked (budget %d)", p.name, len(leaks), tried, maxLeaks)
			if len(leaks) > maxLeaks {
				for i, l := range leaks {
					if i >= 20 {
						t.Logf("  ... +%d more", len(leaks)-20)
						break
					}
					t.Logf("  %s", l)
				}
				t.Errorf("%s: %d commands lost their BLOCK to an unset-parameter expansion (budget %d)",
					p.name, len(leaks), maxLeaks)
			}
		})
	}
}
