package analyzer_test

import (
	"fmt"
	"strings"
	"testing"
)

// TestCarrierPayloadParity is the fitness function for issue #3241: a carrier's
// payload was reconstructed by stripping one outer quote pair rather than by
// performing quote removal, so a payload whose WORD BOUNDARIES were hidden
// inside the word survived reconstruction verbatim and re-parsed as a single
// word — an executable literally named "rm -rf /".
//
// This is the residual of #3050, which fixed the whole-word-quoted spelling
// (`bash -c 'rm -rf /'`) and left the per-word-quoted ones untouched.
//
// Measured before the fix: 75.4% on a sampled baseline against a 1.0% control —
// the largest single leak recorded in this repo, past the 68.6% ${IFS} gap
// (#3044) and the 75.1% unset-parameter splice (#3206). All EIGHT carrier
// surfaces leaked at once (bash -c, sh -c, eval, trap, su -c, watch, man -P,
// flock -c) because all eight reconstruct through the one primitive — the
// uniformity signature of one shared defect, not eight gaps (#3227/#3232).
//
// TWO positions, sized by MECHANISM rather than by carrier (#3232's sizing
// rule). Which carrier delivers the payload is irrelevant to this defect —
// they share the primitive, and TestPayloadValueThroughCarriers in
// internal/shellparse proves the wiring for all eight at one evaluation each.
// What differs, and therefore what is swept, is how the word boundary is
// hidden: by escaping it, or by quoting around it.
//
// Candidate generation is restricted to commands built only from plain words
// and spaces. Escaping the spaces of a command that already contains a shell
// operator would leave that operator live at the OUTER level, so the mutation
// would no longer be the meaning-preserving rewrite the measurement claims —
// the probe-validity error that the reserved-word exclusion in
// TestEscapeSpliceParity and the tilde exclusion in TestUnsetParamExpParity
// both guard against.
func TestCarrierPayloadParity(t *testing.T) {
	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}

	// A command safe to rewrite by hiding its word boundaries: no quoting, no
	// expansion, no operator, no glob — nothing whose meaning depends on the
	// word boundary staying visible to the OUTER shell.
	plainWords := func(cmd string) bool {
		return !strings.ContainsAny(cmd, "'\"$`\\;|&<>()*?{}[]~!#\n")
	}

	// Post-fix, measured 2026-08-06: escaped-space 8/1062 (0.75%), quote-splice
	// 4/1062 (0.38%) — at the level of the `sudo`/`bash -c '…'` controls, which
	// leak ~1% on this corpus for reasons unrelated to any carrier.
	//
	// A separate, larger residue exists and is deliberately NOT measured here:
	// a payload that is several STATEMENTS rather than one word
	// (`eval P1=~/.ssh;\ cat\ $P1/id_rsa`). parseLoneWord rejects those by
	// design — they are already shell source in their own right, so resolving
	// them would be flattening rather than quote removal. Excluding them from
	// the sweep is what `plainWords` does; folding them in would report this
	// fix as ~10% effective when it is ~99% effective at the mechanism it
	// models. If that shape gets modelled, give it its own position.
	//
	// Budgets sit ~3x the measurement so ordinary corpus churn does not turn
	// this red, while a genuine regression (which would restore hundreds of
	// leaks, not a handful) still fails loudly. Ratchet DOWN as the residue
	// shrinks; never up without recording why here.
	positions := []struct {
		name     string
		maxLeaks int
		floor    int
		ossFloor int
		fn       func(string) string
	}{
		// Escaped spaces: the whole payload becomes ONE Lit whose escapes the
		// old reconstruction never removed.
		{"escaped-space-splice", 25, 900, 600, func(cmd string) string {
			return "bash -c " + strings.ReplaceAll(cmd, " ", `\ `)
		}},
		// Quoted spaces: the payload becomes Lit + SglQuoted + Lit + ..., where
		// the old reconstruction's first-char/last-char test either found no
		// quote pair at all or stripped quotes belonging to two different spans.
		{"interior-quote-splice", 20, 900, 600, func(cmd string) string {
			return "eval " + strings.ReplaceAll(cmd, " ", `' '`)
		}},
	}

	engine, baseline := blockingBaseline(t)

	for _, p := range positions {
		t.Run(p.name, func(t *testing.T) {
			var leaks []string
			tried := 0
			for _, tc := range baseline {
				if !plainWords(tc.Command) || len(strings.Fields(tc.Command)) < 2 {
					continue
				}
				mutated := p.fn(tc.Command)
				tried++
				if got := string(engine.Evaluate(mutated, nil).Decision); rank[got] < rank["BLOCK"] {
					leaks = append(leaks, fmt.Sprintf("[%s] %q -> %q = %s", tc.ID, tc.Command, mutated, got))
				}
			}
			floor := p.floor
			if !premiumPacksPresent() {
				floor = p.ossFloor
			}
			assertProbeNotVacuous(t, "carrier-payload/"+p.name, tried, floor)

			t.Logf("%s: %d/%d leaked (budget %d)", p.name, len(leaks), tried, p.maxLeaks)
			if len(leaks) > p.maxLeaks {
				for i, l := range leaks {
					if i >= 20 {
						t.Logf("  ... +%d more", len(leaks)-20)
						break
					}
					t.Logf("  %s", l)
				}
				t.Errorf("%s: %d commands lost their BLOCK to a hidden-word-boundary payload (budget %d)",
					p.name, len(leaks), p.maxLeaks)
			}
		})
	}
}

// TestCarrierPayloadFPBoundary is the false-positive counterpart. Two distinct
// regressions are possible here and both bite developers, not attackers:
//
//   - The resolver over-reaching. `bash -c 'echo "hi"'` must still reconstruct
//     to `echo "hi"` — the inner quotes are the INNER shell's to remove, not
//     ours, and flattening them would change what the payload parses as.
//   - The regex promotion widening what unanchored rules match. That promotion
//     is gated on the reconstructed fragment not being a substring of the text
//     it came from; for every ordinary payload it IS a substring and nothing is
//     added at all. These commands exercise that gate from the benign side.
func TestCarrierPayloadFPBoundary(t *testing.T) {
	engine := newPipelineEngine(t)

	for _, cmd := range []string{
		// Ordinary carrier usage with a visible word boundary.
		`bash -c 'echo "build complete"'`,
		`bash -c 'npm run test -- --coverage'`,
		`sh -c 'cd /srv/app && git pull --ff-only'`,
		`eval "$(direnv hook bash)"`,
		`eval "$(ssh-agent -s)"`,
		// A payload that legitimately escapes a space — a real filename.
		`bash -c 'ls "/Users/dev/My Documents"'`,
		`bash -c ls\ /tmp`,
		// find's escaped terminator, the commonest escaped punctuation there is.
		`find . -type f -exec grep -l TODO {} \;`,
		// trap doing what trap is for.
		`trap 'rm -f "$tmpdir"/*.lock' EXIT`,
		// watch/flock/man with benign payloads — the same carriers the sweep
		// exercises, on the FP side.
		`watch -n5 'kubectl get pods'`,
		`flock /tmp/deploy.lock -c 'make deploy'`,
		`man -P cat git-rebase`,
	} {
		t.Run(cmd, func(t *testing.T) {
			if got := string(engine.Evaluate(cmd, nil).Decision); got == "BLOCK" {
				t.Errorf("legitimate carrier usage was BLOCKed:\n  %s", cmd)
			}
		})
	}
}
