package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// TestGlobEvasionParity is the fitness function for issue #3102, sibling to
// TestBraceExpansionParity (#3085) and TestDoubleBraceExpansionParity
// (#3087) — the same shell-expansion-phase gap, one phase later: brace
// expansion happens FIRST, pathname expansion (globbing) happens LAST (bash
// manual, EXPANSION section). mvdan.cc/sh does not model globbing any more
// than it models brace expansion, so `cat /?tc/shadow` parses as a literal,
// unmatched argument even though a real shell resolves that `?` against the
// filesystem and reads /etc/shadow verbatim.
//
// The invariant: hiding one interior byte of a well-known sensitive path
// segment behind an unquoted '?' must never LOWER the decision.
func TestGlobEvasionParity(t *testing.T) {
	t.Parallel()
	// The one residual leak (1/183 at introduction) is a pre-existing,
	// documented gap unrelated to glob evasion specifically —
	// TP-COMPOUND-EVASION-009 (`{ cat ~/.ssh/id_rsa; git commit -m "notes";
	// }`) degrades identically under the already-shipped brace/quote-splice
	// fixes (`{ cat ~/.ss'h'/id_r'sa'; git commit -m "notes"; }` → AUDIT
	// too, per TestBraceExpansionParity) — a pre-existing
	// IntentExcludedForStatements gap that consults ctx.RawStatements (the
	// original, untransformed statement text), so it doesn't know about ANY
	// candidate-form transform, glob or not.
	//
	// This test's needle list only covers the credential/system-file shapes
	// #3102 targets (RegexAnalyzer candidate-list injection). The
	// structural + dataflow residual described in #3103 (disk-device
	// destructive writes, chmod targets, dataflow source paths — the same
	// architectural boundary ExpandBraces left for brace expansion) needs
	// its own fitness function once that follow-up lands.
	// Ratchet DOWN as gaps are fixed; never up without recording why.
	const maxLeaks = 1

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}
	engine, baseline := blockingBaseline(t)

	// Well-known sensitive path segments — the same shape
	// shellparse.DeglobSensitivePaths resolves, duplicated here as the
	// test's independent search needles (same convention
	// TestBraceExpansionParity uses for its own `dirs` list).
	needles := []string{
		"/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/gshadow",
		".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa", ".ssh/id_dsa",
		".ssh/authorized_keys", ".ssh/known_hosts", ".ssh/config",
		".aws/credentials", ".aws/config",
		".gnupg/secring.gpg", ".gnupg/private-keys-v1.d",
		".kube/config", ".docker/config.json",
		".npmrc", ".netrc", ".pgpass", ".git-credentials",
	}

	var leaks []string
	var tried int
	for _, tc := range baseline {
		for _, needle := range needles {
			idx := strings.Index(tc.Command, needle)
			if idx < 0 {
				continue
			}
			// Mask one interior byte (never the needle's first or last
			// character, and never a '/') with '?' — the exact shape
			// shellparse.DeglobSensitivePaths resolves.
			maskPos := len(needle) / 2
			if maskPos < 1 {
				maskPos = 1
			}
			if maskPos > len(needle)-2 {
				maskPos = len(needle) - 2
			}
			if maskPos < 1 || maskPos > len(needle)-2 || needle[maskPos] == '/' {
				continue
			}
			candidate := tc.Command[:idx+maskPos] + "?" + tc.Command[idx+maskPos+1:]

			// Validity gate: only count it if production code itself agrees
			// an unquoted, resolvable wildcard is present (see doc comment
			// above; same convention TestBraceExpansionParity uses with
			// shellparse.ExpandBraces as its own gate).
			if shellparse.DeglobSensitivePaths(candidate) == nil {
				continue
			}
			tried++

			got := string(engine.Evaluate(candidate, nil).Decision)
			if rank[got] < rank["BLOCK"] {
				leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, got, candidate))
			}
			break // one needle match per command is enough
		}
	}

	// 183 candidates at measurement (2026-07-28). See assertProbeNotVacuous:
	// the validity gate above is shellparse.DeglobSensitivePaths itself, so
	// without this floor a dead deglobber reads as "0/0 leaked" and PASSES.
	assertProbeNotVacuous(t, "glob-evasion", tried, 140)

	if len(leaks) > maxLeaks {
		t.Errorf("hiding one interior byte of a sensitive path segment behind an unquoted '?' lowered the decision for %d/%d commands (budget %d).\n"+
			"Pathname expansion resolves identically to the un-hidden path — see #3102.\n%s",
			len(leaks), tried, maxLeaks, joinLines(leaks))
	}
	t.Logf("glob-evasion: %d/%d leaked (budget %d)", len(leaks), tried, maxLeaks)
}
