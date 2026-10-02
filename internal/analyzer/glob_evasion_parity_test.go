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
	// This test's needle list only covers the credential/system-file shapes
	// #3102 targets (RegexAnalyzer candidate-list injection). The
	// structural + dataflow residual described in #3103 (disk-device
	// destructive writes, chmod targets, dataflow source paths — the same
	// architectural boundary ExpandBraces left for brace expansion) needs
	// its own fitness function once that follow-up lands.
	//
	// #3927 (closed): substitutionReachesExecutor's per-body attribution
	// check (`matchesStatement(body)`) used to test the rule's own pattern
	// against the RAW substitution-body text — the same ctx.RawStatements-
	// blind shape the pre-existing TP-COMPOUND-EVASION-009 leak came from
	// (no visibility into ANY candidate-form transform, glob included). So
	// `echo "$(cat ~/.?sh/id_ed25519)"` deglobbed to a BLOCKing candidate at
	// the whole-command level, but the attribution check that decides
	// whether to withdraw is_doc_text saw only the un-deglobbed body, found
	// no match inside it, and never withdrew — decision stayed AUDIT. Fixed
	// by running shellparse.DeglobSensitivePaths over every statement in
	// StatementMatchCandidates (statement_forms.go) — the same generator
	// statementMatcher and substitutionReachesExecutor both share, so the
	// fix reaches every ctx.RawStatements-blind attribution site at once,
	// not just command-substitution bodies. TP-COMPOUND-EVASION-009's own
	// glob-masked derivative (constructed by this test) closed as a result;
	// see TestGlobEvasion_SubstitutionBodyAttribution for the direct
	// mechanism pin. Ratchet DOWN as gaps are fixed; never up without
	// recording why.
	const maxLeaks = 0

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
