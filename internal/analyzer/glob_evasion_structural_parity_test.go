package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// TestGlobEvasionStructuralParity is the fitness function for issue #3103,
// the direct follow-up to TestGlobEvasionParity (#3102). #3102 extended
// RegexAnalyzer's candidate list only; every check that compares
// ctx.Parsed.Segments[].Args (structural) or a dataflow source/sink
// argument directly — never retrying through that candidate list — was
// still vulnerable: disk-device destructive writes, chmod-on-system-file,
// and credential dataflow/archive source paths, per the issue's own
// measurement (21/223, 9.4%).
//
// Three call sites needed their own shellparse.DeglobPath hook (the
// single-argument counterpart to DeglobSensitivePaths, since each already
// holds an isolated arg string rather than a whole raw command):
//   - normalizeTargetPath (structural.go) — single source of truth for
//     isBlockDevice/isSystemDir/isSystemPath/isRootTarget.
//   - isSensitivePath / isCredentialPath (dataflow.go) — source/sink path
//     classification.
//   - matchArgGlob (structural_rule.go) — the generic args_any/args_none
//     glob matcher used by protected_paths-style rules like
//     sec-block-archive-ssh-dir; a SEPARATE code path from
//     normalizeTargetPath that the initial fix missed until this test
//     caught it (`tar czf keys.tar.gz ~/.?sh/` still leaked).
//
// This test masks the destination-anchored shape of wildcard from the
// issue's own examples: "of=/dev/" (dd's target device, never the "if="
// source — masking the source is a different, broader residual: wrapper/
// nested-shell forms like `bash -c "dd if=/?ev/zero of=..."` never run their
// inline code fragment through DeglobSensitivePaths at all yet, tracked as
// further follow-up if it proves worth closing) and the system/credential
// path segments shellparse.DeglobPath's target list already covers.
func TestGlobEvasionStructuralParity(t *testing.T) {
	t.Parallel()
	// The one residual leak (1/128 at introduction) is the SAME pre-existing
	// TP-COMPOUND-EVASION-009 IntentExcludedForStatements gap documented in
	// TestGlobEvasionParity/TestBraceExpansionParity — unrelated to glob
	// evasion specifically. Ratchet DOWN as further shapes are closed; never
	// up without recording why.
	const maxLeaks = 1

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}
	engine, baseline := blockingBaseline(t)

	// needle -> the byte offset (within needle) to mask with '?'. "of=/dev/"
	// anchors to the DESTINATION argument specifically (dd's target device),
	// never the "if=" source — masking the source is a different, already-
	// tracked residual (nested-shell/wrapper inline-code fragments don't run
	// through DeglobSensitivePaths at all yet), not what normalizeTargetPath's
	// ofPath check inspects.
	type needle struct {
		text string
		mask int
	}
	needles := []needle{
		{"of=/dev/", 4}, // masks "d" in "of=/?ev/..."
		{"/etc/passwd", 1},
		{"/etc/shadow", 1},
		{".gnupg/secring.gpg", 1},
		{".ssh/", 1},
	}

	var leaks []string
	var tried int
	for _, tc := range baseline {
		for _, n := range needles {
			idx := strings.Index(tc.Command, n.text)
			if idx < 0 {
				continue
			}
			candidate := tc.Command[:idx+n.mask] + "?" + tc.Command[idx+n.mask+1:]

			// Validity gate: only count it if production code itself agrees
			// an unquoted, resolvable wildcard is present — the same
			// convention TestGlobEvasionParity uses with
			// shellparse.DeglobSensitivePaths as its own gate. This
			// correctly excludes probes landing inside a quoted argument
			// (e.g. a single-quoted curl -d payload or `touch --
			// '--reference=...'`), where a real shell would never resolve
			// the wildcard either.
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

	// 128 candidates at measurement (2026-07-28). See assertProbeNotVacuous:
	// the validity gate above is shellparse.DeglobSensitivePaths itself, so
	// without this floor a dead deglobber reads as "0/0 leaked" and PASSES.
	assertProbeNotVacuous(t, "glob-evasion (structural/dataflow)", tried, 95)

	if len(leaks) > maxLeaks {
		t.Errorf("hiding one interior byte of a structural/dataflow-matched path segment behind an unquoted '?' lowered the decision for %d/%d commands (budget %d).\n"+
			"normalizeTargetPath/isSensitivePath/isCredentialPath should resolve this via shellparse.DeglobPath — see #3103.\n%s",
			len(leaks), tried, maxLeaks, joinLines(leaks))
	}
	t.Logf("glob-evasion (structural/dataflow): %d/%d leaked (budget %d)", len(leaks), tried, maxLeaks)
}
