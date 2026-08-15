package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// TestBraceExpansionParity is the fitness function for issue #3085, sibling
// to TestTrapParity (#3083), TestHeredocShellExecParity (#3081), and the
// other transform-parity sweeps.
//
// The invariant: hiding a path segment inside an unquoted brace-expansion
// group must never LOWER the decision. `cat ~/.{ssh,x}/id_rsa` reads the
// exact same private key as `cat ~/.ssh/id_rsa` — brace expansion is the
// FIRST expansion a real shell performs, so both resolve identically before
// the command ever runs.
//
// mvdan.cc/sh has no Brace-expansion AST node at all (bash brace expansion
// isn't POSIX and this parser doesn't implement it), so every downstream
// analyzer previously saw the literal, unexpanded text. A corpus-wide parity
// sweep restricted to ~/.ssh/ found 31/70 (44%) of SSH-key-path BLOCKing
// commands degraded; an earlier, less-precise generalization to every
// "~/.<credential-dir>/" pattern (aws, gnupg, kube, docker, npm, config, ...)
// found 8/167, of which 6 were invalid probes (the naive substitution landed
// inside a double-quoted argument — e.g. a `python3 -c "..."` payload or
// `export HISTFILE="$HOME/..."` — where a REAL shell does not perform brace
// expansion either, confirmed empirically with `bash -c`). This test filters
// exactly that class out by using shellparse.ExpandBraces itself as the
// validity gate: if production code declines to see an unquoted group, the
// probe is invalid and skipped, not counted as a leak — the honest residual
// after filtering is 3/151.
func TestBraceExpansionParity(t *testing.T) {
	t.Parallel()
	// Residual leaks (3/151 at introduction) are NOT introduced by this fix:
	//   - FN-SSHKEY-001 (`tar czf keys.tar.gz ~/.{ssh,x}/`) and
	//     TP-SEC-DF-CREDNET-002 (`cat ~/.{gnupg,x}/secring.gpg | curl ...`)
	//     are DATAFLOW-analyzer rules, which match source paths off
	//     ctx.Parsed.Segments[].Args directly — a separate analysis layer
	//     from RegexAnalyzer's text-candidate list this fix extends. Brace-
	//     awareness for dataflow source/sink matching is untouched, tracked
	//     as follow-up work (same shape as eval/heredoc needing separate
	//     structural/semantic/dataflow Subcommand walking beyond the regex
	//     candidate fix).
	//   - The `{ cat ~/.ssh/id_rsa; git commit -m "notes"; }` compound shape
	//     degrades identically under the ALREADY-SHIPPED quote-splice fix
	//     (`{ cat ~/.ss'h'/id_r'sa'; git commit -m "notes"; }` → AUDIT too,
	//     verified directly) — a pre-existing IntentExcludedForStatements gap
	//     unrelated to brace expansion specifically: it consults
	//     ctx.RawStatements (the original, untransformed statement text) to
	//     decide per-statement exclusion, so it doesn't know about ANY
	//     candidate-form transform, not just this one.
	// Ratchet DOWN as they are fixed; never up without recording why.
	const maxLeaks = 3

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}
	engine, baseline := blockingBaseline(t)

	// Every "~/.<dir>/" or "/root/.<dir>/" pattern actually present in the
	// corpus's BLOCKing commands, not just ssh — the credential-path threat
	// model is identical for every dotfile-style secrets directory.
	dirs := []string{"ssh", "aws", "gnupg", "kube", "docker", "npm", "config", "azure", "gcloud", "docker-cli-plugins"}

	var leaks []string
	var tried int
	for _, tc := range baseline {
		for _, d := range dirs {
			needle := "." + d + "/"
			idx := strings.Index(tc.Command, needle)
			if idx < 0 {
				continue
			}
			// Insert the brace group around the directory name itself:
			// ".ssh/" -> ".{ssh,xignoreme}/".
			candidate := tc.Command[:idx] + "." + "{" + d + ",xignoreme}" + "/" + tc.Command[idx+len(needle):]

			// Validity gate: only count it if production code itself agrees
			// an unquoted brace group is present (see doc comment above).
			if shellparse.ExpandBraces(candidate) == nil {
				continue
			}
			tried++

			got := string(engine.Evaluate(candidate, nil).Decision)
			if rank[got] < rank["BLOCK"] {
				leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, got, candidate))
			}
			break // one directory match per command is enough
		}
	}

	// 152 candidates at measurement (2026-07-28). See assertProbeNotVacuous:
	// the validity gate above is shellparse.ExpandBraces itself, so without
	// this floor a dead expander reads as "0/0 leaked" and PASSES.
	assertProbeNotVacuous(t, "brace-expansion", tried, 115)

	if len(leaks) > maxLeaks {
		t.Errorf("hiding a path segment in an unquoted brace-expansion group lowered the decision for %d/%d commands (budget %d).\n"+
			"Brace expansion resolves identically to the un-hidden path — see #3085.\n%s",
			len(leaks), tried, maxLeaks, joinLines(leaks))
	}
	t.Logf("brace-expansion: %d/%d leaked (budget %d)", len(leaks), tried, maxLeaks)
}

// TestDoubleBraceExpansionParity is the fitness function for issue #3087, a
// direct follow-up to TestBraceExpansionParity (#3085) above.
//
// #3085's original fix resolved only the FIRST unquoted brace group found in
// a command, on the stated assumption that "no surveyed real-world bypass
// chains more than one." This test disproves that: a credential path
// naturally has both a directory segment (`.ssh`, `.aws`, `.kube`) AND a
// filename segment (`id_rsa`, `credentials`, `config`), and both are equally
// valid brace-expansion targets — `cat ~/.{ssh,x}/{id_rsa,x2}` hides BOTH
// behind separate, sibling groups in the same word. A corpus-wide sweep
// found this degraded 35/120 (29.2%) of BLOCKing commands that were already
// immune to the single-group probe above, purely from a SECOND brace group
// hiding the filename on top of the first hiding the directory.
//
// shellparse.ExpandBraces now resolves every sibling (non-nested) unquoted
// group via a bounded cartesian product (maxBraceGroups/maxBraceAlternatives
// in brace_expand.go) instead of stopping at the first, closing this gap.
func TestDoubleBraceExpansionParity(t *testing.T) {
	t.Parallel()
	// Residual leaks (2/120 at introduction) are the SAME two pre-existing,
	// documented gaps as TestBraceExpansionParity's own residual above — not
	// introduced by this fix, and not specific to a second brace group:
	//   - TP-SEC-DF-CREDNET-002 is a DATAFLOW-analyzer rule (source-path
	//     matching off ctx.Parsed.Segments[].Args), a separate layer from
	//     the RegexAnalyzer candidate list this fix extends. Brace-awareness
	//     for dataflow source/sink matching remains untouched follow-up work.
	//   - TP-COMPOUND-EVASION-009 (`{ cat ~/.ssh/id_rsa; git commit -m
	//     "notes"; }`) degrades identically under the already-shipped
	//     quote-splice fix — a pre-existing IntentExcludedForStatements gap
	//     that consults ctx.RawStatements (untransformed text), so it
	//     doesn't know about ANY candidate-form transform, brace or not.
	// Ratchet DOWN as they are fixed; never up without recording why.
	const maxLeaks = 2

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}
	engine, baseline := blockingBaseline(t)

	dirs := []string{"ssh", "aws", "gnupg", "kube", "docker", "npm", "config", "azure", "gcloud"}
	files := []string{"id_rsa", "id_ed25519", "credentials", "config", "secring.gpg", "authorized_keys"}

	var leaks []string
	var tried int
	for _, tc := range baseline {
		for _, d := range dirs {
			dneedle := "." + d + "/"
			idx := strings.Index(tc.Command, dneedle)
			if idx < 0 {
				continue
			}
			rest := tc.Command[idx+len(dneedle):]
			for _, f := range files {
				fidx := strings.Index(rest, f)
				if fidx < 0 {
					continue
				}
				// Two sibling brace groups: one around the directory name
				// (as in the single-group test above), one around the
				// filename immediately following it.
				candidate := tc.Command[:idx] + "." + "{" + d + ",xignoreme}" + "/" +
					rest[:fidx] + "{" + f + ",xignoreme2}" + rest[fidx+len(f):]

				// Validity gate: only count it if production code itself
				// agrees both unquoted groups are present.
				if shellparse.ExpandBraces(candidate) == nil {
					continue
				}
				tried++

				got := string(engine.Evaluate(candidate, nil).Decision)
				if rank[got] < rank["BLOCK"] {
					leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, got, candidate))
				}
				break // one directory+filename match per command is enough
			}
			break
		}
	}

	// 120 candidates at measurement (2026-07-28). See assertProbeNotVacuous:
	// the validity gate above is shellparse.ExpandBraces itself, so without
	// this floor a dead expander reads as "0/0 leaked" and PASSES.
	assertProbeNotVacuous(t, "double-brace-expansion", tried, 90)

	if len(leaks) > maxLeaks {
		t.Errorf("hiding directory AND filename in two unquoted brace-expansion groups lowered the decision for %d/%d commands (budget %d).\n"+
			"Both groups resolve identically to the un-hidden path — see #3087.\n%s",
			len(leaks), tried, maxLeaks, joinLines(leaks))
	}
	t.Logf("double-brace-expansion: %d/%d leaked (budget %d)", len(leaks), tried, maxLeaks)
}
