// Package main implements a ratcheting CI guardrail against duplicate rule IDs
// across every pack Shield loads.
//
// WHY THIS IS NOT A TIDINESS GATE (#3660). Shield's loaders append into one
// slice — mergeMCPPack/LoadPacks do not dedupe on id — and evaluate()
// accumulates matches without deduping either. So an id defined twice produces
// TWO entries for ONE detection. Confirmed live against the deployed binary:
//
//	$ agentshield mcp-eval --tool read_file \
//	    --arg path=/home/user/.config/hcloud/cli.toml --format json
//	"rules":         ["mcp-sec-block-hcloud-credentials", "mcp-sec-block-hcloud-credentials"]
//	"taxonomy_refs": ["credential-exposure/cloud-credentials/cloud-provider-credential-access",
//	                  "credential-exposure/cloud-credentials/cloud-provider-token"]
//
// One tool call, one BLOCK, two different taxonomy nodes. The attestation chain
// (block -> taxonomy node -> compliance control -> evidence record) is the
// product's central claim; a receipt that cites two nodes for one event is a
// falsified receipt, not a cosmetic wart.
//
// WHY IT IS NOT A VERBATIM PORT OF COMPLY#3433. Comply solved the same problem,
// but its collector records each FILE once per id:
//
//	if !contains(out[r.ID], base) { out[r.ID] = append(out[r.ID], base) }
//
// That is correct THERE — measured 2026-09-05, Comply has 0 intra-file
// duplicates across 1029 files — but it makes the gate structurally blind to
// duplicates inside a single file. Shield has two of those today, both in
// packs/community/mcp/mcp-secrets.yaml, ~7000 lines apart, and both disagree on
// taxonomy exactly the way the cross-file pairs do. Ported verbatim this gate
// would catch 5 of 7 and green on the rest: the vacuous-gate shape (#3119,
// #3130, #3137) this repo has been bitten by three times.
//
// So: count OCCURRENCES, not distinct files. File boundaries are irrelevant to
// the invariant the loaders need.
//
// RATCHET SEMANTICS, both directions:
//   - an occurrence set not in the baseline, or larger than baselined -> FAIL
//     (new duplicate, or an existing one that grew)
//   - a baselined entry that no longer reproduces at that count -> FAIL
//     (it was fixed; remove the line, so the list can only shrink)
//
// The second direction is what keeps the baseline honest. A baseline that only
// ever grows is a list of excuses; one that must shrink when reality shrinks is
// a measurement.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/rulecount"
)

// occurrence is one definition site. Two occurrences of the same id in one file
// are two entries, on purpose — see the package comment.
type occurrence struct {
	Path     string
	Taxonomy string
}

func main() {
	packsDir := flag.String("packs", "packs", "Root directory to walk for pack YAML")
	baselinePath := flag.String("baseline", "cmd/check-duplicate-rule-ids/baseline.txt",
		"Baseline file listing grandfathered duplicate ids as `<count> <rule-id>`")
	verbose := flag.Bool("v", false, "Print the full duplicate set, not just the delta")
	flag.Parse()
	os.Exit(run(*packsDir, *baselinePath, *verbose, os.Stdout, os.Stderr))
}

// run is main() with the exit code returned instead of taken, so the ratchet
// can be tested in both directions rather than only asserted about.
// 0 = no delta, 1 = delta, 2 = unusable input.
func run(packsDir, baselinePath string, verbose bool, out, errw io.Writer) int {
	occ, err := collect(packsDir)
	if err != nil {
		_, _ = fmt.Fprintf(errw, "error: %v\n", err)
		return 2
	}
	if len(occ) == 0 {
		_, _ = fmt.Fprintf(errw, "error: no rule ids found under %s — refusing to report a vacuous pass\n", packsDir)
		return 2
	}

	observed := map[string]int{}
	for id, sites := range occ {
		if len(sites) > 1 {
			observed[id] = len(sites)
		}
	}

	baseline, err := loadBaseline(baselinePath)
	if err != nil {
		_, _ = fmt.Fprintf(errw, "error: %v\n", err)
		return 2
	}

	var newDup, grown, fixed []string
	for id, n := range observed {
		b, ok := baseline[id]
		switch {
		case !ok:
			newDup = append(newDup, id)
		case n > b:
			grown = append(grown, id)
		}
	}
	for id, b := range baseline {
		if n, ok := observed[id]; !ok || n < b {
			fixed = append(fixed, id)
		}
	}
	sort.Strings(newDup)
	sort.Strings(grown)
	sort.Strings(fixed)

	_, _ = fmt.Fprintf(out, "scanned %d rule ids under %s — %d duplicated, %d baselined\n",
		len(occ), packsDir, len(observed), len(baseline))

	if verbose && len(observed) > 0 {
		_, _ = fmt.Fprintln(out, "\nduplicate ids (occurrence count, taxonomy agreement, sites):")
		ids := make([]string, 0, len(observed))
		for id := range observed {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			_, _ = fmt.Fprintf(out, "  %-45s %s\n", id, describe(occ[id]))
		}
	}

	ok := true
	if len(newDup) > 0 {
		ok = false
		_, _ = fmt.Fprintln(out, "\nNEW — rule ids defined more than once, not baselined:")
		for _, id := range newDup {
			_, _ = fmt.Fprintf(out, "  %-45s %s\n", id, describe(occ[id]))
		}
		_, _ = fmt.Fprintln(out, "\nShield's loaders do not dedupe on id, so each of these emits its rule id")
		_, _ = fmt.Fprintln(out, "and its taxonomy ref once PER DEFINITION at eval time. Rename one side, or")
		_, _ = fmt.Fprintf(out, "— with maintainer sign-off — record it in %s.\n", baselinePath)
	}
	if len(grown) > 0 {
		ok = false
		_, _ = fmt.Fprintln(out, "\nGROWN — baselined duplicates that gained another definition:")
		for _, id := range grown {
			_, _ = fmt.Fprintf(out, "  %-45s baselined %d, now %d: %s\n", id, baseline[id], observed[id], describe(occ[id]))
		}
	}
	if len(fixed) > 0 {
		ok = false
		_, _ = fmt.Fprintln(out, "\nFIXED — baselined duplicates that no longer reproduce. Remove these lines")
		_, _ = fmt.Fprintf(out, "from %s; the baseline may only shrink:\n", baselinePath)
		for _, id := range fixed {
			_, _ = fmt.Fprintf(out, "  %-45s baselined %d, now %d\n", id, baseline[id], observed[id])
		}
	}
	if !ok {
		return 1
	}
	_, _ = fmt.Fprintln(out, "\nOK — no duplicate-id delta against the baseline.")
	return 0
}

// describe renders the sites and, crucially, whether they agree on taxonomy.
// A duplicate whose definitions carry DIFFERENT taxonomy refs is the case that
// falsifies an attestation; one where they agree is merely redundant.
func describe(sites []occurrence) string {
	paths := make([]string, 0, len(sites))
	taxa := map[string]bool{}
	for _, s := range sites {
		paths = append(paths, s.Path)
		taxa[s.Taxonomy] = true
	}
	sort.Strings(paths)
	scope := "cross-file"
	if uniq(paths) == 1 {
		scope = "INTRA-FILE"
	}
	agree := "taxonomy agrees"
	if len(taxa) > 1 {
		agree = "TAXONOMY DISAGREES"
	}
	return fmt.Sprintf("n=%d %s, %s [%s]", len(sites), scope, agree, strings.Join(paths, " "))
}

func uniq(sorted []string) int {
	n := 0
	for i, s := range sorted {
		if i == 0 || s != sorted[i-1] {
			n++
		}
	}
	return n
}

// collect walks packsDir and returns rule_id -> every definition site,
// repetitions included. The walk itself — which files, which top-level
// sections, and the refusal of an id-bearing section nobody has vetted — is
// internal/rulecount, the one definition every count in this repo derives
// from. Files under packsDir that are not in one of its four pack directories
// are therefore not scanned; that matches what Shield loads.
func collect(packsDir string) (map[string][]occurrence, error) {
	report, err := rulecount.Count(packsDir)
	if err != nil {
		return nil, err
	}
	out := map[string][]occurrence{}
	for _, e := range report.Entries {
		out[e.ID] = append(out[e.ID], occurrence{Path: e.Path, Taxonomy: e.Taxonomy})
	}
	return out, nil
}

// loadBaseline reads `<count> <rule-id>` lines, ignoring blanks and comments.
func loadBaseline(path string) (map[string]int, error) {
	out := map[string]int{}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil // baseline is optional; absent means "expect zero"
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	ln := 0
	for sc.Scan() {
		ln++
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		var n int
		var id string
		if _, err := fmt.Sscanf(line, "%d %s", &n, &id); err != nil || n < 2 || id == "" {
			return nil, fmt.Errorf("%s:%d: expected `<count> <rule-id>` with count >= 2, got %q", path, ln, line)
		}
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf("%s:%d: %s listed twice in the baseline", path, ln, id)
		}
		out[id] = n
	}
	return out, sc.Err()
}
