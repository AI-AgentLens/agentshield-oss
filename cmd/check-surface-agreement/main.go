// check-surface-agreement verifies that when the SAME detection is implemented
// on both interception surfaces — the shell hook and the MCP proxy — both
// implementations resolve to the SAME taxonomy node.
//
// # Why this is a different question from fit
//
// cmd/check-pack-taxonomy-fit already asks, of every pack rule, "does the node
// this rule points at describe what this rule detects?" That is a property of
// ONE rule against ONE node, and a rule can pass it while still being wrong,
// because two adjacent nodes can both plausibly describe the same detection.
// `.git/hooks/` writes fit `pipeline-config-write` lexically just fine — the
// words "config" and "write" are right there — and they fit
// `git-hook-injection` too. Fit cannot choose between them. Nothing did.
//
// The result, measured 2026-08-16 across 3,452 pack rules: eight detections
// implemented on both surfaces resolved to two DIFFERENT taxonomy nodes, four
// of them in different KINGDOMS. Since aiagentlens#78/#81 the SaaS resolves
// compliance controls THROUGH the taxonomy ref carried on the wire, so those
// eight rendered a different control set, a different severity and a different
// customer-facing narrative depending only on whether the attack arrived
// through the shell hook or the MCP proxy. The attestation chain stayed
// structurally intact and said two different things about one attack, which is
// precisely the failure mode that is worse than a missing mapping: it looks
// authoritative.
//
// A concrete one, because the shape is easy to miss in the abstract:
// `git-hook-injection`'s own explanation opens "Unlike CI/CD pipeline configs,
// git hooks run locally on every developer's machine" — the correct node had
// already written down, in prose, that the node the MCP rule was using is the
// wrong one. No gate reads that sentence. This one does not read it either; it
// just notices the two surfaces disagree, which turns out to be enough.
//
// # What it checks
//
// Rule IDs on both surfaces are conventionally the same phrase behind a
// surface/action prefix and an optional argument/language suffix:
//
//	ts-block-python-pth-write            (shell)
//	mcp-persist-block-python-pth-write   (MCP)
//	                └── stem: python-pth-write
//
// For every stem implemented on BOTH surfaces, the check compares the set of
// taxonomy nodes each surface resolves it to. Disjoint sets are a flag.
// Overlapping sets are not: a stem legitimately spread over several nodes is
// only a divergence if the two surfaces agree on NONE of them.
//
// # Scope, stated honestly
//
// This is a consistency check, not a correctness one. It cannot tell which of
// two disagreeing nodes is right — that is a human judgement, and for three of
// the eight seed flags the honest answer was "these are two taxonomy nodes for
// one threat", which is a deprecation question for the comply repo and not
// something a Shield gate should decide. It also sees only detections that
// exist on both surfaces (32 of 3,391 stems today). A detection implemented on
// one surface only cannot disagree with anything and is invisible here.
//
// Deliberately reads packs/ and nothing else. It needs no taxonomy tree, so it
// runs in the ordinary Test job rather than the cross-repo taxonomy job, and
// adds no coupling to AI_risk_compliance (workspace CLAUDE.md, invariant 3).
//
// Usage:
//
//	go run ./cmd/check-surface-agreement
//	go run ./cmd/check-surface-agreement -write-baseline
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// Rule-ID normalisation
//
// Both lists are deliberately CONSERVATIVE. Over-stripping invents pairs that
// were never the same detection and produces false flags; under-stripping only
// costs coverage, and a missed pair is a divergence this check does not catch
// rather than a wrong claim it makes. When in doubt, do not add a token.
// ---------------------------------------------------------------------------

// surfacePrefix strips the leading surface + optional pack-area + action
// tokens: `mcp-persist-block-`, `ts-block-`, `sc-audit-`, `dl-`, `gd-`.
var surfacePrefix = regexp.MustCompile(`^(?:mcp-[a-z]+-|mcp-|ts-|sc-|dl-|gd-)?(?:block-|audit-|allow-|warn-)?`)

// argSuffix strips trailing tokens that name HOW a rule matched rather than
// WHAT it detects — the MCP packs pair many rules as `-key-arg` variants — plus
// the per-language suffixes used on both sides.
var argSuffix = regexp.MustCompile(`-(?:key-arg|arg|py|ts|js|go|rb|java|php|generated)$`)

func stemOf(ruleID string) string {
	s := surfacePrefix.ReplaceAllString(ruleID, "")
	for {
		n := argSuffix.ReplaceAllString(s, "")
		if n == s {
			return s
		}
		s = n
	}
}

// surfaceOf classifies a pack file. MCP packs live under packs/*/mcp/ or are
// named mcp-*.yaml; everything else evaluates shell commands.
func surfaceOf(path string) string {
	if strings.Contains(filepath.ToSlash(path), "/mcp/") ||
		strings.HasPrefix(filepath.Base(path), "mcp-") {
		return "mcp"
	}
	return "shell"
}

var (
	reRuleID   = regexp.MustCompile(`^\s*-?\s*id:\s*["']?([A-Za-z0-9._-]+)`)
	reTaxonomy = regexp.MustCompile(`^\s*taxonomy:\s*["']?([a-z0-9][a-z0-9/_-]*)`)
)

type impl struct {
	Node, File, Rule string
}

// scanPacks returns stem -> surface -> the implementations found.
//
// The YAML is read line-wise rather than unmarshalled because the pack files
// carry rules under seven different top-level keys (see CLAUDE.md, "Policy
// Packs" — parsing only `rules:` silently drops 386 of them). Tracking the most
// recent `id:` and attaching the next `taxonomy:` to it is key-agnostic and
// matches how check-taxonomy-refs.sh reads the same tree.
func scanPacks(dir string) (map[string]map[string][]impl, int, error) {
	out := map[string]map[string][]impl{}
	total := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if ext := filepath.Ext(path); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()

		surface := surfaceOf(path)
		base := filepath.Base(path)
		cur := ""
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if m := reRuleID.FindStringSubmatch(line); m != nil {
				cur = m[1]
				continue
			}
			if m := reTaxonomy.FindStringSubmatch(line); m != nil && cur != "" {
				stem := stemOf(cur)
				if out[stem] == nil {
					out[stem] = map[string][]impl{}
				}
				out[stem][surface] = append(out[stem][surface], impl{Node: m[1], File: base, Rule: cur})
				total++
			}
		}
		return sc.Err()
	})
	return out, total, err
}

type flag_ struct {
	Stem       string
	ShellNodes []string
	MCPNodes   []string
	ShellEx    impl
	MCPEx      impl
}

func (f flag_) key() string {
	return fmt.Sprintf("%s :: %s :: %s", f.Stem, f.ShellNodes[0], f.MCPNodes[0])
}

func nodesOf(is []impl) []string {
	seen := map[string]bool{}
	var out []string
	for _, i := range is {
		if !seen[i.Node] {
			seen[i.Node] = true
			out = append(out, i.Node)
		}
	}
	sort.Strings(out)
	return out
}

func overlap(a, b []string) bool {
	in := map[string]bool{}
	for _, x := range a {
		in[x] = true
	}
	for _, y := range b {
		if in[y] {
			return true
		}
	}
	return false
}

// analyse returns the divergent stems plus how many stems exist on both
// surfaces at all — the denominator, without which "0 flags" is unreadable.
func analyse(corpus map[string]map[string][]impl) (flags []flag_, bothSurfaces int) {
	for stem, bySurface := range corpus {
		sh, okS := bySurface["shell"]
		mc, okM := bySurface["mcp"]
		if !okS || !okM {
			continue
		}
		bothSurfaces++
		sn, mn := nodesOf(sh), nodesOf(mc)
		if overlap(sn, mn) {
			continue
		}
		flags = append(flags, flag_{Stem: stem, ShellNodes: sn, MCPNodes: mn, ShellEx: sh[0], MCPEx: mc[0]})
	}
	sort.Slice(flags, func(i, j int) bool { return flags[i].Stem < flags[j].Stem })
	return flags, bothSurfaces
}

func loadBaseline(path string) (map[string]bool, error) {
	out := map[string]bool{}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			out[line] = true
		}
	}
	return out, sc.Err()
}

func main() {
	packsDir := flag.String("packs", "packs", "Directory containing policy pack YAML")
	baselinePath := flag.String("baseline", "cmd/check-surface-agreement/baseline.txt", "Baseline of known, tracked divergences")
	writeBaseline := flag.Bool("write-baseline", false, "Rewrite the baseline from the current corpus")
	verbose := flag.Bool("v", false, "Print a summary even when clean")
	flag.Parse()

	corpus, totalRefs, err := scanPacks(*packsDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan packs:", err)
		os.Exit(2)
	}

	// Collecting nothing means packs/ moved or the YAML keys were renamed —
	// never that the corpus is clean. A gate that cannot fail loudly is worse
	// than no gate (#3130), and a vacuous pass is how this repo has been
	// burned before: assert a floor on the denominator, not only on the
	// failure count.
	if totalRefs == 0 {
		fmt.Fprintf(os.Stderr, "FAIL: found no 'taxonomy:' refs under %s at all.\n", *packsDir)
		fmt.Fprintln(os.Stderr, "      Expected thousands. Either this ran outside the repo root,")
		fmt.Fprintln(os.Stderr, "      packs/ has moved, or the YAML key was renamed.")
		os.Exit(2)
	}

	flags, bothSurfaces := analyse(corpus)

	if *writeBaseline {
		var sb strings.Builder
		sb.WriteString(baselineHeader)
		for _, f := range flags {
			fmt.Fprintf(&sb, "%s\n", f.key())
		}
		if err := os.WriteFile(*baselinePath, []byte(sb.String()), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write baseline:", err)
			os.Exit(2)
		}
		fmt.Printf("wrote %d divergence(s) to %s\n", len(flags), *baselinePath)
		return
	}

	baseline, err := loadBaseline(*baselinePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read baseline:", err)
		os.Exit(2)
	}

	var fresh []flag_
	seen := map[string]bool{}
	for _, f := range flags {
		seen[f.key()] = true
		if !baseline[f.key()] {
			fresh = append(fresh, f)
		}
	}
	var stale []string
	for k := range baseline {
		if !seen[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)

	for _, f := range fresh {
		fmt.Printf("DIVERGENT  %s\n", f.Stem)
		fmt.Printf("    shell -> %s\n", strings.Join(f.ShellNodes, ", "))
		fmt.Printf("             %s  [%s]\n", f.ShellEx.Rule, f.ShellEx.File)
		fmt.Printf("    mcp   -> %s\n", strings.Join(f.MCPNodes, ", "))
		fmt.Printf("             %s  [%s]\n", f.MCPEx.Rule, f.MCPEx.File)
		fmt.Println()
	}
	for _, k := range stale {
		fmt.Printf("STALE      %s\n", k)
		fmt.Println("    The surfaces now agree (or a rule was renamed). Delete this baseline line.")
		fmt.Println()
	}

	if len(fresh) > 0 || len(stale) > 0 {
		fmt.Fprintf(os.Stderr,
			"FAIL: %d new divergence(s), %d stale baseline entr(y/ies). "+
				"%d stem(s) implemented on both surfaces, %d taxonomy ref(s) scanned.\n",
			len(fresh), len(stale), bothSurfaces, totalRefs)
		fmt.Fprintln(os.Stderr,
			"      A detection must resolve to ONE taxonomy node regardless of whether it")
		fmt.Fprintln(os.Stderr,
			"      arrived through the shell hook or the MCP proxy — the node is what the")
		fmt.Fprintln(os.Stderr,
			"      SaaS resolves compliance controls through (aiagentlens#78/#81).")
		os.Exit(1)
	}

	if *verbose || len(baseline) > 0 {
		fmt.Printf("OK: %d taxonomy ref(s), %d stem(s) on both surfaces, %d baselined divergence(s), 0 new, 0 stale\n",
			totalRefs, bothSurfaces, len(baseline))
	} else {
		fmt.Printf("OK: %d taxonomy ref(s), %d stem(s) on both surfaces, all agree\n", totalRefs, bothSurfaces)
	}
}

const baselineHeader = `# baseline.txt — detections implemented on BOTH interception surfaces whose
# two implementations resolve to DIFFERENT taxonomy nodes.
#
# Read by cmd/check-surface-agreement. See that package's doc comment for what
# the check measures and why fit cannot answer it. A line here is a known,
# evidenced divergence; any stem NOT listed is new and fails CI.
#
# Format: <rule stem> :: <shell node> :: <mcp node>. Comments after '#'.
#
# BURN IT DOWN. Two ways to clear a line:
#   1. Point one surface at the node the other already uses (when one is
#      plainly right — usually because a node exists named for the mechanism).
#   2. Resolve the two nodes upstream in AI_risk_compliance, when the real
#      defect is that the taxonomy carries two nodes for one threat. That is a
#      deprecation decision and needs Gary + Kai; this gate must not make it.
# Adding a NEW line requires Gary + Kai sign-off and a note saying why neither
# fix could ship with the change that introduced it. Removing a line is
# MANDATORY once the surfaces agree — the checker reports STALE and fails.
#
# Bootstrap:  go run ./cmd/check-surface-agreement -write-baseline
# NOTE: -write-baseline DISCARDS the hand-written verdicts below. It is a
# bootstrap tool, not a maintenance one — to clear an entry, delete its line.
#
`
