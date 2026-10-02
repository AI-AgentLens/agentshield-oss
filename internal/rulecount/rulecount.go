// Package rulecount is the ONE definition of "how many rules does Shield
// have". Every surface that states a count — the published premium manifest,
// COVERAGE.md, the duplicate-id ratchet, the pack listing — derives it from
// here, so they cannot disagree with each other.
//
// WHY ONE DEFINITION. On 2026-09-28 the rule count was stated five ways and
// all five disagreed: packs/ held 3,622 entries; cmd/coverage said 3,624
// (it counted blocked_tools as synthetic rules and skipped semantic_rules);
// README said 1,998 MCP rules (stale since 2026-08); the heartbeat sent the
// SaaS a count of YAML *files* (~9); and `pack list` never showed MCP packs at
// all. Each number was locally reasonable; none was checkable against the
// others. A count that cannot be cross-checked is a claim, not a measurement.
//
// THE DEFINITION. A rule entry is one item under any of the five id-bearing
// top-level pack keys — rules, structural_rules, value_limits, resource_rules,
// semantic_rules — in a non-disabled (no "_" prefix) YAML file under one of
// the four pack directories:
//
//	packs/community        shell, community      packs/community/mcp   mcp, community
//	packs/premium          shell, premium        packs/premium/mcp     mcp, premium
//
// Two things are deliberately NOT rules: `blocked_tools` / `blocked_resources`
// entries (bare strings, no id, no taxonomy — they cannot produce an
// attestation), and Go-implemented intercepts (not in packs/ at all). A rule
// in this repo is something with an id that a taxonomy node can be attached
// to; that is what the attestation chain counts, so it is what we count.
//
// UNKNOWN ID-BEARING KEYS ARE A HARD ERROR, NOT A SILENT SKIP. A top-level
// list whose items carry an `id` but whose key is in neither
// IDBearingSections nor NonRuleIDSections makes Count fail, naming the key.
// The alternative — counting any id-bearing list — would quietly widen the
// definition; the other alternative — skipping — would quietly narrow it.
// Refusing forces the decision to be made where it is visible: add the key to
// one list or the other, with a reason. `data_labels` is the worked example:
// policy.DataLabel carries an id, both loaders merge it, and it is not a rule,
// so it is listed in NonRuleIDSections and skipped. This is the same stance
// cmd/check-duplicate-rule-ids took (#3660).
//
// FILE SELECTION MATCHES WHAT SHIELD LOADS, PER DIRECTORY. The four
// directories reach an install by different routes and the routes select
// files differently, so a single filter would count packs that never load:
//
//	packs/community, packs/community/mcp, packs/premium/mcp
//	    embedded via `//go:embed <dir>/*.yaml` — ".yaml" exactly, never ".yml";
//	    the loader core then skips "_"-prefixed stems (disabled).
//	packs/premium (shell)
//	    delivered by the manifest and loaded from disk by policy.LoadPacks —
//	    ".yaml" or ".yml" (case-insensitive), skipping "_"-prefixed files and
//	    flat "mcp-*" files (those are MCP-schema packs the shell loader cannot
//	    parse and deliberately ignores, #2219).
//
// A community pack named *.yml, or a flat premium/mcp-*.yaml, is therefore
// NOT counted here — exactly as it is not loaded. The manifest generator's
// count-vs-delivery refusal is what turns such a file into a loud error
// rather than a silent gap.
package rulecount

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// IDBearingSections are the top-level pack keys whose list items are rules.
var IDBearingSections = []string{"rules", "structural_rules", "value_limits", "resource_rules", "semantic_rules"}

// NonRuleIDSections are top-level pack keys whose list items carry an `id`
// but are NOT rules; they are skipped without error. Value is the reason.
// Both Pack (shell) and MCPPack accept data_labels and merge them, so a pack
// carrying them is legitimate and must count only its rules.
var NonRuleIDSections = map[string]string{
	"data_labels": "customer data-label patterns (policy.DataLabel) — configuration merged by the loaders, not rules",
}

// Surface is which mediation surface a rule belongs to, by directory.
type Surface string

// Tier is the commercial tier a rule ships in, by directory.
type Tier string

const (
	Shell Surface = "shell"
	MCP   Surface = "mcp"

	Community Tier = "community"
	Premium   Tier = "premium"
)

// Entry is one rule definition site. Two definitions of the same id are two
// entries, on purpose: Shield's loaders append without deduping, so each
// definition fires (#3660).
type Entry struct {
	ID       string
	Taxonomy string
	Path     string // as given to Count/Collect, joined with the file name
	Section  string // which of IDBearingSections it sits under
	Surface  Surface
	Tier     Tier
}

// TierCounts is the per-surface breakdown that appears in the manifest.
type TierCounts struct {
	Community int `json:"community"`
	Premium   int `json:"premium"`
	Total     int `json:"total"`
}

// Counts is the published shape. Field names are a cross-repo contract once
// the SaaS reads them; today it ignores the block (encoding/json drops unknown
// keys), so adding it is additive.
type Counts struct {
	Shell     TierCounts `json:"shell"`
	MCP       TierCounts `json:"mcp"`
	Total     int        `json:"total"`
	UniqueIDs int        `json:"unique_ids"`
	// Definition is the sentence a reader needs to reproduce the numbers.
	Definition string `json:"definition"`
}

// Definition is the one-sentence contract the manifest carries.
const Definition = "One rule = one item under a top-level rules, structural_rules, value_limits, resource_rules or semantic_rules key in a non-disabled pack file under packs/{community,premium}{,/mcp}; blocked_tools are not rules; duplicate ids are counted once per definition, unique_ids once per id."

// Report is everything Count knows: the entries, their summary, and the ids
// defined more than once (id -> number of definitions).
type Report struct {
	Entries    []Entry
	Counts     Counts
	Duplicates map[string]int
}

// Count walks the four pack directories under packsRoot and returns the
// report. It refuses (returns an error) on: an unreadable directory, a pack
// that does not parse, an id-bearing section it does not know, or an empty
// corpus — a zero from a walker is a claim about the walker, not the corpus.
func Count(packsRoot string) (*Report, error) {
	dirs := []struct {
		rel     string
		surface Surface
		tier    Tier
	}{
		{"community", Shell, Community},
		{filepath.Join("community", "mcp"), MCP, Community},
		{"premium", Shell, Premium},
		{filepath.Join("premium", "mcp"), MCP, Premium},
	}
	var all []Entry
	for _, d := range dirs {
		entries, err := Collect(filepath.Join(packsRoot, d.rel), d.surface, d.tier)
		if err != nil {
			return nil, err
		}
		all = append(all, entries...)
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("no rule entries found under %s — refusing to report a vacuous zero", packsRoot)
	}
	return Summarize(all), nil
}

// Summarize builds the report from entries (exposed so a caller with its own
// selection of files can reuse the arithmetic).
func Summarize(entries []Entry) *Report {
	r := &Report{Entries: entries, Duplicates: map[string]int{}}
	seen := map[string]int{}
	for _, e := range entries {
		seen[e.ID]++
		tc := &r.Counts.Shell
		if e.Surface == MCP {
			tc = &r.Counts.MCP
		}
		switch e.Tier {
		case Community:
			tc.Community++
		case Premium:
			tc.Premium++
		}
		tc.Total++
	}
	for id, n := range seen {
		if n > 1 {
			r.Duplicates[id] = n
		}
	}
	r.Counts.Total = r.Counts.Shell.Total + r.Counts.MCP.Total
	r.Counts.UniqueIDs = len(seen)
	r.Counts.Definition = Definition
	return r
}

// Collect reads the top-level pack files of ONE directory (not recursive:
// packs/community/mcp is a different surface from packs/community and is
// collected separately), selecting files the way that directory's loader
// does — see the package comment. A missing directory yields no entries and
// no error, so an OSS checkout without packs/premium still counts.
func Collect(dir string, surface Surface, tier Tier) ([]Entry, error) {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	var out []Entry
	for _, de := range dirEntries {
		if de.IsDir() || !Loaded(de.Name(), surface, tier) {
			continue
		}
		path := filepath.Join(dir, de.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		entries, err := Parse(raw, path)
		if err != nil {
			return nil, err
		}
		for i := range entries {
			entries[i].Surface = surface
			entries[i].Tier = tier
		}
		out = append(out, entries...)
	}
	return out, nil
}

// Loaded reports whether a file of this name in the given pack directory is
// one Shield loads — the per-directory selection the package comment
// describes. Exported so a test can pin each rule by name.
func Loaded(name string, surface Surface, tier Tier) bool {
	if strings.HasPrefix(name, "_") {
		return false // disabled, every loader
	}
	if surface == Shell && tier == Premium {
		// Disk route: policy.DiskPackSources + LoadPacks.
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yaml" && ext != ".yml" {
			return false
		}
		return !strings.HasPrefix(strings.ToLower(name), "mcp-")
	}
	// Embedded route: //go:embed <dir>/*.yaml.
	return strings.HasSuffix(name, ".yaml")
}

// Parse extracts the rule entries of one pack document. path is used only in
// errors and in Entry.Path.
func Parse(raw []byte, path string) ([]Entry, error) {
	var doc map[string]yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s does not parse as YAML: %w", path, err)
	}
	known := map[string]bool{}
	for _, k := range IDBearingSections {
		known[k] = true
	}
	// Deterministic order (sorted keys), so an error names the same stray
	// section on every run and entries come out in a stable order.
	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []Entry
	for _, key := range keys {
		node := doc[key]
		if node.Kind != yaml.SequenceNode {
			continue
		}
		var items []struct {
			ID       string `yaml:"id"`
			Taxonomy string `yaml:"taxonomy"`
		}
		if err := node.Decode(&items); err != nil {
			continue // a list of plain strings (blocked_tools) or of something else
		}
		carriesID := false
		for _, it := range items {
			if it.ID != "" {
				carriesID = true
				break
			}
		}
		if !carriesID {
			continue
		}
		if _, nonRule := NonRuleIDSections[key]; nonRule {
			continue // carries ids, is not a rule (data_labels)
		}
		if !known[key] {
			return nil, fmt.Errorf("%s: unknown id-bearing section %q — decide deliberately: add it to rulecount.IDBearingSections if its items are rules, or to rulecount.NonRuleIDSections if they are not", path, key)
		}
		for i, it := range items {
			if it.ID == "" {
				return nil, fmt.Errorf("%s: %s[%d] has no id", path, key, i)
			}
			out = append(out, Entry{ID: it.ID, Taxonomy: it.Taxonomy, Path: path, Section: key})
		}
	}
	return out, nil
}
