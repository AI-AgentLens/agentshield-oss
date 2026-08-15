package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Shell-pack discovery, and the floor that makes a failed discovery loud.
//
// The generator no-op'd for 96 days (#3359) because discovery pointed at
// `packs/`, a directory the OSS pack split (5899f2ad) emptied of YAML: every
// terminal pack moved into `packs/community/` and `packs/premium/`. A flat
// os.ReadDir over a directory of directories returns nothing, and the
// generator's own "No new rules to generate." reads as "already up to date".
//
// Fixing the path is the small half. The durable half is that discovering
// nothing must be indistinguishable from a crash, never from success —
// CLAUDE.md, "Gates must be able to fail (#3130)" and "Vacuous probes":
// assert a floor on the DENOMINATOR (packs and rules found), not only on the
// output count. A generator that emits 0 rules from 1,515 inputs is plausible;
// one that emits 0 rules from 0 inputs is broken.

// packSource declares one directory that holds terminal (shell) rule packs,
// together with the discovery floor that directory must clear.
//
// Floors are set at roughly half of the corpus present when they were written
// (community 3 packs / 823 rules, premium 6 packs / 692 rules). They are a
// tripwire for "the scan stopped finding things", not a coverage target: a
// legitimate pack merge should not trip them, while any directory-shape
// regression — a rename, another tier split, a glob that stops matching —
// drops the count to zero or near it and does. Raise them when the corpus
// grows enough that the headroom stops being meaningful.
type packSource struct {
	// Dir is relative to the project root.
	Dir string
	// Required means the directory must exist. `packs/premium/` is stripped
	// from the OSS tree by scripts/publish-oss.sh while cmd/mcp-gen ships in
	// it, so premium is optional — but see discoverFrom: optional means "may
	// be absent", NOT "may be present and empty". A premium directory that
	// exists and yields nothing is the exact regression this guards.
	Required bool
	MinPacks int
	MinRules int
}

// shellPackSources lists where terminal rule packs live today. Keep this in
// step with cmd/check-rule-coverage's -rules default ("packs/community,packs/premium")
// — both answer "where are the terminal packs?" and drifting them apart
// reintroduces #3359 in whichever tool is not updated.
var shellPackSources = []packSource{
	{Dir: filepath.Join("packs", "community"), Required: true, MinPacks: 2, MinRules: 400},
	{Dir: filepath.Join("packs", "premium"), Required: false, MinPacks: 3, MinRules: 300},
}

// sourceCount records what one source contributed, so callers can print the
// denominator rather than only the result.
type sourceCount struct {
	Dir     string
	Present bool
	Packs   int
	Rules   int
	Files   []string // pack file paths, relative to root
}

// DiscoveryResult is the outcome of a shell-pack scan.
type DiscoveryResult struct {
	Packs   []*ShellPack
	Sources []sourceCount
}

// TotalRules returns the number of shell rules discovered across all sources.
func (d *DiscoveryResult) TotalRules() int {
	n := 0
	for _, p := range d.Packs {
		n += len(p.Rules)
	}
	return n
}

// Summary renders the per-source denominator for human output.
func (d *DiscoveryResult) Summary() string {
	var b strings.Builder
	for _, s := range d.Sources {
		if !s.Present {
			fmt.Fprintf(&b, "  %-16s absent (optional — OSS tree)\n", s.Dir)
			continue
		}
		fmt.Fprintf(&b, "  %-16s %d packs, %d rules\n", s.Dir, s.Packs, s.Rules)
	}
	fmt.Fprintf(&b, "  %-16s %d packs, %d rules\n", "TOTAL", len(d.Packs), d.TotalRules())
	return b.String()
}

// DiscoverShellPacks scans every declared source under root and returns an
// error if any source falls below its floor.
//
// The error is the whole point: main() turns it into a non-zero exit, so
// `make mcp-gen` fails loudly instead of printing "No new rules to generate."
// over a broken scan.
func DiscoverShellPacks(root string, sources []packSource) (*DiscoveryResult, error) {
	res := &DiscoveryResult{}

	for _, src := range sources {
		packs, files, present, err := discoverFrom(filepath.Join(root, src.Dir))
		if err != nil {
			return nil, fmt.Errorf("scanning %s: %w", src.Dir, err)
		}

		rules := 0
		for _, p := range packs {
			rules += len(p.Rules)
		}
		res.Sources = append(res.Sources, sourceCount{
			Dir: src.Dir, Present: present, Packs: len(packs), Rules: rules, Files: files,
		})

		if !present {
			if src.Required {
				return nil, fmt.Errorf(
					"shell-pack discovery floor: required directory %s does not exist. "+
						"Terminal packs have moved again — update shellPackSources in "+
						"cmd/mcp-gen/discovery.go (see #3359)", src.Dir)
			}
			continue
		}

		// Present-but-empty is a failure for optional sources too. "Optional"
		// covers a checkout that never shipped the directory, not a directory
		// whose contents the scan can no longer see.
		if len(packs) < src.MinPacks || rules < src.MinRules {
			return nil, fmt.Errorf(
				"shell-pack discovery floor: %s yielded %d packs / %d rules, below the "+
					"floor of %d packs / %d rules. Either the pack layout changed (the "+
					"#3359 shape — fix shellPackSources in cmd/mcp-gen/discovery.go) or "+
					"the corpus genuinely shrank, in which case lower the floor "+
					"deliberately and say why",
				src.Dir, len(packs), rules, src.MinPacks, src.MinRules)
		}

		res.Packs = append(res.Packs, packs...)
	}

	return res, nil
}

// discoverFrom loads the terminal packs directly inside dir.
//
// Deliberately non-recursive. `packs/community/mcp/` and `packs/premium/mcp/`
// sit under these directories and hold MCP rules, which are this generator's
// OUTPUT domain, not its input — walking into them would feed MCP rules back
// in as shell rules. Skipping subdirectories is what the pre-#3359 loader did
// correctly; its mistake was being pointed one level too high.
func discoverFrom(dir string) (packs []*ShellPack, files []string, present bool, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, false, nil
		}
		return nil, nil, false, err
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		// `_`-prefixed files are the repo's disabled-pack convention
		// (CLAUDE.md → Policy Packs). The engine does not load them, so the
		// generator must not classify them either.
		if strings.HasPrefix(e.Name(), "_") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names) // deterministic output across filesystems

	for _, name := range names {
		path := filepath.Join(dir, name)
		pack, loadErr := LoadShellPack(path)
		if loadErr != nil {
			return nil, nil, true, loadErr
		}
		packs = append(packs, pack)
		files = append(files, path)
	}
	return packs, files, true, nil
}
