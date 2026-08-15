package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AI-AgentLens/agentshield/packs"
	"gopkg.in/yaml.v3"
)

// Pack extends Policy with metadata for policy packs.
// We avoid yaml:",inline" because Policy also has a `version` field.
type Pack struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	PackVersion string      `yaml:"version"`
	Author      string      `yaml:"author"`
	Defaults    Defaults    `yaml:"defaults"`
	Network     Network     `yaml:"network"`
	Rules       []Rule      `yaml:"rules"`
	DataLabels  []DataLabel `yaml:"data_labels,omitempty"`
}

// PackInfo is a summary of a pack for listing.
type PackInfo struct {
	Name        string
	Description string
	Version     string
	Author      string
	Enabled     bool
	Path        string
	RuleCount   int

	// LoadError is set when the pack file was present on disk (or embedded) but
	// failed to parse. When non-nil, RuleCount is 0 and NONE of this pack's
	// rules were loaded into the policy — enforcement for that pack is silently
	// absent unless callers surface this field. Loading continues for the other
	// packs (partial enforcement beats none), but the failure is no longer
	// swallowed: it is recorded here so the hook, scan diagnostic, and pack
	// listing can warn loudly. See issue #2188 — a single quoted-string typo in
	// premium/supply-chain.yaml dropped 153 rules with zero signal.
	LoadError error
}

// FailedPacks returns the subset of infos whose pack failed to parse
// (LoadError != nil). It is the testable seam used by the hook, scan, and
// pack-list surfaces to decide whether to warn (or, in managed fail-closed
// mode, block). Returns an empty slice when every pack loaded cleanly.
func FailedPacks(infos []PackInfo) []PackInfo {
	var failed []PackInfo
	for _, info := range infos {
		if info.LoadError != nil {
			failed = append(failed, info)
		}
	}
	return failed
}

// LoadPacks reads all .yaml files from the packs directory and merges them
// into the base policy. Rules from packs are appended after the base rules.
// Protected paths and allow domains are unioned. The most restrictive
// default decision wins.
func LoadPacks(packsDir string, base *Policy) (*Policy, []PackInfo, error) {
	var infos []PackInfo

	entries, err := os.ReadDir(packsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return base, nil, nil
		}
		return nil, nil, err
	}

	result := clonePolicy(base)

	diskHooks := PackLoadHooks[Pack]{
		Parse:    parseShellPack,
		Describe: describeShellPack,
		Merge:    func(p *Pack) { mergePackInto(result, p) },
	}

	for _, entry := range entries {
		// Support subdirectory-based loading (packs/regex/, packs/structural/, etc.)
		// Each subdirectory's YAML files are loaded as packs of that analyzer type.
		if entry.IsDir() {
			dirName := entry.Name()
			// `mcp` is never a terminal analyzer-type subdir. MCP-protocol packs
			// use a schema this loader can't parse (tool/args test cases unmarshal
			// as map-into-string) and are loaded separately by mcp.LoadMCPPacks
			// from ~/.agentshield/mcp-packs (and the legacy packs/mcp fallback).
			// Skipping it here is defense-in-depth: a stray ~/.agentshield/packs/mcp
			// — e.g. left by a pre-#2219 `make deploy` — must not surface a spurious
			// parse failure that reads as degraded terminal enforcement (#2219).
			if strings.EqualFold(dirName, "mcp") {
				continue
			}
			enabled := !strings.HasPrefix(dirName, "_")
			subDir := filepath.Join(packsDir, dirName)
			subInfos, err := loadPacksFromDir(subDir, dirName, enabled, result)
			if err != nil {
				continue
			}
			infos = append(infos, subInfos...)
			continue
		}

		if !IsYAMLFile(entry.Name()) {
			continue
		}

		// Skip MCP-protocol packs that landed flat in packs/ — e.g. an older
		// `agentshield update` wrote mcp-*.yaml here before #2219 routed them to
		// mcp-packs/. They use a schema this loader can't parse and are enforced
		// separately by mcp.LoadMCPPacks from ~/.agentshield/mcp-packs/. Skipping
		// avoids a spurious "0 rules loaded (enforcement degraded)" failure; it
		// does not drop terminal rules — no terminal pack is named mcp-*.
		if strings.HasPrefix(strings.ToLower(entry.Name()), "mcp-") {
			continue
		}

		// Process each flat file through the shared core immediately (rather
		// than batching) so infos and merge order stay interleaved with the
		// subdirectory packs exactly as os.ReadDir returns them.
		path := filepath.Join(packsDir, entry.Name())
		src := PackSource{
			Stem:  strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name())),
			Path:  path,
			Label: path,
			Read:  func() ([]byte, error) { return os.ReadFile(path) },
		}
		infos = append(infos, LoadPackSources([]PackSource{src}, diskHooks)...)
	}

	return result, infos, nil
}

// loadPacksFromDir loads all YAML files from an analyzer-type subdirectory
// (e.g., packs/regex/, packs/structural/) and merges them into the target policy.
func loadPacksFromDir(dir, analyzerType string, enabled bool, target *Policy) ([]PackInfo, error) {
	sources, err := DiskPackSources(dir, nil)
	if err != nil {
		return nil, err
	}
	return LoadPackSources(sources, PackLoadHooks[Pack]{
		Parse:      parseShellPack,
		Describe:   describeShellPack,
		NameFor:    func(stem string) string { return analyzerType + "/" + stem },
		EnabledFor: func(stem string) bool { return enabled && !strings.HasPrefix(stem, "_") },
		Merge:      func(p *Pack) { mergePackInto(target, p) },
	}), nil
}

// LoadEmbeddedShellPacks merges the community shell packs embedded in the
// binary (via packs.ShellFiles()) into base, and returns the new policy plus
// per-pack metadata.
//
// Unlike LoadPacks, this does not touch the filesystem — it's safe to call
// before ~/.agentshield/packs/ exists, and it guarantees the engine always
// has community shell rules available (no dependency on the brew cask
// postflight or goreleaser archive contents).
//
// Callers typically invoke LoadEmbeddedShellPacks first, then LoadPacks on
// top so that disk-installed packs (premium, user custom) layer over the
// embedded baseline. Duplicate rules across layers are harmless because the
// combiner uses most-restrictive-wins.
func LoadEmbeddedShellPacks(base *Policy) (*Policy, []PackInfo, error) {
	embedded := packs.ShellFiles()
	if len(embedded) == 0 {
		return base, nil, nil
	}

	result := clonePolicy(base)

	// Note: disabled packs (underscore prefix) would not normally appear in
	// the embed.FS — the //go:embed directive globs real files on disk at
	// build time. The core's default underscore check is kept for symmetry
	// with LoadPacks. Embedded packs are also guarded at build time by
	// TestEmbeddedPacks_RuleCountFloor, but recording LoadError keeps the
	// runtime path honest if a malformed pack ever ships (#2188).
	infos := LoadPackSources(EmbeddedPackSources(embedded), PackLoadHooks[Pack]{
		Parse: func(data []byte, label string) (*Pack, error) {
			var pack Pack
			if err := yaml.Unmarshal(data, &pack); err != nil {
				return nil, fmt.Errorf("failed to parse embedded pack %s: %w", label, err)
			}
			return &pack, nil
		},
		Describe: describeShellPack,
		Merge:    func(p *Pack) { mergePackInto(result, p) },
	})

	return result, infos, nil
}

// parseShellPack unmarshals one shell pack from disk, wrapping errors with
// the source path so the recorded LoadError is actionable (#2188).
func parseShellPack(data []byte, label string) (*Pack, error) {
	var pack Pack
	if err := yaml.Unmarshal(data, &pack); err != nil {
		return nil, fmt.Errorf("failed to parse pack %s: %w", label, err)
	}
	return &pack, nil
}

// describeShellPack returns a shell pack's listing metadata (the shared
// loader core fills in Enabled/Path and the name fallback).
func describeShellPack(p *Pack) PackInfo {
	return PackInfo{
		Name:        p.Name,
		Description: p.Description,
		Version:     p.PackVersion,
		Author:      p.Author,
		RuleCount:   len(p.Rules),
	}
}

// mergePackInto merges a pack's rules, protected paths, and domains into the target policy.
func mergePackInto(target *Policy, pack *Pack) {
	// Append rules (pack rules run after base rules)
	target.Rules = append(target.Rules, pack.Rules...)

	// Append data labels
	target.DataLabels = append(target.DataLabels, pack.DataLabels...)

	// Union protected paths
	existingPaths := make(map[string]bool)
	for _, p := range target.Defaults.ProtectedPaths {
		existingPaths[p] = true
	}
	for _, p := range pack.Defaults.ProtectedPaths {
		if !existingPaths[p] {
			target.Defaults.ProtectedPaths = append(target.Defaults.ProtectedPaths, p)
		}
	}

	// Union allow domains
	existingDomains := make(map[string]bool)
	for _, d := range target.Network.AllowDomains {
		existingDomains[d] = true
	}
	for _, d := range pack.Network.AllowDomains {
		if !existingDomains[d] {
			target.Network.AllowDomains = append(target.Network.AllowDomains, d)
		}
	}
}

func clonePolicy(p *Policy) *Policy {
	clone := &Policy{
		Version: p.Version,
		Defaults: Defaults{
			Decision:       p.Defaults.Decision,
			NonInteractive: p.Defaults.NonInteractive,
			LogRedaction:   p.Defaults.LogRedaction,
		},
	}

	clone.Defaults.ProtectedPaths = make([]string, len(p.Defaults.ProtectedPaths))
	copy(clone.Defaults.ProtectedPaths, p.Defaults.ProtectedPaths)

	clone.Network.AllowDomains = make([]string, len(p.Network.AllowDomains))
	copy(clone.Network.AllowDomains, p.Network.AllowDomains)

	clone.Rules = make([]Rule, len(p.Rules))
	copy(clone.Rules, p.Rules)

	clone.DataLabels = make([]DataLabel, len(p.DataLabels))
	copy(clone.DataLabels, p.DataLabels)

	// DisableRules MUST be carried through the clone — LoadEmbeddedShellPacks
	// and LoadPacks both call clonePolicy as their first step, so dropping it
	// here silently disables the entire `agentshield rule disable` mechanism
	// for any user who also has embedded or disk packs (which is everyone).
	// Surfaced by E2E (2026-04-27): rule disable wrote disable_rules: [...]
	// to policy.yaml, but the rule still fired.
	clone.DisableRules = make([]string, len(p.DisableRules))
	copy(clone.DisableRules, p.DisableRules)

	return clone
}
