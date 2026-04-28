package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

	for _, entry := range entries {
		// Support subdirectory-based loading (packs/regex/, packs/structural/, etc.)
		// Each subdirectory's YAML files are loaded as packs of that analyzer type.
		if entry.IsDir() {
			dirName := entry.Name()
			enabled := !strings.HasPrefix(dirName, "_")
			subDir := filepath.Join(packsDir, dirName)
			subInfos, err := loadPacksFromDir(subDir, dirName, enabled, result)
			if err != nil {
				continue
			}
			infos = append(infos, subInfos...)
			continue
		}

		if !isYAMLFile(entry.Name()) {
			continue
		}

		path := filepath.Join(packsDir, entry.Name())

		// Check if pack is disabled (prefixed with underscore)
		baseName := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		enabled := !strings.HasPrefix(baseName, "_")

		pack, err := loadPack(path)
		if err != nil {
			infos = append(infos, PackInfo{
				Name:    baseName,
				Enabled: enabled,
				Path:    path,
			})
			continue
		}

		info := PackInfo{
			Name:        pack.Name,
			Description: pack.Description,
			Version:     pack.PackVersion,
			Author:      pack.Author,
			Enabled:     enabled,
			Path:        path,
			RuleCount:   len(pack.Rules),
		}
		if info.Name == "" {
			info.Name = baseName
		}
		infos = append(infos, info)

		if !enabled {
			continue
		}

		// Merge pack into result
		mergePackInto(result, pack)
	}

	return result, infos, nil
}

// loadPacksFromDir loads all YAML files from an analyzer-type subdirectory
// (e.g., packs/regex/, packs/structural/) and merges them into the target policy.
func loadPacksFromDir(dir, analyzerType string, enabled bool, target *Policy) ([]PackInfo, error) {
	var infos []PackInfo

	subEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, se := range subEntries {
		if se.IsDir() || !isYAMLFile(se.Name()) {
			continue
		}

		path := filepath.Join(dir, se.Name())
		baseName := strings.TrimSuffix(se.Name(), filepath.Ext(se.Name()))
		fileEnabled := enabled && !strings.HasPrefix(baseName, "_")

		pack, err := loadPack(path)
		if err != nil {
			infos = append(infos, PackInfo{
				Name:    analyzerType + "/" + baseName,
				Enabled: fileEnabled,
				Path:    path,
			})
			continue
		}

		info := PackInfo{
			Name:        pack.Name,
			Description: pack.Description,
			Version:     pack.PackVersion,
			Author:      pack.Author,
			Enabled:     fileEnabled,
			Path:        path,
			RuleCount:   len(pack.Rules),
		}
		if info.Name == "" {
			info.Name = analyzerType + "/" + baseName
		}
		infos = append(infos, info)

		if !fileEnabled {
			continue
		}

		mergePackInto(target, pack)
	}

	return infos, nil
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
	var infos []PackInfo

	// Sort filenames for deterministic load order (matters for test stability
	// and for "pack list" output).
	names := make([]string, 0, len(embedded))
	for name := range embedded {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		data := embedded[name]
		baseName := strings.TrimSuffix(name, filepath.Ext(name))

		// Disabled packs (underscore prefix) would not normally appear in the
		// embed.FS — the //go:embed directive globs real files on disk at
		// build time. Keep the check for symmetry with LoadPacks.
		enabled := !strings.HasPrefix(baseName, "_")

		var pack Pack
		if err := yaml.Unmarshal(data, &pack); err != nil {
			infos = append(infos, PackInfo{
				Name:    baseName,
				Enabled: enabled,
				Path:    "(embedded)",
			})
			continue
		}

		info := PackInfo{
			Name:        pack.Name,
			Description: pack.Description,
			Version:     pack.PackVersion,
			Author:      pack.Author,
			Enabled:     enabled,
			Path:        "(embedded)",
			RuleCount:   len(pack.Rules),
		}
		if info.Name == "" {
			info.Name = baseName
		}
		infos = append(infos, info)

		if !enabled {
			continue
		}
		mergePackInto(result, &pack)
	}

	return result, infos, nil
}

func loadPack(path string) (*Pack, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pack Pack
	if err := yaml.Unmarshal(data, &pack); err != nil {
		return nil, fmt.Errorf("failed to parse pack %s: %w", path, err)
	}

	return &pack, nil
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

func isYAMLFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".yaml" || ext == ".yml"
}
