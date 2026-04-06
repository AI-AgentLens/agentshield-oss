package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

	return clone
}

func isYAMLFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".yaml" || ext == ".yml"
}
