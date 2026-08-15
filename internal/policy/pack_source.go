package policy

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// This file is the shared pack-loading core for the two pack families:
// shell packs (policy.Pack, this package) and MCP packs (mcp.MCPPack).
// Both families follow the same lifecycle — enumerate YAML payloads
// (disk dir or embedded FS), honor the `_` disabled-prefix convention,
// parse, record LoadError loudly instead of silently dropping rules
// (issue #2188), and merge enabled packs into an accumulating policy.
// The family-specific parts (parse target, listing metadata, merge/union
// semantics, exclusion rules) are injected via PackLoadHooks.

// PackSource is one loadable pack payload — a YAML file on disk or an
// embedded blob.
type PackSource struct {
	// Stem is the file name without extension; it drives the `_` disabled
	// check and the fallback pack name.
	Stem string
	// Path is the disk path, or "(embedded)" for embedded packs.
	Path string
	// Label identifies the source in parse-error messages (disk: full path;
	// embedded: original file name).
	Label string
	// Read returns the raw YAML payload.
	Read func() ([]byte, error)
}

// PackLoadHooks bundles the family-specific behavior for LoadPackSources.
type PackLoadHooks[P any] struct {
	// Parse unmarshals one pack payload. It must wrap parse errors with the
	// source label so the recorded LoadError is actionable (#2188).
	Parse func(data []byte, label string) (*P, error)
	// Describe returns the pack's listing metadata (Name, Description,
	// Version, Author, RuleCount). The core sets Enabled and Path, and falls
	// back to NameFor(stem) when Describe leaves Name empty.
	Describe func(p *P) PackInfo
	// NameFor maps a source stem to the listed fallback name (also used for
	// packs that fail to parse). Nil means the stem itself.
	NameFor func(stem string) string
	// EnabledFor decides whether a source is enabled. Nil means the standard
	// `_`-prefix convention (underscore-prefixed stems are disabled).
	EnabledFor func(stem string) bool
	// SkipPack, when non-nil, is consulted after a successful parse+describe;
	// returning true drops the pack from BOTH the returned infos and the
	// merge. Used for the MCP exclude-names dedupe (#1628).
	SkipPack func(info PackInfo) bool
	// Merge folds an enabled, non-skipped pack into the caller's accumulating
	// policy.
	Merge func(p *P)
}

// LoadPackSources runs the shared pack lifecycle over sources in order:
// enabled check → read+parse (recording LoadError on failure, #2188) →
// describe with name fallback → optional skip → merge when enabled.
func LoadPackSources[P any](sources []PackSource, h PackLoadHooks[P]) []PackInfo {
	nameFor := h.NameFor
	if nameFor == nil {
		nameFor = func(stem string) string { return stem }
	}
	enabledFor := h.EnabledFor
	if enabledFor == nil {
		enabledFor = func(stem string) bool { return !strings.HasPrefix(stem, "_") }
	}

	var infos []PackInfo
	for _, src := range sources {
		enabled := enabledFor(src.Stem)

		data, err := src.Read()
		var pack *P
		if err == nil {
			pack, err = h.Parse(data, src.Label)
		}
		if err != nil {
			// Record the failure instead of silently dropping the pack's rules
			// (issue #2188). RuleCount stays 0 — none of this pack's rules made
			// it into the policy.
			infos = append(infos, PackInfo{
				Name:      nameFor(src.Stem),
				Enabled:   enabled,
				Path:      src.Path,
				LoadError: err,
			})
			continue
		}

		info := h.Describe(pack)
		info.Enabled = enabled
		info.Path = src.Path
		if info.Name == "" {
			info.Name = nameFor(src.Stem)
		}

		if h.SkipPack != nil && h.SkipPack(info) {
			// Skip silently: the caller already has this pack from a higher
			// priority source. Do NOT add to infos — surfacing it would imply
			// it contributed rules.
			continue
		}

		infos = append(infos, info)

		if !enabled {
			continue
		}
		h.Merge(pack)
	}
	return infos
}

// DiskPackSources lists dir's YAML pack files as PackSources in os.ReadDir
// (lexical) order. Subdirectories are skipped; skipFile, when non-nil, drops
// additional files by name. Errors from os.ReadDir (including not-exist) are
// returned to the caller to interpret.
func DiskPackSources(dir string, skipFile func(fileName string) bool) ([]PackSource, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var sources []PackSource
	for _, entry := range entries {
		if entry.IsDir() || !IsYAMLFile(entry.Name()) {
			continue
		}
		if skipFile != nil && skipFile(entry.Name()) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		sources = append(sources, PackSource{
			Stem:  strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name())),
			Path:  path,
			Label: path,
			Read:  func() ([]byte, error) { return os.ReadFile(path) },
		})
	}
	return sources, nil
}

// EmbeddedPackSources adapts an embedded name→payload map to PackSources,
// sorted by name for deterministic load order (matters for test stability and
// for "pack list" output).
func EmbeddedPackSources(files map[string][]byte) []PackSource {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	sources := make([]PackSource, 0, len(names))
	for _, name := range names {
		data := files[name]
		sources = append(sources, PackSource{
			Stem:  strings.TrimSuffix(name, filepath.Ext(name)),
			Path:  "(embedded)",
			Label: name,
			Read:  func() ([]byte, error) { return data, nil },
		})
	}
	return sources
}

// IsYAMLFile reports whether name has a YAML extension. Shared by the shell
// and MCP pack loaders (and the scan diagnostic).
func IsYAMLFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".yaml" || ext == ".yml"
}
