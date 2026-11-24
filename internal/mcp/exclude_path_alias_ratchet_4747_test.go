package mcp

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// pathAliasNames are the names #3225 copied a path exclude under, in
// normalizeFieldName form (file_path and filepath fold to one). An exclude
// keyed on `path` reads file_path itself since #4747, so a pack never needs
// to key one on any of these, and keying it there is how the class reopens:
// the copy covers one rule and one spelling, the next rule forgets it.
var pathAliasNames = map[string]bool{"file": true, "filepath": true, "filename": true}

// grandfatheredPathAliasExcludes are the alias-keyed excludes that predate
// #4747, as "<rule id>/<key>". They stay because removing them is not
// decision-neutral: each also excuses a call whose `path` is outside the
// excused locations (a decoy file_path), and plural or nested spellings
// (file_paths, {"request":{"file_path":…}}) the engine alias does not read.
// Removing one raises decisions, so it is its own reviewed change. Delete an
// entry when its key leaves the pack; the test fails on a stale entry.
var grandfatheredPathAliasExcludes = map[string]bool{
	"mcp-privesc-block-privileged-container/file":                true,
	"mcp-privesc-block-privileged-container/filepath":            true,
	"mcp-privesc-block-privileged-container/filename":            true,
	"mcp-privesc-block-privileged-container/file_path":           true,
	"mcp-struct-block-prompt-injection-content/file_path":        true,
	"mcp-struct-block-system-prompt-jailbreak-content/file_path": true,
}

// pathAliasExcludeKeys lists every exclude_args_match key in pack that names
// the path under an alias, as "<rule id>/<key>": structural rules and the
// structural block of a flat rule alike.
func pathAliasExcludeKeys(pack MCPPolicy) []string {
	var out []string
	add := func(id string, m *MCPStructuralMatch) {
		if m == nil {
			return
		}
		for key := range m.ExcludeArgsMatch {
			if pathAliasNames[normalizeFieldName(key)] {
				out = append(out, id+"/"+key)
			}
		}
	}
	for i := range pack.StructuralRules {
		add(pack.StructuralRules[i].ID, &pack.StructuralRules[i].Match)
	}
	for i := range pack.Rules {
		add(pack.Rules[i].ID, pack.Rules[i].Match.Structural)
	}
	sort.Strings(out)
	return out
}

func pathAliasExcludeKeysInDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read %s: %v", dir, err)
	}
	var out []string
	files := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		pack, err := parseMCPPackFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files++
		out = append(out, pathAliasExcludeKeys(pack)...)
	}
	if files == 0 {
		t.Fatalf("no MCP packs read in %s: the ratchet would pass vacuously", dir)
	}
	return out
}

// TestExcludeArgsMatch_NoNewPathAliasKeys is the #4747 ratchet: a pack keys
// a path exclude on `path`, and the engine resolves file_path for it. A new
// exclude keyed on file, filepath, filename or file_path fails here.
func TestExcludeArgsMatch_NoNewPathAliasKeys(t *testing.T) {
	found := pathAliasExcludeKeysInDir(t, mcpPacksDir())
	premium := ossbuild.PremiumPacksPresent()
	if premium {
		found = append(found, pathAliasExcludeKeysInDir(t, premiumMCPPacksDir())...)
	}
	// The OSS tree has no premium packs, so their entries cannot be checked there.
	unexpected, stale := pathAliasRatchet(found, grandfatheredPathAliasExcludes, premium)
	for _, k := range unexpected {
		t.Errorf("exclude_args_match key %s names the path under an alias. Key the exclude on `path`: "+
			"since #4747 it also reads file_path, and only those two names, so a copy under another name "+
			"covers one rule and lets the next one reopen the class", k)
	}
	for _, k := range stale {
		t.Errorf("grandfathered entry %s no longer exists in any pack: delete it from grandfatheredPathAliasExcludes", k)
	}
}

// pathAliasRatchet is the ratchet's decision: the found keys not
// grandfathered, and (when checkStale) the grandfathered keys not found.
func pathAliasRatchet(found []string, grandfathered map[string]bool, checkStale bool) (unexpected, stale []string) {
	seen := map[string]bool{}
	for _, k := range found {
		seen[k] = true
		if !grandfathered[k] {
			unexpected = append(unexpected, k)
		}
	}
	if checkStale {
		for k := range grandfathered {
			if !seen[k] {
				stale = append(stale, k)
			}
		}
	}
	sort.Strings(stale)
	return unexpected, stale
}

// TestExcludeArgsMatch_RatchetDecision: a new alias key is reported, a
// grandfathered one is not, and a grandfathered key gone from the packs is
// reported as stale only where the premium packs are present.
func TestExcludeArgsMatch_RatchetDecision(t *testing.T) {
	g := map[string]bool{"old-rule/file_path": true, "gone-rule/file": true}
	unexpected, stale := pathAliasRatchet([]string{"old-rule/file_path", "new-rule/filename"}, g, true)
	if strings.Join(unexpected, ",") != "new-rule/filename" {
		t.Errorf("unexpected = %v, want [new-rule/filename]", unexpected)
	}
	if strings.Join(stale, ",") != "gone-rule/file" {
		t.Errorf("stale = %v, want [gone-rule/file]", stale)
	}
	if _, stale := pathAliasRatchet(nil, g, false); len(stale) != 0 {
		t.Errorf("stale must not be checked without the premium packs, got %v", stale)
	}
}

// TestExcludeArgsMatch_RatchetCanFail proves the ratchet sees what it claims
// to: an alias key in a structural rule and in a flat rule's structural
// block, in several spellings, and nothing for a path or content key.
func TestExcludeArgsMatch_RatchetCanFail(t *testing.T) {
	dir := t.TempDir()
	pack := `
name: "ratchet probe"
structural_rules:
  - id: probe-structural
    match:
      tool_name_regex: ".*"
      args_match:
        content: {pattern_any: ["x"]}
      exclude_args_match:
        path: {pattern_any: ["^docs/"]}
        content: {pattern_any: ["^#"]}
        filePath: {pattern_any: ["^docs/"]}
        filename: {pattern_any: ["^docs/"]}
    decision: "BLOCK"
    reason: "probe"
rules:
  - id: probe-flat
    match:
      tool_name_any: ["write_file"]
      structural:
        args_match:
          content: {pattern_any: ["x"]}
        exclude_args_match:
          file: {pattern_any: ["^docs/"]}
    decision: "BLOCK"
    reason: "probe"
`
	if err := os.WriteFile(filepath.Join(dir, "probe.yaml"), []byte(pack), 0o644); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(pathAliasExcludeKeysInDir(t, dir), ",")
	want := "probe-flat/file,probe-structural/filePath,probe-structural/filename"
	if got != want {
		t.Errorf("ratchet saw %q, want %q", got, want)
	}
}
