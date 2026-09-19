package mcp

import "testing"

// exclude_when on structural_rules (#3735).
//
// The motivating defect is not a missed detection — it is TWO taxonomy nodes on
// ONE event. `mcp-struct-block-credential-path-access` matches every tool name
// (`.*`) against ~65 credential paths, so on a path that also has a dedicated
// rule it fired alongside that rule and the audit event carried both its own
// generic node and the specific one (#3682).
//
// The FIRST fix was a tool-name-only exclude, and review caught it fail-open:
// the catch-all's `\.pypirc$` also matches `release.pypirc`, its unanchored
// `\.gradle/gradle\.properties` also matches `.bak`/`~` backups — variants the
// dedicated globs (`**/.pypirc`, `**/.gradle/gradle.properties`) do NOT cover.
// A bare tool-name exclude dropped the catch-all's BLOCK on those variants to
// AUDIT with no rule, on a COMMUNITY pack. `exclude_when` is the path-aware
// conjunction that fixes it: exclude only when tool AND path both match, so
// every variant keeps the fallback.

// pkgmgrExcludeMatch mirrors the shape shipped on the catch-all: a `.*` tool
// name, one path predicate that matches variants, and an exclude_when whose
// path predicate is ANCHORED to exactly the dedicated-covered forms.
func pkgmgrExcludeMatch() MCPStructuralMatch {
	return MCPStructuralMatch{
		ToolNameRegex: ".*",
		ExcludeWhen: &StructuralExcludeClause{
			ToolNameRegex: "(?i)^(?:read[_-]file|cat[_-]file|str[_-]replace[_-]editor)$",
			ArgsMatch: map[string]ArgFieldMatch{
				"path": {PatternAny: []string{
					"(?:^|/)\\.pypirc$",
					"(?:^|/)\\.gradle/gradle\\.properties$",
				}},
			},
		},
		ArgsMatch: map[string]ArgFieldMatch{
			// The catch-all's own path predicate matches variants too.
			"path": {PatternAny: []string{
				"\\.pypirc$",
				"\\.gradle/gradle\\.properties",
			}},
		},
	}
}

func TestStructuralExcludeWhenIsPathAware(t *testing.T) {
	cases := []struct {
		name     string
		tool     string
		path     string
		wantFire bool
		why      string
	}{
		// EXACT dedicated-covered path + excluded read tool → carve out (the
		// dedicated rule owns the event and its precise taxonomy).
		{"exact-pypirc/read_file", "read_file", "/home/user/.pypirc", false,
			"dedicated mcp-sec-block-pypirc owns this exact path + name"},
		{"exact-gradle/cat_file", "cat_file", "/home/user/.gradle/gradle.properties", false,
			"dedicated mcp-sec-block-gradle-properties owns this"},

		// VARIANT paths + excluded read tool → MUST still fire. This is the
		// regression: the dedicated globs do not cover these, so the catch-all
		// is the only thing between them and AUDIT.
		{"variant-release-pypirc/read_file", "read_file", "/home/user/release.pypirc", true,
			"release.pypirc is not **/.pypirc; the catch-all is the only cover"},
		{"variant-pypirc-in-subdir-name/read_file", "read_file", "/home/user/my.pypirc", true,
			"my.pypirc has no leading slash before .pypirc — anchored exclude must miss it"},
		{"variant-gradle-bak/read_file", "read_file", "/home/user/.gradle/gradle.properties.bak", true,
			"a .bak backup is not the exact file; $ anchor must miss it"},
		{"variant-gradle-tilde/cat_file", "cat_file", "/home/user/.gradle/gradle.properties~", true,
			"an editor ~ backup is not the exact file"},

		// Non-excluded tool (write family) on the EXACT path → still fires
		// (the write-half double-fire is Gary's tier decision, untouched).
		{"exact-pypirc/write_file", "write_file", "/home/user/.pypirc", true,
			"write_file is not in the exclude set — catch-all still fires"},

		// Unrecognized tool on the exact path → still fires (that is the
		// catch-all's whole purpose).
		{"exact-pypirc/exotic", "acme_fs_put", "/home/user/.pypirc", true,
			"an unknown tool name is not excluded"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := matchStructural(c.tool, map[string]interface{}{"path": c.path}, pkgmgrExcludeMatch())
			if got != c.wantFire {
				t.Errorf("matchStructural(tool=%q path=%q) = %v, want %v — %s",
					c.tool, c.path, got, c.wantFire, c.why)
			}
		})
	}
}

// TestStructuralExcludeWhenIsNotRenderRecovered: a name that RENDERS as an
// excluded tool must still fire (two rules is tolerable for an obfuscated call;
// zero is not). CLAUDE.md: "Only POSITIVE predicates get the recovered form."
func TestStructuralExcludeWhenIsNotRenderRecovered(t *testing.T) {
	confusable := "reаd_file" // Cyrillic а (U+0430) for ASCII a
	if confusable == "read_file" {
		t.Fatal("fixture is not actually a confusable — this test would prove nothing")
	}
	if normalizeSeparators(confusable) != normalizeSeparators("read_file") {
		t.Fatalf("fixture %q does not recover to read_file — pick a real confusable", confusable)
	}
	if !matchStructural(confusable, map[string]interface{}{"path": "/home/user/.pypirc"}, pkgmgrExcludeMatch()) {
		t.Errorf("a confusable spelling of an excluded tool name satisfied the carve-out and switched the rule OFF.\n"+
			"tool=%q must still fire — exclude_when.tool_name_regex matches the WIRE name by design.", confusable)
	}
}

// TestStructuralExcludeWhenIsConjunction: the tool matches but the path does
// not (and vice versa) — neither alone may exclude. This is what "path-aware"
// means and what the first fix got wrong.
func TestStructuralExcludeWhenIsConjunction(t *testing.T) {
	m := pkgmgrExcludeMatch()

	// tool matches exclude, path is an UNRELATED credential path the catch-all
	// also matches → must NOT exclude (only tool matched).
	if !matchStructural("read_file", map[string]interface{}{"path": "/home/user/release.pypirc"}, m) {
		t.Error("tool matched but path did not — the conjunction must NOT exclude, or every variant fails open")
	}
	// path matches exclude, tool does not → must NOT exclude (only path matched).
	if !matchStructural("write_file", map[string]interface{}{"path": "/home/user/.pypirc"}, m) {
		t.Error("path matched but tool did not — the conjunction must NOT exclude")
	}
}

// TestStructuralExcludeWhenInvalidRegexKeepsRuleLive: an unparseable
// tool_name_regex must leave the rule ENFORCING, never silently disable it —
// the same fail-safe direction cachedRegexp's swallowed error implies.
func TestStructuralExcludeWhenInvalidRegexKeepsRuleLive(t *testing.T) {
	m := pkgmgrExcludeMatch()
	m.ExcludeWhen.ToolNameRegex = "([unclosed"
	if !matchStructural("read_file", map[string]interface{}{"path": "/home/user/.pypirc"}, m) {
		t.Error("an invalid exclude_when.tool_name_regex disabled the rule; it must fail SAFE (rule stays live)")
	}
}

// TestStructuralExcludeWhenEmptyClauseNeverExcludes: a clause with no
// conditions is a no-op, not a match-everything switch.
func TestStructuralExcludeWhenEmptyClauseNeverExcludes(t *testing.T) {
	m := MCPStructuralMatch{
		ToolNameRegex: ".*",
		ExcludeWhen:   &StructuralExcludeClause{}, // no conditions
		ArgsMatch:     map[string]ArgFieldMatch{"path": {PatternAny: []string{"\\.pypirc$"}}},
	}
	if !matchStructural("read_file", map[string]interface{}{"path": "/home/user/.pypirc"}, m) {
		t.Error("an empty exclude_when clause excluded the rule; it must never exclude")
	}
}

// TestStructuralExcludeWhenToolNameOnlyStillWorks: a clause with only a
// tool_name_regex (no path) reduces to the semantic-parity tool-name exclude —
// the capability #3735 asked for — for rules whose paths ARE fully covered by a
// sibling. It is allowed; the path-aware form is preferred where variants exist.
func TestStructuralExcludeWhenToolNameOnlyStillWorks(t *testing.T) {
	m := MCPStructuralMatch{
		ToolNameRegex: ".*",
		ExcludeWhen:   &StructuralExcludeClause{ToolNameRegex: "(?i)^rotate_secret$"},
		ArgsMatch:     map[string]ArgFieldMatch{"path": {PatternAny: []string{"\\.pypirc$"}}},
	}
	if matchStructural("rotate_secret", map[string]interface{}{"path": "/home/user/.pypirc"}, m) {
		t.Error("tool-name-only exclude_when did not carve out the named tool")
	}
	if !matchStructural("read_file", map[string]interface{}{"path": "/home/user/.pypirc"}, m) {
		t.Error("tool-name-only exclude_when carved out a tool it should not have")
	}
}
