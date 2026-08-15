package policy_test

// Schema lint for pack YAML files (#2863).
//
// The runtime loaders use lenient yaml.Unmarshal, so a mis-indented key —
// e.g. `command_intent_exclude` at rule level instead of inside `match:` —
// is silently dropped and the rule ships with its FP suppression inert.
// 16 premium shell rules shipped exactly that way (#2863); nothing failed
// because the lenient decode swallowed the unknown rule-level key.
//
// Both pack families now get the strongest guard:
//
//  1. Shell packs (community/*.yaml, premium/*.yaml): full strict decode
//     with yaml.Decoder.KnownFields(true) into policy.Pack. Any field not
//     declared on the Go types — at any nesting level — fails the build
//     with a file:line error. Shell packs are schema-clean, so this is the
//     strongest possible guard and it is green from day one.
//
//  2. MCP packs (community/mcp, premium/mcp): full strict decode with
//     yaml.Decoder.KnownFields(true) into mcp.MCPPack (TestMCPPackYAML_
//     StrictDecode below). This became possible once #2869 Class A
//     (confidence/taxonomy/tests/description/generated/result/tools_list —
//     advisory metadata the Go types hadn't caught up to) was closed by
//     adding those fields to the MCP types. The narrower, pre-#2869
//     targeted lints (TestMCPPackYAML_NoRuleLevelMatchKeys and
//     TestMCPPackYAML_NoInertMatchPredicates below) are now subsumed by
//     full strict decode but kept for their more precise per-rule-id,
//     per-section diagnostics.
//
// The runtime loaders stay lenient on purpose (fail-safe: a customer's
// hand-edited policy with an extra key must not disable enforcement) —
// these tests are the strict twin that keeps the packs WE ship honest.
//
// External test package (policy_test) so it can import internal/mcp for the
// MCP pack types without an import cycle (mcp imports policy).

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// strictDecode decodes data into out with KnownFields(true), returning the
// decode error (nil when the document is schema-clean).
func strictDecode(data []byte, out interface{}) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	return dec.Decode(out)
}

// packsRoot returns the absolute path to the repo's packs/ directory.
func packsRoot() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "packs")
}

// yamlFilesIn returns the .yaml files directly inside dir, skipping
// underscore-prefixed (disabled legacy) files. Missing directories are
// skipped silently — the OSS publish excludes packs/premium.
func yamlFilesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			t.Logf("skipping missing pack dir %s", dir)
			return nil
		}
		t.Fatalf("cannot read pack dir %s: %v", dir, err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".yaml") || strings.HasPrefix(name, "_") {
			continue
		}
		files = append(files, filepath.Join(dir, name))
	}
	return files
}

// TestPackYAML_StrictDecode strict-decodes every shipped shell pack against
// the Go policy types. An unknown field anywhere (top level, rule level,
// inside match:, nested analyzer blocks) fails with the offending file and
// line number.
func TestPackYAML_StrictDecode(t *testing.T) {
	root := packsRoot()
	shellDirs := []string{
		filepath.Join(root, "community"),
		filepath.Join(root, "premium"),
	}

	checked := 0
	for _, dir := range shellDirs {
		for _, file := range yamlFilesIn(t, dir) {
			file := file
			t.Run(relToRoot(root, file), func(t *testing.T) {
				data, err := os.ReadFile(file)
				if err != nil {
					t.Fatalf("read: %v", err)
				}
				var pack policy.Pack
				if err := strictDecode(data, &pack); err != nil {
					t.Errorf("strict decode failed — mis-indented or unknown field (see #2863):\n%v", err)
				}
			})
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no shell pack files found — packsRoot() is wrong")
	}
	t.Logf("strict-decoded %d shell pack files", checked)
}

// TestPackYAML_StrictDecode_CatchesRuleLevelIntentExclude is the negative
// fixture: a rule-level command_intent_exclude (the exact #2863 bug shape)
// must FAIL strict decode. If this ever starts passing, the lint has gone
// blind to the very class it exists to catch.
func TestPackYAML_StrictDecode_CatchesRuleLevelIntentExclude(t *testing.T) {
	const misindented = `
name: Negative Fixture
description: rule-level command_intent_exclude must be rejected
version: 1.0.0
author: test
rules:
- id: fixture-rule-level-intent-exclude
  taxonomy: destructive-ops/fs-destruction/recursive-root-delete
  match:
    command_regex: "^echo fixture$"
  command_intent_exclude: [is_doc_text]
  decision: AUDIT
  reason: fixture
`
	var pack policy.Pack
	err := strictDecode([]byte(misindented), &pack)
	if err == nil {
		t.Fatal("strict decode ACCEPTED a rule-level command_intent_exclude — the #2863 lint is blind")
	}
	if !strings.Contains(err.Error(), "command_intent_exclude") {
		t.Fatalf("strict decode failed for the wrong reason: %v", err)
	}

	// Same key correctly placed inside match: must pass.
	correct := strings.Replace(misindented,
		"  command_intent_exclude: [is_doc_text]\n", "", 1)
	correct = strings.Replace(correct,
		"    command_regex: \"^echo fixture$\"\n",
		"    command_regex: \"^echo fixture$\"\n    command_intent_exclude: [is_doc_text]\n", 1)
	var ok policy.Pack
	if err := strictDecode([]byte(correct), &ok); err != nil {
		t.Fatalf("strict decode rejected a correctly-placed command_intent_exclude: %v", err)
	}
	if len(ok.Rules) != 1 || len(ok.Rules[0].Match.CommandIntentExclude) != 1 {
		t.Fatalf("correctly-placed exclude did not land in Match.CommandIntentExclude: %+v", ok.Rules)
	}
}

// yamlFieldNames returns the yaml key names declared on a struct type,
// derived via reflection so the lint cannot rot when fields are added.
func yamlFieldNames(t reflect.Type) map[string]bool {
	names := make(map[string]bool)
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name != "" {
			names[name] = true
		}
	}
	return names
}

// mcpRuleSections maps each MCP pack rule-list section to the match struct
// whose keys must NOT appear at rule level in that section. value_limits is
// absent by design: ValueLimitRule has no nested match — its match fields
// legitimately live at rule level.
var mcpRuleSections = map[string]reflect.Type{
	"rules":            reflect.TypeOf(mcp.MCPMatch{}),
	"structural_rules": reflect.TypeOf(mcp.MCPStructuralMatch{}),
	"semantic_rules":   reflect.TypeOf(mcp.MCPSemanticMatch{}),
	"resource_rules":   reflect.TypeOf(mcp.ResourceMatch{}),
}

// mcpRuleLevelMatchKeys returns one violation string per match-struct key
// found at rule level in the generically-decoded pack document.
func mcpRuleLevelMatchKeys(doc map[string]interface{}) []string {
	var violations []string
	for section, matchType := range mcpRuleSections {
		matchKeys := yamlFieldNames(matchType)
		list, ok := doc[section].([]interface{})
		if !ok {
			continue
		}
		for i, entry := range list {
			rule, ok := entry.(map[string]interface{})
			if !ok {
				continue
			}
			id, _ := rule["id"].(string)
			for key := range rule {
				if matchKeys[key] {
					violations = append(violations,
						fmt.Sprintf("%s[%d] (id=%s): match key %q at rule level — silently ignored by the lenient loader; move it inside match:", section, i, id, key))
				}
			}
		}
	}
	sort.Strings(violations)
	return violations
}

// TestMCPPackYAML_NoRuleLevelMatchKeys is the MCP analogue of the strict
// decode: a match-struct key at rule level is the #2863 inert-config shape
// and fails the build with the pack, section, and rule id.
func TestMCPPackYAML_NoRuleLevelMatchKeys(t *testing.T) {
	root := packsRoot()
	mcpDirs := []string{
		filepath.Join(root, "community", "mcp"),
		filepath.Join(root, "premium", "mcp"),
	}

	checked := 0
	for _, dir := range mcpDirs {
		for _, file := range yamlFilesIn(t, dir) {
			file := file
			t.Run(relToRoot(root, file), func(t *testing.T) {
				data, err := os.ReadFile(file)
				if err != nil {
					t.Fatalf("read: %v", err)
				}
				var doc map[string]interface{}
				if err := yaml.Unmarshal(data, &doc); err != nil {
					t.Fatalf("parse: %v", err)
				}
				for _, v := range mcpRuleLevelMatchKeys(doc) {
					t.Error(v)
				}
			})
			checked++
		}
	}
	if checked == 0 {
		t.Skip("no MCP pack files found (OSS build without premium?)")
	}
	t.Logf("linted %d MCP pack files for rule-level match keys", checked)
}

// TestMCPPackYAML_LintCatchesRuleLevelMatchKeys is the negative fixture for
// the MCP lint: match keys at rule level in both flat and structural rule
// sections must be flagged.
func TestMCPPackYAML_LintCatchesRuleLevelMatchKeys(t *testing.T) {
	const misindented = `
name: Negative Fixture
rules:
- id: fixture-flat-rule
  match:
    tool_name: read_file
  tool_name_regex: ".*"
  decision: AUDIT
  reason: fixture
structural_rules:
- id: fixture-structural-rule
  match:
    tool_name_regex: ".*"
  args_match:
    path:
      pattern_any: ["fixture"]
  decision: AUDIT
  reason: fixture
`
	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(misindented), &doc); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	violations := mcpRuleLevelMatchKeys(doc)
	if len(violations) != 2 {
		t.Fatalf("expected exactly 2 violations (tool_name_regex on flat rule, args_match on structural rule), got %d: %v", len(violations), violations)
	}
	joined := strings.Join(violations, "\n")
	for _, want := range []string{"tool_name_regex", "args_match", "fixture-flat-rule", "fixture-structural-rule"} {
		if !strings.Contains(joined, want) {
			t.Errorf("violations missing %q:\n%s", want, joined)
		}
	}
}

// TestMCPPackYAML_StrictDecode strict-decodes every shipped MCP pack against
// mcp.MCPPack with KnownFields(true) — the MCP analogue of
// TestPackYAML_StrictDecode above. This became possible once the #2869
// Class A advisory fields (taxonomy/tests/confidence/description/generated/
// result/tools_list) were added to the MCP Go types; before that, ~1500
// legitimate field occurrences across the packs would have failed strict
// decode for reasons that had nothing to do with a real authoring mistake,
// making the signal useless. With Class A closed, an unknown field here is
// unambiguously either a new authoring mistake or a new field that needs a
// Go type update — never expected drift.
func TestMCPPackYAML_StrictDecode(t *testing.T) {
	root := packsRoot()
	mcpDirs := []string{
		filepath.Join(root, "community", "mcp"),
		filepath.Join(root, "premium", "mcp"),
	}

	checked := 0
	for _, dir := range mcpDirs {
		for _, file := range yamlFilesIn(t, dir) {
			file := file
			t.Run(relToRoot(root, file), func(t *testing.T) {
				data, err := os.ReadFile(file)
				if err != nil {
					t.Fatalf("read: %v", err)
				}
				var pack mcp.MCPPack
				if err := strictDecode(data, &pack); err != nil {
					t.Errorf("strict decode failed — mis-indented or unknown field (see #2869):\n%v", err)
				}
			})
			checked++
		}
	}
	if checked == 0 {
		t.Skip("no MCP pack files found (OSS build without premium?)")
	}
	t.Logf("strict-decoded %d MCP pack files", checked)
}

func relToRoot(root, file string) string {
	rel, err := filepath.Rel(root, file)
	if err != nil {
		return file
	}
	return rel
}

// --- #2869 Class B: inert match predicates one nesting level deeper ---
//
// TestMCPPackYAML_NoRuleLevelMatchKeys (above) catches a match-struct key
// living at rule level. This section catches the same silent-drop failure
// mode one level deeper: the key IS correctly nested inside match:, but the
// rule lives under a *section* whose Go type doesn't declare that key at
// all — e.g. `args_match`/`tool_name_regex` inside a semantic_rules: entry,
// which decodes against mcp.MCPSemanticMatch (intent_any/intent_all/
// confidence_min only). The lenient loader drops the field with no warning,
// so the rule's author-intended filter never applies.
//
// mcpBenignAdvisoryFields separates that from #2869 Class A: fields every
// MCP pack family carries (taxonomy/tests/confidence/description/...) that
// the Go types haven't caught up to yet, but whose absence only degrades
// metadata (attestation/coverage tooling), not the rule's runtime behavior.
// Class A is tracked in #2869 but does not fail this test.
var mcpBenignAdvisoryFields = map[string]bool{
	"taxonomy":    true,
	"tests":       true,
	"confidence":  true,
	"description": true,
	"generated":   true,
	"result":      true,
	"tools_list":  true,
}

// mcpSectionTypes maps each MCP pack rule-list section to a constructor for
// the concrete Go type its entries decode into (the same mapping the
// runtime loaders use).
var mcpSectionTypes = map[string]func() interface{}{
	"rules":            func() interface{} { return &mcp.MCPRule{} },
	"structural_rules": func() interface{} { return &mcp.MCPStructuralRule{} },
	"semantic_rules":   func() interface{} { return &mcp.MCPSemanticRule{} },
	"resource_rules":   func() interface{} { return &mcp.ResourceRule{} },
	"value_limits":     func() interface{} { return &mcp.ValueLimitRule{} },
}

var yamlUnknownFieldRe = regexp.MustCompile(`field (\S+) not found in type`)

// classBFields strict-decodes err (from decoding one rule entry) and returns
// the unknown field names that are NOT in the benign-advisory allowlist —
// i.e. the genuinely inert match predicates.
func classBFields(err error) []string {
	var typeErr *yaml.TypeError
	if !errors.As(err, &typeErr) {
		return nil
	}
	var out []string
	for _, msg := range typeErr.Errors {
		m := yamlUnknownFieldRe.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		if field := m[1]; !mcpBenignAdvisoryFields[field] {
			out = append(out, field)
		}
	}
	return out
}

// knownMCPClassBGaps allowlists rule IDs with a known, already-filed Class B
// violation so this test is green today. Chip this down the same way
// knownPremiumMCPTestGaps gets chipped down (internal/mcp/rule_yaml_test.go):
// fix the rule (move it to the section whose type actually declares the
// field it needs) and remove the entry.
//
// Tracking: https://github.com/AI-AgentLens/agentshield-oss/issues/2869
var knownMCPClassBGaps = map[string]string{}

// TestMCPPackYAML_NoInertMatchPredicates is the negative-space twin of
// TestMCPPackYAML_NoRuleLevelMatchKeys: it catches a match predicate that is
// correctly nested under match: but placed in a rule-list section whose Go
// type doesn't declare it, so the lenient runtime loader silently drops it
// and the rule's filter never applies (#2869 Class B).
func TestMCPPackYAML_NoInertMatchPredicates(t *testing.T) {
	root := packsRoot()
	mcpDirs := []string{
		filepath.Join(root, "community", "mcp"),
		filepath.Join(root, "premium", "mcp"),
	}

	checked := 0
	seenGaps := map[string]bool{}
	for _, dir := range mcpDirs {
		for _, file := range yamlFilesIn(t, dir) {
			file := file
			t.Run(relToRoot(root, file), func(t *testing.T) {
				data, err := os.ReadFile(file)
				if err != nil {
					t.Fatalf("read: %v", err)
				}
				var doc map[string]interface{}
				if err := yaml.Unmarshal(data, &doc); err != nil {
					t.Fatalf("parse: %v", err)
				}
				for section, newTarget := range mcpSectionTypes {
					list, ok := doc[section].([]interface{})
					if !ok {
						continue
					}
					for i, entry := range list {
						id := "?"
						if m, ok := entry.(map[string]interface{}); ok {
							if idv, ok := m["id"].(string); ok {
								id = idv
							}
						}
						b, err := yaml.Marshal(entry)
						if err != nil {
							t.Errorf("%s[%d] (id=%s): re-marshal: %v", section, i, id, err)
							continue
						}
						target := newTarget()
						decodeErr := strictDecode(b, target)
						if decodeErr == nil {
							continue
						}
						fields := classBFields(decodeErr)
						if len(fields) == 0 {
							continue
						}
						if reason, known := knownMCPClassBGaps[id]; known {
							seenGaps[id] = true
							t.Logf("KNOWN GAP %s (section=%s, fields=%v): %s", id, section, fields, reason)
							continue
						}
						t.Errorf("%s[%d] (id=%s): inert match predicate(s) %v — declared under match: but %T has no such field; the lenient loader silently drops it and the filter never applies (see #2869)", section, i, id, fields, target)
					}
				}
			})
			checked++
		}
	}
	if checked == 0 {
		t.Skip("no MCP pack files found (OSS build without premium?)")
	}
	for id := range knownMCPClassBGaps {
		if !seenGaps[id] {
			t.Errorf("knownMCPClassBGaps entry %q was not observed — rule fixed or renamed? remove it from the allowlist", id)
		}
	}
	t.Logf("checked %d MCP pack files for Class B inert match predicates (%d known gaps)", checked, len(knownMCPClassBGaps))
}
