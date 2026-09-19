package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRuleSchema_StaysInSyncWithGoTypes is a fitness function: every YAML field
// on the Go side has a matching JSON Schema property, and every schema property
// has a matching Go field. When someone adds a Go field but forgets the schema
// (or vice versa), this test fails — drift detection without needing a full
// JSON Schema validator dep.
//
// We deliberately allow the schema to be a *subset* of the Go types overall
// (so we can omit advanced/internal fields like data_labels in v1), but for
// each schema definition we cover, the keys must match exactly.
func TestRuleSchema_StaysInSyncWithGoTypes(t *testing.T) {
	schema := loadSchema(t)

	tests := []struct {
		schemaPath []string // path into the schema JSON
		goType     reflect.Type
	}{
		{[]string{"$defs", "rule"}, reflect.TypeOf(Rule{})},
		{[]string{"$defs", "match"}, reflect.TypeOf(Match{})},
		{[]string{"$defs", "structural_match"}, reflect.TypeOf(StructuralMatch{})},
		{[]string{"$defs", "dataflow_match"}, reflect.TypeOf(DataflowMatch{})},
		{[]string{"$defs", "dataflow_endpoint"}, reflect.TypeOf(DataflowEndpoint{})},
		{[]string{"$defs", "semantic_match"}, reflect.TypeOf(SemanticMatch{})},
		{[]string{"$defs", "stateful_match"}, reflect.TypeOf(StatefulMatch{})},
		{[]string{"$defs", "context_match"}, reflect.TypeOf(ContextMatch{})},
		{[]string{"$defs", "chain_step"}, reflect.TypeOf(ChainStep{})},
		{[]string{"$defs", "rule_tests"}, reflect.TypeOf(RuleTest{})},
		// Defined inline rather than in $defs, and therefore missed by every
		// row above. It shipped with `additionalProperties: false`, so a Go
		// field with no schema property does not merely go undocumented — it
		// makes the shipped configs/default_policy.yaml INVALID against our
		// own schema, which is what an editor validates a user's policy with.
		// #3630 added `env` and hit exactly that (2026-09-06).
		{[]string{"$defs", "defaults", "properties", "protected_path_consumers", "items"}, reflect.TypeOf(ProtectedPathConsumer{})},
	}

	for _, tt := range tests {
		schemaProps := extractSchemaProperties(t, schema, tt.schemaPath)
		goFields := yamlFieldNames(tt.goType)

		schemaOnly := setDifference(schemaProps, goFields)
		goOnly := setDifference(goFields, schemaProps)

		if len(schemaOnly) > 0 || len(goOnly) > 0 {
			t.Errorf("%s drift between schema and Go type %s:\n  schema-only fields: %v\n  Go-only fields:     %v",
				strings.Join(tt.schemaPath, "."),
				tt.goType.Name(),
				sorted(schemaOnly),
				sorted(goOnly),
			)
		}
	}
}

// TestRuleSchema_TopLevelIncludesDisableRules locks in that disable_rules is
// schema-visible — the FP-triage feature is the kind of thing a Reddit user
// discovers via VS Code intellisense, so it must be schema-documented.
func TestRuleSchema_TopLevelIncludesDisableRules(t *testing.T) {
	schema := loadSchema(t)
	props := extractSchemaProperties(t, schema, []string{"properties"})

	if !contains(props, "disable_rules") {
		t.Errorf("schema top-level properties must include 'disable_rules'; got %v", sorted(props))
	}
	if !contains(props, "rules") {
		t.Errorf("schema top-level properties must include 'rules'; got %v", sorted(props))
	}
}

// schemaIntentionallyOmits lists Policy fields we deliberately exclude from
// the schema. These are advanced/internal surfaces a typical OSS user does
// not author by hand — keeping them out of intellisense reduces noise.
// Adding a new field here REQUIRES a one-line justification. If you're not
// sure whether to add to the schema or to this list, prefer adding to the
// schema.
var schemaIntentionallyOmits = map[string]string{
	"data_labels":      "advanced/premium feature; rule writers iterating on basic rules don't need it surfaced in intellisense",
	"enforcement_mode": "SaaS-pushed by AI Agent Lens via /api/policy/yaml (issue #1952); not user-authored. Surfacing it in intellisense would suggest hand-editing, which the local agentshield.yaml `mode:` field is the right knob for.",
}

// TestRuleSchema_TopLevelGoFieldsAreSchemaProperties — every YAML field on
// the Policy struct must EITHER appear in the schema's top-level properties
// OR be in schemaIntentionallyOmits with a justification.
//
// Catches the common drift: someone adds a Policy field without updating
// the schema, so VS Code intellisense doesn't know the field exists.
func TestRuleSchema_TopLevelGoFieldsAreSchemaProperties(t *testing.T) {
	schema := loadSchema(t)
	schemaProps := extractSchemaProperties(t, schema, []string{"properties"})
	goFields := yamlFieldNames(reflect.TypeOf(Policy{}))

	var undocumented []string
	for _, field := range goFields {
		if contains(schemaProps, field) {
			continue
		}
		if _, intentional := schemaIntentionallyOmits[field]; intentional {
			continue
		}
		undocumented = append(undocumented, field)
	}

	if len(undocumented) > 0 {
		t.Errorf("Policy struct has YAML fields the schema doesn't document: %v\n"+
			"  Either add them to docs/schemas/agentshield-rule.schema.json,\n"+
			"  or add them to schemaIntentionallyOmits in this file with a justification.",
			sorted(undocumented))
	}
}

// allDecisionConstants is the authoritative list of decisions the engine
// understands — every Decision constant this package defines
// (internal/policy/types.go). Deriving the schema check from these constants
// (instead of a separately hand-maintained string list) means a decision the
// engine adds or removes fails this test at compile time if this slice is
// forgotten, and at test time if the schema is forgotten. See #3707: the
// schema's enum previously listed only BLOCK/AUDIT/ALLOW (missing
// REQUIRE_APPROVAL, which IS a real constant here), while the shipped
// configs/default_policy.yaml separately used "SANDBOX", which is NOT one —
// it was removed along with the `run` subcommand and internal/approval
// (git history 4fee4f6c) and the template was never updated. That is why the
// fix is "add REQUIRE_APPROVAL to the schema, fix the template's SANDBOX
// rules" rather than "add SANDBOX to the schema too" — SANDBOX names nothing
// the engine can act on.
var allDecisionConstants = []Decision{
	DecisionAllow,
	DecisionAudit,
	DecisionBlock,
	DecisionRequireApproval,
}

// schemaDecisionEnum extracts the string enum values of $defs.decision from
// the schema.
func schemaDecisionEnum(t *testing.T, schema map[string]interface{}) map[string]bool {
	t.Helper()
	defs, _ := schema["$defs"].(map[string]interface{})
	decision, _ := defs["decision"].(map[string]interface{})
	enum, _ := decision["enum"].([]interface{})

	got := map[string]bool{}
	for _, v := range enum {
		if s, ok := v.(string); ok {
			got[s] = true
		}
	}
	return got
}

// TestRuleSchema_DecisionEnum locks the schema's decision enum to EXACTLY the
// set of Decision constants this package defines — not merely "contains
// BLOCK/AUDIT/ALLOW" (the previous, weaker check), which is how the schema
// was able to omit REQUIRE_APPROVAL for as long as it did (#3707).
// Bidirectional: a constant added to allDecisionConstants with no matching
// schema entry fails here, and a schema entry with no matching Go constant
// (a stray "SANDBOX", a typo'd "block", an accidental "DROP") fails here too.
func TestRuleSchema_DecisionEnum(t *testing.T) {
	schema := loadSchema(t)
	schemaEnum := schemaDecisionEnum(t, schema)

	want := map[string]bool{}
	for _, d := range allDecisionConstants {
		want[string(d)] = true
	}

	var missingFromSchema, extraInSchema []string
	for v := range want {
		if !schemaEnum[v] {
			missingFromSchema = append(missingFromSchema, v)
		}
	}
	for v := range schemaEnum {
		if !want[v] {
			extraInSchema = append(extraInSchema, v)
		}
	}

	if len(missingFromSchema) > 0 || len(extraInSchema) > 0 {
		t.Errorf("schema decision enum drifted from internal/policy/types.go Decision constants:\n"+
			"  missing from schema (a real Go constant, not offered by the schema): %v\n"+
			"  extra in schema (accepted by the schema, no matching Go constant):    %v",
			sorted(missingFromSchema), sorted(extraInSchema))
	}
}

// TestRuleSchema_ShippedConfigsUseOnlyValidDecisions is the other half of
// #3707's fix. TestRuleSchema_DecisionEnum checks the schema's OWN enum
// definition is right; this checks the actual decision VALUES shipped in
// configs/default_policy.yaml and DefaultPolicy() are each a member of it —
// closing the gap the issue named directly: "the drift test compares
// property names only." Before this test existed, an executed
// schema-vs-value comparison found five invalid locations, all in
// configs/default_policy.yaml (defaults.decision + 4 rules).
//
// configs/default_policy.yaml is read and unmarshalled directly here — NOT
// via Load(), which layers the file over DefaultPolicy() (merging in extra
// baseline rules and letting an empty user field fall back to a valid
// default). A YAML-aware editor validates the raw file exactly as authored,
// so that's what this test has to check too, or it can pass while the
// shipped file itself still fails real schema validation.
func TestRuleSchema_ShippedConfigsUseOnlyValidDecisions(t *testing.T) {
	schema := loadSchema(t)
	valid := schemaDecisionEnum(t, schema)

	checkDecisions := func(t *testing.T, label string, pol *Policy) {
		t.Helper()
		var invalid []string
		if pol.Defaults.Decision != "" && !valid[string(pol.Defaults.Decision)] {
			invalid = append(invalid, fmt.Sprintf("defaults.decision=%q", pol.Defaults.Decision))
		}
		if pol.Defaults.NonInteractive != "" && !valid[string(pol.Defaults.NonInteractive)] {
			invalid = append(invalid, fmt.Sprintf("defaults.non_interactive=%q", pol.Defaults.NonInteractive))
		}
		for _, r := range pol.Rules {
			if r.Decision != "" && !valid[string(r.Decision)] {
				invalid = append(invalid, fmt.Sprintf("rules[%s].decision=%q", r.ID, r.Decision))
			}
		}
		if len(invalid) > 0 {
			sort.Strings(invalid)
			t.Errorf("%s uses decision value(s) the schema's enum doesn't allow (%d invalid location(s)):\n  %s",
				label, len(invalid), strings.Join(invalid, "\n  "))
		}
	}

	t.Run("configs/default_policy.yaml (raw file, as a schema validator sees it)", func(t *testing.T) {
		path := filepath.Join("..", "..", "configs", "default_policy.yaml")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var raw Policy
		if err := yaml.Unmarshal(data, &raw); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		checkDecisions(t, path, &raw)
	})

	t.Run("DefaultPolicy() serialised", func(t *testing.T) {
		pol := DefaultPolicy()
		out, err := yaml.Marshal(pol)
		if err != nil {
			t.Fatalf("marshal DefaultPolicy(): %v", err)
		}
		var roundTripped Policy
		if err := yaml.Unmarshal(out, &roundTripped); err != nil {
			t.Fatalf("unmarshal serialised DefaultPolicy(): %v", err)
		}
		checkDecisions(t, "DefaultPolicy()", &roundTripped)
	})
}

// --- helpers ---------------------------------------------------------------

func loadSchema(t *testing.T) map[string]interface{} {
	t.Helper()
	// Test runs from internal/policy. Schema lives at repo-root/docs/schemas.
	path := filepath.Join("..", "..", "docs", "schemas", "agentshield-rule.schema.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema %s: %v", path, err)
	}
	var schema map[string]interface{}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	return schema
}

// extractSchemaProperties walks the schema to a node like
// {"properties": {"id": {...}, "taxonomy": {...}}} and returns ["id",
// "taxonomy"]. The path can be "$defs/rule" or just "properties".
func extractSchemaProperties(t *testing.T, schema map[string]interface{}, path []string) []string {
	t.Helper()
	node := interface{}(schema)
	for _, segment := range path {
		m, ok := node.(map[string]interface{})
		if !ok {
			t.Fatalf("schema path %v: expected map at segment %q, got %T", path, segment, node)
		}
		node = m[segment]
	}
	defNode, ok := node.(map[string]interface{})
	if !ok {
		t.Fatalf("schema path %v: leaf is not a map (got %T)", path, node)
	}

	// If the leaf is itself a `properties` map, use it. Otherwise look for a
	// `properties` field beneath it (the more common case for type definitions).
	props := defNode
	if inner, hasProps := defNode["properties"].(map[string]interface{}); hasProps {
		props = inner
	}

	out := make([]string, 0, len(props))
	for k := range props {
		out = append(out, k)
	}
	return out
}

// yamlFieldNames returns the YAML tag names of all exported struct fields,
// stripping `omitempty` and skipping `yaml:"-"`.
func yamlFieldNames(t reflect.Type) []string {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	var out []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.SplitN(tag, ",", 2)[0]
		if name == "" {
			continue
		}
		out = append(out, name)
	}
	return out
}

func setDifference(a, b []string) []string {
	bSet := make(map[string]bool, len(b))
	for _, x := range b {
		bSet[x] = true
	}
	var out []string
	for _, x := range a {
		if !bSet[x] {
			out = append(out, x)
		}
	}
	return out
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func contains(s []string, want string) bool {
	for _, x := range s {
		if x == want {
			return true
		}
	}
	return false
}
