package mcp

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// The static node of the synthetic rules below: deliberately one the
// matched-path lookup never returns, so a test can tell the two apart.
const taxonomyFromStaticNode = "credential-exposure/private-key-access/ssh-private-key-read"

func taxonomyFromRule(id, from string, args map[string]ArgFieldMatch) MCPStructuralRule {
	return MCPStructuralRule{
		ID:           id,
		Taxonomy:     taxonomyFromStaticNode,
		TaxonomyFrom: from,
		Match:        MCPStructuralMatch{ToolNameRegex: ".*", ArgsMatch: args},
		Decision:     policy.DecisionBlock,
		Reason:       "synthetic #4665 rule",
	}
}

func credPathArgs(key string) map[string]ArgFieldMatch {
	return map[string]ArgFieldMatch{key: {PatternAny: []string{`\.ssh/`, `\.pypirc$`, `\.azure/?$`}}}
}

// #4665: with taxonomy_from: matched_path, a firing records the node of the
// path it matched (policy.MatchedPathTaxonomyRef), once per distinct node,
// and the decision and rule list are exactly those of the same rule without
// it.
func TestStructuralTaxonomyFromMatchedPath4665(t *testing.T) {
	const pkg = "credential-exposure/package-registry/package-manager-credential-access"
	cases := []struct {
		name string
		args map[string]interface{}
		want []string
	}{
		{"pypirc", map[string]interface{}{"file": "/home/u/.pypirc"}, []string{pkg}},
		{"ssh key", map[string]interface{}{"file": "/home/u/.ssh/id_rsa"}, []string{taxonomyFromStaticNode}},
		{"no row: generic node", map[string]interface{}{"file": "/home/u/.azure"}, []string{policy.ProtectedPathNode}},
		{"batch: each matched value, sorted", map[string]interface{}{
			"files": []interface{}{"/home/u/.pypirc", "/tmp/notes.txt", "/home/u/.ssh/id_rsa", "/srv/.pypirc"},
		}, []string{pkg, taxonomyFromStaticNode}},
	}
	refined := NewPolicyEvaluator(&MCPPolicy{StructuralRules: []MCPStructuralRule{
		taxonomyFromRule("synthetic-refined", TaxonomyFromMatchedPath, credPathArgs("file")),
	}})
	static := NewPolicyEvaluator(&MCPPolicy{StructuralRules: []MCPStructuralRule{
		taxonomyFromRule("synthetic-refined", "", credPathArgs("file")),
	}})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := refined.EvaluateToolCall("read_file", tc.args)
			base := static.EvaluateToolCall("read_file", tc.args)
			if got.Decision != base.Decision || !reflect.DeepEqual(got.TriggeredRules, base.TriggeredRules) {
				t.Fatalf("decision changed: refined %s %v, static %s %v",
					got.Decision, got.TriggeredRules, base.Decision, base.TriggeredRules)
			}
			if got.Decision != policy.DecisionBlock {
				t.Fatalf("control: the rule must fire, got %s", got.Decision)
			}
			if !reflect.DeepEqual(got.TaxonomyRefs, tc.want) {
				t.Errorf("taxonomy %v, want %v", got.TaxonomyRefs, tc.want)
			}
			if !reflect.DeepEqual(base.TaxonomyRefs, []string{taxonomyFromStaticNode}) {
				t.Errorf("control: the static rule records %v, want its own node", base.TaxonomyRefs)
			}
		})
	}
}

// The refinement never drops a node and never touches a rule that did not
// opt in: an unknown taxonomy_from value, and a match that names no value,
// both keep the static node.
func TestStructuralTaxonomyFromKeepsStaticNode4665(t *testing.T) {
	yes := true
	cases := []struct {
		name string
		rule MCPStructuralRule
		args map[string]interface{}
	}{
		{"not opted in", taxonomyFromRule("r", "", credPathArgs("file")),
			map[string]interface{}{"file": "/home/u/.pypirc"}},
		{"unknown value", taxonomyFromRule("r", "matched-path", credPathArgs("file")),
			map[string]interface{}{"file": "/home/u/.pypirc"}},
		{"existence-only match", taxonomyFromRule("r", TaxonomyFromMatchedPath,
			map[string]ArgFieldMatch{"file": {Exists: &yes}}),
			map[string]interface{}{"file": "/home/u/.pypirc"}},
		{"pattern_not only", taxonomyFromRule("r", TaxonomyFromMatchedPath,
			map[string]ArgFieldMatch{"file": {PatternNot: []string{`^/tmp/`}}}),
			map[string]interface{}{"file": "/home/u/.pypirc"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewPolicyEvaluator(&MCPPolicy{StructuralRules: []MCPStructuralRule{tc.rule}})
			got := e.EvaluateToolCall("read_file", tc.args)
			if got.Decision != policy.DecisionBlock {
				t.Fatalf("control: the rule must fire, got %s", got.Decision)
			}
			if !reflect.DeepEqual(got.TaxonomyRefs, []string{taxonomyFromStaticNode}) {
				t.Errorf("taxonomy %v, want the static node", got.TaxonomyRefs)
			}
		})
	}
}

// A tying BLOCK appends its refined nodes after the other rule's; an
// outranking one replaces what the losing severity collected (the
// firstTaxonomy/appendTaxonomy contract the static path keeps).
func TestStructuralTaxonomyFromSeverityContract4665(t *testing.T) {
	const pkg = "credential-exposure/package-registry/package-manager-credential-access"
	const other = "credential-exposure/config-file-access/generic-config-access"
	audit := MCPStructuralRule{
		ID: "synthetic-audit", Taxonomy: other, Decision: policy.DecisionAudit,
		Match: MCPStructuralMatch{ToolNameRegex: ".*", ArgsMatch: credPathArgs("file")},
	}
	tie := audit
	tie.ID, tie.Decision = "synthetic-tie", policy.DecisionBlock
	refined := taxonomyFromRule("synthetic-refined", TaxonomyFromMatchedPath, credPathArgs("file"))
	args := map[string]interface{}{"file": "/home/u/.pypirc"}

	outranks := NewPolicyEvaluator(&MCPPolicy{StructuralRules: []MCPStructuralRule{audit, refined}}).
		EvaluateToolCall("read_file", args)
	if !reflect.DeepEqual(outranks.TaxonomyRefs, []string{pkg}) {
		t.Errorf("outranking: taxonomy %v, want [%s]", outranks.TaxonomyRefs, pkg)
	}
	ties := NewPolicyEvaluator(&MCPPolicy{StructuralRules: []MCPStructuralRule{tie, refined}}).
		EvaluateToolCall("read_file", args)
	if want := []string{other, pkg}; !reflect.DeepEqual(ties.TaxonomyRefs, want) {
		t.Errorf("tie: taxonomy %v, want %v", ties.TaxonomyRefs, want)
	}
}

// Every shipped taxonomy_from is a value the evaluator knows. An unknown one
// is ignored at runtime (the static node is recorded, see above), so a typo
// in a pack would silently undo the refinement it asks for.
func TestShippedTaxonomyFromValuesAreKnown4665(t *testing.T) {
	known := map[string]bool{"": true, TaxonomyFromMatchedPath: true}
	checked, optedIn := 0, 0
	for _, dir := range []string{mcpPacksDir(), premiumMCPPacksDir()} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
		for _, file := range files {
			if strings.HasPrefix(filepath.Base(file), "_") {
				continue
			}
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read %s: %v", file, err)
			}
			var pack MCPPolicy
			if err := yaml.Unmarshal(data, &pack); err != nil {
				t.Fatalf("parse %s: %v", file, err)
			}
			for _, r := range pack.StructuralRules {
				checked++
				if r.TaxonomyFrom != "" {
					optedIn++
				}
				if !known[r.TaxonomyFrom] {
					t.Errorf("%s: rule %s has taxonomy_from %q; known values: %q",
						filepath.Base(file), r.ID, r.TaxonomyFrom, TaxonomyFromMatchedPath)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no structural rules read: the ratchet checked nothing")
	}
	t.Logf("%d structural rules checked, %d with taxonomy_from", checked, optedIn)
}
