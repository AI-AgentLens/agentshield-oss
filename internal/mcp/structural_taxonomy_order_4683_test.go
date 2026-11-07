package mcp

import (
	"reflect"
	"sort"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4683 item 3: values reached through nested arrays under several top-level
// keys come out of map walks, so the order of a matched-path rule's taxonomy
// list varied run to run (3 orders in 15 runs) while the set did not. The
// list is sorted, so it is one list.
func TestStructuralTaxonomyFromOrderIsDeterministic4683(t *testing.T) {
	const pkg = "credential-exposure/package-registry/package-manager-credential-access"
	args := map[string]interface{}{
		"a": []interface{}{map[string]interface{}{"file": "/home/u/.ssh/id_rsa"}},
		"b": []interface{}{map[string]interface{}{"file": "/home/u/.pypirc"}},
		"c": []interface{}{map[string]interface{}{"file": "/home/u/.azure"}},
	}
	want := []string{policy.ProtectedPathNode, pkg, taxonomyFromStaticNode}
	if !sort.StringsAreSorted(want) {
		t.Fatalf("control: the expectation must itself be sorted: %v", want)
	}
	ev := NewPolicyEvaluator(&MCPPolicy{StructuralRules: []MCPStructuralRule{
		taxonomyFromRule("synthetic-order", TaxonomyFromMatchedPath, credPathArgs("file")),
	}})
	for i := 0; i < 60; i++ {
		got := ev.EvaluateToolCall("read_file", args)
		if got.Decision != policy.DecisionBlock {
			t.Fatalf("control: the rule must fire, got %s", got.Decision)
		}
		if !reflect.DeepEqual(got.TaxonomyRefs, want) {
			t.Fatalf("run %d: taxonomy %v, want %v", i, got.TaxonomyRefs, want)
		}
	}
}
