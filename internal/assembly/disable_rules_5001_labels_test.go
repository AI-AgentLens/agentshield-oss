package assembly

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #5001 fix round: the list decides which rules can MATCH. It never changes
// what a receipt resolves. Go checks on the tool-call side reach a YAML rule
// in three ways other than matching it, and each must answer the same with
// the rule listed as without:
//   - LookupSentinel(engine): the sentinel a Go check labels its finding with,
//     and that finding's taxonomy node (sentinelTaxonomyRef);
//   - RuleTaxonomyRefs(ids): the proxies' audit sink fills a record that names
//     rules but carries no node from it (withRuleTaxonomy, #4734): the
//     rug-pull, schema-drift and description-scan records;
//   - IsSelfProtectionRule(id): audit-only mode keeps a BLOCK whose rules
//     include one (KeepsSelfProtectionBlock, ApplyModeKeepingSelfProtection).
// The set of ids is built from the code and the packs, not copied by hand.

// declaredMCPPolicy is the MCP policy a premium install loads: the defaults,
// the embedded community packs, then packs/premium/mcp when present.
func declaredMCPPolicy(t *testing.T) (*mcp.MCPPolicy, bool) {
	t.Helper()
	p, _, err := mcp.LoadEmbeddedMCPPacks(mcp.DefaultMCPPolicy())
	if err != nil {
		t.Fatal(err)
	}
	premium := filepath.Join("..", "..", "packs", "premium", "mcp")
	if _, err := os.Stat(premium); err != nil {
		return p, false
	}
	merged, _, err := mcp.LoadMCPPacks(premium, p)
	if err != nil {
		t.Fatal(err)
	}
	return merged, true
}

// goStringLiterals is every string literal in the non-test Go files of the
// tool-call surfaces: internal/mcp, internal/cli and cmd/shield-server.
func goStringLiterals(t *testing.T) map[string]bool {
	t.Helper()
	lits := map[string]bool{}
	files := 0
	for _, dir := range []string{"../mcp", "../cli", "../../cmd/shield-server"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			files++
			ast.Inspect(f, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if s, err := strconv.Unquote(lit.Value); err == nil {
						lits[s] = true
					}
				}
				return true
			})
		}
	}
	if files < 100 {
		t.Fatalf("parsed %d Go files: the walk lost the source", files)
	}
	return lits
}

// goNamedRule is a YAML rule a Go check reaches without matching it.
type goNamedRule struct {
	id, family, engine string
}

// goNamedRules is every sentinel (engine:) and every rule of any id-bearing
// family whose id the tool-call Go code spells as a string literal.
func goNamedRules(t *testing.T, p *mcp.MCPPolicy) []goNamedRule {
	t.Helper()
	lits := goStringLiterals(t)
	var out []goNamedRule
	seen := map[string]bool{}
	add := func(id, family, engine string) {
		if seen[id] || (engine == "" && !lits[id]) {
			return
		}
		seen[id] = true
		out = append(out, goNamedRule{id, family, engine})
	}
	for _, r := range p.Rules {
		add(r.ID, "rules", r.Engine)
	}
	for _, r := range p.StructuralRules {
		add(r.ID, "structural_rules", "")
	}
	for _, r := range p.SemanticRules {
		add(r.ID, "semantic_rules", "")
	}
	for _, r := range p.ResourceRules {
		add(r.ID, "resource_rules", "")
	}
	for _, r := range p.ValueLimits {
		add(r.ID, "value_limits", "")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

// resolution is what a Go check can learn about a rule without matching it.
type resolution struct {
	taxonomy       []string
	sentinel       *mcp.MCPRule
	selfProtection bool
}

func resolve(ev *mcp.PolicyEvaluator, r goNamedRule) resolution {
	out := resolution{taxonomy: ev.RuleTaxonomyRefs([]string{r.id}), selfProtection: ev.IsSelfProtectionRule(r.id)}
	if r.engine != "" {
		if s := ev.LookupSentinel(r.engine); s != nil {
			c := *s
			out.sentinel = &c
		}
	}
	return out
}

func TestMCPEvaluator_ListedGoNamedRulesStillResolve5001(t *testing.T) {
	p, premium := declaredMCPPolicy(t)
	rules := goNamedRules(t, p)
	sentinels, labels := 0, 0
	var ids []string
	for _, r := range rules {
		ids = append(ids, r.id)
		if r.engine != "" {
			sentinels++
		} else {
			labels++
			t.Logf("Go-named, no engine: %s (%s)", r.id, r.family)
		}
	}
	t.Logf("%d Go-named rules: %d sentinels, %d without engine:", len(rules), sentinels, labels)
	// Vacuity floors. The rug-pull label is a community rule; every sentinel
	// is premium, so the OSS tree has none.
	if labels < 1 || (premium && sentinels < 100) {
		t.Fatalf("%d label rules, %d sentinels (premium %v): the set is not what this test measures", labels, sentinels, premium)
	}
	if !containsRule(ids, "mcp-sec-audit-tool-description-changed") {
		t.Fatal("the rug-pull label rule is not in the set: the literal walk or the pack load is broken")
	}

	base := MCPEvaluator(p, policy.ToolCallInputs{}, "")
	all := MCPEvaluator(p, policy.ToolCallInputs{DisableRules: ids}, "")
	for _, r := range rules {
		want := resolve(base, r)
		if got := resolve(MCPEvaluator(p, policy.ToolCallInputs{DisableRules: []string{r.id}}, ""), r); !reflect.DeepEqual(got, want) {
			t.Errorf("%s (%s) listed alone: resolves to %+v, unlisted %+v", r.id, r.family, got, want)
		}
		if got := resolve(all, r); !reflect.DeepEqual(got, want) {
			t.Errorf("%s (%s) listed with every Go-named id: resolves to %+v, unlisted %+v", r.id, r.family, got, want)
		}
	}
}

// The Go checks themselves, driven where a unit test can drive them: the
// rug-pull detection (a label rule without engine:) and the scheme-hijack scan
// (a sentinel). With the rule listed the check decides and records the same,
// rule id and taxonomy node included, the node filled as the proxies' sink
// fills it.
func TestMCPEvaluator_ListedGoNamedRulesKeepTheirChecksRecord5001(t *testing.T) {
	p, premium := declaredMCPPolicy(t)
	sinkFill := func(ev *mcp.PolicyEvaluator, e mcp.AuditEntry) mcp.AuditEntry {
		if len(e.TriggeredRules) > 0 && len(e.AllTaxonomyRefs()) == 0 {
			e.TaxonomyRefs = ev.RuleTaxonomyRefs(e.TriggeredRules)
		}
		e.Timestamp = ""
		return e
	}

	rugPull := func(list []string) []mcp.AuditEntry {
		ev := MCPEvaluator(p, policy.ToolCallInputs{DisableRules: list}, "")
		var got []mcp.AuditEntry
		h := &mcp.MessageHandler{Evaluator: ev, Stderr: io.Discard, ServerName: "zz5001",
			SchemaDrift: &mcp.SchemaDriftScanner{CacheDir: t.TempDir()},
			OnAudit:     func(e mcp.AuditEntry) { got = append(got, sinkFill(ev, e)) }}
		for _, desc := range []string{"Returns the current time.", "Returns the current date."} {
			resp, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": map[string]interface{}{"tools": []interface{}{
				map[string]interface{}{"name": "zz5001_clock", "description": desc, "inputSchema": map[string]interface{}{"type": "object"}}}}})
			h.FilterToolsListResponse(resp)
		}
		return got
	}
	const rugPullID = "mcp-sec-audit-tool-description-changed"
	want := rugPull(nil)
	found := false
	for _, e := range want {
		if containsRule(e.TriggeredRules, rugPullID) {
			found = true
			if !reflect.DeepEqual(e.TaxonomyRefs, []string{"unauthorized-execution/agentic-attacks/mcp-tool-rug-pull"}) {
				t.Fatalf("setup: rug-pull record %+v, want the rug-pull node", e)
			}
		}
	}
	if !found {
		t.Fatalf("setup: no %s record from a description change: %+v", rugPullID, want)
	}
	if got := rugPull([]string{rugPullID}); !reflect.DeepEqual(got, want) {
		t.Errorf("%s listed:\n  records %+v\n  want    %+v", rugPullID, got, want)
	}

	if !premium {
		t.Log("no premium packs: the scheme-hijack sentinel is not loaded, so only the rug-pull row ran")
		return
	}
	var sentinelID string
	for _, r := range p.Rules {
		if r.Engine == "mcp-filesystem-scheme-hijack" {
			sentinelID = r.ID
		}
	}
	if sentinelID == "" {
		t.Fatal("premium packs loaded but no scheme-hijack sentinel")
	}
	schemeHijack := func(list []string) (bool, mcp.AuditEntry) {
		ev := MCPEvaluator(p, policy.ToolCallInputs{DisableRules: list}, "")
		var got mcp.AuditEntry
		h := &mcp.MessageHandler{Evaluator: ev, Stderr: io.Discard, OnAudit: func(e mcp.AuditEntry) { got = sinkFill(ev, e) }}
		id := json.RawMessage(`"zz5001"`)
		// A remote scheme no YAML rule blocks first, so the Go scan decides.
		params, _ := json.Marshal(mcp.CallToolParams{Name: "read_file", Arguments: map[string]interface{}{"path": "ft" + "p://files.example.org/notes.txt"}})
		blocked, _ := h.HandleToolCall(&mcp.Message{JSONRPC: "2.0", ID: &id, Method: mcp.MethodToolsCall, Params: params})
		got.Arguments = nil
		return blocked, got
	}
	wantBlocked, wantRec := schemeHijack(nil)
	if !wantBlocked || !containsRule(wantRec.TriggeredRules, sentinelID) {
		t.Fatalf("setup: scheme hijack blocked=%v %+v, want a BLOCK labelled %s", wantBlocked, wantRec, sentinelID)
	}
	if blocked, rec := schemeHijack([]string{sentinelID}); blocked != wantBlocked || !reflect.DeepEqual(rec, wantRec) {
		t.Errorf("%s listed: blocked=%v %+v\n  want blocked=%v %+v", sentinelID, blocked, rec, wantBlocked, wantRec)
	}
}

// The other direction still holds: a listed rule that MATCHES does not fire,
// and its id is not on the record, even though its taxonomy stays resolvable.
func TestMCPEvaluator_ListedMatchingRuleStillOff5001(t *testing.T) {
	ev := MCPEvaluator(families5001(t), policy.ToolCallInputs{DisableRules: []string{"a5001-rule"}}, "")
	r := ev.EvaluateToolCall("a5001_rule", nil)
	if r.Decision == policy.DecisionBlock || containsRule(r.TriggeredRules, "a5001-rule") {
		t.Errorf("listed matching rule: %s %v; want it off and off the record", r.Decision, r.TriggeredRules)
	}
}
