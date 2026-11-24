package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"gopkg.in/yaml.v3"
)

// #5001 part A, through the real entry points: an id listed in the shell
// policy's disable_rules (~/.agentshield/policy.yaml, what `agentshield rule
// disable` writes) switches that rule off as a tool-call rule too, on the
// hook's tool path, mcp-eval and both MCP proxies (shield-server has its own
// test in cmd/shield-server). These tests use only symbols that exist on main,
// so they also run there, where every "listed" row fails: main's tool-call
// surfaces never read the list.
//
// A managed host mirrors the shell side surface by surface (see
// toolCallShellPolicy): the hook ignores the local list on a managed host
// (dropLocalDisablesWhenManaged), and so do its tool path and the proxies;
// `agentshield check` honours it there, and so does mcp-eval, its tool-call
// twin. The twin rows below pin both shell sides so the two cannot drift.

const (
	dtTool      = "zz5001_probe" // invented: no shipped rule names it
	dtMeterTool = "zz5001_meter"
	dtBlock     = "zz5001-block-probe"
	dtAudit     = "zz5001-audit-probe"
	dtCap       = "zz5001-cap-units"
	dtShellRule = "zz5001-shell-block"
	dtShellCmd  = "zz5001-shell now"
)

var dtPackRules = []struct{ id, yaml string }{
	{dtBlock, `  - id: zz5001-block-probe
    taxonomy: "zz5001/test/held-target"
    match:
      tool_name: zz5001_probe
      argument_patterns:
        target: "held-*"
    decision: BLOCK
    reason: "zz5001: a held target"
`},
	{dtAudit, `  - id: zz5001-audit-probe
    match:
      tool_name: zz5001_probe
    decision: AUDIT
    reason: "zz5001: every probe is recorded"
`},
}

const dtCapYAML = `  - id: zz5001-cap-units
    tool_pattern: zz5001_meter
    argument: units
    max: 10
    decision: BLOCK
    reason: "zz5001: units over the cap"
`

// dtPackYAML is the test's disk MCP pack, without the rules named in without:
// the oracle for "the call falls to whatever the engine decides without it" is
// the same call on a home where the rule was deleted rather than listed.
func dtPackYAML(without ...string) string {
	skip := map[string]bool{}
	for _, id := range without {
		skip[id] = true
	}
	var b strings.Builder
	b.WriteString("name: zz5001\ndescription: \"#5001 test rules\"\nversion: 1.0.0\nrules:\n")
	for _, r := range dtPackRules {
		if !skip[r.id] {
			b.WriteString(r.yaml)
		}
	}
	if !skip[dtCap] {
		b.WriteString("value_limits:\n" + dtCapYAML)
	}
	return b.String()
}

type dtOpts struct {
	list         []string // the shell policy's disable_rules; nil writes no key
	without      []string // pack rules deleted (the oracle)
	managed      bool     // managed.json {"managed": true}, fail_closed off
	mcpPolicyKey []string // disable_rules written into mcp-policy.yaml instead
	customerPack bool     // the #4645 customer protected-path pack (ppPack)
}

// dtHome is a scratch HOME in enforce mode with the test pack in mcp-packs/
// and a policy.yaml holding one shell rule (the twin) and the list.
func dtHome(t *testing.T, o dtOpts) string {
	t.Helper()
	home := proxyHome(t, "mode: enforce\n")
	dir := filepath.Join(home, ".agentshield")
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(mcp.DefaultMCPPacksDir, "zz5001.yaml"), dtPackYAML(o.without...))
	pol := map[string]interface{}{
		"version": "0.1",
		"rules": []map[string]interface{}{{
			"id":       dtShellRule,
			"match":    map[string]interface{}{"command_regex": `^zz5001-shell\b`},
			"decision": "BLOCK",
			"reason":   "zz5001: the shell twin",
		}},
	}
	if o.list != nil {
		pol["disable_rules"] = o.list
	}
	out, err := yaml.Marshal(pol)
	if err != nil {
		t.Fatal(err)
	}
	write("policy.yaml", string(out))
	if o.mcpPolicyKey != nil {
		mp, err := yaml.Marshal(map[string]interface{}{
			"defaults":      map[string]interface{}{"decision": "AUDIT"},
			"disable_rules": o.mcpPolicyKey,
		})
		if err != nil {
			t.Fatal(err)
		}
		write(mcp.DefaultMCPPolicyFile, string(mp))
	}
	if o.customerPack {
		write(filepath.Join("packs", "co-acme.yaml"), ppPack)
	}
	if o.managed {
		write("managed.json", `{"managed": true}`)
	}
	return home
}

// dtRecord is what a harness and an auditor see of one hook run.
type dtRecord struct {
	Code     int
	Decision interface{}
	Rules    interface{}
	Reasons  interface{}
	Taxonomy interface{}
	Original interface{}
}

func dtHookRun(t *testing.T, home, tool string, input map[string]interface{}) (dtRecord, string) {
	t.Helper()
	inv := invokeAgentshield(t, home, []string{"agentshield", "hook"}, stdinPipe, ppPayload(tool, input))
	rec := lastHookRecord(t, home)
	return dtRecord{inv.code, rec["decision"], rec["triggered_rules"], rec["reasons"], rec["taxonomy"], rec["original_decision"]}, inv.stderr
}

func (r dtRecord) has(id string) bool {
	list, _ := r.Rules.([]interface{})
	for _, x := range list {
		if x == id {
			return true
		}
	}
	return false
}

func dtHeld() map[string]interface{} { return map[string]interface{}{"target": "held-1"} }

// The hook's tool path: a listed BLOCK rule decides exactly as if it had been
// deleted, an unlisted rule on the same call is unchanged, and the bare-name
// reading of an mcp__ tool (#4351) honours the list too.
func TestDisableRules5001_HookToolPath(t *testing.T) {
	for _, tool := range []string{dtTool, "mcp__zz__" + dtTool} {
		t.Run(tool, func(t *testing.T) {
			base, _ := dtHookRun(t, dtHome(t, dtOpts{}), tool, dtHeld())
			if base.Code != 2 || base.Decision != "BLOCK" || !base.has(dtBlock) {
				t.Fatalf("setup, no list: %+v; want exit 2, BLOCK by %s", base, dtBlock)
			}

			listed, _ := dtHookRun(t, dtHome(t, dtOpts{list: []string{dtBlock}}), tool, dtHeld())
			deleted, _ := dtHookRun(t, dtHome(t, dtOpts{without: []string{dtBlock}}), tool, dtHeld())
			if listed.Code != 0 || listed.Decision != "AUDIT" || listed.has(dtBlock) || !listed.has(dtAudit) {
				t.Errorf("listed %s: %+v; want exit 0, AUDIT by %s only", dtBlock, listed, dtAudit)
			}
			if !reflect.DeepEqual(listed, deleted) {
				t.Errorf("listed is not the deleted rule's decision:\n  listed  %+v\n  deleted %+v", listed, deleted)
			}

			// The unlisted BLOCK rule keeps deciding when only its neighbour
			// is listed, exactly as with that neighbour deleted.
			other, _ := dtHookRun(t, dtHome(t, dtOpts{list: []string{dtAudit}}), tool, dtHeld())
			otherDeleted, _ := dtHookRun(t, dtHome(t, dtOpts{without: []string{dtAudit}}), tool, dtHeld())
			if other.Code != 2 || other.Decision != "BLOCK" || !other.has(dtBlock) || !reflect.DeepEqual(other, otherDeleted) {
				t.Errorf("listed %s: %+v (deleted: %+v); want %s's BLOCK unchanged", dtAudit, other, otherDeleted, dtBlock)
			}
		})
	}
}

// On a managed host the hook ignores the local list on its tool path, as its
// shell path does (twin row: the shell rule listed beside it still fires, and
// the hook says it ignored the list). Unmanaged control: the same files switch
// both off.
func TestDisableRules5001_HookToolPath_ManagedIgnoresLocalList(t *testing.T) {
	list := []string{dtBlock, dtShellRule}
	for _, managed := range []bool{true, false} {
		home := dtHome(t, dtOpts{list: list, managed: managed})
		tool, _ := dtHookRun(t, home, dtTool, dtHeld())
		shell, stderr := dtHookRun(t, home, "Bash", map[string]interface{}{"command": dtShellCmd})
		if managed {
			if tool.Code != 2 || !tool.has(dtBlock) {
				t.Errorf("managed, tool call: %+v; want exit 2, BLOCK by %s although the local list names it", tool, dtBlock)
			}
			if shell.Code != 2 || !shell.has(dtShellRule) || !strings.Contains(stderr, "ignoring local disable_rules") {
				t.Errorf("managed, shell twin: %+v (stderr %q); want the hook's shell path to ignore the list too", shell, stderr)
			}
			continue
		}
		if tool.Code != 0 || tool.has(dtBlock) {
			t.Errorf("unmanaged control, tool call: %+v; want %s switched off", tool, dtBlock)
		}
		if shell.has(dtShellRule) {
			t.Errorf("unmanaged control, shell twin: %+v; want %s switched off", shell, dtShellRule)
		}
	}
}

// The hint a tool-call BLOCK prints is now true: running the command it names
// (in the same profile) switches the rule off, and the next identical call
// decides as if the rule were deleted.
func TestDisableRules5001_BlockHintSwitchesTheRuleOff(t *testing.T) {
	home := dtHome(t, dtOpts{})
	first, stderr := dtHookRun(t, home, dtTool, dtHeld())
	if first.Code != 2 {
		t.Fatalf("setup: %+v; want exit 2", first)
	}
	m := regexp.MustCompile(`(?m)^\s*agentshield (rule disable \S+)\s*$`).FindStringSubmatch(stderr)
	if m == nil {
		t.Fatalf("no `agentshield rule disable <id>` hint in the block message:\n%s", stderr)
	}
	argv := append([]string{"agentshield"}, strings.Fields(m[1])...)
	if argv[len(argv)-1] != dtBlock {
		t.Fatalf("the hint names %q, want the rule that decided, %s", argv[len(argv)-1], dtBlock)
	}
	if inv := invokeAgentshield(t, home, argv, stdinDevNull, ""); inv.code != 0 {
		t.Fatalf("%v: exit %d\n%s%s", argv, inv.code, inv.stdout, inv.stderr)
	}
	again, _ := dtHookRun(t, home, dtTool, dtHeld())
	deleted, _ := dtHookRun(t, dtHome(t, dtOpts{without: []string{dtBlock}}), dtTool, dtHeld())
	if again.Code != 0 || again.has(dtBlock) || !reflect.DeepEqual(again, deleted) {
		t.Errorf("after %v: %+v; want the deleted rule's decision %+v", argv, again, deleted)
	}
}

// Only the exact id switches a rule off: a prefix, a longer id, another case,
// surrounding whitespace, an empty entry and an id no rule has change
// nothing, on the tool path and on the shell twin.
func TestDisableRules5001_LookalikeAndUnknownIdsAreHarmless(t *testing.T) {
	lookalikes := []string{
		"zz5001-block", dtBlock + "-x", strings.ToUpper(dtBlock), "Zz5001-block-probe",
		dtBlock + " ", " " + dtBlock, dtBlock + "\t", "", "zz5001-no-such-rule", "*", "zz5001-*",
		"zz5001-shell", strings.ToUpper(dtShellRule),
	}
	base := dtHome(t, dtOpts{})
	home := dtHome(t, dtOpts{list: lookalikes})
	for _, c := range []struct {
		tool  string
		input map[string]interface{}
	}{
		{dtTool, dtHeld()},
		{"Bash", map[string]interface{}{"command": dtShellCmd}},
	} {
		want, _ := dtHookRun(t, base, c.tool, c.input)
		got, _ := dtHookRun(t, home, c.tool, c.input)
		if want.Code != 2 || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: with lookalikes %+v\n  without a list %+v; want identical BLOCKs", c.tool, got, want)
		}
	}
}

// The list is the shell policy's: the same key in mcp-policy.yaml is not read
// (no second list, no new MCP policy key).
func TestDisableRules5001_ListInTheMCPPolicyFileIsNotRead(t *testing.T) {
	got, _ := dtHookRun(t, dtHome(t, dtOpts{mcpPolicyKey: []string{dtBlock}}), dtTool, dtHeld())
	if got.Code != 2 || !got.has(dtBlock) {
		t.Errorf("disable_rules in mcp-policy.yaml: %+v; want %s's BLOCK unchanged", got, dtBlock)
	}
}

// protected-path is a Go check, not a YAML rule. The shell side never lets
// disable_rules reach it, so neither does the tool side: a customer protected
// path still BLOCKs the agent's Read and the shell's cat with it listed.
func TestDisableRules5001_ProtectedPathIsNotSwitchedOff(t *testing.T) {
	home := dtHome(t, dtOpts{customerPack: true, list: []string{policy.ProtectedPathRuleID}})
	for _, c := range []struct {
		tool  string
		input map[string]interface{}
	}{
		{"Read", map[string]interface{}{"file_path": ppSecret()}},
		{"Bash", map[string]interface{}{"command": ppCat(ppSecret())}},
	} {
		got, _ := dtHookRun(t, home, c.tool, c.input)
		if got.Code != 2 || !got.has(policy.ProtectedPathRuleID) {
			t.Errorf("%s with %s listed: %+v; want exit 2, BLOCK by it", c.tool, policy.ProtectedPathRuleID, got)
		}
	}
}

// mcpEval5001 runs `agentshield mcp-eval` on one call.
func mcpEval5001(t *testing.T, home, tool string, args map[string]interface{}) (int, mcp.MCPEvalResult) {
	t.Helper()
	enc, _ := json.Marshal(args)
	inv := invokeAgentshield(t, home, []string{"agentshield", "mcp-eval", "--tool", tool, "--json", string(enc), "--format", "json"}, stdinDevNull, "")
	var r mcp.MCPEvalResult
	if err := json.Unmarshal([]byte(inv.stdout), &r); err != nil {
		t.Fatalf("mcp-eval output: %v\n%s\nstderr: %s", err, inv.stdout, inv.stderr)
	}
	return inv.code, r
}

func has5001(rules []string, id string) bool {
	for _, r := range rules {
		if r == id {
			return true
		}
	}
	return false
}

// mcp-eval: rules and value limits switched off by id; on a managed host it
// honours the list, as `agentshield check` (its shell twin) does there.
func TestDisableRules5001_MCPEval(t *testing.T) {
	meter := map[string]interface{}{"units": 50}

	code, r := mcpEval5001(t, dtHome(t, dtOpts{}), dtTool, dtHeld())
	if code != 2 || !has5001(r.TriggeredRules, dtBlock) {
		t.Fatalf("setup, no list: exit %d %s %v; want exit 2, BLOCK by %s", code, r.Decision, r.TriggeredRules, dtBlock)
	}
	if code, r := mcpEval5001(t, dtHome(t, dtOpts{}), dtMeterTool, meter); code != 2 || !has5001(r.TriggeredRules, dtCap) {
		t.Fatalf("setup, value limit: exit %d %s %v; want exit 2, BLOCK by %s", code, r.Decision, r.TriggeredRules, dtCap)
	}
	if inv := invokeAgentshield(t, dtHome(t, dtOpts{}), []string{"agentshield", "check", "--shell", dtShellCmd}, stdinDevNull, ""); inv.code != 2 || !strings.Contains(inv.stdout, dtShellRule) {
		t.Fatalf("setup, check twin without a list: exit %d\n%s; want exit 2, BLOCK by %s", inv.code, inv.stdout, dtShellRule)
	}

	for _, managed := range []bool{false, true} {
		home := dtHome(t, dtOpts{list: []string{dtBlock, dtCap, dtShellRule}, managed: managed})
		_, deleted := mcpEval5001(t, dtHome(t, dtOpts{without: []string{dtBlock}}), dtTool, dtHeld())
		code, r := mcpEval5001(t, home, dtTool, dtHeld())
		if code != 0 || r.Decision != policy.DecisionAudit || has5001(r.TriggeredRules, dtBlock) || !reflect.DeepEqual(r, deleted) {
			t.Errorf("managed=%v, listed rule: exit %d %+v; want the deleted rule's %+v", managed, code, r, deleted)
		}
		code, r = mcpEval5001(t, home, dtMeterTool, meter)
		if code != 0 || r.Decision == policy.DecisionBlock || has5001(r.TriggeredRules, dtCap) || has5001(r.TriggeredRules, "value-limit") {
			t.Errorf("managed=%v, listed value limit: exit %d %s %v; want it switched off", managed, code, r.Decision, r.TriggeredRules)
		}
		// The shell twin: `agentshield check` reads the same list on this host.
		if inv := invokeAgentshield(t, home, []string{"agentshield", "check", "--shell", dtShellCmd}, stdinDevNull, ""); inv.code != 0 || strings.Contains(inv.stdout, dtShellRule) {
			t.Errorf("managed=%v, check twin: exit %d\n%s; want %s switched off (check honours the list on this host)", managed, inv.code, inv.stdout, dtShellRule)
		}
	}

	if code, r := mcpEval5001(t, dtHome(t, dtOpts{list: []string{dtAudit}}), dtTool, dtHeld()); code != 2 || !has5001(r.TriggeredRules, dtBlock) {
		t.Errorf("unlisted BLOCK rule: exit %d %s %v; want it unchanged", code, r.Decision, r.TriggeredRules)
	}
}

func dtToolsCall(tool string, args map[string]interface{}) string {
	b, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": map[string]interface{}{"name": tool, "arguments": args}})
	return string(b)
}

func dtServed(resp string) bool {
	return strings.Contains(resp, `"served"`) && !strings.Contains(resp, `"error"`)
}

// The stdio MCP proxy reads the list at startup; a managed host ignores it, as
// the hook does.
func TestDisableRules5001_StdioProxy(t *testing.T) {
	probe := dtToolsCall(dtTool, dtHeld())
	meter := dtToolsCall(dtMeterTool, map[string]interface{}{"units": 50})
	for _, c := range []struct {
		name   string
		o      dtOpts
		req    string
		served bool
	}{
		{"no list", dtOpts{}, probe, false},
		{"rule listed", dtOpts{list: []string{dtBlock}}, probe, true},
		{"neighbour listed", dtOpts{list: []string{dtAudit}}, probe, false},
		{"value limit, no list", dtOpts{}, meter, false},
		{"value limit listed", dtOpts{list: []string{dtCap}}, meter, true},
		{"managed: list ignored", dtOpts{list: []string{dtBlock}, managed: true}, probe, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			home := dtHome(t, c.o)
			resp := runStdioProxy(t, home, c.req)
			if dtServed(resp) != c.served {
				t.Fatalf("served = %v; want %v. response: %s", dtServed(resp), c.served, resp)
			}
			if c.served && c.req == probe {
				// The record is the deleted rule's: same decision, rules,
				// reasons and taxonomy.
				ev := lastProxyAudit(t, home, dtTool)
				deletedHome := dtHome(t, dtOpts{without: []string{dtBlock}})
				if resp := runStdioProxy(t, deletedHome, probe); !dtServed(resp) {
					t.Fatalf("oracle (rule deleted): not served: %s", resp)
				}
				want := lastProxyAudit(t, deletedHome, dtTool)
				for _, k := range []string{"decision", "triggered_rules", "reasons", "taxonomy", "taxonomy_ref", "original_decision"} {
					if !reflect.DeepEqual(ev[k], want[k]) {
						t.Errorf("record %s = %v; the deleted rule's is %v", k, ev[k], want[k])
					}
				}
				if ev["decision"] != "AUDIT" {
					t.Errorf("record decision %v, want AUDIT", ev["decision"])
				}
			}
		})
	}
}

// The HTTP MCP proxy, the same contract.
func TestDisableRules5001_HTTPProxy(t *testing.T) {
	probe := dtToolsCall(dtTool, dtHeld())
	for _, c := range []struct {
		name    string
		o       dtOpts
		req     string
		reached bool
	}{
		{"no list", dtOpts{}, probe, false},
		{"rule listed", dtOpts{list: []string{dtBlock}}, probe, true},
		{"neighbour listed", dtOpts{list: []string{dtAudit}}, probe, false},
		{"value limit listed", dtOpts{list: []string{dtCap}}, dtToolsCall(dtMeterTool, map[string]interface{}{"units": 50}), true},
		{"managed: list ignored", dtOpts{list: []string{dtBlock}, managed: true}, probe, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if out, reached := runHTTPProxyOnce(t, dtHome(t, c.o), c.req); reached != c.reached {
				t.Errorf("reached upstream = %v; want %v. response: %s", reached, c.reached, out)
			}
		})
	}
}
