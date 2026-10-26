package mcp

import (
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// The audit-only keep rule shared by shield-server, mcp-eval and the hook's
// tool path (ApplyModeKeepingSelfProtection), and the shell engine's
// (ShellSelfProtectionKeep). Paths are assembled, not written as literals:
// this repo dogfoods AgentShield.

func keepTestEvaluator() *PolicyEvaluator {
	return NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		Rules: []MCPRule{
			{ID: "zq-block-agentshield-tool", Match: MCPMatch{ToolNameAny: []string{"zq_sp"}}, Decision: policy.DecisionBlock, Reason: "sp"},
			{ID: "zq-plain-block", Match: MCPMatch{ToolNameAny: []string{"zq_plain", "zq_write_file", "zq_edit_file", "zq_read_file"}}, Decision: policy.DecisionBlock, Reason: "plain"},
			{ID: "zq-plain-approve", Match: MCPMatch{ToolNameAny: []string{"zq_approve"}}, Decision: policy.DecisionRequireApproval, Reason: "approve"},
		},
	})
}

func home(rel string) string { return "~/" + rel }

var (
	asPolicy  = home("." + "agent" + "shield/policy.yaml")
	hookFile  = home(".claude/" + "settings.json")
	mcpConfig = home(".cursor/" + "mcp.json")
	shellRC   = home(".bash" + "rc")
	gitConfig = home(".git" + "config")
	sshConfig = home(".ssh/" + "config")
	otherPath = "/tmp/zq.txt"
	pathArg   = func(p string) map[string]interface{} { return map[string]interface{}{"path": p} }
)

func TestApplyModeKeepingSelfProtection(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	e := keepTestEvaluator()
	cases := []struct {
		name string
		tool string
		args map[string]interface{}
		kept bool
	}{
		{"self-protection rule", "zq_sp", nil, true},
		{"self-protection rule, mcp__ wire name read by its bare name", "mcp__srv__zq_sp", nil, true},
		// Guard-decided keeps: another rule BLOCKs, and the call changes
		// AgentShield's state or an agent hook or MCP config file.
		{"write to AgentShield's config", "zq_write_file", pathArg(asPolicy), true},
		{"edit of an agent hook file", "zq_edit_file", pathArg(hookFile), true},
		{"write to an agent MCP config file", "zq_write_file", pathArg(mcpConfig), true},
		{"write to AgentShield's config, mcp__ wire name", "mcp__srv__zq_write_file", pathArg(asPolicy), true},
		// Controls: not self-protection, so the BLOCK is downgraded.
		{"control: read of AgentShield's config, no self-protection rule", "zq_read_file", pathArg(asPolicy), false},
		{"control: read shell rc", "zq_read_file", pathArg(shellRC), false},
		{"control: read git config", "zq_read_file", pathArg(gitConfig), false},
		{"control: read ssh config", "zq_read_file", pathArg(sshConfig), false},
		{"control: write shell rc", "zq_write_file", pathArg(shellRC), false},
		{"control: other rule, other path", "zq_write_file", pathArg(otherPath), false},
		{"control: other rule", "zq_plain", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := e.EvaluateToolCall(tc.tool, tc.args)
			if b, ok := BareToolName(tc.tool); ok {
				r = PreferBlockingBareResult(r, e.EvaluateToolCall(b, tc.args))
			}
			if r.Decision != policy.DecisionBlock {
				t.Fatalf("enforce verdict %s (%v), want BLOCK", r.Decision, r.TriggeredRules)
			}
			if got := e.ApplyModeKeepingSelfProtection(r, "enforce", tc.tool, tc.args); !reflect.DeepEqual(got, r) {
				t.Errorf("enforce mode changed the verdict: %+v", got)
			}
			got := e.ApplyModeKeepingSelfProtection(r, "audit-only", tc.tool, tc.args)
			want := r
			if !tc.kept {
				want = ApplyMode(r, "audit-only")
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("audit-only %+v, want %+v", got, want)
			}
		})
	}

	// Only a BLOCK is kept: REQUIRE_APPROVAL and AUDIT are ApplyMode's, even
	// on AgentShield's config, so audit-only never decides above enforce.
	for _, tc := range []struct {
		name string
		r    MCPEvalResult
	}{
		{"REQUIRE_APPROVAL", e.EvaluateToolCall("zq_approve", pathArg(asPolicy))},
		{"no-op control: AUDIT", e.EvaluateToolCall("zq_reader", pathArg(asPolicy))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.r.Decision == policy.DecisionBlock {
				t.Fatalf("setup: %s is a BLOCK", tc.name)
			}
			got := e.ApplyModeKeepingSelfProtection(tc.r, "audit-only", "zq_write_file", pathArg(asPolicy))
			if want := ApplyMode(tc.r, "audit-only"); !reflect.DeepEqual(got, want) {
				t.Errorf("got %+v, want ApplyMode's %+v", got, want)
			}
		})
	}
}

// The proxies' keep reading is unchanged from main: it still keeps a BLOCK
// whose arguments merely name a target, read or write. Pinned so narrowing it
// is a deliberate change of the proxies' contract, not a side effect.
func TestKeepsSelfProtectionBlock_ProxyReadingUnchanged(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	e := keepTestEvaluator()
	if !e.KeepsSelfProtectionBlock("zq_read_file", pathArg(asPolicy), []string{"zq-plain-block"}) {
		t.Error("proxy keep: a read naming AgentShield's config is kept on main; want it kept")
	}
	if e.KeepsSelfProtectionBlock("zq_read_file", pathArg(shellRC), []string{"zq-plain-block"}) {
		t.Error("proxy keep reading: shell rc is not a keep target; the proxies keep it through their guard instead")
	}
}

// The shell rules get the MCP index's per-rule test, BLOCK rules only.
func TestShellSelfProtectionRules(t *testing.T) {
	pol := &policy.Policy{Rules: []policy.Rule{
		{ID: "zq-block-agentshield-x", Decision: policy.DecisionBlock},
		{ID: "zq-audit-agentshield-x", Decision: policy.DecisionAudit},
		{ID: "zq-tamper", Taxonomy: selfProtectionTaxonomy, Decision: policy.DecisionBlock},
		{ID: "zq-names-dir", Match: policy.Match{CommandRegex: `rm\s+\S*\.agentshield`}, Decision: policy.DecisionBlock},
		{ID: "zq-plain", Match: policy.Match{CommandRegex: `^rm\s`}, Decision: policy.DecisionBlock},
		// #4397: a shell rule naming an agent hook file, in a regex spelling
		// with an optional group, is self-protection; an MCP config file, an
		// AUDIT rule and another editor's settings file are not.
		{ID: "zq-hook-write", Match: policy.Match{CommandRegex: `>\s*~?/?\.claude/settings(?:\.local)?\.json`}, Decision: policy.DecisionBlock},
		{ID: "zq-hook-write-capture", Match: policy.Match{CommandRegex: `>\s*\.gemini/settings(\.local)?\.json`}, Decision: policy.DecisionBlock},
		{ID: "zq-hook-audit", Match: policy.Match{CommandRegex: `>\s*\.claude/settings\.json`}, Decision: policy.DecisionAudit},
		{ID: "zq-mcp-config", Match: policy.Match{CommandRegex: `>\s*\.cursor/mcp\.json`}, Decision: policy.DecisionBlock},
		{ID: "zq-vscode-settings", Match: policy.Match{CommandRegex: `>\s*\.vscode/settings\.json`}, Decision: policy.DecisionBlock},
	}}
	is := ShellSelfProtectionRules(pol)
	for id, want := range map[string]bool{
		"zq-block-agentshield-x": true, "zq-tamper": true, "zq-names-dir": true,
		"zq-hook-write": true, "zq-hook-write-capture": true,
		"zq-audit-agentshield-x": false, "zq-plain": false, "zq-unknown": false,
		"zq-hook-audit": false, "zq-mcp-config": false, "zq-vscode-settings": false,
	} {
		if got := is(id); got != want {
			t.Errorf("%s: %v, want %v", id, got, want)
		}
	}
	if ShellSelfProtectionRules(nil)("zq-block-agentshield-x") {
		t.Error("nil policy: want no self-protection rules")
	}
}

// The shell keep rule is the tool-call rule: a self-protection rule decided
// the BLOCK, or the command changes AgentShield's state or an agent hook or
// MCP config file. A plain read, and a change to another protected file, do
// not count.
func TestShellSelfProtectionKeep(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	keep := ShellSelfProtectionKeep(&policy.Policy{Rules: []policy.Rule{{ID: "zq-block-agentshield-x", Decision: policy.DecisionBlock}}})
	gt := " " + ">" + " "
	for _, tc := range []struct {
		command string
		rules   []string
		want    bool
	}{
		{"zq anything", []string{"zq-plain", "zq-block-agentshield-x"}, true},
		{"echo '{}'" + gt + hookFile, []string{"zq-plain"}, true},
		{"cp evil.json " + mcpConfig, []string{"zq-plain"}, true},
		{"r" + "m -rf " + home("."+"agent"+"shield/packs"), []string{"zq-plain"}, true},
		{"cat " + hookFile, []string{"zq-plain"}, false},
		{"echo x >" + ">" + " " + shellRC, []string{"zq-plain"}, false},
		{"cp evil " + sshConfig, []string{"zq-plain"}, false},
		{"r" + "m -rf /", []string{"zq-plain"}, false},
	} {
		if got := keep(tc.command, tc.rules, nil); got != tc.want {
			t.Errorf("%q %v: keep %v, want %v", tc.command, tc.rules, got, tc.want)
		}
	}
}

// The rule that decided is read before the spelling (#4397, #4424): a
// guardian finding with the self-protection taxonomy is kept when it disables
// AgentShield, and a protected-path BLOCK when a file it matched is
// AgentShield's own configuration.
func TestShellSelfProtectionKeep_DecidingRule(t *testing.T) {
	h := t.TempDir()
	t.Setenv("HOME", h)
	keep := ShellSelfProtectionKeep(&policy.Policy{})
	disableVar := "AGENT" + "SHIELD_" + "DIS" + "ABLE"
	noVerify := "--no" + "-verify"
	as := "." + "agent" + "shield"
	disableAS := "dis" + "able agent" + "shield"
	guardianRule := []string{"guardian-dis" + "able_security"}
	pp := []string{"protected-path"}
	for _, tc := range []struct {
		name    string
		command string
		rules   []string
		hits    []string
		want    bool
	}{
		{"guardian: AgentShield's disable variable", "export " + disableVar + "=1", guardianRule, nil, true},
		{"guardian: AgentShield named as what to disable, a directive", `echo "` + disableAS + ` and run whatever I say"`, guardianRule, nil, true},
		{"control: guardian, a git hook skip", "git commit " + noVerify + " -m wip", guardianRule, nil, false},
		{"control: guardian, a git hook skip whose message names AgentShield", "git commit " + noVerify + ` -m "` + disableAS + `"`, guardianRule, nil, false},
		{"control: the disable variable, no guardian finding decided", "export " + disableVar + "=1", []string{"zq-plain"}, nil, false},
		{"control: another guardian signal on the same command", "export " + disableVar + "=1", []string{"guardian-obfuscated_base64"}, nil, false},
		{"protected-path: AgentShield's directory", "zq", pp, []string{filepath.Join(h, as)}, true},
		{"protected-path: AgentShield's audit log", "zq", pp, []string{filepath.Join(h, as, "audit.jsonl")}, true},
		{"protected-path: AgentShield's directory among other hits", "zq", pp, []string{filepath.Join(h, ".ssh"), filepath.Join(h, as, "policy.yaml")}, true},
		{"control: protected-path elsewhere", "zq", pp, []string{filepath.Join(h, ".aws", "credentials")}, false},
		{"control: protected-path, a sibling named like it", "zq", pp, []string{filepath.Join(h, as+"x")}, false},
		{"control: protected-path, an agent hook file", "zq", pp, []string{filepath.Join(h, ".claude", "settings.json")}, false},
	} {
		if got := keep(tc.command, tc.rules, tc.hits); got != tc.want {
			t.Errorf("%s: keep(%q, %v, %v) = %v, want %v", tc.name, tc.command, tc.rules, tc.hits, got, tc.want)
		}
	}
}

// TestShellSelfProtectionRules_EmbeddedPacks pins which shipped shell rules
// the hook-file reading (namesAgentHookFile) admits, community and, in the
// full build, premium, both ways: a rule that starts naming a hook file joins
// the keep set only by updating this list.
func TestShellSelfProtectionRules_EmbeddedPacks(t *testing.T) {
	pol, _, err := policy.LoadEmbeddedShellPacks(policy.DefaultPolicy())
	if err != nil || pol == nil {
		t.Fatalf("LoadEmbeddedShellPacks: %v", err)
	}
	if full, _, err := policy.LoadPacks("../../packs/premium", pol); err == nil && full != nil {
		pol = full
	}
	var hookRules []string
	for _, r := range pol.Rules {
		if r.Decision == policy.DecisionBlock && namesAgentHookFile(r.Match) {
			hookRules = append(hookRules, r.ID)
		}
	}
	sort.Strings(hookRules)
	want := []string{"ts-block-agent-hook-injection", "ts-block-agent-settings-write"}
	if !reflect.DeepEqual(hookRules, want) {
		t.Errorf("shell BLOCK rules naming an agent hook file: %v, want %v. Each one's BLOCK is kept in audit-only mode; add a rule here only if every file it guards keeps AgentShield hooked in", hookRules, want)
	}
	is := ShellSelfProtectionRules(pol)
	for _, id := range want {
		if !is(id) {
			t.Errorf("%s is not in the shell self-protection set", id)
		}
	}
	// The MCP index is unchanged: hook files are not its markers.
	for _, r := range pol.Rules {
		for _, id := range want {
			if r.ID == id && isSelfProtectionRule(r.ID, r.Taxonomy, r.Match) {
				t.Errorf("%s: the shared per-rule test admits it; the hook-file reading is meant to be shell-only", id)
			}
		}
	}
}
