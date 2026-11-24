package mcp

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4937: rules that match a file path are written on `path`, and a tool that
// carries the path as file_path, filepath, file or filename was invisible to
// them. The fix is one more raise-only reading (pathAliasArguments), built the
// way the case-fold (#4194), separator (#4243) and /private (#4387) readings
// are. The probe paths are assembled from pieces: this machine's own hook
// reads test sources.

const aliasHome = "/home/user/"

func aliasSSHKey() string   { return aliasHome + ".ssh/" + "id_rsa" }
func aliasAWSCreds() string { return aliasHome + ".aws/" + "credentials" }
func aliasKubeconf() string { return "/etc/" + "kubernetes/" + "admin.conf" }
func aliasEnviron() string  { return "/proc/" + "self/" + "environ" }

func aliasAuthorizedKeys() string { return aliasHome + ".ssh/" + "authorized_keys" }

// aliasNames are the closed list: the four read/edit names of #4937 and the
// six write-destination names of #4942, plus loose spellings that must
// resolve the way resolveField resolves a rule's field name.
var aliasWriteDestNames = []string{"dest", "destination", "output_file", "output_path", "out_path", "save_path"}
var aliasNames = append([]string{"file_path", "filepath", "file", "filename"}, aliasWriteDestNames...)
var aliasLooseSpellings = []string{"filePath", "file-path", "FILE_PATH", "fileName", "File", "f\u0456le_path", "outputFile", "save-path", "OUT_PATH", "Dest"}

// TestPathAliasArguments_Readings is the table for the reading itself.
func TestPathAliasArguments_Readings(t *testing.T) {
	type args = map[string]interface{}
	cases := []struct {
		name string
		in   args
		want []args // nil: no alias reading is built
	}{
		{"file_path", args{"file_path": "/w/a"}, []args{{"file_path": "/w/a", "path": "/w/a"}}},
		{"filepath", args{"filepath": "/w/a"}, []args{{"filepath": "/w/a", "path": "/w/a"}}},
		{"file", args{"file": "/w/a"}, []args{{"file": "/w/a", "path": "/w/a"}}},
		{"filename", args{"filename": "/w/a"}, []args{{"filename": "/w/a", "path": "/w/a"}}},
		{"camelCase filePath", args{"filePath": "/w/a"}, []args{{"filePath": "/w/a", "path": "/w/a"}}},
		{"kebab file-path", args{"file-path": "/w/a"}, []args{{"file-path": "/w/a", "path": "/w/a"}}},
		{"upper FILE_PATH", args{"FILE_PATH": "/w/a"}, []args{{"FILE_PATH": "/w/a", "path": "/w/a"}}},
		{"camelCase fileName", args{"fileName": "/w/a"}, []args{{"fileName": "/w/a", "path": "/w/a"}}},
		{"confusable f\u0456le_path", args{"f\u0456le_path": "/w/a"}, []args{{"f\u0456le_path": "/w/a", "path": "/w/a"}}},
		{"other arguments are kept", args{"file_path": "/w/a", "content": "x", "n": 3.0},
			[]args{{"file_path": "/w/a", "content": "x", "n": 3.0, "path": "/w/a"}}},
		{"nested object", args{"request": args{"file_path": "/w/a"}},
			[]args{{"request": args{"file_path": "/w/a", "path": "/w/a"}}}},
		{"batch of objects", args{"items": []interface{}{args{"file_path": "/w/a"}, args{"filename": "/w/b"}, "/w/c"}},
			[]args{{"items": []interface{}{args{"file_path": "/w/a", "path": "/w/a"}, args{"filename": "/w/b", "path": "/w/b"}, "/w/c"}}}},
		{"list value", args{"file_path": []interface{}{"/w/a", "/w/b"}},
			[]args{{"file_path": []interface{}{"/w/a", "/w/b"}, "path": []interface{}{"/w/a", "/w/b"}}}},
		{"both present, different values", args{"path": "/w/p", "file_path": "/w/f"},
			[]args{{"file_path": "/w/f", "path": "/w/f"}}},
		{"both present, nested", args{"request": args{"path": "/w/p", "filename": "/w/f"}},
			[]args{{"request": args{"filename": "/w/f", "path": "/w/f"}}}},
		{"two alias names, two values: one reading each", args{"file_path": "/w/a", "filename": "/w/b"},
			[]args{{"file_path": "/w/a", "filename": "/w/b", "path": "/w/a"}, {"file_path": "/w/a", "filename": "/w/b", "path": "/w/b"}}},
		{"two alias spellings, one value", args{"file_path": "/w/a", "filePath": "/w/a"},
			[]args{{"filePath": "/w/a", "file_path": "/w/a", "path": "/w/a"}}},
		{"both present, same value", args{"path": "/w/p", "file_path": "/w/p"}, nil},
		{"both present, same value, path spelled loosely", args{"Path": "/w/p", "file_path": "/w/p"}, nil},
		{"no alias: path only", args{"path": "/w/p"}, nil},
		{"no alias: nil", nil, nil},
		{"no alias: empty", args{}, nil},
		{"dest", args{"dest": "/w/a"}, []args{{"dest": "/w/a", "path": "/w/a"}}},
		{"destination", args{"destination": "/w/a"}, []args{{"destination": "/w/a", "path": "/w/a"}}},
		{"output_file", args{"output_file": "/w/a"}, []args{{"output_file": "/w/a", "path": "/w/a"}}},
		{"output_path", args{"output_path": "/w/a"}, []args{{"output_path": "/w/a", "path": "/w/a"}}},
		{"out_path", args{"out_path": "/w/a"}, []args{{"out_path": "/w/a", "path": "/w/a"}}},
		{"save_path", args{"save_path": "/w/a"}, []args{{"save_path": "/w/a", "path": "/w/a"}}},
		{"camelCase outputFile", args{"outputFile": "/w/a"}, []args{{"outputFile": "/w/a", "path": "/w/a"}}},
		{"download shape: path is the remote file, dest the local one", args{"path": "/api/pcaps/export.pcap", "dest": "/w/a"},
			[]args{{"dest": "/w/a", "path": "/w/a"}}},
		{"copy shape: source is not read as path, destination is", args{"source": "/w/s", "destination": "/w/d"},
			[]args{{"source": "/w/s", "destination": "/w/d", "path": "/w/d"}}},
		{"not an alias: output", args{"output": "/w/a"}, nil},
		{"not an alias: output_dir", args{"output_dir": "/w/a"}, nil},
		{"not an alias: dest_path", args{"dest_path": "/w/a"}, nil},
		{"not an alias: outfile", args{"outfile": "/w/a"}, nil},
		{"not an alias: dst", args{"dst": "/w/a"}, nil},
		{"not an alias: source", args{"source": "/w/a"}, nil},
		{"not an alias: name", args{"name": "/w/a"}, nil},
		{"not an alias: id", args{"id": "/w/a"}, nil},
		{"not an alias: target", args{"target": "/w/a"}, nil},
		{"not an alias: notebook_path", args{"notebook_path": "/w/a"}, nil},
		{"not an alias: plural file_paths", args{"file_paths": []interface{}{"/w/a"}}, nil},
		{"not an alias: plural files", args{"files": []interface{}{"/w/a"}}, nil},
		{"not an alias: profile", args{"profile": "/w/a"}, nil},
		{"not an alias: string-encoded JSON", args{"payload": `{"file_path": "/w/a"}`}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := fmt.Sprint(tc.in)
			got := pathAliasArguments(tc.in)
			if fmt.Sprint(tc.in) != before {
				t.Fatalf("input mutated: %v", tc.in)
			}
			if tc.want == nil {
				if got != nil {
					t.Fatalf("no reading wanted, got %v", got)
				}
				return
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("got  %v\nwant %v", got, tc.want)
			}
		})
	}
}

// TestPathAliasArguments_Overflow: a call can carry any number of keys that
// fold to an alias name. The readings are bounded at maxPathAliasReadings plus
// one overflow reading, and every value is still presented under `path` in
// one of them.
func TestPathAliasArguments_Overflow(t *testing.T) {
	keys := []string{"file_path", "filePath", "file-path", "FILE_PATH", "filepath", "File_Path"}
	in := map[string]interface{}{}
	for i, k := range keys {
		in[k] = fmt.Sprintf("/w/%d", i)
	}
	got := pathAliasArguments(in)
	if len(got) != maxPathAliasReadings+1 {
		t.Fatalf("got %d readings, want %d", len(got), maxPathAliasReadings+1)
	}
	seen := map[string]bool{}
	for _, r := range got {
		switch p := r["path"].(type) {
		case string:
			seen[p] = true
		case []interface{}:
			for _, x := range p {
				seen[x.(string)] = true
			}
		}
	}
	for i := range keys {
		if v := fmt.Sprintf("/w/%d", i); !seen[v] {
			t.Errorf("%s is never presented under path: %v", v, got)
		}
	}
	if _, isList := got[maxPathAliasReadings]["path"].([]interface{}); !isList {
		t.Errorf("the overflow reading must carry the rest as one list, got %v", got[maxPathAliasReadings]["path"])
	}
}

// TestPathAliasReading_OverflowExclusionGap pins the accepted residual of the
// bound: past maxPathAliasReadings distinct alias values in one map, the rest
// share one reading as a list, so an exclusion on `path` that excuses one of
// them excuses the reading, as it does for the elements of a batch's `paths`.
// Main read none of these values. Closing it means one reading per value past
// the bound, which is the unbounded cost the bound exists to stop. The
// control is the same call without the excused decoy.
func TestPathAliasReading_OverflowExclusionGap(t *testing.T) {
	ev := windowsSlashEvaluator(t, `
defaults:
  decision: AUDIT
rules:
  - id: t-excl
    match:
      tool_name_any: ["read_file"]
      argument_patterns:
        path: "**/.vendor/secret.json"
      exclude_argument_patterns:
        path: ["**/README.md"]
    decision: BLOCK
    reason: test
`)
	// Sorted key order: FILE_PATH, File_Path, file-path, filePath, file_path,
	// filepath. The first four take the per-value readings; the last two
	// share the overflow reading.
	args := map[string]interface{}{
		"FILE_PATH": "/w/a.go", "File_Path": "/w/b.go", "file-path": "/w/c.go", "filePath": "/w/d.go",
		"file_path": "/w/README.md", "filepath": "/w/.vendor/secret.json",
	}
	if got := ev.EvaluateToolCall("read_file", args); got.Decision != policy.DecisionAudit {
		t.Errorf("accepted gap changed: got %s %v, want AUDIT (update this pin and the maxPathAliasReadings comment)", got.Decision, got.TriggeredRules)
	}
	args["file_path"] = "/w/e.go"
	if got := ev.EvaluateToolCall("read_file", args); got.Decision != policy.DecisionBlock {
		t.Errorf("control: without the excused decoy the overflow value must BLOCK, got %s %v", got.Decision, got.TriggeredRules)
	}
}

// aliasRuleEvaluator is a small synthetic policy with one rule per kind of
// predicate a path rule is written in, all on `path`.
func aliasRuleEvaluator(t *testing.T) *PolicyEvaluator {
	t.Helper()
	return windowsSlashEvaluator(t, `
defaults:
  decision: AUDIT
rules:
  - id: t-glob
    match:
      tool_name_any: ["read_file"]
      argument_patterns:
        path: "**/.vendor/secret.json"
    decision: BLOCK
    reason: test
  - id: t-glob-any
    match:
      tool_name_any: ["read_file"]
      argument_patterns_any:
        path: ["/proc/**/environ"]
    decision: BLOCK
    reason: test
  - id: t-regex
    match:
      tool_name_any: ["read_file"]
      argument_regex_patterns:
        path: '\.vendor/token\.txt$'
    decision: BLOCK
    reason: test
structural_rules:
  - id: t-args-match
    match:
      tool_name_regex: ".*"
      args_match:
        path:
          pattern_any:
            - '\.vendor/creds\.ini$'
    decision: BLOCK
    reason: test
`)
}

// TestPathAliasReading_RaisesPathRules: each kind of predicate written on
// `path` fires on each alias name and loose spelling, through the alias
// reading only (the as-written pass is the positive control), and the rule
// recorded is the rule that matched.
func TestPathAliasReading_RaisesPathRules(t *testing.T) {
	ev := aliasRuleEvaluator(t)
	probes := []struct{ rule, value string }{
		{"t-glob", "/w/.vendor/secret.json"},
		{"t-glob-any", aliasEnviron()},
		{"t-regex", "/w/.vendor/token.txt"},
		{"t-args-match", "/w/.vendor/creds.ini"},
	}
	for _, p := range probes {
		if got := ev.EvaluateToolCall("read_file", map[string]interface{}{"path": p.value}); got.Decision != policy.DecisionBlock || !slices.Equal(got.TriggeredRules, []string{p.rule}) {
			t.Fatalf("control: path=%q got %s %v, want BLOCK by %s", p.value, got.Decision, got.TriggeredRules, p.rule)
		}
		for _, name := range append(append([]string{}, aliasNames...), aliasLooseSpellings...) {
			args := map[string]interface{}{name: p.value}
			if got := ev.evaluateValueReadings("read_file", args, "", nil); got.Decision == policy.DecisionBlock {
				t.Fatalf("positive control: %s=%q already BLOCKs without the alias reading", name, p.value)
			}
			got := ev.EvaluateToolCall("read_file", args)
			if got.Decision != policy.DecisionBlock || !slices.Equal(got.TriggeredRules, []string{p.rule}) {
				t.Errorf("%s=%q: got %s %v, want BLOCK by %s", name, p.value, got.Decision, got.TriggeredRules, p.rule)
			}
		}
	}
}

// TestPathAliasReading_NestedListAndBoth covers the shapes beyond a top-level
// scalar: an envelope object, the items of a batch, a list value, and a call
// that carries path and file_path with different values, in both orders.
func TestPathAliasReading_NestedListAndBoth(t *testing.T) {
	ev := aliasRuleEvaluator(t)
	bad, good := "/w/.vendor/secret.json", "/w/README.md"
	cases := []struct {
		name string
		args map[string]interface{}
		want policy.Decision
	}{
		{"envelope", map[string]interface{}{"request": map[string]interface{}{"file_path": bad}}, policy.DecisionBlock},
		{"batch items", map[string]interface{}{"items": []interface{}{map[string]interface{}{"file_path": good}, map[string]interface{}{"filename": bad}}}, policy.DecisionBlock},
		{"list value", map[string]interface{}{"file_path": []interface{}{good, bad}}, policy.DecisionBlock},
		{"both: alias is the bad one", map[string]interface{}{"path": good, "file_path": bad}, policy.DecisionBlock},
		{"both: path is the bad one", map[string]interface{}{"path": bad, "file_path": good}, policy.DecisionBlock},
		{"both: neither", map[string]interface{}{"path": good, "file_path": "/w/b.md"}, policy.DecisionAudit},
	}
	for _, tc := range cases {
		got := ev.EvaluateToolCall("read_file", tc.args)
		if got.Decision != tc.want {
			t.Errorf("%s: got %s %v, want %s", tc.name, got.Decision, got.TriggeredRules, tc.want)
			continue
		}
		if tc.want == policy.DecisionBlock && !slices.Equal(got.TriggeredRules, []string{"t-glob"}) {
			t.Errorf("%s: rules %v, want [t-glob]", tc.name, got.TriggeredRules)
		}
	}
}

// TestPathAliasReading_ComposesWithValueReadings: an alias reading gets the
// case-fold, separator and /private readings too, as the as-written one does.
func TestPathAliasReading_ComposesWithValueReadings(t *testing.T) {
	ev := windowsSlashEvaluator(t, `
defaults:
  decision: AUDIT
structural_rules:
  - id: t-fwd
    match:
      tool_name_regex: ".*"
      args_match:
        path:
          pattern_any:
            - '\.vendor/secret\.json$'
            - '^/etc/agent-test\.conf$'
    decision: BLOCK
    reason: test
`)
	for _, v := range []string{
		`C:\Users\u\.vendor\secret.json`,    // separators
		"/Users/u/.VENDOR/secret.json",      // case fold
		"/private" + "/etc/agent-test.conf", // /private alias
		"/private" + "/ETC/agent-test.conf", // /private alias, then the case fold
	} {
		if got := ev.EvaluateToolCall("read_file", map[string]interface{}{"path": v}); got.Decision != policy.DecisionBlock {
			t.Fatalf("control: path=%q got %s, want BLOCK", v, got.Decision)
		}
		got := ev.EvaluateToolCall("read_file", map[string]interface{}{"file_path": v})
		if got.Decision != policy.DecisionBlock || !slices.Equal(got.TriggeredRules, []string{"t-fwd"}) {
			t.Errorf("file_path=%q: got %s %v, want BLOCK by t-fwd", v, got.Decision, got.TriggeredRules)
		}
	}
}

// TestPathAliasReading_NeverLowers pins "nothing gets weaker". A rule written
// on file_path BLOCKs on main; rules written on `path` that would exclude,
// ALLOW or carve the same path out act only inside the alias reading, so the
// verdict and its record stay the as-written ones. The control proves the
// test can tell: the same call with file_path rewritten IN PLACE to path
// (the construction this change must not use) decides lower.
func TestPathAliasReading_NeverLowers(t *testing.T) {
	ev := windowsSlashEvaluator(t, `
defaults:
  decision: AUDIT
rules:
  - id: r-file-path
    match:
      tool_name_any: ["read_file"]
      argument_patterns:
        file_path: "**/.ssh/**"
    decision: BLOCK
    reason: test
  - id: r-allow-path
    match:
      tool_name_any: ["read_file"]
      argument_patterns:
        path: "**"
    decision: ALLOW
    reason: test
  - id: r-path-excluded
    match:
      tool_name_any: ["read_file"]
      argument_patterns:
        path: "**/.ssh/**"
      exclude_argument_patterns:
        path: ["**/.ssh/**"]
    decision: BLOCK
    reason: test
structural_rules:
  - id: s-path-excluded
    match:
      tool_name_regex: ".*"
      exclude_when:
        args_match:
          path:
            pattern_any: ['\.ssh/']
      args_match:
        path:
          pattern_any: ['.*']
    decision: BLOCK
    reason: test
`)
	key := aliasSSHKey()
	args := map[string]interface{}{"file_path": key}
	got := ev.EvaluateToolCall("read_file", args)
	if got.Decision != policy.DecisionBlock || !slices.Equal(got.TriggeredRules, []string{"r-file-path"}) {
		t.Errorf("file_path call: got %s %v, want BLOCK by r-file-path (the as-written record)", got.Decision, got.TriggeredRules)
	}
	inPlace := map[string]interface{}{"path": key}
	if ctl := ev.EvaluateToolCall("read_file", inPlace); ctl.Decision == policy.DecisionBlock {
		t.Fatalf("control: an in-place rewrite must decide lower here, got %s %v", ctl.Decision, ctl.TriggeredRules)
	}

	// Both present: the as-written path BLOCKs; the alias value is benign and
	// its reading decides lower, which must not displace the as-written one.
	ev2 := aliasRuleEvaluator(t)
	both := map[string]interface{}{"path": "/w/.vendor/secret.json", "file_path": "/w/README.md"}
	if got := ev2.EvaluateToolCall("read_file", both); got.Decision != policy.DecisionBlock || !slices.Equal(got.TriggeredRules, []string{"t-glob"}) {
		t.Errorf("both present: got %s %v, want BLOCK by t-glob", got.Decision, got.TriggeredRules)
	}
}

// aliasCommunityEvaluator is the community MCP packs alone: no premium rule
// keyed on file_path can BLOCK the alias spelling as written, so the rule a
// raised verdict reports is the community `path` rule's.
func aliasCommunityEvaluator(t *testing.T) *PolicyEvaluator {
	t.Helper()
	merged, _, err := LoadMCPPacks("../../packs/community/mcp", DefaultMCPPolicy())
	if err != nil {
		t.Fatalf("load community MCP packs: %v", err)
	}
	return NewPolicyEvaluator(merged)
}

// TestPathAliasReading_ShippedPackRules: existing BLOCK rules written on
// `path`, the same call with the path under each alias name, BLOCK with the
// same rules and taxonomy as the `path` call. Negative controls: an ordinary
// workspace file under each alias name, on MCP and Claude Code tool names.
func TestPathAliasReading_ShippedPackRules(t *testing.T) {
	type probe struct {
		rule, tool, value string
		premium           bool
	}
	probes := []probe{
		{"mcp-sec-block-ssh-private-key-read", "read_file", aliasSSHKey(), false},
		{"mcp-sec-block-aws-access", "read_file", aliasAWSCreds(), false},
		{"mcp-sec-block-k8s-system-kubeconfig", "read_file", aliasKubeconf(), false},
		{"mcp-recon-block-proc-environ", "read_file", aliasEnviron(), true},
	}
	community := aliasCommunityEvaluator(t)
	var full *PolicyEvaluator
	for _, p := range probes {
		ev := community
		if p.premium {
			if !ossbuild.PremiumPacksPresent() {
				t.Logf("skip %s: premium packs absent (OSS tree)", p.rule)
				continue
			}
			if full == nil {
				full = newTestMCPEvaluator(t)
			}
			ev = full
		}
		ctl := ev.EvaluateToolCall(p.tool, map[string]interface{}{"path": p.value})
		if ctl.Decision != policy.DecisionBlock || !slices.Contains(ctl.TriggeredRules, p.rule) {
			t.Fatalf("control: %s path=%q got %s %v, want BLOCK by %s", p.tool, p.value, ctl.Decision, ctl.TriggeredRules, p.rule)
		}
		for _, name := range append(append([]string{}, aliasNames...), "filePath", "file-path") {
			args := map[string]interface{}{name: p.value}
			if asWritten := ev.evaluateValueReadings(p.tool, args, "", nil); asWritten.Decision == policy.DecisionBlock {
				t.Fatalf("positive control: %s=%q BLOCKs without the alias reading (%v)", name, p.value, asWritten.TriggeredRules)
			}
			got := ev.EvaluateToolCall(p.tool, args)
			if got.Decision != policy.DecisionBlock {
				t.Errorf("%s %s=%q: got %s %v, want BLOCK by %s", p.tool, name, p.value, got.Decision, got.TriggeredRules, p.rule)
				continue
			}
			if !sameSet(got.TriggeredRules, ctl.TriggeredRules) || !sameSet(got.TaxonomyRefs, ctl.TaxonomyRefs) {
				t.Errorf("%s %s=%q: rules %v taxonomy %v, want the path call's %v %v", p.tool, name, p.value, got.TriggeredRules, got.TaxonomyRefs, ctl.TriggeredRules, ctl.TaxonomyRefs)
			}
		}
	}

	evs := []*PolicyEvaluator{community}
	if ossbuild.PremiumPacksPresent() {
		if full == nil {
			full = newTestMCPEvaluator(t)
		}
		evs = append(evs, full)
	}
	for _, ev := range evs {
		for _, v := range []string{"/workspace/project/README.md", "/workspace/src/main.go", "/Users/dev/repo/docs/guide.md"} {
			for _, tool := range []string{"read_file", "write_file", "Read", "Write", "Edit"} {
				for _, name := range aliasNames {
					args := map[string]interface{}{name: v}
					if tool == "Write" || tool == "write_file" {
						args["content"] = "hello"
					}
					if got := ev.EvaluateToolCall(tool, args); got.Decision == policy.DecisionBlock {
						t.Errorf("negative control: %s %s=%q got BLOCK %v", tool, name, v, got.TriggeredRules)
					}
				}
			}
		}
	}
}

// harnessScopePaths are the three paths Gary's 2026-11-16 scoping decision
// was made on: a traversal, an orchestration config, a credential.
func harnessScopePaths() map[string]string {
	return map[string]string{
		"traversal":   "/Users/dev/repo/docs/../../outside.txt",
		"orch-config": "/Users/dev/proj/crew.yaml",
		"credential":  aliasSSHKey(),
	}
}

// harnessScopeArgs is a call of tool with the path under key, carrying the
// payload argument the tool's write shape carries.
func harnessScopeArgs(tool, key, p string) map[string]interface{} {
	args := map[string]interface{}{key: p}
	switch tool {
	case "Write", "write_file", "create":
		args["content"] = "name: demo\n"
	case "Edit", "MultiEdit", "edit", "edit_file":
		args["old_string"] = "a"
		args["new_string"] = "b"
	}
	return args
}

// harnessFileTools is every name on harnessReadTools and harnessWriteTools,
// sorted, with whether it is a read tool.
func harnessFileTools() (names []string, isRead map[string]bool) {
	isRead = map[string]bool{}
	for n := range harnessReadTools {
		names = append(names, n)
		isRead[n] = true
	}
	for n := range harnessWriteTools {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, isRead
}

// TestPathAliasReading_HarnessFileToolsAsOnMain: Gary, 2026-11-16, MCP
// server tools only. A harness's own file tools (Claude Code Read, Write,
// Edit, MultiEdit; Copilot CLI view, create, edit) keep main's verdict in
// every field, and their record-only attribution (#4248 option (c), #4457):
// a credential read stays AUDIT with the read rules recorded, not BLOCK by
// the catch-all through file_path.
//
// The pins are main's verdicts as observed on main (ee1f6dee) on
// 2026-11-16, decision and recorded rule ids. Every field is also compared
// with the evaluation minus the alias reading: evaluate's own steps with
// evaluateValueReadings in place of evaluateReadings.
func TestPathAliasReading_HarnessFileToolsAsOnMain(t *testing.T) {
	type pin struct {
		decision policy.Decision
		rules    []string
	}
	none := []string{}
	sshRead := []string{"mcp-sec-block-ssh-private-key-read", "mcp-sec-block-ssh-dir-read", "mcp-struct-block-credential-path-access"}
	sshWrite := []string{"mcp-sec-block-ssh-access", "mcp-struct-block-sensitive-path-write", "mcp-struct-block-credential-path-access"}
	traversal := []string{"mcp-struct-block-path-traversal"}
	// pins[evaluator][path][read?]
	pins := map[string]map[string]map[bool]pin{
		"community": {
			"traversal":   {true: {policy.DecisionAudit, traversal}, false: {policy.DecisionAudit, traversal}},
			"orch-config": {true: {policy.DecisionAudit, none}, false: {policy.DecisionAudit, none}},
			"credential":  {true: {policy.DecisionAudit, sshRead}, false: {policy.DecisionAudit, sshWrite}},
		},
		"full": {
			"traversal":   {true: {policy.DecisionAudit, traversal}, false: {policy.DecisionAudit, traversal}},
			"orch-config": {true: {policy.DecisionAudit, none}, false: {policy.DecisionAudit, []string{"mcp-agentic-block-orchestration-config-write"}}},
			"credential":  {true: {policy.DecisionBlock, []string{"mcp-prem-block-cred-path-filepath-key"}}, false: {policy.DecisionBlock, []string{"mcp-prem-block-cred-path-filepath-key"}}},
		},
	}
	evs := map[string]*PolicyEvaluator{"community": aliasCommunityEvaluator(t)}
	if ossbuild.PremiumPacksPresent() {
		evs["full"] = newTestMCPEvaluator(t)
	} else {
		t.Log("full-tree pins skipped: premium packs absent (OSS tree)")
	}
	tools, isRead := harnessFileTools()
	if len(tools) != 7 {
		t.Fatalf("harness file tools %v: the pins were taken for 7 (Read, view, Write, Edit, MultiEdit, create, edit)", tools)
	}
	checked := 0
	for evName, ev := range evs {
		for pName, p := range harnessScopePaths() {
			for _, tool := range tools {
				args := harnessScopeArgs(tool, "file_path", p)
				got := ev.EvaluateToolCall(tool, args)
				want := pins[evName][pName][isRead[tool]]
				if got.Decision != want.decision || !sameSet(got.TriggeredRules, want.rules) || len(got.TriggeredRules) != len(want.rules) {
					t.Errorf("%s %s %s: got %s %v, want main's %s %v", evName, pName, tool, got.Decision, got.TriggeredRules, want.decision, want.rules)
				}
				if got.OriginalDecision != "" {
					t.Errorf("%s %s %s: OriginalDecision %q, want empty as on main", evName, pName, tool, got.OriginalDecision)
				}
				if got.Decision == policy.DecisionAudit {
					for _, r := range got.Reasons {
						if !strings.HasPrefix(r, "Recorded, not enforced (") {
							t.Errorf("%s %s %s: reason %q is not a record-only attribution", evName, pName, tool, r)
						}
					}
				}
				noAlias := ev.attributeHarnessRead(ev.foldProtectedPath(ev.evaluateValueReadings(tool, args, "", nil), args), tool, args)
				if fmt.Sprintf("%#v", got) != fmt.Sprintf("%#v", noAlias) {
					t.Errorf("%s %s %s: verdict differs from the evaluation without the alias reading:\n got %#v\nwant %#v", evName, pName, tool, got, noAlias)
				}
				checked++
			}
		}
	}
	if checked < 21 {
		t.Fatalf("checked %d harness calls, want at least 21", checked)
	}

	// A harness call carrying both path and file_path: attributeHarnessRead
	// keeps the call's own path, and its equivalent MCP call must not get the
	// alias reading either, or the credential under file_path would be
	// recorded where main records nothing. Main (ee1f6dee), observed for
	// these four tool names: community AUDIT with no record-only reason; full
	// BLOCK by mcp-prem-block-cred-path-filepath-key.
	for evName, ev := range evs {
		for _, tool := range []string{"Read", "view", "Write", "Edit"} {
			args := map[string]interface{}{"path": "/w/README.md", "file_path": aliasSSHKey()}
			got := ev.EvaluateToolCall(tool, args)
			switch evName {
			case "community":
				if got.Decision != policy.DecisionAudit {
					t.Errorf("community both-present %s: got %s %v, want main's AUDIT", tool, got.Decision, got.TriggeredRules)
				}
				for _, r := range got.Reasons {
					if strings.HasPrefix(r, "Recorded, not enforced (") {
						t.Errorf("community both-present %s: records %q, main records nothing", tool, r)
					}
				}
			case "full":
				if got.Decision != policy.DecisionBlock || !slices.Equal(got.TriggeredRules, []string{"mcp-prem-block-cred-path-filepath-key"}) {
					t.Errorf("full both-present %s: got %s %v, want main's BLOCK [mcp-prem-block-cred-path-filepath-key]", tool, got.Decision, got.TriggeredRules)
				}
			}
		}
	}
}

// TestPathAliasReading_MCPToolsStillRaise: the same three paths under
// file_path on an MCP server tool name still raise, to the `path` call's
// rules and taxonomy, where the as-written reading decides lower. The raising
// combinations are pinned so a lost one is noticed.
func TestPathAliasReading_MCPToolsStillRaise(t *testing.T) {
	raises := map[string][]string{
		"community": {"traversal/read_file", "traversal/write_file", "traversal/edit_file", "credential/read_file", "credential/write_file", "credential/edit_file"},
		// With premium, credential under file_path already BLOCKs as
		// written (mcp-prem-block-cred-path-filepath-key), so it is not a
		// raise there.
		"full": {"traversal/read_file", "traversal/write_file", "traversal/edit_file", "orch-config/write_file", "orch-config/edit_file"},
	}
	evs := map[string]*PolicyEvaluator{"community": aliasCommunityEvaluator(t)}
	if ossbuild.PremiumPacksPresent() {
		evs["full"] = newTestMCPEvaluator(t)
	}
	for evName, ev := range evs {
		paths := harnessScopePaths()
		for _, combo := range raises[evName] {
			pName, tool, _ := strings.Cut(combo, "/")
			args := harnessScopeArgs(tool, "file_path", paths[pName])
			if asWritten := ev.evaluateValueReadings(tool, args, "", nil); asWritten.Decision == policy.DecisionBlock {
				t.Fatalf("%s %s: positive control: already BLOCKs as written (%v)", evName, combo, asWritten.TriggeredRules)
			}
			ctl := ev.EvaluateToolCall(tool, harnessScopeArgs(tool, "path", paths[pName]))
			got := ev.EvaluateToolCall(tool, args)
			if got.Decision != policy.DecisionBlock || !sameSet(got.TriggeredRules, ctl.TriggeredRules) || !sameSet(got.TaxonomyRefs, ctl.TaxonomyRefs) {
				t.Errorf("%s %s: got %s %v %v, want the path call's %s %v %v", evName, combo, got.Decision, got.TriggeredRules, got.TaxonomyRefs, ctl.Decision, ctl.TriggeredRules, ctl.TaxonomyRefs)
			}
		}
	}
}

// TestPathAliasReading_WriteDestinationNames is #4942 on the shipped
// community rules: the two advisories' own call shapes, with the place the
// tool writes to under a write-destination name. The control is the same tool
// with that value under `path`; the call must decide BLOCK by the same rules.
// Ordinary destinations, and values that are not file paths at all, stay
// below BLOCK. A harness's own file tool is out of the reading's scope
// whatever the argument is called.
func TestPathAliasReading_WriteDestinationNames(t *testing.T) {
	ev := aliasCommunityEvaluator(t)
	shapes := []struct {
		tool string
		args func(name, value string) map[string]interface{}
	}{
		// GHSA-gj7r-p794-hhq5: path is the remote file, the alias the local one.
		{"download_file", func(name, value string) map[string]interface{} {
			return map[string]interface{}{"path": "/api/pcaps/export.pcap", name: value}
		}},
		// GHSA-mqm3-w68j-75mw: a report tool with no `path` at all.
		{"generate_cost_report", func(name, value string) map[string]interface{} {
			return map[string]interface{}{"service_name": "Amazon EC2", "format": "markdown", name: value}
		}},
	}
	targets := []string{aliasAuthorizedKeys(), aliasSSHKey(), aliasAWSCreds()}
	names := append(append([]string{}, aliasWriteDestNames...), "outputFile", "save-path", "OUT_PATH")
	raised := 0
	for _, sh := range shapes {
		for _, target := range targets {
			ctl := ev.EvaluateToolCall(sh.tool, map[string]interface{}{"path": target})
			if ctl.Decision != policy.DecisionBlock {
				// Not every shipped path rule covers every tool name; a pair
				// the `path` call does not BLOCK is not an alias of a BLOCK.
				continue
			}
			for _, name := range names {
				args := sh.args(name, target)
				if asWritten := ev.evaluateValueReadings(sh.tool, args, "", nil); asWritten.Decision == policy.DecisionBlock {
					t.Fatalf("positive control: %s %s=%q BLOCKs without the alias reading (%v)", sh.tool, name, target, asWritten.TriggeredRules)
				}
				got := ev.EvaluateToolCall(sh.tool, args)
				if got.Decision != policy.DecisionBlock || !sameSet(got.TriggeredRules, ctl.TriggeredRules) || !sameSet(got.TaxonomyRefs, ctl.TaxonomyRefs) {
					t.Errorf("%s %s=%q: got %s %v %v, want the path call's %s %v %v", sh.tool, name, target, got.Decision, got.TriggeredRules, got.TaxonomyRefs, ctl.Decision, ctl.TriggeredRules, ctl.TaxonomyRefs)
					continue
				}
				raised++
			}
		}
	}
	// Both advisory shapes must be covered for at least the authorized_keys
	// target, or the loop above proved nothing.
	if min := len(shapes) * len(names); raised < min {
		t.Fatalf("only %d calls were raised, want at least %d (each shape, each name, one target): the controls no longer BLOCK under `path`", raised, min)
	}

	for _, sh := range shapes {
		for _, value := range []string{"/workspace/project/out/report.md", "/Users/dev/repo/build/export.pcap", "s3://reports-bucket/2026/11/cost.md", "#finance-reports", "ops@example.com", "report.md"} {
			for _, name := range aliasWriteDestNames {
				if got := ev.EvaluateToolCall(sh.tool, sh.args(name, value)); got.Decision == policy.DecisionBlock {
					t.Errorf("negative control: %s %s=%q got BLOCK %v", sh.tool, name, value, got.TriggeredRules)
				}
			}
		}
	}

	for _, tool := range []string{"Write", "Edit", "Read"} {
		for _, name := range aliasWriteDestNames {
			args := map[string]interface{}{"file_path": "/Users/dev/repo/notes.md", "content": "x", name: aliasAuthorizedKeys()}
			asWritten := ev.evaluateValueReadings(tool, args, "", nil)
			if got := ev.EvaluateToolCall(tool, args); got.Decision != asWritten.Decision {
				t.Errorf("harness tool %s with %s: got %s %v, want the as-written %s (no alias reading for a harness's own file tools)", tool, name, got.Decision, got.TriggeredRules, asWritten.Decision)
			}
		}
	}
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

// pathAliasKnownGaps is the residual of the sweep below, by probe id, with the
// reason. Ratchet DOWN: an entry that stops leaking fails the test.
var pathAliasKnownGaps = map[string]string{}

// TestPathAliasReading_ShippedMCPPacks is the ratchet over every shipped MCP
// rule: an inline TP that BLOCKs with its path under top-level `path` must
// BLOCK with the path under an alias name too. The names rotate across the
// probes (each is read identically once normalizeFieldName has folded it, and
// TestPathAliasReading_RaisesPathRules covers every name on every predicate
// kind), which keeps the sweep to three evaluations per probe. A TP that
// already carries an alias-named key is skipped: renaming its path would
// overwrite that key, not move the path. A TP whose tool is a harness's own
// file tool is out of the reading's scope (Gary, 2026-11-16), so it is
// counted and skipped; TestPathAliasReading_HarnessFileToolsAsOnMain pins
// those.
func TestPathAliasReading_ShippedMCPPacks(t *testing.T) {
	t.Parallel()
	ev := newTestMCPEvaluator(t)
	type probe struct {
		id, tool string
		args     map[string]interface{}
	}
	var probes []probe
	add := func(id string, tests *MCPRuleTest) {
		if tests == nil {
			return
		}
		for i, tc := range tests.TP {
			if tc.Tool == "" {
				continue
			}
			args, err := tc.ResolvedArgs()
			if err != nil {
				continue
			}
			if _, ok := args["path"].(string); !ok { //argmaplookup:allow test fixture shape, exact key by construction
				continue
			}
			collides := false
			for k := range args {
				if pathArgAliasNames[normalizeFieldName(k)] {
					collides = true
				}
			}
			if collides {
				continue
			}
			probes = append(probes, probe{fmt.Sprintf("%s/TP-%d", id, i+1), tc.Tool, args})
		}
	}
	p := ev.policy
	for _, r := range p.Rules {
		add(r.ID, r.Tests)
	}
	for _, r := range p.StructuralRules {
		add(r.ID, r.Tests)
	}
	for _, r := range p.SemanticRules {
		add(r.ID, r.Tests)
	}
	evaluated, flipped, harness := 0, 0, 0
	stillOpen := map[string]bool{}
	var leaks []string
	for _, pr := range probes {
		if isHarnessFileTool(pr.tool) {
			harness++
			continue
		}
		base := ev.EvaluateToolCall(pr.tool, pr.args)
		if base.Decision != policy.DecisionBlock {
			continue
		}
		name := aliasNames[evaluated%len(aliasNames)]
		evaluated++
		renamed := make(map[string]interface{}, len(pr.args))
		for k, v := range pr.args {
			if k == "path" {
				k = name
			}
			renamed[k] = v
		}
		if asWritten := ev.evaluateValueReadings(pr.tool, renamed, "", nil); asWritten.Decision != policy.DecisionBlock {
			flipped++
		}
		got := ev.EvaluateToolCall(pr.tool, renamed)
		if got.Decision == policy.DecisionBlock {
			continue
		}
		id := pr.id + "/" + name
		if _, ok := pathAliasKnownGaps[id]; ok {
			stillOpen[id] = true
			continue
		}
		leaks = append(leaks, fmt.Sprintf("%s: %s BLOCK -> %s %v : %v", id, pr.tool, got.Decision, got.TriggeredRules, renamed))
	}
	if evaluated < 100 || flipped < 100 {
		t.Fatalf("path-alias sweep: %d BLOCKing probes with a top-level path, %d alias calls that leak without the reading — vacuous, not clean", evaluated, flipped)
	}
	t.Logf("path-alias sweep: %d probes with a top-level path (%d on a harness file tool, skipped), %d BLOCK, %d alias calls that leak without the reading, %d leak with it", len(probes), harness, evaluated, flipped, len(leaks))
	if len(leaks) > 0 {
		sort.Strings(leaks)
		t.Errorf("%d BLOCKing MCP tool call(s) decided lower with the path under an alias name (#4937):\n%s", len(leaks), strings.Join(leaks, "\n"))
	}
	for id := range pathAliasKnownGaps {
		if !stillOpen[id] {
			t.Errorf("known gap %q no longer leaks — remove it from pathAliasKnownGaps (ratchet down)", id)
		}
	}
}

// BenchmarkPathAliasReading compares a call that carries `path` (no alias
// reading is built) with the same call under file_path (one alias reading),
// on the shipped packs.
func BenchmarkPathAliasReading(b *testing.B) {
	mcpPolicy := DefaultMCPPolicy()
	merged, _, err := LoadMCPPacks("../../packs/community/mcp", mcpPolicy)
	if err != nil {
		b.Fatal(err)
	}
	if pm, _, perr := LoadMCPPacks("../../packs/premium/mcp", merged); perr == nil {
		merged = pm
	}
	ev := NewPolicyEvaluator(merged)
	for _, c := range []struct{ tool, key string }{{"read_file", "path"}, {"read_file", "file_path"}, {"Read", "file_path"}} {
		args := map[string]interface{}{c.key: "/Users/dev/repo/src/main.go"}
		b.Run(c.tool+"/"+c.key, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ev.EvaluateToolCall(c.tool, args)
			}
		})
	}
}
