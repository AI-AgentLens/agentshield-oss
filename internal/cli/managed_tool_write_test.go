package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// #4260: on a managed host a harness's own file-write tool could rewrite
// AgentShield's config. Claude Code's Write/Edit and Copilot CLI's
// create/edit/apply_patch decided AUDIT and exited 0, while the shell path
// (sp-block-config-touch plus the ~/.agentshield/** protected path) blocked
// every equivalent command. These drive the real hook entry point.

// asConfigFile is the managed config directory's policy.yaml, spelled under home.
func asConfigFile(home, name string) string {
	return filepath.Join(home, ".agentshield", name)
}

func claudeToolPayload(t *testing.T, session, tool string, input interface{}) string {
	t.Helper()
	// Claude Code's shape: no timestamp, a transcript path, and the session's cwd.
	return strings.Replace(copilotCompatPayload(t, session, tool, input),
		`"timestamp":"2026-10-07T16:41:43.120Z"`, `"transcript_path":"/tmp/t.jsonl"`, 1)
}

func TestHook_ManagedHarnessWriteToConfig_IsBlocked(t *testing.T) {
	home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
	policyFile := asConfigFile(home, "policy.yaml")

	// Indirections that land in the config directory.
	outside := t.TempDir()
	dirLink := filepath.Join(outside, "cfg")
	if err := os.Symlink(configDir, dirLink); err != nil {
		t.Fatal(err)
	}
	fileLink := filepath.Join(outside, "p.yaml")
	if err := os.Symlink(policyFile, fileLink); err != nil {
		t.Fatal(err)
	}
	// A symlink to a directory under home, then "..": the OS resolves the
	// link first, so this spelling names the config; filepath.Clean says
	// otherwise (Opus pass 1).
	if err := os.MkdirAll(filepath.Join(home, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	subLink := filepath.Join(outside, "l")
	if err := os.Symlink(filepath.Join(home, "sub"), subLink); err != nil {
		t.Fatal(err)
	}
	// A link in home to somewhere else, then "..": the kernel lands outside,
	// but a harness that normalises the string first writes the config.
	elsewhere := filepath.Join(outside, "zz")
	if err := os.MkdirAll(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(home, "m")); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(outside, "new.yaml")
	if err := os.Symlink(asConfigFile(home, "packs/new.yaml"), dangling); err != nil {
		t.Fatal(err)
	}

	patch := func(header string) string {
		return "*** Begin Patch\n" + header + "\n@@\n-a\n+b\n*** End Patch\n"
	}

	cases := []struct {
		name, payload string
	}{
		{"claude Write", claudeToolPayload(t, "w1", "Write", map[string]interface{}{"file_path": policyFile, "content": "rules: []\n"})},
		{"claude Edit managed.json", claudeToolPayload(t, "w2", "Edit", map[string]interface{}{"file_path": asConfigFile(home, "managed.json"), "old_string": "true", "new_string": "false"})},
		{"claude MultiEdit", claudeToolPayload(t, "w3", "MultiEdit", map[string]interface{}{"file_path": policyFile, "edits": []interface{}{}})},
		{"claude NotebookEdit", claudeToolPayload(t, "w4", "NotebookEdit", map[string]interface{}{"notebook_path": asConfigFile(home, "n.ipynb"), "new_source": "x"})},
		{"claude Write new pack", claudeToolPayload(t, "w5", "Write", map[string]interface{}{"file_path": asConfigFile(home, "packs/evil.yaml"), "content": "x"})},
		{"claude Write audit log", claudeToolPayload(t, "w6", "Write", map[string]interface{}{"file_path": asConfigFile(home, "audit.jsonl"), "content": ""})},
		{"tilde", claudeToolPayload(t, "w7", "Write", map[string]interface{}{"file_path": "~/.agentshield/policy.yaml", "content": "x"})},
		{"dot-dot", claudeToolPayload(t, "w8", "Write", map[string]interface{}{"file_path": filepath.Join(home, "proj") + "/../.agentshield/policy.yaml", "content": "x"})},
		{"symlinked dir", claudeToolPayload(t, "w10", "Write", map[string]interface{}{"file_path": filepath.Join(dirLink, "policy.yaml"), "content": "x"})},
		{"symlinked file", claudeToolPayload(t, "w11", "Edit", map[string]interface{}{"file_path": fileLink, "old_string": "a", "new_string": "b"})},
		{"dangling symlink into config", claudeToolPayload(t, "w12", "Write", map[string]interface{}{"file_path": dangling, "content": "x"})},
		{"symlink then dot-dot", claudeToolPayload(t, "w21", "Write", map[string]interface{}{"file_path": subLink + "/../.agentshield/policy.yaml", "content": "x"})},
		{"symlink then dot-dot, new file", claudeToolPayload(t, "w22", "Write", map[string]interface{}{"file_path": subLink + "/../.agentshield/packs/new.yaml", "content": "x"})},
		{"normalising harness: link then dot-dot", claudeToolPayload(t, "w23", "Write", map[string]interface{}{"file_path": filepath.Join(home, "m") + "/../.agentshield/policy.yaml", "content": "x"})},
		{"copilot compat Write", copilotCompatPayload(t, "w13", "Write", map[string]interface{}{"path": policyFile, "file_text": "x"})},
		{"copilot compat Edit", copilotCompatPayload(t, "w14", "Edit", map[string]interface{}{"path": policyFile, "old_str": "a", "new_str": "b"})},
		{"copilot native create", copilotNativePayload(t, "w15", "create", map[string]interface{}{"path": policyFile, "file_text": "x"})},
		{"copilot native edit", copilotNativePayload(t, "w16", "edit", map[string]interface{}{"path": policyFile, "old_str": "a", "new_str": "b"})},
		{"apply_patch absolute", copilotNativePayload(t, "w17", "apply_patch", patch("*** Update File: "+policyFile))},
		{"apply_patch move into config", copilotNativePayload(t, "w18", "apply_patch", patch("*** Update File: notes.txt\n*** Move to: "+policyFile))},
		{"apply_patch add pack", copilotCompatPayload(t, "w19", "Edit", "*** Begin Patch\n*** Add File: "+asConfigFile(home, "packs/x.yaml")+"\n+x\n*** End Patch\n")},
		{"apply_patch delete", copilotNativePayload(t, "w20", "apply_patch", "*** Begin Patch\n*** Delete File: "+asConfigFile(home, "managed.json")+"\n*** End Patch\n")},
	}
	// A case variant is the config only where the volume says so (macOS and
	// Windows defaults); on a case-sensitive volume it is another directory.
	if _, err := os.Stat(filepath.Join(home, ".AgentShield")); err == nil {
		cases = append(cases, struct{ name, payload string }{"case variant (case-insensitive volume)",
			claudeToolPayload(t, "w9", "Write", map[string]interface{}{"file_path": filepath.Join(home, ".AgentShield", "Policy.yaml"), "content": "x"})})
	}
	for _, c := range cases {
		code, _, stderr := runHookChild(t, home, c.payload)
		if code != 2 {
			t.Errorf("%s: exit %d, want 2 — a harness write to the managed config was not blocked. stderr:\n%s", c.name, code, stderr)
		}
	}
	if log := readFailSafeAuditLog(t, configDir); !strings.Contains(log, "sp-block-config-tool-write") {
		t.Errorf("audit.jsonl does not attribute the blocks to sp-block-config-tool-write:\n%s", log)
	}
}

// A relative apply_patch path resolves against the payload's cwd: Copilot's
// captured patches name files relative to the session directory.
func TestHook_ManagedRelativePatchIntoConfig_IsBlocked(t *testing.T) {
	home, _ := newFailSafeHome(t, true, failSafePolicyGood)
	p := strings.Replace(copilotNativePayload(t, "r1", "apply_patch", "*** Begin Patch\n*** Update File: .agentshield/policy.yaml\n@@\n-a\n+b\n*** End Patch\n"),
		`"cwd":"/repo"`, `"cwd":"`+home+`"`, 1)
	code, stdout, stderr := runHookChild(t, home, p, "AGENTSHIELD_AGENT_ID=copilot-cli")
	requireCopilotDeny(t, "relative patch", code, stdout, stderr, "sp-block-config-tool-write")
}

// The Copilot deny verdict reaches the agent, so it learns why.
func TestHook_ManagedConfigWrite_CopilotGetsDenyVerdict(t *testing.T) {
	home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
	p := copilotCompatPayload(t, "v1", "Write", map[string]interface{}{"path": asConfigFile(home, "policy.yaml"), "file_text": "x"})
	code, stdout, stderr := runHookChild(t, home, p, "AGENTSHIELD_AGENT_ID=copilot-cli")
	requireCopilotDeny(t, "compat Write", code, stdout, stderr, "sp-block-config-tool-write")

	// The receipt: the harness's source, the BLOCK, and a taxonomy node, so
	// the attempt attests to the control it maps to.
	var found bool
	for _, l := range strings.Split(readFailSafeAuditLog(t, configDir), "\n") {
		var e struct {
			SessionID string   `json:"session_id"`
			Source    string   `json:"source"`
			Decision  string   `json:"decision"`
			Taxonomy  []string `json:"taxonomy"`
		}
		if json.Unmarshal([]byte(l), &e) != nil || e.SessionID != "v1" {
			continue
		}
		found = true
		if e.Decision != "BLOCK" || e.Source != "copilot-cli-mcp-hook" || !containsStr(e.Taxonomy, selfProtectTaxonomy) {
			t.Errorf("receipt = %+v, want BLOCK from copilot-cli-mcp-hook with taxonomy %s", e, selfProtectTaxonomy)
		}
	}
	if !found {
		t.Error("no audit event for the blocked write")
	}
}

// What must keep working on a managed host: reading the config (the shell
// layer allows plain reads too), writing anywhere else — including a file
// whose CONTENT names the config, and a sibling directory that shares the
// prefix — and an unrelated patch.
func TestHook_ManagedHarnessWrite_ControlsPass(t *testing.T) {
	home, _ := newFailSafeHome(t, true, failSafePolicyGood)
	policyFile := asConfigFile(home, "policy.yaml")
	cases := []struct {
		name, payload string
	}{
		{"claude Read config", claudeToolPayload(t, "c1", "Read", map[string]interface{}{"file_path": policyFile})},
		{"copilot view config", copilotNativePayload(t, "c2", "view", map[string]interface{}{"path": policyFile})},
		{"claude Grep config dir", claudeToolPayload(t, "c3", "Grep", map[string]interface{}{"pattern": "rules", "path": filepath.Join(home, ".agentshield")})},
		{"doc that names the config", claudeToolPayload(t, "c4", "Write", map[string]interface{}{"file_path": filepath.Join(home, "proj", "README.md"), "content": "Edit ~/.agentshield/policy.yaml to tune rules."})},
		{"prefix sibling", claudeToolPayload(t, "c5", "Write", map[string]interface{}{"file_path": filepath.Join(home, ".agentshield-backup", "policy.yaml"), "content": "x"})},
		{"copilot create elsewhere", copilotNativePayload(t, "c6", "create", map[string]interface{}{"path": filepath.Join(home, "proj", "a.txt"), "file_text": "x"})},
		{"captured patch", copilotNativePayload(t, "c7", "apply_patch", capturedPatch)},
		// Codex pass 2: passing through the directory is not landing in it.
		{"through the config dir and out", claudeToolPayload(t, "c9", "Write", map[string]interface{}{"file_path": filepath.Join(home, ".agentshield") + "/../outside.txt", "content": "x"})},
		{"through a missing subdir and out", claudeToolPayload(t, "c10", "Write", map[string]interface{}{"file_path": filepath.Join(home, ".agentshield") + "/packs/../../outside2.txt", "content": "x"})},
		{"patch whose context names the config", copilotCompatPayload(t, "c8", "Edit", "*** Begin Patch\n*** Update File: README.md\n@@\n *** Delete File: ~/.agentshield/policy.yaml\n-old\n+new\n*** End Patch\n")},
	}
	for _, c := range cases {
		if code, _, stderr := runHookChild(t, home, c.payload); code != 0 {
			t.Errorf("%s: exit %d, want 0 on a managed host. stderr:\n%s", c.name, code, stderr)
		}
	}
}

// Unmanaged control: the guard is a managed-mode guarantee. The same Write
// is not blocked by it on an unmanaged host, so the tests above measure it.
func TestHook_UnmanagedHarnessWriteToConfig_NotSelfProtected(t *testing.T) {
	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	p := claudeToolPayload(t, "u1", "Write", map[string]interface{}{"file_path": asConfigFile(home, "policy.yaml"), "content": "x"})
	code, _, stderr := runHookChild(t, home, p)
	if code != 0 {
		t.Errorf("unmanaged: exit %d, want 0. stderr:\n%s", code, stderr)
	}
	if strings.Contains(readFailSafeAuditLog(t, configDir), "sp-block-config-tool-write") {
		t.Error("unmanaged host: the managed self-protection guard fired")
	}
}

func TestPatchTargets(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		want  []string
	}{
		{"every header kind", []string{
			"*** Begin Patch",
			"*** Add File: a.txt",
			"+*** Update File: added-content.txt",
			"*** Update File: b.txt",
			"*** Move to: c.txt",
			"@@",
			"-x",
			"+y",
			"*** Delete File: d.txt\r",
			"*** End Patch",
		}, []string{"a.txt", "b.txt", "c.txt", "d.txt"}},
		// Codex pass 1: hunk content is the edited file's text. An unchanged
		// line that reads like a header is not one.
		{"update context that reads like a header", []string{
			"*** Begin Patch",
			"*** Update File: README.md",
			"@@",
			" *** Delete File: ~/.agentshield/policy.yaml",
			"- *** Update File: ~/.agentshield/managed.json",
			"+ *** Add File: ~/.agentshield/packs/x.yaml",
			"",
			"*** End of File",
			" *** Update File: still-content.txt",
			"*** End Patch",
		}, []string{"README.md"}},
		// Outside a hunk body a header is read leniently, so a parser that
		// accepts padding or another case cannot write past this check.
		{"padded header after Begin Patch", []string{"*** Begin Patch", "   *** Update File: p.txt", "@@", "-a", "+b"}, []string{"p.txt"}},
		{"padded header after an Add body", []string{"*** Add File: a.txt", "+x", "  *** Delete File: q.txt"}, []string{"a.txt", "q.txt"}},
		{"tab ends the update body", []string{"*** Update File: a.txt", "@@", "-x", "\t*** Delete File: r.txt"}, []string{"a.txt", "r.txt"}},
		{"case variant", []string{"*** update file: s.txt"}, []string{"s.txt"}},
		{"renamed file keeps its body", []string{"*** Update File: a.txt", "*** Move to: b.txt", " *** Delete File: content.txt", "-x"}, []string{"a.txt", "b.txt"}},
	}
	for _, c := range cases {
		if got := patchTargets(strings.Join(c.lines, "\n")); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: patchTargets = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestHarnessWriteTargets(t *testing.T) {
	cases := []struct {
		name     string
		tool     string
		args     map[string]interface{}
		fromText bool
		want     []string
	}{
		{"Write file_path", "Write", map[string]interface{}{"file_path": "/x/a"}, false, []string{"/x/a"}},
		{"copilot Write path", "Write", map[string]interface{}{"path": "/x/a"}, false, []string{"/x/a"}},
		{"NotebookEdit", "NotebookEdit", map[string]interface{}{"notebook_path": "/x/n.ipynb"}, false, []string{"/x/n.ipynb"}},
		{"Read is not a write", "Read", map[string]interface{}{"file_path": "/x/a"}, false, nil},
		{"MCP write_file is the MCP layer's", "write_file", map[string]interface{}{"path": "/x/a"}, false, nil},
		{"Write content is not a target", "Write", map[string]interface{}{"file_path": "/x/a", "content": "*** Begin Patch\n*** Update File: /x/b\n"}, false, []string{"/x/a"}},
		{"string patch under any tool name", "Edit", map[string]interface{}{"patch": "*** Begin Patch\n*** Update File: /x/b\n"}, true, []string{"/x/b"}},
		{"apply_patch object input", "apply_patch", map[string]interface{}{"input": "*** Begin Patch\n*** Add File: /x/c\n"}, false, []string{"/x/c"}},
		{"non-string path ignored", "Write", map[string]interface{}{"file_path": 42}, false, nil},
	}
	for _, c := range cases {
		if got := harnessWriteTargets(c.tool, c.args, c.fromText); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: harnessWriteTargets = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestInManagedConfigDir(t *testing.T) {
	home := t.TempDir()
	configDir := filepath.Join(home, ".agentshield")
	if err := os.MkdirAll(filepath.Join(configDir, "packs"), 0o700); err != nil {
		t.Fatal(err)
	}
	in := []string{
		configDir,
		filepath.Join(configDir, "policy.yaml"),
		filepath.Join(configDir, "packs", "deep", "x.yaml"),
		"~/.agentshield/policy.yaml",
		"proj/../.agentshield/managed.json", // relative to cwd = home
	}
	out := []string{
		filepath.Join(home, ".agentshield-backup", "policy.yaml"),
		filepath.Join(home, "proj", ".agentshield", "policy.yaml"),
		configDir + "/../outside.txt",
		"/etc/hosts",
		"",
	}
	// macOS firmlink: the same directory under a spelling no lexical or
	// symlink reading recognises — only file identity does.
	if runtime.GOOS == "darwin" {
		if real, err := filepath.EvalSymlinks(configDir); err == nil {
			if firm := "/System/Volumes/Data" + real; dirExists(firm) {
				in = append(in, filepath.Join(firm, "policy.yaml"))
			}
		}
	}
	for _, p := range in {
		if !inManagedConfigDir(p, home, home) {
			t.Errorf("inManagedConfigDir(%q) = false, want true", p)
		}
	}
	for _, p := range out {
		if inManagedConfigDir(p, home, home) {
			t.Errorf("inManagedConfigDir(%q) = true, want false", p)
		}
	}
}

// #4351: Claude Code names an MCP server's tool mcp__<server>__<tool>. The
// pack rules are authored against the bare tool name, so the namespaced call
// used to decide AUDIT. The bare-name call is the positive control.
func TestHook_ManagedMCPNamespacedWriteToConfig_IsBlocked(t *testing.T) {
	// The MCP-policy BLOCK for write_file into the config dir comes from the
	// premium rule set; with community rules only the call records AUDIT.
	ossbuild.SkipPremiumSized(t)
	home, _ := newFailSafeHome(t, true, failSafePolicyGood)
	target := map[string]interface{}{"path": asConfigFile(home, "managed.json"), "content": `{"managed": false}`}
	for _, tool := range []string{"write_file", "mcp__filesystem__write_file", "mcp__fs__write_file", "mcp__my_srv__write_file"} {
		code, _, stderr := runHookChild(t, home, claudeToolPayload(t, "m1", tool, target))
		if code != 2 {
			t.Errorf("%s: exit %d, want 2 on a managed host. stderr:\n%s", tool, code, stderr)
		}
	}
	benign := map[string]interface{}{"path": filepath.Join(home, "proj", "notes.txt"), "content": "x"}
	for _, tool := range []string{"write_file", "mcp__filesystem__write_file"} {
		if code, _, stderr := runHookChild(t, home, claudeToolPayload(t, "m2", tool, benign)); code != 0 {
			t.Errorf("%s benign project file: exit %d, want 0. stderr:\n%s", tool, code, stderr)
		}
	}
}
