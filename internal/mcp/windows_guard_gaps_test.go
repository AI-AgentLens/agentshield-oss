package mcp

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Windows gaps in the MCP config guard, pinned (#5021) next to controls, so a
// fix has to flip its row on purpose and then drop the row from
// windowsGapRows. Each was confirmed on Windows 10.
//
//  1. Closed by #5062: a canonical Windows file: URI, file:///C:/Users/u/...
//     (RFC 8089 puts a slash before the drive letter). spellingToPath and
//     EvaluateResourceRead kept that slash, so "/C:/Users/u/..." was neither
//     under HOME by spelling nor a path os.Stat resolves, and slashpath.Match
//     against a plain pattern (~/.bashrc) failed. They now read the drive
//     path. The rows block, as file:///home/u/... does on unix.
//  2. Closed by #5060: command text. homeAnchored reads ~, $HOME, ${HOME},
//     "/..." and file: tokens, and commandTokens removes a backslash, so a
//     drive-letter path (C:\Users\u\.agentshield), its slash form,
//     %USERPROFILE% and $env:USERPROFILE were not read. The Windows reading
//     (windowsCommandNamesTarget) reads them; the rows block, as the same
//     command with the absolute home path does on unix.
//  3. Open (#5063): an over-block, not a security gap. foldKey folds U+017F
//     (long s) as APFS does, and NTFS does not, so ~/.agentſhield is refused
//     although it is another directory there.
func TestConfigGuard_WindowsGaps5021(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows readings; on unix the same spellings decide as TestConfigGuard_SpellingProof and TestResourcePolicy_* expect")
	}
	initHome := guardHome() // the plain patterns' home, fixed at package init
	if initHome == "" {
		t.Skip("no home directory")
	}
	home := newTargetHome(t) // the self-protection targets exist here
	cfg := filepath.Join(home, spDir)
	hook := filepath.Join(home, ".claude", "settings.json")
	w := func(p string) map[string]interface{} { return map[string]interface{}{"path": p, "content": "{}"} }
	cmd := func(c string) map[string]interface{} { return map[string]interface{}{"command": c} }

	longS := home + `\.agent` + "\u017f" + `hield\managed.json`
	if sameFile(longS, filepath.Join(cfg, "managed.json")) {
		t.Fatalf("premise: NTFS does not fold U+017F, so %s is not the config dir; it is here, so gap 3 is no over-block", longS)
	}

	runGuardRows(t, []guardRow{
		{"control: native path to the config", "write_file", w(filepath.Join(cfg, "managed.json")), true},
		{"control: native path to a hook file", "write_file", w(hook), true},
		{"control: ~ in command text", "start_process", cmd("rm -rf ~/" + spDir), true},

		{"closed 1 (#5062): file:/// URI to the config", "write_file", w(fileURI(filepath.Join(cfg, "managed.json"))), true},
		{"closed 1 (#5062): file://localhost/ URI to the config", "write_file", w("file://localhost/" + filepath.ToSlash(filepath.Join(cfg, "managed.json"))), true},
		{"closed 1 (#5062): file:/// URI to a hook file", "write_file", w(fileURI(hook)), true},

		{"closed 2 (#5060): drive-letter path in command text", "start_process", cmd("Remove-Item -Recurse -Force " + cfg), true},
		{"closed 2 (#5060): slash-form drive path in command text", "start_process", cmd("rm -rf " + filepath.ToSlash(cfg)), true},
		{"closed 2 (#5060): %USERPROFILE% in command text", "start_process", cmd(`del %USERPROFILE%\` + spDir + `\managed.json`), true},
		{"closed 2 (#5060): $env:USERPROFILE in command text", "start_process", cmd(`Remove-Item -Recurse $env:USERPROFILE\` + spDir), true},

		{"OVER-BLOCK 3: long-s spelling of the config dir", "write_file", w(longS), true},
	})

	ev := NewPolicyEvaluator(&MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit}})
	native := func(rel string) string { return filepath.Join(initHome, filepath.FromSlash(rel)) }
	for _, r := range []struct {
		name string
		uri  string
		want policy.Decision
	}{
		{"control: a \"**\" pattern matches the URI", fileURI(native(spDir + "/policy.yaml")), policy.DecisionBlock},
		{"control: without the slash before the drive", "file://" + filepath.ToSlash(native(".bashrc")), policy.DecisionBlock},
		{"closed 1 (#5062): file:/// URI to a shell startup file", fileURI(native(".bashrc")), policy.DecisionBlock},
		{"closed 1 (#5062): file:/// URI to the Docker config", fileURI(native(".docker/config.json")), policy.DecisionBlock},
	} {
		if got := ev.EvaluateResourceRead(r.uri); got.Decision != r.want {
			t.Errorf("%s: EvaluateResourceRead(%s) = %s %v; pinned %s", r.name, r.uri, got.Decision, got.TriggeredRules, r.want)
		}
	}
}

// windowsGapRows names the TestConfigGuard_SpellingProof rows whose Windows
// answer is an open gap above, with the reason. They are left out on Windows
// only, and pinned in TestConfigGuard_WindowsGaps5021 instead; off Windows
// the map is empty and every row runs. Gaps 1 and 2 are closed, so their four
// rows (three file: URIs and the interpreter's command text) run everywhere.
func windowsGapRows() map[string]string {
	if runtime.GOOS != "windows" {
		return nil
	}
	const fold = "Windows over-block 3 (NTFS does not fold U+017F, #5063), pinned by TestConfigGuard_WindowsGaps5021"
	return map[string]string{
		"pass2: config dir, APFS long-s fold (#4352)": fold,
		"pass2: Gemini hook file, APFS long-s fold":   fold,
	}
}
