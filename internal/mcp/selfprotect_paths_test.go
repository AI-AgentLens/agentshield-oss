package mcp

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Tests for the self-protection target readings (#4337 review passes 1 and
// 2, #4352). Every test runs in a scratch HOME holding the targets. A row
// whose spelling names the target only on some volumes (a case or Unicode
// case variant, an NFD name, the firmlink) expects a BLOCK exactly where the
// spelling and the target are the same file on this machine: macOS APFS
// (case- and normalisation-insensitive) says yes, Linux CI says no.

const spDir = "." + "agent" + "shield"

// newTargetHome builds a scratch HOME with the self-protection targets and a
// project tree, points HOME at it, and returns it.
func newTargetHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if real, err := filepath.EvalSymlinks(home); err == nil {
		home = real // so a test can spell an alias of it
	}
	files := map[string]string{
		spDir + "/managed.json":                   `{"managed": true}`,
		spDir + "/policy.yaml":                    "rules: []\n",
		".gemini/settings.json":                   "{}",
		".codex/hooks.json":                       "{}",
		".claude/settings.json":                   "{}",
		".cursor/hooks.json":                      "{}",
		".copilot/hooks/agent" + "shield.json":    "{}",
		"projects/app/README.md":                  "x",
		"projects/agentshield-notes/readme.md":    "x",
		"projects/" + spDir + "-notes/readme.md":  "x",
		"projects/app/.claude/settings.json":      "{}",
		"projects/app/config/" + spDir + "/r.yml": "x",
	}
	for rel, body := range files {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	return home
}

// sameFile reports whether a and b exist and are the same file.
func sameFile(a, b string) bool {
	fa, err1 := os.Stat(a)
	fb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(fa, fb)
}

type guardRow struct {
	name  string
	tool  string
	args  map[string]interface{}
	block bool
}

func runGuardRows(t *testing.T, rows []guardRow) {
	t.Helper()
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got := CheckConfigGuard(r.tool, r.args)
			if got.Blocked != r.block {
				t.Fatalf("CheckConfigGuard(%s, %v).Blocked = %v; want %v (findings %+v)", r.tool, r.args, got.Blocked, r.block, got.Findings)
			}
		})
	}
}

// The guard (every mode), as the OSS build has it: spellings that name the
// targets on this machine block; everything else that main allowed stays
// allowed.
func TestConfigGuard_SpellingProof(t *testing.T) {
	home := newTargetHome(t)
	t.Chdir(home) // a stdio server inherits the proxy's working directory
	cfg := home + "/" + spDir
	w := func(p string) map[string]interface{} { return map[string]interface{}{"path": p, "content": "{}"} }

	// A symlinked alias of HOME and a symlink into the config directory.
	aliasDir := t.TempDir()
	alias := filepath.Join(aliasDir, "home-alias")
	if err := os.Symlink(home, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(cfg, filepath.Join(home, "projects", "cfg-link")); err != nil {
		t.Fatal(err)
	}

	rows := []guardRow{
		{"plain ~ path", "write_file", w("~/" + spDir + "/policy.yaml"), true},
		{"absolute path", "write_file", w(cfg + "/managed.json"), true},
		{"literal $HOME", "write_file", w("$HOME/" + spDir + "/managed.json"), true},
		{"literal ${HOME}", "write_file", w("${HOME}/" + spDir + "/policy.yaml"), true},
		{"file:// URI", "write_file", w("file://" + cfg + "/managed.json"), true},
		{"file:/ URI, one slash (#4352)", "write_file", w("file:" + cfg + "/managed.json"), true},
		{"file://localhost URI", "write_file", w("file://localhost" + cfg + "/managed.json"), true},
		{"percent-encoded file:// URI", "write_file", w("file://" + home + "/%2E" + spDir[1:] + "/managed.json"), true},
		{"relative, cwd HOME", "write_file", w(spDir + "/policy.yaml"), true},
		{"relative ./, cwd HOME", "delete_file", map[string]interface{}{"path": "./" + spDir + "/managed.json"}, true},
		{"relative through ..", "write_file", w("projects/../" + spDir + "/managed.json"), true},
		{"absolute through ..", "write_file", w(home + "/projects/../" + spDir + "/managed.json"), true},
		{"directory itself", "delete_directory", map[string]interface{}{"path": "~/" + spDir}, true},
		{"symlinked HOME alias (#4352)", "write_file", w(alias + "/" + spDir + "/managed.json"), true},
		{"symlink into the config directory", "write_file", w(home + "/projects/cfg-link/managed.json"), true},
		{"move the enrollment away", "move_file", map[string]interface{}{"source": cfg + "/managed.json", "destination": home + "/projects/app/x"}, true},
		{"nested path argument", "batch_write", map[string]interface{}{"files": []interface{}{map[string]interface{}{"path": spDir + "/packs/x.yaml"}}}, true},
		{"file_path argument", "write_file", map[string]interface{}{"file_path": cfg + "/policy.yaml"}, true},
		{"paths array", "save_file", map[string]interface{}{"paths": []interface{}{home + "/projects/app/ok.txt", cfg + "/policy.yaml"}}, true},
		{"Gemini hook file", "write_file", w("~/.gemini/settings.json"), true},
		{"pass2: Gemini hook file, relative", "write_file", w(".gemini/settings.json"), true},
		{"Codex hooks.json", "write_file", w("~/.codex/hooks.json"), true},
		{"Cursor hook through $HOME", "write_file", w("$HOME/.cursor/hooks.json"), true},
		{"Copilot hook file", "write_file", w("~/.copilot/hooks/agent" + "shield.json"), true},
		{"Gemini hook file, file:/ URI", "write_file", w("file:" + home + "/.gemini/settings.json"), true},
		{"command text: remove the directory", "execute_command", map[string]interface{}{"command": "rm -rf ~/" + spDir}, true},
		{"command text: quote-split", "execute_command", map[string]interface{}{"command": "rm -rf ~/.agent''shield"}, true},
		{"command text: glob", "execute_command", map[string]interface{}{"command": "rm -rf ~/.agent*"}, true},
		{"command text: overwrite a hook file", "start_process", map[string]interface{}{"command": "echo {} > ~/.claude/settings.json"}, true},
		{"command text: variable indirection", "execute_command", map[string]interface{}{"command": "X=shield; rm -rf ~/.agent$X"}, true},
		{"command text: braced variable", "execute_command", map[string]interface{}{"command": "export D=" + spDir + " && rm -rf ~/${D}"}, true},
		{"Cursor MCP config (setup mcp wraps it)", "write_file", w("$HOME/.cursor/mcp.json"), true},
		{"Cursor MCP config, file:/ URI", "write_file", w("file:" + home + "/.cursor/mcp.json"), true},
		{"command text: interpreter", "run_shell", map[string]interface{}{"cmd": "python3 -c \"open('" + cfg + "/policy.yaml','w')\""}, true},

		// Allowed: main allowed these, and none names a target here.
		{"agentshield-notes directory", "write_file", w("~/projects/agentshield-notes/readme.md"), false},
		{".agentshield-notes directory", "write_file", w("~/projects/" + spDir + "-notes/readme.md"), false},
		{"word glued to a directory name", "write_file", w("docs/my" + spDir + "/notes.md"), false},
		{"another user's directory", "write_file", w("/home/other-user/" + spDir + "/audit.log"), false},
		{"another user's directory as a file:// URI", "write_file", w("file:///home/other-user/" + spDir + "/audit.log"), false},
		{"file:// URI on another host", "write_file", w("file://fileserver" + cfg + "/managed.json"), false},
		{"project-level config dir, relative", "write_file", w("projects/app/config/" + spDir + "/r.yml"), false},
		{"project-level settings, absolute", "write_file", w(home + "/projects/app/.claude/settings.json"), false},
		{"Windows separators are one file name here", "write_file", w(`C:\Users\u\` + spDir + `\policy.yaml`), false},
		{"percent-encoded relative path is literal", "write_file", w("%2E" + spDir[1:] + "/policy.yaml"), false},
		{"command text: relative word (cd, then act) is not read", "run_shell", map[string]interface{}{"cmd": "cd " + spDir + " && rm managed.json"}, false},
		{"command text: echo into .gitignore", "start_process", map[string]interface{}{"command": "echo '" + spDir + "/' >> .gitignore"}, false},
		{"command text: plain read, tail", "start_process", map[string]interface{}{"command": "tail -5 ~/" + spDir + "/audit.jsonl"}, false},
		{"command text: plain read, ls", "start_process", map[string]interface{}{"command": "ls -la ~/" + spDir}, false},
		{"command text: plain read, grep", "start_process", map[string]interface{}{"command": "grep -rn \"" + spDir + "\" docs/"}, false},
		{"command text: agentshield CLI", "execute_command", map[string]interface{}{"command": "agentshield status"}, false},
		{"read tool, relative", "read_file", map[string]interface{}{"path": spDir + "/policy.yaml"}, false},
	}
	runGuardRows(t, rows)

	// Rows whose answer is the volume's. The spelled path is checked against
	// the real one on this machine.
	upper := strings.ToUpper(spDir)
	for _, v := range []struct{ name, spelled, real string }{
		{"upper-case directory", home + "/" + upper + "/managed.json", cfg + "/managed.json"},
		{"mixed-case directory", home + "/.AgentShield/policy.yaml", cfg + "/policy.yaml"},
		{"pass2: config dir, APFS long-s fold (#4352)", home + "/.agentſhield/managed.json", cfg + "/managed.json"},
		{"pass2: Gemini hook file, APFS long-s fold", home + "/.gemini/ſettings.json", home + "/.gemini/settings.json"},
		{"pass2: Codex hook file, APFS Kelvin fold", home + "/.codex/hooKs.json", home + "/.codex/hooks.json"},
		{"upper-case hook directory", home + "/.CLAUDE/settings.json", home + "/.claude/settings.json"},
	} {
		want := sameFile(v.spelled, v.real)
		runGuardRows(t, []guardRow{{v.name + " (same file here: " + map[bool]string{true: "yes", false: "no"}[want] + ")", "write_file", w(v.spelled), want}})
	}

	// The /System/Volumes/Data firmlink. On macOS it is the same file, and the
	// row requires that before asserting the BLOCK, so a change of premise
	// fails here instead of passing quietly. Elsewhere the firmlink does not
	// exist: /System/Volumes/Data/... is another path, and the documented
	// behaviour is that the guard does not block it.
	firm := "/System/Volumes/Data" + cfg + "/managed.json"
	if runtime.GOOS == "darwin" {
		if !sameFile(firm, cfg+"/managed.json") {
			t.Fatalf("premise: on macOS %s should be %s/managed.json", firm, cfg)
		}
		runGuardRows(t, []guardRow{{"firmlink (macOS: the same file)", "write_file", w(firm), true}})
	} else {
		runGuardRows(t, []guardRow{{"firmlink (" + runtime.GOOS + ": another path)", "write_file", w(firm), false}})
	}
}

// A relative path resolves against the proxy's working directory: in a
// project, `.claude/settings.json` is the project's file, not the user's hook.
func TestConfigGuard_RelativeFromProjectCwd(t *testing.T) {
	home := newTargetHome(t)
	t.Chdir(filepath.Join(home, "projects", "app"))
	runGuardRows(t, []guardRow{
		{"project .claude/settings.json", "write_file", map[string]interface{}{"path": ".claude/settings.json"}, false},
		{"project config/.agentshield", "write_file", map[string]interface{}{"path": "config/" + spDir + "/r.yml"}, false},
		{"up to HOME through ..", "write_file", map[string]interface{}{"path": "../../" + spDir + "/managed.json"}, true},
	})
}

// An NFD-spelled HOME names the NFC directory on APFS (#4352).
func TestConfigGuard_NFDHome(t *testing.T) {
	base := t.TempDir()
	if real, err := filepath.EvalSymlinks(base); err == nil {
		base = real
	}
	nfc := filepath.Join(base, "jos\u00e9")
	nfd := filepath.Join(base, "jose\u0301")
	if err := os.MkdirAll(filepath.Join(nfc, spDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nfc, spDir, "managed.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", nfc)
	want := sameFile(nfd, nfc)
	got := CheckConfigGuard("write_file", map[string]interface{}{"path": nfd + "/" + spDir + "/managed.json"})
	if got.Blocked != want {
		t.Fatalf("NFD HOME spelling: Blocked = %v; want %v (same directory on this volume: %v)", got.Blocked, want, want)
	}
}

// The case fold below HOME follows the volume. Pinned both ways, so the
// probe's answer is what decides and a mutant that ignores it fails on any
// machine.
func TestConfigGuard_CaseFoldFollowsVolume(t *testing.T) {
	home := newTargetHome(t)
	// ~/.codex/config.json is a target that does not exist here, in a
	// directory that does: the file part can only be compared by spelling,
	// so the probe's answer decides.
	spelled := home + "/.codex/CONFIG.JSON"
	prev := homeFoldsCase
	t.Cleanup(func() { homeFoldsCase = prev })
	for _, folds := range []bool{true, false} {
		homeFoldsCase = func(string) bool { return folds }
		got := CheckConfigGuard("write_file", map[string]interface{}{"path": spelled})
		if got.Blocked != folds {
			t.Errorf("homeFoldsCase=%v: Blocked = %v; want %v", folds, got.Blocked, folds)
		}
	}
	// A probe that says "no fold" on a volume that does fold: an existing
	// directory the spelling resolves to is still found by identity.
	homeFoldsCase = func(string) bool { return false }
	upperDir := home + "/" + strings.ToUpper(spDir)
	want := sameFile(upperDir, home+"/"+spDir)
	if got := CheckConfigGuard("write_file", map[string]interface{}{"path": upperDir + "/managed.json"}); got.Blocked != want {
		t.Errorf("probe says no fold, %s is the config dir here: %v; Blocked = %v; want %v", upperDir, want, got.Blocked, want)
	}
	if foldKey("ſ") != foldKey("s") || foldKey("K") != foldKey("k") || foldKey("S") != foldKey("s") {
		t.Error("foldKey does not fold long s and the Kelvin sign")
	}
}

// The reviewer's false-positive set (#4337 review pass 2, fp.py): benign
// calls that name the directory. The guard (every mode) must not block what
// main allowed. The one row main blocks is pinned too.
func TestConfigGuard_FalsePositiveCorpus(t *testing.T) {
	home := newTargetHome(t)
	t.Chdir(home)
	P := home + "/projects/app"
	rows := []guardRow{
		{"write README prose naming the dir", "write_file", map[string]interface{}{"path": P + "/README.md", "content": "AgentShield keeps its settings in ~/" + spDir + "/agentshield.yaml; edit that file to switch modes."}, false},
		{"write doc: code-block line $HOME/...", "write_file", map[string]interface{}{"path": P + "/docs/setup.md", "content": "# Setup\n\n```\n$HOME/" + spDir + "/agentshield.yaml\n```\n"}, false},
		{"write doc: code-block line ${HOME}/...", "write_file", map[string]interface{}{"path": P + "/docs/setup2.md", "content": "Config file:\n\n    ${HOME}/" + spDir + "/policy.yaml\n"}, false},
		{"write doc: line file:// URI", "write_file", map[string]interface{}{"path": P + "/docs/links.md", "content": "See\nfile://" + home + "/" + spDir + "/audit.jsonl\n"}, false},
		{"write doc: line ~/.AgentShield (mixed case)", "write_file", map[string]interface{}{"path": P + "/docs/case.md", "content": "Path:\n~/.AgentShield/policy.yaml\n"}, false},
		{"write .gitignore with dir line", "write_file", map[string]interface{}{"path": P + "/.gitignore", "content": "node_modules/\n" + spDir + "/\n"}, false},
		{"write relative docs/agentshield.md", "write_file", map[string]interface{}{"path": "docs/agentshield.md", "content": "notes"}, false},
		{"write relative src/.agentshield.ts", "write_file", map[string]interface{}{"path": "src/" + spDir + ".ts", "content": "export {}"}, false},
		{"write relative project-local .agentshield/rules.yaml", "write_file", map[string]interface{}{"path": "config/" + spDir + "/rules.yaml", "content": "rules: []"}, false},
		{"write absolute project-local .agentshield/rules.yaml", "write_file", map[string]interface{}{"path": P + "/" + spDir + "/rules.yaml", "content": "rules: []"}, false},
		{"write project .vscode/settings.json", "write_file", map[string]interface{}{"path": P + "/.vscode/settings.json", "content": "{}"}, false},
		{"write project src/index.ts", "write_file", map[string]interface{}{"path": P + "/src/index.ts", "content": "console.log(1)"}, false},
		{"write ~/Projects (capital) file", "write_file", map[string]interface{}{"path": home + "/Projects/App/notes.md", "content": "x"}, false},
		{"write ~/.config/app/config.json", "write_file", map[string]interface{}{"path": home + "/.config/app/config.json", "content": "{}"}, false},
		{"write ~/.Bashrc (case variant of a non-self-protection file: main's matching)", "write_file", map[string]interface{}{"path": home + "/.Bashrc", "content": "x"}, false},
		{"write ~/.SSH/config (same)", "write_file", map[string]interface{}{"path": home + "/.SSH/config", "content": "x"}, false},
		{"start_process: tail the audit log", "start_process", map[string]interface{}{"command": "tail -5 ~/" + spDir + "/audit.jsonl"}, false},
		{"start_process: grep docs for the dir", "start_process", map[string]interface{}{"command": "grep -rn \"" + spDir + "\" docs/"}, false},
		{"start_process: ls the dir", "start_process", map[string]interface{}{"command": "ls -la ~/" + spDir}, false},
		{"start_process: agentshield status", "start_process", map[string]interface{}{"command": "agentshield status"}, false},
		{"start_process: git status", "start_process", map[string]interface{}{"command": "git status"}, false},
		{"start_process: append dir to .gitignore", "start_process", map[string]interface{}{"command": "echo '" + spDir + "/' >> .gitignore"}, false},
		{"update_description: prose naming the dir", "update_description", map[string]interface{}{"text": "Store overrides in ~/" + spDir + "/agentshield.yaml"}, false},
		{"get_transcript: prose", "get_transcript", map[string]interface{}{"video_id": "abc", "note": "mentions " + spDir + " folder"}, false},
		{"retrieval_search: query naming the dir", "retrieval_search", map[string]interface{}{"query": "where is " + spDir + "/policy.yaml documented"}, false},
		{"evaluate_model: prompt naming the dir", "evaluate_model", map[string]interface{}{"prompt": "Explain what ~/" + spDir + " contains"}, false},
		{"search_files: pattern = the dir name", "search_files", map[string]interface{}{"path": P, "pattern": spDir}, false},
		{"send_message: single path token", "send_message", map[string]interface{}{"text": spDir + "/policy.yaml"}, false},
		{"send_message: sentence", "send_message", map[string]interface{}{"text": "Please review " + spDir + "/policy.yaml today"}, false},
		// Not exec tools by name segment, so an "input" is not command text.
		{"update_description: input naming a hook file", "update_description", map[string]interface{}{"input": "echo {} " + ">" + " ~/.claude/settings.json"}, false},
		{"get_transcript: args naming the dir", "get_transcript", map[string]interface{}{"args": "rm -rf ~/" + spDir}, false},
		// Reads are not tampering: the new readings cover write-, delete- and
		// exec-shaped tools only. (Main's own reading still blocks a read of
		// ~/.agentshield/... spelled with ~; unchanged.)
		{"read_file: $HOME spelling", "read_file", map[string]interface{}{"path": "$HOME/" + spDir + "/policy.yaml"}, false},
		{"read_file: relative example policy", "read_file", map[string]interface{}{"path": "examples/" + spDir + "/policy.yaml"}, false},
		{"read_file: .agentshield-example dir", "read_file", map[string]interface{}{"path": "docs/" + spDir + "-example/policy.yaml"}, false},
	}
	runGuardRows(t, rows)
}

// The audit-only keep rule: a BLOCK enforce mode made is kept when the call
// names a target in any spelling, a relative path by its tail. It never adds
// a BLOCK, so it reads more broadly than the guard.
func TestKeepRule_NamesSelfProtectTarget(t *testing.T) {
	home := newTargetHome(t)
	t.Chdir(t.TempDir()) // not HOME: the tail reading must not need it
	for _, r := range []struct {
		name string
		tool string
		args map[string]interface{}
		keep bool
	}{
		{"relative Gemini hook file", "write_file", map[string]interface{}{"path": ".gemini/settings.json"}, true},
		{"relative ./ Codex hook file", "write_file", map[string]interface{}{"path": "./.codex/hooks.json"}, true},
		{"relative ../ Claude hook file", "write_file", map[string]interface{}{"path": "../../x/.claude/settings.json"}, true},
		{"relative config dir", "delete_file", map[string]interface{}{"path": spDir + "/managed.json"}, true},
		{"long s in a hook file name", "write_file", map[string]interface{}{"path": home + "/.gemini/ſettings.json"}, true},
		{"Kelvin sign in a hook file name", "write_file", map[string]interface{}{"path": home + "/.codex/hooKs.json"}, true},
		{"file:/ URI", "write_file", map[string]interface{}{"path": "file:" + home + "/.gemini/settings.json"}, true},
		{"command text names a hook file", "execute_command", map[string]interface{}{"command": "echo {} > ~/.claude/settings.json"}, true},
		{"command text: cd, then relative", "execute_command", map[string]interface{}{"command": "cd ~ && rm -rf " + spDir}, true},
		{"command text: long s", "execute_command", map[string]interface{}{"command": "rm -rf ~/.agentſhield"}, true},
		{"command text: plain read is not kept", "execute_command", map[string]interface{}{"command": "tail -5 ~/" + spDir + "/audit.jsonl"}, false},
		{"prose is not a path", "write_file", map[string]interface{}{"path": home + "/projects/app/README.md", "content": "see ~/" + spDir + "/policy.yaml for details"}, false},
		{"VS Code settings are not a target", "write_file", map[string]interface{}{"path": home + "/Library/Application Support/Code/User/settings.json"}, false},
		{"project file", "write_file", map[string]interface{}{"path": home + "/projects/app/README.md"}, false},
	} {
		t.Run(r.name, func(t *testing.T) {
			if got := argsNameSelfProtectTarget(r.tool, r.args); got != r.keep {
				t.Fatalf("argsNameSelfProtectTarget(%s, %v) = %v; want %v", r.tool, r.args, got, r.keep)
			}
		})
	}
}

// End to end through the handler in audit-only: a hook-file write enforce
// mode BLOCKs (here by a **/.gemini/** rule, as the community pack does) is
// kept, in a spelling the guard does not read (relative, cwd not HOME); the
// same rule on a non-target file is lowered.
func TestApplyToolCallMode_KeepsHookFileBlock(t *testing.T) {
	newTargetHome(t)
	t.Chdir(t.TempDir())
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		Rules:    []MCPRule{{ID: "gemini-dir", Match: MCPMatch{ToolName: "write_file", ArgumentPatterns: map[string]string{"path": "**/.gemini/**"}}, Decision: policy.DecisionBlock, Reason: "gemini dir"}},
	}
	for _, r := range []struct {
		path string
		keep bool
	}{
		{".gemini/settings.json", true},
		{".gemini/notes.md", false},
	} {
		var entries []AuditEntry
		h := newMessageHandler(NewPolicyEvaluator(pol), func(e AuditEntry) { entries = append(entries, e) }, io.Discard, "t", t.TempDir(), nil, nil)
		h.Mode = "audit-only"
		params, _ := json.Marshal(map[string]interface{}{"name": "write_file", "arguments": map[string]interface{}{"path": r.path, "content": "{}"}})
		raw, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": json.RawMessage(params)})
		msg, _, _ := ParseMessage(raw)
		if blocked, _ := h.HandleToolCall(msg); blocked != r.keep {
			t.Errorf("%s: blocked = %v; want %v (record %+v)", r.path, blocked, r.keep, entries)
		}
	}
}
