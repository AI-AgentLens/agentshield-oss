package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/logger"
)

// #4452: the Claude-shaped PreToolUse path (Claude Code, Codex CLI, both
// Copilot CLI dialects) evaluated every command against the hook PROCESS's
// working directory and ignored the payload's cwd. These tests start the real
// hook entry point in one directory with a payload naming another, which is
// the only setup that can tell the two apart: a test whose hook process runs
// in the payload's cwd passes on main.

// cwdFixture is a scratch HOME plus two sibling directories. Only a/vault is
// protected, so `cat vault/key` BLOCKs exactly when it resolves against a.
type cwdFixture struct {
	home, a, b string
}

// canonicalTempDir returns t.TempDir() with symlinks resolved (/var →
// /private/var on macOS), so the child's os.Getwd() spells it the same way.
func canonicalTempDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func newCwdFixture(t *testing.T) *cwdFixture {
	t.Helper()
	root := canonicalTempDir(t)
	f := &cwdFixture{
		home: filepath.Join(root, "home"),
		a:    filepath.Join(root, "a"),
		b:    filepath.Join(root, "b"),
	}
	for _, d := range []string{filepath.Join(f.home, ".agentshield"), filepath.Join(f.a, "vault"), f.b} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.a, "vault", "key"), []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.writePolicy(t, "version: \"0.1\"\ndefaults:\n  decision: \"AUDIT\"\n  protected_paths:\n    - \""+f.a+"/vault/**\"\n")
	if err := os.WriteFile(filepath.Join(f.home, ".agentshield", "agentshield.yaml"), []byte("mode: enforce\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *cwdFixture) writePolicy(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.home, ".agentshield", "policy.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// vaultRead is relative on purpose: it names a protected file only when it
// resolves against f.a.
const vaultRead = "cat vault/key"

// runHookFrom runs the real hook entry point in a child process whose working
// directory is dir, with HOME=home and AGENTSHIELD_AGENT_ID cleared.
func runHookFrom(t *testing.T, dir, home, payload string, extraEnv ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHookProcess$")
	cmd.Dir = dir
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "AGENTSHIELD_AGENT_ID=") || strings.HasPrefix(kv, "PWD=") ||
			strings.HasPrefix(kv, "AGENTSHIELD_ARTIFACT_") || strings.HasPrefix(kv, "AGENTSHIELD_BYPASS=") {
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = append(append(env, "AGENTSHIELD_FAILSAFE_HOOK_HELPER=1", "HOME="+home, "PWD="+dir), extraEnv...)
	cmd.Stdin = strings.NewReader(payload)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err == nil {
		return 0, out.String(), errb.String()
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), out.String(), errb.String()
	}
	t.Fatalf("running hook helper: %v", err)
	return -1, "", ""
}

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// claudeBash is a Claude Code Bash PreToolUse payload; cwd "" omits the key.
func claudeBash(t *testing.T, cwd, command string) string {
	t.Helper()
	p := map[string]interface{}{
		"session_id":      "sess-4452",
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input":      map[string]interface{}{"command": command},
	}
	if cwd != "" {
		p["cwd"] = cwd
	}
	return mustJSON(t, p)
}

func lastHookEvent(t *testing.T, home string) logger.AuditEvent {
	t.Helper()
	events := readAuditEventsForTest(t, home)
	if len(events) == 0 {
		t.Fatal("no audit events written")
	}
	return events[len(events)-1]
}

func cwdNoteOf(e logger.AuditEvent) (logger.Note, bool) {
	for _, n := range e.Notes {
		if n.Kind == analyzer.NotePayloadCwdUnusable {
			return n, true
		}
	}
	return logger.Note{}, false
}

// TestPayloadEvalCwd is the decision table for the payload cwd.
func TestPayloadEvalCwd(t *testing.T) {
	dir := canonicalTempDir(t)
	file := filepath.Join(dir, "plain-file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, in, want, why string // why "" = no note
	}{
		{"empty", "", "", ""},
		{"absolute directory", dir, dir, ""},
		{"absolute directory, trailing slash kept as sent", dir + "/", dir + "/", ""},
		{"relative", "some/rel", "", "is not an absolute path"},
		{"dot", ".", "", "is not an absolute path"},
		{"missing", filepath.Join(dir, "gone"), "", "does not exist"},
		{"not a directory", file, "", "is not a directory"},
		// stat fails with ENOTDIR, which is not "does not exist".
		{"under a file", filepath.Join(file, "sub"), "", "cannot be read"},
	}
	for _, c := range cases {
		got, notes := payloadEvalCwd(c.in)
		if got != c.want {
			t.Errorf("%s: payloadEvalCwd(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
		if c.why == "" {
			if len(notes) != 0 {
				t.Errorf("%s: unexpected notes %+v", c.name, notes)
			}
			continue
		}
		if len(notes) != 1 || notes[0].Kind != analyzer.NotePayloadCwdUnusable ||
			!strings.Contains(notes[0].Detail, c.why) || !strings.Contains(notes[0].Detail, c.in) {
			t.Errorf("%s: notes = %+v, want one %s note naming %q and %q", c.name, notes, analyzer.NotePayloadCwdUnusable, c.in, c.why)
		}
	}
	// The process's own directory under another spelling (a symlink to it)
	// yields the process's spelling: what main evaluated against.
	link := filepath.Join(canonicalTempDir(t), "link-to-dir")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	wd, _ := os.Getwd()
	if got, notes := payloadEvalCwd(link); got != wd || len(notes) != 0 {
		t.Errorf("payloadEvalCwd(symlink to the process dir) = %q %+v, want the process spelling %q", got, notes, wd)
	}
	if got, _ := payloadEvalCwd(dir + "/"); got != wd {
		t.Errorf("payloadEvalCwd(process dir + \"/\") = %q, want %q", got, wd)
	}

	long := "rel/" + strings.Repeat("x", 2*maxNoteValueLen)
	if _, notes := payloadEvalCwd(long); len(notes) != 1 || len(notes[0].Detail) > maxNoteValueLen+200 {
		t.Errorf("a long payload cwd must be truncated in the note: %+v", notes)
	}
}

// TestHookPayloadCwd_ArtifactHashRepro is the issue's repro: the payload's cwd
// is a repo whose skill script changed after the scan, the manifest is set and
// verify mode is block. The hook process starts somewhere else. Main skipped
// the artifact check silently (the script was not under the process cwd) and
// returned AUDIT.
func TestHookPayloadCwd_ArtifactHashRepro(t *testing.T) {
	f := newCwdFixture(t)
	script := filepath.Join(".claude", "skills", "pdf-export", "scripts", "export.py")
	original := "print('export')\n"
	sum := sha256.Sum256([]byte(original))
	manifest := filepath.Join(f.home, "artifacts.yaml")
	if err := os.WriteFile(manifest, []byte("version: 1.0.0\nartifacts:\n  - path: "+filepath.ToSlash(script)+"\n    sha256: "+hex.EncodeToString(sum[:])+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// repo-after: the script as it is now (one line appended upstream);
	// repo: the reviewed original, a sibling the hook process may sit in.
	after := filepath.Join(f.b, "repo-after")
	reviewed := filepath.Join(f.b, "repo")
	for dir, body := range map[string]string{after: original + "# updated upstream\n", reviewed: original} {
		p := filepath.Join(dir, script)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	payload := claudeBash(t, after, "python3 "+filepath.ToSlash(script)+" report.md")
	env := []string{"AGENTSHIELD_ARTIFACT_MANIFEST=" + manifest, "AGENTSHIELD_ARTIFACT_VERIFY_MODE=block"}

	for _, start := range []struct{ label, dir string }{
		{"unrelated directory (main: check skipped, AUDIT)", f.a},
		{"sibling checkout holding the reviewed script (main: hashed the wrong file, AUDIT)", reviewed},
		{"the repo itself (main already BLOCKed)", after},
	} {
		code, _, stderr := runHookFrom(t, start.dir, f.home, payload, env...)
		if code != 2 || !strings.Contains(stderr, artifactRuleIDForTest) {
			t.Errorf("hook started in %s: exit %d, want 2 naming %s (stderr: %s)", start.label, code, artifactRuleIDForTest, stderr)
		}
		if e := lastHookEvent(t, f.home); e.Cwd != after {
			t.Errorf("hook started in %s: event cwd %q, want the payload's %q", start.label, e.Cwd, after)
		}
	}

	// Control: the unmodified repo as the payload cwd passes, wherever the
	// hook starts, so the BLOCK above is the hash mismatch and not the setup.
	code, _, stderr := runHookFrom(t, f.a, f.home, claudeBash(t, reviewed, "python3 "+filepath.ToSlash(script)+" report.md"), env...)
	if code != 0 {
		t.Errorf("reviewed repo as payload cwd: exit %d, want 0 (stderr: %s)", code, stderr)
	}
}

const artifactRuleIDForTest = "comply-skill-artifact-tamper"

// TestHookPayloadCwd_RelativeProtectedPathBothDirections: a relative path
// resolves where the agent's shell is, which moves decisions both ways.
func TestHookPayloadCwd_RelativeProtectedPathBothDirections(t *testing.T) {
	f := newCwdFixture(t)

	// Raise: the agent is in a, the hook process in b. Main resolved
	// b/vault/key (unprotected) and allowed the read of a/vault/key.
	code, _, stderr := runHookFrom(t, f.b, f.home, claudeBash(t, f.a, vaultRead))
	if code != 2 {
		t.Errorf("agent in protected dir, hook elsewhere: exit %d, want 2 (stderr: %s)", code, stderr)
	}
	if e := lastHookEvent(t, f.home); e.Decision != "BLOCK" || e.Cwd != f.a {
		t.Errorf("raise: event decision=%s cwd=%q, want BLOCK at %q", e.Decision, e.Cwd, f.a)
	}

	// Lower: the agent is in b, the hook process in a. Main resolved
	// a/vault/key and blocked a read of b/vault/key, which is not protected.
	code, _, stderr = runHookFrom(t, f.a, f.home, claudeBash(t, f.b, vaultRead))
	if code != 0 {
		t.Errorf("agent outside protected dir, hook inside: exit %d, want 0 (stderr: %s)", code, stderr)
	}
	if e := lastHookEvent(t, f.home); e.Decision == "BLOCK" || e.Cwd != f.b {
		t.Errorf("lower: event decision=%s cwd=%q, want not BLOCK at %q", e.Decision, e.Cwd, f.b)
	}
	if _, noted := cwdNoteOf(lastHookEvent(t, f.home)); noted {
		t.Error("a usable payload cwd must not carry a payload_cwd_unusable note")
	}

	// An absolute path is not moved by the cwd at all.
	code, _, _ = runHookFrom(t, f.b, f.home, claudeBash(t, f.b, "cat "+f.a+"/vault/key"))
	if code != 2 {
		t.Errorf("absolute protected path: exit %d, want 2 regardless of cwd", code)
	}
}

// TestHookPayloadCwd_SymlinkSpelling: a payload cwd that is the process's
// own directory under a symlinked spelling evaluates exactly as main did (the
// process spelling). Without that rule the symlink spelling missed a/vault/**
// lexically and a BLOCK main made became AUDIT. A symlinked cwd naming a
// DIFFERENT directory is used as sent: protected-path matching is lexical and
// does not resolve symlinks (true of absolute paths too), so it decides what
// main decided there. Pinned as a known gap, not closed here.
func TestHookPayloadCwd_SymlinkSpelling(t *testing.T) {
	f := newCwdFixture(t)
	link := filepath.Join(f.b, "link-to-a")
	if err := os.Symlink(f.a, link); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runHookFrom(t, f.a, f.home, claudeBash(t, link, vaultRead))
	if code != 2 {
		t.Errorf("payload cwd = symlink to the process dir: exit %d, want 2 as on main (stderr: %s)", code, stderr)
	}
	if e := lastHookEvent(t, f.home); e.Cwd != f.a {
		t.Errorf("event cwd %q, want the process spelling %q", e.Cwd, f.a)
	}
	// Known gap, pinned: same file, different directory from the process.
	code, _, _ = runHookFrom(t, f.b, f.home, claudeBash(t, link, vaultRead))
	if code != 0 {
		t.Errorf("payload cwd = symlink to a, process in b: exit %d; the lexical-match gap is pinned at main's decision (0)", code)
	}
}

// TestHookPayloadCwd_PrivateVarSpelling probes both macOS spellings of a cwd
// under /var: the payload cwd is used as sent (not symlink-resolved), so a
// /private/var spelling has to reach the protected /var pattern through the
// engine's #4387 alias reading. Linux has no /private, so it is skipped there.
func TestHookPayloadCwd_PrivateVarSpelling(t *testing.T) {
	short := filepath.Clean(os.TempDir())
	if !strings.HasPrefix(short, "/var/") {
		t.Skipf("TMPDIR %q is not under /var", short)
	}
	if fi, err := os.Stat("/private" + short); err != nil || !fi.IsDir() {
		t.Skip("no /private alias on this system")
	}
	dir, err := os.MkdirTemp(short, "cwd4452-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.MkdirAll(filepath.Join(dir, "vault"), 0o700); err != nil {
		t.Fatal(err)
	}
	f := newCwdFixture(t)
	f.writePolicy(t, "version: \"0.1\"\ndefaults:\n  decision: \"AUDIT\"\n  protected_paths:\n    - \""+dir+"/vault/**\"\n")
	for _, cwd := range []string{dir, "/private" + dir} {
		code, _, stderr := runHookFrom(t, f.b, f.home, claudeBash(t, cwd, vaultRead))
		if code != 2 {
			t.Errorf("payload cwd %q: exit %d, want 2 (stderr: %s)", cwd, code, stderr)
		}
	}
}

// TestHookPayloadCwd_FallsBackToProcessDir: no cwd, a relative cwd, a missing
// one and a file all evaluate against the hook process's directory — main's
// behaviour — and only the unusable ones carry a note naming the payload value.
func TestHookPayloadCwd_FallsBackToProcessDir(t *testing.T) {
	f := newCwdFixture(t)
	file := filepath.Join(f.b, "not-a-dir")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		label, cwd, why string
	}{
		{"no cwd in the payload", "", ""},
		{"relative cwd", "b", "is not an absolute path"},
		{"missing cwd", filepath.Join(f.b, "gone"), "does not exist"},
		{"cwd is a file", file, "is not a directory"},
	}
	for _, c := range cases {
		// The process sits in a, so the fallback BLOCKs and a wrong use of
		// the payload value (resolving under b) would not.
		code, _, stderr := runHookFrom(t, f.a, f.home, claudeBash(t, c.cwd, vaultRead))
		if code != 2 {
			t.Errorf("%s: exit %d, want 2 from the process-dir fallback (stderr: %s)", c.label, code, stderr)
			continue
		}
		e := lastHookEvent(t, f.home)
		if e.Cwd != f.a {
			t.Errorf("%s: event cwd %q, want the process dir %q", c.label, e.Cwd, f.a)
		}
		n, noted := cwdNoteOf(e)
		switch {
		case c.why == "" && noted:
			t.Errorf("%s: unexpected note %+v", c.label, n)
		case c.why != "" && (!noted || !strings.Contains(n.Detail, c.why) || !strings.Contains(n.Detail, c.cwd)):
			t.Errorf("%s: notes %+v, want a %s note naming %q and %q", c.label, e.Notes, analyzer.NotePayloadCwdUnusable, c.cwd, c.why)
		}
	}
}

// TestHookPayloadCwd_NoteOnFailSafeAndSelfProtectEvents: the note travels on
// every event the evaluation can record, not only the ordinary one.
func TestHookPayloadCwd_NoteOnFailSafeAndSelfProtectEvents(t *testing.T) {
	t.Run("fail-safe (policy load failed)", func(t *testing.T) {
		f := newCwdFixture(t)
		f.writePolicy(t, "version: [not yaml\n")
		_, _, _ = runHookFrom(t, f.a, f.home, claudeBash(t, "rel", vaultRead))
		e := lastHookEvent(t, f.home)
		if e.Error == "" {
			t.Fatalf("want a fail-safe event, got %+v", e)
		}
		if _, noted := cwdNoteOf(e); !noted {
			t.Errorf("fail-safe event lost the payload cwd note: %+v", e.Notes)
		}
	})
	t.Run("managed self-protect block", func(t *testing.T) {
		f := newCwdFixture(t)
		if err := os.WriteFile(filepath.Join(f.home, ".agentshield", "managed.json"), []byte(`{"managed": true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := "export AGENTSHIELD_" + "BYPASS=1"
		code, _, stderr := runHookFrom(t, f.a, f.home, claudeBash(t, "rel", cmd))
		if code != 2 {
			t.Fatalf("self-protect: exit %d, want 2 (stderr: %s)", code, stderr)
		}
		e := lastHookEvent(t, f.home)
		if len(e.TriggeredRules) == 0 || e.TriggeredRules[0] != "enterprise-self-protect" {
			t.Fatalf("want the self-protect event, got %+v", e)
		}
		if _, noted := cwdNoteOf(e); !noted {
			t.Errorf("self-protect event lost the payload cwd note: %+v", e.Notes)
		}
	})
}

// TestHookPayloadCwd_EveryClaudeShapedDialect: Codex CLI and both Copilot CLI
// dialects share handlePreToolUse; Copilot's native dialect carries cwd at the
// top level next to toolName/toolArgs, and handleCopilotNativeHook copied it
// into a field nothing read.
func TestHookPayloadCwd_EveryClaudeShapedDialect(t *testing.T) {
	f := newCwdFixture(t)
	payloads := map[string]string{
		"codex": mustJSON(t, map[string]interface{}{
			"hook_event_name": "PreToolUse", "tool_name": "Bash", "turn_id": "t1", "cwd": f.a,
			"tool_input": map[string]interface{}{"command": vaultRead},
		}),
		"copilot compat": copilotCompatPayload(t, "s", "Bash", shellArgs(vaultRead)),
		"copilot native": copilotNativePayload(t, "s", "bash", shellArgs(vaultRead)),
	}
	for name, p := range payloads {
		p = strings.Replace(p, `"cwd":"/repo"`, `"cwd":"`+f.a+`"`, 1)
		if !strings.Contains(p, f.a) {
			t.Fatalf("%s: fixture did not take the cwd: %s", name, p)
		}
		code, _, stderr := runHookFrom(t, f.b, f.home, p)
		if code != 2 {
			t.Errorf("%s: hook in b, payload cwd a: exit %d, want 2 (stderr: %s)", name, code, stderr)
		}
		if e := lastHookEvent(t, f.home); e.Cwd != f.a {
			t.Errorf("%s: event cwd %q, want %q", name, e.Cwd, f.a)
		}
	}
}

// TestHookPayloadCwd_OtherHarnessesUnchanged pins Cursor, Windsurf and Gemini
// CLI, which passed their own cwd before #4452 and still do, unvalidated.
func TestHookPayloadCwd_OtherHarnessesUnchanged(t *testing.T) {
	f := newCwdFixture(t)

	// Cursor: top-level cwd, used as sent.
	code, out, _ := runHookFrom(t, f.b, f.home, mustJSON(t, map[string]interface{}{"command": vaultRead, "cwd": f.a}))
	if code != 0 || !strings.Contains(out, `"permission":"deny"`) {
		t.Errorf("cursor, payload cwd a: exit %d stdout %q, want a deny verdict", code, out)
	}
	code, out, _ = runHookFrom(t, f.a, f.home, mustJSON(t, map[string]interface{}{"command": vaultRead, "cwd": f.b}))
	if code != 0 || !strings.Contains(out, `"permission":"allow"`) {
		t.Errorf("cursor, payload cwd b: exit %d stdout %q, want allow", code, out)
	}
	// Known gap, pinned: Cursor's cwd is not validated, so a relative one is
	// recorded and evaluated as sent, with no note. payloadEvalCwd covers the
	// Claude-shaped path only (#4452).
	_, _, _ = runHookFrom(t, f.a, f.home, mustJSON(t, map[string]interface{}{"command": vaultRead, "cwd": "rel"}))
	if e := lastHookEvent(t, f.home); e.Cwd != "rel" {
		t.Errorf("cursor relative cwd: event cwd %q, want %q as sent", e.Cwd, "rel")
	} else if _, noted := cwdNoteOf(e); noted {
		t.Error("cursor relative cwd: got a payload_cwd_unusable note; the Cursor path is not validated")
	}

	// Windsurf: tool_info.cwd.
	code, _, stderr := runHookFrom(t, f.b, f.home, mustJSON(t, map[string]interface{}{
		"agent_action_name": "pre_run_command",
		"tool_info":         map[string]interface{}{"command_line": vaultRead, "cwd": f.a},
	}))
	if code != 2 {
		t.Errorf("windsurf, tool_info.cwd a: exit %d, want 2 (stderr: %s)", code, stderr)
	}

	// Gemini CLI: tool_input.dir_path.
	code, out, _ = runHookFrom(t, f.b, f.home, mustJSON(t, map[string]interface{}{
		"hook_event_name": "BeforeTool", "tool_name": "run_shell_command",
		"tool_input": map[string]interface{}{"command": vaultRead, "dir_path": f.a},
	}))
	if code != 0 || !strings.Contains(out, `"decision":"deny"`) {
		t.Errorf("gemini, dir_path a: exit %d stdout %q, want deny", code, out)
	}
	// Known gap, pinned: Gemini's handler reads tool_input.dir_path only; a
	// top-level cwd is ignored and the process directory is used.
	code, out, _ = runHookFrom(t, f.b, f.home, mustJSON(t, map[string]interface{}{
		"hook_event_name": "BeforeTool", "tool_name": "run_shell_command", "cwd": f.a,
		"tool_input": map[string]interface{}{"command": vaultRead},
	}))
	if code != 0 || !strings.Contains(out, `"decision":"allow"`) {
		t.Errorf("gemini, top-level cwd a without dir_path: exit %d stdout %q, want allow (process dir b)", code, out)
	}
}

// TestHookPayloadCwd_MCPEventRecordsPayloadCwd: a non-shell tool call on the
// same path records the payload cwd too. It used to record os.Getwd().
func TestHookPayloadCwd_MCPEventRecordsPayloadCwd(t *testing.T) {
	f := newCwdFixture(t)
	read := func(cwd string) string {
		return mustJSON(t, map[string]interface{}{
			"session_id": "sess-4452", "hook_event_name": "PreToolUse", "tool_name": "Read", "cwd": cwd,
			"tool_input": map[string]interface{}{"file_path": "/etc/hostname-4452"},
		})
	}
	_, _, _ = runHookFrom(t, f.a, f.home, read(f.b))
	if e := lastHookEvent(t, f.home); e.ToolName != "Read" || e.Cwd != f.b {
		t.Errorf("MCP event: tool=%q cwd=%q, want Read at the payload's %q", e.ToolName, e.Cwd, f.b)
	} else if _, noted := cwdNoteOf(e); noted {
		t.Error("MCP event with a usable cwd carries a note")
	}
	_, _, _ = runHookFrom(t, f.a, f.home, read("rel"))
	e := lastHookEvent(t, f.home)
	if e.Cwd != f.a {
		t.Errorf("MCP event, relative payload cwd: cwd %q, want the process dir %q", e.Cwd, f.a)
	}
	if _, noted := cwdNoteOf(e); !noted {
		t.Errorf("MCP event, relative payload cwd: no %s note: %+v", analyzer.NotePayloadCwdUnusable, e.Notes)
	}
}
