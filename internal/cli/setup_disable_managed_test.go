package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/spf13/cobra"
)

// Tests for #4534. A managed host refuses `setup <surface> --disable` on every
// surface, `setup mcp` included, before anything is read or written, and
// `setup mcp --disable` never creates MCP state on a machine that never had
// it. Each test runs the real command tree in a child process with a scratch
// HOME (TestHelperSetupProcess), so the exit code and the files are what a
// user gets.

// minDisableSurfaces is a floor for the command-tree walk, so a walk that
// finds nothing cannot pass. As of #4534: claude-code, gemini-cli, codex,
// copilot-cli, windsurf, cursor, openclaw and mcp.
const minDisableSurfaces = 8

// setupDisableSurfaces walks the `setup` command tree and returns the
// arguments that select every subcommand taking --disable, e.g.
// ["setup", "mcp"]. Nothing is listed by hand: a new surface is covered the
// day it registers the flag.
func setupDisableSurfaces() [][]string {
	var out [][]string
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Flags().Lookup("disable") != nil {
			// CommandPath is "agentshield setup <name>"; drop the root.
			out = append(out, strings.Fields(c.CommandPath())[1:])
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(setupCmd)
	return out
}

// runSetupChild runs `agentshield <args>` in a child process with HOME set
// and returns its combined output and exit code. The working directory is an
// empty directory, so `setup mcp` finds no project-level .cursor/mcp.json.
func runSetupChild(t *testing.T, home string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperSetupProcess$")
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(),
		"AGENTSHIELD_SETUP_HELPER=1",
		"AGENTSHIELD_SETUP_ARGS="+strings.Join(args, " "),
		"HOME="+home,
		"COPILOT_HOME=",
	)
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &exitErr):
		return string(out), exitErr.ExitCode()
	default:
		t.Fatalf("agentshield %s: %v\n%s", strings.Join(args, " "), err, out)
		return "", -1
	}
}

// writeManagedJSON enrolls home as a managed host.
func writeManagedJSON(t *testing.T, home string) {
	t.Helper()
	dir := filepath.Join(home, ".agentshield")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "managed.json"), []byte(`{"managed": true}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// managedRefusal returns the error CheckDisableAllowed gives for home, which
// must be managed. The tests compare against it rather than a copy of the
// text, so they check that the same function refused.
func managedRefusal(t *testing.T, home string) string {
	t.Helper()
	t.Setenv("HOME", home)
	err := enterprise.CheckDisableAllowed()
	if err == nil {
		t.Fatalf("CheckDisableAllowed() = nil for a HOME with managed.json; the test setup is wrong")
	}
	return err.Error()
}

// snapshotTree maps every path under root to its content hash ("dir" for a
// directory), so two snapshots are equal only if nothing was created,
// removed or changed.
func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	snap := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			snap[rel] = "dir"
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		snap[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

const originalCursorMCP = `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}}}` + "\n"

// wrappedCursorHome returns a HOME whose ~/.cursor/mcp.json was wrapped by a
// real `setup mcp --target cursor` run, with the backup that run left.
func wrappedCursorHome(t *testing.T) string {
	t.Helper()
	home := newSetupHome(t)
	cursorMCP := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(cursorMCP), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cursorMCP, []byte(originalCursorMCP), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := runSetupChild(t, home, "setup", "mcp", "--target", "cursor")
	if code != 0 {
		t.Fatalf("setup mcp --target cursor exited %d:\n%s", code, out)
	}
	wrapped, err := os.ReadFile(cursorMCP)
	if err != nil || !strings.Contains(string(wrapped), "mcp-proxy") {
		t.Fatalf("setup mcp did not wrap %s (err %v):\n%s\nsetup output:\n%s", cursorMCP, err, wrapped, out)
	}
	if _, err := os.Stat(cursorMCP + ".agentshield-backup"); err != nil {
		t.Fatalf("setup mcp left no backup: %v", err)
	}
	return home
}

// On a managed host `setup mcp --disable` is refused like the hook surfaces:
// exit 1, CheckDisableAllowed's message, and the wrapped mcp.json, its backup
// and everything else in HOME byte-identical afterwards.
func TestSetupMCPDisable_ManagedRefusesAndLeavesConfig(t *testing.T) {
	home := wrappedCursorHome(t)
	writeManagedJSON(t, home)
	want := managedRefusal(t, home)
	cursorMCP := filepath.Join(home, ".cursor", "mcp.json")
	wrappedBefore, err := os.ReadFile(cursorMCP)
	if err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, home)

	out, code := runSetupChild(t, home, "setup", "mcp", "--disable")

	if code != 1 {
		t.Errorf("setup mcp --disable on a managed host exited %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, want) {
		t.Errorf("setup mcp --disable on a managed host did not print the managed-mode refusal %q:\n%s", want, out)
	}
	wrappedAfter, err := os.ReadFile(cursorMCP)
	if err != nil {
		t.Fatal(err)
	}
	if string(wrappedAfter) != string(wrappedBefore) {
		t.Errorf("setup mcp --disable changed %s on a managed host:\nbefore:\n%s\nafter:\n%s", cursorMCP, wrappedBefore, wrappedAfter)
	}
	if after := snapshotTree(t, home); !reflect.DeepEqual(before, after) {
		t.Errorf("setup mcp --disable changed HOME on a managed host:\nbefore: %v\nafter:  %v", before, after)
	}
}

// The refusal comes before setup looks agentshield up on PATH: with no
// agentshield on PATH, a managed host still refuses --disable with exit 1.
// Run after the lookup, the check never runs, because setup returns 0 at
// "agentshield not found in PATH".
func TestSetupMCPDisable_ManagedRefusesWithoutAgentshieldOnPath(t *testing.T) {
	home := wrappedCursorHome(t)
	writeManagedJSON(t, home)
	want := managedRefusal(t, home)
	t.Setenv("PATH", t.TempDir())
	if p, err := exec.LookPath("agentshield"); err == nil {
		t.Fatalf("agentshield is still on PATH at %s; the test setup is wrong", p)
	}
	before := snapshotTree(t, home)

	out, code := runSetupChild(t, home, "setup", "mcp", "--disable")

	if code != 1 {
		t.Errorf("setup mcp --disable on a managed host with no agentshield on PATH exited %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, want) {
		t.Errorf("setup mcp --disable on a managed host with no agentshield on PATH did not print the managed-mode refusal %q:\n%s", want, out)
	}
	if after := snapshotTree(t, home); !reflect.DeepEqual(before, after) {
		t.Errorf("setup mcp --disable changed HOME on a managed host:\nbefore: %v\nafter:  %v", before, after)
	}
}

// Managed mode refuses only --disable: `setup mcp` on a managed host still
// wraps the config and exits 0. This keeps the check from widening to setup
// itself.
func TestSetupMCP_ManagedHostStillWraps(t *testing.T) {
	home := newSetupHome(t)
	writeManagedJSON(t, home)
	managedRefusal(t, home) // precondition: this HOME is managed
	cursorMCP := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(cursorMCP), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cursorMCP, []byte(originalCursorMCP), 0o644); err != nil {
		t.Fatal(err)
	}

	out, code := runSetupChild(t, home, "setup", "mcp", "--target", "cursor")

	if code != 0 {
		t.Fatalf("setup mcp --target cursor on a managed host exited %d, want 0:\n%s", code, out)
	}
	wrapped, err := os.ReadFile(cursorMCP)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wrapped), "mcp-proxy") {
		t.Errorf("setup mcp on a managed host did not wrap %s:\n%s\nsetup output:\n%s", cursorMCP, wrapped, out)
	}
	if _, err := os.Stat(cursorMCP + ".agentshield-backup"); err != nil {
		t.Errorf("setup mcp on a managed host left no backup: %v", err)
	}
}

// Off a managed host, --disable unwraps the config in place, so the servers
// come back as they were (#4732: it used to copy the setup-time backup over
// the file, losing whatever was written since).
func TestSetupMCPDisable_UnmanagedUnwrapsInPlace(t *testing.T) {
	home := wrappedCursorHome(t)
	cursorMCP := filepath.Join(home, ".cursor", "mcp.json")

	out, code := runSetupChild(t, home, "setup", "mcp", "--disable")

	if code != 0 {
		t.Fatalf("setup mcp --disable exited %d:\n%s", code, out)
	}
	got, err := os.ReadFile(cursorMCP)
	if err != nil {
		t.Fatal(err)
	}
	var gotJSON, wantJSON interface{}
	if err := json.Unmarshal(got, &gotJSON); err != nil {
		t.Fatalf("%s after --disable is not JSON: %v\n%s", cursorMCP, err, got)
	}
	if err := json.Unmarshal([]byte(originalCursorMCP), &wantJSON); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotJSON, wantJSON) {
		t.Errorf("%s after --disable = %s, want the original %s", cursorMCP, got, originalCursorMCP)
	}
	if _, err := os.Stat(cursorMCP + ".agentshield-backup"); !os.IsNotExist(err) {
		t.Errorf("the backup is still there after --disable (stat err %v)", err)
	}
}

// #4732: a server added and a top-level key written after `setup mcp` survive
// --disable, and the wrapped server comes back as it was.
func TestSetupMCPDisable_KeepsChangesMadeSinceSetup(t *testing.T) {
	home := wrappedCursorHome(t)
	cursorMCP := filepath.Join(home, ".cursor", "mcp.json")
	data, err := os.ReadFile(cursorMCP)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["preferences"] = map[string]interface{}{"theme": "dark"}
	cfg["mcpServers"].(map[string]interface{})["added-later"] = map[string]interface{}{"command": "node", "args": []interface{}{"srv.js"}}
	edited, _ := json.Marshal(cfg)
	if err := os.WriteFile(cursorMCP, edited, 0o644); err != nil {
		t.Fatal(err)
	}

	out, code := runSetupChild(t, home, "setup", "mcp", "--disable")

	if code != 0 {
		t.Fatalf("setup mcp --disable exited %d:\n%s", code, out)
	}
	got, err := os.ReadFile(cursorMCP)
	if err != nil {
		t.Fatal(err)
	}
	var after map[string]interface{}
	if err := json.Unmarshal(got, &after); err != nil {
		t.Fatalf("not JSON after --disable: %v\n%s", err, got)
	}
	if _, ok := after["preferences"]; !ok {
		t.Errorf("top-level key written after setup was lost:\n%s", got)
	}
	servers := after["mcpServers"].(map[string]interface{})
	if _, ok := servers["added-later"]; !ok {
		t.Errorf("server added after setup was lost:\n%s", got)
	}
	fs, _ := servers["fs"].(map[string]interface{})
	if fs["command"] != "npx" {
		t.Errorf("wrapped server not restored, fs = %v", fs)
	}
}

// If the current file cannot be unwrapped (it no longer parses), the
// setup-time backup is still the fallback, and the output says what was lost.
func TestSetupMCPDisable_FallsBackToBackupWhenUnparseable(t *testing.T) {
	home := wrappedCursorHome(t)
	cursorMCP := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.WriteFile(cursorMCP, []byte("agentshield {not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, code := runSetupChild(t, home, "setup", "mcp", "--disable")

	if code != 0 {
		t.Fatalf("setup mcp --disable exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "restored the setup-time backup") {
		t.Errorf("fallback not reported:\n%s", out)
	}
	got, _ := os.ReadFile(cursorMCP)
	if string(got) != originalCursorMCP {
		t.Errorf("fallback restore = %q, want %q", got, originalCursorMCP)
	}
}

// On a machine where MCP was never set up, --disable creates nothing: no
// mcp-policy.yaml, no mcp-packs/, nothing in HOME. The control runs setup on
// the same HOME afterwards and checks it creates both, so the paths asserted
// absent are the ones the bootstrap writes.
func TestSetupMCPDisable_NeverSetUpCreatesNothing(t *testing.T) {
	home := newSetupHome(t)
	policy := filepath.Join(home, ".agentshield", "mcp-policy.yaml")
	packsDir := filepath.Join(home, ".agentshield", "mcp-packs")

	out, code := runSetupChild(t, home, "setup", "mcp", "--disable")

	if code != 0 {
		t.Fatalf("setup mcp --disable exited %d:\n%s", code, out)
	}
	if _, err := os.Stat(policy); !os.IsNotExist(err) {
		t.Errorf("setup mcp --disable created %s (stat err %v)", policy, err)
	}
	if _, err := os.Stat(packsDir); !os.IsNotExist(err) {
		t.Errorf("setup mcp --disable created %s (stat err %v)", packsDir, err)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Errorf("setup mcp --disable wrote into a HOME that never had AgentShield: %v\n%s", entries, out)
	}

	// Control: setup itself still bootstraps both.
	out, code = runSetupChild(t, home, "setup", "mcp")
	if code != 0 {
		t.Fatalf("setup mcp exited %d:\n%s", code, out)
	}
	if _, err := os.Stat(policy); err != nil {
		t.Errorf("control: setup mcp did not create %s: %v", policy, err)
	}
	if packs, _ := os.ReadDir(packsDir); len(packs) == 0 {
		t.Errorf("control: setup mcp installed no packs into %s", packsDir)
	}
}

// Parity: every `setup` subcommand that takes --disable is refused on a
// managed host with CheckDisableAllowed's message, exit 1, before it writes
// anything. The list comes from the command tree, so a new surface cannot
// skip the check unnoticed. Each surface also runs once unmanaged, as the
// control that the refusal comes from managed.json.
func TestSetupDisable_EverySurfaceRefusedWhenManaged(t *testing.T) {
	surfaces := setupDisableSurfaces()
	if len(surfaces) < minDisableSurfaces {
		t.Fatalf("found %d setup subcommands with --disable, want at least %d: %v", len(surfaces), minDisableSurfaces, surfaces)
	}
	t.Logf("%d setup subcommands take --disable: %v", len(surfaces), surfaces)

	for _, surface := range surfaces {
		args := append(append([]string{}, surface...), "--disable")
		t.Run(strings.Join(surface[1:], "_"), func(t *testing.T) {
			managed := newSetupHome(t)
			writeManagedJSON(t, managed)
			want := managedRefusal(t, managed)
			before := snapshotTree(t, managed)

			out, code := runSetupChild(t, managed, args...)

			if code != 1 {
				t.Errorf("agentshield %s on a managed host exited %d, want 1:\n%s", strings.Join(args, " "), code, out)
			}
			if !strings.Contains(out, want) {
				t.Errorf("agentshield %s on a managed host did not print the managed-mode refusal %q:\n%s", strings.Join(args, " "), want, out)
			}
			if after := snapshotTree(t, managed); !reflect.DeepEqual(before, after) {
				t.Errorf("agentshield %s changed HOME on a managed host:\nbefore: %v\nafter:  %v", strings.Join(args, " "), before, after)
			}

			unmanaged := newSetupHome(t)
			out, _ = runSetupChild(t, unmanaged, args...)
			if strings.Contains(out, want) {
				t.Errorf("control: agentshield %s refused on a host with no managed.json:\n%s", strings.Join(args, " "), out)
			}
		})
	}
}
