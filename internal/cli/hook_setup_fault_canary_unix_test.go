//go:build unix

package cli

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/packs"
)

// TestHook_SetupFaultCannotLowerABlock: a fault in the hook's own setup (a
// file it cannot open, read or create) must not turn a known BLOCK into an
// unenforced AUDIT, unless that fault is pinned in hookFaultPins below.
//
// #4052 made the audit-log lock open fatal in logger.New. The hook read that
// as "audit log init failed", took the fail-safe path and skipped evaluation,
// so every BLOCK became an AUDIT (#4056, fixed by #4057). Nothing in that
// diff looked like a decision: the branch it reached lives in hook.go. So
// this test does not name the paths it faults. It DISCOVERS every path a
// clean hook call creates under HOME and faults each one two ways (pre-created
// as a directory; as an empty mode-000 file), plus a fixed list of the inputs
// the hook reads. A change that adds a file to the hook's path gets that file
// faulted without anyone listing it here.
//
// The canary is destructiveCommand through the real hook entry point in a
// child process. It BLOCKs on the embedded community packs alone, so the test
// runs unchanged in the OSS tree. The HOME is the `make deploy` layout:
// unmanaged, `mode: enforce`, community packs on disk and in mcp-packs, and no
// credentials. Logged in, the heartbeat goroutine would install a real launchd
// agent; logged out, it and the machine-id prefetch return after one read, so
// discovery is deterministic: a child writes nothing once it has exited.
func TestHook_SetupFaultCannotLowerABlock(t *testing.T) {
	created := discoverHookCreatedPaths(t)
	faults := append([]hookFault(nil), fixedHookFaults...)
	for _, c := range created {
		faults = append(faults, discoveredHookFaults(c)...)
	}

	// A pin that matches no fault has gone stale (the hook stopped creating
	// that path, or the fault was renamed). Fail rather than keep a pin that
	// documents nothing.
	names := map[string]bool{}
	for _, f := range faults {
		names[f.name] = true
	}
	for name := range hookFaultPins {
		if !names[name] {
			t.Errorf("hookFaultPins[%q] matches no fault (discovered: %v); delete or rename the pin", name, created)
		}
	}

	for _, f := range faults {
		t.Run(f.name, func(t *testing.T) {
			home := newFaultCanaryHome(t)
			f.stage(t, home)

			got := runFaultCanary(t, home)

			want, reason := "BLOCK", "unpinned: a setup fault must not lower the canary"
			if pin, ok := hookFaultPins[f.name]; ok {
				want, reason = pin.want, pin.reason
			}
			if got.decision != want {
				t.Fatalf("canary decided %q, want %q (%s).\nIf this is intended, pin or re-pin %q in hookFaultPins with a reason.\nstderr:\n%s", got.decision, want, reason, f.name, got.stderr)
			}
		})
	}
}

// hookFaultPins are the faults under which main already decides lower than
// BLOCK by design. Outside managed fail_closed, a hook that cannot open its
// audit log evaluates nothing and records a flagged AUDIT (#3619,
// failSafeDecision). Whether that should stay AUDIT is a product decision,
// not this test's. Each entry is pinned to the exact decision main makes, so
// a change in either direction is an edit here, not a silent drift.
var hookFaultPins = map[string]struct{ want, reason string }{
	"config-dir-read-only": {
		"AUDIT via fail-safe: audit log init",
		"audit.jsonl cannot be created in a read-only config dir; #3619 fail-safe AUDIT outside managed mode",
	},
	"dir:audit.jsonl": {
		"AUDIT via fail-safe: audit log init",
		"a directory at audit.jsonl cannot be opened for append; #3619 fail-safe AUDIT outside managed mode",
	},
	"mode-000:audit.jsonl": {
		"AUDIT via fail-safe: audit log init",
		"an unwritable audit.jsonl cannot be opened for append; #3619 fail-safe AUDIT outside managed mode",
	},
}

// hookFault stages one fault in a fresh canary HOME. A fault that relies on
// permission bits checks that it took effect and skips when it did not (root
// ignores modes); the directory variants run everywhere.
type hookFault struct {
	name  string
	stage func(t *testing.T, home string)
}

func canaryConfigDir(home string) string { return filepath.Join(home, ".agentshield") }

// fixedHookFaults are the inputs the hook reads on every call. The canary
// BLOCKs under each one on main except config-dir-read-only (pinned): an
// unreadable config falls back to the built-in mode, and unreadable packs
// degrade to the embedded layer (#4071).
var fixedHookFaults = []hookFault{
	{"none", func(*testing.T, string) {}},
	{"config-dir-read-only", func(t *testing.T, home string) {
		dir := canaryConfigDir(home)
		chmodFault(t, dir, 0o555, func() error {
			f, err := os.CreateTemp(dir, "probe")
			if err == nil {
				_ = f.Close()
				_ = os.Remove(f.Name())
			}
			return err
		})
	}},
	{"config-mode-000", func(t *testing.T, home string) {
		p := filepath.Join(canaryConfigDir(home), "agentshield.yaml")
		chmodFault(t, p, 0o000, func() error { _, err := os.ReadFile(p); return err })
	}},
	{"packs-dir-mode-000", func(t *testing.T, home string) {
		p := filepath.Join(canaryConfigDir(home), "packs")
		chmodFault(t, p, 0o000, func() error { _, err := os.ReadDir(p); return err })
	}},
	{"pack-file-mode-000", func(t *testing.T, home string) {
		p := filepath.Join(canaryConfigDir(home), "packs", "terminal-safety.yaml")
		chmodFault(t, p, 0o000, func() error { _, err := os.ReadFile(p); return err })
	}},
	{"mcp-packs-dir-mode-000", func(t *testing.T, home string) {
		p := filepath.Join(canaryConfigDir(home), "mcp-packs")
		chmodFault(t, p, 0o000, func() error { _, err := os.ReadDir(p); return err })
	}},
}

// createdPath is a path the clean hook call created, relative to HOME.
type createdPath struct {
	rel   string
	isDir bool
}

// String names the path for fault names and pins: relative to the config dir
// when it is inside it (every path the hook creates today), "~/..." otherwise.
func (c createdPath) String() string {
	if in, ok := strings.CutPrefix(c.rel, ".agentshield"+string(filepath.Separator)); ok {
		return in
	}
	return "~/" + c.rel
}

// discoveredHookFaults faults a path the hook creates: a directory where it
// expects a file, and an empty file nobody can open. A path the hook creates
// as a directory gets only the file variant; an empty directory there is not
// a fault.
func discoveredHookFaults(c createdPath) []hookFault {
	file := hookFault{"mode-000:" + c.String(), func(t *testing.T, home string) {
		p := filepath.Join(home, c.rel)
		mustMkdirAll(t, filepath.Dir(p))
		if err := os.WriteFile(p, nil, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
		if f, err := os.OpenFile(p, os.O_RDWR, 0); err == nil {
			_ = f.Close()
			t.Skip("root ignores file modes (the dir: variant still runs)")
		}
	}}
	if c.isDir {
		return []hookFault{file}
	}
	return []hookFault{{"dir:" + c.String(), func(t *testing.T, home string) {
		mustMkdirAll(t, filepath.Join(home, c.rel))
	}}, file}
}

// chmodFault sets mode on p, restores it at cleanup so t.TempDir can remove
// the tree, and skips when probe still succeeds: the fault did not take.
func chmodFault(t *testing.T, p string, mode os.FileMode, probe func() error) {
	t.Helper()
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("fault target missing from the canary HOME: %v", err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, info.Mode().Perm()) })
	if probe() == nil {
		t.Skipf("mode %#o on %s did not take effect (running as root?)", mode, filepath.Base(p))
	}
}

func mustMkdirAll(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
}

// newFaultCanaryHome builds the deploy-layout HOME described on the test, on
// top of the fail-safe tests' unmanaged HOME (no policy.yaml, as setup leaves
// it).
func newFaultCanaryHome(t *testing.T) (home string) {
	t.Helper()
	home, configDir := newFailSafeHome(t, false, "")
	write := func(rel string, data []byte) {
		p := filepath.Join(configDir, rel)
		mustMkdirAll(t, filepath.Dir(p))
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("agentshield.yaml", []byte("mode: enforce\n"))
	for name, data := range packs.ShellFiles() {
		write(filepath.Join("packs", name), data)
	}
	for name, data := range packs.MCPFiles() {
		write(filepath.Join("mcp-packs", name), data)
	}
	if _, err := os.Stat(filepath.Join(configDir, "packs", "terminal-safety.yaml")); err != nil {
		t.Fatalf("embedded community packs lack terminal-safety.yaml, which pack-file-mode-000 faults: %v", err)
	}
	return home
}

// discoverHookCreatedPaths runs one clean hook call and returns every path it
// left under HOME that the fresh HOME did not have. That clean call is also
// the control: if the canary does not BLOCK here, every fault result is
// meaningless. The audit log is the floor: finding nothing means discovery is
// broken, not that the hook writes nothing.
func discoverHookCreatedPaths(t *testing.T) []createdPath {
	t.Helper()
	home := newFaultCanaryHome(t)
	before := listTree(t, home)

	if got := runFaultCanary(t, home); got.decision != "BLOCK" {
		t.Fatalf("control: canary decided %q on a clean HOME, want BLOCK; every fault result would be vacuous.\nstderr:\n%s", got.decision, got.stderr)
	}

	var out []createdPath
	for rel, isDir := range listTree(t, home) {
		if _, ok := before[rel]; !ok {
			out = append(out, createdPath{rel, isDir})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	found := false
	for _, c := range out {
		found = found || c.String() == "audit.jsonl"
	}
	if !found {
		t.Fatalf("discovery found %v; want at least audit.jsonl (the hook logs every decision)", out)
	}
	return out
}

// listTree maps every path under root, relative to it, to whether it is a
// directory.
func listTree(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p != root {
			rel, _ := filepath.Rel(root, p)
			out[rel] = d.IsDir()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type canaryResult struct{ decision, stderr string }

// failSafeAudit is the stderr line failSafeDecision writes outside managed
// mode; its stage names the setup step that failed.
var failSafeAudit = regexp.MustCompile(`AgentShield: ([a-z ]+) failed — evaluated as AUDIT`)

// runFaultCanary sends the canary through the Claude Code hook in a child
// process with HOME pointed at home, and names the decision the harness sees:
// "BLOCK" (exit 2 with the BLOCK banner and no panic: a Go panic exits 2
// too), "AUDIT via fail-safe: <stage>", or the raw exit code.
func runFaultCanary(t *testing.T, home string) canaryResult {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"session_id":      "fault-canary",
		"cwd":             home,
		"tool_input":      map[string]string{"command": destructiveCommand},
	})
	if err != nil {
		t.Fatal(err)
	}
	// A hang guard, not a latency assertion.
	code, stderr, timedOut := runHookWithDeadline(t, home, string(payload), 30*time.Second)
	r := canaryResult{stderr: stderr}
	switch {
	case timedOut:
		r.decision = "no verdict in 30s"
	case strings.Contains(stderr, "panic:"):
		r.decision = fmt.Sprintf("panic (exit %d)", code)
	case code == 2 && strings.Contains(stderr, "AgentShield BLOCKED this command"):
		r.decision = "BLOCK"
	case code == 0 && failSafeAudit.MatchString(stderr):
		r.decision = "AUDIT via fail-safe: " + failSafeAudit.FindStringSubmatch(stderr)[1]
	default:
		r.decision = fmt.Sprintf("exit %d", code)
	}
	return r
}
