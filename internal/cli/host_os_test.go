package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
)

// envTestHostOS makes this test binary, and every child it re-execs, route
// as if it ran on that OS (route.ToolCall.OS). Without it a Windows-only row
// (Copilot's compatible format on Windows, ADR-001 D1) could not be exercised
// on the macOS and Linux CI. Only this test binary reads the variable
// (pinTestHostOS, called from TestMain), exactly as envTestAccountHome: the
// agentshield binary has no such switch, because one would let an agent turn
// the PowerShell lane off (TestHostOSOverride_ProductionBinaryIgnoresIt).
const envTestHostOS = "AGENTSHIELD_TEST_HOST_OS"

func pinTestHostOS() {
	if v := os.Getenv(envTestHostOS); v != "" {
		hostOS = func() string { return v }
	}
}

// onWindows is the extra environment of a hook child routing as a Windows
// host.
var onWindows = []string{envTestHostOS + "=windows"}

// TestHostOSOverride_ProductionBinaryIgnoresIt builds the real agentshield
// binary and sends it a Copilot compatible-format Bash call that only the
// PowerShell lane blocks, with envTestHostOS=windows. The binary must route it
// as this host does (POSIX alone: ALLOW), while this test binary, which honours
// the override, blocks it: the positive control that proves the payload
// discriminates. An override the binary read would let an agent switch the
// PowerShell lane off, or on, at will.
func TestHostOSOverride_ProductionBinaryIgnoresIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the override names the OS this host already has")
	}
	if testing.Short() {
		t.Skip("builds the agentshield binary")
	}
	bin := filepath.Join(t.TempDir(), "agentshield")
	build := exec.Command("go", "build", "-o", bin, "github.com/AI-AgentLens/agentshield/cmd/agentshield")
	build.Env = withoutEnv(os.Environ(), "GOFLAGS=")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	payload := copilotCompatPayload(t, "host-os", "Bash", shellArgs(psKeyRead()))
	env := append([]string{"AGENTSHIELD_AGENT_ID=copilot-cli"}, onWindows...)

	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	if code, _, stderr := runHookChild(t, home, payload, env...); code != 2 {
		t.Fatalf("control: the test binary with %s exits %d, want 2 (the PowerShell lane's BLOCK). stderr:\n%s", onWindows[0], code, stderr)
	}
	if n := laneReadingsNotes(oneEvent(t, configDir).Notes); len(n) != 1 || !strings.HasSuffix(n[0], "kept=powershell") {
		t.Fatalf("control: %s notes %q, want the PowerShell lane kept", analyzer.NoteLaneReadings, n)
	}

	home, configDir = newFailSafeHome(t, false, failSafePolicyGood)
	cmd := exec.Command(bin, "hook")
	cmd.Env = append(withoutEnv(os.Environ(), "AGENTSHIELD_", "HOME="), append(env, "HOME="+home)...)
	cmd.Stdin = strings.NewReader(payload)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the agentshield binary with %s: %v (want exit 0: routed as %s, POSIX alone)\n%s", onWindows[0], err, runtime.GOOS, out)
	}
	e := oneEvent(t, configDir)
	if e.Decision != "ALLOW" || len(laneReadingsNotes(e.Notes)) != 0 {
		t.Errorf("the agentshield binary decided %s with notes %v; want ALLOW from the POSIX lane alone, no lane_readings", e.Decision, noteKinds(e.Notes))
	}
}

// TestHostOSOverride_OnlyTestsSetIt: no file of the agentshield build names
// the override variable or assigns hostOS. The binary test above proves the
// behaviour for this host; this keeps a later edit from adding a reader on
// another code path.
func TestHostOSOverride_OnlyTestsSetIt(t *testing.T) {
	root := filepath.Join("..", "..")
	assigned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "build", "dist", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(src), envTestHostOS) {
			t.Errorf("%s names %s: only the internal/cli test binary may read it", path, envTestHostOS)
		}
		if filepath.Base(filepath.Dir(path)) != "cli" {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if as, ok := n.(*ast.AssignStmt); ok {
				for _, lhs := range as.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && id.Name == "hostOS" {
						assigned++
						t.Errorf("%s assigns hostOS: only TestMain may", path)
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Control: the scan sees the declaration's file.
	if src, err := os.ReadFile("hook.go"); err != nil || !strings.Contains(string(src), "var hostOS = ") {
		t.Fatalf("control: hook.go does not declare hostOS where this test expects (%v)", err)
	}
	if assigned != 0 {
		t.Errorf("%d assignment(s) to hostOS outside tests", assigned)
	}
}

// withoutEnv drops every entry starting with one of prefixes.
func withoutEnv(env []string, prefixes ...string) []string {
	var out []string
next:
	for _, kv := range env {
		for _, p := range prefixes {
			if strings.HasPrefix(kv, p) {
				continue next
			}
		}
		out = append(out, kv)
	}
	return out
}
