package cli

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/homedir"
)

// Tests for #4565 step 1: one home resolver for setup and the managed check,
// setup refuses an empty or unset HOME, and managed mode is a property of the
// account (managed.json under $HOME or under the account's home from the user
// database). Like setup_disable_managed_test.go, each test runs the real
// command tree in a child process (TestHelperSetupProcess), so the exit code
// and the files are what a user gets.

// envTestAccountHome tells this test binary, and every child it re-execs,
// which directory the user database names as the account's home. Unset, the
// account's home is $HOME, as on a normal install, so a test that points HOME
// at a scratch directory sees one home, exactly as on main, and no test ever
// reads the developer's real home. testAccountLookupError makes the lookup
// fail. Only this test binary reads the variable (pinTestAccountHome, called
// from TestMain); the agentshield binary has no such switch.
const (
	envTestAccountHome     = "AGENTSHIELD_TEST_ACCOUNT_HOME"
	testAccountLookupError = "<lookup-error>"
)

func pinTestAccountHome() {
	homedir.SetAccountLookupForTest(func() (string, error) {
		switch v := os.Getenv(envTestAccountHome); v {
		case "":
			return os.Getenv("HOME"), nil
		case testAccountLookupError:
			return "", errors.New("user: unknown userid (test)")
		default:
			return v, nil
		}
	})
}

// childHome is the HOME a child process gets: a directory, empty, or unset.
type childHome struct {
	value string
	unset bool
}

func homeAt(dir string) childHome { return childHome{value: dir} }

var (
	homeEmpty = childHome{}
	homeUnset = childHome{unset: true}
)

func (h childHome) String() string {
	switch {
	case h.unset:
		return "HOME unset"
	case h.value == "":
		return "HOME="
	default:
		return "HOME=" + h.value
	}
}

// runSetupChildEnv runs `agentshield <args>` in a child process with the
// given HOME, working directory and account home, and returns its combined
// output and exit code.
func runSetupChildEnv(t *testing.T, home childHome, dir, account string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperSetupProcess$")
	cmd.Dir = dir
	env := []string{
		"AGENTSHIELD_SETUP_HELPER=1",
		"AGENTSHIELD_SETUP_ARGS=" + strings.Join(args, " "),
		"COPILOT_HOME=",
		envTestAccountHome + "=" + account,
	}
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch k {
		case "HOME", "COPILOT_HOME", envTestAccountHome, "AGENTSHIELD_SETUP_HELPER", "AGENTSHIELD_SETUP_ARGS":
			continue
		}
		env = append(env, kv)
	}
	if !home.unset {
		env = append(env, "HOME="+home.value)
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &exitErr):
		return string(out), exitErr.ExitCode()
	default:
		t.Fatalf("agentshield %s (%s): %v\n%s", strings.Join(args, " "), home, err, out)
		return "", -1
	}
}

// putOnPath puts a stand-in executable named name (exit 0) first on PATH.
func putOnPath(t *testing.T, name string) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// copyTree copies the regular files and directories under src into dst.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}

// emptyDir fails the test if dir holds anything.
func requireEmptyDir(t *testing.T, dir, what string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("%s: %s is no longer empty: %v", what, dir, names)
	}
}

// installedSurfaceFiles is the file each surface's enable writes, relative to
// HOME. Each must mention agentshield after `setup <surface>`.
var installedSurfaceFiles = map[string]string{
	"claude-code": ".claude/settings.json",
	"codex":       ".codex/hooks.json",
	"copilot-cli": ".copilot/hooks/agentshield.json",
	"cursor":      ".cursor/hooks.json",
	"gemini-cli":  ".gemini/settings.json",
	"mcp":         ".cursor/mcp.json",
	"openclaw":    ".openclaw/hooks/agentshield/HOOK.md",
	"windsurf":    ".codeium/windsurf/hooks.json",
}

// setupSubcommands returns every `setup` subcommand name, from the command
// tree.
func setupSubcommands() []string {
	var out []string
	for _, c := range setupCmd.Commands() {
		out = append(out, c.Name())
	}
	return out
}

// enableArgs is the `setup <surface>` call that installs a surface. For mcp
// it targets Cursor, whose mcp.json installHome writes first.
func enableArgs(surface string) []string {
	if surface == "mcp" {
		return []string{"setup", "mcp", "--target", "cursor"}
	}
	return []string{"setup", surface}
}

// installAllSurfaces runs the real enable for every surface into home, an
// unmanaged HOME whose account home is itself, and checks each one installed
// its file. OpenClaw gets a stand-in `openclaw` on PATH and runs from a copy
// of the repo's openclaw-hook source, which is where setup finds it in a
// checkout. It is the "enable" half of the unmanaged regression and the
// installed state the managed tests must leave alone.
func installAllSurfaces(t *testing.T, home string) {
	t.Helper()
	putOnPath(t, "openclaw")
	hookSrc := t.TempDir()
	copyTree(t, filepath.Join("..", "..", "openclaw-hook"), filepath.Join(hookSrc, "openclaw-hook"))
	cursorMCP := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(cursorMCP), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cursorMCP, []byte(originalCursorMCP), 0o644); err != nil {
		t.Fatal(err)
	}

	surfaces := setupDisableSurfaces()
	if len(surfaces) < minDisableSurfaces {
		t.Fatalf("found %d setup subcommands with --disable, want at least %d: %v", len(surfaces), minDisableSurfaces, surfaces)
	}
	for _, s := range surfaces {
		name := s[1]
		file, ok := installedSurfaceFiles[name]
		if !ok {
			t.Fatalf("setup %s takes --disable but installedSurfaceFiles has no entry for it; add the file its enable writes", name)
		}
		dir := t.TempDir()
		if name == "openclaw" {
			dir = hookSrc
		}
		out, code := runSetupChildEnv(t, homeAt(home), dir, home, enableArgs(name)...)
		if code != 0 {
			t.Fatalf("agentshield %s exited %d:\n%s", strings.Join(enableArgs(name), " "), code, out)
		}
		data, err := os.ReadFile(filepath.Join(home, file))
		if err != nil || !strings.Contains(strings.ToLower(string(data)), "agentshield") {
			t.Fatalf("agentshield %s did not install %s (err %v):\n%s\noutput:\n%s", strings.Join(enableArgs(name), " "), file, err, data, out)
		}
	}
}

// installedHomeTemplate returns a directory holding every surface installed
// by its real enable, with no managed.json. Tests copy it rather than
// re-running eight enables per case.
func installedHomeTemplate(t *testing.T) string {
	t.Helper()
	tmpl := newSetupHome(t)
	installAllSurfaces(t, tmpl)
	return tmpl
}

// A managed account refuses `setup <surface> --disable` on all 8 surfaces
// whatever HOME says (#4565): HOME set to the managed home, HOME empty or
// unset with the managed home as the working directory, and HOME pointed
// elsewhere with the managed home as the working directory. Each exits 1 and
// leaves the managed home byte-identical, with every surface installed in it
// by its real enable.
//
// When the account lookup fails, the check reads $HOME alone, as main did
// (Gary, 2026-10-26): a managed $HOME still refuses, and an unmanaged one
// disables with exit 0. A lookup error is no evidence of management, so it
// never refuses on its own.
//
// The control runs the same --disable on an unmanaged copy of the same home
// and requires exit 0 and a changed tree, so "byte-identical" means the
// refusal stopped a disable that would otherwise have happened.
func TestSetupDisable_ManagedAccountRefusedUnderAnyHOME(t *testing.T) {
	tmpl := installedHomeTemplate(t)
	surfaces := setupDisableSurfaces()
	t.Logf("%d setup subcommands take --disable: %v", len(surfaces), surfaces)
	homeRefusal := errSetupNoHome.Error()
	enrolled := t.TempDir()
	writeManagedJSON(t, enrolled)
	want := managedRefusal(t, enrolled) // CheckDisableAllowed's own text

	for _, surface := range surfaces {
		args := append(append([]string{}, surface...), "--disable")
		cmdline := strings.Join(args, " ")
		t.Run(surface[1], func(t *testing.T) {
			managedCopy := func(t *testing.T) string {
				m := t.TempDir()
				copyTree(t, tmpl, m)
				writeManagedJSON(t, m)
				return m
			}

			t.Run("HOME is the managed home", func(t *testing.T) {
				m := managedCopy(t)
				before := snapshotTree(t, m)
				cwd := t.TempDir()
				out, code := runSetupChildEnv(t, homeAt(m), cwd, m, args...)
				if code != 1 || !strings.Contains(out, want) {
					t.Errorf("agentshield %s: exit %d, want 1 with %q:\n%s", cmdline, code, want, out)
				}
				if after := snapshotTree(t, m); !reflect.DeepEqual(before, after) {
					t.Errorf("agentshield %s changed the managed home:\nbefore: %v\nafter:  %v", cmdline, before, after)
				}
				requireEmptyDir(t, cwd, cmdline)
			})

			for _, h := range []childHome{homeEmpty, homeUnset} {
				t.Run(h.String()+", cwd is the managed home", func(t *testing.T) {
					m := managedCopy(t)
					before := snapshotTree(t, m)
					out, code := runSetupChildEnv(t, h, m, m, args...)
					if code != 1 || !strings.Contains(out, homeRefusal) {
						t.Errorf("agentshield %s with %s from the managed home: exit %d, want 1 with %q:\n%s", cmdline, h, code, homeRefusal, out)
					}
					if after := snapshotTree(t, m); !reflect.DeepEqual(before, after) {
						t.Errorf("agentshield %s with %s changed the managed home:\nbefore: %v\nafter:  %v", cmdline, h, before, after)
					}
				})
			}

			t.Run("HOME elsewhere, cwd is the managed home", func(t *testing.T) {
				m := managedCopy(t)
				elsewhere := t.TempDir()
				before := snapshotTree(t, m)
				out, code := runSetupChildEnv(t, homeAt(elsewhere), m, m, args...)
				if code != 1 || !strings.Contains(out, want) {
					t.Errorf("agentshield %s with HOME elsewhere, from the managed home: exit %d, want 1 with %q:\n%s", cmdline, code, want, out)
				}
				if after := snapshotTree(t, m); !reflect.DeepEqual(before, after) {
					t.Errorf("agentshield %s with HOME elsewhere changed the managed home:\nbefore: %v\nafter:  %v", cmdline, before, after)
				}
				requireEmptyDir(t, elsewhere, cmdline+" (the HOME it was pointed at)")
			})

			t.Run("account lookup fails, HOME managed: refused", func(t *testing.T) {
				m := managedCopy(t)
				before := snapshotTree(t, m)
				cwd := t.TempDir()
				out, code := runSetupChildEnv(t, homeAt(m), cwd, testAccountLookupError, args...)
				if code != 1 || !strings.Contains(out, want) {
					t.Errorf("agentshield %s with a failed account lookup and a managed HOME: exit %d, want 1 with %q:\n%s", cmdline, code, want, out)
				}
				if after := snapshotTree(t, m); !reflect.DeepEqual(before, after) {
					t.Errorf("agentshield %s with a failed account lookup changed the managed HOME:\nbefore: %v\nafter:  %v", cmdline, before, after)
				}
			})

			t.Run("account lookup fails, HOME unmanaged: disables as on main", func(t *testing.T) {
				u := t.TempDir()
				copyTree(t, tmpl, u)
				before := snapshotTree(t, u)
				out, code := runSetupChildEnv(t, homeAt(u), t.TempDir(), testAccountLookupError, args...)
				if code != 0 || strings.Contains(out, want) {
					t.Errorf("agentshield %s with a failed account lookup and an unmanaged HOME: exit %d, want 0 with no managed refusal; a lookup error is no evidence of management:\n%s", cmdline, code, out)
				}
				if after := snapshotTree(t, u); reflect.DeepEqual(before, after) {
					t.Errorf("agentshield %s with a failed account lookup and an unmanaged HOME changed nothing; it must disable as on main:\n%s", cmdline, out)
				}
			})

			// The reviewer's case: a service account whose passwd home is a
			// directory it cannot read (root-owned, mode 700). The account's
			// managed.json cannot be read, which is no evidence of anything,
			// so $HOME alone decides, as on main.
			t.Run("account home unreadable, HOME unmanaged: disables as on main", func(t *testing.T) {
				if os.Geteuid() == 0 {
					t.Skip("root reads a mode-000 directory, so the account home cannot be made unreadable")
				}
				locked := t.TempDir()
				writeManagedJSON(t, locked)
				if err := os.Chmod(locked, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
				u := t.TempDir()
				copyTree(t, tmpl, u)
				before := snapshotTree(t, u)
				out, code := runSetupChildEnv(t, homeAt(u), t.TempDir(), locked, args...)
				if code != 0 || strings.Contains(out, want) {
					t.Errorf("agentshield %s with an unreadable account home and an unmanaged HOME: exit %d, want 0 with no managed refusal:\n%s", cmdline, code, out)
				}
				if after := snapshotTree(t, u); reflect.DeepEqual(before, after) {
					t.Errorf("agentshield %s with an unreadable account home changed nothing; it must disable as on main:\n%s", cmdline, out)
				}
			})

			t.Run("control: unmanaged account, same home, disables", func(t *testing.T) {
				u := t.TempDir()
				copyTree(t, tmpl, u)
				before := snapshotTree(t, u)
				out, code := runSetupChildEnv(t, homeAt(u), t.TempDir(), u, args...)
				if code != 0 {
					t.Errorf("control: agentshield %s on an unmanaged account exited %d, want 0:\n%s", cmdline, code, out)
				}
				if after := snapshotTree(t, u); reflect.DeepEqual(before, after) {
					t.Errorf("control: agentshield %s on an unmanaged account changed nothing, so the managed cases above prove nothing:\n%s", cmdline, out)
				}
			})
		})
	}
}

// Unmanaged, with a correct HOME: every surface enables and then disables
// exactly as before #4565 (exit 0 both times, the enable installs its file,
// the disable takes AgentShield out of it). This is the regression guard for
// "additive only".
func TestSetup_UnmanagedNormalHOME_EnableThenDisableEverySurface(t *testing.T) {
	home := newSetupHome(t)
	installAllSurfaces(t, home) // the enable half, with its own checks

	for _, surface := range setupDisableSurfaces() {
		name := surface[1]
		args := append(append([]string{}, surface...), "--disable")
		out, code := runSetupChildEnv(t, homeAt(home), t.TempDir(), home, args...)
		if code != 0 {
			t.Errorf("agentshield %s exited %d, want 0:\n%s", strings.Join(args, " "), code, out)
			continue
		}
		path := filepath.Join(home, installedSurfaceFiles[name])
		data, err := os.ReadFile(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			// Removed or moved aside: disabled.
		case err != nil:
			t.Errorf("reading %s after %s: %v", path, strings.Join(args, " "), err)
		case name == "mcp" && !sameJSON(t, data, []byte(originalCursorMCP)):
			t.Errorf("%s after setup mcp --disable = %q, want the original %q", path, data, originalCursorMCP)
		case name != "mcp" && strings.Contains(string(data), "agentshield"):
			t.Errorf("%s still mentions agentshield after %s:\n%s\noutput:\n%s", path, strings.Join(args, " "), data, out)
		}
	}
}

// An empty or unset HOME is refused by every `setup` command, enable and
// --disable, on a host that is not managed, and nothing is written: not in
// the working directory (where paths built from an empty HOME used to land)
// and not in the account's home. `setup` and `setup --install` refuse too.
func TestSetup_EmptyHOMERefusedOnEverySurfaceAndCreatesNothing(t *testing.T) {
	newSetupHome(t) // stand-in agentshield on PATH
	putOnPath(t, "openclaw")
	refusal := errSetupNoHome.Error()

	calls := [][]string{{"setup"}, {"setup", "--install"}}
	withDisable := map[string]bool{}
	for _, s := range setupDisableSurfaces() {
		withDisable[s[1]] = true
	}
	subs := setupSubcommands()
	if len(subs) < minDisableSurfaces {
		t.Fatalf("found %d setup subcommands, want at least %d: %v", len(subs), minDisableSurfaces, subs)
	}
	for _, name := range subs {
		calls = append(calls, enableArgs(name))
		if withDisable[name] {
			calls = append(calls, []string{"setup", name, "--disable"})
		}
	}
	t.Logf("%d setup calls: %v", len(calls), calls)

	for _, h := range []childHome{homeEmpty, homeUnset} {
		for _, args := range calls {
			cmdline := strings.Join(args, " ")
			t.Run(h.String()+"/"+cmdline, func(t *testing.T) {
				cwd := t.TempDir()
				account := t.TempDir()
				out, code := runSetupChildEnv(t, h, cwd, account, args...)
				if code != 1 || !strings.Contains(out, refusal) {
					t.Errorf("agentshield %s with %s: exit %d, want 1 with %q:\n%s", cmdline, h, code, refusal, out)
				}
				requireEmptyDir(t, cwd, "agentshield "+cmdline+" with "+h.String()+" (working directory)")
				requireEmptyDir(t, account, "agentshield "+cmdline+" with "+h.String()+" (account home)")
			})
		}
	}
}

// `setup claude-code --managed` never uses HOME (it prints the managed
// settings and writes nothing), so it still runs without one: an MDM script
// may have no HOME. It writes nothing in the working directory either.
func TestSetupClaudeCodeManaged_RunsWithoutHOME(t *testing.T) {
	newSetupHome(t)
	cwd := t.TempDir()
	out, code := runSetupChildEnv(t, homeEmpty, cwd, t.TempDir(), "setup", "claude-code", "--managed")
	if code != 0 || !strings.Contains(out, "PreToolUse") {
		t.Errorf("setup claude-code --managed with HOME empty: exit %d, want 0 with the managed settings:\n%s", code, out)
	}
	if strings.Contains(out, errSetupNoHome.Error()) {
		t.Errorf("setup claude-code --managed refused an empty HOME it never uses:\n%s", out)
	}
	requireEmptyDir(t, cwd, "setup claude-code --managed with HOME empty")
}

// homeReadCalls returns "file:line call" for every call in src that reads the
// home directory without the resolver: os.Getenv("HOME"),
// os.LookupEnv("HOME") and os.UserHomeDir().
func homeReadCalls(t *testing.T, fset *token.FileSet, f *ast.File) []string {
	t.Helper()
	var found []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "os" {
			return true
		}
		hit := sel.Sel.Name == "UserHomeDir"
		if (sel.Sel.Name == "Getenv" || sel.Sel.Name == "LookupEnv") && len(call.Args) == 1 {
			if lit, ok := call.Args[0].(*ast.BasicLit); ok {
				if v, err := strconv.Unquote(lit.Value); err == nil && v == "HOME" {
					hit = true
				}
			}
		}
		if hit {
			found = append(found, fset.Position(call.Pos()).String()+" os."+sel.Sel.Name)
		}
		return true
	})
	return found
}

// One home resolver (#4565): the setup and disable code, the managed check
// and config.Load find home only through internal/homedir. A direct
// os.Getenv("HOME") or os.UserHomeDir() in these files is how the guard and
// the writers came to disagree.
func TestSetupCode_FindsHomeOnlyThroughTheResolver(t *testing.T) {
	files, err := filepath.Glob("setup*.go")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files,
		filepath.Join("..", "enterprise", "setup_guard.go"),
		filepath.Join("..", "config", "config.go"),
	)
	fset := token.NewFileSet()
	scanned := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		for _, hit := range homeReadCalls(t, fset, f) {
			t.Errorf("%s: find home with homedir.Dir (setupHome in setup code), not directly", hit)
		}
	}
	if scanned < 7 {
		t.Fatalf("scanned %d files, want at least 7 (setup.go, setup_copilot.go, setup_managed.go, setup_mcp.go, setup_mode.go, setup_guard.go, config.go): %v", scanned, files)
	}

	// Positive control: the checker finds each spelling.
	src := `package p
import "os"
func a() { _ = os.Getenv("HOME"); _, _ = os.LookupEnv("HOME"); _, _ = os.UserHomeDir(); _ = os.Getenv("PATH") }`
	f, err := parser.ParseFile(fset, "control.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := homeReadCalls(t, fset, f); len(got) != 3 {
		t.Fatalf("control: the checker found %d home reads in a source with 3: %v", len(got), got)
	}
}

// sameJSON reports whether two JSON documents decode to the same value
// (--disable unwraps in place, #4732, so the bytes are not the original's).
func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y interface{}
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}
