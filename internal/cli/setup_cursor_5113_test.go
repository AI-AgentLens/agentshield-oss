package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/hookentry"
)

// The hooks.json `setup cursor` wrote from 4f8c594f (2026-02-08) until #5113.
// Cursor ignores it because it has no "version". A live canary on Cursor CLI
// 2026.11.22 ran its marker command unevaluated, and the same run was
// blocked once "version": 1 was added.
const preFixCursorHooks = `{
  "hooks": {
    "beforeShellExecution": [
      {
        "command": "agentshield hook",
        "show_output": true
      }
    ]
  }
}
`

func cursorHooksPath(home string) string { return filepath.Join(home, ".cursor", "hooks.json") }

func writeCursorHooks(t *testing.T, home, content string) {
	t.Helper()
	p := cursorHooksPath(home)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readCursorHooks(t *testing.T, home string) []byte {
	t.Helper()
	data, err := os.ReadFile(cursorHooksPath(home))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func runSetupCursor(t *testing.T, home string, args ...string) string {
	t.Helper()
	putOnPath(t, "agentshield")
	out, code := runSetupChildEnv(t, homeAt(home), t.TempDir(), home, append([]string{"setup", "cursor"}, args...)...)
	if code != 0 {
		t.Fatalf("agentshield setup cursor exited %d:\n%s", code, out)
	}
	return out
}

// A fresh install must write a file Cursor loads, not only one that holds
// the entry. The second half is what the old checks tested, and it passed
// the file Cursor ignored.
func TestSetupCursor_FreshInstallWritesAFileCursorLoads_5113(t *testing.T) {
	home := t.TempDir()
	runSetupCursor(t, home)
	data := readCursorHooks(t, home)
	if p := hookentry.CursorConfigProblem(data); p != "" {
		t.Fatalf("setup cursor wrote a hooks.json Cursor ignores (%s):\n%s", p, data)
	}
	if !hookentry.CursorHookFile.Has(data) {
		t.Fatalf("setup cursor wrote no AgentShield entry:\n%s", data)
	}
}

// An install from before the fix must be repaired by re-running setup. The
// old code answered "already configured" and left Cursor ignoring the file.
// The user's own hooks and other top-level members survive the repair.
func TestSetupCursor_RepairsAFileWithoutVersion_5113(t *testing.T) {
	t.Run("the exact pre-fix file", func(t *testing.T) {
		home := t.TempDir()
		writeCursorHooks(t, home, preFixCursorHooks)
		out := runSetupCursor(t, home)
		data := readCursorHooks(t, home)
		if p := hookentry.CursorConfigProblem(data); p != "" {
			t.Fatalf("after setup cursor, Cursor still ignores the file (%s):\n%s\noutput:\n%s", p, data, out)
		}
		if !strings.Contains(out, "repaired") {
			t.Errorf("setup cursor should say it repaired the file; output:\n%s", out)
		}
		if strings.Contains(out, "already configured") {
			t.Errorf("setup cursor must not call a file Cursor ignored 'already configured'; output:\n%s", out)
		}
	})

	t.Run("the user's own hooks and members are kept", func(t *testing.T) {
		home := t.TempDir()
		writeCursorHooks(t, home, `{
  "hooks": {
    "afterFileEdit": [{"command": "./my-formatter.sh"}],
    "beforeShellExecution": [{"command": "agentshield hook", "show_output": true}]
  },
  "note": "mine"
}`)
		runSetupCursor(t, home)
		var doc struct {
			Version float64                     `json:"version"`
			Hooks   map[string][]map[string]any `json:"hooks"`
			Note    string                      `json:"note"`
		}
		data := readCursorHooks(t, home)
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("repaired file is not JSON: %v\n%s", err, data)
		}
		if doc.Version != 1 {
			t.Errorf("version = %v, want 1", doc.Version)
		}
		if got := doc.Hooks["afterFileEdit"]; len(got) != 1 || got[0]["command"] != "./my-formatter.sh" {
			t.Errorf("the user's afterFileEdit hook was not kept: %v", got)
		}
		if got := doc.Hooks["beforeShellExecution"]; len(got) != 1 || got[0]["command"] != "agentshield hook" {
			t.Errorf("AgentShield's entry was not kept: %v", got)
		}
		if doc.Note != "mine" {
			t.Errorf("top-level member 'note' was not kept: %q", doc.Note)
		}
	})

	t.Run("an invalid version is replaced", func(t *testing.T) {
		home := t.TempDir()
		writeCursorHooks(t, home, `{"version": "1", "hooks": {"beforeShellExecution": [{"command": "agentshield hook"}]}}`)
		runSetupCursor(t, home)
		if p := hookentry.CursorConfigProblem(readCursorHooks(t, home)); p != "" {
			t.Fatalf("Cursor still ignores the file: %s", p)
		}
	})
}

// A file Cursor already loads is left byte for byte.
func TestSetupCursor_LeavesAWorkingFileAlone_5113(t *testing.T) {
	home := t.TempDir()
	writeCursorHooks(t, home, cursorHooksContent)
	out := runSetupCursor(t, home)
	if got := string(readCursorHooks(t, home)); got != cursorHooksContent {
		t.Fatalf("setup cursor rewrote a working file:\n%s", got)
	}
	if !strings.Contains(out, "already configured") {
		t.Errorf("want 'already configured'; output:\n%s", out)
	}
}

// A file whose problem adding "version" cannot fix is reported and left
// as it is.
func TestSetupCursor_DoesNotRewriteAFileItCannotFix_5113(t *testing.T) {
	for name, content := range map[string]string{
		"hooks is not an object": `{"hooks": ["agentshield hook"]}`,
		"not JSON":               `{"hooks": {"beforeShellExecution": [{"command": "agentshield hook"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			writeCursorHooks(t, home, content)
			out := runSetupCursor(t, home)
			if got := string(readCursorHooks(t, home)); got != content {
				t.Fatalf("setup cursor changed a file it cannot fix:\n%s", got)
			}
			if !strings.Contains(out, "did not change") || strings.Contains(out, "already configured") {
				t.Errorf("want a warning that the file was left unchanged; output:\n%s", out)
			}
		})
	}
}

// When another tool's hooks.json is in place, setup prints the entry to add
// by hand. The instructions must also name the "version" Cursor requires.
func TestSetupCursor_ManualInstructionsNameTheVersion_5113(t *testing.T) {
	home := t.TempDir()
	other := `{"hooks": {"afterFileEdit": [{"command": "./fmt.sh"}]}}`
	writeCursorHooks(t, home, other)
	out := runSetupCursor(t, home)
	if !strings.Contains(out, `"version": 1`) {
		t.Errorf("manual instructions omit the version Cursor requires; output:\n%s", out)
	}
	if got := string(readCursorHooks(t, home)); got != other {
		t.Fatalf("setup cursor changed another tool's file:\n%s", got)
	}
}

// status said "✅ Cursor: hook active" for the file Cursor ignores.
func TestStatus_CursorFileCursorIgnoresIsNotActive_5113(t *testing.T) {
	for _, c := range []struct {
		name, content, want, notWant string
	}{
		{"pre-fix file", preFixCursorHooks, "Cursor: hook NOT active", "✅ Cursor: hook active"},
		{"working file", cursorHooksContent, "✅ Cursor: hook active", "NOT active"},
	} {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			writeCursorHooks(t, home, c.content)
			out, code := runSetupChildEnv(t, homeAt(home), t.TempDir(), home, "status")
			if code != 0 {
				t.Fatalf("agentshield status exited %d:\n%s", code, out)
			}
			if !strings.Contains(out, c.want) || strings.Contains(out, c.notWant) {
				t.Fatalf("status output wants %q and not %q:\n%s", c.want, c.notWant, out)
			}
		})
	}
}

func TestAddCursorHooksVersion_5113(t *testing.T) {
	t.Run("version goes first, other members keep their order", func(t *testing.T) {
		got, err := addCursorHooksVersion([]byte(`{"b": 2, "version": "x", "a": {"k": [1, "two"]}}`))
		if err != nil {
			t.Fatal(err)
		}
		want := "{\n  \"version\": 1,\n  \"b\": 2,\n  \"a\": {\n    \"k\": [\n      1,\n      \"two\"\n    ]\n  }\n}\n"
		if string(got) != want {
			t.Fatalf("got:\n%s\nwant:\n%s", got, want)
		}
	})
	t.Run("an empty object gets only the version", func(t *testing.T) {
		got, err := addCursorHooksVersion([]byte(`{}`))
		if err != nil || string(got) != "{\n  \"version\": 1\n}\n" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	for name, in := range map[string]string{
		"an array":              `[{"version": 1}]`,
		"data after the object": `{"hooks": {}} {}`,
		"truncated":             `{"hooks": {`,
		"empty input":           ``,
		"a string at top level": `"agentshield hook"`,
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			if out, err := addCursorHooksVersion([]byte(in)); err == nil {
				t.Fatalf("want an error, got %q", out)
			}
		})
	}
}
