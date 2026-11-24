package hookentry

import (
	"strings"
	"testing"
)

// preFixCursorHooks is the exact hooks.json `setup cursor` wrote from
// 4f8c594f (2026-02-08) until #5113. In a live run on Cursor CLI
// 2026.11.22, Cursor ignored it, and the canary's marker command ran
// unevaluated. With only "version": 1 added, the same run was blocked.
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

// TestCursorConfigProblem_MirrorsCursorsValidator pins each of Cursor's
// top-level rules: a numeric "version" that is a positive integer, and an
// object "hooks". The pre-fix file must fail. That is the case that
// shipped, and the entry check alone (Present) passes it.
func TestCursorConfigProblem_MirrorsCursorsValidator(t *testing.T) {
	cases := []struct {
		name    string
		data    string
		problem string // substring; "" means Cursor loads the file
	}{
		{"the file setup wrote before #5113", preFixCursorHooks, `no "version"`},
		{"version 1", `{"version": 1, "hooks": {}}`, ""},
		{"version 2 (a later format Cursor accepts)", `{"version": 2, "hooks": {}}`, ""},
		{"version 1.0 is the integer 1 in JSON", `{"version": 1.0, "hooks": {}}`, ""},
		{"version as a string", `{"version": "1", "hooks": {}}`, "not a number"},
		{"version null", `{"version": null, "hooks": {}}`, "not a number"},
		{"version 0", `{"version": 0, "hooks": {}}`, "positive integer"},
		{"version negative", `{"version": -1, "hooks": {}}`, "positive integer"},
		{"version fractional", `{"version": 1.5, "hooks": {}}`, "positive integer"},
		{"hooks missing", `{"version": 1}`, `"hooks" is not an object`},
		{"hooks an array", `{"version": 1, "hooks": []}`, `"hooks" is not an object`},
		{"hooks null", `{"version": 1, "hooks": null}`, `"hooks" is not an object`},
		{"top level an array", `[]`, "not a JSON object"},
		{"top level null", `null`, "not a JSON object"},
		{"not JSON", `{"version": 1, "hooks": {}`, "not a JSON object"},
		{"empty file", ``, "not a JSON object"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CursorConfigProblem([]byte(c.data))
			if c.problem == "" {
				if got != "" {
					t.Fatalf("Cursor loads this file, but CursorConfigProblem says %q", got)
				}
				return
			}
			if !strings.Contains(got, c.problem) {
				t.Fatalf("CursorConfigProblem = %q, want it to contain %q", got, c.problem)
			}
		})
	}
}

// TestCursorConfigProblem_EntryCheckAloneMissesIt shows why the check
// exists: Present and Has both accept the file Cursor ignores.
func TestCursorConfigProblem_EntryCheckAloneMissesIt(t *testing.T) {
	data := []byte(preFixCursorHooks)
	if !CursorHookFile.Has(data) || !CursorHookFile.Present(data) {
		t.Fatal("precondition: the entry check should find AgentShield's hook in the pre-fix file")
	}
	if CursorConfigProblem(data) == "" {
		t.Fatal("the pre-fix file is one Cursor ignores, so CursorConfigProblem must report it")
	}
}
