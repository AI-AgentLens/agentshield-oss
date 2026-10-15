package mcp

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"gopkg.in/yaml.v3"
)

// #4243: a native Windows agent sends backslash-separated paths, and the
// args_match regexes are authored with forward slashes. The glob matcher
// retries with folded separators (#3610); args_match did not, so the
// tool-name-agnostic catch-all that covers a harness's own file tools
// (Claude Code Read, Copilot CLI view) AUDITed a credential read it BLOCKs in
// POSIX spelling. The fix is a third, separator-normalised reading under the
// same raise-only construction as the #4194 case fold.

func windowsSlashEvaluator(t *testing.T, pack string) *PolicyEvaluator {
	t.Helper()
	var p MCPPolicy
	if err := yaml.Unmarshal([]byte(pack), &p); err != nil {
		t.Fatalf("unmarshal pack: %v", err)
	}
	return NewPolicyEvaluator(&p)
}

// TestWindowsSlashReading_RaisesForwardSlashRule pins the mechanism with an inline
// rule, independent of pack churn: a forward-slash args_match pattern now
// fires on the backslash spelling of the same path, and only through the new
// reading (the as-written pass is the positive control).
func TestWindowsSlashReading_RaisesForwardSlashRule(t *testing.T) {
	ev := windowsSlashEvaluator(t, `
defaults:
  decision: AUDIT
structural_rules:
  - id: t-fwd-slash
    match:
      tool_name_regex: ".*"
      args_match:
        path:
          pattern_any:
            - '\.vendor/secret\.json$'
    decision: BLOCK
    reason: test
`)
	for _, v := range []string{
		`C:\Users\dev\.vendor\secret.json`,
		`c:\users\dev\.vendor\secret.json`,
		`%USERPROFILE%\.vendor\secret.json`,
		`$env:USERPROFILE\.vendor\secret.json`,
		`\\host\share\dev\.vendor\secret.json`,
	} {
		args := map[string]interface{}{"path": v}
		if got := ev.evaluateArguments("view", args, "", nil, false).Decision; got == policy.DecisionBlock {
			t.Fatalf("positive control: the as-written reading already BLOCKs %q — the case no longer exercises the fold", v)
		}
		got := ev.EvaluateToolCall("view", args)
		if got.Decision != policy.DecisionBlock || !slices.Contains(got.TriggeredRules, "t-fwd-slash") {
			t.Errorf("%q: got %s %v, want BLOCK by t-fwd-slash", v, got.Decision, got.TriggeredRules)
		}
	}
}

// TestWindowsSlashReading_KeepsBackslashLiteralRules is the additive guard. Rules
// authored with backslash literals for this same platform reason (#3601/#3604)
// match only the as-written spelling; the slashed reading must not displace
// them, and a tie keeps the as-written attribution.
func TestWindowsSlashReading_KeepsBackslashLiteralRules(t *testing.T) {
	ev := windowsSlashEvaluator(t, `
defaults:
  decision: AUDIT
structural_rules:
  - id: t-backslash-literal
    match:
      tool_name_regex: ".*"
      args_match:
        path:
          pattern_any:
            - 'ProgramData\\Vendor\\'
    decision: BLOCK
    reason: test
`)
	got := ev.EvaluateToolCall("write_file", map[string]interface{}{"path": `C:\ProgramData\Vendor\cfg.json`})
	if got.Decision != policy.DecisionBlock || !slices.Contains(got.TriggeredRules, "t-backslash-literal") {
		t.Fatalf("backslash-literal rule lost: got %s %v", got.Decision, got.TriggeredRules)
	}
}

// TestWindowsSlashReading_HarnessFileToolsOnShippedPacks is the issue's matrix on
// the shipped community packs: every Windows spelling of a credential file
// read through a harness file tool must decide BLOCK, as its POSIX spelling
// does. read_file is not in the matrix — its dedicated glob rules were
// already covered by #3610.
func TestWindowsSlashReading_HarnessFileToolsOnShippedPacks(t *testing.T) {
	// The control expects a harness Read of an SSH key to BLOCK, which only the
	// premium rule set does (community records it, #4248).
	ossbuild.SkipPremiumSized(t)
	t.Parallel()
	ev := newTestMCPEvaluator(t)
	targets := []string{`.ssh\id_ed25519`, `.aws\credentials`, `.kube\config`, `.config\gcloud\credentials.db`}
	roots := []string{`C:\Users\dev\`, `c:\users\dev\`, `%USERPROFILE%\`, `$env:USERPROFILE\`, `\\host\share\dev\`}
	tools := []struct{ name, key string }{{"Read", "file_path"}, {"view", "path"}, {"fs_get", "path"}}

	evaluated, leakedAsWritten := 0, 0
	for _, tool := range tools {
		for _, target := range targets {
			posix := "/home/dev/" + strings.ReplaceAll(target, `\`, "/")
			if c := ev.EvaluateToolCall(tool.name, map[string]interface{}{tool.key: posix}).Decision; c != policy.DecisionBlock {
				t.Fatalf("control: %s %s=%s decided %s, want BLOCK — the catch-all changed, fix the matrix", tool.name, tool.key, posix, c)
			}
			for _, root := range roots {
				args := map[string]interface{}{tool.key: root + target}
				evaluated++
				asWritten := ev.evaluateArguments(tool.name, args, "", nil, false).Decision
				if asWritten != policy.DecisionBlock {
					leakedAsWritten++
				}
				got := ev.EvaluateToolCall(tool.name, args).Decision
				if got != policy.DecisionBlock {
					t.Errorf("%s %s=%s: got %s, want BLOCK (POSIX spelling BLOCKs)", tool.name, tool.key, root+target, got)
				}
				if decisionSeverity(got) < decisionSeverity(asWritten) {
					t.Errorf("%s %s=%s: final %s is LOWER than as-written %s — raise-only construction broken", tool.name, tool.key, root+target, got, asWritten)
				}
			}
		}
	}
	// Positive control: without the new reading these spellings leak. If none
	// do, the matrix no longer measures the fix.
	if leakedAsWritten < evaluated/2 {
		t.Errorf("positive control too weak: only %d of %d Windows spellings leak in the as-written reading", leakedAsWritten, evaluated)
	}
	t.Logf("windows slash-reading matrix: %d cases, %d leak without the fold", evaluated, leakedAsWritten)
}

// TestWindowsSlashReading_TN_OrdinaryWindowsPaths: project files that merely look
// near a credential directory must not be raised to BLOCK.
func TestWindowsSlashReading_TN_OrdinaryWindowsPaths(t *testing.T) {
	t.Parallel()
	ev := newTestMCPEvaluator(t)
	for _, v := range []string{
		`C:\src\app\README.md`,
		`C:\Users\dev\projects\ssh-notes\readme.md`,
		`C:\Users\dev\.sshrc-example.md`,
		`D:\work\aws-docs\credentials-guide.md`,
	} {
		for _, tool := range []struct{ name, key string }{{"Read", "file_path"}, {"view", "path"}} {
			if got := ev.EvaluateToolCall(tool.name, map[string]interface{}{tool.key: v}).Decision; got == policy.DecisionBlock {
				t.Errorf("%s %s=%s: got BLOCK, want no BLOCK", tool.name, tool.key, v)
			}
		}
	}
}

// TestSlashWindowsPathArguments_GateAndCopy: only Windows-style values are
// rewritten, nested values are reached, and the input is never mutated (the
// proxy forwards the caller's arguments verbatim).
func TestSlashWindowsPathArguments_GateAndCopy(t *testing.T) {
	in := map[string]interface{}{
		"path":  `C:\Users\U\.cfg\k`,
		"posix": `/tmp/a\b`,
		"list":  []interface{}{`%APPDATA%\x\y`, map[string]interface{}{"p": `\\h\s\f`}},
		"strs":  []string{`D:\a\b`, "plain"},
		"n":     3.0,
	}
	before := fmt.Sprint(in)
	out, ok := slashWindowsPathArguments(in)
	if !ok {
		t.Fatal("expected a rewrite")
	}
	if fmt.Sprint(in) != before {
		t.Fatalf("input mutated: %v", in)
	}
	want := map[string]interface{}{
		"path":  `C:/Users/U/.cfg/k`,
		"posix": `/tmp/a\b`,
		"list":  []interface{}{`%APPDATA%/x/y`, map[string]interface{}{"p": `//h/s/f`}},
		"strs":  []string{`D:/a/b`, "plain"},
		"n":     3.0,
	}
	if fmt.Sprint(out) != fmt.Sprint(want) {
		t.Fatalf("got  %v\nwant %v", out, want)
	}
	for _, v := range []string{`/posix/a\b`, `C:/already/forward`, `%an <%ae>`, "no path"} {
		if _, ok := slashWindowsPathArguments(map[string]interface{}{"v": v}); ok {
			t.Errorf("%q must not be rewritten (nothing to fold, or not Windows-style)", v)
		}
	}
}
