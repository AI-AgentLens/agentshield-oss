package remediation

import (
	"strings"
	"testing"
)

func TestSuggestForShell_RendersDisableCommand(t *testing.T) {
	out := SuggestForShell([]string{"sc-block-rm-root"}, "rm -rf /")
	for _, want := range []string{
		"agentshield rule disable sc-block-rm-root",
		`agentshield check --shell "rm -rf /"`,
		"managed mode",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestSuggestForShell_NoCommand_RendersPlaceholder(t *testing.T) {
	out := SuggestForShell([]string{"sc-block-rm-root"}, "")
	if !strings.Contains(out, `agentshield check --shell "<the command>"`) {
		t.Errorf("expected placeholder when command is empty, got:\n%s", out)
	}
}

func TestSuggestForShell_FirstRuleWins(t *testing.T) {
	// The first rule in the slice is what gets surfaced — that's what fired first
	// in the analyzer pipeline. Subsequent rules are ignored in the disable hint.
	out := SuggestForShell([]string{"first", "second", "third"}, "")
	if !strings.Contains(out, "agentshield rule disable first") {
		t.Errorf("expected first rule to be in disable hint, got:\n%s", out)
	}
	if strings.Contains(out, "agentshield rule disable second") {
		t.Errorf("did not expect 'second' to appear in disable hint, got:\n%s", out)
	}
}

func TestSuggestForShell_NoRules_NoOutput(t *testing.T) {
	if got := SuggestForShell(nil, "rm -rf /"); got != "" {
		t.Errorf("expected empty string when no rules triggered, got:\n%s", got)
	}
	if got := SuggestForShell([]string{}, "rm -rf /"); got != "" {
		t.Errorf("expected empty string when no rules triggered, got:\n%s", got)
	}
}

func TestSuggestForMCP_RendersDisableCommand(t *testing.T) {
	out := SuggestForMCP([]string{"mcp-block-credential-read"})
	for _, want := range []string{
		"agentshield rule disable mcp-block-credential-read",
		"managed mode",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

// TestSuggestForMCP_OmitsShellCheckHint — MCP tool calls have no shell command
// to replay, so the `agentshield check --shell` line must NOT appear. If the
// hint did include it, the user would type a meaningless command and get an
// empty result, then assume AgentShield is broken. Worse than no hint.
func TestSuggestForMCP_OmitsShellCheckHint(t *testing.T) {
	out := SuggestForMCP([]string{"mcp-block-credential-read"})
	if strings.Contains(out, "agentshield check --shell") {
		t.Errorf("MCP hint must NOT mention `agentshield check --shell` — that's shell-only:\n%s", out)
	}
}

func TestSuggestForMCP_NoRules_NoOutput(t *testing.T) {
	if got := SuggestForMCP(nil); got != "" {
		t.Errorf("expected empty string when no rules triggered, got:\n%s", got)
	}
}
