package remediation

import (
	"strings"
	"testing"
)

// withManaged pins the managed-mode answer for one test.
//
// Every test here sets it explicitly, including the ones that want "false".
// Left unset, the package would read the DEVELOPER's ~/.agentshield/managed.json
// and the suite would pass or fail depending on whose laptop ran it — the same
// class of untrustworthy result as the hints this file is testing.
func withManaged(t *testing.T, managed bool) {
	t.Helper()
	prev := managedMode
	managedMode = func() bool { return managed }
	t.Cleanup(func() { managedMode = prev })
}

func TestSuggestForShell_RendersDisableCommand(t *testing.T) {
	withManaged(t, false)
	out := SuggestForShell([]string{"sc-block-rm-root"}, "rm -rf /")
	for _, want := range []string{
		"agentshield rule disable sc-block-rm-root",
		`agentshield check --shell "rm -rf /"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestSuggestForShell_NoCommand_RendersPlaceholder(t *testing.T) {
	withManaged(t, false)
	out := SuggestForShell([]string{"sc-block-rm-root"}, "")
	if !strings.Contains(out, `agentshield check --shell "<the command>"`) {
		t.Errorf("expected placeholder when command is empty, got:\n%s", out)
	}
}

func TestSuggestForShell_FirstRuleWins(t *testing.T) {
	// The first rule in the slice is what gets surfaced — that's what fired first
	// in the analyzer pipeline. Subsequent rules are ignored in the disable hint.
	withManaged(t, false)
	out := SuggestForShell([]string{"first", "second", "third"}, "")
	if !strings.Contains(out, "agentshield rule disable first") {
		t.Errorf("expected first rule to be in disable hint, got:\n%s", out)
	}
	if strings.Contains(out, "agentshield rule disable second") {
		t.Errorf("did not expect 'second' to appear in disable hint, got:\n%s", out)
	}
}

func TestSuggestForShell_NoRules_NoOutput(t *testing.T) {
	withManaged(t, false)
	if got := SuggestForShell(nil, "rm -rf /"); got != "" {
		t.Errorf("expected empty string when no rules triggered, got:\n%s", got)
	}
	if got := SuggestForShell([]string{}, "rm -rf /"); got != "" {
		t.Errorf("expected empty string when no rules triggered, got:\n%s", got)
	}
}

func TestSuggestForMCP_RendersDisableCommand(t *testing.T) {
	withManaged(t, false)
	out := SuggestForMCP([]string{"mcp-block-credential-read"})
	if !strings.Contains(out, "agentshield rule disable mcp-block-credential-read") {
		t.Errorf("expected output to contain the disable hint, got:\n%s", out)
	}
}

// TestSuggestForMCP_OmitsShellCheckHint — MCP tool calls have no shell command
// to replay, so the `agentshield check --shell` line must NOT appear. If the
// hint did include it, the user would type a meaningless command and get an
// empty result, then assume AgentShield is broken. Worse than no hint.
func TestSuggestForMCP_OmitsShellCheckHint(t *testing.T) {
	withManaged(t, false)
	out := SuggestForMCP([]string{"mcp-block-credential-read"})
	if strings.Contains(out, "agentshield check --shell") {
		t.Errorf("MCP hint must NOT mention `agentshield check --shell` — that's shell-only:\n%s", out)
	}
}

func TestSuggestForMCP_NoRules_NoOutput(t *testing.T) {
	withManaged(t, false)
	if got := SuggestForMCP(nil); got != "" {
		t.Errorf("expected empty string when no rules triggered, got:\n%s", got)
	}
}

// --- #3302: a hint that cannot be followed is worse than no hint ---

// TestUnmanaged_OmitsManagedCaveat pins the half of #3302 that affected every
// user. The caveat "Disabling rules in managed mode is not allowed" was printed
// unconditionally, two lines under an instruction to disable the rule. Exactly
// one of those sentences is true on any machine and the text never said which,
// so on an unmanaged laptop — the overwhelmingly common case — every block
// message contradicted itself.
func TestUnmanaged_OmitsManagedCaveat(t *testing.T) {
	withManaged(t, false)
	for name, out := range map[string]string{
		"shell": SuggestForShell([]string{"sc-block-rm-root"}, "rm -rf /"),
		"mcp":   SuggestForMCP([]string{"mcp-block-credential-read"}),
	} {
		if strings.Contains(out, "managed mode") {
			t.Errorf("[%s] unmanaged machine must not mention managed mode:\n%s", name, out)
		}
		if !strings.Contains(out, "agentshield rule disable") {
			t.Errorf("[%s] unmanaged machine should get the runnable disable hint:\n%s", name, out)
		}
	}
}

// TestManaged_OmitsDisableCommand is the other direction, and the one that
// matters for a managed fleet: printing `agentshield rule disable <id>` there
// hands the user a command that is guaranteed to be refused. The rule ID still
// appears — it is what the administrator needs — but not as an invocation.
func TestManaged_OmitsDisableCommand(t *testing.T) {
	withManaged(t, true)
	for name, out := range map[string]string{
		"shell": SuggestForShell([]string{"sc-block-rm-root"}, "rm -rf /"),
		"mcp":   SuggestForMCP([]string{"sc-block-rm-root"}),
	} {
		if strings.Contains(out, "agentshield rule disable") {
			t.Errorf("[%s] managed machine must not print a disable invocation:\n%s", name, out)
		}
		if !strings.Contains(out, "managed mode") {
			t.Errorf("[%s] managed machine should say so:\n%s", name, out)
		}
		if !strings.Contains(out, "sc-block-rm-root") {
			t.Errorf("[%s] rule id must still be named for the administrator:\n%s", name, out)
		}
		if !strings.Contains(out, "administrator") {
			t.Errorf("[%s] managed message should say who can change it:\n%s", name, out)
		}
	}
}

// TestSuggestForShell_OffersNonLoopingEscape pins the original #3302 report.
// `agentshield check --shell "<blocked command>"` puts the flagged text back in
// argv, so for a text-matching rule the diagnosis re-triggers the block it was
// meant to explain. The replay line stays (plenty of blocks are path- or
// structure-based and replay fine), but it can no longer be the ONLY thing
// offered.
func TestSuggestForShell_OffersNonLoopingEscape(t *testing.T) {
	withManaged(t, false)
	out := SuggestForShell([]string{"sc-block-rm-root"}, "rm -rf /")
	if !strings.Contains(out, "--shell-file") {
		t.Errorf("expected a --shell-file escape for the self-blocking case:\n%s", out)
	}
	if !strings.Contains(out, "the command TEXT is what matched") {
		t.Errorf("expected the hint to explain WHY the replay can block:\n%s", out)
	}
}

// TestSuggestForShell_DoesNotTeachCommandSubstitution is a guard on the shape
// of the escape rather than its presence. Wrapping the command in `$(cat file)`
// would also dodge the hook — because the hook sees the pre-expansion text —
// and it is a bypass technique. A security tool must not print one as a
// workaround, however convenient. If someone "simplifies" the hint later, this
// fails.
func TestSuggestForShell_DoesNotTeachCommandSubstitution(t *testing.T) {
	withManaged(t, false)
	out := SuggestForShell([]string{"sc-block-rm-root"}, "rm -rf /")
	for _, forbidden := range []string{"$(cat", "`cat", "$(< ", "xargs"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("hint must not suggest %q — that is an evasion shape, not a workaround:\n%s", forbidden, out)
		}
	}
}

// TestManagedModeDefaultIsWiredToEnterprise guards the indirection itself.
// managedMode is a variable so tests can drive both branches; the risk of that
// is someone leaving it stubbed, or pointing it at a second reading of
// managed.json that drifts from enterprise.CheckDisableAllowed. This asserts
// the real default is callable and returns without panicking on whatever the
// running machine looks like.
func TestManagedModeDefaultIsWiredToEnterprise(t *testing.T) {
	_ = managedMode() // must not panic; value is machine-dependent by design
}
