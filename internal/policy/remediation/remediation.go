// Package remediation builds the self-help text appended to BLOCK messages
// across the shell PreToolUse hook (Claude Code) and the MCP proxy
// (Cursor/Windsurf, plus the Claude Code MCP path inside hook.go).
//
// Centralizing the text here means future tweaks to the disable workflow
// (rename of `agentshield rule disable`, new flags, managed-mode caveat
// updates) land in one place and propagate to every surface that renders
// a block to a user.
package remediation

import (
	"fmt"
	"strings"
)

// SuggestForShell renders the BLOCK self-help text for a shell command that
// got blocked through a PreToolUse hook. `command` is the shell command that
// got blocked; pass "" when the caller doesn't have it and the hint will
// render a placeholder instead of a runnable invocation.
func SuggestForShell(triggeredRules []string, command string) string {
	if len(triggeredRules) == 0 {
		return ""
	}
	first := triggeredRules[0]

	var sb strings.Builder
	writeDisableHint(&sb, first)

	sb.WriteString("To see why this triggered:\n")
	if command != "" {
		fmt.Fprintf(&sb, "    agentshield check --shell %q\n", command)
	} else {
		sb.WriteString("    agentshield check --shell \"<the command>\"\n")
	}

	writeManagedCaveat(&sb)
	return sb.String()
}

// SuggestForMCP renders the BLOCK self-help text for an MCP tool call that
// got blocked. There is no shell-command replay equivalent for an MCP call,
// so we omit the `agentshield check --shell` line and only render the disable
// hint plus the managed-mode caveat. The user can see what tool and args got
// rejected from the BLOCK header itself.
func SuggestForMCP(triggeredRules []string) string {
	if len(triggeredRules) == 0 {
		return ""
	}
	first := triggeredRules[0]

	var sb strings.Builder
	writeDisableHint(&sb, first)
	writeManagedCaveat(&sb)
	return sb.String()
}

func writeDisableHint(sb *strings.Builder, ruleID string) {
	sb.WriteString("\n")
	sb.WriteString("To allow this in your local environment (after confirming it's safe):\n")
	fmt.Fprintf(sb, "    agentshield rule disable %s\n", ruleID)
}

func writeManagedCaveat(sb *strings.Builder) {
	sb.WriteString("Disabling rules in managed mode is not allowed.\n")
}
