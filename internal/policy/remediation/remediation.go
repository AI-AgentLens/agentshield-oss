// Package remediation builds the self-help text appended to BLOCK messages
// across the shell PreToolUse hook (Claude Code) and the MCP proxy
// (Cursor/Windsurf, plus the Claude Code MCP path inside hook.go).
//
// Centralizing the text here means future tweaks to the disable workflow
// (rename of `agentshield rule disable`, new flags, managed-mode caveat
// updates) land in one place and propagate to every surface that renders
// a block to a user.
//
// The governing rule for anything printed from here: a hint that cannot be
// followed is worse than no hint. Two of them shipped anyway (#3302), and both
// failed in the same way — asserted rather than checked against the machine
// they were printed on:
//
//   - The disable hint told every user to run `agentshield rule disable <id>`
//     and then, two lines later, that disabling is not allowed in managed
//     mode. Exactly one of those sentences applies to any given machine, and
//     the text never said which. Now the caller says whether the machine is
//     managed, and the hint prints one.
//   - The replay hint rendered `agentshield check --shell "<blocked command>"`,
//     which puts the flagged text back in argv. For a text-matching rule —
//     most of the corpus — running it re-triggers the same block, so the
//     "to see why" instruction is the one thing you cannot do.
package remediation

import (
	"fmt"
	"strings"
)

// Whether the machine is managed is a parameter, not something this package
// reads (#4321). The engine calls these functions, and the engine must not
// read enterprise config itself (internal/archtest/layering_test.go). Callers
// pass enterprise.ManagedHost(), the same reading of managed.json that
// CheckDisableAllowed enforces, so the hint and the enforcement cannot drift.

// SuggestForShell renders the BLOCK self-help text for a shell command that
// got blocked through a PreToolUse hook. `command` is the shell command that
// got blocked; pass "" when the caller doesn't have it and the hint will
// render a placeholder instead of a runnable invocation.
func SuggestForShell(triggeredRules []string, command string, managed bool) string {
	if len(triggeredRules) == 0 {
		return ""
	}
	first := triggeredRules[0]

	var sb strings.Builder
	writeDisableHint(&sb, first, managed)

	sb.WriteString("To see why this triggered:\n")
	if command != "" {
		fmt.Fprintf(&sb, "    agentshield check --shell %q\n", command)
	} else {
		sb.WriteString("    agentshield check --shell \"<the command>\"\n")
	}
	// The escape hatch, and why it is phrased as "save it with your editor":
	// every shell form that rebuilds the command inline (printf, echo, a
	// heredoc) puts the flagged text back in argv and blocks again, and the
	// one form that would slip past — wrapping it in a command substitution —
	// is a bypass shape. A security tool should not teach that as a workaround.
	sb.WriteString("    If that is itself blocked, the command TEXT is what matched. Save it\n")
	sb.WriteString("    to a file with your editor, then: agentshield check --shell-file <file>\n")

	return sb.String()
}

// SuggestForMCP renders the BLOCK self-help text for an MCP tool call that
// got blocked. There is no shell-command replay equivalent for an MCP call,
// so we omit the `agentshield check --shell` line and only render the disable
// hint. The user can see what tool and args got rejected from the BLOCK header.
func SuggestForMCP(triggeredRules []string, managed bool) string {
	if len(triggeredRules) == 0 {
		return ""
	}
	first := triggeredRules[0]

	var sb strings.Builder
	writeDisableHint(&sb, first, managed)
	return sb.String()
}

func writeDisableHint(sb *strings.Builder, ruleID string, managed bool) {
	sb.WriteString("\n")
	if managed {
		// Naming the rule is still useful — it is what the administrator needs
		// in order to act — but the local `rule disable` invocation is not
		// printed, because on this machine it is guaranteed to be refused.
		fmt.Fprintf(sb, "This machine is in managed mode, so rule %s cannot be disabled locally.\n", ruleID)
		sb.WriteString("Contact your AgentShield administrator to change the policy.\n")
		return
	}
	sb.WriteString("To allow this in your local environment (after confirming it's safe):\n")
	fmt.Fprintf(sb, "    agentshield rule disable %s\n", ruleID)
}
