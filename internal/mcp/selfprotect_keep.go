package mcp

import (
	"encoding/json"
	"regexp"
	"strings"
	"sync"

	"github.com/AI-AgentLens/agentshield/internal/guardian"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// The audit-only keep rule (#4337 review B1), shared by every surface that
// applies audit-only mode. Audit-only records a BLOCK instead of enforcing it,
// except a self-protection BLOCK, which blocks in either mode: on the
// new-install default (audit-only) an agent could otherwise switch off the
// guard that is recording it, and that also ends the evidence.
//
// The rule only ever keeps a BLOCK enforce mode already made. It never raises
// a decision above enforce mode, and it never applies in enforce mode.

// KeepsSelfProtectionBlock is the MCP proxies' keep reading
// (MessageHandler.applyToolCallMode), unchanged from #4337: a self-protection
// rule (IsSelfProtectionRule) is among rules, the rules that decided the
// BLOCK, or the arguments name AgentShield's configuration or an agent hook or
// MCP configuration file in any spelling, read or write
// (argsNameSelfProtectTarget). The proxies add their whole config guard on
// top. The other surfaces use the narrower ApplyModeKeepingSelfProtection,
// which counts only a change to those files; aligning the proxies with it is
// a separate decision.
func (e *PolicyEvaluator) KeepsSelfProtectionBlock(toolName string, arguments map[string]interface{}, rules []string) bool {
	for _, id := range rules {
		if e.IsSelfProtectionRule(id) {
			return true
		}
	}
	return argsNameSelfProtectTarget(toolName, arguments)
}

// ApplyModeKeepingSelfProtection is ApplyMode with a self-protection
// exception, for the surfaces that apply audit-only mode to a tool-call
// verdict outside the proxies: shield-server /v1/evaluate, mcp-eval and the
// hook's tool path. r must be the verdict enforce mode computes. In
// audit-only mode a BLOCK stays BLOCK, with no OriginalDecision, when
// SelfProtectionDecided holds for the tool name or, for an
// mcp__<server>__<tool> name, the bare tool name. Every other decision is
// ApplyMode's, so nothing blocks here that enforce mode would not block.
//
// The kept verdict is enforce mode's verdict exactly. Unlike the proxies it
// does not gain a config-file-guard rule: on these surfaces the guard is not
// a block source in enforce mode.
func (e *PolicyEvaluator) ApplyModeKeepingSelfProtection(r MCPEvalResult, mode, toolName string, arguments map[string]interface{}) MCPEvalResult {
	if mode == "audit-only" && r.Decision == policy.DecisionBlock && e.selfProtectionDecided(toolName, arguments, r.TriggeredRules) {
		return r
	}
	return applyMCPModeDowngrade(r, mode)
}

func (e *PolicyEvaluator) selfProtectionDecided(toolName string, arguments map[string]interface{}, rules []string) bool {
	for _, id := range rules {
		if e.IsSelfProtectionRule(id) {
			return true
		}
	}
	names := []string{toolName}
	if bare, ok := BareToolName(toolName); ok {
		names = append(names, bare)
	}
	for _, name := range names {
		if ChangesSelfProtectTarget(name, arguments) {
			return true
		}
	}
	return false
}

// ChangesSelfProtectTarget reports whether a tool call changes one of the
// files AgentShield's enforcement depends on: its own state (~/.agentshield)
// or an agent's hook or MCP configuration file (selfProtectTargets), in any
// spelling. It is the config guard's self-protection reading
// (selfProtectFindings): a path argument of a write-, move- or delete-shaped
// tool, or a HOME-anchored word in the command text of an exec-shaped tool
// that is not a plain read. A read-shaped tool never counts, and neither do
// the guard's other protected files (shell startup files; git, SSH,
// package-manager, Docker and Kubernetes configuration): those are the
// proxies' wider guard, which this does not change.
//
// This is the second half of the audit-only keep rule on every surface but
// the proxies (#4395 fix round 1): a BLOCK stays BLOCK when a self-protection
// rule decided it or when the call changes such a file.
func ChangesSelfProtectTarget(toolName string, arguments map[string]interface{}) bool {
	return len(selfProtectFindings(toolName, arguments)) > 0
}

// shellCommandTool is the exec-shaped tool name the shell keep rule reads a
// command as, so ChangesSelfProtectTarget reads it as command text.
const shellCommandTool = "execute_command"

// ShellSelfProtectionKeep returns the shell engine's audit-only keep rule
// (policy.Engine.SetSelfProtectionKeep) for a merged shell policy, the same
// rule the tool-call surfaces apply (ApplyModeKeepingSelfProtection): a BLOCK
// stays BLOCK when a self-protection rule decided it, or when the command
// changes AgentShield's state or an agent's hook or MCP configuration file
// (ChangesSelfProtectTarget, reading the command as an exec tool's command
// text). A self-protection rule is a BLOCK rule ShellSelfProtectionRules
// accepts. The rule set is built on first use; only an audit-only BLOCK asks.
//
// The rule that decided is read first, so a relative spelling after `cd`
// (which the command-text reading does not resolve) is kept whenever the
// decision itself was self-protection (#4397, #4424):
//   - a guardian finding with the self-protection taxonomy whose target is
//     AgentShield itself (guardian.TargetsAgentShield): disabling AgentShield,
//     not `git commit --no-verify`;
//   - a protected-path BLOCK whose resolved file is AgentShield's own
//     configuration directory. A managed host protects that directory, and
//     the protected-path check returns before the pipeline, so on a managed
//     host this is often the only rule the keep sees.
func ShellSelfProtectionKeep(pol *policy.Policy) policy.SelfProtectionKeep {
	isSP := ShellSelfProtectionRules(pol)
	return func(command string, rules, protectedHits []string) bool {
		for _, id := range rules {
			if isSP(id) {
				return true
			}
			if guardian.RuleTaxonomy(id) == selfProtectionTaxonomy && guardian.TargetsAgentShield(id, command) {
				return true
			}
		}
		for _, p := range protectedHits {
			if namesAgentShieldConfig(p) {
				return true
			}
		}
		return ChangesSelfProtectTarget(shellCommandTool, map[string]interface{}{"command": command})
	}
}

// namesAgentShieldConfig reports whether the path p is, on this machine,
// AgentShield's own configuration (the guard's agentshield-config entries),
// by the keep rule's reading (namesTargetKeep).
func namesAgentShieldConfig(p string) bool {
	rel, ok := namesTargetKeep(p)
	if !ok {
		return false
	}
	for _, c := range protectedConfigs {
		if c.category == "agentshield-config" && (rel == c.rel || (c.dir && strings.HasPrefix(rel, c.rel+"/"))) {
			return true
		}
	}
	return false
}

// optionalGroupRe is an optional regex group with no group inside it,
// `(?:\.local)?` or `(\.local)?`. Dropping one leaves a spelling the regex
// still matches, so `settings(?:\.local)?\.json` reads as `settings\.json`.
var optionalGroupRe = regexp.MustCompile(`\((?:\?:)?[^()]*\)\?`)

// namesAgentHookFile reports whether a shell rule's match names an agent hook
// file (the guard's ide-hooks entries: Claude Code's settings files, the
// Codex, Cursor, Gemini, Windsurf and Copilot hook files), read as its JSON
// with optional groups dropped and backslashes removed. Such a rule is what
// keeps AgentShield hooked in (ts-block-agent-settings-write,
// ts-block-agent-hook-injection), so its BLOCK is self-protection whatever
// spelling of the file the command used (#4397).
//
// Shell rules only. The MCP index (IsSelfProtectionRule) leaves hook files
// out on purpose: there a rule such as mcp-persist-block-ide-settings-write
// also covers VS Code, Cursor and Zed settings, and the MCP keep reads a hook
// file from the call's path argument instead (#4337 review pass 2).
// TestShellSelfProtectionRules_EmbeddedPacks pins what this admits.
func namesAgentHookFile(match policy.Match) bool {
	b, err := json.Marshal(match)
	if err != nil {
		return false
	}
	text := strings.ToLower(strings.ReplaceAll(optionalGroupRe.ReplaceAllString(string(b), ""), `\`, ""))
	for _, c := range protectedConfigs {
		if c.category == "ide-hooks" && strings.Contains(text, c.rel) {
			return true
		}
	}
	return false
}

// ShellSelfProtectionRules is the self-protection rule test over a merged
// shell policy: a BLOCK rule that IsSelfProtectionRule's per-rule test
// accepts, or whose match names an agent hook file (namesAgentHookFile). The
// set is built on first use.
func ShellSelfProtectionRules(pol *policy.Policy) func(ruleID string) bool {
	var once sync.Once
	var ids map[string]bool
	return func(ruleID string) bool {
		once.Do(func() {
			ids = map[string]bool{}
			if pol == nil {
				return
			}
			for _, r := range pol.Rules {
				if r.Decision == policy.DecisionBlock && (isSelfProtectionRule(r.ID, r.Taxonomy, r.Match) || namesAgentHookFile(r.Match)) {
					ids[r.ID] = true
				}
			}
		})
		return ids[ruleID]
	}
}
