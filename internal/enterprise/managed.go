package enterprise

import (
	"fmt"
	"os"
	"regexp"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// EvalContext carries data through the middleware chain.
type EvalContext struct {
	Command    string
	Cwd        string
	Source     string
	Result     interface{} // *policy.EvalResult — uses interface{} to avoid circular import
	Blocked    bool
	BlockMsg   string
	AuditEvent interface{} // *logger.AuditEvent — uses interface{} to avoid circular import
}

// EvalMiddleware is a function that can inspect/modify the eval context.
// Call next() to continue the chain, or set ctx.Blocked to short-circuit.
type EvalMiddleware func(ctx *EvalContext, next func())

// RunChain executes the middleware chain in order.
func RunChain(ctx *EvalContext, chain []EvalMiddleware) {
	if len(chain) == 0 {
		return
	}
	var run func(i int)
	run = func(i int) {
		if i >= len(chain) {
			return
		}
		chain[i](ctx, func() { run(i + 1) })
	}
	run(0)
}

// BypassGuard is pre-eval middleware that neutralizes AGENTSHIELD_BYPASS in managed mode.
func BypassGuard(cfg *ManagedConfig) EvalMiddleware {
	return func(ctx *EvalContext, next func()) {
		if os.Getenv("AGENTSHIELD_BYPASS") == "1" {
			fmt.Fprintf(os.Stderr, "[AgentShield] warning: AGENTSHIELD_BYPASS detected in managed mode — ignoring bypass, evaluation continues\n")
		}
		next()
	}
}

// selfProtectRules are hardcoded patterns that block attempts to tamper with AgentShield.
var selfProtectRules = []struct {
	ID      string
	Pattern *regexp.Regexp
}{
	{
		ID:      "sp-block-bypass-env",
		Pattern: regexp.MustCompile(`(?i)export\s+AGENTSHIELD_BYPASS\s*=`),
	},
	{
		ID:      "sp-block-setup-disable",
		Pattern: regexp.MustCompile(`agentshield\s+setup\s+\S+\s+--disable`),
	},
	{
		ID:      "sp-block-delete-config",
		Pattern: regexp.MustCompile(`rm\s+.*[~/]\.agentshield`),
	},
	{
		ID:      "sp-block-delete-hooks",
		Pattern: regexp.MustCompile(`rm\s+.*(\.(claude|cursor|windsurf|codeium|gemini|codex|openclaw)/(settings\.json|hooks\.json|hooks/))`),
	},
	{
		ID:      "sp-block-policy-write",
		Pattern: regexp.MustCompile(`(echo|cat|tee|>)\s*.*[~/]\.agentshield/policy\.yaml`),
	},
	{
		ID:      "sp-block-binary-replace",
		Pattern: regexp.MustCompile(`(cp|mv|ln|install)\s+.*agentshield`),
	},
}

// SelfProtect is pre-eval middleware that blocks commands targeting AgentShield itself.
func SelfProtect() EvalMiddleware {
	return func(ctx *EvalContext, next func()) {
		if rule, matched := matchesSelfProtectRule(ctx.Command); matched {
			ctx.Blocked = true
			ctx.BlockMsg = fmt.Sprintf("Blocked: attempt to modify AgentShield configuration (rule: %s)", rule)
			return
		}
		next()
	}
}

// matchesSelfProtectRule checks if a command matches any self-protection rule.
//
// Checks both the raw command and its AST-dequoted reconstruction (GuardFall
// quote-splice class, issue #2813 family): bash's unconditional quote removal
// makes a spliced token like AGENTSHIELD_BYPA'S'S or ~/.agentshi'e'ld resolve
// to the real, unmodified value at execution, but a raw-text regex never sees
// it as a contiguous substring. RegexAnalyzer (internal/analyzer/regex.go)
// already applies this same fallback for command_regex pack rules (#2854);
// the enterprise self-protection layer — the mechanism behind "AgentShield
// cannot be turned off by an AI agent" — needs the identical fix.
func matchesSelfProtectRule(cmd string) (ruleID string, matched bool) {
	match := func(s string) (string, bool) {
		if s == "" {
			return "", false
		}
		for _, rule := range selfProtectRules {
			if rule.Pattern.MatchString(s) {
				return rule.ID, true
			}
		}
		return "", false
	}

	if id, ok := match(cmd); ok {
		return id, true
	}
	dequoted := shellparse.DequoteCommand(cmd)
	if id, ok := match(dequoted); ok {
		return id, true
	}

	// Unset-parameter expansion is the same evasion with a different
	// primitive, and it lands on this layer just as hard as the quote splice
	// did. Verified in bash: `export AGENTSHIELD_BYPA${zqx}SS=1` really does
	// set AGENTSHIELD_BYPASS, `agentshield setup --disa${zqx}ble` really does
	// reach the disable handler, and `rm -rf ~/.agentshi${zqx}eld` really does
	// delete the config — while none of the six raw-text patterns match.
	// An unset variable expands to nothing, so the attacker never has to bind
	// anything; the splice is free.
	//
	// Composed with dequoting in this order only: DequoteCommand bails on any
	// word containing a ParamExp, so a token carrying BOTH tricks
	// (~/.agentshi'e'${zqx}ld) stays undequotable until the splice is folded
	// away first.
	folded := shellparse.NormalizeUnsetParamExp(cmd)
	if id, ok := match(folded); ok {
		return id, true
	}
	if folded != "" {
		if id, ok := match(shellparse.DequoteCommand(folded)); ok {
			return id, true
		}
	}
	if dequoted != "" {
		if id, ok := match(shellparse.NormalizeUnsetParamExp(dequoted)); ok {
			return id, true
		}
	}
	return "", false
}

// SelfProtectRuleCount returns the number of active self-protection rules.
func SelfProtectRuleCount() int {
	return len(selfProtectRules)
}
