package enterprise

import (
	"fmt"
	"os"
	"regexp"
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
func matchesSelfProtectRule(cmd string) (ruleID string, matched bool) {
	for _, rule := range selfProtectRules {
		if rule.Pattern.MatchString(cmd) {
			return rule.ID, true
		}
	}
	return "", false
}

// SelfProtectRuleCount returns the number of active self-protection rules.
func SelfProtectRuleCount() int {
	return len(selfProtectRules)
}
