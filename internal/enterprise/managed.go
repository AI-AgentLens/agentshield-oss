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
//
// A rule fires when Pattern matches and Exclude (optional) does not. Exclude
// exists for the default-deny shape (sp-block-config-touch): "anything that
// names this file, unless it is plainly a read".
var selfProtectRules = []struct {
	ID      string
	Pattern *regexp.Regexp
	Exclude *regexp.Regexp
}{
	{
		ID: "sp-block-bypass-env",
		// Anchored on the ASSIGNMENT, not on the `export` keyword (#3212).
		// `export` is one of five ways to set this variable and the least
		// likely to be typed: measured against SelfProtect, `declare -x`,
		// `typeset -x`, `AGENTSHIELD_BYPASS=1 claude` and
		// `env AGENTSHIELD_BYPASS=1 claude` all went unblocked, and the bare
		// inline prefix is the form anyone would actually reach for.
		//
		// A pure READ still passes — `printenv AGENTSHIELD_BYPASS` and
		// `echo $AGENTSHIELD_BYPASS` carry no `=`. What this does newly catch
		// is prose that contains the assignment (a commit message, a doc). In
		// managed mode that is the correct direction: this rule exists to
		// block and audit the ATTEMPT, on the layer that backs the claim that
		// AgentShield cannot be turned off by an AI agent, and nothing benign
		// assigns this variable. BypassGuard independently ignores the
		// variable, so the bypass never worked — but a tamper layer that does
		// not record four of the five attempts is not a tamper layer.
		Pattern: regexp.MustCompile(`(?i)AGENTSHIELD_BYPASS\s*=`),
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
		// Narrowed 2026-09-02 (#3620): the verb list used to be
		// (echo|cat|tee|>). `cat` and `echo` only write through a redirect,
		// and `>` already matches that form (`cat > ~/.agentshield/policy.yaml
		// <<EOF`, `echo x >> …`), so listing them blocked every plain
		// `cat ~/.agentshield/policy.yaml` on a managed host — a false positive
		// that had been there since the rule was written. Writers that are not
		// tee-or-redirect are sp-block-config-touch's job below.
		ID:      "sp-block-policy-write",
		Pattern: regexp.MustCompile(`(tee|>)\s*.*[~/]\.agentshield/policy\.yaml`),
	},
	{
		ID:      "sp-block-binary-replace",
		Pattern: regexp.MustCompile(`(cp|mv|ln|install)\s+.*agentshield`),
	},
	{
		// sp-block-config-touch (#3620) is the default-deny counterpart of
		// sp-block-policy-write. That rule enumerates write verbs — echo, cat,
		// tee, a redirect — and an interpreter is not one of them:
		// `python3 -c "open('~/.agentshield/policy.yaml','w').write(...)"`
		// passed as AUDIT on a managed host while the echo form was blocked.
		// Enumerating writers cannot win (perl, ruby, node, sed -i, cp, mv, dd,
		// install, rsync, and every tool not yet thought of), so this rule
		// inverts the question: on a managed host nothing an agent does with
		// these files is legitimate except reading them, so any command that
		// names one is blocked unless it is a single simple statement that
		// starts with a read-only tool and contains no redirect, pipe,
		// separator, subshell or backtick. The write-verb rules stay for their
		// specific audit attribution.
		//
		// Honest limit: this is still a match over command TEXT (raw, dequoted
		// and unset-param-folded, via matchesSelfProtectRule). A path reached
		// through a symlink or an alias the shell resolves is not seen. The
		// path-based layer that would close that lives in the structural and
		// dataflow analyzers and is tracked separately under #3620.
		ID:      "sp-block-config-touch",
		Pattern: regexp.MustCompile(`[~/]\.agentshield/(policy\.yaml|managed\.json|agentshield\.yaml|credentials\.json|packs(/|\b))`),
		Exclude: plainReadRe,
	},
}

// plainReadRe recognises a single simple statement that starts with a
// read-only tool and contains no redirect, pipe, separator, subshell or
// backtick — the one shape of command that may touch the managed config
// directory on a managed host. Shared by sp-block-config-touch (text layer)
// and IsPlainConfigRead (the path layer in internal/cli), so the two layers
// cannot disagree about what a read is.
//
// The allowlist is tools that CANNOT write or execute through any argument.
// It used to include less, more, bat and yq; the adversarial review of
// 2026-09-02 rewrote the managed policy with `yq -i` and ran arbitrary
// commands with `less +':!sh …'` and `bat --pager 'sh …'`, all exit 0, each
// doubly exempted (text rule AND path layer). A pager with a shell escape is
// not a reader. jq stays: it has no in-place or exec mode. Anything not on
// the list — a pager, an editor, an in-place processor — falls through to
// the default-deny and blocks.
var plainReadRe = regexp.MustCompile("^\\s*(sudo\\s+)?(cat|head|tail|grep|rg|ls|stat|file|wc|diff|jq|echo|printf|agentshield)(\\s+[^;&|<>\\n`(!]*)?$")

// IsPlainConfigRead reports whether cmd is a single simple read-only
// statement (see plainReadRe). The path-based config protection in managed
// mode (#3620) exempts exactly these, so that `cat ~/.agentshield/policy.yaml`
// stays possible while every other access to the directory — including one
// reached through a variable or an interpreter — is blocked.
func IsPlainConfigRead(cmd string) bool {
	return plainReadRe.MatchString(cmd)
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
			if !rule.Pattern.MatchString(s) {
				continue
			}
			if rule.Exclude != nil && rule.Exclude.MatchString(s) {
				continue
			}
			return rule.ID, true
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
