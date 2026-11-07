package enterprise

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
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
	// BlockRule is the id of the self-protection rule that blocked (an sp-*
	// id), set by SelfProtect together with BlockMsg. The receipt maps its
	// taxonomy node per rule, not per middleware (#4603), so the id has to
	// leave the matcher as data rather than only as text inside BlockMsg.
	BlockRule string
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
// names this file, unless it is plainly a read", and for one recognised
// false-positive shape (sp-block-binary-replace, #4637).
//
// ExcludeRawOnly makes the exclusion apply to a reading only when the RAW
// command matches Exclude too. A reading can only add a match, so an
// exclusion granted to a reading the raw text is not can only remove one:
// #4642's Codex pass folded `echo mc${zqx#$('mv' …)}p agentshield` to the
// recognised `echo mcp agentshield` while zsh ran the move.
var selfProtectRules = []struct {
	ID             string
	Pattern        *regexp.Regexp
	Exclude        *regexp.Regexp
	ExcludeRawOnly bool
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
		ID: "sp-block-setup-disable",
		// Keep the historical text match as an OR with matchesSetupDisable:
		// parsed argv adds flag-order coverage without weakening any decision.
		// --remove-managed (setup claude-code) takes AgentShield's hook out of
		// Claude Code's managed settings: the same family, one more spelling.
		Pattern: regexp.MustCompile(`agentshield\s+setup\s+\S+\s+--(?:disable|remove-managed)`),
	},
	{
		ID:      "sp-block-delete-config",
		Pattern: regexp.MustCompile(`rm\s+.*[~/]\.agentshield`),
	},
	{
		ID:      "sp-block-delete-hooks",
		Pattern: regexp.MustCompile(`rm\s+.*(\.(claude|cursor|windsurf|codeium|gemini|codex|openclaw|copilot)/(settings\.json|hooks\.json|hooks/))`),
	},
	{
		// sp-block-brew-uninstall (#4662): an agent must not remove its own
		// guard; uninstall happens outside the agent. That is #4035's reason
		// for sp-block-delete-config, and removing the Homebrew package goes
		// further: it deletes the binary every hook calls. On main
		// `brew remove` and `brew rm` of the cask were allowed, and
		// `brew uninstall` / `brew reinstall` were blocked only because the
		// `install` inside them matched sp-block-binary-replace's verb list.
		//
		// The verbs are Homebrew's own: uninstall and its aliases from
		// Library/Homebrew/brew.sh and commands.rb (`rm`, `remove`,
		// `uninstal`), reinstall, which runs the cask's uninstall stanza
		// before it installs again, and unlink (Gary, 2026-10-30): it
		// removes a formula's links and a cask's `binary` symlink
		// (cmd/unlink.rb), which is the PATH entry a hook written as
		// `agentshield hook` resolves. The name may be tap-qualified
		// (`ai-agentlens/tap/agentshield`) and is matched without case,
		// because Homebrew downcases named arguments (cli/named_args.rb);
		// the whole pattern is case-blind so `BREW` on a case-insensitive
		// volume is not a way around it. The flags in between are not
		// enumerated, so `--cask`, `--zap`, `--force` and their order do
		// not matter. Everything from the verb to the name stays inside one
		// statement: no `;`, `&`, `|` or newline, so
		// `brew uninstall --cask other && agentshield status` does not match.
		// A backslash-newline is a line continuation, not a newline, and is
		// read as a space: no reading of the family joins continued lines
		// (`rm -rf \<newline> ~/.agentshield` matches no rule on main), so
		// the pattern has to.
		//
		// Fix round 1 (#4664 pass 1, three AUDITs on a managed host):
		//   - One `-v` may come before the verb. brew.sh shifts a leading
		//     `-v` to the end of the arguments (`if [[ "$1" == "-v" ]]`),
		//     and that is the only word it accepts there: everything else
		//     in that position is the command (`HOMEBREW_COMMAND="$1"`), so
		//     `brew --verbose rm x` and `brew -d rm x` print usage, and
		//     `brew -v -v rm x` prints the version. Measured on Homebrew
		//     7.0.11. Any other word before the verb is not a removal.
		//   - `-v` and the verb may each be one whole quoted word (`"rm"`,
		//     `'remove'`). DequoteCommand leaves a word that is a single
		//     quote alone by design, so no reading removes those quotes.
		//   - A redirect may follow the name with no space
		//     (`agentshield>/dev/null`, `agentshield</dev/null`).
		//   - The name must be an operand, not a redirect target: the word
		//     that holds it contains no `<` or `>`, and the word before it
		//     does not end in one, so `brew rm --cask other >/tmp/agentshield`
		//     no longer matches (it did in pass 1).
		//
		// Fix round 2 (#4664; Gary, 2026-10-30: fix all four):
		//   - `brew` must be the command word: its own word at the start of
		//     a statement, after an assignment, a redirect or an exec
		//     wrapper (brewCommandWord), optionally with a path. A word
		//     that merely ends in `brew` (`cp /tmp/homebrew rm agentshield`)
		//     is not Homebrew, and keeps main's attribution.
		//   - A word ending in an escaped `\<` / `\>`, or in a CR, is an
		//     operand, not a redirect (fix round 1 read it as one). The
		//     words before the name are read escape by escape, so `x\\>` is
		//     still a redirect (the backslash is escaped, the `>` is not),
		//     and an escaped `\;`, `\&` or `\|` is a literal, not a separator.
		//   - A redirect that duplicates or closes a descriptor (`2>&1`,
		//     `>&2`, `<&3`, `&>file`) may come before the name: its `&` is
		//     part of the redirect, not a statement separator.
		//   - The name may carry `.rb`. For a formula, Formulary.to_rack
		//     takes File.basename(ref, ".rb") as the rack, so
		//     `brew rm agentshield.rb` removes the installed formula, as does
		//     a path to an existing formula file; a cask path loads by
		//     token_from_path, which drops the extension the same way.
		//
		// `brew upgrade agentshield` also runs the uninstall stanza (#4535),
		// but it reinstalls the guard rather than removing it: allowed
		// (Gary, 2026-10-30), and TestSelfProtect_BrewUninstall_4662 pins
		// it unmatched.
		ID:      "sp-block-brew-uninstall",
		Pattern: brewUninstallPattern,
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
		// main's pattern, byte for byte. Its verb has no left boundary, so
		// `cp` matches inside `mcp` (#4637). A boundary was tried first and
		// dropped real spellings (`scp`, `$1cp`, `gcp`: #4642 review pass 1),
		// so the pattern stays as it was and the exclusion recognises only
		// the false-positive shape #4637 reported. Anything it does not
		// recognise keeps main's decision. See binaryReplaceMCPWordRe.
		ID:             "sp-block-binary-replace",
		Pattern:        regexp.MustCompile(`(cp|mv|ln|install)\s+.*agentshield`),
		Exclude:        binaryReplaceMCPWordRe,
		ExcludeRawOnly: true,
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

// binaryReplaceMCPWordRe is sp-block-binary-replace's exclusion (#4637). It
// recognises, as the whole command, only the two shapes #4637 reported, in
// which the `cp` of the word `mcp` is what makes the pattern match:
//
//   - `agentshield setup mcp` with only its own --mode and --target flags and
//     their documented values, optionally followed by `&&` or `;` and
//     `agentshield status`;
//   - `echo` and plain words, one of them `mcp`.
//
// It is anchored at both ends, so it is a recogniser, not a boundary: a
// command it does not match in full keeps main's BLOCK. The only review
// question is whether a string it matches can replace the binary, and none
// can. setup mcp writes the MCP clients' config files, the MCP packs and the
// default policy under HOME (setup_mcp.go); status only reads; echo writes to
// stdout. The words admit no redirect, pipe, expansion, quote, backslash,
// glob or newline. Two things are left out on purpose:
//
//   - `agentshield` with other arguments. `agentshield mcp-proxy -- <cmd>`
//     runs <cmd>, so an open argument list would forward
//     `cp /tmp/x /usr/local/bin/agentshield` past this rule.
//   - `\s`. Only spaces and tabs separate words: a newline separates
//     statements and would let a second command through.
var binaryReplaceMCPWordRe = regexp.MustCompile(`^[ \t]*(?:` +
	`agentshield[ \t]+setup[ \t]+mcp` +
	`(?:[ \t]+--(?:mode(?:=|[ \t]+)(?:enforce|audit-only)|target(?:=|[ \t]+)(?:all|claude-desktop|cursor)))*` +
	`(?:[ \t]*(?:&&|;)[ \t]*agentshield[ \t]+status)?` +
	`|echo(?:[ \t]+[A-Za-z0-9_.-]+)*[ \t]+mcp(?:[ \t]+[A-Za-z0-9_.-]+)*` +
	`)[ \t]*$`)

// brewUninstallPattern is sp-block-brew-uninstall's pattern (#4662). The
// reasons for each part are on the rule's entry in selfProtectRules.
var brewUninstallPattern = regexp.MustCompile(`(?i)` + brewCommandWord + brewSep +
	`(?:` + brewWord(`-v`) + brewSep + `)?` +
	brewWord(`(?:uninstall|uninstal|remove|rm|reinstall|unlink)`) + brewSep +
	// Flags, other names and redirects, then the name's own word: one that
	// holds no redirect operator, after a word that does not end in one. The
	// words are read a character or an escape pair at a time (`\` and the
	// character after it, which covers the `\`-newline continuation), so an
	// escaped `\>` or `\;` is a literal and `\\>` is an escaped backslash
	// before a real `>`. A `&` is a separator except inside a descriptor
	// redirect (`2>&1`, `>&2`, `<&3`, `&>file`). bash reads CR as a word
	// character, so a word may end in one.
	`(?:(?:\\[\s\S]|[^;&|\n\\]|[<>]&|&>)*(?:\\[^\n]|[^;&|<> \t\n\\])` + brewSep + `)?` +
	`(?:[^\s;&|<>]*[/'"])?agentshield(?:\.rb)?(?:$|[ \t\r\n'"` + "`" + `;&|)<>]|\\\n)`)

// brewCommandWord is `brew` as the command word of a statement (#4664 fix
// round 2): the start of the text or of a statement (after `;`, `&`, `|`,
// `(`, `)`, `{`, a backtick, a newline or `!`, or an opening quote, which is
// how `bash -c 'brew …'` and `eval "brew …"` carry one), then any number of
// prefix words (brewPrefixWord), then `brew` with an optional path
// (`/opt/homebrew/bin/brew`, `$HOMEBREW_PREFIX/bin/brew`), `\`, zsh's `=`, or
// a special parameter that expands to nothing (`$1brew`). A word that only
// ends in `brew` (`/tmp/homebrew`) or an argument of a command that is not a
// wrapper (`cp /tmp/brew rm agentshield`) is not this rule's: those keep
// main's attribution.
const brewCommandWord = `(?:^|[;&|(){\n` + "`" + `!'"])(?:[ \t]|\\\n)*` +
	`(?:` + brewPrefixWord + brewSep + `)*` +
	`(?:[^\s;&|<>()=]*/)?(?:[\\=]|\$[0-9@*#?$!-]|\$\{[^}\s]*\})*brew`

// brewPrefixWord is one word that may stand before the command word: an
// assignment (`HOMEBREW_NO_AUTO_UPDATE=1`), a redirect (`>/dev/null`,
// `2>&1`), or an exec wrapper or keyword, bare or by path
// (`/usr/bin/env`), followed by its own options and arguments
// (`sudo -u admin`, `env -i PATH=…`, `arch -arm64`, `then`).
//
// The wrappers are an allowlist, kept on purpose: the commands that run an
// argument as a command can be listed, the commands that merely mention one
// cannot. A wrapper not on the list leaves the statement to main's rules
// (`sp-block-binary-replace` still blocks `… brew uninstall agentshield`
// there). That is the price of item 4 of #4664 fix round 2: `brew` as an
// argument of a command that does not run it is not this rule's.
const brewPrefixWord = `(?:` +
	`[A-Za-z_][A-Za-z0-9_]*\+?=[^\s;&|<>()]*` +
	`|[0-9]*(?:[<>]&|&>>?|>>|>\||<>|<<<|[<>])[ \t]*[^\s;&|<>()]+` +
	`|(?:[^\s;&|<>()=]*/)?\\?(?:` + brewWrappers + `)` +
	`(?:` + brewSep + `[^\s;&|<>()]+)*?` +
	`)`

// brewWrappers are the commands and keywords after which the next word, or a
// later one, runs as a command.
const brewWrappers = `sudo|doas|su-exec|gosu|runuser|env|command|builtin|exec|eval|` +
	`nohup|setsid|time|nice|ionice|timeout|gtimeout|caffeinate|taskpolicy|arch|` +
	`xargs|find|parallel|watch|entr|flock|stdbuf|unbuffer|rlwrap|script|chronic|` +
	`noglob|nocorrect|sandbox-exec|launchctl|screen|chroot|unshare|nsenter|firejail|` +
	`proxychains4?|torsocks|faketime|strace|ltrace|dtruss|valgrind|tini|dumb-init|ssh|` +
	`uvx?|poetry|pdm|pipx|bundle|npx|bunx|pnpm|yarn|mise|asdf|direnv|nix|devbox|` +
	`op|doppler|aws-vault|dotenv|infisical|` +
	`then|do|else|elif|if|while|until`

// brewSep is the space between two words of a brew command: blanks, or a
// backslash-newline continuation.
const brewSep = `(?:[ \t]|\\\n)+`

// brewWord matches word bare or as one whole single- or double-quoted word.
func brewWord(word string) string {
	return `(?:` + word + `|'` + word + `'|"` + word + `")`
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
			ctx.BlockRule = rule
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
	// The readings main made, unchanged: the argv walk reads each text only
	// when it parses as bash.
	if id, ok := matchSelfProtectReadings(cmd, cmd, setupDisableInParse); ok {
		return id, true
	}

	// Everything below runs only for a command nothing above matched, so a
	// command that matched before keeps its rule id, and these readings can
	// only add a match (#4631).
	//
	// A command the bash parser rejects gets nothing from the dequoted and
	// unset-param-folded readings above, which return "" without a bash
	// parse, or from the argv walk. zsh, which runs the Bash tool's commands
	// on a stock Mac, accepts commands the bash parser rejects, and one
	// zsh-only no-op statement (`: ${(U)HOME};`) is enough to cause the
	// rejection, so `: ${(U)HOME}; rm -rf ~/.agentshi'e'ld` matched nothing.
	// The same readings are tried on zsh's reading of the command (#4598),
	// which exists only when the bash parse fails.
	zsh := shellparse.ZshReading(cmd)
	if zsh != "" {
		if id, ok := matchSelfProtectReadings(zsh, cmd, setupDisableInParse); ok {
			return id, true
		}
	}
	// What the readings above leave to matchesSetupDisable: the argv walk on
	// #3211's backslash fold, and the token scan for a command no reading
	// parses.
	if matchesSetupDisable(cmd) {
		return "sp-block-setup-disable", true
	}

	// The readings main never made (#4663) come last, after every reading
	// main made, so a command main matched keeps main's rule id. Run earlier,
	// they claimed a bash-unparseable command for sp-block-delete-config that
	// main attributes to sp-block-setup-disable through the zsh reading.
	if id, ok := matchContinuationAndQuotedVerbReadings(cmd, cmd, setupDisableInParse); ok {
		return id, true
	}
	if zsh != "" {
		if id, ok := matchContinuationAndQuotedVerbReadings(zsh, cmd, setupDisableInParse); ok {
			return id, true
		}
	}
	return "", false
}

// matchSelfProtectText tries one text against every rule, with argv as the
// argv reading of sp-block-setup-disable. raw is the command as the harness
// sent it, which an ExcludeRawOnly rule's exclusion must also match.
func matchSelfProtectText(s, raw string, argv func(string) bool) (ruleID string, matched bool) {
	if s == "" {
		return "", false
	}
	for _, rule := range selfProtectRules {
		if !rule.Pattern.MatchString(s) && !(rule.ID == "sp-block-setup-disable" && argv(s)) {
			continue
		}
		if rule.Exclude != nil && rule.Exclude.MatchString(s) &&
			(!rule.ExcludeRawOnly || rule.Exclude.MatchString(raw)) {
			continue
		}
		return rule.ID, true
	}
	return "", false
}

// matchSelfProtectReadings is main's matchesSelfProtectRule for one text: the
// text itself, its dequoted reconstruction and its unset-param-folded
// readings, each tried against every rule, with argv as the argv reading of
// sp-block-setup-disable. raw is the command as the harness sent it, which an
// ExcludeRawOnly rule's exclusion must also match.
func matchSelfProtectReadings(cmd, raw string, argv func(string) bool) (ruleID string, matched bool) {
	match := func(s string) (string, bool) { return matchSelfProtectText(s, raw, argv) }

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

// matchContinuationAndQuotedVerbReadings holds two readings main never made
// (#4663). matchesSelfProtectRule tries them only after every reading main
// made has missed, so they can only add a match.
func matchContinuationAndQuotedVerbReadings(cmd, raw string, argv func(string) bool) (ruleID string, matched bool) {
	match := func(s string) (string, bool) { return matchSelfProtectText(s, raw, argv) }

	// A backslash-newline is deleted by the shell before tokenizing, so
	// `cp /tmp/x \<NL> /usr/local/bin/agentshield` is one command. No pattern's
	// `\s+` spans it, and DequoteCommand returns "" when it has nothing to
	// dequote, so no reading above ever held the joined line.
	joined := shellparse.JoinLineContinuations(cmd)
	if id, ok := match(joined); ok {
		return id, true
	}
	if joined != "" {
		if id, ok := match(shellparse.DequoteCommand(joined)); ok {
			return id, true
		}
	}
	// A quoted command word (`'cp'`, `"mv"`) is the same program, but
	// DequoteCommand leaves the executable position to NormalizeExecName and
	// the verbs' patterns need whitespace right after the verb. Each
	// statement's first word is folded in place, so separators stay as written.
	// The folded statement then gets every reading main makes, so a quoted verb
	// with a spliced path (`'cp' x /usr/local/bin/agentshi'e'ld`) is read too.
	// FoldLeadingExecWord returns "" unless the first word was quoted, so this
	// reads nothing new for any other statement.
	for _, base := range []string{cmd, joined} {
		if base == "" {
			continue
		}
		for _, stmt := range shellparse.SplitTopLevelStatements(base) {
			folded := shellparse.FoldLeadingExecWord(stmt)
			if folded == "" {
				continue
			}
			if id, ok := matchSelfProtectReadings(folded, raw, argv); ok {
				return id, true
			}
		}
	}
	return "", false
}

// matchesSetupDisable adds an argv reading of sp-block-setup-disable (#4565).
// Each simple command is considered independently, including commands nested
// in substitutions or compound statements. It ORs with the regex readings in
// matchesSelfProtectRule, so it can only add matches.
//
// The argv walk needs a bash parse, and until #4631 a parse failure meant "no
// match": one zsh-only statement anywhere in the command (`: ${(U)HOME};`, a
// `{ C }` group, an anonymous function) turned the walk off and left only the
// regex, which knows one argument order. So when the command does not parse,
// the walk runs on the readings that do: #3211's backslash fold and #4598's
// zsh reading (setupDisableArgvReadings).
//
// When no reading parses, the command names no argv at all, and the walk is
// replaced by a token scan (namesAgentshieldSetup): an `agentshield` word
// followed later by a `setup` word is a match, with or without `--disable`.
// That is deliberately fail-closed. It applies only to text neither parser
// accepts, only in managed mode, and only to the one shape every disable has
// to take; `--disable` is not required because its spellings (`--disa${x}ble`,
// `--disable=1`, a flag in a variable) cannot be enumerated without a parse.
// The cost is a BLOCK on such text that only mentions the two words. Where
// real zsh cannot parse the text either, that BLOCK stops nothing: zsh 5.9
// refuses the whole string, in `zsh -c` and in `eval`, on an unmatched quote
// in any line. Where real zsh runs text the pinned zsh parser rejects (the
// short `for i (1) C` loop), the BLOCK is real (#4631).
//
// A zsh reading can also erase: a statement that zsh runs and that no edit
// makes bash-parseable is written `:` (shellparse.ZshReadingErased), so
// `X=$((1.5)) agentshield setup mcp --disable` leaves a reading that parses
// and holds no agentshield at all. Each erased statement's own text gets the
// token scan, statement by statement, so words that survive in another
// statement (`… ; grep 'agentshield setup' README.md`) neither help nor hurt
// (review round 1 on #4634).
func matchesSetupDisable(cmd string) bool {
	readings, erased := setupDisableArgvReadings(cmd)
	if len(readings) == 0 {
		return namesAgentshieldSetup(cmd)
	}
	for _, parsed := range readings {
		if setupDisableInArgv(parsed) {
			return true
		}
	}
	for _, stmt := range erased {
		if namesAgentshieldSetup(stmt) {
			return true
		}
	}
	return false
}

// setupDisableInParse is the argv reading main made: cmd's own bash parse,
// and no match when it does not parse. matchesSelfProtectRule uses it for
// every reading it tried before #4631, so those decide exactly as before.
func setupDisableInParse(cmd string) bool {
	p := shellparse.Parse(cmd, 0)
	return p != nil && !p.Fallback && setupDisableInArgv(p)
}

// setupDisableArgvReadings returns the bash parses the argv walk reads: the
// command as written when it parses, which is every command main read;
// otherwise the command with #3211's obfuscating backslashes folded
// (`export FO\O=1` is FOO to bash, as DequoteCommand already reads it) and
// zsh's reading of the command (shellparse.ZshReading, #4598), each also
// folded, keeping every one that parses. Empty means no reading parses.
// erased is the source text of the statements the zsh reading wrote `:`
// (shellparse.ZshReadingErased), returned only when that reading is kept.
func setupDisableArgvReadings(cmd string) (readings []*shellparse.ParsedCommand, erased []string) {
	parse := func(s string) *shellparse.ParsedCommand {
		if p := shellparse.Parse(s, 0); p != nil && !p.Fallback {
			return p
		}
		return nil
	}
	if p := parse(cmd); p != nil {
		return []*shellparse.ParsedCommand{p}, nil
	}
	addFolded := func(s string) bool {
		if folded, changed := pathnorm.FoldObfuscatingBackslashesUnquoted(s); changed {
			if p := parse(folded); p != nil {
				readings = append(readings, p)
				return true
			}
		}
		return false
	}
	addFolded(cmd)
	if reading, dropped := shellparse.ZshReadingErased(cmd); reading != "" {
		if p := parse(reading); p != nil {
			readings = append(readings, p)
			erased = dropped
		} else if addFolded(reading) {
			erased = dropped
		}
	}
	return readings, erased
}

// namesAgentshieldSetup is the token scan matchesSetupDisable falls back to
// when no reading of cmd parses (#4631). It reports whether an `agentshield`
// executable word (any path whose last element is agentshield, as in the argv
// walk) is followed, anywhere later in the text, by a `setup` word.
//
// The text cannot be tokenised the way a shell would, so the scan is
// tolerant in the direction that adds matches. It first decodes `$'...'`
// spans as the argv path does (pathnorm.DecodeDollarQuotedSpans), then
// deletes `${...}` expansions and `$name` references (an unset one expands
// to nothing, the #3044 splice), the `$` of `$"..."` (and of an unterminated
// `$'`), backslash-newline, and
// then every quote and backslash, so `agent'sh'ield`, `se"tu"p`,
// `agentshi${z}eld` and `agent\shield` all read as the plain words. It then
// splits on whitespace and the shell's operator and grouping characters, and
// on brace-expansion commas (`{agentshield,setup}`). A leading `=` is dropped
// from a word: zsh's `=agentshield` runs agentshield from PATH (#4597).
//
// The decoded and raw texts are both scanned, also with static default and
// alternate words in parameter expansions retained instead of deleted. Each
// extra candidate is ORed with the original scan, so matches can only rise.
//
// Not matched, on purpose: `agentshield` alone, `setup` alone, and `setup`
// before `agentshield`. The last one would be reachable only through
// indirection (`x=setup; agentshield $x`), which the parsed path does not
// resolve either; matching any co-occurrence would block every unparseable
// command that mentions both words in either order. The comparison is
// case-sensitive, like the argv walk and the regex.
func namesAgentshieldSetup(cmd string) bool {
	decoded, _ := pathnorm.DecodeDollarQuotedSpans(cmd)
	if scanAgentshieldSetup(decoded) || scanAgentshieldSetup(cmd) {
		return true
	}
	// Keep the deletion reading above: a default or alternate word is only
	// another candidate, as is the raw text when decoding opens a false span
	// at an earlier single-quoted word's closing `$'` (#4638).
	for _, s := range []string{decoded, cmd} {
		s = strings.ReplaceAll(s, "\\\n", "")
		withWords := setupScanParamWordRe.ReplaceAllString(s, "$1")
		if withWords != s && scanAgentshieldSetup(withWords) {
			return true
		}
	}
	return false
}

func scanAgentshieldSetup(s string) bool {
	s = strings.ReplaceAll(s, "\\\n", "")
	s = setupScanParamRe.ReplaceAllString(s, "")
	s = setupScanQuotePrefixRe.ReplaceAllString(s, "$1")
	s = strings.NewReplacer(`'`, "", `"`, "", `\`, "").Replace(s)
	words := strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', '\v', '\f', ';', '&', '|', '(', ')', '<', '>', '`', '{', '}', ',':
			return true
		}
		return false
	})
	seenAgentshield := false
	for _, w := range words {
		w = strings.TrimPrefix(w, "=")
		if !seenAgentshield {
			seenAgentshield = path.Base(w) == "agentshield" && !strings.HasSuffix(w, "/")
			continue
		}
		if w == "setup" {
			return true
		}
	}
	return false
}

var (
	// setupScanParamRe matches a `${...}` expansion (no nested braces) or a
	// `$name` reference, which namesAgentshieldSetup deletes.
	setupScanParamRe = regexp.MustCompile(`\$\{[^{}]*\}|\$[A-Za-z_][A-Za-z0-9_]*`)
	// setupScanParamWordRe retains the word of a default, assignment or
	// alternate expansion; the original scan still deletes the expansion.
	setupScanParamWordRe = regexp.MustCompile(`\$\{(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-]):?[=+-]([^{}]*)\}`)
	// setupScanQuotePrefixRe matches the `$` that opens `$'...'` or `$"..."`.
	setupScanQuotePrefixRe = regexp.MustCompile(`\$(['"])`)
	// bareExpansionWordRe matches a command word that is one unquoted plain
	// parameter expansion, `$name` or `${name}` (#4636).
	bareExpansionWordRe = regexp.MustCompile(`^(?:\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\})$`)
)

// namesAgentshieldBinary reports whether an executable word names the
// agentshield binary. It keeps the basename test the walk always made on the
// word as parsed and ORs a second reading: a word that is one quoted span has
// its quotes removed (single quotes keep everything literal; inside double
// quotes a backslash escapes only \ " $ and a backtick). The parser keeps a
// quoted path containing `$` or a backtick whole, so its basename ends in the
// closing quote and missed (#4577). Matches can only rise.
func namesAgentshieldBinary(exe string) bool {
	isBin := func(w string) bool { return path.Base(w) == "agentshield" && !strings.HasSuffix(w, "/") }
	if isBin(exe) {
		return true
	}
	if len(exe) < 2 || exe[0] != exe[len(exe)-1] || (exe[0] != '\'' && exe[0] != '"') {
		return false
	}
	inner := exe[1 : len(exe)-1]
	if exe[0] == '\'' {
		if strings.ContainsRune(inner, '\'') {
			return false // more than one span
		}
		return isBin(inner)
	}
	inner = strings.NewReplacer(`\\`, `\`, `\"`, `"`, `\$`, `$`, "\\`", "`").Replace(inner)
	return isBin(inner)
}

// setupDisableInArgv is the argv walk of matchesSetupDisable over one parse.
func setupDisableInArgv(parsed *shellparse.ParsedCommand) bool {
	for _, pc := range shellparse.AllParsedCommands(parsed) {
		if pc.Fallback {
			continue
		}
	segments:
		for _, seg := range pc.Segments {
			// Unlike ProgramName, this rule also covers relative binary paths.
			// A statically quoted path with a literal `$` is read through
			// namesAgentshieldBinary (#4577).
			exe, words := seg.Executable, seg.RawWords
			// An unquoted `$name` / `${name}` command word that expands to
			// nothing is dropped by bash and zsh, and the next word runs
			// (#4636). Peel such words as an additional reading; the quoted
			// `"$name"` form keeps its quotes in Executable, never matches
			// here, and still reads as the (failing) empty command it is.
			for bareExpansionWordRe.MatchString(exe) && len(words) > 0 {
				exe, words = pathnorm.StripShellQuotes(words[0]), words[1:]
			}
			if !namesAgentshieldBinary(exe) {
				continue
			}
			args := make([]string, len(words))
			for i, word := range words {
				args[i] = pathnorm.StripShellQuotes(word)
			}
			// Add Cobra's discovery reading, retaining the conservative reading
			// below (e.g. --disable before setup) so decisions can only rise.
			setup, disable := setupDisableRootIsSetup(args), false
			for i := 0; i < len(args); i++ {
				arg := args[i]
				if arg == "--" {
					break // pflag v1.0.9 flag.go:1143-1147: -- ends flags.
				}
				switch {
				case arg == "--disable" || arg == "--remove-managed":
					// --remove-managed takes the hook out of Claude Code's
					// managed settings: the same family as --disable.
					disable = true // pflag v1.0.9 bool.go:56: NoOptDefVal = "true".
				case strings.HasPrefix(arg, "--disable="):
					// pflag v1.0.9 bool.go:20-24 uses strconv.ParseBool.
					v, err := strconv.ParseBool(strings.TrimPrefix(arg, "--disable="))
					disable = disable || (err == nil && v)
				case strings.HasPrefix(arg, "--remove-managed="):
					v, err := strconv.ParseBool(strings.TrimPrefix(arg, "--remove-managed="))
					disable = disable || (err == nil && v)
				case arg == "--policy" || arg == "--log" || arg == "--mode" || arg == "--target":
					// Root string flags and setup mcp's string flag consume one
					// argv word, even a flag: pflag v1.0.9 flag.go:1011-1021.
					i++
				case !setup && !strings.HasPrefix(arg, "-"):
					// The first positional names the root subcommand. A later
					// operand spelled "setup" cannot turn status into setup.
					if arg != "setup" {
						continue segments
					}
					setup = true
				}
			}
			if setup && disable {
				return true
			}
		}
	}
	return false
}

// setupDisableRootIsSetup mirrors Cobra v1.10.2 command.go:674-705,760-769:
// skip empty/dash words, consume bare long/single-short flag values (unknown
// flags too), stop at --, and use the first remaining operand. root.go defines
// only string flags (policy/log/mode), with no shorthands or NoOptDefVal;
// Cobra adds help flags after Find (command.go:916-919,1120-1123).
func setupDisableRootIsSetup(args []string) bool {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			return false
		case !strings.Contains(arg, "=") && (strings.HasPrefix(arg, "--") ||
			(strings.HasPrefix(arg, "-") && len(arg) == 2)):
			i++
		case arg != "" && !strings.HasPrefix(arg, "-"):
			return arg == "setup"
		}
	}
	return false
}

// PlainReadPattern returns plainReadRe's source. internal/mcp keeps a copy
// (it may not import this package); a test in internal/cli pins the two equal.
func PlainReadPattern() string {
	return plainReadRe.String()
}

// MatchSelfProtectCommand reports whether cmd matches a self-protection rule,
// with the same raw, dequoted and unset-param-folded readings SelfProtect
// uses. The MCP proxies apply it to command-text arguments on a managed host
// (#4337 review B1), so execute_command cannot do what the shell hook refuses.
// For a command past the chain bound, which no reading may parse (#4778), it
// reads the raw text only (MatchSelfProtectRawText), since the proxies call
// it outside any evaluation surface's guard, and a command the raw text does
// not match is ChainTooLongRuleID: past the bound every managed host BLOCKs
// (Gary, 2026-11-04), as the hook does, so the spellings only a parsing
// reading finds are not let through (#4823 Opus pass 1: 63 of 66 were).
func MatchSelfProtectCommand(cmd string) (ruleID string, matched bool) {
	if shellparse.GuardChainBound(cmd, func() { ruleID, matched = matchesSelfProtectRule(cmd) }) != nil {
		if ruleID, matched = MatchSelfProtectRawText(cmd); matched {
			return ruleID, true
		}
		return ChainTooLongRuleID, true
	}
	return ruleID, matched
}

// ChainTooLongRuleID is the rule id of a managed host's BLOCK of a command
// past the chain bound that no self-protection pattern matches as written
// (#4778, Gary 2026-11-04: past the chain bound, every managed host BLOCKs).
// No rule matched: the command was not parsed, so it names no taxonomy node.
const ChainTooLongRuleID = "enterprise-chain-too-long"

// MatchSelfProtectRawText reports whether the command AS WRITTEN matches a
// self-protection rule: each rule's pattern and exclusion on the raw text,
// and no reading that parses it (dequoted, unset-param-folded, zsh, the
// setup argv walk, the token scan). It is matchesSelfProtectRule's first
// reading, so a command it matches gets the rule id main gives it.
//
// It is what a managed host keeps for a command past the chain bound
// (#4778): no reading may parse that text, because walking the parser's tree
// for the chain overflows the stack, but these regexes need no parse, and
// main's middleware ran them on every command under its crash point. Not
// kept: the spellings only a parsing reading finds (a quote splice, an unset
// expansion, a zsh-only prefix, a reordered setup argv).
func MatchSelfProtectRawText(cmd string) (ruleID string, matched bool) {
	return matchSelfProtectText(cmd, cmd, func(string) bool { return false })
}

// SelfProtectRawText is SelfProtect reading the raw text only
// (MatchSelfProtectRawText), for a command past the chain bound (#4778). Its
// BLOCK is SelfProtect's, rule id and message alike.
func SelfProtectRawText() EvalMiddleware {
	return func(ctx *EvalContext, next func()) {
		if rule, matched := MatchSelfProtectRawText(ctx.Command); matched {
			ctx.Blocked = true
			ctx.BlockRule = rule
			ctx.BlockMsg = fmt.Sprintf("Blocked: attempt to modify AgentShield configuration (rule: %s)", rule)
			return
		}
		next()
	}
}

// SelfProtectRuleCount returns the number of active self-protection rules.
func SelfProtectRuleCount() int {
	return len(selfProtectRules)
}

// SelfProtectRuleIDs returns the id of every self-protection rule, in match
// order. The receipt's per-rule taxonomy table (internal/cli) ratchets against
// it: a rule added here without a mapped node or a written reason for having
// none fails that test (#4603).
func SelfProtectRuleIDs() []string {
	ids := make([]string, len(selfProtectRules))
	for i, r := range selfProtectRules {
		ids[i] = r.ID
	}
	return ids
}
