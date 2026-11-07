package cli

import (
	"bytes"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
	"github.com/AI-AgentLens/agentshield/packs"
)

// A managed host's shell self-protection BLOCK (rule enterprise-self-protect)
// attests the taxonomy node of the sp-* rule that fired. It never attests one
// node for the whole middleware (#4603, Gary 2026-10-30). The rules guard
// different things: tampering with the tool, deleting its audit trail, and,
// for sp-block-config-touch, reads as well as writes. One node for all of them
// attested tampering for an audit-log delete and for a read of the policy
// (#4603 pass 1).
//
// Each node is written as a TaxonomyRef field set to a string literal, on
// purpose. scripts/check-taxonomy-refs.sh (CI's taxonomy-refs job) resolves
// exactly that spelling against Comply's taxonomy tree; a bare const is
// invisible to it (#4602).
//
// Evidence only: nothing here changes a decision, a rule id or a reason.

// selfProtectRuleTaxonomy maps each sp-* rule with one node to that node.
// Gary approved security-tool-tampering for each on 2026-10-30, and the pass-1
// reviewer confirmed it is true for every command each rule blocks.
// sp-block-binary-replace left this table for selfProtectTargetRules (#4670).
var selfProtectRuleTaxonomy = []struct {
	RuleID      string
	TaxonomyRef string
}{
	{RuleID: "sp-block-bypass-env", TaxonomyRef: "persistence-evasion/defense-evasion/security-tool-tampering"},
	{RuleID: "sp-block-setup-disable", TaxonomyRef: "persistence-evasion/defense-evasion/security-tool-tampering"},
	{RuleID: "sp-block-policy-write", TaxonomyRef: "persistence-evasion/defense-evasion/security-tool-tampering"},
	{RuleID: "sp-block-delete-hooks", TaxonomyRef: "persistence-evasion/defense-evasion/security-tool-tampering"},
	{RuleID: "sp-block-brew-uninstall", TaxonomyRef: "persistence-evasion/defense-evasion/security-tool-tampering"},
}

// The sp-* rules whose node depends on their target, not only on their id.
const (
	spDeleteConfigRule  = "sp-block-delete-config"
	spBinaryReplaceRule = "sp-block-binary-replace"
)

// selfProtectTargetRules maps each sp-* rule whose node depends on its target
// to the classifier that reads the target from the blocked command. Both cite
// spTargetTaxonomy's nodes. sp-block-binary-replace joined on 2026-10-30
// (Gary, #4670): a copy, move, link or install onto the audit log cited
// tampering, while a delete of the same file cited the audit-trail node.
var selfProtectTargetRules = map[string]func(command string) []string{
	spDeleteConfigRule:  deleteConfigTaxonomyRefs,
	spBinaryReplaceRule: binaryReplaceTaxonomyRefs,
}

// spTarget is the class of AgentShield path a blocked command acts on.
type spTarget uint8

const (
	spTargetConfig spTarget = 1 << iota // the binary, policy, enrollment, packs or other config
	spTargetLog                         // the audit trail
)

// spTargetTaxonomy is the node per target class, shared by
// selfProtectTargetRules and the harness file-write path
// (sp-block-config-tool-write, managed_tool_write.go). A command that names
// several targets attests each class's node once. A whole ~/.agentshield
// delete names both classes, because it removes the audit trail together with
// the policy that produces it.
var spTargetTaxonomy = []struct {
	Target      spTarget
	TaxonomyRef string
}{
	{Target: spTargetConfig, TaxonomyRef: "persistence-evasion/defense-evasion/security-tool-tampering"},
	{Target: spTargetLog, TaxonomyRef: "persistence-evasion/anti-forensics/ai-audit-trail-circumvention"},
}

// selfProtectUnattributed lists the sp-* rules that deliberately attest no
// node, each with the reason. A gap written down beats a guessed node, and
// TestSelfProtectEveryRuleIsMappedOrUnattributed keeps every rule in exactly
// one of these tables.
var selfProtectUnattributed = map[string]string{
	// sp-block-config-touch is a default-deny over command text. It blocks every
	// command that names the managed config files unless the command is a plain
	// read, so its BLOCKs mix reads (less, sed -n, cat $(…), grep | head) with
	// interpreter writes (python3 -c "open(…,'w')"). security-tool-tampering
	// is false for the reads; its own good example is "reading policy is safe".
	// Nothing today tells the two apart, so the rule attests nothing until it
	// can (#4666).
	"sp-block-config-touch": "reads and interpreter writes cannot be told apart today (#4666)",
}

// selfProtectTaxonomyRefs is the evidence for one shell self-protection BLOCK:
// the node or nodes of the sp-* rule ruleID, given the blocked command. It
// returns nil for an unattributed rule and for an id it does not know. An
// absent ref is better than a guessed one.
func selfProtectTaxonomyRefs(ruleID, command string) []string {
	if classify, ok := selfProtectTargetRules[ruleID]; ok {
		return classify(command)
	}
	for _, m := range selfProtectRuleTaxonomy {
		if m.RuleID == ruleID {
			return []string{m.TaxonomyRef}
		}
	}
	return nil
}

// spTargetRefs returns the node of each class in targets, once each, sorted.
func spTargetRefs(targets spTarget) []string {
	var refs []string
	for _, m := range spTargetTaxonomy {
		if targets&m.Target != 0 {
			refs = append(refs, m.TaxonomyRef)
		}
	}
	sort.Strings(refs)
	return refs
}

// The two community rules whose definitions sp-block-delete-config's receipt
// reuses, so a managed host and an unmanaged host agree on what a delete
// removes (Gary, 2026-10-30):
//   - auditLogDeleteRule's command_regex defines an audit-log target. On an
//     unmanaged host the same delete reaches that rule and cites
//     ai-audit-trail-circumvention.
//   - agentshieldDirDeleteRule's structural match defines the whole
//     directory: the delete verb (executable: rm) and the spellings of the
//     directory itself (args_any: ~, $HOME, ${HOME}, /Users/*, /home/*,
//     /root). A .agentshield directory anywhere else is not AgentShield's.
//
// sp-block-binary-replace's receipt and the harness file-write path reuse one
// more, for the same reason (#4670): auditLogOverwriteRule's command_regex
// carries the log-path set (audit.jsonl*, logs/**, any other *.jsonl under a
// home spelling of ~/.agentshield), the same set the delete and move community
// rules use. Testing `cp /dev/null <operand>` against it answers "is this
// operand the log?"; the receipt decides source vs destination itself (#4670
// pass-1 findings 1–3), so the move rule's whole-statement regex is not read.
//
// All of them are read from the community packs embedded in the binary, never
// from the disk packs, which an install may have edited or let go stale. None
// is copied into Go, so the definitions cannot drift apart as the rules
// evolve.
const (
	auditLogDeleteRule       = "ts-block-agentshield-log-delete"
	agentshieldDirDeleteRule = "ts-struct-block-agentshield-dir-delete"
	auditLogOverwriteRule    = "ts-block-agentshield-log-overwrite"
)

// embeddedCommunityRule returns the rule id from the shell packs embedded in
// the binary.
func embeddedCommunityRule(id string) (policy.Rule, bool) {
	files := packs.ShellFiles()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data := files[name]
		if !bytes.Contains(data, []byte(id)) {
			continue
		}
		var pack policy.Pack
		if err := yaml.Unmarshal(data, &pack); err != nil {
			continue
		}
		for _, r := range pack.Rules {
			if r.ID == id {
				return r, true
			}
		}
	}
	return policy.Rule{}, false
}

// auditLogPathSet is auditLogDeleteRule's command_regex. Nil when the rule is
// missing or has no command_regex. TestAuditLogPathSetComesFromCommunityPack
// fails the build in that case, and at runtime it means a delete attests no
// node.
var auditLogPathSet = sync.OnceValue(func() *regexp.Regexp {
	return embeddedCommandRegex(auditLogDeleteRule)
})

// auditLogOverwriteSet is auditLogOverwriteRule's command_regex. Nil when the
// rule is missing or has no command_regex; TestAuditLogOverwriteSetComesFromCommunityPack
// fails the build in that case, and at runtime it means the receipt keeps
// tampering.
var auditLogOverwriteSet = sync.OnceValue(func() *regexp.Regexp {
	return embeddedCommandRegex(auditLogOverwriteRule)
})

// embeddedCommandRegex is the compiled command_regex of the embedded
// community rule id, or nil.
func embeddedCommandRegex(id string) *regexp.Regexp {
	r, ok := embeddedCommunityRule(id)
	if !ok || r.Match.CommandRegex == "" {
		return nil
	}
	re, err := regexp.Compile(r.Match.CommandRegex)
	if err != nil {
		return nil
	}
	return re
}

// agentshieldDirSet is agentshieldDirDeleteRule's structural match, in the
// form the structural analyzer evaluates. Nil when the rule is missing, is
// not structural, or names no delete verb or no directory spelling.
// TestAgentshieldDirSetComesFromCommunityPack fails the build in that case,
// and at runtime it means a delete attests no node.
var agentshieldDirSet = sync.OnceValue(func() *analyzer.StructuralRule {
	r, ok := embeddedCommunityRule(agentshieldDirDeleteRule)
	if !ok || r.Match.Structural == nil {
		return nil
	}
	sm := r.Match.Structural
	if len(sm.Executable) == 0 || len(sm.ArgsAny) == 0 {
		return nil
	}
	return &analyzer.StructuralRule{
		ID:         r.ID,
		Decision:   string(r.Decision),
		Executable: []string(sm.Executable),
		SubCommand: sm.SubCommand,
		FlagsAll:   sm.FlagsAll,
		FlagsAny:   sm.FlagsAny,
		FlagsNone:  sm.FlagsNone,
		ArgsAny:    sm.ArgsAny,
		ArgsNone:   sm.ArgsNone,
	}
})

var (
	// spDirShapedWord names a directory called .agentshield, or everything in
	// one: …/.agentshield, …/.agentshield/ or …/.agentshield/*. Only the
	// spellings in agentshieldDirSet are AgentShield's directory. Any other
	// (/tmp/scratch-home/.agentshield) attests nothing, and in particular is
	// not read as a config path inside the directory.
	spDirShapedWord = regexp.MustCompile(`[~/]\.agentshield(?:/+\*?)?$`)
	// spInsideDirWord is a word that names something inside the directory.
	spInsideDirWord = regexp.MustCompile(`[~/]\.agentshield/.`)
)

// deleteConfigTaxonomyRefs classifies only the operands of the delete
// statements in the blocked command (Gary, 2026-10-30, #4603 fix round 2).
// sp-block-delete-config matches `rm\s+.*[~/]\.agentshield` over the command
// TEXT, so it also fires when the path is only mentioned: in another
// statement (`rm -f /tmp/x; cat <policy>`), in a redirect target, in a
// heredoc body, in an echo's arguments or in a comment. Those words are not
// deleted, and the receipt must not attest them.
//
// A delete statement is a simple command whose executable is the community
// directory rule's delete verb (rm, the same verb sp-block-delete-config
// matches), read with the structural analyzer's parse: wrappers such as sudo
// are seen through, unset-parameter splices are folded, and a statement
// inside a compound command or a $(…) / <(…) body counts, because it runs.
// A `bash -c` body is not parsed (pass-2 follow-up 1). Its operands are its
// positional arguments. Each operand is then:
//   - the directory itself, by agentshieldDirSet → both classes;
//   - any other directory called .agentshield, or its glob → nothing;
//   - a path the community log-delete rule protects (`rm <operand>` matches
//     its pattern) → log;
//   - any other path inside the directory → config.
//
// An operand of the form $(echo …) is read as the words the echo prints,
// which is what rm receives: `rm -rf $(echo x; echo <logs>)` is a TP of the
// community log rule. Any other substitution operand cannot be read and
// attests nothing. So does a quoted operand containing whitespace, which is
// prose, not a path.
//
// When the command does not parse as bash (a zsh-only splice, a syntax
// error), the delete statement cannot be identified and the receipt attests
// nothing. An absent ref is better than a guessed one.
func deleteConfigTaxonomyRefs(command string) []string {
	logSet := auditLogPathSet()
	dirSet := agentshieldDirSet()
	if logSet == nil || dirSet == nil {
		return nil
	}
	parsed := shellparse.Parse(command, 1)
	if parsed == nil || parsed.Fallback {
		return nil
	}
	var targets spTarget
	for _, seg := range deleteStatements(parsed, dirSet) {
		for _, arg := range seg.Args {
			targets |= deleteOperandTargets(seg, arg, dirSet, logSet)
		}
	}
	return spTargetRefs(targets)
}

// everyStatement returns the simple commands in parsed: the top-level
// statements, including those in compound commands, and those in every
// command or process substitution.
func everyStatement(parsed *shellparse.ParsedCommand) []shellparse.CommandSegment {
	segs := append([]shellparse.CommandSegment(nil), parsed.Segments...)
	for _, s := range parsed.Substitutions {
		if s.Parsed != nil {
			segs = append(segs, s.Parsed.Segments...)
		}
	}
	return segs
}

// deleteStatements returns the statements in parsed (everyStatement) that run
// the directory rule's delete verb.
func deleteStatements(parsed *shellparse.ParsedCommand, dirSet *analyzer.StructuralRule) []shellparse.CommandSegment {
	var out []shellparse.CommandSegment
	for _, seg := range everyStatement(parsed) {
		for _, verb := range dirSet.Executable {
			if seg.Executable == verb {
				out = append(out, seg)
				break
			}
		}
	}
	return out
}

// deleteOperandTargets classifies one operand arg of the delete statement seg.
func deleteOperandTargets(seg shellparse.CommandSegment, arg string, dirSet *analyzer.StructuralRule, logSet *regexp.Regexp) spTarget {
	if strings.Contains(arg, "$(") || strings.Contains(arg, "<(") || strings.Contains(arg, ">(") || strings.Contains(arg, "`") {
		var targets spTarget
		for _, word := range echoedWords(arg) {
			targets |= literalOperandTargets(seg, word, dirSet, logSet)
		}
		return targets
	}
	return literalOperandTargets(seg, arg, dirSet, logSet)
}

// literalOperandTargets classifies an operand that carries no substitution.
func literalOperandTargets(seg shellparse.CommandSegment, arg string, dirSet *analyzer.StructuralRule, logSet *regexp.Regexp) spTarget {
	words := shellWordsForTargets(arg)
	if len(words) != 1 {
		return 0
	}
	w := words[0]
	if strings.IndexFunc(w, unicode.IsSpace) >= 0 {
		return 0
	}
	// The directory rule judges the operand as the structural analyzer would
	// have: on this statement, with this one operand.
	one := seg
	one.Args = []string{arg}
	switch {
	case analyzer.MatchStructuralRule(&shellparse.ParsedCommand{Segments: []shellparse.CommandSegment{one}}, *dirSet):
		return spTargetConfig | spTargetLog
	case spDirShapedWord.MatchString(w):
		return 0
	case logSet.MatchString("rm " + w):
		return spTargetLog
	case spInsideDirWord.MatchString(w):
		return spTargetConfig
	}
	return 0
}

// echoedWords reads an operand that is exactly one $(…) (or a backquote
// substitution, which the parser prints the same way), optionally inside
// double quotes, whose body is only echo statements with no redirect and no
// substitution of their own. It returns the words those echoes print, which
// are the operands rm receives. It returns nil for anything else: that
// operand's value is not known here.
func echoedWords(arg string) []string {
	body := arg
	if len(body) >= 2 && body[0] == '"' && body[len(body)-1] == '"' {
		body = body[1 : len(body)-1]
	}
	if !strings.HasPrefix(body, "$(") || !strings.HasSuffix(body, ")") || strings.HasPrefix(body, "$((") {
		return nil
	}
	body = body[2 : len(body)-1]
	parsed := shellparse.Parse(body, 1)
	if parsed == nil || parsed.Fallback || len(parsed.Segments) == 0 ||
		len(parsed.Substitutions) > 0 || len(parsed.Redirects) > 0 {
		return nil
	}
	var words []string
	for _, seg := range parsed.Segments {
		if seg.Executable != "echo" || len(seg.Redirects) > 0 {
			return nil
		}
		words = append(words, seg.Args...)
	}
	return words
}

// shellWordsForTargets splits text into shell words with their quote
// characters and backslash escapes removed. It splits on unquoted whitespace
// and on the unquoted operators ; & | ( ) < > and backtick. The receipt calls
// it on one operand word, as the parser printed it, to read the path the
// shell passes to rm; more than one word back means the operand is not a
// plain path.
//
// It is not a shell parser and does not need to be. Its one job is to keep a
// quoted metacharacter inside its word, as in ~/.agentshield/'session;1.jsonl',
// which is a TP of the community log rule. Inside double quotes a backslash
// escapes the next character. Inside single quotes nothing does.
func shellWordsForTargets(s string) []string {
	var (
		words  []string
		b      strings.Builder
		inWord bool
		quote  rune
	)
	flush := func() {
		if inWord {
			words = append(words, b.String())
			b.Reset()
			inWord = false
		}
	}
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case quote == '\'':
			if r == '\'' {
				quote = 0
			} else {
				b.WriteRune(r)
			}
		case quote == '"':
			switch {
			case r == '"':
				quote = 0
			case r == '\\' && i+1 < len(rs):
				i++
				b.WriteRune(rs[i])
			default:
				b.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			inWord = true
		case r == '\\' && i+1 < len(rs):
			i++
			if rs[i] != '\n' { // a backslash-newline joins two lines
				b.WriteRune(rs[i])
				inWord = true
			}
		case unicode.IsSpace(r) || strings.ContainsRune(";&|()<>`", r):
			flush()
		default:
			b.WriteRune(r)
			inWord = true
		}
	}
	flush()
	return words
}

// binaryReplaceVerbs are sp-block-binary-replace's verbs, from its pattern
// (cp|mv|ln|install) in internal/enterprise/managed.go.
// TestBinaryReplaceVerbsReachTheRule holds the two lists together.
var binaryReplaceVerbs = []string{"cp", "mv", "ln", "install"}

// binaryReplaceTaxonomyRefs is sp-block-binary-replace's receipt, split by
// target the way sp-block-delete-config's is (Gary, 2026-10-30, #4670). A
// copy, move, link or install onto the audit log replaces the trail, which is
// ai-audit-trail-circumvention: the node a delete of the same file has cited
// since #4603. Every other target keeps security-tool-tampering.
//
// It reads the statements that run one of the rule's verbs (everyStatement,
// with the structural parse: wrappers such as sudo are seen through,
// unset-parameter splices are folded, and compound commands and substitution
// bodies count). The node is decided by WHICH OPERAND the write lands on, not
// by a whole-statement text match (#4670 pass 1: that match read the log as a
// destination under `-t`, read a source copied out, and matched a `..` operand
// by its text before it cleaned to a non-log path):
//   - cp/ln/install modify only the DESTINATION. That is the last operand, or
//     the directory named by -t/--target-directory (then every positional is a
//     read). A destination on a log path cites the log node; a destination
//     under ~/.agentshield that is not a log cites tampering; a copy-out or a
//     one-operand ln (the link is made in the cwd) names no AgentShield
//     destination and keeps main's node.
//   - mv removes every source and writes the destination, so every operand
//     that names an AgentShield path is modified: a log operand (moved onto or
//     away) cites the log node, anything else under ~/.agentshield cites
//     tampering. Moving the log away removes the trail as completely as a
//     delete does, and on an unmanaged host the community move rule cites the
//     same node (Gary's "destination" word, extended to the source by the
//     managed/unmanaged-agreement principle; the alternative is in the PR).
//
// Whether an operand is the log is asked of the community overwrite rule's
// path set (`cp /dev/null <operand>`), after `..`/`.`/`//` are cleaned out of
// the operand, so `logs/../policy.yaml` is the policy and `logs/../audit.jsonl`
// is the log. A log-named file copied INTO the .agentshield directory itself
// is classified by where it lands.
//
// When no statement writes an AgentShield path, the receipt keeps main's node,
// tampering. That covers a match on text the parse does not give to one of
// these statements (prose, a heredoc body, a `bash -c` body, a word such as
// `mcp` that contains a verb) and a command that does not parse as bash.
// Nothing here changes a decision.
func binaryReplaceTaxonomyRefs(command string) []string {
	return binaryReplaceTaxonomyRefsWith(command, auditLogOverwriteSet())
}

// binaryReplaceTaxonomyRefsWith is the body, with the log-path set injected so
// the absent-rule fallback is testable (#4670 pass 1, F2–F4). A nil set means
// the overwrite rule is missing from the embedded packs: every statement then
// falls through to tampering, never the log node.
func binaryReplaceTaxonomyRefsWith(command string, overwrite *regexp.Regexp) []string {
	var targets spTarget
	if overwrite != nil {
		if parsed := shellparse.Parse(command, 1); parsed != nil && !parsed.Fallback {
			for _, seg := range everyStatement(parsed) {
				targets |= replaceStatementTargets(seg, overwrite)
			}
		}
	}
	if targets == 0 {
		targets = spTargetConfig
	}
	return spTargetRefs(targets)
}

// replaceStatementTargets classifies one statement for
// binaryReplaceTaxonomyRefs. It returns 0 for a statement that runs none of
// the rule's verbs or writes no AgentShield path.
func replaceStatementTargets(seg shellparse.CommandSegment, overwrite *regexp.Regexp) spTarget {
	verb := ""
	for _, v := range binaryReplaceVerbs {
		// seg.Program sees through a path (/bin/cp); widening the receipt to it
		// cannot lower a decision, so a planted /tmp/evil/cp is at worst a
		// receipt the real cp would also have earned. Receipt-only.
		if seg.Program == v || seg.Executable == v {
			verb = v
			break
		}
	}
	if verb == "" || len(seg.Args) == 0 {
		return 0
	}
	ops := make([]replaceOperand, len(seg.Args))
	for i, arg := range seg.Args {
		ops[i] = classifyReplaceOperand(arg, overwrite)
	}

	dest, sources, ok := replaceDestination(seg, ops, overwrite)

	var t spTarget
	// The destination is modified by every verb. A directory destination takes
	// each source by where it lands (dest/<basename>); otherwise the
	// destination operand decides directly.
	if ok {
		if dest.dir {
			for _, src := range sources {
				if landingIsLog(dest, src, overwrite) {
					t |= spTargetLog
				} else {
					t |= spTargetConfig
				}
			}
			if t == 0 {
				t = spTargetConfig // a write into the directory with no readable source
			}
		} else {
			switch {
			case dest.log:
				t |= spTargetLog
			case dest.agentshield:
				t |= spTargetConfig
			}
		}
	}

	// mv removes its sources too, so a log moved away, or any other AgentShield
	// path moved away, is modified as well. When the destination is uncertain
	// (!ok) every operand is read as a source, which is mv's safe reading: a
	// move touches all of them. cp/ln/install sources are reads, so they add
	// nothing — an uncertain destination there keeps main's tampering.
	if verb == "mv" {
		srcs := sources
		if !ok {
			srcs = ops
		}
		for _, op := range srcs {
			switch {
			case op.log:
				t |= spTargetLog
			case op.agentshield:
				t |= spTargetConfig
			}
		}
	}
	return t
}

// replaceDestination returns the destination operand of a cp/mv/ln/install
// statement, the source operands, and whether a destination could be placed
// with certainty.
//
//   - -t/--target-directory names the destination directory: as a flag value
//     (`--target-directory=DIR`), or as the first positional (`-t DIR SRC…`).
//   - otherwise the destination is the last operand, and a statement with
//     fewer than two operands (a one-operand `ln`, which links into the cwd)
//     has none.
//
// Gary's 2026-10-31 conservative fallback (#4670 pass 2): when a `-t`-family
// option cannot be placed with certainty, return !ok, so a cp/ln/install
// receipt keeps main's tampering rather than guessing the log node. The parser
// files every character of a short cluster as a boolean flag and consumes no
// value (`-t/tmp` → {t,/,m,p}, `-gstaff` → {g,s,t,a,f}), keeps a quoted `'-t'`
// in Args, and keys a long option verbatim (`--target` is not
// `target-directory`). uncertainTargetOption reads the raw option words and
// treats any of those as uncertain.
func replaceDestination(seg shellparse.CommandSegment, ops []replaceOperand, overwrite *regexp.Regexp) (replaceOperand, []replaceOperand, bool) {
	if uncertainTargetOption(seg) {
		return replaceOperand{}, nil, false
	}
	if v, ok := seg.Flags["target-directory"]; ok && v != "" {
		return classifyReplaceOperand(v, overwrite), ops, true
	}
	_, shortT := seg.Flags["t"]
	_, longT := seg.Flags["target-directory"]
	if shortT || longT {
		if len(ops) == 0 {
			return replaceOperand{}, nil, false
		}
		return ops[0], ops[1:], true
	}
	if len(ops) < 2 {
		return replaceOperand{}, nil, false
	}
	return ops[len(ops)-1], ops[:len(ops)-1], true
}

// uncertainTargetOption reports whether the statement carries a `-t`-family
// option this parse cannot place, so the destination must not be guessed
// (#4670 pass 2). The only forms placed with certainty are an exact short
// `-t` word, `--target-directory`, and `--target-directory=VAL`.
//
//   - A raw short-option word (one leading `-`, unquoted) that contains `t` or
//     `T` and is not exactly `-t`: a cluster that jammed the directory on
//     (`-t/tmp`, `-rt/tmp/backup`), or that is a value-taking option whose
//     value happens to contain the letter (`install -gstaff`), or `-T` /
//     `-rT`.
//   - A long flag key that is a `target-directory` variant but not exact
//     (`--target`, `--target-dir`, `--no-target-directory`): GNU accepts
//     abbreviations, so it may be the target option and may consume the next
//     word.
//   - An operand that, with surrounding quotes removed, begins with `-` and is
//     not `-`/`--`: a quoted `'-t'` or `"--target-directory=/tmp"` that the
//     shell parser left in Args but the target program still reads as an
//     option.
func uncertainTargetOption(seg shellparse.CommandSegment) bool {
	for _, w := range strings.Fields(seg.Raw) {
		if len(w) < 2 || w[0] != '-' || strings.HasPrefix(w, "--") {
			continue
		}
		body := w[1:] // short cluster, e.g. "rt/tmp/backup", "gstaff", "t"
		if body != "t" && strings.ContainsAny(body, "tT") {
			return true
		}
	}
	for key := range seg.Flags {
		if len(key) > 1 && key != "target-directory" && strings.Contains(key, "target") {
			return true
		}
	}
	for _, arg := range seg.Args {
		if w := strings.Trim(arg, "'\""); strings.HasPrefix(w, "-") && w != "-" && w != "--" {
			return true
		}
	}
	return false
}

// landingIsLog reports whether the source src copied into the directory dest
// lands on a log path: dest/<basename of src>, tested against the community
// overwrite rule's path set, over every pair of their path forms so a quoted
// spelling is read the way the shell passes it (#4670 pass 2 finding 2). A
// source whose value is not known (an unreadable substitution) has no form and
// is not a log.
func landingIsLog(dest, src replaceOperand, overwrite *regexp.Regexp) bool {
	for _, df := range dest.forms {
		for _, sf := range src.forms {
			if overwrite.MatchString("cp /dev/null " + path.Join(df, path.Base(sf))) {
				return true
			}
		}
	}
	return false
}

// replaceOperand is what one operand of a cp/mv/ln/install statement names.
type replaceOperand struct {
	forms       []string // cleaned path spellings (quote-removed; ./..//' collapsed)
	log         bool     // some form is a log path, by the overwrite rule's set
	agentshield bool     // some form names agentshield
	dir         bool     // some form is the .agentshield directory, or its glob
}

// classifyReplaceOperand reads one operand as the words the shell passes: the
// operand itself, or, for an operand that is exactly one $(echo …), the words
// the echo prints (echoedWords). Any other substitution has no known value and
// names nothing. Each word is quote-removed and path-cleaned (so `..` resolves
// before the log set is consulted), then classified by the overwrite rule's
// set and by spelling.
func classifyReplaceOperand(arg string, overwrite *regexp.Regexp) replaceOperand {
	var op replaceOperand
	words := []string{arg}
	if strings.Contains(arg, "$(") || strings.Contains(arg, "<(") || strings.Contains(arg, ">(") || strings.Contains(arg, "`") {
		words = echoedWords(arg)
	} else if strings.Contains(arg, "agentshield") {
		op.agentshield = true
	}
	// A leading `~` inside quotes is a literal, not the home directory: bash
	// expands a tilde only when it is unquoted (#4670 pass 2, Gary's ruling).
	// So `'~/.agentshield/'` is a relative `~` directory in the cwd, not the
	// real log — its home-anchored log/dir readings are suppressed, and it
	// keeps tampering through the `agentshield` substring. The community
	// overwrite rule's own `["']?~` would read it as home, so this is the one
	// place a managed receipt deliberately differs from the unmanaged text
	// match, on the side of bash's real behaviour.
	literalTilde := strings.HasPrefix(arg, "'~") || strings.HasPrefix(arg, `"~`)
	seen := map[string]bool{}
	for _, w := range words {
		for _, f := range cleanedOperandForms(w) {
			if seen[f] {
				continue
			}
			seen[f] = true
			op.forms = append(op.forms, f)
			if strings.Contains(f, "agentshield") {
				op.agentshield = true
			}
			if literalTilde {
				continue
			}
			if overwrite.MatchString("cp /dev/null " + f) {
				op.log = true
			}
			if spDirShapedWord.MatchString(f) {
				op.dir = true
			}
		}
	}
	return op
}

// cleanedOperandForms returns the path spellings of one word to classify: the
// word with its quotes removed (so `au'd'it.jsonl` reads as the shell passes
// it), path-cleaned so a `..`/`.`/`//` segment resolves before the log set is
// consulted. A word that carries whitespace after quote removal is not a plain
// path and yields none.
func cleanedOperandForms(w string) []string {
	candidates := []string{}
	if strings.IndexFunc(w, unicode.IsSpace) < 0 {
		candidates = append(candidates, w)
	}
	if u := shellWordsForTargets(w); len(u) == 1 && u[0] != w && strings.IndexFunc(u[0], unicode.IsSpace) < 0 {
		candidates = append(candidates, u[0])
	}
	var out []string
	for _, c := range candidates {
		out = append(out, path.Clean(c))
	}
	return out
}
