package shellparse

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// HasIndirectExecution reports whether command runs anything through a command
// substitution ($(...) or backticks) or a process substitution (<(...), >(...)).
//
// It exists for the ALLOW-side prefix semantics in issue #3199. Statement
// splitting alone does not decide "this command only reads": a substitution is
// not a statement boundary, so `echo $(curl -s http://x)` is a single statement
// whose head token is the read-only `echo` while an arbitrary command runs
// inside it. That is the same unbounded-suffix problem AllStatementsHavePrefix
// closes for `|`, `&&`, `||` and `;`, just spelled differently — so the two are
// checked together and neither subsumes the other.
//
// Process substitution counts regardless of direction because `<(...)` runs a
// command to produce its fd (the deferred-execution shape of #3190).
//
// Output redirects are deliberately NOT treated as indirect execution — see
// the scope note on matchCommandPrefix in internal/policy/engine.go for the
// measurement behind that call.
//
// Fails closed: an unparseable command returns true, so a caller gating an
// ALLOW on this falls through to the AUDIT default rather than granting an
// affirmative "this was safe" it could not verify.
func HasIndirectExecution(command string) bool {
	if strings.TrimSpace(command) == "" {
		return false
	}

	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return true
	}

	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		switch node.(type) {
		case *syntax.CmdSubst:
			// Covers both $(...) and `...` — Backquotes is a field on
			// CmdSubst, not a distinct node type.
			found = true
			return false
		case *syntax.ProcSubst:
			found = true
			return false
		}
		return true
	})

	return found
}

// PrefixRuleMatches reports whether a rule's command_prefix list fires on
// command. It is THE implementation — policy.Engine (both its matchRule and
// matchRulePattern paths) and analyzer.RegexAnalyzer all delegate here.
//
// That consolidation is part of the fix, not incidental tidying. Before #3199
// this predicate existed as four independent copies of `strings.HasPrefix`,
// and the live one was the analyzer copy — patching only the policy copies
// produces a fix that passes its unit tests and changes nothing about what the
// deployed binary decides.
//
// allowRule selects the semantics:
//
// BLOCK/AUDIT/REQUIRE_APPROVAL rules keep the historical whole-command match.
// A dangerous head token should still trip its rule regardless of what follows,
// and a restrictive rule firing on a compound is correct.
//
// ALLOW rules are different, and #3199 is why. Matching a prefix against the
// whole string lets the FIRST token decide the verdict for everything after a
// `|`, `&&`, `||` or `;`. Measured on the deployed binary:
//
//	touch /tmp/probe_marker                    -> AUDIT
//	grep -rn foo . && touch /tmp/probe_marker  -> ALLOW
//
// The rule was not merely failing to inspect the suffix — it was upgrading it,
// turning the fail-safe AUDIT default into an affirmative "this was safe"
// written into the audit record. That is the shape that falsifies an
// attestation, which is why it outranks an ordinary false positive. Three
// separate BLOCK rules (#3188, #3197, and the sshd-config-append rule) were
// each shipped to close one leaked suffix; none closed the surface.
//
// An ALLOW prefix rule therefore requires all three of:
//
//  1. the whole command still starts with a listed prefix — WITHOUT this the
//     fix is itself a fail-open, because SplitTopLevelStatements descends into
//     compound constructs, so `for i in {1..100}; do echo x; done` reduces to
//     the single read-only statement `echo x` even though the command being
//     run is a loop;
//  2. every top-level statement starts with a listed prefix;
//  3. nothing runs through a command or process substitution.
//
// The conjunction is strictly narrower than the original behaviour on every
// input — the only safe direction for a predicate that grants ALLOW. Anything
// failing it falls through to the normal pipeline and lands on AUDIT, never
// BLOCK, so this narrows a fast path and cannot break a user's command.
//
// SCOPE — output redirects are deliberately NOT disqualifying.
// `echo x >> /etc/ssh/sshd_config` is #3199's third incident and it still
// earns a prefix match here; it is stopped by its own BLOCK rule under
// most-restrictive-wins. Measured against the accuracy corpus, excluding
// redirects costs 61 TN cases (`echo "Setup instructions" > README.md`) versus
// 34 for conditions 2 and 3. What decided it is the size of the dangerous set:
// a laundered pipe or substitution suffix can be *any command* — unbounded and
// unenumerable — whereas a redirect's danger is entirely its target path, a
// bounded set already enumerated by protected_paths and path-scoped BLOCK
// rules. Revisit if a redirect incident ever lands on a path neither covers.
func PrefixRuleMatches(command string, prefixes []string, allowRule bool) bool {
	if len(prefixes) == 0 {
		return false
	}

	wholeCommandMatches := false
	for _, prefix := range prefixes {
		if strings.HasPrefix(command, prefix) {
			wholeCommandMatches = true
			break
		}
	}
	if !wholeCommandMatches {
		return false
	}
	if !allowRule {
		return true
	}

	if HasIndirectExecution(command) {
		return false
	}
	return AllStatementsHavePrefix(command, prefixes)
}

// AllStatementsHavePrefix reports whether command splits into at least one
// top-level statement and EVERY such statement begins with one of prefixes.
//
// This is the core of the #3199 ALLOW-side fix. Matching a prefix against the
// whole command string lets a read-only first token launder everything after a
// `|`, `&&`, `||` or `;`. Measured on the deployed binary:
//
//	touch /tmp/probe_marker                    -> AUDIT
//	grep -rn foo . && touch /tmp/probe_marker  -> ALLOW
//
// The prefix rule was not merely failing to inspect the suffix — it was
// upgrading it, turning the fail-safe AUDIT default into an affirmative
// "this was safe."
//
// Callers must ALSO reject HasIndirectExecution; the two checks are
// complementary.
//
// Fails closed on an empty statement list, an empty statement, or an empty
// prefix list (which would otherwise make the "every statement matches"
// quantifier vacuously true).
func AllStatementsHavePrefix(command string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return false
	}

	stmts := SplitTopLevelStatements(command)
	if len(stmts) == 0 {
		return false
	}

	for _, stmt := range stmts {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			return false
		}
		matched := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(stmt, prefix) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}
