package shellparse

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// isPrefixWordByte reports whether b is a character a shell treats as part of
// an unquoted token — the classic \b word-character class (alnum + '_').
// Hyphens, dots, slashes and whitespace are all boundaries.
func isPrefixWordByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// hasPrefixWithBoundary reports whether s starts with prefix AND the prefix
// ends on a token boundary — either prefix already ends on a non-word
// character (e.g. the trailing space in "grep "), or s ends exactly there, or
// the character in s immediately following prefix is not a word character.
//
// This exists for #3534: bare strings.HasPrefix lets an allowlisted token
// match as a substring of an unrelated program name. `ls` is a prefix of
// `lsyncd`; an attacker only has to name a script `lsyncd-payload.sh` to
// launder it past ts-allow-readonly's command_prefix ALLOW. Empirically:
// `lsyncd /etc/lsyncd.conf` (unrelated daemon), `pwdx 1234`, `idmapd -f`,
// `dfu-util -D firmware.bin`, `freeradius -X`, `dumpe2fs /dev/disk1` all
// resolved ALLOW via bare prefixes ls/pwd/id/df/free/du before this fix.
//
// Prefixes that already end in a space ("grep ", "cat ") are unaffected —
// their trailing space already supplies the boundary, which is why the
// original 35-entry ts-allow-readonly list only leaked on its 19 bare
// entries (the space-terminated half's boundary was supplied by hand).
func hasPrefixWithBoundary(s, prefix string) bool {
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	if prefix == "" {
		return false
	}
	if !isPrefixWordByte(prefix[len(prefix)-1]) {
		return true
	}
	if len(s) == len(prefix) {
		return true
	}
	return !isPrefixWordByte(s[len(prefix)])
}

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
// An output redirect is not indirect execution — nothing extra runs — and is
// reported separately by HasFileWriteRedirect. PrefixRuleMatches rejects both
// (#4082); keeping them apart keeps each predicate's name true.
//
// Fails closed: an unparseable command returns true, so a caller gating an
// ALLOW on this falls through to the AUDIT default rather than granting an
// affirmative "this was safe" it could not verify.
func HasIndirectExecution(command string) bool {
	indirect, _ := scanAllowDisqualifiers(command)
	return indirect
}

// HasFileWriteRedirect reports whether any statement in command — at any
// depth, including inside a group, subshell or loop body — carries a
// redirect that can write to a file (#4082).
//
// It exists for the ALLOW-side prefix semantics. `echo`, `cat`, `printf`,
// `grep`, `head` and the rest of ts-allow-readonly's list only read while
// their output stays on the inherited stdout/stderr. One redirect later,
// `echo '<anything>' >> ~/.zshenv` is an arbitrary-content file write, and the
// prefix ALLOW used to vouch for it — below the AUDIT default — whenever no
// other rule happened to name the destination.
//
// Harmless, and therefore NOT reported:
//
//   - input: `<`, heredocs, here-strings;
//   - output to a literal /dev/null, /dev/stdout or /dev/stderr (quote
//     removal applied; any expansion, escape or other spelling counts as a
//     write — the exemption is the direction that keeps an ALLOW, so it
//     must be exact, not "looks like");
//   - descriptor duplication onto stdout, stderr or a close (`2>&1`, `>&2`,
//     `>&-`) and any `<&` that duplicates onto stdin. A duplicate onto any
//     other number (`>&4`, `1<&4`) writes wherever the parent left that
//     descriptor, which the command never opened, so it counts as a write
//     (the same line st-allow-dd-to-file draws — dd_allow_gate.go, #3997).
//
// Everything else is reported: `>`, `>>`, `>|`, `&>`, `&>>`, `n>` to a path,
// `<>` (opens read-write, creating the file), and bash's `>&word` with a
// non-numeric word (the same write as `&>word`). A redirect operator this
// function does not know is reported too.
//
// Fails closed: an unparseable command returns true.
func HasFileWriteRedirect(command string) bool {
	_, write := scanAllowDisqualifiers(command)
	return write
}

// AllowDisqualified reports whether command, as written, must never be
// vouched for by an ALLOW prefix rule: it executes something indirectly or
// redirects output to a file. PrefixRuleMatches asks this of whatever text it
// is handed. A caller that ALSO tries a rule against rewritten forms of the
// command (line-continuation joins, ${V:-default} folds, brace expansion) must
// ask it of the raw command first and withhold the ALLOW on every form when
// it answers true, because a rewrite can drop or neutralise a redirect bash
// still performs. #4088 pass 1 (Opus review), each ALLOW before this:
// `echo x > ${X:-/dev/null}` folds to a /dev/null target; an escaped
// backslash before a newline is joined as a continuation and takes the next
// line's `>` with it; `>> {f,/dev/null}` expands to a /dev/null alternative.
// Deciding once on the raw text errs toward withholding the ALLOW, never
// toward granting it.
func AllowDisqualified(command string) bool {
	indirect, write := scanAllowDisqualifiers(command)
	return indirect || write
}

// scanAllowDisqualifiers parses command once and reports the two things that
// stop an ALLOW prefix rule from vouching for it beyond its statement heads:
// indirect execution (see HasIndirectExecution) and a file-writing redirect
// (see HasFileWriteRedirect). One parse serves both because PrefixRuleMatches
// needs both on every ALLOW candidate, and a large heredoc should not be
// parsed twice to answer one question.
//
// A blank command reports neither; an unparseable one reports both.
func scanAllowDisqualifiers(command string) (indirect, write bool) {
	if strings.TrimSpace(command) == "" {
		return false, false
	}

	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return true, true
	}

	syntax.Walk(file, func(node syntax.Node) bool {
		if indirect && write {
			return false
		}
		switch n := node.(type) {
		case *syntax.CmdSubst:
			// Covers both $(...) and `...` — Backquotes is a field on
			// CmdSubst, not a distinct node type.
			indirect = true
		case *syntax.ProcSubst:
			indirect = true
		case *syntax.Redirect:
			if redirectMayWriteFile(n) {
				write = true
			}
		}
		return true
	})

	return indirect, write
}

// harmlessOutputTargets are the only literal paths an output redirect may
// name and still leave a command read-only. Each is the inherited stream or
// the null device — no file on disk changes.
var harmlessOutputTargets = map[string]bool{
	"/dev/null":   true,
	"/dev/stdout": true,
	"/dev/stderr": true,
}

// redirectMayWriteFile is the per-redirect half of HasFileWriteRedirect. It
// is written as an allowlist of the harmless forms so that an operator it
// does not recognise counts as a write.
func redirectMayWriteFile(r *syntax.Redirect) bool {
	switch r.Op {
	case syntax.RdrIn, syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
		// Input. `1<file` opens the file read-only, so even an input
		// redirect onto stdout cannot write it.
		return false
	case syntax.DplIn:
		// `<&M` onto stdin reads. `N<&M` for any other N is an output
		// duplicate in disguise (bash implements both as dup2), so it
		// gets the DplOut test.
		if r.N == nil || r.N.Value == "0" {
			return false
		}
		return !isInheritedStreamFd(r.Word)
	case syntax.DplOut:
		// `>&/dev/null` is bash's older spelling of `&>/dev/null`: with a
		// non-numeric word it redirects both streams to that path. It gets
		// the same harmless-target exemption, or the two spellings of one
		// operation would disagree (#4088 pass 1, F3).
		if v, ok := staticRedirectTarget(r.Word); ok && harmlessOutputTargets[v] {
			return false
		}
		return !isInheritedStreamFd(r.Word)
	default:
		// >, >>, >|, &>, &>>, <> and anything newer: a write unless the
		// target is literally the null device or an inherited stream.
		v, ok := staticRedirectTarget(r.Word)
		return !ok || !harmlessOutputTargets[v]
	}
}

// isInheritedStreamFd reports whether a duplication target is stdout, stderr
// or a close — the descriptors every harness hands a command, which is the
// one destination treated as trusted. `>&word` with a non-numeric word is a
// file write in bash and falls out as false here too.
func isInheritedStreamFd(w *syntax.Word) bool {
	v, ok := staticRedirectTarget(w)
	return ok && (v == "1" || v == "2" || v == "-")
}

// staticRedirectTarget returns a redirect word's value after quote removal
// when it is built only from literal and quoted-literal parts. An unquoted
// literal keeps any backslash verbatim, so `/dev/nu\ll` does not compare
// equal to /dev/null — an unusual spelling loses the exemption rather than
// earning it.
func staticRedirectTarget(w *syntax.Word) (string, bool) {
	if w == nil || len(w.Parts) == 0 {
		return "", false
	}
	return literalWordValue(w)
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
// An ALLOW prefix rule therefore requires all four of:
//
//  1. the whole command still starts with a listed prefix — WITHOUT this the
//     fix is itself a fail-open, because SplitTopLevelStatements descends into
//     compound constructs, so `for i in {1..100}; do echo x; done` reduces to
//     the single read-only statement `echo x` even though the command being
//     run is a loop;
//  2. every top-level statement starts with a listed prefix;
//  3. nothing runs through a command or process substitution;
//  4. no statement, at any depth, redirects output to a file (#4082, see
//     HasFileWriteRedirect for what counts).
//
// #3534 sharpened (1) and (2): "starts with" is boundary-aware on the ALLOW
// path, not a bare strings.HasPrefix. `ls` is a substring-prefix of `lsyncd`,
// `pwd` of `pwdx`, `id` of `idmapd`, `df` of `dfu-util` — every one of the 19
// bare (non-space-terminated) entries in ts-allow-readonly had this gap, and
// the attacker only needs to name a script accordingly. hasPrefixWithBoundary
// requires the match to end on a non-word character or end-of-string.
//
// The conjunction is strictly narrower than the original behaviour on every
// input — the only safe direction for a predicate that grants ALLOW. Anything
// failing it falls through to the normal pipeline and lands on AUDIT, never
// BLOCK, so this narrows a fast path and cannot break a user's command.
//
// Condition 4 — output redirects — was deliberately out of scope under #3199.
// The reasoning then: a redirect's danger is entirely its target path, a
// bounded set already enumerated by protected_paths and path-scoped BLOCK
// rules, so the 61 accuracy-corpus TNs it would cost (`echo "Setup
// instructions" > README.md`) bought nothing. The note ended "revisit if a
// redirect incident ever lands on a path neither covers". #4082 is that
// incident: `echo '<a BLOCK rule's TP text>' >> ~/.zshenv` earned ALLOW on
// the deployed binary, because no rule names ~/.zshenv as a destination and
// the default policy protects no paths at all. The premise fails twice over —
// echo/printf/cat write ATTACKER-CHOSEN content, and the set of paths where
// arbitrary content does harm (startup files, config read by any daemon,
// anything a later step executes) is not the set any rule enumerates.
//
// Measured when condition 4 landed: 64 of 6,832 accuracy-corpus cases change
// decision, all TN, all ALLOW -> AUDIT; no TP changes and nothing moves to
// BLOCK. The dangerous set here is not enumerable, so the ALLOW is withheld
// rather than a destination list grown — and withholding it denies nothing:
// the command falls to other rules, else the default decision.
func PrefixRuleMatches(command string, prefixes []string, allowRule bool) bool {
	if len(prefixes) == 0 {
		return false
	}

	// #3534: the whole-command check is boundary-aware ONLY on the ALLOW path.
	// BLOCK/AUDIT prefix rules deliberately keep the historical bare substring
	// match here — narrowing them is a separate, separately-measured change
	// (see the issue's scoping decision); a dangerous head token should still
	// trip its rule even when boundary-matching would (correctly, for ALLOW)
	// refuse it, e.g. `sec-audit-env-dump`'s `set` prefix firing on `setpriv`.
	matchPrefix := strings.HasPrefix
	if allowRule {
		matchPrefix = hasPrefixWithBoundary
	}

	wholeCommandMatches := false
	for _, prefix := range prefixes {
		if matchPrefix(command, prefix) {
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

	if indirect, write := scanAllowDisqualifiers(command); indirect || write {
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
//
// Per-statement matching is boundary-aware (#3534) for the same reason the
// whole-command check in PrefixRuleMatches is: this function is only ever
// reached on the ALLOW path (PrefixRuleMatches calls it after allowRule is
// already established), so there is no BLOCK/AUDIT semantics to preserve
// here. Without it, `ls -la && lsyncd /etc/lsyncd.conf` would pass — every
// "statement" starts with `ls` as a bare substring even though the second
// statement runs an unrelated daemon.
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
			if hasPrefixWithBoundary(stmt, prefix) {
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
