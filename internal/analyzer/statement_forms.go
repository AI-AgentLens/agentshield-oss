package analyzer

import (
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// StatementFoldContext carries the whole-command facts a single statement
// cannot see for itself, so a fold that a SIBLING statement's assignment
// invalidates is not invented.
//
// Two of the rewrites below resolve shell parameters, and bash resolves those
// against the whole shell rather than one statement:
//
//	IFS=; : cmd${IFS}--flag ; git commit -m "...cmd --flag..."
//	x=:;  ${x:-cmd} --flag  ; git commit -m "...cmd --flag..."
//
// With an empty IFS the first runs `: cmd--flag`; with x=: the second runs
// `: --flag`. Neither is the invocation a rule matching "cmd --flag" is
// written against. The whole-command normalizers already refuse both — one
// bails on any `IFS=`, the other skips names assignedNames() found — but
// handed one statement in isolation they see no assignment and fold anyway,
// which turned a correct AUDIT into a false BLOCK once the folds started
// feeding ATTRIBUTION as well as matching (found by adversarial review of
// #3724).
//
// A nil *StatementFoldContext means "no context": every fold allowed, no
// symbol table. That is the pre-#3717 behaviour and is what tests that care
// only about the lexical rewrites should pass.
type StatementFoldContext struct {
	// ExecSyms resolves one level of indirect executable naming, built from
	// the WHOLE raw command because a defining "NAME=value" assignment
	// routinely lives in a different statement from the "$NAME ..." use site
	// (#3089).
	ExecSyms *shellparse.ExecSymbols
	// IFSReassigned is true when the whole command assigns IFS anywhere.
	IFSReassigned bool
	// AssignedNames holds every name assigned anywhere in the whole command.
	AssignedNames map[string]bool
}

// NewStatementFoldContext builds the context for one whole command. Callers
// build it once per evaluation and reuse it for every statement — it costs
// two AST parses.
func NewStatementFoldContext(command string) *StatementFoldContext {
	ifsReassigned, assigned := shellparse.CommandAssignmentContext(command)
	return &StatementFoldContext{
		ExecSyms:      shellparse.BuildExecSymbolTable(command),
		IFSReassigned: ifsReassigned,
		AssignedNames: assigned,
	}
}

func (fc *StatementFoldContext) execSymbols() *shellparse.ExecSymbols {
	if fc == nil {
		return nil
	}
	return fc.ExecSyms
}

func (fc *StatementFoldContext) ifsReassigned() bool {
	return fc != nil && fc.IFSReassigned
}

func (fc *StatementFoldContext) assignedNames() map[string]bool {
	if fc == nil {
		return nil
	}
	return fc.AssignedNames
}

// StatementMatchCandidates returns every text shape a single top-level shell
// statement can legitimately be matched in: as written, with quote artifacts
// removed, with ${IFS}/$IFS word-splitting separators collapsed to a literal
// space, with unset-parameter splices folded away, with constant assignments
// materialized, with prefixes/exec-wrappers that do not change which command
// runs peeled off, with code carried inside `bash -c '...'`/`eval`/heredoc
// bodies extracted, and with one level of indirect-executable resolution
// applied. candidates[0] is always stmt itself, so a caller can treat the
// result as "the raw text, plus every equivalent rendering of it".
//
// fc carries the whole-command context — see StatementFoldContext. Pass nil
// for "no context": indirect-executable resolution is skipped and every fold
// is allowed.
//
// # Why this is a package-level function and not a closure (#3717)
//
// It has two consumers that MUST agree:
//
//  1. RegexAnalyzer.Analyze's per-statement retry, which decides whether a
//     rule fires AT ALL.
//  2. The per-statement predicate handed to IntentExcludedForStatements by
//     command_intent_exclude / command_intent_downgrade — on both the
//     pipeline path here and the regex-fallback path in policy.Engine —
//     which decides WHICH statement a match is attributed to.
//
// Until #3717 only (1) folded; (2) tested each statement with the plain
// matcher against raw text. So in a compound command pairing an obfuscated
// real invocation with an unobfuscated doc-text sibling that happens to
// repeat the same pattern verbatim, the real statement did not count as
// matching and was skipped during attribution, leaving the doc-text sibling
// as the only statement counted — carrying the whole downgrade decision and
// turning an executed BLOCK into AUDIT. A fail-open: the attestation records
// "no violation" for a statement that ran.
//
// Callers are expected to memoize per statement for the duration of one
// evaluation — this costs several AST parses, and the ~176 rules carrying
// intent labels all re-test the same handful of statements.
func StatementMatchCandidates(stmt string, fc *StatementFoldContext) []string {
	if stmt == "" {
		return nil
	}
	execSyms := fc.execSymbols()
	var candidates []string
	seen := map[string]bool{}

	// normIFS / normUnset are the two folds a SIBLING statement's assignment
	// can invalidate — see StatementFoldContext. Everything else in this
	// function is a purely lexical rewrite of the statement's own text
	// (dequoting, line-continuation joining, prefix/wrapper stripping,
	// carrier-body extraction), which no outer assignment can make wrong.
	//
	// They return "" — the no-op sentinel every normalizer here uses — rather
	// than the input, so a refused fold adds no candidate at all instead of a
	// duplicate.
	normIFS := func(s string) string {
		if fc.ifsReassigned() {
			return ""
		}
		return shellparse.NormalizeIFS(s)
	}
	normUnset := func(s string) string {
		return shellparse.NormalizeUnsetParamExpInContext(s, fc.assignedNames())
	}

	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		candidates = append(candidates, s)
		// Fold unset-parameter expansions on the way IN, so every peel
		// below gets it for free — the splice can hide inside whatever a
		// peel extracts, not just in the statement the peel started from.
		// `trap 'cat /${zqx}etc/shadow' EXIT` is the case that forced
		// this: InlineCodeFragments recovers the trap body, and the body
		// still carries the splice. Doing it here rather than at each peel
		// site means a peel added later cannot forget it. Non-recursive on
		// purpose — folding is idempotent, so the second fold of a folded
		// form returns the "" no-op sentinel anyway.
		if folded := normUnset(s); folded != "" && !seen[folded] {
			seen[folded] = true
			candidates = append(candidates, folded)
		}
		// Same reasoning, for split-concat assignments (#3249): a carrier
		// body can itself contain "p=id_rsa; cat ~/.ssh/$p" — the literal
		// a rule is written against never appears in ITS text either,
		// same as ctx.RawCommand's own split-concat case the
		// wholeCommandForms pass already folds (line ~310). That pass
		// only walks ctx.RawCommand and its whole-command forms, never a
		// fragment recovered from inside a carrier, so a rule needing
		// this fold saw nothing when the split-concat assignment was
		// delivered through eval/bash -c/trap instead of written
		// directly (#3321).
		if materialized := shellparse.MaterializeAssignments(s); materialized != "" && !seen[materialized] {
			seen[materialized] = true
			candidates = append(candidates, materialized)
		}
	}

	// addInlineCodeForms registers the code carried inside `bash -c '...'`,
	// `eval '...'`, `trap '...' EXIT`, a shell heredoc body and friends
	// (#3050/#3059/#3081), in every shape a peel can expose.
	//
	// It exists as ONE function because there are two call sites — the
	// statement as written, and the statement after its executable has been
	// resolved through one level of indirection (#3089) — and they had
	// drifted. The `s` site peeled leading assignments off a recovered
	// fragment; the `resolved` site did not; neither peeled an exec
	// wrapper. So `bash -c 'env dd if=/dev/zero of=/dev/sda'` handed the
	// ^-anchored dd rule a fragment still beginning with `env`, and
	// `x=bash; $x -c 'env dd ...'` was a second, independent instance of
	// the same omission.
	//
	// That gap pre-dates #3221 — `env` is the oldest entry in the wrapper
	// table, and #3057 peels wrappers off a STATEMENT — it simply had no
	// witness, because no corpus TP was wrapper-prefixed until #3221 added
	// some. Wrapping those in a carrier composed the two features for the
	// first time and three carrier parity sweeps went over budget at once.
	//
	// Keeping the peels here rather than in add() confines the parse cost
	// to commands that actually carry inline code. Keeping them in one
	// function is what stops the next peel from being added to one call
	// site and not the other.
	// It recurses because a carrier body is very often another carrier:
	// `bash <<EOF ... bash -c 'dd if=/dev/zero of=/dev/sda' ... EOF`,
	// `bash <<EOF ... su -c 'rm -rf /' ... EOF`, heredoc-wrapped `eval`.
	// One level of extraction leaves the ^-anchored rule looking at
	// `bash -c '...'`, which it does not match. This is the "double-wrapped
	// payload" residual #3081 recorded and attributed to maxParseDepth's
	// default of 2 — true for the AST layers, but the regex layer's own
	// extraction was simply not recursive, and that half is fixable here
	// without touching the parse depth every analyzer shares.
	//
	// Depth is capped at maxInlineCodeNesting rather than left to terminate
	// naturally on "no carrier found". Termination is not in doubt — a
	// fragment with no inline code yields none — but the cost is
	// multiplicative per level and an adversarial input can nest carriers
	// as deep as it likes.
	const maxInlineCodeNesting = 3
	var addInlineCodeForms func(text string, depth int)
	addInlineCodeForms = func(text string, depth int) {
		if depth > maxInlineCodeNesting {
			return
		}
		for _, frag := range shellparse.InlineCodeFragments(text) {
			add(frag)
			add(normIFS(frag))
			if fs := shellparse.StripCommandPrefixes(frag); fs != "" {
				add(fs)
				add(normIFS(fs))
			}
			if fw := shellparse.StripExecWrapperPrefix(frag); fw != "" {
				add(fw)
				add(shellparse.DequoteCommand(fw))
				add(normIFS(fw))
			}
			// A fragment can itself be a bare indirection — `eval "$zc"`
			// and `bash -c "$zc"` both recover the fragment "$zc" above,
			// unresolved, when zc is a constant scalar assigned earlier in
			// the raw command. ResolveIndirectExecutable already resolves
			// exactly this shape for a plain STATEMENT (#3089); it was
			// never called on a fragment recovered from a carrier's BODY,
			// so the two features — carrier-body extraction and indirect-
			// executable resolution — never composed (#3238). Both halves
			// independently produce the right answer; only the call was
			// missing, so this mirrors the peels above rather than adding
			// a new mechanism.
			if resolved := shellparse.ResolveIndirectExecutable(frag, execSyms); resolved != "" {
				add(resolved)
				add(shellparse.DequoteCommand(resolved))
				add(normIFS(resolved))
				if fs := shellparse.StripCommandPrefixes(resolved); fs != "" {
					add(fs)
					add(normIFS(fs))
				}
				if fw := shellparse.StripExecWrapperPrefix(resolved); fw != "" {
					add(fw)
					add(shellparse.DequoteCommand(fw))
					add(normIFS(fw))
				}
				// The resolved value is the scalar's whole runtime text,
				// which is very often a COMPOUND command ("if true; then
				// rm -rf /; fi") rather than a single simple one — the
				// scalar carries whatever the attacker assigned it, same
				// as ctx.RawCommand itself can be compound. Splitting it
				// the same way the top-level command is split (#3045) is
				// what lets an anchored rule see "rm -rf /" as its own
				// statement instead of only the unmatchable "if true;
				// then rm -rf /; fi" blob. Deliberately NOT re-entering
				// addStatementForms here (its own call back into
				// addInlineCodeForms would make this mutually recursive
				// with no combined depth limit) — this is one bounded
				// pass of the cheap peels only, not the full arsenal.
				for _, sub := range shellparse.SplitSequencedStatements(resolved) {
					sub = strings.TrimRight(sub, " \t\n;")
					if sub == "" || sub == resolved {
						continue
					}
					add(sub)
					add(shellparse.DequoteCommand(sub))
					add(normIFS(sub))
				}
				addInlineCodeForms(resolved, depth+1)
			}
			addInlineCodeForms(frag, depth+1)
		}
	}

	// addStatementForms registers every text shape a single statement can
	// legitimately be matched in: as written, with quote artifacts removed,
	// with ${IFS}/$IFS word-splitting separators collapsed to a literal
	// space (#3044 — a bare ${IFS} default-whitespace substitution
	// defeated 68% of BLOCKing commands corpus-wide, the largest single
	// bypass class found in this codebase), and with prefixes that do not
	// change which command runs peeled off.
	addStatementForms := func(s string) {
		add(s)
		// A whole-word brace group ("{env,dd,if=/dev/zero,of=/dev/sda}")
		// can BE the prefix-plus-command shape the peels below exist to
		// see through — StripCommandPrefixes/StripExecWrapperPrefix look
		// for a literal "NAME=value "/"env "/"! " token at the START of
		// the text, which a brace group hides entirely (it is one token,
		// no spaces, until expanded). Expand up front, replacing the
		// working statement, so every peel below runs against the
		// corrected text the same way it already runs against the raw
		// one (issue #3217).
		if expanded := shellparse.NormalizeBraceWordList(s); expanded != "" {
			s = expanded
			add(s)
		}
		dequoted := shellparse.DequoteCommand(s)
		add(dequoted)
		ifsNormalized := normIFS(s)
		add(ifsNormalized)
		// Composed forms, both orders: a quote-splice AND an ${IFS}
		// separator can coexist in the same statement
		// ("cat${IFS}~/.gi'thub'/creden'tials'"), and each transform
		// alone leaves the other artifact standing. Order matters here —
		// DequoteCommand bails on any word containing a ParamExp
		// (dynamic content), so "cat${IFS}~/.gi'thub'/creden'tials'"
		// dequotes to "" (the $IFS glues the whole thing into one
		// unresolvable word) until IFS is normalized FIRST, splitting it
		// into a separate, now purely-static, quoted word.
		if dequoted != "" {
			add(normIFS(dequoted))
		}
		if ifsNormalized != "" {
			add(shellparse.DequoteCommand(ifsNormalized))
		}
		// An unset-parameter splice inside this statement
		// ("r${zqx}m -rf /", "${zqx:-dd} if=/dev/zero of=/dev/sda").
		// Composed with dequoting in that order only: DequoteCommand
		// bails on any word holding a ParamExp, so the splice has to go
		// first for a statement carrying both.
		if folded := normUnset(s); folded != "" {
			add(folded)
			add(shellparse.DequoteCommand(folded))
			add(normIFS(folded))
		}

		// Leading env assignments and "!" negation sit BEFORE the command
		// word and do not change which command runs, but they defeat every
		// "^"-anchored rule (#3048). Note this applies even when the command
		// is a SINGLE statement equal to ctx.RawCommand — "LC_ALL=C dd
		// if=/dev/zero of=/dev/sda" has nothing to split, yet still needs
		// its stripped form checked.
		if stripped := shellparse.StripCommandPrefixes(s); stripped != "" {
			add(stripped)
			add(shellparse.DequoteCommand(stripped))
			add(normIFS(stripped))
		}

		// Code carried inside `bash -c '...'` / `sh -c "..."` (#3050). The
		// structural analyzer can see in there once the fragment is
		// dequoted, but regex anchors still only see "bash -c ...", so
		// `bash -c "dd if=/dev/zero of=/dev/sda"` kept missing the
		// ^-anchored dd rule.
		addInlineCodeForms(s, 1)

		// An execution wrapper is the same shape of prefix: `env`, `exec`,
		// `nohup`, `timeout 10` and friends do not change WHICH command
		// runs, but they defeat anchored rules exactly as an assignment
		// does. The AST layers have seen through wrappers for a while; the
		// regex layer had no equivalent, leaving a hard 11.1% floor (#3057).
		if unwrapped := shellparse.StripExecWrapperPrefix(s); unwrapped != "" {
			add(unwrapped)
			add(shellparse.DequoteCommand(unwrapped))
			add(normIFS(unwrapped))
		}

		// A statement's own executable can be named through one level of
		// indirection — "x=dd; $x if=/dev/zero of=/dev/sda" or "$(echo dd)
		// if=/dev/zero of=/dev/sda" run exactly "dd if=/dev/zero
		// of=/dev/sda" (#3089). The AST layer already resolves this via
		// shellparse.Parse's own symbol table; execSyms is built once from
		// ctx.RawCommand (where the defining assignment lives, even when
		// it's a separate preceding statement) and reused for every
		// candidate here.
		if resolved := shellparse.ResolveIndirectExecutable(s, execSyms); resolved != "" {
			add(resolved)
			add(shellparse.DequoteCommand(resolved))
			add(normIFS(resolved))
			if stripped := shellparse.StripCommandPrefixes(resolved); stripped != "" {
				add(stripped)
			}
			// The wrapper/carrier ITSELF can be the thing delivered
			// indirectly — "x=env; $x dd if=/dev/zero of=/dev/sda" or
			// "x=bash; $x -c 'dd if=/dev/zero of=/dev/sda'" — so re-run the
			// same wrapper-stripping and inline-code extraction used for
			// the plain statement `s` against the newly-resolved text too;
			// otherwise composing indirection with an already-covered
			// carrier (env/nice/timeout, bash -c, eval, trap) reopens the
			// exact gap those carriers' own fixes closed (#3057, #3050,
			// #3059/#3084), one level removed (#3089).
			if unwrapped := shellparse.StripExecWrapperPrefix(resolved); unwrapped != "" {
				add(unwrapped)
				add(shellparse.DequoteCommand(unwrapped))
				add(normIFS(unwrapped))
			}
			addInlineCodeForms(resolved, 1)
		}

		// Re-run the prefix/inline-code/wrapper peels against the
		// ${IFS}-normalized form too: each of those identifies its target
		// by the literal first-word text ("nice", "env", "bash -c"), which
		// an unresolved ${IFS} glued onto it defeats — "/bin/nice${IFS}dd"
		// parses as ONE token, not "/bin/nice" separate from "dd", so
		// StripExecWrapperPrefix's wrapper-name lookup never matches it.
		// Only the exec-wrapper case is wired below: prefix-strip and
		// inline-code-fragment extraction don't depend on ${IFS} being
		// glued to a following word the way a wrapper's own name does,
		// so running them a second time on ifsNormalized would just
		// re-derive forms add() already dedupes.
		if ifsNormalized != "" {
			if unwrapped := shellparse.StripExecWrapperPrefix(ifsNormalized); unwrapped != "" {
				add(unwrapped)
				add(shellparse.DequoteCommand(unwrapped))
			}
		}
	}

	addStatementForms(stmt)

	// A backslash-newline is whitespace the shell deletes before tokenizing,
	// so `rm \<NL>-rf /` IS `rm -rf /` — but no regex matches a backslash
	// where it expects a space, and 52.5% of BLOCKing commands degraded behind
	// one (#3055). Re-render the statement on a single line and match that
	// shape too.
	if joined := shellparse.JoinLineContinuations(stmt); joined != "" {
		addStatementForms(joined)
	}
	return candidates
}
