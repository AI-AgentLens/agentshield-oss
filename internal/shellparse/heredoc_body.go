package shellparse

import (
	"path"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// HeredocBodyPlaceholder is the text substituted for a redacted heredoc body.
// Opaque and single-token for the same reason as LoopItemPlaceholder and
// SearchNeedlePlaceholder: it must survive re-parsing as shell and match no
// shipped rule pattern.
const HeredocBodyPlaceholder = "HEREDOCBODY"

// NOTE (#3827): the old two-name allowlist (cat, tee) is gone — see
// heredocBodyIsInert for why the gate inverted. The InHeredoc intent label in
// intent.go still scopes to exactly those two names; that asymmetry is now
// deliberate, because the label and this function answer different questions.
//
// heredocBindingSinks read stdin into a NAME rather than executing it — and
// the name is then executed later in the same command:
//
//	read zc <<< "rm -rf /"; $zc          (TP-READ-SCALAR-EXEC-001)
//	mapfile -t a <<< "..."; ${a[0]}      (TP-READ-MAPFILE-EXEC-001)
//
// So the body is NOT inert even though the sink interprets nothing itself.
// This is the real reason the old allowlist had to be short, and it is a
// sharper reason than "any other consumer can execute what it reads": the set
// of bash builtins that slurp stdin into a variable is CLOSED and tiny, where
// the set of commands that might be an interpreter is open-ended. The same
// three names are already recognised as a class in parse.go and
// unset_paramexp.go; this is that class, named.
var heredocBindingSinks = []string{"read", "mapfile", "readarray"}

func isHeredocBindingSink(name string) bool {
	for _, s := range heredocBindingSinks {
		if name == s {
			return true
		}
	}
	return false
}

// heredocExecSinks execute or FORWARD stdin without being named in the
// interpreter maps, which key on binary names rather than builtins:
//
//   - eval  — runs what it is given; TestHeredocBodies pins it as non-inert.
//   - source / .  — `source /dev/stdin <<'EOF'` runs the body in the CURRENT
//     shell. That is the same mechanism closed for pipes in #3798 item 1, and
//     it would be incoherent to treat it as inert here.
//   - xargs — hands stdin to another command as arguments, so the body is not
//     consumed as data by xargs itself.
//
// `command` and `exec` are deliberately absent: both are already in
// ExecWrappers and therefore stripped before the sink is named, so
// `exec bash <<'EOF'` resolves to bash.
var heredocExecSinks = []string{"eval", "source", ".", "xargs"}

func isHeredocExecSink(name string) bool {
	for _, s := range heredocExecSinks {
		if name == s {
			return true
		}
	}
	return false
}

// heredocBodyIsInert reports whether a QUOTED heredoc body fed to this sink is
// merely data. args is the sink's full argument list with exec wrappers
// already stripped.
//
// # Why this is a blocklist and not an allowlist (#3827, Gary's call)
//
// It used to be an allowlist of two names, so every unrecognised sink kept its
// body live — `gh issue comment --body-file - <<'BODY'` BLOCKed on prose that
// merely QUOTED an attack string, and so did any in-house tool. That treats
// "sink I do not recognise" as evidence of execution, which inverts this
// package's own rule that withdrawing an inertness excuse requires EVIDENCE.
// It also has a specific cost here: filing a false-positive report about a
// rule was blocked BY that rule, twice in one day (#3822, #3827).
//
// The two classes that genuinely are not inert are both ENUMERABLE, which is
// what makes the inversion safe rather than optimistic:
//
//   - executors — ShellInterpreters/CodeInterpreters, hardened in the #3796
//     review precisely so mksh/ash/rbash/ksh93/osascript/tclsh/Rscript could
//     not launder a body past it.
//   - binding sinks — the three builtins above.
//
// git is neither, and is handled by spelling: `git commit -F -` takes inert
// prose (#3493), while `git apply` and `git am` take a patch, so only the
// commit spelling qualifies.
//
// Residual risk, stated rather than hidden: a sink that binds stdin to a name
// by some mechanism not in heredocBindingSinks. That is a far more bounded
// unknown than "every command that might be an interpreter", and the nine
// TP-READ-*/TP-MAPFILE-* corpus cases turn red the moment it is got wrong.
func heredocBodyIsInert(name string, args []*syntax.Word) bool {
	if IsShellOrInterpreter(name) || isHeredocBindingSink(name) || isHeredocExecSink(name) {
		return false
	}
	if name == "git" {
		return isGitCommitMessageStdinSink(args)
	}
	return true
}

// isGitCommitMessageStdinSink reports whether args (the CallExpr's argument
// list with "git" itself already stripped) is `commit` reading its message
// from stdin via `-F -` / `--file -` / `--file=-` / `-F-` — the shape
// reported in #3493 (`git commit -q -F - <<'EOF' … EOF`). Deliberately
// narrower than "any git subcommand fed a heredoc": `git apply`, `git am`
// and hook invocations all treat stdin as a patch or script rather than
// inert prose, so only the exact `commit …-F -` spelling qualifies — no
// other subcommand, and not `-F FILE` pointing at a real path.
func isGitCommitMessageStdinSink(args []*syntax.Word) bool {
	if len(args) == 0 || staticWord(args[0]) != "commit" {
		return false
	}
	for i := 1; i < len(args); i++ {
		w := staticWord(args[i])
		switch w {
		case "-F-", "--file=-":
			return true
		case "-F", "--file":
			if i+1 < len(args) && staticWord(args[i+1]) == "-" {
				return true
			}
		}
	}
	return false
}

// HeredocBodies reports the BODY spans of every `<<DELIM … DELIM` heredoc in
// command whose sink does not execute, bind, or forward the body (see
// heredocBodyIsInert), together with a rendering of command in which exactly
// those bodies have been replaced by HeredocBodyPlaceholder.
//
// # Why this exists
//
// The InHeredoc intent label already exists and answers "does this command
// involve a cat/tee heredoc at all" — a whole-command question, downgrade-only
// (BLOCK to AUDIT), used by ~100+ rules. It is the wrong tool for a rule whose
// OWN pattern can also match the heredoc's TARGET (the write destination on
// the command line, before the body even starts): `ts-block-python-
// sitecustomize-write` matches `(cat|tee|…)\b.*\b(site|user)customize\.py`,
// and that pattern is satisfied two structurally different ways —
//
//	cat > sitecustomize.py <<'EOF'      # sitecustomize.py is the WRITE TARGET
//	  import os
//	EOF
//
//	cat > "$S/notes.md" <<'EOF'         # sitecustomize.py is PROSE inside the BODY
//	  ...describes the sitecustomize.py persistence technique...
//	EOF
//
// A command_intent_downgrade on in_heredoc cannot tell these apart — both
// commands are "a cat heredoc", so both would downgrade, and the first one is
// a real attack (issue #3397, the fourth instance of the "count without
// position" class documented in the workspace CLAUDE.md). This function
// answers the narrower, positional question instead: is the rule's match
// found ONLY inside the body text itself, never on the command line that
// names the actual write target? Combined with PositionExcluded's existing
// attribution/subtraction check, redacting only the body span (never the
// redirect target, the executable name, or anything before "<<") makes the
// first example above ineligible for exclusion automatically — the match
// survives redaction because "sitecustomize.py" the write target is untouched
// — while the second is correctly excused.
//
// # What is deliberately NOT covered
//
// Since #3827 the gate is a blocklist, not an allowlist: a heredoc qualifies
// UNLESS its sink executes the body (an interpreter, eval, source/., xargs),
// binds it to a name that is executed later (read/mapfile/readarray), or is a
// git subcommand other than `commit … -F -`/`--file -` (#3493 — reading the
// commit message from stdin is exactly as inert as `cat`/`tee`, while
// `git apply`/`git am` take a patch; see isGitCommitMessageStdinSink). Exec
// wrappers are stripped first, so `sudo bash <<'EOF'` is named bash, not sudo.
// A heredoc fed to an interpreter
// (`bash <<EOF`, `python3 <<EOF`, `eval <<EOF`) is source code, not inert
// data — the InInterpreterHeredoc label already exists for the python/node/
// etc. case and carries its own explicit warning that rules serving as sole
// coverage for an attack path must not opt into treating that body as
// harmless. This function does not widen that: it never even considers those
// heredocs, so a rule combining command_position_exclude: [heredoc_body] gets
// no exemption at all on `bash <<EOF … EOF`.
//
// A here-string (`<<<`, syntax.WordHdoc) is a single expression, not a
// multi-line body with its own delimiter, and is not a Hdoc/DashHdoc
// redirect — Redirect.Hdoc is nil for it, so it is never collected here.
//
// # Quoted vs. unquoted delimiter (#3730)
//
// A shell only treats the body as inert literal text when the delimiter is
// quoted (`<<'EOF'`, `<<"EOF"`, `<<\EOF`). An UNQUOTED delimiter (`<<EOF`)
// gets the same expansion a double-quoted string gets: parameter expansion,
// command substitution, arithmetic expansion. So `$(rm -rf /)` inside an
// unquoted-delimiter body to `cat`/`tee` genuinely executes before the sink
// ever sees it — redacting the whole span for a rule like
// `ts-block-mcp-socket-hijack` would blind it to a real listener started via
// `cat <<EOF\n$(nc -lU /tmp/mcp-agent.sock)\nEOF`.
//
// mvdan/sh already encodes this structurally, so this function does not
// need to inspect the delimiter itself: `Redirect.Hdoc.Parts` is a single
// `*syntax.Lit` for a quoted delimiter (the whole body, verbatim, including
// any literal `$(...)` text), and a mix of `*syntax.Lit` and expansion nodes
// (`*syntax.CmdSubst`, `*syntax.ParamExp`, `*syntax.ArithmExp`, …) for an
// unquoted one. Only `*syntax.Lit` parts are ever redacted or collected as
// items; every other part type is left untouched in both the item text and
// the redacted command, so a pattern that only matches inside a live
// expansion still matches the redacted form and PositionExcluded's
// subtraction check correctly refuses to exclude it. A quoted delimiter is
// unaffected: its single Lit part reproduces the pre-#3730 whole-body
// behavior exactly.
//
// Returns (nil, "") when the command has no qualifying heredoc, when parsing
// fails, or when nothing was rewritten — the same no-op sentinel convention
// as InertLoopWordLists, SearchToolNeedles, NormalizeIFS and DequoteCommand.
func HeredocBodies(command string) (items []string, redacted string) {
	// Cheap prefilter: every shape this handles requires a heredoc operator,
	// and the AST parse is the expensive part.
	if !strings.Contains(command, "<<") {
		return nil, ""
	}
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, ""
	}

	var spans []byteSpan
	syntax.Walk(file, func(node syntax.Node) bool {
		st, ok := node.(*syntax.Stmt)
		if !ok || len(st.Redirs) == 0 {
			return true
		}
		ce, ok := st.Cmd.(*syntax.CallExpr)
		if !ok || len(ce.Args) == 0 {
			return true
		}
		// Strip exec wrappers before naming the sink, or `sudo bash <<'EOF'`
		// reads as the unknown command "sudo" and its body would be called
		// inert — the exact regression the inversion below could introduce.
		// The corpus carries that shape (`sudo bash <<< …`), so this is
		// load-bearing, not defensive.
		words := make([]string, len(ce.Args))
		for i, a := range ce.Args {
			words[i] = WordToString(a)
		}
		stripped := StripExecWrappers(words)
		if len(stripped) == 0 {
			return true
		}
		offset := len(words) - len(stripped) // StripExecWrappers only trims the front
		exe := staticWord(ce.Args[offset])
		if exe == "" {
			return true
		}
		name := path.Base(NormalizeExecName(exe))
		if !heredocBodyIsInert(name, ce.Args[offset+1:]) {
			return true
		}
		for _, r := range st.Redirs {
			if r == nil || r.Hdoc == nil {
				continue
			}
			if r.Op != syntax.Hdoc && r.Op != syntax.DashHdoc {
				continue
			}
			// Only literal text is inert. A live expansion part (CmdSubst,
			// ParamExp, ArithmExp, ProcSubst, ...) is left completely
			// untouched — neither redacted nor collected as an item — so it
			// stays visible to the pattern matcher in both attribution and
			// subtraction. See "Quoted vs. unquoted delimiter" above.
			for _, part := range r.Hdoc.Parts {
				lit, ok := part.(*syntax.Lit)
				if !ok {
					continue
				}
				s, e := int(lit.Pos().Offset()), int(lit.End().Offset())
				if s < 0 || e > len(command) || s >= e {
					continue
				}
				spans = append(spans, byteSpan{s, e})
			}
		}
		return true
	})
	if len(spans) == 0 {
		return nil, ""
	}

	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var sb strings.Builder
	last := 0
	for _, s := range spans {
		if s.start < last {
			continue // overlapping span — skip defensively, never corrupt the text
		}
		sb.WriteString(command[last:s.start])
		sb.WriteString(HeredocBodyPlaceholder)
		last = s.end
		items = append(items, command[s.start:s.end])
	}
	sb.WriteString(command[last:])

	out := sb.String()
	if out == command {
		return nil, ""
	}
	return items, out
}
