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

// heredocDataSinks are the executables whose heredoc-fed stdin is treated as
// inert DATA: they copy or print stdin verbatim and never interpret it as
// code. Deliberately the same two names the InHeredoc intent label already
// scopes to ("cat/tee << EOF — body is data written to a file, not
// execution", intent.go) — this function answers a different question about
// the same shape (see below), not a broader one. Kept short on purpose: any
// other consumer (bash, sh, python3, …) can execute what it reads from stdin,
// which is exactly the risk InInterpreterHeredoc's doc comment already warns
// about for the sibling label.
var heredocDataSinks = []string{"cat", "tee"}

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
// command that feeds a recognized inert-data consumer (cat, tee, or
// `git commit … -F -`), together with a rendering of command in which exactly
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
// Only cat/tee heredocs, and `git commit … -F -`/`--file -` heredocs
// (#3493 — reading the commit message from stdin is exactly as inert as
// `cat`/`tee`; no other git subcommand qualifies, see
// isGitCommitMessageStdinSink), qualify. A heredoc fed to an interpreter
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
		exe := staticWord(ce.Args[0])
		if exe == "" {
			return true
		}
		name := path.Base(NormalizeExecName(exe))
		if !isHeredocDataSink(name) && (name != "git" || !isGitCommitMessageStdinSink(ce.Args[1:])) {
			return true
		}
		for _, r := range st.Redirs {
			if r == nil || r.Hdoc == nil {
				continue
			}
			if r.Op != syntax.Hdoc && r.Op != syntax.DashHdoc {
				continue
			}
			s, e := int(r.Hdoc.Pos().Offset()), int(r.Hdoc.End().Offset())
			if s < 0 || e > len(command) || s >= e {
				continue
			}
			spans = append(spans, byteSpan{s, e})
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

func isHeredocDataSink(exe string) bool {
	for _, name := range heredocDataSinks {
		if exe == name {
			return true
		}
	}
	return false
}
