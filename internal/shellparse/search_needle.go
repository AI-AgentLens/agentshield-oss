package shellparse

import (
	"path"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// SearchNeedlePlaceholder is the text substituted for a redacted grep-family
// pattern operand. Opaque and single-token for the same reason as
// LoopItemPlaceholder: it must survive re-parsing as shell and match no
// shipped rule pattern.
const SearchNeedlePlaceholder = "SEARCHNEEDLE"

// grepFamilyNames are the executables SearchToolNeedles treats as search
// tools. Kept in one place so the cheap substring prefilter and the AST
// switch cannot drift.
var grepFamilyNames = []string{"grep", "egrep", "fgrep", "rg", "ag"}

// SearchToolNeedles reports the PATTERN operand of every grep-family
// invocation in command, together with a rendering of command in which
// exactly those operands have been replaced by SearchNeedlePlaceholder.
//
// # Why this exists
//
// A grep pattern operand is the NEEDLE of a search — data being compared
// against file content, never a target being opened, executed, or attached
// to. `grep -i "frida -n <process>" -r docs/` runs frida on nothing; it reads
// documentation looking for a string that happens to spell out a dangerous
// invocation. A rule keyed on that literal text sees it anyway, which is
// issue #3382 — the same "count without position" shape InertLoopWordLists
// closed for `for … in` word lists (#3376), on a different syntactic
// position: the loop case redacts DATA BEING ITERATED, this one redacts DATA
// BEING SEARCHED FOR. Both are consumed positions, neither is a target.
//
// # What is deliberately NOT covered
//
// grepNeedleSpan already refuses to identify the pattern when a flag that
// might consume a SEPARATE following token (`-e VALUE`, -f, -m, -A, --include,
// …) is present — see its doc comment. That refusal propagates here unchanged:
// an ambiguous invocation keeps every word live rather than guessing which one
// is the needle, so a mis-scoped flag costs a block that stands, not a bypass
// that ships. Inline pattern-bearing flags (`-e"$p"`, `--regexp=…`) are the
// exception it CAN resolve: the value is glued into the same word, so
// grepNeedleSpan returns just that value subspan (#3728).
//
// Unlike InertLoopWordLists this does not gate on whether the invocation's
// output escapes to somewhere that could act on it. That gate exists there
// because the loop VALUE (e.g. a candidate file path) is the thing at risk if
// it survives to a consumer. Here the redacted text is the search TERM, not a
// value being carried forward — PositionExcluded's own subtraction check
// (does the rule's pattern still match once the needle is removed) is what
// catches a real invocation that happens to share the string elsewhere in the
// command, so no separate escape analysis is needed.
//
// Returns (nil, "") when the command has no qualifying invocation, when
// parsing fails, or when nothing was rewritten — the same no-op sentinel
// convention as InertLoopWordLists, NormalizeIFS and DequoteCommand.
func SearchToolNeedles(command string) (items []string, redacted string) {
	hasCandidate := strings.Contains(command, "git")
	for _, name := range grepFamilyNames {
		if hasCandidate {
			break
		}
		if strings.Contains(command, name) {
			hasCandidate = true
			break
		}
	}
	if !hasCandidate {
		return nil, ""
	}

	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, ""
	}

	needles := searchNeedles(file, len(command))
	if len(needles) == 0 {
		return nil, ""
	}
	spans := make([]byteSpan, len(needles))
	for i, n := range needles {
		spans[i] = n.span
	}

	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var sb strings.Builder
	last := 0
	for _, s := range spans {
		if s.start < last {
			continue // overlapping span — skip defensively, never corrupt the text
		}
		sb.WriteString(command[last:s.start])
		sb.WriteString(SearchNeedlePlaceholder)
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

// searchNeedle is one redactable search operand: its byte span, and the
// grep-family invocation it belongs to (nil for a git pickaxe string).
type searchNeedle struct {
	span byteSpan
	grep *syntax.CallExpr
}

// searchNeedles is the walk behind SearchToolNeedles, shared with
// ForwardedSearchNeedles so the two can never disagree about what a needle
// is. n is the length of the parsed source; a span outside it is dropped.
func searchNeedles(file *syntax.File, n int) []searchNeedle {
	shadowed := definedCommandNames(file)
	valid := func(s byteSpan) bool { return s.start >= 0 && s.end <= n && s.start < s.end }
	var out []searchNeedle
	syntax.Walk(file, func(node syntax.Node) bool {
		c, ok := node.(*syntax.CallExpr)
		if !ok || len(c.Args) == 0 {
			return true
		}
		exe := staticWord(c.Args[0])
		if exe == "" {
			return true
		}
		base := path.Base(NormalizeExecName(exe))
		if shadowed[base] {
			return true // #4415: the command line defines what this name runs
		}
		if base == "git" {
			if span, ok := gitPickaxeSpan(c.Args); ok && valid(span) {
				out = append(out, searchNeedle{span: span})
			}
			return true
		}
		if !isGrepFamily(base) {
			return true
		}
		if span, ok := grepNeedleSpan(c.Args); ok && valid(span) {
			out = append(out, searchNeedle{span: span, grep: c})
		}
		return true
	})
	return out
}

// ForwardedSearchNeedles returns the PATTERN operand of every grep-family
// invocation whose matching lines the command hands to a stage that acts on
// each line (#4468):
//
//   - xargs with a target other than echo/printf: `grep P f | xargs cat`
//     runs cat on the selected lines' words;
//   - a while/until loop whose condition reads a line into a variable the
//     body uses anywhere but a print: `grep P f | while read -r l; do eval
//     "$l"; done`.
//
// The stage may be fed by a pipe (any later stage of the pipeline) or by a
// process substitution on its stdin (`done < <(grep P f)`).
//
// # Why
//
// search_needle (#3382) excuses a pattern operand because searching for a
// name is not using it. That holds only while grep's output goes nowhere that
// acts on it: every line a needle selects contains the needle, so a stage
// that runs or opens those lines acts on exactly the text the rule keys on.
// Pipes into a shell, written-then-run files and executed substitutions are
// already answered by TextReachesExecutor and ExecutedSubstitutionBodies,
// which PositionExcluded consults first. xargs and read loops are the two
// channels neither sees, because the program receiving the text is not a
// shell or interpreter named in the pipe.
//
// # What it does not claim
//
// A grep that provably prints no matched line (-c, -q, -l, -L, the
// hasGrepSummaryFlag set) forwards no needle text and is skipped. A git
// pickaxe string is skipped too: git log/diff/show print commit metadata,
// not the needle. A read loop whose variables are only printed (judged by
// loopVarInert, the loop_wordlist allowlist) keeps the excuse, as does xargs
// with no target or an echo/printf target. A loop variable the read cannot
// name statically (`read "$v"`) counts as live.
//
// Attribution is by span: the grep must sit inside the stage's upstream. A
// sed or sort between the grep and the stage may remove the needle; that is
// treated as forwarded, the same granularity TextReachesExecutor accepts for
// pipes.
//
// Returns nil when nothing is forwarded or the command does not parse.
func ForwardedSearchNeedles(command string) []string {
	if !strings.Contains(command, "xargs") && !strings.Contains(command, "read") {
		return nil
	}
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return nil
	}
	upstream := forwardedUpstreamSpans(file, command)
	if len(upstream) == 0 {
		return nil
	}
	var out []string
	for _, n := range searchNeedles(file, len(command)) {
		if n.grep == nil || hasGrepSummaryFlag(n.grep.Args) {
			continue
		}
		call := byteSpan{int(n.grep.Pos().Offset()), int(n.grep.End().Offset())}
		for _, u := range upstream {
			if u.contains(call) {
				out = append(out, command[n.span.start:n.span.end])
				break
			}
		}
	}
	return out
}

// forwardedUpstreamSpans returns the byte spans whose output reaches a
// line-forwarding stage (lineForwardingStage): the left side of every pipe
// with such a stage on its right, and every process substitution redirected
// into such a stage's stdin.
func forwardedUpstreamSpans(file *syntax.File, src string) []byteSpan {
	escapes := outputEscapeSpans(file)
	var out []byteSpan
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.BinaryCmd:
			if (n.Op != syntax.Pipe && n.Op != syntax.PipeAll) || n.X == nil || n.Y == nil {
				return true
			}
			// The parser nests `a | b | c` as `(a | b) | c`, so X is every
			// stage upstream of Y.
			if lineForwardingStage(n.Y, src, escapes) {
				out = append(out, byteSpan{int(n.X.Pos().Offset()), int(n.X.End().Offset())})
			}
		case *syntax.Stmt:
			for _, r := range n.Redirs {
				if r == nil || r.Op != syntax.RdrIn || r.Word == nil || !wordIsProcessSubstitution(r.Word) {
					continue
				}
				if lineForwardingStage(n, src, escapes) {
					out = append(out, byteSpan{int(r.Word.Pos().Offset()), int(r.Word.End().Offset())})
				}
			}
		}
		return true
	})
	return out
}

// lineForwardingStage reports whether st turns each line on its stdin into
// arguments of a command or a value the shell then acts on — the two stages
// ForwardedSearchNeedles adds to the executor channels.
func lineForwardingStage(st *syntax.Stmt, src string, escapes []byteSpan) bool {
	if wc, ok := st.Cmd.(*syntax.WhileClause); ok {
		return readLoopUsesLine(wc, escapes)
	}
	call := leftmostCallExpr(st)
	if call == nil || len(call.Args) == 0 {
		return false
	}
	words := make([]string, len(call.Args))
	for i, a := range call.Args {
		words[i] = WordToString(a)
	}
	stripped := StripExecWrappers(words)
	if len(stripped) == 0 || path.Base(NormalizeExecName(stripped[0])) != "xargs" {
		return false
	}
	target := strings.Fields(xargsTargetText(src, st))
	if len(target) == 0 {
		return false // bare xargs runs echo
	}
	switch path.Base(NormalizeExecName(target[0])) {
	case "echo", "printf":
		return false
	}
	return true
}

// readLoopUsesLine reports whether a while/until loop reads its stdin with
// `read` and uses a variable it read anywhere loopVarInert does not allow.
func readLoopUsesLine(wc *syntax.WhileClause, escapes []byteSpan) bool {
	names := map[string]bool{}
	reads := false
	for _, c := range wc.Cond {
		call := leftmostCallExpr(c)
		if call == nil || len(call.Args) == 0 || staticWord(call.Args[0]) != "read" {
			continue
		}
		reads = true
		names["REPLY"] = true // read with no name operand
		for _, a := range call.Args[1:] {
			if wordHasExpansion(a) {
				return true // a target the read names at run time
			}
			if v := staticWord(a); isIdentifier(v) {
				names[v] = true // over-collects option values; harmless
			}
		}
	}
	if !reads {
		return false
	}
	for name := range names {
		if !loopVarInert(name, wc.Do, escapes) {
			return true
		}
	}
	return false
}

// wordHasExpansion reports whether w carries any expansion, unlike
// staticWord, whose "" also means an empty quoted string (read's -d option
// given an empty delimiter, the find -print0 idiom).
func wordHasExpansion(w *syntax.Word) bool {
	found := false
	syntax.Walk(w, func(n syntax.Node) bool {
		switch n.(type) {
		case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ArithmExp, *syntax.ExtGlob, *syntax.BraceExp:
			found = true
		}
		return !found
	})
	return found
}

func isGrepFamily(exe string) bool {
	for _, name := range grepFamilyNames {
		if exe == name {
			return true
		}
	}
	return false
}

// gitPickaxeSpan returns the byte span of the VALUE glued onto a pickaxe flag
// (`-S<string>`, `-G<regex>`) of `git log|diff|show` (#4331). The pickaxe
// string is compared against the diff of every commit; it is a needle exactly
// like a grep pattern and is never opened, executed or attached to.
//
// Deliberately narrow, so a miss costs a block that stands and not a bypass:
//   - the subcommand must be args[1] (no `git -c k=v log`, which can carry
//     config that runs programs);
//   - only the GLUED spelling (`-S'x'`), because the separate-word form shifts
//     every later operand by one if a flag is mis-scoped;
//   - only flags before `--`;
//   - the value must be literal or quoted text: no command substitution,
//     process substitution, arithmetic, or unquoted parameter expansion
//     (which would word-split the value into a separate token).
//
// At most one span is returned: the first qualifying flag.
func gitPickaxeSpan(args []*syntax.Word) (byteSpan, bool) {
	if len(args) < 3 {
		return byteSpan{}, false
	}
	switch staticWord(args[1]) {
	case "log", "diff", "show":
	default:
		return byteSpan{}, false
	}
	for _, w := range args[2:] {
		t := staticWord(w)
		if t == "--" {
			return byteSpan{}, false
		}
		if len(w.Parts) == 0 {
			continue
		}
		lit, ok := w.Parts[0].(*syntax.Lit)
		if !ok || len(lit.Value) < 2 || lit.Value[0] != '-' || (lit.Value[1] != 'S' && lit.Value[1] != 'G') {
			continue
		}
		if len(lit.Value) == 2 && len(w.Parts) == 1 {
			continue // bare -S: the value is the NEXT word, which we do not resolve
		}
		if containsExecutingExpansion(w) {
			continue
		}
		inert := true
		for _, part := range w.Parts[1:] {
			switch part.(type) {
			case *syntax.Lit, *syntax.SglQuoted, *syntax.DblQuoted:
			default:
				inert = false
			}
		}
		if !inert {
			continue
		}
		return byteSpan{int(w.Pos().Offset()) + 2, int(w.End().Offset())}, true
	}
	return byteSpan{}, false
}

// definedCommandNames returns the command names the same command line defines
// itself (#4415): a function, an alias, or a file written under that name
// (redirect target, or a cp/mv/ln/install/tee operand). A call to such a name
// runs the definition, not the search tool, so its operands are not a needle.
// Over-collecting only withdraws an exemption, which keeps the rule's finding.
func definedCommandNames(file *syntax.File) map[string]bool {
	names := map[string]bool{}
	add := func(v string) {
		if v != "" {
			names[path.Base(v)] = true
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.FuncDecl:
			if n.Name != nil {
				add(n.Name.Value)
			}
		case *syntax.Redirect:
			if n.Word != nil && n.Op != syntax.Hdoc && n.Op != syntax.DashHdoc && n.Op != syntax.WordHdoc {
				add(staticWord(n.Word))
			}
		case *syntax.CallExpr:
			if len(n.Args) < 2 {
				return true
			}
			switch path.Base(NormalizeExecName(staticWord(n.Args[0]))) {
			case "alias":
				for _, a := range n.Args[1:] {
					v := staticWord(a)
					if i := strings.IndexByte(v, '='); i > 0 {
						add(v[:i])
					}
				}
			case "cp", "mv", "ln", "install", "tee":
				for _, a := range n.Args[1:] {
					if v := staticWord(a); !strings.HasPrefix(v, "-") {
						add(v)
					}
				}
			}
		}
		return true
	})
	return names
}
