package shellparse

import (
	"path"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// LoopItemPlaceholder is the text substituted for a redacted loop word-list
// item. It is deliberately a single opaque identifier: it keeps the redacted
// text parseable as shell (so the caller can re-derive candidate forms from
// it) while matching no rule pattern in the corpus.
const LoopItemPlaceholder = "LOOPITEM"

// InertLoopWordLists reports the word-list items of every `for NAME in W…`
// clause whose loop variable is INERT in the loop body, together with a
// rendering of command in which exactly those items have been replaced by
// LoopItemPlaceholder.
//
// # Why this exists
//
// A `for … in` word list is data being iterated, not a set of operands being
// acted on. `for p in ".ssh/" "/etc/shadow"; do grep -c -- "$p" notes.txt; done`
// opens nothing: the sensitive path is the *needle* of a search, never the
// haystack. A rule keyed on the literal text sees it anyway, which is issue
// #3376 — the fourth instance of the "the path appears as a string value, not
// a filesystem target" class that sec-block-etc-shadow's exclusion list
// already carved out three times.
//
// # Why position alone is not enough
//
// The obvious fix — "exempt a token that sits between `in` and the loop's
// `do`" — is wrong, and the issue that proposed it did not trace it:
//
//	for p in /etc/shadow; do cat "$p"; done
//
// puts the path in exactly that position and READS it. Word-list position
// makes a token data only if the loop variable never reaches somewhere that
// can act on it. So inertness is judged from the BODY, and judged by an
// allowlist: a reference to NAME is inert only where there is no reading of
// it under which the value is opened, executed, or stored for later use.
// Everything else — an executable word, a redirect target, an assignment
// value, a `[[ -f $p ]]` test, an unrecognised command — is treated as live.
// The failure direction of an unknown shape is therefore "keep the block".
//
// Returns (nil, "") when the command has no qualifying loop, when parsing
// fails, or when nothing was rewritten — the same no-op sentinel convention
// as NormalizeIFS, DequoteCommand and NormalizeUnsetParamExp.
func InertLoopWordLists(command string) (items []string, redacted string) {
	// Cheap prefilter: every shape this handles is spelled with one of these
	// two keywords, and the AST parse is the expensive part.
	if !strings.Contains(command, "for") && !strings.Contains(command, "select") {
		return nil, ""
	}
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, ""
	}

	// Computed over the WHOLE file, not the loop body: a pipe or capture can
	// sit OUTSIDE the loop and still consume what the body printed
	// (`for p in …; do echo "$p"; done | xargs cat`).
	escapes := outputEscapeSpans(file)

	var spans []byteSpan
	syntax.Walk(file, func(node syntax.Node) bool {
		fc, ok := node.(*syntax.ForClause)
		if !ok {
			return true
		}
		wi, ok := fc.Loop.(*syntax.WordIter)
		// An invalid InPos means `for x; do …` — iteration over the positional
		// parameters, with no word list to redact. A CStyleLoop (`for ((…))`)
		// has none either.
		if !ok || !wi.InPos.IsValid() || wi.Name == nil {
			return true
		}
		if !loopVarInert(wi.Name.Value, fc.Do, escapes) {
			return true
		}
		for _, w := range wi.Items {
			s, e := int(w.Pos().Offset()), int(w.End().Offset())
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
		sb.WriteString(LoopItemPlaceholder)
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

type byteSpan struct{ start, end int }

func (s byteSpan) contains(inner byteSpan) bool {
	return inner.start >= s.start && inner.end <= s.end
}

// loopVarInert reports whether every reference to name inside body sits at a
// position where the value cannot be opened, executed, or retained.
//
// The judgement is per-reference and per-innermost-command, which is the part
// that is easy to get wrong: `echo "$(cat $p)"` has the reference lexically
// inside an argument of `echo`, and treating containment in an allowlisted
// command's argument span as sufficient would bless the `cat` that actually
// reads the file. Each reference is therefore attributed to the SMALLEST
// simple command that encloses it, and judged against that command.
//
// A body with no reference at all is inert — the loop is iterating for its
// count, and the word list is pure data.
func loopVarInert(name string, body []*syntax.Stmt, escapes []byteSpan) bool {
	if name == "" {
		return false
	}
	type call struct {
		span byteSpan
		safe []byteSpan
	}
	var calls []call
	var refs []byteSpan

	for _, st := range body {
		if st == nil {
			continue
		}
		syntax.Walk(st, func(node syntax.Node) bool {
			switch n := node.(type) {
			case *syntax.CallExpr:
				span := byteSpan{int(n.Pos().Offset()), int(n.End().Offset())}
				calls = append(calls, call{span: span, safe: inertArgSpans(n, escaping(span, escapes))})
			case *syntax.ParamExp:
				if n.Param != nil && n.Param.Value == name {
					refs = append(refs, byteSpan{int(n.Pos().Offset()), int(n.End().Offset())})
				}
			}
			return true
		})
	}

	for _, ref := range refs {
		inner := -1
		for i, c := range calls {
			if !c.span.contains(ref) {
				continue
			}
			// Smallest enclosing simple command wins: a nested command
			// substitution is a tighter span than the argument word holding it.
			if inner == -1 || c.span.start > calls[inner].span.start {
				inner = i
			}
		}
		if inner == -1 {
			return false // redirect target, test clause, arithmetic — treat as live
		}
		ok := false
		for _, s := range calls[inner].safe {
			if s.contains(ref) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// inertArgSpans returns the byte spans of the argument words of one simple
// command in which a loop-variable reference is inert.
//
// This is an allowlist, and it is short on purpose. Two shapes are covered
// because two shapes are what the reported idiom uses: printing the value,
// and searching FOR the value. Adding an entry means asserting that no
// spelling of that command can turn the argument into a file it opens or a
// command it runs — which is a much stronger claim than "this usually looks
// benign". When in doubt, leave it out: the cost is a block that stands, not
// a bypass that ships.
//
// escapes says whether this command's stdout goes somewhere other than the
// caller's terminal — a pipe, a redirect, or a command substitution. It is
// not a detail: "printing a value" is inert exactly because nothing consumes
// the print. `echo "$p" | xargs cat` prints the same string and reads the
// file, and an earlier version of this function excused it. Found by probing
// the fix's own blast radius, not by a test that already existed.
func inertArgSpans(c *syntax.CallExpr, escapes bool) []byteSpan {
	// A command with assignments but no words ("n=$(…)") executes nothing, but
	// it RETAINS the value under a new name, which this analysis does not
	// follow. Nothing in it is inert.
	if len(c.Args) == 0 {
		return nil
	}
	exe := staticWord(c.Args[0])
	if exe == "" {
		return nil
	}
	switch path.Base(NormalizeExecName(exe)) {
	case "agentshield":
		return agentshieldMCPEvalSafeArgs(c)
	case "echo", "printf":
		// The reference IS the output, so it is inert only while the output
		// goes nowhere a command can act on it.
		if escapes {
			return nil
		}
		out := make([]byteSpan, 0, len(c.Args)-1)
		for _, w := range c.Args[1:] {
			out = append(out, byteSpan{int(w.Pos().Offset()), int(w.End().Offset())})
		}
		return out
	case "grep", "egrep", "fgrep", "rg", "ag":
		// grep's output is lines of the HAYSTACK, so capturing it is not the
		// same hazard as capturing an echo — with one exception: matching
		// lines contain the needle, so `grep "$p" f | xargs cat` hands the
		// path onward just as `echo` would. When the output escapes, require
		// a flag that provably suppresses the matched text: a count, a
		// filename list, or nothing at all. `-c` is what the reported FP
		// (#3376) uses inside its command substitution, so this keeps it.
		if escapes && !hasGrepSummaryFlag(c.Args) {
			return nil
		}
		i := grepPatternOperand(c.Args)
		if i <= 0 {
			return nil
		}
		w := c.Args[i]
		return []byteSpan{{int(w.Pos().Offset()), int(w.End().Offset())}}
	}
	return nil
}

// agentshieldMCPEvalSafeArgs returns the byte spans of the `--arg`/`--json`
// VALUE words of an `agentshield mcp-eval` invocation (#3547).
//
// mcp-eval is Shield's own policy simulator (internal/cli/mcp_eval.go): it
// string-matches an argument value against MCP rules and returns a decision —
// it never opens, executes, or retains the value. That is a stronger
// guarantee than echo/grep's "inert while nothing consumes the print" above,
// so no escapes check is needed here: mcp-eval's own output is a
// BLOCK/AUDIT/ALLOW decision plus rule ids and reason text, never the raw
// argument value, regardless of where its stdout goes.
//
// Scoped to mcp-eval specifically, and to the --arg/--json value words only:
// other agentshield subcommands, and mcp-eval's own --mcp-policy flag, load a
// real file from the path they're given, so a loop variable landing there
// must stay live.
func agentshieldMCPEvalSafeArgs(c *syntax.CallExpr) []byteSpan {
	hasSubcmd := false
	for _, w := range c.Args[1:] {
		if v, lit := literalWordValue(w); lit && v == "mcp-eval" {
			hasSubcmd = true
			break
		}
	}
	if !hasSubcmd {
		return nil
	}
	var out []byteSpan
	for i := 2; i < len(c.Args); i++ {
		if prev, lit := literalWordValue(c.Args[i-1]); lit && (prev == "--arg" || prev == "--json") {
			out = append(out, byteSpan{int(c.Args[i].Pos().Offset()), int(c.Args[i].End().Offset())})
		}
	}
	return out
}

// MCPEvalDynamicPolicyFlag reports whether command contains an `agentshield
// mcp-eval` invocation whose `--mcp-policy` value word is not a static
// string literal (#3548).
//
// Unlike --arg/--json (agentshieldMCPEvalSafeArgs above) — which mcp-eval
// only ever string-matches, never opens — --mcp-policy genuinely loads that
// path as a YAML file (internal/cli/mcp_eval.go's loadDeployedMCPPolicy). A
// STATIC --mcp-policy literal is already caught independently by the
// structural protected-path check against defaults.protected_paths, so this
// only needs to flag what that check cannot see: a DYNAMIC value (e.g. a
// `for … in` loop binding) whose runtime value no static check can rule
// out. Consulted by IntentExcludedForStatements so the is_self_mgmt fact
// ("an agentshield mcp-eval invocation is present in this text") does not
// excuse a match merely because mcp-eval also appears somewhere in it,
// regardless of which flag the matched literal actually reaches.
func MCPEvalDynamicPolicyFlag(command string) bool {
	if !strings.Contains(command, "mcp-policy") {
		return false
	}
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return false
	}
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		c, ok := node.(*syntax.CallExpr)
		if !ok || len(c.Args) == 0 {
			return true
		}
		if path.Base(NormalizeExecName(staticWord(c.Args[0]))) != "agentshield" {
			return true
		}
		hasSubcmd := false
		for _, w := range c.Args[1:] {
			if v, lit := literalWordValue(w); lit && v == "mcp-eval" {
				hasSubcmd = true
				break
			}
		}
		if !hasSubcmd {
			return true
		}
		for i := 1; i < len(c.Args); i++ {
			prev, prevLit := literalWordValue(c.Args[i-1])
			if prevLit && prev == "--mcp-policy" {
				if _, valLit := literalWordValue(c.Args[i]); !valLit {
					found = true
				}
			}
		}
		return true
	})
	return found
}

// hasGrepSummaryFlag reports whether the invocation carries a flag under which
// grep never prints a matched line: -c/--count, -q/--quiet/--silent, and the
// filename-only forms -l/-L.
func hasGrepSummaryFlag(args []*syntax.Word) bool {
	for i := 1; i < len(args); i++ {
		t := staticWord(args[i])
		if t == "--" {
			return false // operands from here on
		}
		switch t {
		case "--count", "--quiet", "--silent", "--files-with-matches", "--files-without-match":
			return true
		}
		if strings.HasPrefix(t, "--") || !strings.HasPrefix(t, "-") || len(t) < 2 {
			continue
		}
		if strings.ContainsAny(t[1:], "cqlL") {
			return true
		}
	}
	return false
}

// outputEscapeSpans returns the byte spans inside which a command's stdout
// does NOT reach the caller's terminal: the left-hand side of every pipe, the
// body of every command/process substitution, and any statement carrying an
// output redirect.
//
// Computed over the whole file rather than the loop body because the consumer
// is often outside the loop — `for p in …; do echo "$p"; done | xargs cat`
// pipes the loop itself, so a body-scoped walk sees nothing.
func outputEscapeSpans(file *syntax.File) []byteSpan {
	var out []byteSpan
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.BinaryCmd:
			// Only the LEFT operand feeds the pipe. The right-hand side's own
			// output goes wherever the pipeline's does, and is covered by the
			// enclosing BinaryCmd when the pipeline is longer.
			if (n.Op == syntax.Pipe || n.Op == syntax.PipeAll) && n.X != nil {
				out = append(out, byteSpan{int(n.X.Pos().Offset()), int(n.X.End().Offset())})
			}
		case *syntax.CmdSubst:
			out = append(out, byteSpan{int(n.Pos().Offset()), int(n.End().Offset())})
		case *syntax.ProcSubst:
			out = append(out, byteSpan{int(n.Pos().Offset()), int(n.End().Offset())})
		case *syntax.Stmt:
			for _, r := range n.Redirs {
				if r == nil {
					continue
				}
				switch r.Op {
				case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.DplOut, syntax.RdrClob:
					out = append(out, byteSpan{int(n.Pos().Offset()), int(n.End().Offset())})
				}
			}
		}
		return true
	})
	return out
}

func escaping(span byteSpan, escapes []byteSpan) bool {
	for _, e := range escapes {
		if e.contains(span) {
			return true
		}
	}
	return false
}

// grepPatternOperand returns the index in args of the PATTERN operand of a
// grep-family invocation, or -1 when it cannot be identified with certainty.
//
// Only the pattern is inert: `grep foo "$p"` has "$p" as the HAYSTACK, a file
// the command opens. Distinguishing the two means knowing where the flags
// stop, so any flag that might consume the following token (-e, -f, -m, -A,
// --include …) gives up rather than guessing — mistaking a flag VALUE for the
// pattern would shift every later operand by one and could mark a haystack
// inert.
func grepPatternOperand(args []*syntax.Word) int {
	endOfFlags := false
	for i := 1; i < len(args); i++ {
		t := staticWord(args[i])
		if !endOfFlags {
			if t == "--" {
				endOfFlags = true
				continue
			}
			if strings.HasPrefix(t, "--") {
				// `--include=*.go` carries its value inline, so the next token
				// is still the pattern. A bare long flag is only safe to skip
				// when it is known not to take one.
				if strings.Contains(t, "=") || grepBooleanLongFlags[t] {
					continue
				}
				return -1
			}
			if len(t) > 1 && strings.HasPrefix(t, "-") {
				for _, r := range t[1:] {
					if !strings.ContainsRune(grepBooleanShortFlags, r) {
						return -1
					}
				}
				continue
			}
		}
		return i
	}
	return -1
}

// grepBooleanShortFlags are the grep short options that never consume the
// following token. Anything absent here (-e, -f, -m, -A, -B, -C, -D, -d) may,
// so its presence makes the operand layout unknowable.
const grepBooleanShortFlags = "acEFGHhIiLlnoPqRrsUvwxZz"

var grepBooleanLongFlags = map[string]bool{
	"--basic-regexp": true, "--count": true, "--extended-regexp": true,
	"--files-with-matches": true, "--files-without-match": true,
	"--fixed-strings": true, "--ignore-case": true, "--invert-match": true,
	"--line-number": true, "--line-regexp": true, "--no-filename": true,
	"--no-messages": true, "--null": true, "--null-data": true,
	"--only-matching": true, "--perl-regexp": true, "--quiet": true,
	"--recursive": true, "--silent": true, "--text": true,
	"--with-filename": true, "--word-regexp": true,
}

// staticWord returns a word's literal text, or "" when any part of it is
// dynamic (a parameter expansion, command substitution, arithmetic). Callers
// use "" as "unknown", never as "empty string".
func staticWord(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	var sb strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return ""
				}
				sb.WriteString(lit.Value)
			}
		default:
			return ""
		}
	}
	return sb.String()
}
