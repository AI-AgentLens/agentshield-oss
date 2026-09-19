package shellparse

import (
	"path"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// InterpreterHeredocSpan is one literal-only text span of a `<<DELIM …
// DELIM` heredoc body fed to a CodeInterpreters executable (python3, node,
// ruby, …), given as an absolute byte range into the command it was found
// in, together with the resolved executable name (the same CodeInterpreters
// key AnalyzeTextReach and collectCall resolve to).
type InterpreterHeredocSpan struct {
	Lang       string
	Start, End int
}

// InterpreterHeredocLiteralSpans walks command for every heredoc fed to a
// CodeInterpreters executable and returns the LITERAL-only byte spans of its
// body.
//
// This mirrors HeredocBodies' own AST walk exactly, generalized from the
// two-name heredocDataSinks allowlist to CodeInterpreters — see that
// function's "Quoted vs. unquoted delimiter" section for why only a
// *syntax.Lit part (a quoted-delimiter heredoc's body, or the literal
// portions of an unquoted one) is ever returned: a live expansion part
// (CmdSubst, ParamExp, ArithmExp, ProcSubst) is left out entirely, so a
// caller that redacts these spans can never blind itself to something that
// genuinely executes before the interpreter ever sees it.
//
// It returns spans rather than a redacted string, unlike HeredocBodies,
// because the caller (internal/analyzer/interp_heredoc_literal.go) has to
// further analyze the body text — distinguish an inert string literal from
// a command-execution call's argument — before deciding what, if anything,
// is safe to redact.
func InterpreterHeredocLiteralSpans(command string) []InterpreterHeredocSpan {
	if !strings.Contains(command, "<<") {
		return nil
	}
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return nil
	}

	var out []InterpreterHeredocSpan
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
		if !CodeInterpreters[name] {
			return true
		}
		for _, r := range st.Redirs {
			if r == nil || r.Hdoc == nil {
				continue
			}
			if r.Op != syntax.Hdoc && r.Op != syntax.DashHdoc {
				continue
			}
			for _, part := range r.Hdoc.Parts {
				lit, ok := part.(*syntax.Lit)
				if !ok {
					continue
				}
				s, e := int(lit.Pos().Offset()), int(lit.End().Offset())
				if s < 0 || e > len(command) || s >= e {
					continue
				}
				out = append(out, InterpreterHeredocSpan{Lang: name, Start: s, End: e})
			}
		}
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}
