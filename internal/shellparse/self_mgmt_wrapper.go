package shellparse

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// selfMgmtSubcommands mirrors intent.go's IsSelfMgmt allowlist (the
// `agentshield\s+(?:mcp-eval|scan|setup|setup-mcp|pack|log|watchdog|update|login)`
// regex) as a set, for the AST-based check below. Duplicated rather than
// imported: analyzer already imports shellparse, so shellparse cannot import
// analyzer back — the same self-contained-copy convention buildExecSymbols
// documents for the identical constraint. Keep the two lists in sync by hand.
var selfMgmtSubcommands = map[string]bool{
	"mcp-eval": true, "scan": true, "setup": true, "setup-mcp": true,
	"pack": true, "log": true, "watchdog": true, "update": true, "login": true,
}

// selfMgmtBenignExecs are output-shaping executables tolerated inside a
// SelfMgmtWrapperFunctionNames body alongside `agentshield`. The allowlist by
// itself is not what makes the result safe — see isSelfMgmtWrapperBody's doc
// comment for the check that actually carries the soundness burden. This
// list only rules out an obviously dangerous executable (cat, curl, ssh, ...)
// from ever appearing in a qualifying body at all.
var selfMgmtBenignExecs = map[string]bool{
	"printf": true, "echo": true, "grep": true, "head": true, "tail": true,
	"cut": true, "wc": true, "sed": true,
}

// SelfMgmtWrapperFunctionNames returns the names of shell functions defined
// in command that are provably pure `agentshield <self-mgmt subcommand>`
// wrappers (#3314).
//
// # The bug this closes
//
// intent.go's IsSelfMgmt label requires the `agentshield mcp-eval` marker to
// appear in the SAME top-level statement as a sensitive literal. That holds
// for a direct call (`agentshield mcp-eval --json '{"paths":["~/.ssh/id_rsa"]}'`)
// but not once it's routed through a shell helper:
//
//	run() { printf '...' "$1" "$(agentshield mcp-eval --json "$2")"; }
//	run 'label' '{"paths":["~/.ssh/id_rsa"]}'
//
// SplitTopLevelStatements flattens the FuncDecl body into its OWN top-level
// statement (#3045), so the marker (in the definition) and the literal (in
// the call) end up as sibling statements, neither containing the other. The
// call statement's own text never satisfies IsSelfMgmt, so
// sec-block-ssh-private fires unexcused — a false positive discovered inside
// Shield's own dogfooding loop, which necessarily needs to put
// credential-shaped literals next to `mcp-eval` to exercise these rules.
//
// # Why "the function calls agentshield" is not the whole check
//
// A function is only as inert as what it does with its arguments. It is not
// enough that agentshield appears somewhere in the body:
//
//	evil() { cat "$1"; agentshield mcp-eval --arg path=/dev/null; }
//
// genuinely reads whatever path $1 carries, and `evil ~/.ssh/id_rsa` must
// still BLOCK. So a function only qualifies when BOTH hold:
//
//  1. every OTHER (non-agentshield) executable anywhere in the body is drawn
//     from selfMgmtBenignExecs;
//  2. the set of positional parameters ($1..$N, $@, $*) referenced directly
//     by the agentshield call(s) is DISJOINT from the set referenced
//     directly by every other call in the body.
//
// (2) is the load-bearing check, not (1): even an allowlisted tool becomes a
// real read if handed the SAME positional as a filename —
// `grep "$1" "$2"` where $2 is both the mcp-eval payload AND a grep operand
// would read whatever path $2 names. Requiring disjoint positional sets rules
// that out: whatever value reaches agentshield is proven to reach nothing
// else in the body.
//
// Deliberately conservative: an unrecognized executable, a dynamically-named
// one ($x "$@"), or any positional overlap disqualifies the WHOLE function,
// not just the offending call — a caller passing a credential path to such a
// function keeps BLOCKing exactly as it does today. This only ever ADDS an
// exclusion; a command with no qualifying function returns nil, identical to
// today's behavior.
func SelfMgmtWrapperFunctionNames(command string) map[string]bool {
	if !strings.Contains(command, "agentshield") {
		return nil
	}
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return nil
	}

	var out map[string]bool
	syntax.Walk(file, func(n syntax.Node) bool {
		fd, ok := n.(*syntax.FuncDecl)
		if !ok || fd.Name == nil || fd.Name.Value == "" || fd.Body == nil {
			return true
		}
		if isSelfMgmtWrapperBody(fd.Body) {
			if out == nil {
				out = map[string]bool{}
			}
			out[fd.Name.Value] = true
		}
		return true
	})
	return out
}

// isSelfMgmtWrapperBody implements the two-part check documented on
// SelfMgmtWrapperFunctionNames.
func isSelfMgmtWrapperBody(body *syntax.Stmt) bool {
	sawMarker := false
	agentshieldPositions := map[string]bool{}
	otherPositions := map[string]bool{}
	ok := true

	syntax.Walk(body, func(n syntax.Node) bool {
		if !ok {
			return false
		}
		call, isCall := n.(*syntax.CallExpr)
		if !isCall || len(call.Args) == 0 {
			return true
		}
		exe, literal := literalWordValue(call.Args[0])
		if !literal {
			// Dynamically-named executable ($x "$@") — cannot prove what it
			// does. Disqualify the whole function.
			ok = false
			return false
		}
		exe = NormalizeExecName(exe)
		positions := callPositionalRefs(call)

		switch {
		case exe == "agentshield" && callHasSelfMgmtSubcommand(call):
			sawMarker = true
			for p := range positions {
				agentshieldPositions[p] = true
			}
		case selfMgmtBenignExecs[exe]:
			for p := range positions {
				otherPositions[p] = true
			}
		default:
			// Any other executable — including "agentshield" invoked without
			// a recognized self-mgmt subcommand — disqualifies the body.
			ok = false
			return false
		}
		return true
	})

	if !ok || !sawMarker {
		return false
	}
	for p := range agentshieldPositions {
		if otherPositions[p] {
			return false
		}
	}
	return true
}

// callHasSelfMgmtSubcommand reports whether call's arguments (after the
// executable name) contain a literal token from selfMgmtSubcommands. A
// CallExpr has already separated the executable from its arguments, so a
// plain scan of Args[1:] is equivalent to intent.go's regex, which matches
// the subcommand immediately following "agentshield".
func callHasSelfMgmtSubcommand(call *syntax.CallExpr) bool {
	for _, w := range call.Args[1:] {
		if val, literal := literalWordValue(w); literal && selfMgmtSubcommands[val] {
			return true
		}
	}
	return false
}

// callPositionalRefs returns the set of positional-parameter names ($1..$N
// via bare digits, $@/$* via those literal names) referenced directly within
// call's own argument words.
//
// Deliberately stops at a nested command substitution ($(...) / `...`)
// rather than walking into it: that substitution runs a SEPARATE call, which
// the outer isSelfMgmtWrapperBody walk visits and classifies on its own. A
// caller's positional reference nested inside `"$(agentshield ... "$2")"`
// belongs to the agentshield call, not to whichever outer command's argument
// word happens to embed the substitution — printf's own args in the
// motivating #3314 example are just "$1" and that substitution, and
// attributing the nested "$2" to printf too would manufacture a false
// overlap with the agentshield call and wrongly disqualify a real wrapper.
func callPositionalRefs(call *syntax.CallExpr) map[string]bool {
	refs := map[string]bool{}
	for _, w := range call.Args {
		syntax.Walk(w, func(n syntax.Node) bool {
			switch v := n.(type) {
			case *syntax.CmdSubst:
				return false
			case *syntax.ParamExp:
				if v.Param != nil {
					refs[v.Param.Value] = true
				}
			}
			return true
		})
	}
	return refs
}

// StatementLeadingCommandName returns the first word of a single shell
// statement, quote-stripped the same way Parse's own Executable field is.
// Used by intent.go to test whether a statement is a call to a
// SelfMgmtWrapperFunctionNames result — a plain first-word check is
// sufficient there, since a real function call is always `name args...` and
// a function DEFINITION never reaches this helper (SplitTopLevelStatements
// already flattens definitions into their body statements, #3045).
// Returns "" when statement is empty, unparseable, or not a simple command.
func StatementLeadingCommandName(statement string) string {
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(statement), "")
	if err != nil || len(file.Stmts) == 0 {
		return ""
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return ""
	}
	name, literal := literalWordValue(call.Args[0])
	if !literal {
		return ""
	}
	return NormalizeExecName(name)
}
