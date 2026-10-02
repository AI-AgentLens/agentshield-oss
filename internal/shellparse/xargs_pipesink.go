package shellparse

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// XargsPipeSinkTargets returns, for every xargs invocation anywhere in
// command (a pipe sink, or the command's own leading statement), the target
// command xargs is told to run: xargs's own trailing words with xargs's
// flags — and their values, per wrapperValueFlags["xargs"] — skipped, using
// the SAME walk StripExecWrapperPrefix uses for every other wrapper
// (wrapperTargetIndex).
//
// # Why this is not just another ExecWrappers entry (#3992, follow-up to #3985/#3991)
//
// `ts-block-tar-shell-exec-flags` anchors on `^(?:sudo\s+)?tar\b` (#3982), so
// the pipeline's per-statement retry (#3045) can still catch a genuine
// invocation chained after an unrelated command — but only when tar is a
// STATEMENT's own leading word. `find . | xargs tar --to-command=sh -xf` has
// tar named on xargs's own command line, sitting behind a pipe: the anchor
// can never reach it, because tar is never the first word of ANY statement in
// that command (#3045's own doc comment: "pipe sinks are the dataflow and
// structural analyzers' job, not anchored regex's").
//
// Adding xargs to ExecWrappers was considered and rejected: every downstream
// layer (structural/semantic/dataflow/stateful) would then read xargs's
// static target as the WHOLE command's executable, discarding the fact that
// the real invocation also gets a dynamic tail of stdin items xargs appends
// at runtime — a materially different grammar from every wrapper already
// there (batching via -L/-n, per-item substitution via -I{}), and reopening
// the #3057 decision at every layer for one rule's benefit. This stays
// regex-layer-only: it feeds an ADDITIONAL text candidate into
// StatementMatchCandidates so an anchored rule can still see the literal
// command xargs's own argv names, and never changes what the AST layers call
// the executable (which stays "xargs").
//
// # What is deliberately NOT covered
//
// The extracted target text is xargs's STATIC argv only — never the dynamic
// items xargs appends from stdin/-a at runtime, which are not knowable here.
// A rule that needs one of those appended items (a filename, say) as its own
// match target is out of scope; this closes "the target program's own
// written flags name something dangerous" (tar --to-command, sort
// --compress-program, …), not "the appended item is dangerous".
func XargsPipeSinkTargets(command string) []string {
	// Cheap fast-path: StatementMatchCandidates calls this for every
	// statement form it builds, so a command with no "xargs" substring at
	// all (the overwhelming majority) must not pay for an extra AST parse.
	if !strings.Contains(command, "xargs") {
		return nil
	}
	file := parseBashFile(command)
	if file == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		if target := xargsTargetText(command, stmt); target != "" && !seen[target] {
			seen[target] = true
			out = append(out, target)
		}
		return true
	})
	return out
}

// xargsTargetText returns the target command text xargs (stmt's own call, not
// a pipe target of it) is told to run, or "" if stmt is not an xargs
// invocation with a resolvable target.
func xargsTargetText(command string, stmt *syntax.Stmt) string {
	call := leftmostCallExpr(stmt)
	if call == nil || len(call.Args) == 0 {
		return ""
	}
	words := make([]string, len(call.Args))
	for i, a := range call.Args {
		words[i] = WordToString(a)
	}
	// `find . | sudo xargs tar ...` — the privilege wrapper is not xargs
	// itself; peel it first, same as pipeTargetIsExecutor does.
	stripped := StripExecWrappers(words)
	argIdx := len(words) - len(stripped) // StripExecWrappers only trims the front
	words = stripped
	if path.Base(NormalizeExecName(words[0])) != "xargs" {
		return ""
	}
	target := wrapperTargetIndex(words)
	if target <= 0 || target >= len(words) {
		return "" // no target, or xargs itself has no trailing command
	}
	start := int(call.Args[argIdx+target].Pos().Offset())
	if start <= 0 || start > len(command) {
		return ""
	}
	text := strings.TrimSpace(command[start:])
	if text == "" || text == command {
		return ""
	}
	return text
}
