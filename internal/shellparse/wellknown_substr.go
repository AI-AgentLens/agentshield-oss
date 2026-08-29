package shellparse

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// mayContainWellKnownAbsolutePathVar is a cheap, deliberately over-approximate
// pre-check letting MaterializeAssignments skip its AST walk when the command
// text can't possibly reference a wellKnownAbsolutePathVars name — a plain
// substring test, not a parse, so it also matches names that merely CONTAIN
// one (GOPATH, NODE_PATH, LD_LIBRARY_PATH, ...). That's fine: a spurious match
// only costs one extra (harmless) walk attempt, and the exact-name check lives
// in foldWellKnownVarLeadingSlash, not here.
func mayContainWellKnownAbsolutePathVar(command string) bool {
	for name := range wellKnownAbsolutePathVars {
		if strings.Contains(command, name) {
			return true
		}
	}
	return false
}

// wellKnownAbsolutePathVars are environment variables guaranteed, in any real
// Unix shell, to hold a non-empty absolute path — so their FIRST character is
// always '/'. This is a small, deliberately conservative subset of
// unset_paramexp.go's wellKnownEnvVars (which lists names never treated as
// unset): most entries there (USER, TERM, LANG, HOSTNAME, ...) carry no
// guarantee about their first character, only that they're set. PATH and HOME
// are the two POSIX/bash always populate with an absolute path — PATH because
// command lookup depends on it, HOME because login-shell initialization sets
// it before a user's own scripts ever run. Extend this set cautiously: a wrong
// entry here doesn't just miss a detection, it fabricates a resolved path a
// real shell may never form (a false BLOCK), which is a different and worse
// failure mode than the "provably unset" fold's over-approximation.
var wellKnownAbsolutePathVars = map[string]bool{
	"PATH": true,
	"HOME": true,
}

// foldWellKnownVarLeadingSlash resolves ${VAR:0:1} to "/" for a variable in
// wellKnownAbsolutePathVars that is NOT locally assigned (a locally assigned
// scalar is already handled by appendConstPart's syms lookup ahead of this
// fallback, and takes priority — a script that does `PATH=xyz; ...${PATH:0:1}`
// reads "x", not "/").
//
// Issue #3378. NormalizeUnsetParamExp deliberately never folds PATH/HOME
// because they are never actually unset — but that exclusion only protects
// the BARE/default-value shapes, where the full (unpredictable, machine-
// specific) value would otherwise be modeled as empty. A SUBSTRING read is a
// different question: ${PATH:0:1} does not require knowing the whole value,
// only its first character, which every real shell fixes to '/'. Left
// unfolded, `cat ${PATH:0:1}etc${PATH:0:1}shadow` reads exactly the file
// sec-block-etc-shadow blocks (verified against real bash) while every
// text-matching rule and every AST-based analyzer sees only a ParamExp node,
// never the literal "/etc/shadow" — the same "guard matches pre-expansion
// text" class as the unset-splice bypass (#3206) and the constant-scalar
// indirection resolved by resolveExecWord (#3089), just via a var that is
// bound but whose full value is unknowable rather than one that is unbound.
//
// Only the EXACT offset-0/length-1 shape is safe to fold: every other
// position or length past the first character is machine-specific (PATH's
// second character could be anything) and not knowable statically. This
// mirrors FoldConstantParamOp's "exact or it does not happen" discipline
// (#3220) — a refused fold can only ever be a missed detection, never a wrong
// one.
func foldWellKnownVarLeadingSlash(part *syntax.ParamExp) (string, bool) {
	if part == nil || part.Param == nil || !wellKnownAbsolutePathVars[part.Param.Value] {
		return "", false
	}
	if part.Repl != nil || part.Exp != nil || part.Index != nil ||
		part.NestedParam != nil || part.Excl || part.Length || part.Width {
		return "", false
	}
	sl := part.Slice
	if sl == nil || sl.Offset == nil || sl.Length == nil {
		return "", false
	}
	off, ok := constArithmInt(sl.Offset)
	if !ok || off != 0 {
		return "", false
	}
	n, ok := constArithmInt(sl.Length)
	if !ok || n != 1 {
		return "", false
	}
	return "/", true
}
