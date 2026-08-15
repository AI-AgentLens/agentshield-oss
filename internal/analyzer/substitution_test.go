package analyzer

import (
	"slices"
	"sort"
	"strings"
	"testing"
)

// runSubstitution is a thin helper so each test reads as "given this command
// string, what materialized paths fall out?" — keeps the table dense.
func runSubstitution(t *testing.T, command string) []string {
	t.Helper()
	ctx := &AnalysisContext{RawCommand: command}
	a := NewSubstitutionAnalyzer()
	if findings := a.Analyze(ctx); len(findings) != 0 {
		t.Fatalf("substitution analyzer should not emit findings, got %d", len(findings))
	}
	out := append([]string(nil), ctx.MaterializedPaths...)
	sort.Strings(out)
	return out
}

func TestSubstitutionAnalyzer_JosephSplitConcat(t *testing.T) {
	// The exact attack reported via Joseph: assemble ~/.ssh/id_rsa from two
	// vars and concatenate at use site. This is the regression-proof case
	// for #1698.
	got := runSubstitution(t, "P1=~/.ssh; P2=id_rsa; cat $P1/$P2")
	want := []string{"~/.ssh/id_rsa"}
	if !slices.Equal(got, want) {
		t.Errorf("materialized paths = %v, want %v", got, want)
	}
}

func TestSubstitutionAnalyzer_BraceSyntax(t *testing.T) {
	// `${P1}/${P2}` should resolve identically to the bare-dollar form. The
	// engine treats both as the same ParamExp shape.
	got := runSubstitution(t, "P1=~/.ssh; P2=id_rsa; cat ${P1}/${P2}")
	want := []string{"~/.ssh/id_rsa"}
	if !slices.Equal(got, want) {
		t.Errorf("materialized paths = %v, want %v", got, want)
	}
}

func TestSubstitutionAnalyzer_ChainedVars(t *testing.T) {
	// P2's RHS references P1. The fixed-point iteration must resolve P1
	// first, then come back to P2 on a subsequent pass. If this regresses,
	// the iteration is broken — chained obfuscation will silently bypass.
	got := runSubstitution(t, "P1=~/.ssh; P2=$P1/id_rsa; cat $P2")
	wantContains := "~/.ssh/id_rsa"
	if !slices.Contains(got, wantContains) {
		t.Errorf("expected materialized path containing %q, got %v", wantContains, got)
	}
}

func TestSubstitutionAnalyzer_SingleVarFullPath(t *testing.T) {
	// The whole sensitive path lives in one var. The literal regex layer
	// also catches this, but Layer 2.5 should still surface the materialized
	// form so the engine's protected-path check has a chance.
	got := runSubstitution(t, "X=~/.ssh/id_rsa; cat $X")
	want := []string{"~/.ssh/id_rsa"}
	if !slices.Equal(got, want) {
		t.Errorf("materialized paths = %v, want %v", got, want)
	}
}

func TestSubstitutionAnalyzer_DoubleQuotedSubstitution(t *testing.T) {
	// `"$P1/$P2"` — ParamExp inside DblQuoted. The recursive walk in
	// appendPart needs to handle the nested case.
	got := runSubstitution(t, `P1=~/.ssh; P2=id_rsa; cat "$P1/$P2"`)
	want := []string{"~/.ssh/id_rsa"}
	if !slices.Equal(got, want) {
		t.Errorf("materialized paths = %v, want %v", got, want)
	}
}

func TestSubstitutionAnalyzer_UnknownVarSkipped(t *testing.T) {
	// $UNDEFINED can't be materialized. The materialization should bail
	// rather than emit a partial string like "/file" — partial outputs would
	// be footguns for the engine's path matcher.
	got := runSubstitution(t, "cat $UNDEFINED/file")
	if len(got) != 0 {
		t.Errorf("expected no materialized paths for unknown var, got %v", got)
	}
}

func TestSubstitutionAnalyzer_PartialResolutionSkipped(t *testing.T) {
	// Mix of resolvable and unresolvable vars in the same arg. If we can't
	// resolve every part, we must skip — emitting "~/.ssh/" with the second
	// var dropped would be misleading and could cause false BLOCKs.
	got := runSubstitution(t, "P1=~/.ssh; cat $P1/$UNKNOWN")
	if len(got) != 0 {
		t.Errorf("expected no materialized paths when one var is unknown, got %v", got)
	}
}

func TestSubstitutionAnalyzer_PureLiteralArgsSkipped(t *testing.T) {
	// `cat /tmp/foo` has no ParamExp — there's nothing to materialize. The
	// output should be empty so the engine doesn't waste cycles re-checking
	// paths the regular `paths` slice already covered.
	got := runSubstitution(t, "cat /tmp/foo")
	if len(got) != 0 {
		t.Errorf("expected no materialized paths for pure-literal args, got %v", got)
	}
}

func TestSubstitutionAnalyzer_NoAssignmentsAtAll(t *testing.T) {
	// Defensive: a command with no `Name=value` segment must short-circuit
	// before walking args, or we'd emit every literal arg.
	got := runSubstitution(t, "ls -la /tmp")
	if len(got) != 0 {
		t.Errorf("expected no materialized paths for command without assignments, got %v", got)
	}
}

func TestSubstitutionAnalyzer_DefaultExpansionNotFolded(t *testing.T) {
	// `${VAR:-default}` is a shape we explicitly refuse to fold — the
	// runtime semantics depend on whether VAR is set. Test with a *known*
	// var so we know we're refusing on shape, not on lookup miss.
	got := runSubstitution(t, "P1=~/.ssh; cat ${P1:-/tmp}/id_rsa")
	if len(got) != 0 {
		t.Errorf("expected no materialized paths for ${VAR:-default} shape, got %v", got)
	}
}

func TestSubstitutionAnalyzer_CmdSubstNotFolded(t *testing.T) {
	// Command substitution as the assignment value — Layer 2.5 doesn't
	// execute, so it can't know the value. The decoder fold extension
	// (#1699) plugs in here later.
	got := runSubstitution(t, "P=$(echo ~/.ssh); cat $P/id_rsa")
	if len(got) != 0 {
		t.Errorf("expected no materialized paths when assign value is CmdSubst, got %v", got)
	}
}

func TestSubstitutionAnalyzer_SingleQuotedAssignmentLiteral(t *testing.T) {
	// `P='~/.ssh'` — single-quoted strings are entirely literal in bash, so
	// the value should be `~/.ssh` (tilde included as a literal char). This
	// matches bash semantics: tilde expansion only happens unquoted.
	got := runSubstitution(t, "P='~/.ssh'; F='id_rsa'; cat $P/$F")
	want := []string{"~/.ssh/id_rsa"}
	if !slices.Equal(got, want) {
		t.Errorf("materialized paths = %v, want %v", got, want)
	}
}

func TestSubstitutionAnalyzer_DedupesMaterializedPaths(t *testing.T) {
	// Multiple references to the same var should produce one path, not N.
	// Avoids blowing up the engine's protected-path scan for repetitive
	// commands.
	got := runSubstitution(t, "P=~/.ssh/id_rsa; cat $P; ls $P; head $P")
	want := []string{"~/.ssh/id_rsa"}
	if !slices.Equal(got, want) {
		t.Errorf("materialized paths = %v, want %v (no dupes)", got, want)
	}
}

func TestSubstitutionAnalyzer_AppendsToExistingPaths(t *testing.T) {
	// If ctx.MaterializedPaths is pre-populated (e.g., a future analyzer
	// stage adds entries), Layer 2.5 should append, not overwrite.
	ctx := &AnalysisContext{
		RawCommand:        "P1=~/.ssh; P2=id_rsa; cat $P1/$P2",
		MaterializedPaths: []string{"/seeded/path"},
	}
	NewSubstitutionAnalyzer().Analyze(ctx)
	if !slices.Contains(ctx.MaterializedPaths, "/seeded/path") {
		t.Errorf("expected pre-populated path to survive, got %v", ctx.MaterializedPaths)
	}
	if !slices.Contains(ctx.MaterializedPaths, "~/.ssh/id_rsa") {
		t.Errorf("expected new materialized path appended, got %v", ctx.MaterializedPaths)
	}
}

func TestSubstitutionAnalyzer_EmptyCommandDoesNothing(t *testing.T) {
	ctx := &AnalysisContext{RawCommand: ""}
	a := NewSubstitutionAnalyzer()
	if findings := a.Analyze(ctx); len(findings) != 0 {
		t.Errorf("expected no findings for empty command, got %d", len(findings))
	}
	if len(ctx.MaterializedPaths) != 0 {
		t.Errorf("expected no materialized paths for empty command, got %v", ctx.MaterializedPaths)
	}
}

func TestSubstitutionAnalyzer_MalformedCommandStaysSilent(t *testing.T) {
	// Unclosed quote — mvdan.cc/sh returns a parse error. Layer 2.5 must
	// not panic and must not emit anything. Other layers (regex fallback)
	// still see the raw text.
	ctx := &AnalysisContext{RawCommand: `cat "unclosed`}
	NewSubstitutionAnalyzer().Analyze(ctx)
	if len(ctx.MaterializedPaths) != 0 {
		t.Errorf("expected no materialized paths on parse failure, got %v", ctx.MaterializedPaths)
	}
}

// TestSubstitutionAnalyzer_DeclClauseBinding covers #3203: declare/export/
// typeset/readonly/local parse as *syntax.DeclClause, not a CallExpr carrying
// Assigns, so a walker keyed on CallExpr alone (as buildSymbolTable was)
// never sees the binding. Mirrors shellparse's TestDeclClauseBindingParity
// for the executable-position resolver (#3299), for the path-materialization
// walker.
func TestSubstitutionAnalyzer_DeclClauseBinding(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want []string
	}{
		{
			name: "declare-bound pair",
			cmd:  "declare P1=~/.ssh; declare P2=id_rsa; cat $P1/$P2",
			want: []string{"~/.ssh/id_rsa"},
		},
		{
			name: "export-bound pair",
			cmd:  "export P1=~/.ssh; export P2=id_rsa; cat $P1/$P2",
			want: []string{"~/.ssh/id_rsa"},
		},
		{
			name: "typeset-bound pair",
			cmd:  "typeset P1=~/.ssh; typeset P2=id_rsa; cat $P1/$P2",
			want: []string{"~/.ssh/id_rsa"},
		},
		{
			name: "readonly-bound pair",
			cmd:  "readonly P1=~/.ssh; readonly P2=id_rsa; cat $P1/$P2",
			want: []string{"~/.ssh/id_rsa"},
		},
		{
			name: "local-bound pair",
			cmd:  "local P1=~/.ssh; local P2=id_rsa; cat $P1/$P2",
			want: []string{"~/.ssh/id_rsa"},
		},
		{
			name: "mixed declare + plain assignment",
			cmd:  "typeset P1=~/.ssh; P2=id_rsa; cat $P1/$P2",
			want: []string{"~/.ssh/id_rsa"},
		},
		{
			name: "nameref must not resolve",
			cmd:  "declare -n P1=OTHER; cat $P1/id_rsa",
			want: nil,
		},
		{
			name: "naked re-export binds nothing",
			cmd:  "declare -x P1; cat $P1/id_rsa",
			want: nil,
		},
		{
			name: "benign declare-bound path stays unresolved-to-nothing-sensitive",
			cmd:  "declare D=/tmp; declare F=hello.txt; cat $D/$F",
			want: []string{"/tmp/hello.txt"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := runSubstitution(t, tc.cmd)
			if !slices.Equal(got, tc.want) {
				t.Errorf("materialized paths = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSubstitutionAnalyzer_AndChainedAssignments(t *testing.T) {
	// `&&` separator instead of `;` — same shape, different operator. The
	// AST walker should treat both as compound statements.
	got := runSubstitution(t, "P1=~/.ssh && P2=id_rsa && cat $P1/$P2")
	// Note: `P1=~/.ssh && ...` parses as a CallExpr with Assigns AND a
	// BinaryCmd with the && operator. As long as walk visits the assigns,
	// resolution should work.
	if !slices.ContainsFunc(got, func(s string) bool { return strings.Contains(s, "~/.ssh/id_rsa") }) {
		t.Errorf("expected ~/.ssh/id_rsa in materialized paths for && chain, got %v", got)
	}
}

// TestSubstitutionAnalyzer_ParamOpConstantFold covers #3220: a parameter-
// expansion OPERATOR (replace, slice, prefix/suffix removal, case change)
// applied to a variable already bound to a constant is itself statically
// computable — `p=/etc/shadQow; cat ${p/Q/}` reads /etc/shadow on every
// shell. Mirrors the executable-position fold TestParamOpConstantFoldResolution
// (internal/shellparse) covers for resolveExecParamExp.
func TestSubstitutionAnalyzer_ParamOpConstantFold(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want []string
	}{
		{
			name: "replace operator folds a spliced path",
			cmd:  "p=/etc/shadQow; cat ${p/Q/}",
			want: []string{"/etc/shadow"},
		},
		{
			name: "slice operator folds a padded path",
			cmd:  "p=/etc/shadowZZZ; cat ${p:0:11}",
			want: []string{"/etc/shadow"},
		},
		{
			name: "suffix removal operator folds",
			cmd:  "p=/etc/shadow.bak; cat ${p%.bak}",
			want: []string{"/etc/shadow"},
		},
		{
			name: "unbound variable with operator stays unresolved",
			cmd:  "cat ${UNKNOWN/Q/}",
			want: nil,
		},
		{
			name: "glob pattern operand is refused, not interpreted",
			cmd:  "p=/etc/shXdow; cat ${p/[A-Z]/}",
			want: nil,
		},
		{
			name: "array literal assignment is not a scalar binding, stays unresolved",
			cmd:  "a=(/etc/shadow); cat ${a[0]}",
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := runSubstitution(t, tc.cmd)
			if !slices.Equal(got, tc.want) {
				t.Errorf("materialized paths = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSubstitutionAnalyzer_RedirectAndTestClause covers #3325: a split-concat
// path materializable only through a Redirect target or a `[[ ... ]]` test
// operand — never appearing as a CallExpr argument at all — was invisible to
// materializeArgs before this fix, so ctx.MaterializedPaths stayed empty and
// engine.go's protected-path-via-substitution post-pass never fired. Verified
// end-to-end (not just at this layer): before the fix, `cat < $P1/$P2`
// evaluated to AUDIT against the default policy while the CallExpr-arg form
// `cat $P1/$P2` correctly evaluated to BLOCK.
func TestSubstitutionAnalyzer_RedirectAndTestClause(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want []string
	}{
		{
			name: "input redirect target, no CallExpr arg carries the path",
			cmd:  "P1=~/.ssh; P2=id_rsa; cat < $P1/$P2",
			want: []string{"~/.ssh/id_rsa"},
		},
		{
			name: "output redirect target",
			cmd:  "P1=~/.ssh; P2=leaked; echo pwned > $P1/$P2",
			want: []string{"~/.ssh/leaked"},
		},
		{
			name: "redirect on a loop with no CallExpr arg at all",
			cmd:  `P1=~/.ssh; P2=id_rsa; while read -r line; do echo "$line"; done < $P1/$P2`,
			want: []string{"~/.ssh/id_rsa"},
		},
		{
			name: "testclause unary operand",
			cmd:  "P1=~/.ssh; P2=id_rsa; [[ -f $P1/$P2 ]] && echo found",
			want: []string{"~/.ssh/id_rsa"},
		},
		{
			name: "testclause binary operand, both sides",
			cmd:  "P1=~/.ssh; P2=id_rsa; A=other; [[ $P1/$P2 == $A ]] && echo match",
			want: []string{"other", "~/.ssh/id_rsa"},
		},
		{
			name: "testclause wrapped in parens",
			cmd:  "P1=~/.ssh; P2=id_rsa; [[ ( -f $P1/$P2 ) ]] && echo found",
			want: []string{"~/.ssh/id_rsa"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := runSubstitution(t, tc.cmd)
			if !slices.Equal(got, tc.want) {
				t.Errorf("materialized paths = %v, want %v", got, tc.want)
			}
		})
	}
}
