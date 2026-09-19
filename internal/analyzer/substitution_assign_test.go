package analyzer

import (
	"slices"
	"testing"
)

// Assign materialization (#3630, environment half).
//
// The substitution analyzer built a symbol table from `NAME=value` nodes and
// then threw the names away — it published only what the VALUES resolved
// inside CallExpr args, redirects and test operands. `export
// KUBECONFIG=$HOME/.kube/config` has none of those, so the binding was
// invisible to everything downstream and the engine had nothing to attribute.
//
// Two properties, and the second matters as much as the first:
//   - the binding is published (name AND resolved value), and
//   - it is published on a SEPARATE field from MaterializedPaths, because
//     MaterializedPaths is what the engine blocks on and an assignment must
//     never block. `P=~/.kube/config` alone has always been allowed.

func runAssignments(t *testing.T, command string) []Assignment {
	t.Helper()
	ctx := &AnalysisContext{RawCommand: command}
	a := NewSubstitutionAnalyzer()
	if findings := a.Analyze(ctx); len(findings) != 0 {
		t.Fatalf("substitution analyzer should not emit findings, got %d", len(findings))
	}
	return ctx.Assignments
}

func assignmentValue(assigns []Assignment, name string) (string, bool) {
	for _, a := range assigns {
		if a.Name == name {
			return a.Value, true
		}
	}
	return "", false
}

func TestSubstitution_PublishesResolvedAssignments(t *testing.T) {
	kube := "~/." + "kube/config"

	cases := []struct {
		name    string
		command string
		varName string
		want    string
	}{
		{"export with tilde", "export KUBECONFIG=" + kube, "KUBECONFIG", kube},
		{"export with $HOME", "export KUBECONFIG=$HOME/." + "kube/config", "KUBECONFIG", kube},
		{"export with ${HOME}", "export KUBECONFIG=${HOME}/." + "kube/config", "KUBECONFIG", kube},
		{"export double-quoted", `export KUBECONFIG="` + kube + `"`, "KUBECONFIG", kube},
		{"export single-quoted", `export KUBECONFIG='` + kube + `'`, "KUBECONFIG", kube},
		{"bare assignment", "KUBECONFIG=" + kube, "KUBECONFIG", kube},
		{"prefix assignment", "KUBECONFIG=" + kube + " kubectl get pods", "KUBECONFIG", kube},
		{"declare", "declare KUBECONFIG=" + kube, "KUBECONFIG", kube},
		{"chained through a temp var", "K=$HOME/." + "kube; export KUBECONFIG=$K/config", "KUBECONFIG", kube},
		{"non-path value", "export EDITOR=vim", "EDITOR", "vim"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := assignmentValue(runAssignments(t, tc.command), tc.varName)
			if !ok {
				t.Fatalf("%s not published for %q; got %v", tc.varName, tc.command, runAssignments(t, tc.command))
			}
			if got != tc.want {
				t.Fatalf("%s = %q, want %q (%s)", tc.varName, got, tc.want, tc.command)
			}
		})
	}
}

// The separation is the safety property: an assignment publishes a binding,
// never a path the engine can block on. If these two ever merge, `export
// KUBECONFIG=~/.kube/config` becomes a BLOCK and every kubeconfig-switching
// workflow breaks.
func TestSubstitution_AssignmentIsNotAMaterializedPath(t *testing.T) {
	kube := "~/." + "kube/config"
	for _, cmd := range []string{
		"export KUBECONFIG=" + kube,
		"export KUBECONFIG=$HOME/." + "kube/config",
		"KUBECONFIG=" + kube,
		"P=$HOME/." + "kube/config",
	} {
		ctx := &AnalysisContext{RawCommand: cmd}
		if findings := NewSubstitutionAnalyzer().Analyze(ctx); len(findings) != 0 {
			t.Fatalf("substitution analyzer emitted findings for %q", cmd)
		}
		if slices.Contains(ctx.MaterializedPaths, kube) {
			t.Errorf("assignment leaked into MaterializedPaths (would BLOCK): %s → %v", cmd, ctx.MaterializedPaths)
		}
		if len(ctx.Assignments) == 0 {
			t.Errorf("assignment not published at all: %s", cmd)
		}
	}
	// ...while a READ through the same variable still materializes, which is
	// what keeps `export KUBECONFIG=…; cat $KUBECONFIG` a BLOCK.
	ctx := &AnalysisContext{RawCommand: "export KUBECONFIG=$HOME/." + "kube/config; cat $KUBECONFIG"}
	NewSubstitutionAnalyzer().Analyze(ctx)
	if !slices.Contains(ctx.MaterializedPaths, kube) {
		t.Fatalf("read through the variable did not materialize: %v", ctx.MaterializedPaths)
	}
}

// Unresolvable and empty right-hand sides publish nothing rather than
// publishing a half-folded string a path check could misread.
func TestSubstitution_UnresolvableAssignmentsArePublishedAsNothing(t *testing.T) {
	for _, cmd := range []string{
		"export KUBECONFIG=$(cat /tmp/which-cluster)",
		"export KUBECONFIG=$UNBOUND_PREFIX/config",
		"export KUBECONFIG=",
	} {
		for _, a := range runAssignments(t, cmd) {
			if a.Name == "KUBECONFIG" {
				t.Errorf("published an unresolvable binding %q = %q for %s", a.Name, a.Value, cmd)
			}
		}
	}
}

// Map range order is randomised; the engine names ONE variable in the audit
// reason, so the published order must not be.
func TestSubstitution_AssignmentsAreDeterministicallyOrdered(t *testing.T) {
	cmd := "A=1; B=2; C=3; D=4; E=5; KUBECONFIG=~/." + "kube/config; Z=9"
	first := runAssignments(t, cmd)
	for i := 0; i < 20; i++ {
		got := runAssignments(t, cmd)
		if len(got) != len(first) {
			t.Fatalf("assignment count varies between runs: %d vs %d", len(got), len(first))
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("assignment order varies between runs at %d: %v vs %v", j, got[j], first[j])
			}
		}
	}
	if !slices.IsSortedFunc(first, func(a, b Assignment) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		default:
			return 0
		}
	}) {
		t.Fatalf("assignments are not sorted by name: %v", first)
	}
}
