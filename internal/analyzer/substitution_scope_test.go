package analyzer

import (
	"slices"
	"testing"
)

// Layer-2.5 half of #3706: what the ordered scope evaluator materializes.
// The engine-level assertions (which RULE ID carries the block) live in
// internal/policy/env_read_scope_test.go; these pin the mechanism, so a
// failure here says which of the five sub-fixes broke.

func TestScopeEval_CarrierInheritsPrefixBinding(t *testing.T) {
	got := runSubstitution(t, `KUBECONFIG=$HOME/.kube/config bash -c 'cat "$KUBECONFIG"'`)
	if !slices.Contains(got, "~/.kube/config") {
		t.Errorf("carrier body did not resolve the prefix binding, got %v", got)
	}
}

func TestScopeEval_CarrierInheritsExportedBinding(t *testing.T) {
	for _, cmd := range []string{
		`export P=$HOME/.ssh; bash -c 'cat "$P/id_rsa"'`,
		`declare -x P=$HOME/.ssh; sh -c 'cat "$P/id_rsa"'`,
		`export P=$HOME/.ssh; bash -lc 'cat "$P/id_rsa"'`,
		`export P=$HOME/.ssh; su -c 'cat "$P/id_rsa"'`,
	} {
		got := runSubstitution(t, cmd)
		if !slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: carrier body did not resolve the exported binding, got %v", cmd, got)
		}
	}
}

// The scope model's load-bearing negative. bash does not export an ordinary
// assignment, so the child's $P is empty and the command opens nothing.
// Folding it anyway would be a false BLOCK on a command that reads no file.
func TestScopeEval_CarrierDoesNotInheritUnexportedBinding(t *testing.T) {
	got := runSubstitution(t, `P=$HOME/.ssh; bash -c 'cat "$P/id_rsa"'`)
	if slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("unexported binding leaked into a child process, got %v", got)
	}
}

// eval is the exception: it runs in the current shell, so it sees everything.
func TestScopeEval_EvalSharesTheCurrentShell(t *testing.T) {
	got := runSubstitution(t, `P=$HOME/.ssh; eval 'cat "$P/id_rsa"'`)
	if !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("eval body did not resolve an unexported binding, got %v", got)
	}
}

func TestScopeEval_AppendConcatenates(t *testing.T) {
	got := runSubstitution(t, "P=$HOME/.ssh; P+=/id_rsa; cat $P")
	want := []string{"~/.ssh/id_rsa"}
	if !slices.Equal(got, want) {
		t.Errorf("append not applied: got %v, want %v", got, want)
	}
}

// An append to a name this command never bound starts from the INHERITED
// value. Bash yields exactly the appended text when the name is unset, which
// is what both tables model — the point of the case is that they AGREE, since
// a disagreement here is how the ordered fix and its fallback would produce
// different answers for the same command.
func TestScopeEval_AppendToUnboundNameStartsFromEmpty(t *testing.T) {
	got := runSubstitution(t, "SUFFIX=/id_rsa; P+=$SUFFIX; cat $P/x")
	want := []string{"/id_rsa/x"}
	if !slices.Equal(got, want) {
		t.Errorf("append to an unbound name = %v, want %v", got, want)
	}
}

// Ordering: the binding live at the read site is the one that counts. A
// resolver holding one value per name gets this right only by accident.
func TestScopeEval_LastBindingBeforeTheReadWins(t *testing.T) {
	got := runSubstitution(t, "P=$HOME/.ssh; P=/etc/ok; cat $P/id_rsa")
	if slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("read resolved against a superseded binding, got %v", got)
	}
	if !slices.Contains(got, "/etc/ok/id_rsa") {
		t.Errorf("read did not resolve against the live binding, got %v", got)
	}
}

// ...and in the other direction: a read BEFORE the rebinding resolves to the
// value that was live then, which the pre-#3706 flat table could not express.
func TestScopeEval_ReadBeforeRebindingUsesTheEarlierValue(t *testing.T) {
	got := runSubstitution(t, "P=$HOME/.ssh; cat $P/id_rsa; P=/etc/ok")
	if !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("read did not resolve against the binding live at its own position, got %v", got)
	}
}

func TestScopeEval_PrintfVIsABindingSource(t *testing.T) {
	got := runSubstitution(t, "printf -v P %s $HOME/.ssh; cat $P/id_rsa")
	if !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("printf -v did not bind, got %v", got)
	}
	// The attached spelling bash also accepts.
	got = runSubstitution(t, "printf -vP %s $HOME/.ssh; cat $P/id_rsa")
	if !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("printf -vNAME did not bind, got %v", got)
	}
}

// Only the exactly-foldable subset. A verb whose output this layer cannot
// reproduce, or an argument count bash would handle by REUSING the format,
// must produce no binding rather than a wrong one.
func TestScopeEval_PrintfVRefusesWhatItCannotReproduce(t *testing.T) {
	for _, cmd := range []string{
		"printf -v P %b $HOME/.ssh; cat $P/id_rsa",   // %b interprets escapes
		"printf -v P %q $HOME/.ssh; cat $P/id_rsa",   // %q quotes
		"printf -v P %s $HOME/.ssh x; cat $P/id_rsa", // more args than verbs: format reuse
		"printf -v P %s; cat $P/id_rsa",              // fewer args than verbs
	} {
		if got := runSubstitution(t, cmd); slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: folded a printf format it cannot reproduce, got %v", cmd, got)
		}
	}
}

func TestScopeEval_ReadHereStringIsABindingSource(t *testing.T) {
	got := runSubstitution(t, `read -r P <<< "$HOME/.ssh"; cat "$P/id_rsa"`)
	if !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("read -r <<< did not bind, got %v", got)
	}
}

// Multiple targets split the input on IFS across the names; modelling that
// split would be guessing at the separator. Without -r a backslash is an
// escape character, so a value carrying one is refused too.
func TestScopeEval_ReadRefusesShapesItCannotModel(t *testing.T) {
	for _, cmd := range []string{
		`read -r A B <<< "$HOME/.ssh x"; cat "$A/id_rsa"`,
		`read A <<< "$HOME/.ssh\x"; cat "$A/id_rsa"`,
		`read -a ARR <<< "$HOME/.ssh"; cat "$ARR/id_rsa"`,
	} {
		if got := runSubstitution(t, cmd); slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: bound a read shape it cannot model, got %v", cmd, got)
		}
	}
}

func TestScopeEval_IndirectExpansion(t *testing.T) {
	got := runSubstitution(t, "v=P; P=$HOME/.ssh; cat ${!v}/id_rsa")
	if !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("${!v} did not resolve through both hops, got %v", got)
	}
	// Both hops are required; with the target unbound there is nothing exact
	// to fold, and folding the first hop's own value would be a different
	// variable's content.
	if got := runSubstitution(t, "v=P; cat ${!v}/id_rsa"); len(got) != 0 {
		t.Errorf("${!v} folded with an unbound target, got %v", got)
	}
}

// The $HOME fold stands in for the home PREFIX; it is not the string bash
// holds, so an operator that TRANSFORMS the value must refuse it.
func TestScopeEval_HomeFoldRefusesTransformingOperators(t *testing.T) {
	for _, cmd := range []string{
		"cat ${HOME:0:1}Users/x/.ssh/id_rsa",
		"cat ${HOME/x/y}/.ssh/id_rsa",
		"cat ${HOME%%/*}/.ssh/id_rsa",
	} {
		if got := runSubstitution(t, cmd); len(got) != 0 {
			t.Errorf("%s: transformed the $HOME stand-in, got %v", cmd, got)
		}
	}
	// The default-family operators return the value whole, so they are fine.
	got := runSubstitution(t, "cat ${HOME:-/root}/.ssh/id_rsa")
	if !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("${HOME:-…} did not fold, got %v", got)
	}
}

// Forward references and function bodies resolve only through the
// whole-command fixed-point table, which the ordered walk keeps as a fallback.
// If that fallback is ever dropped, these are the coverage that goes with it.
func TestScopeEval_FixedPointFallbackStillResolves(t *testing.T) {
	for _, cmd := range []string{
		"P2=$P1/id_rsa; P1=$HOME/.ssh; cat $P2",
		"f() { cat $P/id_rsa; }; P=$HOME/.ssh; f",
	} {
		got := runSubstitution(t, cmd)
		if !slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: fixed-point fallback lost, got %v", cmd, got)
		}
	}
}

// Carrier recursion is bounded. Three levels is well past anything observed;
// the point is that the bound exists and the walk terminates.
func TestScopeEval_CarrierRecursionIsBounded(t *testing.T) {
	deep := `A=1 bash -c 'bash -c "bash -c \"bash -c echo\""'`
	_ = runSubstitution(t, deep) // must return, not hang or blow the stack
}

// #3743 — the adversarial pass on PR #3743 named four ways the ordered walk
// still disagreed with the shell. Three were FALSE-BLOCK sources (a value the
// shell had discarded, or one that was never in scope, resolving anyway) and
// one was fail-open. All four are pinned here at the layer that decides them;
// the engine-level rule-id assertions are in internal/policy.

// Finding 1. The fixed-point table was consulted whenever the ordered table
// said "unbound" — which is precisely when a variable has just been cleared, so
// clearing one REVIVED the value it used to hold.
func TestScopeEval_ClearedValueIsNotRevivedBySeed(t *testing.T) {
	for _, cmd := range []string{
		"V=$HOME/.ssh; V=; cat ${V:-/etc/ok}/id_rsa",
		"V=$HOME/.ssh; V=; cat ${V:=/etc/ok}/id_rsa",
		"V=$HOME/.ssh; V=; cat $V/id_rsa",
		"V=$HOME/.ssh; unset V; cat ${V:-/etc/ok}/id_rsa",
		"V=$HOME/.ssh; unset V; cat $V/id_rsa",
		"V=$HOME/.ssh; unset -v V; cat $V/id_rsa",
	} {
		if got := runSubstitution(t, cmd); slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: a discarded value came back from the fixed-point seed, got %v", cmd, got)
		}
	}
	// The control: not cleared, so the default branch is dead code and the
	// live value still resolves. Without this the case above passes on an
	// analyzer that resolves nothing at all.
	if got := runSubstitution(t, "V=$HOME/.ssh; cat ${V:-/etc/ok}/id_rsa"); !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("live value stopped resolving, got %v", got)
	}
}

// An emptied variable takes the DEFAULT branch, deterministically, because this
// command is what emptied it — so the default is folded rather than refused.
func TestScopeEval_EmptyValueTakesTheDefaultBranch(t *testing.T) {
	got := runSubstitution(t, "V=/etc/ok; V=; cat ${V:-$HOME/.ssh}/id_rsa")
	if !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("empty value did not take the default branch, got %v", got)
	}
	// `${V-word}` is the unset-ONLY form: an empty V is still set, so the
	// word is not taken and nothing resolves to it.
	if got := runSubstitution(t, "V=/etc/ok; V=; cat ${V-$HOME/.ssh}/id_rsa"); slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("${V-word} took the default for a SET-but-empty variable, got %v", got)
	}
	// `${V:?msg}` aborts the shell on an empty V, so nothing is read at all.
	if got := runSubstitution(t, "V=$HOME/.ssh; V=; cat ${V:?msg}/id_rsa"); len(got) != 0 {
		t.Errorf("folded a read the shell aborts before performing, got %v", got)
	}
}

// Finding 2. A prefix assignment is scoped to the command it prefixes. It was
// kept live afterwards "conservatively", which made a later carrier resolve a
// binding the shell starting it never had.
func TestScopeEval_PrefixAssignmentDoesNotOutliveItsStatement(t *testing.T) {
	for _, cmd := range []string{
		`V=$HOME/.ssh true; bash -c 'cat "$V/id_rsa"'`,
		`V=$HOME/.ssh true; cat $V/id_rsa`,
		`V=$HOME/.ssh true; eval 'cat "$V/id_rsa"'`,
	} {
		if got := runSubstitution(t, cmd); slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: a prefix binding outlived its own statement, got %v", cmd, got)
		}
	}
	// Controls: within its own statement it resolves, and a BARE assignment
	// (no command word) is not a prefix and does stay live.
	if got := runSubstitution(t, `V=$HOME/.ssh bash -c 'cat "$V/id_rsa"'`); !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("prefix binding stopped reaching its own command, got %v", got)
	}
	if got := runSubstitution(t, "V=$HOME/.ssh; cat $V/id_rsa"); !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("bare assignment stopped being live, got %v", got)
	}
	// An earlier bare binding is RESTORED after a prefix shadows it, not lost.
	if got := runSubstitution(t, `V=$HOME/.ssh; V=/etc/ok true; cat $V/id_rsa`); !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("prefix assignment clobbered the binding it only shadowed, got %v", got)
	}
}

// Finding 3. printf's options end at the format word (and at `--`), so a `-v`
// after either is DATA. Scanning the whole argument list read it as the binding
// option and bound a name bash never binds.
func TestScopeEval_PrintfVOnlyInTheLeadingOptionCluster(t *testing.T) {
	for _, cmd := range []string{
		"printf %s -v P $HOME/.ssh; cat $P/id_rsa",
		"printf -- -v P %s $HOME/.ssh; cat $P/id_rsa",
		"printf '%s' -v P $HOME/.ssh; cat $P/id_rsa",
	} {
		if got := runSubstitution(t, cmd); slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: read a printf DATA argument as the -v binding option, got %v", cmd, got)
		}
	}
	for _, cmd := range []string{
		"printf -v P %s $HOME/.ssh; cat $P/id_rsa",
		"printf -vP %s $HOME/.ssh; cat $P/id_rsa",
	} {
		if got := runSubstitution(t, cmd); !slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: the real binding form stopped binding, got %v", cmd, got)
		}
	}
}

// Finding 4, the fail-open one. `export V` with no `=` marks an EXISTING
// binding for the child, and the two-step spelling is the ordinary one.
func TestScopeEval_BareExportMarksAnExistingBinding(t *testing.T) {
	for _, cmd := range []string{
		`P=$HOME/.ssh; export P; bash -c 'cat "$P/id_rsa"'`,
		`P=$HOME/.ssh; declare -x P; sh -c 'cat "$P/id_rsa"'`,
		`P=$HOME/.ssh; typeset -x P; bash -c 'cat "$P/id_rsa"'`,
		`P=$HOME/.ssh; Q=/etc/ok; export Q P; bash -c 'cat "$P/id_rsa"'`,
	} {
		if got := runSubstitution(t, cmd); !slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: bare export did not reach the carrier, got %v", cmd, got)
		}
	}
	// `export -n` REMOVES the attribute, and `declare -n` is a nameref — a
	// clause carrying either says something other than "the child sees this".
	for _, cmd := range []string{
		`P=$HOME/.ssh; export -n P; bash -c 'cat "$P/id_rsa"'`,
		`P=$HOME/.ssh; declare -n P; bash -c 'cat "$P/id_rsa"'`,
		`P=$HOME/.ssh; readonly P; bash -c 'cat "$P/id_rsa"'`,
		`P=$HOME/.ssh; local P; bash -c 'cat "$P/id_rsa"'`,
	} {
		if got := runSubstitution(t, cmd); slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: a clause that does not export marked the binding anyway, got %v", cmd, got)
		}
	}
}

// #3743 pass 2 — three state-transition bugs in the walker itself. All three
// come from the same mistake in different clothes: an unconditional AST
// traversal was being read as EXECUTION, so text that bash never runs (or runs
// somewhere its effects cannot escape) changed the table anyway.

// Finding 1. A subshell's assignments cannot reach the parent, an uncalled
// function's body has not run at all, and a short-circuited branch may never
// run — so none of them may take a binding away and hide a real read.
func TestScopeEval_NestedAndSkippedCommandsCannotEraseABinding(t *testing.T) {
	for _, cmd := range []string{
		`P=$HOME/.ssh; (unset P); cat "$P/id_rsa"`,
		`P=$HOME/.ssh; (P=/etc/ok); cat "$P/id_rsa"`,
		`P=$HOME/.ssh; f() { unset P; }; cat "$P/id_rsa"`,
		`P=$HOME/.ssh; f() { P=/etc/ok; }; cat "$P/id_rsa"`,
		`P=$HOME/.ssh; false && unset P; cat "$P/id_rsa"`,
		`P=$HOME/.ssh; true || unset P; cat "$P/id_rsa"`,
		`P=$HOME/.ssh; if false; then unset P; fi; cat "$P/id_rsa"`,
		`P=$HOME/.ssh; for i in 1; do unset P; done; cat "$P/id_rsa"`,
		`P=$HOME/.ssh; case x in x) unset P;; esac; cat "$P/id_rsa"`,
		`P=$HOME/.ssh; echo hi | unset P; cat "$P/id_rsa"`,
	} {
		if got := runSubstitution(t, cmd); !slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: a nested or skipped command erased the parent binding, got %v", cmd, got)
		}
	}
}

// The other half: a TOP-LEVEL removal still removes, or the fix above would be
// "never unbind anything", which passes the cases above for the wrong reason.
func TestScopeEval_TopLevelRemovalsStillApply(t *testing.T) {
	for _, cmd := range []string{
		`P=$HOME/.ssh; unset P; cat "$P/id_rsa"`,
		`P=$HOME/.ssh; P=/etc/ok; cat "$P/id_rsa"`,
	} {
		if got := runSubstitution(t, cmd); slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: a top-level removal did not apply, got %v", cmd, got)
		}
	}
}

// Isolation contains STATE, not reads: a subshell or function body that reads a
// protected path still surfaces it.
func TestScopeEval_IsolatedRegionsStillMaterializeTheirReads(t *testing.T) {
	for _, cmd := range []string{
		`P=$HOME/.ssh; (cat "$P/id_rsa")`,
		`P=$HOME/.ssh; f() { cat "$P/id_rsa"; }; f`,
		`P=$HOME/.ssh; cat "$P/id_rsa" | base64`,
		`P=$HOME/.ssh; (P2=$P; cat "$P2/id_rsa")`,
	} {
		if got := runSubstitution(t, cmd); !slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: isolation swallowed a read, got %v", cmd, got)
		}
	}
}

// A conditional branch's WRITE is kept — the union over paths includes it, and
// keeping it can only produce a BLOCK. Without this the finding-1 fix could be
// "isolate conditionals too", which would be fail-open.
func TestScopeEval_ConditionalWritesAreKept(t *testing.T) {
	for _, cmd := range []string{
		`if true; then P=$HOME/.ssh; fi; cat "$P/id_rsa"`,
		`P=/etc/ok; if true; then P=$HOME/.ssh; fi; cat "$P/id_rsa"`,
		`true && P=$HOME/.ssh; cat "$P/id_rsa"`,
	} {
		if got := runSubstitution(t, cmd); !slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: a conditional write was discarded, got %v", cmd, got)
		}
	}
}

// Finding 2. A right-hand side is evaluated BEFORE the target is written, and
// may read the target's old value.
func TestScopeEval_AssignmentRHSReadsThePreAssignmentValue(t *testing.T) {
	for _, cmd := range []string{
		`P=$HOME/.ssh; P=$(cat "$P/id_rsa")`,
		`P=$HOME/.ssh; P=$(base64 $(cat "$P/id_rsa"))`,
		`P=$HOME/.ssh; P+=$(cat "$P/id_rsa")`,
		`P=$HOME/.ssh; Q=$(cat "$P/id_rsa")`,
		`P=$HOME/.ssh; export P=$(cat "$P/id_rsa")`,
	} {
		if got := runSubstitution(t, cmd); !slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: the read inside the RHS was lost to the target's invalidation, got %v", cmd, got)
		}
	}
}

// Finding 3. `export -n` / `declare +x` REMOVE the attribute and keep the
// value; declining to add one was not enough.
func TestScopeEval_ExportAttributeCanBeRemoved(t *testing.T) {
	for _, cmd := range []string{
		`export P=$HOME/.ssh; export -n P; bash -c 'cat "$P/id_rsa"'`,
		`export P=$HOME/.ssh; declare +x P; bash -c 'cat "$P/id_rsa"'`,
		`export P=$HOME/.ssh; typeset +x P; sh -c 'cat "$P/id_rsa"'`,
	} {
		if got := runSubstitution(t, cmd); slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: the child inherited a binding bash had un-exported, got %v", cmd, got)
		}
	}
	// The value survives an un-export, so a SAME-shell read still resolves...
	if got := runSubstitution(t, `export P=$HOME/.ssh; export -n P; cat "$P/id_rsa"`); !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("un-exporting discarded the value as well as the attribute, got %v", got)
	}
	// ...and re-exporting marks it again.
	if got := runSubstitution(t, `export P=$HOME/.ssh; export -n P; export P; bash -c 'cat "$P/id_rsa"'`); !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("re-export did not restore the attribute, got %v", got)
	}
}
