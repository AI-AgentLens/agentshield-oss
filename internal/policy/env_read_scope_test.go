package policy

import (
	"strings"
	"testing"
)

// Scope- and order-aware resolution of a protected-path READ through a variable
// (#3706), the sequel to the assignment half in env_assign_consumer_test.go.
//
// #3630 shipped one guarantee: an ASSIGNMENT of a protected path into a
// designated consumer's environment slot is recorded (protected-path-consumer
// AUDIT), and the READ through that variable BLOCKs. The read half only ever
// held for a DIRECT `$VAR` expansion in the same flat statement list. Measured
// on main f6253bd9 through a binary built from that tree, with
// protected_paths ["~/.kube/**", "~/.ssh/**"]:
//
//	KUBECONFIG=$HOME/.kube/config bash -c 'cat "$KUBECONFIG"'      AUDIT (exit 0)
//	export KUBECONFIG=$HOME/.kube/config; cat ${KUBECONFIG:-…}     AUDIT (exit 0)
//	KUBECONFIG=$HOME/.kube/config; KUBECONFIG+=-prod; cat "$…"     AUDIT (exit 0)
//	printf -v KUBECONFIG %s $HOME/.kube/config; cat "$KUBECONFIG"  ALLOW (exit 0)
//	v=KUBECONFIG; KUBECONFIG=$HOME/.kube/config; cat ${!v}         AUDIT (exit 0)
//
// Fail-open class: the attestation says "no read" when a read happened.
//
// These are unit tests rather than corpus cases DELIBERATELY, for two reasons
// that both matter:
//
//   - The corpus grader compares decisions only. Every case here would pass on
//     a BLOCK produced by some unrelated rule matching the credential literal,
//     which is exactly the layer that must not be allowed to mask a regression.
//     So each case names the rule that must carry its block.
//   - Every corpus case is replayed behind ~30 wrapper prefixes by
//     TestWrapperPositionalParity and friends, and assignment-then-substitution
//     does not survive a wrapper operand (#3227/#3057). A corpus case of this
//     exact shape (TP-CLOUDCFG-ENVASSIGN-001) was removed for that reason and
//     is documented at TestProtectedEnvAssignment_ReadThroughVariableStillBlocks;
//     adding five more would be five more instances of an already-budgeted
//     46-leak gap (#3703).

func readScopeEngine(t *testing.T) *Engine {
	t.Helper()
	// The shipped defaults, so protected_paths and the consumer table are the
	// real ones rather than a fixture that could drift away from them.
	engine, err := NewEngineWithAnalyzers(DefaultPolicy(), 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	return engine
}

// homeKube is the $HOME spelling, which is the interesting one: the tilde
// spelling puts the literal in the command text where the normalizer extracts
// it as an argv path, so the EARLY protected-path check fires and the
// substitution layer is never exercised.
const homeKube = "$HOME/." + "kube/config"

// The four shapes named in #3706, plus the two extra mutations the review
// called out. Each asserts the rule id, because "it blocked" is satisfied by
// the wrong layer just as easily as by the right one.
func TestProtectedRead_ThroughScopeAndOperators(t *testing.T) {
	engine := readScopeEngine(t)

	cases := []struct{ name, cmd, wantRule string }{
		{
			// Shape 1. The body of a `-c` carrier is a quoted string in the
			// outer AST; nothing evaluated it, so the outer symbol table never
			// reached the `$KUBECONFIG` written inside it.
			"carrier body, prefix binding",
			"KUBECONFIG=" + homeKube + " bash -c 'cat \"$KUBECONFIG\"'",
			"protected-path-via-substitution",
		},
		{
			"carrier body, exported binding",
			"export KUBECONFIG=" + homeKube + "; bash -c 'cat \"$KUBECONFIG\"'",
			"protected-path-via-substitution",
		},
		{
			"carrier body, sh -c",
			"KUBECONFIG=" + homeKube + " sh -c 'cat \"$KUBECONFIG\"'",
			"protected-path-via-substitution",
		},
		{
			"carrier body, clustered -lc",
			"KUBECONFIG=" + homeKube + " bash -lc 'cat \"$KUBECONFIG\"'",
			"protected-path-via-substitution",
		},
		{
			// eval runs in THIS shell, so it sees ordinary variables too — the
			// export is not needed and must not be required.
			"eval body, unexported binding",
			"K=" + homeKube + "; eval 'cat \"$K\"'",
			"protected-path-via-substitution",
		},
		{
			// Shape 2. The variable is bound and non-empty, so the default
			// branch is dead code and the read is deterministic.
			"default expansion on a bound name",
			"export KUBECONFIG=" + homeKube + "; cat ${KUBECONFIG:-$HOME/projects/empty}",
			"protected-path-via-substitution",
		},
		{
			"assign-default expansion on a bound name",
			"export KUBECONFIG=" + homeKube + "; cat ${KUBECONFIG:=/etc/fallback}",
			"protected-path-via-substitution",
		},
		{
			"alternate expansion on a bound name",
			"export KUBECONFIG=" + homeKube + "; cat ${KUBECONFIG:+$KUBECONFIG}",
			"protected-path-via-substitution",
		},
		{
			// Shape 3. Assign.Append was discarded, so the table ended up
			// holding just "-prod" and the read folded to a harmless word.
			"append",
			"KUBECONFIG=" + homeKube + "; KUBECONFIG+=-prod; cat \"$KUBECONFIG\"",
			"protected-path-via-substitution",
		},
		{
			"append building the path in two halves",
			"P=$HOME/." + "kube; P+=/config; cat \"$P\"",
			"protected-path-via-substitution",
		},
		{
			// Shape 4. printf is on the text-only list, so its arguments were
			// never materialized — and it was not a binding source either, so
			// the whole shape was invisible. It measured ALLOW, one step BELOW
			// the AUDIT default.
			"printf -v",
			"printf -v KUBECONFIG %s " + homeKube + "; cat \"$KUBECONFIG\"",
			"protected-path-via-substitution",
		},
		{
			"printf -v with surrounding literal text in the format",
			"P=$HOME; printf -v KUBECONFIG %s/." + "kube/config \"$P\"; cat \"$KUBECONFIG\"",
			"protected-path-via-substitution",
		},
		{
			// Named as a surviving mutation of the #3703 tests.
			"indirect expansion",
			"v=KUBECONFIG; KUBECONFIG=" + homeKube + "; cat ${!v}",
			"protected-path-via-substitution",
		},
		{
			"read -r from a here-string, path composed afterwards",
			"read -r P <<< \"$HOME/." + "kube\"; cat \"$P/config\"",
			"protected-path-via-substitution",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := evalNormalized(engine, tc.cmd)
			if res.Decision != DecisionBlock {
				t.Fatalf("read of a protected path not BLOCKed: %s → %s %v",
					tc.cmd, res.Decision, res.TriggeredRules)
			}
			if !has(res.TriggeredRules, tc.wantRule) {
				t.Errorf("BLOCKed, but not by %s — another rule may be masking a regression "+
					"in the layer under test: %s → %v", tc.wantRule, tc.cmd, res.TriggeredRules)
			}
			if has(res.TriggeredRules, ProtectedPathConsumerRuleID) {
				t.Errorf("blocked command annotated 'recorded, not blocked': %s → %v", tc.cmd, res.TriggeredRules)
			}
		})
	}
}

// The false-positive half, and the reason the fix models scope rather than
// simply folding harder. Each of these names a protected path SOMEWHERE and
// still opens no protected file, so a BLOCK here would be wrong.
func TestProtectedRead_ScopeAndOrderNegatives(t *testing.T) {
	engine := readScopeEngine(t)

	cases := []struct{ name, cmd string }{
		{
			// Ordering: the last binding before the read is what the shell
			// reads. A resolver that keeps one value per name gets this right
			// only by accident.
			"reassigned to a benign path before the read",
			"V=" + homeKube + "; V=/etc/ok; cat $V",
		},
		{
			"reassigned, then appended",
			"V=" + homeKube + "; V=/etc/ok; V=$V/more; cat $V",
		},
		{
			// A child process sees the exported environment, not the parent's
			// ordinary variables. `K` was never exported, so the body reads
			// nothing — folding it would manufacture a block for a command
			// that opens no file.
			"carrier body reading an UNEXPORTED binding",
			"K=" + homeKube + "; bash -c 'cat \"$K\"'",
		},
		{
			"carrier body reading an unrelated variable",
			"CFGX=/etc/notsecret bash -c 'cat \"$CFGX\"'",
		},
		{
			// The mirror image of the default-expansion fix: the variable is
			// bound to something harmless and the protected path is only the
			// unreachable fallback.
			"protected path is the unreachable default",
			"export KUBECONFIG=/etc/ok; cat ${KUBECONFIG:-~/." + "kube/config}",
		},
		{
			// ${!v} needs BOTH hops. With the second unbound there is nothing
			// to resolve, and guessing the first hop's own value would be a
			// different variable's content.
			"indirect expansion with an unbound target",
			"v=KUBECONFIG; cat ${!v}",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := evalNormalized(engine, tc.cmd)
			if res.Decision == DecisionBlock {
				t.Errorf("false BLOCK — no protected file is opened here: %s → %v", tc.cmd, res.TriggeredRules)
			}
		})
	}
}

// The #3630 contract, restated against the new binding sources: an ASSIGNMENT
// of a protected path into a designated consumer's environment slot is a
// record, never a block — including through the two binding forms that are not
// spelled `NAME=value`.
func TestProtectedRead_AssignmentHalfStaysARecord(t *testing.T) {
	engine := readScopeEngine(t)

	cases := []struct{ name, cmd string }{
		{"printf -v into the env slot", "printf -v KUBECONFIG %s " + homeKube},
		{"prefix binding on the consumer itself", "KUBECONFIG=" + homeKube + " kubectl get pods"},
		{"prefix binding on a carrier that never reads it", "KUBECONFIG=" + homeKube + " bash -c 'echo hi'"},
		{
			// A colon-separated list is one word and matches no glob, so the
			// record was skipped entirely. KUBECONFIG is documented as a
			// list and kubectl merges every entry (#3706).
			"colon-separated list with the credential second",
			"KUBECONFIG=/etc/a:" + homeKube + "; kubectl get pods",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := evalNormalized(engine, tc.cmd)
			if res.Decision == DecisionBlock {
				t.Fatalf("assignment BLOCKed — it must never block: %s → %v", tc.cmd, res.TriggeredRules)
			}
			if !has(res.TriggeredRules, ProtectedPathConsumerRuleID) {
				t.Errorf("assignment not attributed: %s → %v", tc.cmd, res.TriggeredRules)
			}
			if !strings.Contains(strings.Join(res.Reasons, " "), "environment credential slot") {
				t.Errorf("reason does not name the environment slot: %v", res.Reasons)
			}
		})
	}
}

// The negative control for the record: names that are not credential slots
// must stay unattributed however they are bound. Without this, "attributed"
// above could be satisfied by attributing everything.
func TestProtectedRead_UnlistedNamesStayUnattributed(t *testing.T) {
	engine := readScopeEngine(t)

	for _, cmd := range []string{
		"export EDITOR=/usr/bin/vim; $EDITOR /etc/f",
		"export PATH=/usr/local/bin:$PATH; echo ok",
		"export KUBECONFIG=/etc/kube/cfg; kubectl get pods",
		"printf -v MYVAR %s " + homeKube,
		"P=" + homeKube + "; echo done",
	} {
		res := evalNormalized(engine, cmd)
		if has(res.TriggeredRules, ProtectedPathConsumerRuleID) {
			t.Errorf("attributed a non-credential binding as a consumer: %s → %v", cmd, res.TriggeredRules)
		}
		if res.Decision == DecisionBlock {
			t.Errorf("non-credential binding BLOCKed: %s → %v", cmd, res.TriggeredRules)
		}
	}
}

// Positive controls. Everything above is a claim about a CHANGE; these are the
// two behaviours that must not have moved, and their absence would make the
// whole file vacuous if the engine ever stopped blocking generally.
func TestProtectedRead_UnchangedControls(t *testing.T) {
	engine := readScopeEngine(t)

	if res := evalNormalized(engine, "cat ~/."+"kube/config"); res.Decision != DecisionBlock ||
		!has(res.TriggeredRules, "protected-path") {
		t.Errorf("direct literal read regressed: %s %v", res.Decision, res.TriggeredRules)
	}
	if res := evalNormalized(engine, "export KUBECONFIG="+homeKube+"; cat $KUBECONFIG"); res.Decision != DecisionBlock ||
		!has(res.TriggeredRules, "protected-path-via-substitution") {
		t.Errorf("direct expansion read (#3630) regressed: %s %v", res.Decision, res.TriggeredRules)
	}
	if res := evalNormalized(engine, "ssh -i ~/."+"ssh/id_ed25519 host"); res.Decision == DecisionBlock ||
		!has(res.TriggeredRules, ProtectedPathConsumerRuleID) {
		t.Errorf("flag-slot consumer regressed: %s %v", res.Decision, res.TriggeredRules)
	}
}

// The four findings from the adversarial pass on PR #3743, at the engine, with
// the rule id asserted. Three are FALSE-BLOCK fixes and one is fail-open; the
// mechanism-level cases are in internal/analyzer/substitution_scope_test.go.
//
// Measured on the pre-fix branch (4ecb516a) through a binary built from it:
// F1 `V=<prot>; V=; cat ${V:-…}` exit 2, `V=<prot>; unset V; cat $V` exit 2,
// F2 `V=<prot> true; bash -c 'cat "$V"'` exit 2,
// F3 `printf %s -v P <prot>; cat "$P"` exit 2 — all four opening no protected
// file — and F4 `V=<prot>; export V; bash -c 'cat "$V"'` exit 0, which opens one.

func TestProtectedRead_DiscardedOrOutOfScopeBindingsDoNotBlock(t *testing.T) {
	engine := readScopeEngine(t)

	cases := []struct{ name, cmd string }{
		// Finding 1 — a cleared or unset variable must not resolve to the
		// value it used to hold. The fixed-point table was consulted exactly
		// when the ordered one said "unbound", so clearing revived it.
		{"cleared, then default expansion", "V=" + homeKube + "; V=; cat ${V:-/etc/ok}"},
		{"cleared, then assign-default expansion", "V=" + homeKube + "; V=; cat ${V:=/etc/ok}"},
		{"cleared, then a plain read", "V=" + homeKube + "; V=; cat $V"},
		{"unset, then default expansion", "V=" + homeKube + "; unset V; cat ${V:-/etc/ok}"},
		{"unset, then a plain read", "V=" + homeKube + "; unset V; cat $V"},
		// Finding 2 — a prefix assignment is scoped to the command it prefixes.
		{"prefix binding, later carrier", "V=" + homeKube + " true; bash -c 'cat \"$V\"'"},
		{"prefix binding, later plain read", "V=" + homeKube + " true; cat $V"},
		// Finding 3 — printf's options end at the format word and at `--`.
		{"printf -v after the format is data", "printf %s -v P " + homeKube + "; cat \"$P\""},
		{"printf -v after -- is data", "printf -- -v P %s " + homeKube + "; cat \"$P\""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := evalNormalized(engine, tc.cmd)
			if res.Decision == DecisionBlock {
				t.Errorf("false BLOCK — no protected file is opened here: %s → %v", tc.cmd, res.TriggeredRules)
			}
		})
	}
}

// Finding 4, the fail-open one: `export V` with no `=` marks an EXISTING
// binding for the child, and the two-step spelling is the ordinary one.
func TestProtectedRead_BareExportReachesTheCarrier(t *testing.T) {
	engine := readScopeEngine(t)

	for _, cmd := range []string{
		"V=" + homeKube + "; export V; bash -c 'cat \"$V\"'",
		"V=" + homeKube + "; declare -x V; sh -c 'cat \"$V\"'",
		"V=" + homeKube + "; W=/etc/ok; export W V; bash -c 'cat \"$V\"'",
	} {
		res := evalNormalized(engine, cmd)
		if res.Decision != DecisionBlock {
			t.Fatalf("read through an exported binding not BLOCKed: %s → %s %v", cmd, res.Decision, res.TriggeredRules)
		}
		if !has(res.TriggeredRules, "protected-path-via-substitution") {
			t.Errorf("BLOCKed, but not by the layer under test: %s → %v", cmd, res.TriggeredRules)
		}
	}
	// `export -n` un-exports and `readonly` does not export at all, so the
	// child cannot see the binding and nothing is read.
	for _, cmd := range []string{
		"V=" + homeKube + "; export -n V; bash -c 'cat \"$V\"'",
		"V=" + homeKube + "; readonly V; bash -c 'cat \"$V\"'",
	} {
		if res := evalNormalized(engine, cmd); res.Decision == DecisionBlock {
			t.Errorf("false BLOCK — the child never sees this binding: %s → %v", cmd, res.TriggeredRules)
		}
	}
}

// The scoping fix must not cost the assignment RECORD: a prefix assignment into
// a consumer's environment slot still happened, and #3625 exists to cite it.
func TestProtectedRead_PrefixScopingKeepsTheConsumerRecord(t *testing.T) {
	engine := readScopeEngine(t)

	for _, cmd := range []string{
		"KUBECONFIG=" + homeKube + " kubectl get pods",
		"KUBECONFIG=" + homeKube + " bash -c 'echo hi'",
		"KUBECONFIG=" + homeKube + " true; echo done",
	} {
		res := evalNormalized(engine, cmd)
		if res.Decision == DecisionBlock {
			t.Fatalf("assignment BLOCKed: %s → %v", cmd, res.TriggeredRules)
		}
		if !has(res.TriggeredRules, ProtectedPathConsumerRuleID) {
			t.Errorf("prefix assignment lost its record: %s → %v", cmd, res.TriggeredRules)
		}
	}
}

// #3743 pass 2 — the same three state-transition bugs at the engine, with the
// rule id asserted. Two are fail-open (a real read hidden) and one is a false
// BLOCK. Measured on 508e8d36 through a binary built from it: the seven
// nested/skipped shapes and the three RHS shapes all exited 0, and
// `export P=<prot>; export -n P; bash -c 'cat "$P/config"'` exited 2.

func TestProtectedRead_NestedAndSkippedCommandsCannotHideARead(t *testing.T) {
	engine := readScopeEngine(t)

	cases := []struct{ name, cmd string }{
		{"subshell unset", "P=$HOME/." + "kube; (unset P); cat \"$P/config\""},
		{"subshell reassignment", "P=$HOME/." + "kube; (P=/etc/ok); cat \"$P/config\""},
		{"uncalled function body, unset", "P=$HOME/." + "kube; f() { unset P; }; cat \"$P/config\""},
		{"uncalled function body, reassignment", "P=$HOME/." + "kube; f() { P=/etc/ok; }; cat \"$P/config\""},
		{"short-circuited &&", "P=$HOME/." + "kube; false && unset P; cat \"$P/config\""},
		{"short-circuited ||", "P=$HOME/." + "kube; true || unset P; cat \"$P/config\""},
		{"if branch", "P=$HOME/." + "kube; if false; then unset P; fi; cat \"$P/config\""},
		// Finding 2: the RHS runs against the pre-assignment environment.
		{"command substitution in its own RHS", "P=$HOME/." + "kube; P=$(cat \"$P/config\")"},
		{"nested command substitution in the RHS", "P=$HOME/." + "kube; P=$(base64 $(cat \"$P/config\"))"},
		{"append RHS", "P=$HOME/." + "kube; P+=$(cat \"$P/config\")"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := evalNormalized(engine, tc.cmd)
			if res.Decision != DecisionBlock {
				t.Fatalf("protected read hidden by a state transition: %s → %s %v",
					tc.cmd, res.Decision, res.TriggeredRules)
			}
			if !has(res.TriggeredRules, "protected-path-via-substitution") {
				t.Errorf("BLOCKed, but not by the layer under test: %s → %v", tc.cmd, res.TriggeredRules)
			}
		})
	}
}

// The other side of finding 1: a top-level removal must still remove, or the
// fix degenerates into "never unbind" and the cases above pass vacuously.
func TestProtectedRead_TopLevelRemovalsStillApply(t *testing.T) {
	engine := readScopeEngine(t)
	for _, cmd := range []string{
		"P=$HOME/." + "kube; unset P; cat \"$P/config\"",
		"P=$HOME/." + "kube; P=/etc/ok; cat \"$P/config\"",
	} {
		if res := evalNormalized(engine, cmd); res.Decision == DecisionBlock {
			t.Errorf("false BLOCK — this binding really is gone: %s → %v", cmd, res.TriggeredRules)
		}
	}
}

// Finding 3: `export -n` removes the attribute, so the child no longer sees the
// binding — and the value survives for a same-shell read.
func TestProtectedRead_ExportRemovalIsModelled(t *testing.T) {
	engine := readScopeEngine(t)

	for _, cmd := range []string{
		"export P=$HOME/." + "kube; export -n P; bash -c 'cat \"$P/config\"'",
		"export P=$HOME/." + "kube; declare +x P; bash -c 'cat \"$P/config\"'",
	} {
		if res := evalNormalized(engine, cmd); res.Decision == DecisionBlock {
			t.Errorf("false BLOCK — bash took this binding away from the child: %s → %v", cmd, res.TriggeredRules)
		}
	}
	// Controls in both directions: exported reaches the child, the value
	// survives an un-export for a same-shell read, and re-exporting restores.
	for _, cmd := range []string{
		"export P=$HOME/." + "kube; bash -c 'cat \"$P/config\"'",
		"export P=$HOME/." + "kube; export -n P; cat \"$P/config\"",
		"export P=$HOME/." + "kube; export -n P; export P; bash -c 'cat \"$P/config\"'",
	} {
		res := evalNormalized(engine, cmd)
		if res.Decision != DecisionBlock {
			t.Fatalf("read not BLOCKed: %s → %s %v", cmd, res.Decision, res.TriggeredRules)
		}
		if !has(res.TriggeredRules, "protected-path-via-substitution") {
			t.Errorf("BLOCKed, but not by the layer under test: %s → %v", cmd, res.TriggeredRules)
		}
	}
}

// #3752 pass 3 — six scope-walker bypasses at the engine, with the rule id
// asserted, plus the false BLOCK that came with them. Measured on 1ee76fb0
// through a binary built from that tree: all six of the shapes below exited 0
// (the read was invisible), and the `printf -v` sequence exited 2 on a command
// that opens nothing.
//
// The seventh finding is a COST, not a decision: `V1=$(V2=$(…))` was walked
// twice per nesting level, so 22 levels of a 148-byte command took 2.8s inside
// a synchronous IDE hook. It is pinned in
// internal/analyzer/substitution_scope_test.go's round-3 file, where the walk
// itself can be timed without the rest of the pipeline's noise.

// homeKubeDir is the DIRECTORY spelling: these cases bind the directory and
// compose the file at the read site, which is the shape the round-3
// reproducers used.
const homeKubeDir = "$HOME/." + "kube"

func TestProtectedRead_ScopeWalkerBypassesRound3(t *testing.T) {
	engine := readScopeEngine(t)

	cases := []struct{ name, cmd string }{
		{
			// A branch that may not run cannot OVERWRITE a binding either.
			// Suppressing only removals left `false && P=/tmp` replacing the
			// protected value outright.
			"skipped && branch overwrites",
			"P=" + homeKubeDir + "; false && P=/tmp; cat \"$P/config\"",
		},
		{
			"skipped if branch overwrites",
			"P=" + homeKubeDir + "; if false; then P=/tmp; fi; cat \"$P/config\"",
		},
		{
			// The export ATTRIBUTE is state too.
			"skipped branch un-exports",
			"export P=" + homeKubeDir + "; false && export -n P; bash -c 'cat \"$P/config\"'",
		},
		{
			// `$(…)` runs in a child shell; its unset cannot reach the parent.
			"command substitution unsets",
			"P=" + homeKubeDir + "; Q=$(unset P); cat \"$P/config\"",
		},
		{
			"command substitution reassigns",
			"P=" + homeKubeDir + "; Q=$(P=/tmp); cat \"$P/config\"",
		},
		{
			// Each pipeline component has its own environment.
			"pipeline component reassigns",
			"P=" + homeKubeDir + "; P=/tmp | cat \"$P/config\"",
		},
		{
			// eval runs in THIS shell, so inside a subshell its mutation is
			// undone with that subshell.
			"eval inside a subshell unsets",
			"P=" + homeKubeDir + "; (eval 'unset P'); cat \"$P/config\"",
		},
		{
			// bash expands argv BEFORE performing the prefix assignment.
			"prefix assignment shadows its own argv",
			"P=" + homeKubeDir + "; P=/tmp cat \"$P/config\"",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := evalNormalized(engine, tc.cmd)
			if res.Decision != DecisionBlock {
				t.Fatalf("protected read hidden by a scope-walker disagreement: %s → %s %v",
					tc.cmd, res.Decision, res.TriggeredRules)
			}
			if !has(res.TriggeredRules, "protected-path-via-substitution") {
				t.Errorf("BLOCKed, but not by the layer under test: %s → %v", tc.cmd, res.TriggeredRules)
			}
		})
	}
}

// The other direction. Each of these really does destroy the binding (or never
// makes it), so a BLOCK is a false positive — and without them every fix above
// is satisfied by "never let anything change the table".
func TestProtectedRead_Round3CurrentShellMutationsStillApply(t *testing.T) {
	engine := readScopeEngine(t)

	cases := []struct{ name, cmd string }{
		{
			// `printf -v` with a format this layer cannot reproduce still
			// EXECUTED: bash overwrote the target. Leaving the previous value
			// in place produced a BLOCK on a command that opens nothing.
			"printf -v overwritten by an unfoldable format",
			"printf -v P %s " + homeKubeDir + "; printf -v P %d 42; cat \"$P/config\"",
		},
		{
			"printf -v %q over a protected value",
			"P=" + homeKubeDir + "; printf -v P %q x; cat \"$P/config\"",
		},
		{
			// A brace group is not a subshell: it runs in the current shell.
			"brace group unsets",
			"P=" + homeKubeDir + "; { unset P; }; cat \"$P/config\"",
		},
		{
			"brace group reassigns",
			"P=" + homeKubeDir + "; { P=/tmp; }; cat \"$P/config\"",
		},
		{
			// A subshell's assignment does not escape, so nothing is bound
			// after it — and the fixed-point seed must not supply it either.
			"subshell assignment does not escape",
			"(P=" + homeKubeDir + "); cat \"$P/config\"",
		},
		{
			"pipeline component assignment does not escape",
			"P=" + homeKubeDir + " | true; cat \"$P/config\"",
		},
		{
			// Argv is expanded before the prefix assignment, so with no
			// earlier binding cat receives "/config".
			"prefix assignment cannot reach its own argv",
			"P=" + homeKubeDir + " cat \"$P/config\"",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := evalNormalized(engine, tc.cmd)
			if res.Decision == DecisionBlock {
				t.Errorf("false BLOCK — no protected file is opened here: %s → %v", tc.cmd, res.TriggeredRules)
			}
		})
	}
}

// The conservative merge keeps BOTH values a conditional could leave, so a
// branch that replaces a protected binding with a benign one still resolves the
// protected path. That is the same asymmetry the removal rule already had
// (`P=<prot>; true || unset P` blocks); it is asserted here so the trade-off is
// visible and a future change to it is deliberate rather than accidental.
func TestProtectedRead_ConditionalOverwriteStaysConservative(t *testing.T) {
	engine := readScopeEngine(t)
	cmd := "P=" + homeKubeDir + "; if true; then P=/tmp; fi; cat \"$P/config\""
	res := evalNormalized(engine, cmd)
	if res.Decision != DecisionBlock {
		t.Fatalf("the pre-branch value stopped resolving: %s → %s %v", cmd, res.Decision, res.TriggeredRules)
	}
	if !has(res.TriggeredRules, "protected-path-via-substitution") {
		t.Errorf("BLOCKed, but not by the layer under test: %s → %v", cmd, res.TriggeredRules)
	}
}
