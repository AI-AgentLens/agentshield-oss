package analyzer

import (
	"path"
	"slices"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// Ordered scope evaluation for Layer 2.5 (issue #3706).
//
// # What was wrong with a single flat symbol table
//
// buildSymbolTable collects every `Name=value` in the command and iterates to a
// fixed point, producing ONE map with ONE value per name. That model has no
// notion of "when", and four deterministic readers of a protected file slipped
// through the hole that leaves:
//
//	KUBECONFIG=$HOME/.kube/config bash -c 'cat "$KUBECONFIG"'   the carrier body
//	                                                            is a quoted string,
//	                                                            never evaluated
//	export KUBECONFIG=$HOME/.kube/config; cat ${KUBECONFIG:-…}   default expansion
//	                                                            refused on shape
//	KUBECONFIG=…; KUBECONFIG+=-prod; cat "$KUBECONFIG"          Assign.Append
//	                                                            discarded — the map
//	                                                            ended up holding
//	                                                            just "-prod"
//	printf -v KUBECONFIG %s $HOME/.kube/config; cat "$KUBECONFIG"  not a binding
//	                                                               source at all
//
// The first three are order problems (a value that exists only at a point in
// the statement stream), the fourth is a vocabulary problem. scopeEval fixes
// both: it threads a symbol table through the AST in SOURCE ORDER, so a word is
// materialized against the bindings that are live where it is written, and it
// knows the binding forms that are not `Name=value`.
//
// # Why the flat table is still built
//
// scopeEval is strictly ordered, so it cannot resolve a value that only becomes
// known LATER — a forward reference (`P2=$P1/x; P1=~/.ssh; cat $P2`) or a
// function body defined before the variable it reads is bound. The fixed-point
// table resolves both, and did so before this change. So it SEEDS the ordered
// table rather than sitting behind it as a fallback; see scopeEval's own doc
// comment for why that distinction turned out to matter.
//
// # Scope propagation is modelled on what the shell actually does
//
// A subprocess carrier (`bash -c`, `sh -c`, `su -c`) sees the EXPORTED
// environment plus that statement's own prefix assignments — not the caller's
// ordinary variables. `K=~/.kube/config; bash -c 'cat "$K"'` reads nothing in a
// real bash, so folding it would manufacture a block for a command that opens no
// file. `eval` is the opposite: it runs in the current shell, so it inherits
// everything and its own bindings persist afterwards.
//
// # Model boundary — accepted, not a backlog (#3769, 2026-09-11)
//
// This is a best-effort model of bash variable scope, and it is FROZEN. A
// static walker cannot model an unrestricted shell, and four adversarial
// rounds on this lineage (#3706, #3743, #3752, #3769) each found that the
// previous round's fixes had opened the next round's holes. The decision
// (Gary, 2026-09-11) is to stop extending the model and to write down where
// it ends. The rationale, the rejected alternatives and the revisit trigger
// are in docs/architecture.md, "Known gaps and evolution seams".
//
// Which way it fails. When the walker meets a construct it does not model, or
// models wrongly, it almost always DROPS the value rather than guessing. A
// dropped value materializes no path, so a protected read behind that
// construct never reaches protected_paths, and the command gets the default
// decision unless another rule matches its text. That is fail-open, in line
// with the analyzer's minimal-intrusion default.
//
// Known shapes, measured in #3769 against 0da80a27. P is a variable first
// bound to a protected directory; "missed" means the protected read fell to
// the default decision there.
//
//	1. P=<protected>; printf -v P %s "$(cat "$P/config")"
//	   missed: printf -v invalidates P before the substitution is walked,
//	   although bash runs the substitution first. Introduced by #3761.
//	2. P=<protected>; printf -v P %q "$P"; cat "$P/config"
//	   missed: an unfoldable format is treated as unset, although printf
//	   keeps the value. Introduced by #3761.
//	3. f() { P=/tmp; }; g() { cat "$P/config"; }; P=<protected>; g
//	   missed: closing the UNCALLED f discards the seed P gets from the
//	   later top-level assignment. Introduced by #3761.
//	4. P=<protected>; false && P=/tmp; P=/ok true; cat "$P/config"
//	   missed: the temporary prefix is treated as a definite write and
//	   clears the conditional alternate. A gap in #3761's merge.
//	5. eight `Xi=/a; false && Xi=/b` pairs, then
//	   P=<protected>; false && P=/tmp; cat "$P/config"
//	   missed: past maxScopeAlternates, altSet.add drops the protected
//	   alternate, so padding with harmless conditionals switches the
//	   protection off. A gap in #3761's merge.
//	6. P=$HOME; F=<protected-subdir>; false && { P=/tmp; F=ok; }; cat "$P/$F/config"
//	   missed: alternates substitute one variable at a time, so the joint
//	   state of the skipped branch is never rebuilt. Predates #3761.
//	7. P=<protected>; false && P=/tmp; P+=/config; cat "$P"
//	   missed: += skips alternate propagation and then clears the base.
//	   Predates #3761.
//	8. P=/tmp; (P=<protected>; false && P=/else); cat "$P/config"
//	   FALSE BLOCK, the one shape that errs the other way: the subshell's
//	   alternate leaks out, because closing a region restores scalars but
//	   not alternates. The shell reads /tmp/config. Introduced by #3761.
//
//	9. P=<protected>; \\unset P; cat "$P/config"
//	   missed: the statement's name is flattened and stripped of every quote
//	   and backslash before it is compared, so an escaped-backslash or
//	   quoted-backslash spelling of unset / read / printf -v is taken for the
//	   builtin and invalidates P. bash reports "command not found" and P
//	   stays bound. Predates #3761; measured on a745d993 (2026-09-17, the
//	   adversarial review of #3875). shellparse.literalExecName is the exact
//	   comparison, not used here.
//	10. re""ad P <<< <protected>; cat "$P"   and   pr""intf -v P %s <protected>; cat "$P"
//	   missed: literalWord accepts only a single-Lit word, so an empty-quote
//	   splice of the builtin's name is not recognised and nothing is bound.
//	   bash binds P in both. The read form falls to AUDIT; the printf -v
//	   form was measured at ALLOW for a tilde-spelled path. Predates #3761.
//
// Shapes 9 and 10 belong to a wider pattern tracked in #3876: a builtin that
// merely NAMES a variable switches the model off, whether or not it changes
// the value.
//
// A new report of this class, an adversarial bash-scope shape, is added to
// this list rather than fixed, unless a revisit trigger has fired.

// maxCarrierDepth bounds nested carrier recursion (`bash -c 'sh -c "…"'`).
// Three is well past anything observed in real payloads; the bound exists so a
// pathological input cannot turn a linear walk into an exponential one.
const maxCarrierDepth = 3

// maxScopeAlternates bounds the conditional merge (see altSet). Eight is far
// past anything a real command produces; the bound exists because every
// alternate costs one extra materialization at every later read, and this
// analyzer runs synchronously inside the IDE hook.
//
// Past the bound altSet.add drops the alternate silently. That is a known
// fail-open (#3769 shape 5), accepted with the model boundary at the top of
// this file. Raising the bound does not remove it: any finite bound has the
// same property, and an unbounded list would hand the hook's latency to
// whoever writes the command.
const maxScopeAlternates = 8

// scopeEval threads a symbol table through a parsed command in source order,
// collecting the paths its words materialize to.
//
// # Why one map and not two (#3743 adversarial review)
//
// The first cut kept the ordered table and the fixed-point table separate and
// tried the ordered one first, falling back to the flat one. That made the flat
// table a REVIVAL channel for exactly the values the ordered pass had decided
// were gone: `V=<protected>; V=; cat ${V:-/tmp/x}` and
// `V=<protected>; unset V; cat $V` both resolved back to the protected path,
// because the ordered table's answer was "unbound" and "unbound" is precisely
// when the fallback ran. Same shape for a temporary prefix assignment
// (`V=<protected> true; bash -c 'cat "$V"'`), whose binding the flat table
// keeps forever.
//
// So there is one map. `view` starts as a copy of the fixed-point table — that
// is what still resolves a forward reference (`P2=$P1/x; P1=~/.ssh; cat $P2`)
// or a function body defined before its variable is bound — and the ordered
// pass takes OWNERSHIP of a name the first time it touches it. From that point
// the seeded value is gone for good: a later write replaces it and a later
// unbinding deletes it, with nothing left to fall back to.
type scopeEval struct {
	// view is the live resolution table: the whole-command fixed-point seed,
	// overwritten wherever the ordered pass has an answer of its own.
	view map[string]string
	// owned marks the names the ordered pass has taken over. Keys stay set
	// after an unbinding, which is what stops the seed coming back.
	owned map[string]bool
	// exported records which names a child process would see.
	exported map[string]bool
	// regions is the stack of enclosing tree regions whose effect on shell
	// state differs from their text — see region.
	regions []*region
	// alts holds the values a CONDITIONAL write superseded — see altSet.
	alts *altSet
	// evaluated marks nodes this pass has already walked in the environment
	// they had to be walked in, so the outer traversal does not walk them a
	// second time — see materializeAssignValue.
	evaluated map[syntax.Node]bool
	// isolated marks statements that are a pipeline COMPONENT and therefore
	// run in their own subshell — see openRegion.
	isolated map[*syntax.Stmt]bool
	out      []string
	depth    int
}

// altBinding is a value a CONDITIONAL write superseded without certainly
// destroying: the branch may not have run, in which case the shell still holds
// the earlier value.
type altBinding struct {
	name string
	val  string
}

// altSet is the conditional merge, which a one-value-per-name table cannot
// express on its own.
//
// `P=<protected>; false && P=/tmp; cat "$P/config"` reads the protected file:
// the branch does not run, so P is unchanged. Keeping only the branch's write
// hid that read outright — the same fail-open shape the REMOVAL rule was
// already written to avoid, arriving through an overwrite instead of an
// `unset` (#3752). The state after a conditional is the UNION over the paths,
// so both values are kept: the branch's write stays the live one and the value
// it displaced is re-materialized at every later read.
//
// It is a slice rather than a map because ctx.MaterializedPaths order decides
// which rule the engine reports first, and Go's map iteration order is
// randomised — two runs on the same command must produce the same answer.
//
// It is shared by every evaluator that shares a shell: an `eval` body runs in
// THIS shell, so a value it conditionally supersedes belongs on the same list.
type altSet struct {
	entries []altBinding
	// capped is set the first time add drops an alternate past
	// maxScopeAlternates. The walker's result does not change; the
	// substitution analyzer turns this into NoteScopeAlternatesCapped on the
	// context (#3995) so the event says the model gave up instead of nothing.
	capped bool
}

func (a *altSet) add(name, val string) {
	// Past maxScopeAlternates the alternate is dropped: a documented
	// fail-open (#3769 shape 5). See the model boundary at the top of this
	// file. Since #3995 the drop is recorded rather than silent.
	if a == nil || val == "" {
		return
	}
	if len(a.entries) >= maxScopeAlternates {
		a.capped = true
		return
	}
	for _, e := range a.entries {
		if e.name == name && e.val == val {
			return
		}
	}
	a.entries = append(a.entries, altBinding{name: name, val: val})
}

// clear drops name's alternates, for a write that DEFINITELY happens: after
// `P=<protected>; false && P=/tmp; P=/etc/ok` the shell holds /etc/ok on every
// path, so the protected candidate is gone and keeping it would be a false
// BLOCK.
func (a *altSet) clear(name string) {
	if a == nil || len(a.entries) == 0 {
		return
	}
	kept := a.entries[:0]
	for _, e := range a.entries {
		if e.name != name {
			kept = append(kept, e)
		}
	}
	a.entries = kept
}

// newScopeEval starts a top-level evaluation seeded with the fixed-point table.
func newScopeEval(final map[string]string) *scopeEval {
	view := make(map[string]string, len(final))
	for k, v := range final {
		view[k] = v
	}
	return &scopeEval{
		view:     view,
		owned:    make(map[string]bool),
		exported: make(map[string]bool),
		alts:     &altSet{},
	}
}

// resolve materializes w against the live table.
func (ev *scopeEval) resolve(w *syntax.Word) (string, bool) {
	return materializeWord(w, ev.view)
}

// bind records an ordered-pass value for name, permanently displacing the seed.
func (ev *scopeEval) bind(name, val string) {
	switch {
	case ev.removalsSuppressed():
		// A branch that may not run cannot certainly destroy what it
		// overwrites either — keep the displaced value as an alternate.
		if old, ok := ev.view[name]; ok && old != val {
			ev.alts.add(name, old)
		}
	case ev.writeIsDefinite():
		ev.alts.clear(name)
	}
	ev.journal(name, true)
	ev.view[name] = val
	ev.owned[name] = true
}

// unbind records that name holds nothing this layer can resolve — an `unset`,
// an unresolvable right-hand side, an array target. The name stays OWNED so
// the fixed-point seed cannot supply the value the shell just discarded.
func (ev *scopeEval) unbind(name string) {
	if ev.removalsSuppressed() {
		// A branch that may not run must not be able to take a binding away:
		// the state after it is the UNION over the paths, and the path that
		// skips it leaves the binding in place.
		return
	}
	if ev.writeIsDefinite() {
		ev.alts.clear(name)
	}
	ev.journal(name, true)
	delete(ev.view, name)
	ev.owned[name] = true
}

// ownedValue returns the value the ORDERED pass bound to name, ignoring the
// seed. Any computation that reads a previous value in order to write a new one
// — today just `+=` — must use this rather than the view: the seed for a name
// bound only by `+=` is the fixed-point table's reading of that same append as
// a plain assignment, so folding it in would double the text.
func (ev *scopeEval) ownedValue(name string) (string, bool) {
	if !ev.owned[name] {
		return "", false
	}
	val, ok := ev.view[name]
	return val, ok
}

// ownedBindings returns the bindings this ordered pass established, for the
// engine's assignment record.
func (ev *scopeEval) ownedBindings() map[string]string {
	if len(ev.owned) == 0 {
		return nil
	}
	out := make(map[string]string, len(ev.owned))
	for name := range ev.owned {
		if val, ok := ev.view[name]; ok {
			out[name] = val
		}
	}
	return out
}

// walk runs the ordered evaluation over node.
//
// syntax.Walk is a pre-order depth-first traversal, which visits statements in
// source order — so mutating the table as nodes arrive is enough to get
// statement ordering right, without reimplementing the recursion for all
// nineteen command node types (and silently losing whichever one is forgotten).
//
// It also calls f(nil) after each node's children, and only for nodes it
// actually descended into (walkNilable skips absent children entirely). That
// exit callback is what lets a REGION be opened and closed here rather than by
// hand-walking each compound node's fields — which is exactly how #3045 lost
// four analyzers to one forgotten field. The callback must therefore always
// return true ONCE A REGION HAS BEEN PUSHED: returning false skips the children
// AND the f(nil), and the region stack would never be popped. The one early
// exit below is placed BEFORE openRegion for exactly that reason — no frame is
// pushed, so nothing is left unpopped.
func (ev *scopeEval) walk(node syntax.Node) {
	syntax.Walk(node, func(n syntax.Node) bool {
		if n == nil {
			ev.closeRegion()
			return true
		}
		if ev.evaluated[n] {
			// Already evaluated, against the table it had to be evaluated
			// against (materializeAssignValue). Walking it again is not just
			// redundant: the outer traversal reaches an assignment's RHS after
			// the RHS has already been walked once, so each nesting level
			// DOUBLED the work and `V1=$(V2=$(…))` cost O(2^n) — 22 levels
			// measured at 2.8s inside a synchronous IDE hook (#3752).
			return false
		}
		ev.openRegion(n)
		switch x := n.(type) {
		case *syntax.Stmt:
			// Binding forms whose value is a REDIRECT of the statement rather
			// than an argument of the call (`read -r V <<< word`) can only be
			// seen from here — the CallExpr node does not carry Redirs.
			ev.bindFromRedirects(x)
		case *syntax.CallExpr:
			ev.callExpr(x)
		case *syntax.DeclClause:
			ev.declClause(x)
		case *syntax.Redirect:
			ev.materialize(x.Word)
		case *syntax.TestClause:
			ev.materializeTest(x.X)
		}
		return true
	})
}

// A region is a stretch of the tree whose effect on the SHELL's state is not
// the effect its text would have if it ran here, once, unconditionally.
//
// Two kinds, and the difference is not stylistic:
//
//   - ISOLATED — a subshell, a pipeline component, a function BODY at its
//     declaration. Bash discards their assignments entirely, so the region's
//     writes are journalled and undone on exit. Reads inside still resolve
//     against the enclosing table, and paths they materialize still flow out;
//     it is only the state changes that are contained.
//   - CONDITIONAL — the operands of `&&`/`||`, an `if`/`case` arm, a loop body.
//     These may or may not run, so the state after them is the UNION of what
//     each path leaves. A one-value-per-name table cannot hold a union, so the
//     rule is asymmetric in the fail-safe direction: a write is kept (it might
//     have happened, and keeping it can only produce a BLOCK), a REMOVAL is
//     suppressed (it might not have happened, and applying it hides a read).
//
// Without this, unconditional traversal was being read as execution:
// `P=<protected>; (unset P); cat "$P/config"` applied the subshell's unset to
// the parent table and hid a real read, and an UNCALLED function containing
// `unset P` did the same (#3743 pass 2).
type region struct {
	isolate  bool
	noRemove bool
	journal  []mutation
}

// mutation is one name's state before a write inside an isolated region.
type mutation struct {
	name     string
	val      string
	hadVal   bool
	wasOwned bool
	exported bool
	// valueWrite distinguishes a write of the VALUE from a change to the
	// export attribute alone. Only the former may cost the fixed-point seed
	// — see closeRegion.
	valueWrite bool
}

// openRegion pushes a frame for every visited node, so closeRegion can pair
// with syntax.Walk's f(nil) without knowing which node it is closing.
func (ev *scopeEval) openRegion(n syntax.Node) {
	r := (*region)(nil)
	switch x := n.(type) {
	case *syntax.Subshell:
		r = &region{isolate: true}
	case *syntax.Stmt:
		// A pipeline COMPONENT, tagged when its BinaryCmd was opened. One
		// region around the whole pipeline undid the writes at the end but
		// let them leak sideways, so `P=/tmp | cat "$P/config"` had the left
		// component's assignment reach the right one and hid the read
		// (#3752). Bash gives every component its own environment, forked
		// from the pipeline's incoming state.
		if ev.isolated[x] {
			r = &region{isolate: true}
		}
	case *syntax.CmdSubst:
		// `$(…)` and the backquote spelling run in a CHILD shell, so their
		// mutations cannot reach the parent: `Q=$(unset P)` leaves P alone.
		// Only Subshell was isolated, so the unset was applied to the parent
		// table and hid a real read (#3752). mksh's `${ …;}` / `${|…;}` DO
		// run in the current shell; the parser here is LangBash so they
		// cannot appear, and they are declined rather than guessed at.
		if !x.TempFile && !x.ReplyVar {
			r = &region{isolate: true}
		}
	case *syntax.ProcSubst:
		// `<(…)` / `>(…)` are child processes for the same reason.
		r = &region{isolate: true}
	case *syntax.FuncDecl:
		// A declaration is not a call. Applying the body here made
		// `P=<protected>; f() { unset P; }; cat "$P/config"` behave as though
		// the function had run. Its READS are still materialized — that is
		// what keeps `f() { cat $P/x; }; P=…; f` covered — but nothing it
		// writes escapes. Resolving at the CALL site instead would need a
		// function table, argument binding and recursion limits: a bigger
		// scope model than this change should carry, and no measured shape
		// needs it.
		r = &region{isolate: true}
	case *syntax.BinaryCmd:
		// Every component of a pipeline runs in its own subshell; `&&`/`||`
		// name a branch that may not run at all.
		switch x.Op {
		case syntax.Pipe, syntax.PipeAll:
			r = &region{isolate: true}
			ev.markIsolated(x.X)
			ev.markIsolated(x.Y)
		case syntax.AndStmt, syntax.OrStmt:
			r = &region{noRemove: true}
		}
	case *syntax.IfClause, *syntax.WhileClause, *syntax.ForClause, *syntax.CaseClause:
		// The condition of an `if` and the left operand of `&&` do always run,
		// so covering the whole node is broader than strictly necessary. It
		// errs toward KEEPING a binding, which can only produce a BLOCK.
		r = &region{noRemove: true}
	}
	ev.regions = append(ev.regions, r)
}

// closeRegion pops the frame syntax.Walk is exiting, undoing an isolated
// region's writes.
func (ev *scopeEval) closeRegion() {
	if len(ev.regions) == 0 {
		return
	}
	r := ev.regions[len(ev.regions)-1]
	ev.regions = ev.regions[:len(ev.regions)-1]
	if r == nil || !r.isolate || len(r.journal) == 0 {
		return
	}
	// The journal is chronological and a name can appear more than once — an
	// `export P=v` records the attribute, then the value, then the attribute
	// again. The state to restore is the EARLIEST entry for each name, the one
	// taken before the region touched it at all; replaying every entry in
	// reverse instead re-applies the intermediate states and lands on the
	// wrong one.
	type restore struct {
		m     mutation
		wrote bool
	}
	states := make(map[string]*restore, len(r.journal))
	order := make([]string, 0, len(r.journal))
	for _, m := range r.journal {
		st, ok := states[m.name]
		if !ok {
			st = &restore{m: m}
			states[m.name] = st
			order = append(order, m.name)
		}
		st.wrote = st.wrote || m.valueWrite
	}
	for _, name := range order {
		st := states[name]
		// A name the ordered pass had NOT yet taken over is left
		// OWNED-but-unbound rather than restored WHEN THE REGION WROTE ITS
		// VALUE: the only thing left to restore it from is the fixed-point
		// seed, which reads that very assignment as if it were permanent, so
		// `(P=<protected>); cat "$P/config"` resolved straight back out of it
		// (#3752). A region that only changed the export ATTRIBUTE wrote no
		// value, and the seed is still the right answer for it.
		if st.m.hadVal && (st.m.wasOwned || !st.wrote) {
			ev.view[name] = st.m.val
		} else {
			delete(ev.view, name)
		}
		if st.m.wasOwned || st.wrote {
			ev.owned[name] = true
		} else {
			delete(ev.owned, name)
		}
		if st.m.exported {
			ev.exported[name] = true
		} else {
			delete(ev.exported, name)
		}
	}
}

// journal records name's current state in every enclosing isolated region, so
// each can undo independently when it closes. valueWrite says whether the
// caller is about to change the VALUE or only the export attribute.
func (ev *scopeEval) journal(name string, valueWrite bool) {
	if len(ev.regions) == 0 {
		return
	}
	val, hadVal := ev.view[name]
	m := mutation{
		name: name, val: val, hadVal: hadVal,
		wasOwned: ev.owned[name], exported: ev.exported[name], valueWrite: valueWrite,
	}
	for _, r := range ev.regions {
		if r != nil && r.isolate {
			r.journal = append(r.journal, m)
		}
	}
}

// markIsolated tags a pipeline component so openRegion gives it its own scope.
func (ev *scopeEval) markIsolated(st *syntax.Stmt) {
	if st == nil {
		return
	}
	if ev.isolated == nil {
		ev.isolated = make(map[*syntax.Stmt]bool, 4)
	}
	ev.isolated[st] = true
}

// markEvaluated tags a node this pass has already walked, so walk skips it.
func (ev *scopeEval) markEvaluated(n syntax.Node) {
	if n == nil {
		return
	}
	if ev.evaluated == nil {
		ev.evaluated = make(map[syntax.Node]bool, 4)
	}
	ev.evaluated[n] = true
}

// removalsSuppressed reports whether an enclosing region may not have run, in
// which case a binding it drops must survive — see region's doc comment.
func (ev *scopeEval) removalsSuppressed() bool {
	for _, r := range ev.regions {
		if r != nil && r.noRemove {
			return true
		}
	}
	return false
}

// writeIsDefinite reports whether a write here certainly happens in THIS
// shell: no enclosing region may skip it and none discards its effect. Only
// then can a superseded value be dropped from the alternate set.
func (ev *scopeEval) writeIsDefinite() bool {
	for _, r := range ev.regions {
		if r != nil && (r.isolate || r.noRemove) {
			return false
		}
	}
	return true
}

// alternates materializes w once per surviving conditional candidate, so a
// value a branch may not have replaced still produces its path. primary is the
// materialization against the live table, which is not repeated.
func (ev *scopeEval) alternates(w *syntax.Word, primary string) []string {
	if ev.alts == nil || len(ev.alts.entries) == 0 {
		return nil
	}
	var out []string
	for _, e := range ev.alts.entries {
		saved, had := ev.view[e.name]
		if had && saved == e.val {
			continue
		}
		ev.view[e.name] = e.val
		val, ok := materializeWord(w, ev.view)
		if had {
			ev.view[e.name] = saved
		} else {
			delete(ev.view, e.name)
		}
		if !ok || val == "" || val == primary {
			continue
		}
		if !slices.Contains(out, val) {
			out = append(out, val)
		}
	}
	return out
}

// declClause applies a declaration's bindings and its EXPORT-attribute effect.
func (ev *scopeEval) declClause(d *syntax.DeclClause) {
	effect := declClauseExportEffect(d)
	assigns := shellparse.DeclClauseAssigns(d)
	ev.bindAssigns(assigns, effect == exportAdds)
	if effect == exportNone {
		return
	}
	names := declClauseNakedNames(d)
	for _, a := range assigns {
		if a.Name != nil && a.Name.Value != "" {
			names = append(names, a.Name.Value)
		}
	}
	for _, name := range names {
		if effect == exportRemoves && ev.removalsSuppressed() {
			// The export attribute is state like any other: a branch that may
			// not run cannot take it away. `export P=<protected>; false &&
			// export -n P; bash -c 'cat "$P/config"'` lost the child's view of
			// P and hid the read (#3752).
			continue
		}
		ev.journal(name, false)
		if effect == exportAdds {
			// `export V` with no `=` marks an EXISTING binding for the child.
			// DeclClauseAssigns skips naked args (they bind nothing), so
			// without this `V=<protected>; export V; bash -c 'cat "$V"'` never
			// reached the carrier — a fail-open miss on the ordinary two-step
			// spelling (#3743).
			ev.exported[name] = true
		} else {
			// `export -n V` / `declare +x V` REMOVE the attribute and keep the
			// value. Declining to ADD one was not enough: an attribute set by
			// an earlier `export V=…` survived, and the child inherited a
			// binding bash had explicitly taken away from it — a false BLOCK
			// (#3743 pass 2).
			delete(ev.exported, name)
		}
	}
}

// callExpr applies a call's prefix assignments, materializes its arguments, and
// descends into it when it hands shell source to a shell.
func (ev *scopeEval) callExpr(call *syntax.CallExpr) {
	// A PREFIX assignment (`KUBECONFIG=… cmd`) is exported to the command it
	// prefixes by definition. A bare assignment statement (`KUBECONFIG=…`)
	// parses as the same node with no command word and is NOT exported — that
	// is the whole difference between `K=~/.kube/config; bash -c 'cat "$K"'`,
	// which opens nothing because the child never sees K, and the prefix form,
	// which opens the file.
	//
	// A prefix binding is also SCOPED TO THAT ONE COMMAND, exactly as bash
	// scopes it. The first cut kept it live afterwards "conservatively", and
	// the adversarial review showed what that costs: `V=<protected> true;
	// bash -c 'cat "$V"'` blocked, though the later carrier is started by a
	// shell in which V was never set and the command opens nothing (#3743).
	// The split-concat coverage the #1698 tests pin is unaffected — those are
	// BARE assignments, which have no command word and stay live.
	if len(call.Args) == 0 {
		ev.bindAssigns(call.Assigns, false)
		return
	}
	if ev.unsetBuiltin(call) {
		return
	}
	// ARGV IS EXPANDED FIRST. Bash expands a simple command's words before it
	// performs the command's variable assignments, so `P=/tmp cat "$P/config"`
	// hands cat the path the OLD P names. Binding the prefix first made the
	// analyzer resolve the new value and lose the read outright (#3752) — so
	// everything that reads argv runs here, against the pre-prefix table, and
	// the prefix binding below feeds only the invoked command's ENVIRONMENT.
	// (Statement redirects are reached by the outer walk after this function
	// has returned and the prefix has already been restored, so they see the
	// pre-prefix table for the same reason.)
	restore := ev.scopePrefix(call.Assigns)
	defer restore()
	ev.hidePrefixSeeds(call.Assigns)
	ev.bindFromBuiltin(call)
	// echo/printf arguments are text, not file accesses — see
	// isTextOnlyCommand. `printf -v NAME …` is still a BINDING, which is why
	// bindFromBuiltin runs before this gate rather than after it.
	if !isTextOnlyCommand(call) {
		for _, w := range call.Args {
			ev.materialize(w)
		}
		ev.out = append(ev.out, materializedMountSources(call, ev.resolve)...)
	}
	names := ev.bindAssigns(call.Assigns, true)
	ev.carrier(call, names)
}

// hidePrefixSeeds removes the fixed-point table's reading of the prefix
// assignments this statement is about to make, for the span in which argv is
// expanded.
//
// scopePrefix already refuses to restore a seeded prefix binding AFTER the
// statement, for exactly this reason: the seed's only source for that name is
// this very assignment, read as if it were permanent. Argv is expanded BEFORE
// the assignment takes effect, so the same reasoning applies one step earlier —
// `P=<protected> cat "$P/config"` opens `/config` in a shell where P was never
// set, and folding the seed made it a false BLOCK. A name the ordered pass has
// already TAKEN OVER is untouched: its value came from an earlier statement and
// is what bash expands argv against.
func (ev *scopeEval) hidePrefixSeeds(assigns []*syntax.Assign) {
	for _, asn := range assigns {
		if asn == nil || asn.Name == nil || asn.Name.Value == "" {
			continue
		}
		if !ev.owned[asn.Name.Value] {
			delete(ev.view, asn.Name.Value)
		}
	}
}

// scopePrefix snapshots everything a statement's prefix assignments are about
// to overwrite and returns the undo.
//
// A name the ordered pass had NOT yet touched is left OWNED-but-unbound rather
// than restored, because the only thing left to restore it from is the
// fixed-point seed — which holds this very prefix assignment, read as if it
// were permanent. Restoring that would undo the scoping it is here to enforce.
func (ev *scopeEval) scopePrefix(assigns []*syntax.Assign) func() {
	type saved struct {
		name       string
		val        string
		hadVal     bool
		wasOwned   bool
		wasExports bool
	}
	prev := make([]saved, 0, len(assigns))
	for _, asn := range assigns {
		if asn == nil || asn.Name == nil || asn.Name.Value == "" {
			continue
		}
		name := asn.Name.Value
		val, hadVal := ev.view[name]
		prev = append(prev, saved{name, val, hadVal, ev.owned[name], ev.exported[name]})
	}
	return func() {
		for _, s := range prev {
			if s.wasOwned && s.hadVal {
				ev.view[s.name] = s.val
			} else {
				delete(ev.view, s.name)
			}
			ev.owned[s.name] = true
			if s.wasExports {
				ev.exported[s.name] = true
			} else {
				delete(ev.exported, s.name)
			}
		}
	}
}

// unsetBuiltin models `unset [-v] NAME…`, reporting whether the call was one.
//
// Without it a cleared variable kept resolving to the value it used to hold:
// `V=<protected>; unset V; cat $V` blocked, though the read opens nothing. The
// name is unbound rather than deleted outright so the fixed-point seed — which
// has no notion of `unset` at all — cannot supply it back.
//
// `unset -f` removes a FUNCTION and leaves variables alone; `unset -n` drops a
// nameref's own binding. Neither is modelled, and both are declined whole
// rather than guessed at.
func (ev *scopeEval) unsetBuiltin(call *syntax.CallExpr) bool {
	exe, ok := literalWord(call.Args[0])
	if !ok || shellparse.NormalizeExecName(exe) != "unset" {
		return false
	}
	for _, w := range call.Args[1:] {
		lit, ok := literalWord(w)
		if !ok {
			continue
		}
		if strings.HasPrefix(lit, "-") && len(lit) > 1 {
			if strings.ContainsAny(lit[1:], "fn") {
				return true
			}
			continue
		}
		if isShellIdentifier(lit) {
			ev.unbind(lit)
		}
	}
	return true
}

// materialize appends the materialized form of w, mirroring the pre-#3706
// appendMaterializedWord: a word with nothing to substitute still has its
// interpreter file-access literals extracted.
func (ev *scopeEval) materialize(w *syntax.Word) {
	if !wordRequiresSubstitution(w) {
		if val, ok := materializeWord(w, nil); ok {
			ev.out = append(ev.out, extractFileCallPaths(val)...)
		}
		return
	}
	primary := ""
	if val, ok := ev.resolve(w); ok && val != "" {
		primary = val
		ev.out = append(ev.out, val)
		ev.out = append(ev.out, extractFileCallPaths(val)...)
	}
	// ...and once more for each value a conditional branch may not have
	// replaced. See altSet.
	for _, alt := range ev.alternates(w, primary) {
		ev.out = append(ev.out, alt)
		ev.out = append(ev.out, extractFileCallPaths(alt)...)
	}
}

// materializeTest recurses through a `[[ … ]]` expression to reach its words.
func (ev *scopeEval) materializeTest(expr syntax.TestExpr) {
	switch e := expr.(type) {
	case *syntax.Word:
		ev.materialize(e)
	case *syntax.UnaryTest:
		ev.materializeTest(e.X)
	case *syntax.BinaryTest:
		ev.materializeTest(e.X)
		ev.materializeTest(e.Y)
	case *syntax.ParenTest:
		ev.materializeTest(e.X)
	}
}

// bindAssigns applies assignments in order, honouring `+=`. Returns the names
// it saw (resolved or not) so a carrier can treat this statement's prefix
// assignments as part of the child environment.
//
// An assignment whose value cannot be resolved DELETES the name rather than
// leaving the previous binding in place: `V=~/.ssh; V=$(mktemp -d); cat $V`
// reads a temp dir, and keeping the stale `~/.ssh` there would fold a word to a
// value the shell never forms.
func (ev *scopeEval) bindAssigns(assigns []*syntax.Assign, exported bool) []string {
	var names []string
	for _, asn := range assigns {
		if asn == nil || asn.Name == nil || asn.Name.Value == "" {
			continue
		}
		name := asn.Name.Value
		names = append(names, name)
		if exported {
			ev.journal(name, false)
			ev.exported[name] = true
		}
		// The right-hand side is evaluated BEFORE the target is written, and
		// it can read the target's OLD value: `P=<protected>; P=$(cat "$P/x")`
		// opens the file with the old P and only then overwrites P with the
		// output. Resolving first and unbinding on failure left the preorder
		// walk to reach that inner `cat` with P already gone, so the read
		// vanished (#3743 pass 2). Materializing the RHS here, against the
		// pre-assignment table, is what puts it back — duplicates are deduped
		// by the caller.
		ev.materializeAssignValue(asn.Value)
		// An array literal (`a=(x y)`) or an indexed target (`a[2]=x`) binds
		// something other than the scalar this layer models.
		if asn.Array != nil || asn.Index != nil {
			ev.unbind(name)
			continue
		}
		val, ok := ev.resolve(asn.Value)
		if !ok {
			ev.unbind(name)
			continue
		}
		// The RHS's own alternates become the target's, so a conditionally
		// superseded value survives one hop: `P=<protected>; false && P=/tmp;
		// Q=$P; cat "$Q/config"` still reads the protected path. Skipped for
		// `+=`, whose base value would have to be varied in step with the
		// alternate to mean anything.
		var valueAlts []string
		if !asn.Append {
			valueAlts = ev.alternates(asn.Value, val)
		}
		if asn.Append {
			// `V+=x` on a name this command never bound appends to the
			// INHERITED value. Bash yields exactly x when V is unset, which is
			// both the common case and what the fixed-point table has always
			// modelled (it read `+=` as a plain assignment).
			//
			// ownedValue, not the view: the view's seed for a name bound only
			// by `+=` IS the fixed-point table's reading of this same append as
			// a plain assignment, so taking the base from there would fold the
			// appended text in twice.
			base, _ := ev.ownedValue(name)
			val = base + val
		}
		ev.bind(name, val)
		for _, alt := range valueAlts {
			ev.alts.add(name, alt)
		}
	}
	return names
}

// exportEffect is what a declaration does to its names' export attribute.
type exportEffect int

const (
	exportNone exportEffect = iota
	exportAdds
	exportRemoves
)

// materializeAssignValue collects the paths an assignment's right-hand side
// reads while evaluating itself — the command substitutions inside it.
//
// Scoped to the value word rather than run as part of the outer walk because
// ORDER is the whole point: the outer walk reaches these nodes after the target
// has been written or invalidated, and by then the environment they must be
// read against is gone.
//
// And EXACTLY ONCE. The first cut walked the value here and let the outer
// traversal walk it a second time, so every nesting level doubled the work and
// `V1=$(V2=$(…))` cost O(2^n) — 22 levels measured at 2.8 seconds in an
// analyzer that runs synchronously inside the IDE hook (#3752). Marking the
// node evaluated is what makes the second traversal skip it; the earlier
// wordHasCmdSubst gate is gone with it, because "does this word contain a
// command substitution" was also blind to a ProcSubst right-hand side
// (`Q=<(cat "$P/id_rsa")`), whose read only survived because the outer walk
// picked it up.
func (ev *scopeEval) materializeAssignValue(w *syntax.Word) {
	if w == nil {
		return
	}
	ev.walk(w)
	ev.markEvaluated(w)
}

// declClauseExportEffect classifies a declaration's effect on the export
// attribute: `export x=…` / `export x` / `declare -x` ADD it, `export -n x` and
// `declare +x` REMOVE it, everything else leaves it alone.
//
// The removal case is the one that was missing. Returning "does not add" for
// `export -n` left an attribute an earlier `export` had set, so a child
// inherited a binding bash had taken away from it (#3743 pass 2).
func declClauseExportEffect(d *syntax.DeclClause) exportEffect {
	if d == nil || d.Variant == nil {
		return exportNone
	}
	minus, plus := declClauseFlags(d)
	// `declare -n` is a nameref, a different shape of binding altogether; the
	// clause says nothing this layer can act on.
	for _, f := range minus {
		if strings.ContainsRune(f, 'n') && d.Variant.Value != "export" {
			return exportNone
		}
	}
	switch d.Variant.Value {
	case "export":
		for _, f := range minus {
			if strings.ContainsRune(f, 'n') {
				return exportRemoves
			}
		}
		return exportAdds
	case "declare", "typeset":
		for _, f := range plus {
			if strings.ContainsRune(f, 'x') {
				return exportRemoves
			}
		}
		for _, f := range minus {
			if strings.ContainsRune(f, 'x') {
				return exportAdds
			}
		}
	}
	return exportNone
}

// declClauseFlags returns a declaration's option letters, split by sign:
// `declare -xr +n` yields minus ["xr"], plus ["n"]. The `+` spelling is how
// bash TURNS AN ATTRIBUTE OFF, so a scanner that only looks for `-` cannot see
// a removal at all.
func declClauseFlags(d *syntax.DeclClause) (minus, plus []string) {
	for _, a := range d.Args {
		if a == nil || !a.Naked || a.Value == nil {
			continue
		}
		flag, ok := literalWord(a.Value)
		if !ok || len(flag) < 2 {
			continue
		}
		switch flag[0] {
		case '-':
			minus = append(minus, flag[1:])
		case '+':
			plus = append(plus, flag[1:])
		}
	}
	return minus, plus
}

// declClauseNakedNames returns the bare NAMES a declaration lists without an
// `=` — `export V`, `declare -x A B`. They bind nothing, which is why
// DeclClauseAssigns skips them, but on an export they change who can SEE an
// existing binding, and that is the whole of finding 4 in #3743.
// The two naked shapes are mirror images in the AST, which is the trap: an
// OPTION (`declare -x`) arrives as Name == nil with the flag word in Value,
// while a bare NAME (`export V`) arrives as Name == "V" with Value == nil.
// Reading Value for both finds the flags and none of the names.
func declClauseNakedNames(d *syntax.DeclClause) []string {
	if d == nil {
		return nil
	}
	var out []string
	for _, a := range d.Args {
		if a == nil || !a.Naked || a.Value != nil || a.Name == nil {
			continue
		}
		if !isShellIdentifier(a.Name.Value) {
			continue
		}
		out = append(out, a.Name.Value)
	}
	return out
}

// bindFromBuiltin models the binding builtins whose target is an ARGUMENT
// rather than an `=` — today just `printf -v NAME FORMAT [ARGS]`.
//
// `printf -v` matters twice over: it binds, and `printf` is on the text-only
// list, so its arguments are deliberately not materialized. Before this, the
// whole shape was invisible — `printf -v KUBECONFIG %s $HOME/.kube/config;
// cat "$KUBECONFIG"` measured ALLOW, one step BELOW the AUDIT default.
func (ev *scopeEval) bindFromBuiltin(call *syntax.CallExpr) {
	name, val, folded := printfBinding(call, ev.resolve)
	if name == "" {
		return
	}
	if !folded {
		// The binding EXECUTED — bash wrote something into the target — and
		// this layer cannot say what. Returning without touching the target
		// left the value it used to hold in place, so
		// `printf -v P %s <protected>; printf -v P %d 42; cat "$P/config"`
		// resolved to the stale protected path: a false BLOCK on a command
		// that opens nothing (#3752).
		ev.unbind(name)
		return
	}
	ev.bind(name, val)
}

// printfBinding reports what a `printf -v` invocation does to its target.
//
// The two questions are SEPARATE, and conflating them was #3752 finding 7:
//
//	name == ""     no target — this call binds nothing
//	folded == false  the target IS written, with a value this layer cannot
//	                 reproduce, so whatever it held before is gone
//	folded == true   name now holds val, exactly
//
// Only the exactly-foldable subset is folded: a format built from literal text
// plus `%s`/`%%`, with exactly one argument per `%s`. Any other verb (`%d`,
// `%q`, `%b`, a width or precision) or a mismatched argument count — where bash
// REUSES the format until the arguments run out — yields folded == false,
// because a wrong value here is a wrong path, and a wrong path is a false
// BLOCK. The caller invalidates rather than guessing.
func printfBinding(call *syntax.CallExpr, resolve func(*syntax.Word) (string, bool)) (name, val string, folded bool) {
	if len(call.Args) < 3 {
		return "", "", false
	}
	exe, ok := literalWord(call.Args[0])
	if !ok || shellparse.NormalizeExecName(exe) != "printf" {
		return "", "", false
	}
	// bash's grammar is `printf [-v var] format [arguments]`: options come
	// only BEFORE the format, and `--` ends them. Scanning the whole argument
	// list for a `-v` made ordinary DATA look like the binding option —
	// `printf %s -v P <protected>` prints "-v" and binds nothing, but was read
	// as binding P to the path, and `printf -- -v P %s <protected>` likewise
	// (#3743). Both were false BLOCKs on a command that opens no file.
	rest := call.Args[1:]
	idx := -1
	for i, w := range rest {
		lit, ok := literalWord(w)
		if !ok || !strings.HasPrefix(lit, "-") || lit == "-" {
			break // the format word: options are over
		}
		if lit == "--" {
			break // options explicitly ended, and no -v came before it
		}
		if lit == "-v" {
			if i+1 < len(rest) {
				if n, ok := literalWord(rest[i+1]); ok && isShellIdentifier(n) {
					name, idx = n, i+1
				}
			}
			break
		}
		if strings.HasPrefix(lit, "-v") && len(lit) > 2 {
			// `printf -vNAME fmt` — bash accepts the attached spelling.
			if n := lit[2:]; isShellIdentifier(n) {
				name, idx = n, i
			}
			break
		}
	}
	if name == "" || idx+1 >= len(rest) {
		// No target, or `printf -v P` with no format at all — bash reports a
		// usage error and leaves P alone, so there is nothing to invalidate.
		return "", "", false
	}
	// Past this point the write HAPPENS; only the value is in question.
	format, ok := resolve(rest[idx+1])
	if !ok {
		return name, "", false
	}
	args := make([]string, 0, len(rest))
	for _, w := range rest[idx+2:] {
		v, ok := resolve(w)
		if !ok {
			return name, "", false
		}
		args = append(args, v)
	}
	val, ok = formatStringsOnly(format, args)
	if !ok {
		return name, "", false
	}
	return name, val, true
}

// formatStringsOnly renders a printf format that uses only literal text, `%%`
// and `%s`. Returns ok=false for every other verb and for any argument count
// that does not match the number of `%s` conversions exactly.
func formatStringsOnly(format string, args []string) (string, bool) {
	var sb strings.Builder
	used := 0
	for i := 0; i < len(format); i++ {
		c := format[i]
		if c != '%' {
			sb.WriteByte(c)
			continue
		}
		if i+1 >= len(format) {
			return "", false
		}
		i++
		switch format[i] {
		case '%':
			sb.WriteByte('%')
		case 's':
			if used >= len(args) {
				return "", false
			}
			sb.WriteString(args[used])
			used++
		default:
			return "", false
		}
	}
	if used != len(args) {
		return "", false
	}
	return sb.String(), true
}

// bindFromRedirects models `read [-r] NAME <<< word`, the one binding form
// whose value arrives as a statement redirect instead of an argument.
//
// Restricted to a SINGLE target name: `read a b <<< "x y"` splits the input on
// IFS across the names, and modelling that split would be guessing at the
// separator. Without `-r`, backslashes are escape characters, so a value
// containing one is refused rather than folded wrongly.
func (ev *scopeEval) bindFromRedirects(st *syntax.Stmt) {
	if st == nil || len(st.Redirs) == 0 {
		return
	}
	call, ok := st.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) < 2 {
		return
	}
	exe, ok := literalWord(call.Args[0])
	if !ok || shellparse.NormalizeExecName(exe) != "read" {
		return
	}
	raw := false
	var names []string
	skipNext := false
	for _, w := range call.Args[1:] {
		lit, ok := literalWord(w)
		if !ok {
			return
		}
		if skipNext {
			skipNext = false
			continue
		}
		if strings.HasPrefix(lit, "-") && len(lit) > 1 {
			if strings.ContainsRune(lit[1:], 'r') {
				raw = true
			}
			// -p/-d/-n/-N/-t/-u/-a all consume the following word; -a also
			// binds an ARRAY, which this layer does not model.
			if strings.ContainsAny(lit[1:], "adnNtu") {
				if strings.ContainsRune(lit[1:], 'a') {
					return
				}
				skipNext = true
			}
			if strings.ContainsRune(lit[1:], 'p') {
				skipNext = true
			}
			continue
		}
		if !isShellIdentifier(lit) {
			return
		}
		names = append(names, lit)
	}
	if len(names) != 1 {
		return
	}
	for _, r := range st.Redirs {
		if r == nil || r.Op != syntax.WordHdoc {
			continue
		}
		val, ok := ev.resolve(r.Word)
		if !ok {
			return
		}
		val = strings.TrimSpace(val)
		if val == "" || (!raw && strings.Contains(val, `\`)) {
			return
		}
		ev.bind(names[0], val)
		return
	}
}

// carrier descends into shell source this call hands to a shell, so a `$VAR`
// written inside the body resolves against the bindings the body would actually
// see. prefixNames are the statement's own `VAR=… cmd` assignments, which a
// child process inherits whether or not they were exported.
func (ev *scopeEval) carrier(call *syntax.CallExpr, prefixNames []string) {
	if ev.depth >= maxCarrierDepth || len(call.Args) == 0 {
		return
	}
	exe, ok := literalWord(call.Args[0])
	if !ok {
		return
	}
	name := carrierExecName(exe)

	body := ""
	sameShell := false
	switch {
	case name == "eval":
		// eval takes no options: every argument is source, joined the way
		// shellparse.evalCode joins them.
		parts := make([]string, 0, len(call.Args)-1)
		for _, w := range call.Args[1:] {
			v, ok := ev.resolve(w)
			if !ok {
				return
			}
			parts = append(parts, v)
		}
		body, sameShell = strings.Join(parts, " "), true
	case shellparse.ShellInterpreters[name] || shellparse.PrivilegeShellCarriers[name]:
		body, ok = ev.inlineCodeArg(call.Args[1:])
		if !ok {
			return
		}
	default:
		return
	}
	if strings.TrimSpace(body) == "" {
		return
	}

	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	parsed, err := parser.Parse(strings.NewReader(body), "")
	if err != nil {
		return
	}

	child := ev.childScope(sameShell, prefixNames)
	child.walk(parsed)
	ev.out = append(ev.out, child.out...)
	// A cap reached inside a separate-shell child (bash -c '…') is the same
	// fail-open as one reached here, and the note (#3995) must not depend on
	// which shell the padding ran in. Bindings stay separate; only the flag
	// propagates. Codex review of #4005.
	if child.alts != nil && child.alts.capped && ev.alts != nil {
		ev.alts.capped = true
	}
}

// childScope builds the table the carrier body evaluates against.
//
// eval runs in THIS shell: it shares the table outright, so its own bindings
// persist after it, exactly as bash does. A `-c` carrier is a child process and
// sees only the exported names plus this statement's prefix assignments — the
// distinction that keeps `K=~/.kube/config; bash -c 'cat "$K"'` (which reads
// nothing, K never having been exported) from becoming a false BLOCK.
// It shares the REGION STACK as well, and that is not cosmetic: an eval inside
// a subshell mutates this shell's table, and only a journal entry in the
// subshell's region can undo it when the subshell ends. Without it,
// `P=<protected>; (eval 'unset P'); cat "$P/config"` erased P for good and hid
// the read (#3752). Regions are pointers, so the child journals into the very
// frames the parent will close; it pushes and pops its own frames on its own
// slice and never touches the inherited prefix. A `-c` carrier is the opposite
// case: its maps are its own, so journalling its writes into the parent's
// regions would restore a CHILD's snapshot over the parent's state.
func (ev *scopeEval) childScope(sameShell bool, prefixNames []string) *scopeEval {
	if sameShell {
		return &scopeEval{
			view:     ev.view,
			owned:    ev.owned,
			exported: ev.exported,
			regions:  ev.regions,
			alts:     ev.alts,
			depth:    ev.depth + 1,
		}
	}
	child := &scopeEval{
		view:     make(map[string]string, len(ev.exported)+len(prefixNames)),
		owned:    make(map[string]bool, len(ev.exported)+len(prefixNames)),
		exported: make(map[string]bool, len(ev.exported)+len(prefixNames)),
		alts:     &altSet{},
		depth:    ev.depth + 1,
	}
	inherit := func(n string) {
		if v, ok := ev.view[n]; ok {
			child.bind(n, v)
			child.exported[n] = true
		}
	}
	for n := range ev.exported {
		inherit(n)
	}
	for _, n := range prefixNames {
		inherit(n)
	}
	// A conditionally superseded value the child can still see is still a
	// candidate inside its body.
	if ev.alts != nil {
		for _, e := range ev.alts.entries {
			if _, ok := child.view[e.name]; ok {
				child.alts.add(e.name, e.val)
			}
		}
	}
	return child
}

// inlineCodeArg returns the value of the `-c` operand, accepting the clustered
// spelling (`bash -lc 'code'`, `sh -ec 'code'`) the same way ExtractInlineCode's
// CFlagArg capture does.
func (ev *scopeEval) inlineCodeArg(args []*syntax.Word) (string, bool) {
	for i, w := range args {
		lit, ok := literalWord(w)
		if !ok || !strings.HasPrefix(lit, "-") || strings.HasPrefix(lit, "--") || len(lit) < 2 {
			continue
		}
		if !strings.HasSuffix(lit, "c") {
			continue
		}
		if i+1 >= len(args) {
			return "", false
		}
		return ev.resolve(args[i+1])
	}
	return "", false
}

// carrierExecName resolves a command word to the program name the carrier
// tables are keyed on, accepting an absolute or home-anchored path
// (`/bin/bash` is `bash`). A relative `./bash` is deliberately not resolved —
// far more likely a project script that happens to share the name, the same
// rule lookupShellSource applies.
func carrierExecName(word string) string {
	name := shellparse.NormalizeExecName(word)
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "~/") {
		return path.Base(name)
	}
	return name
}

// isShellIdentifier reports whether s is a valid scalar variable name.
func isShellIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !ok {
			return false
		}
		if i == 0 && c >= '0' && c <= '9' {
			return false
		}
	}
	return true
}

// mergeSyms overlays the ordered end-state on the fixed-point table. The
// ordered values are the accurate ones where both have an answer (append and
// reassignment are only right there); the fixed-point entries fill in names the
// ordered pass could not resolve, which is the record ctx.Assignments carried
// before #3706.
func mergeSyms(final, ordered map[string]string) map[string]string {
	if len(ordered) == 0 {
		return final
	}
	out := make(map[string]string, len(final)+len(ordered))
	for k, v := range final {
		out[k] = v
	}
	for k, v := range ordered {
		out[k] = v
	}
	return out
}
