package shellparse

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// NormalizeUnsetParamExp returns a reconstruction of command with parameter
// expansions of PROVABLY-UNSET variables folded to the text a real shell
// produces for them, so the AST every downstream analyzer consumes reflects
// the command that actually runs rather than the pre-expansion source text.
//
// An unset variable expands to nothing. That single fact makes
// `r${zqx}m -rf /` and `rm -rf /` the same invocation, and makes
// `${zqx:-rm} -rf /` the same one again via the default-value form — but a
// parser operating on pre-expansion text sees an executable named
// "r${zqx}m", so executable-name matching, flag normalization and
// protected-path argument checks all silently stop matching. This is the same
// "guard matches pre-expansion text" class as the ${IFS} separator bypass
// (#3044, NormalizeIFS) and the constant-scalar indirection resolved by
// resolveExecWord (#3089) — with the crucial difference that no symbol table
// can help here, because the attacker's whole point is that the variable is
// never bound.
//
// Measured against the corpus of commands this engine BLOCKs standalone,
// splicing an empty `${zqx}` into the middle of the executable name
// downgraded 75.1% of them (1724/2297), and rewriting the executable as
// `${zqx:-<exec>}` downgraded 59.2% (1365/2306) — the largest bypass class
// found on this codebase to date, past the 68.6% ${IFS} gap (#3044), the
// 52.5% line-continuation gap (#3055) and the 20.8% compound-wrapping gap
// (#3045). Verified against real bash AND POSIX sh: `e${zqx}cho hi` and
// `${zqx:-echo} hi` both run.
//
// # Why this cannot simply fold every expansion
//
// Folding an unset variable to "" is only sound when the variable really is
// unset, and this function can never see the caller's exported environment.
// `rm -rf $BUILD_DIR/` is the notorious Steam-uninstall shape: it IS
// `rm -rf /` when BUILD_DIR is unset, but it is an ordinary build script
// otherwise, and BLOCKing every developer who writes it would be a false
// positive on the overwhelmingly common case. So the fold is gated on a
// distinction that carries the actual signal:
//
//	A parameter expansion that SPLITS A CONTIGUOUS RUN OF WORD CHARACTERS
//	is not parameterization — it is obfuscation.
//
// Legitimate parameterization always lands on a token or path-component
// boundary (`$BUILD_DIR/dist`, `${PREFIX} install`, `rm -rf "$DIR"`). Nobody
// writes `r${BUILD_DIR}m` to mean anything. So an expansion whose unset value
// is EMPTY is folded only when the characters immediately before and after it
// are both word characters — `r${zqx}m`, `/etc/pass${zqx}wd`,
// `cur${zqx}l` — and is left completely alone at every token boundary, which
// is where every legitimate use lives.
//
// Value-PRODUCING forms (`${zqx:-rm}`, `${zqx:=rm}`) need no such gate. They
// fold to their default word, which is precisely the branch a shell takes
// when the variable is unset, and a default is by construction the author's
// stated fallback — folding to it can only make the analyzed command more
// like the one that runs.
//
// # Deliberate exclusions
//
//   - Special and positional parameters ($1, $@, $?, $$, ...) are never
//     "unset variables" — only identifier-shaped names are considered.
//   - Names in wellKnownEnvVars are skipped: HOME/PATH/USER and friends are
//     set in every real shell, so treating them as empty would model a shell
//     that does not exist.
//   - Names assigned anywhere in the command are skipped, so this never
//     races the constant-symbol-table resolution in resolveExecWord (#3089)
//     or substitution.go — `x=rm; ${x} -rf /` stays that layer's job.
//   - The error form (`${x:?msg}`) is skipped because bash ABORTS instead of
//     running the command; folding it would flag a command that never runs.
//   - `${#x}` (length) expands to "0", not empty, and `${!x}` (indirect)
//     resolves through a second variable — neither is folded.
//
// Returns "" (a no-op sentinel, same convention as NormalizeIFS and
// DequoteCommand) when the command contains no "$", when nothing was
// rewritten, or when parsing fails — callers fall back to the raw command in
// all three cases.
func NormalizeUnsetParamExp(command string) string {
	return NormalizeUnsetParamExpInContext(command, nil, nil)
}

// NormalizeUnsetParamExpInContext is NormalizeUnsetParamExp with names known
// to be assigned OUTSIDE command treated exactly as if they were assigned
// inside it — i.e. never folded.
//
// It exists because this normalizer is applied to two different scopes. Given
// the whole command, assignedNames() sees every assignment and the "names
// assigned anywhere in the command are skipped" exclusion documented above
// holds. Given a SINGLE STATEMENT of a compound command, an assignment in a
// SIBLING statement is invisible, so `x=:; ${x:-rm} -rf /` folds to `rm -rf /`
// when what actually runs is `: -rf /`. Bash resolves parameters against the
// whole shell, not against one statement, so the statement-scoped caller has
// to supply the rest of the picture.
//
// Passing nil reproduces NormalizeUnsetParamExp exactly.
//
// outerEmptyBound carries the names a sibling statement bound to a known-empty
// value (a `read` at EOF, #3876); those fold with set-but-empty semantics —
// see unsetExpansion — which differ from unset for `${x-w}`, `${x=w}` and
// `${x+w}`.
func NormalizeUnsetParamExpInContext(command string, outerAssigned, outerEmptyBound map[string]bool) string {
	// Iterated to a fixpoint because one pass folds only the OUTERMOST
	// resolvable expansion of a nest: `${zqx:-r${foo}m}` has a default word
	// that is not statically resolvable until the inner splice is folded, so
	// pass 1 yields `${zqx:-rm}` and pass 2 yields `rm`. Bounded at three
	// because each pass strictly shortens the text and real nesting is one or
	// two deep — the cap is a runaway guard, not a coverage limit.
	out := ""
	for i := 0; i < 3; i++ {
		next := normalizeUnsetParamExpOnce(command, outerAssigned, outerEmptyBound)
		if next == "" || next == command {
			break
		}
		out, command = next, next
	}
	return out
}

func normalizeUnsetParamExpOnce(command string, outerAssigned, outerEmptyBound map[string]bool) string {
	if !strings.Contains(command, "$") {
		return ""
	}

	reader := strings.NewReader(command)
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(reader, "")
	if err != nil {
		return ""
	}

	assigned, emptyBound := assignedNames(file)
	// Names assigned outside this text count as assigned. Merged into a copy
	// so a caller's map is never mutated — the same map is reused across every
	// statement of one command.
	assigned = mergeNames(assigned, outerAssigned)
	emptyBound = mergeNames(emptyBound, outerEmptyBound)
	execStarts := execWordStarts(file)

	type span struct {
		start, end  int
		replacement string
	}
	var spans []span

	syntax.Walk(file, func(node syntax.Node) bool {
		pe, ok := node.(*syntax.ParamExp)
		if !ok {
			return true
		}
		repl, ok := unsetExpansion(pe, assigned, emptyBound)
		if !ok {
			return true
		}
		start, end := int(pe.Pos().Offset()), int(pe.End().Offset())
		if start < 0 || end > len(command) || start >= end {
			return true
		}
		// An expansion that produces nothing is folded only where it splits a
		// contiguous run of word characters — see the "cannot simply fold
		// every expansion" section above — or where it opens the EXECUTABLE
		// word, which has no benign reading either. A value-producing form
		// needs no such gate.
		if repl == "" &&
			!splitsWordRun(command, start, end) &&
			!opensExecWord(command, start, end, execStarts) {
			return true
		}
		spans = append(spans, span{start, end, repl})
		return true
	})

	if len(spans) == 0 {
		return ""
	}

	var sb strings.Builder
	last := 0
	for _, s := range spans {
		if s.start < last {
			continue // overlapping/nested expansion — skip defensively, never corrupt the text
		}
		sb.WriteString(command[last:s.start])
		sb.WriteString(s.replacement)
		last = s.end
	}
	sb.WriteString(command[last:])

	out := strings.TrimSpace(sb.String())
	if out == command {
		return ""
	}
	return out
}

// splitsWordRun reports whether the byte immediately before start and the byte
// immediately after end are both word characters — i.e. removing [start,end)
// would join two runs of identifier text into one. That is the obfuscation
// signature this normalization keys on; every legitimate parameterization sits
// at a token or path-component boundary and fails this test.
// opensExecWord reports whether the expansion at [start,end) is the FIRST
// thing in a word that sits in executable position, immediately followed by
// word text — `${zqx}rm -rf /`, which runs `rm -rf /`.
//
// The splitsWordRun gate cannot see this shape: there is no character before
// the expansion to test, so a token-initial splice slipped every version of
// this fold. Measured at 26.2% of the BLOCKing corpus (605/2308) once the
// interior and default forms were closed — the obvious next move for anyone
// who reads the fix.
//
// Restricting it to executable position is what keeps it safe. In ARGUMENT
// position a leading expansion is the single most common shape of ordinary
// parameterization — `ls ${PREFIX}bin`, `cp ${SRC}file .` — and folding those
// would rewrite benign commands. In executable position there is no such
// reading: nobody names a command by prefixing it with an expansion that has
// to vanish for the name to be valid. The residual accepted here is
// `${VENV}bin/python script.py` folding to `bin/python script.py`, which is
// benign in both spellings.
func opensExecWord(command string, start, end int, execStarts map[int]bool) bool {
	if !execStarts[start] {
		return false
	}
	right, ok := neighborByte(command, end, +1)
	return ok && isRightAdjacencyByte(right)
}

// execWordStarts collects the byte offset of every word in executable
// position (the command word of a CallExpr), so opensExecWord can tell a
// command name from an argument.
func execWordStarts(file *syntax.File) map[int]bool {
	starts := map[int]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) > 0 {
			starts[int(call.Args[0].Pos().Offset())] = true
		}
		return true
	})
	return starts
}

func splitsWordRun(command string, start, end int) bool {
	left, ok := neighborByte(command, start-1, -1)
	if !ok || !isLeftAdjacencyByte(left) {
		return false
	}
	right, ok := neighborByte(command, end, +1)
	return ok && isRightAdjacencyByte(right)
}

// neighborByte returns the first byte from i in direction step that a real
// shell would still see once quote removal has run, skipping over quote
// characters themselves.
//
// The quotes have to be transparent here, because they are not part of the
// word's value: in `~/.agentshi'e'${zqx}ld/` the byte physically preceding
// the expansion is a closing quote, but the character the expansion actually
// abuts is "e", and the path resolves to ~/.agentshield/ at runtime. Reading
// the raw byte would decline to fold exactly the commands that compose this
// splice with a quote splice — and that composition is not hypothetical, it
// is the shape the enterprise self-protection tests exercise
// (TestSelfProtect_UnsetParamExpBypass_ComposedWithQuoteSplice).
//
// Neither order of the two transforms can resolve that composition on its
// own: DequoteCommand bails on any word holding a ParamExp, so dequoting
// first is a no-op, and folding first was blocked by the raw-byte read this
// replaces.
func neighborByte(command string, i, step int) (byte, bool) {
	for i >= 0 && i < len(command) {
		if c := command[i]; c != '\'' && c != '"' {
			return c, true
		}
		i += step
	}
	return 0, false
}

// isRightAdjacencyByte is the character class the byte AFTER the expansion
// must fall in for the fold to apply: identifier characters plus '-', which
// extends the fold to spliced FLAGS ("rm -${zqx}rf /", "curl -${zqx}sSL ...")
// — worth a further 17 points of corpus coverage on its own, because the
// leading '-' of a flag is not an identifier character and every flag splice
// therefore slipped the first version of this gate.
//
// '+' joins the class for the same reason as '-': it is a flag/mode
// character, not a path or version separator, and a splice landing next to
// one has no benign reading — `chmod a${zqx}+rwx`, `chmod +${zqx}s`,
// `set +${zqx}o history` (#3207). Because this function backs both sides of
// splitsWordRun (isLeftAdjacencyByte delegates here), adding it once folds
// the splice regardless of which side of the '+' it lands on. Measured
// against the BLOCKing corpus: closes 7 of the 23 residual arg2-splice leaks
// with zero regressions on TestAccuracy's ALLOW/AUDIT corpus — '+' inside a
// legitimate value (a URL, a version string) only appears at a token
// boundary or glued to '=', neither of which this gate ever sees, since
// splitsWordRun requires a word-run character (not '=' or whitespace) on
// BOTH sides.
//
// '/' and '.' are deliberately excluded HERE, on the right. They are what
// legitimate parameterization is followed by — `k8s/${ENV}/deployment.yaml`,
// `${BUILD}/dist`, `file${N}.txt` — where the expansion names a whole path
// component or filename stem, and folding it away would rewrite a benign
// path into one the author never wrote.
func isRightAdjacencyByte(b byte) bool {
	return b == '-' || b == '+' || isWordByte(b)
}

// isLeftAdjacencyByte is the same class for the byte BEFORE the expansion,
// plus '/' and '.'. The asymmetry is load-bearing and was measured, not
// guessed: `cat /${zqx}etc/shadow` runs `cat /etc/shadow` (verified in bash),
// and splices anchored on a leading path separator were the single largest
// group left in the residual after the first version of this gate shipped.
//
// Allowing '/' on the left while excluding it on the right is what separates
// the two: an expansion sitting BETWEEN two separators (`k8s/${ENV}/x`) is a
// whole path component and stays untouched, while one that GLUES a separator
// to an identifier (`/${zqx}etc`) reconstructs a single path element and is
// folded. The residual accepted here is a benign one — `s3://bucket/${P}data`
// folds to `s3://bucket/data`, a shorter and strictly less sensitive path
// than the original, so it cannot manufacture a match on a protected path.
//
// '.' joined the left class in #3341 for the identical reason: a leading dot
// immediately followed by a vanishing expansion reconstructs a dotfile name
// that was hidden from it — `cat .${zqx}env` runs `cat .env` (verified in
// bash), and the same shape hides `.git/hooks/`, `.devcontainer/`,
// `.mcp.json` and `.cursorrules` from every path-glob and command_regex rule
// keyed on those literals. '.' stays excluded on the RIGHT (isRightAdjacencyByte
// does not carry it) precisely because `file${N}.txt` is the common shape
// there and folding it would strip a legitimate extension boundary — the same
// asymmetry '/' already established, just mirrored: '/' is safe on the left
// because a path separator can only START a component there, and '.' is safe
// on the left for the same reason a dot can only start a dotfile's name, never
// its extension.
//
// '~' is deliberately NOT on either side, and not because of false positives:
// `~${zqx}/.aws/credentials` is not an exploit at all. Bash performs tilde
// expansion BEFORE parameter expansion, so the tilde-prefix is the literal
// text "${zqx}", which is not a valid login name — the tilde does not expand,
// the path stays relative, and the read fails. Verified in bash. Folding it
// would model a command that does not run.
func isLeftAdjacencyByte(b byte) bool {
	return b == '/' || b == '.' || isRightAdjacencyByte(b)
}

func isWordByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

// mergeNames returns a set holding both inputs, copying so neither caller
// map is mutated. It returns a as-is when b is empty.
func mergeNames(a, b map[string]bool) map[string]bool {
	if len(b) == 0 {
		return a
	}
	merged := make(map[string]bool, len(a)+len(b))
	for n := range a {
		merged[n] = true
	}
	for n := range b {
		merged[n] = true
	}
	return merged
}

// unsetExpansion returns the literal text pe expands to when its variable is
// unset, and whether that value is statically determinable at all. See
// NormalizeUnsetParamExp's doc comment for why each shape is included or not.
//
// A name in emptyBound is SET but empty (a `read` at EOF, #3876). bash treats
// that the same as unset for a bare expansion, for the `:`-forms, and for
// slicing, trimming and case-folding — but NOT for the non-colon forms:
// `${x-w}` and `${x=w}` expand to "" (the variable is set), and `${x+w}`
// expands to w. Modelling those as unset would fold `${x-rm} -rf /` to
// `rm -rf /` when bash runs `-rf /` (Codex review of #3962). Verified on
// bash 3.2 and 5.3.
func unsetExpansion(pe *syntax.ParamExp, assigned, emptyBound map[string]bool) (string, bool) {
	if pe.Param == nil || !isIdentifier(pe.Param.Value) {
		return "", false // special/positional parameter ($@, $1, $?, $$)
	}
	name := pe.Param.Value
	if assigned[name] || wellKnownEnvVars[name] {
		return "", false
	}
	setButEmpty := emptyBound[name]
	// Indirect (${!x}) resolves through a second variable; length (${#x})
	// expands to "0", not empty; an explicit index is an array subscript.
	if pe.Excl || pe.Length || pe.Width || pe.Index != nil || pe.NestedParam != nil {
		return "", false
	}
	// Slice (${x:1:2}) and replace (${x//a/b}) of an unset variable are both
	// empty, and can carry no other modifier alongside.
	if pe.Slice != nil || pe.Repl != nil {
		if pe.Exp != nil {
			return "", false
		}
		return "", true
	}
	if pe.Exp == nil {
		return "", true // bare ${x} / $x
	}

	switch pe.Exp.Op {
	case syntax.DefaultUnset, syntax.AssignUnset:
		// ${x-word} / ${x=word} -> word when x is unset, "" when x is set
		// but empty.
		if setButEmpty {
			return "", true
		}
		return staticWordText(pe.Exp.Word)
	case syntax.DefaultUnsetOrNull, syntax.AssignUnsetOrNull:
		// ${x:-word} / ${x:=word} -> word whether x is unset or empty.
		return staticWordText(pe.Exp.Word)
	case syntax.AlternateUnset:
		// ${x+word} -> "" when x is unset, word when x is set but empty.
		if setButEmpty {
			return staticWordText(pe.Exp.Word)
		}
		return "", true
	case syntax.AlternateUnsetOrNull:
		// ${x:+word} -> "" whether x is unset or empty.
		return "", true
	case syntax.RemSmallSuffix, syntax.RemLargeSuffix,
		syntax.RemSmallPrefix, syntax.RemLargePrefix,
		syntax.UpperFirst, syntax.UpperAll,
		syntax.LowerFirst, syntax.LowerAll:
		// Trimming or case-folding an empty value is still empty.
		return "", true
	default:
		// ErrorUnset/ErrorUnsetOrNull abort the command instead of running it;
		// anything else is a shell-specific form not modelled here.
		return "", false
	}
}

// staticWordText returns w's text when w is built entirely from literal and
// quoted-literal parts. A default word containing its own expansion
// (`${x:-$(id)}`) is not statically resolvable and is not folded.
func staticWordText(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", true // ${x:-} — empty default
	}
	var sb strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return "", false
				}
				sb.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return sb.String(), true
}

func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isWordByte(s[i]) {
			return false
		}
		if i == 0 && s[i] >= '0' && s[i] <= '9' {
			return false // positional parameter ($1, $12)
		}
	}
	return true
}

// assignedNames collects every variable name the command binds, so an
// expansion of one is left for the constant-symbol-table layers
// (resolveExecWord #3089, substitution.go) rather than folded to empty here.
//
// #3876 (a): a `read`/`mapfile`/`readarray` binds its target only
// if something arrives on stdin. With `</dev/null`, an empty here-string, or
// no stdin source at all, bash leaves the target EMPTY — which expands
// like unset for a bare expansion — so such a read must not switch the fold
// off. Only a read with a plausible non-empty source (a file that is not
// /dev/null, a non-empty or non-literal here-string, a heredoc, a pipe,
// `<&`, `-u`) counts as a binding here. The targets of an empty read are
// returned separately as emptyBound, because set-but-empty and unset diverge
// for `${x-w}`, `${x=w}` and `${x+w}` (see unsetExpansion).
func assignedNames(file *syntax.File) (names, emptyBound map[string]bool) {
	names = map[string]bool{}
	emptyBound = map[string]bool{}
	emptyReads := map[*syntax.CallExpr]bool{}
	piped := map[*syntax.Stmt]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.BinaryCmd:
			if n.Op == syntax.Pipe || n.Op == syntax.PipeAll {
				piped[n.Y] = true
				if inner, ok := n.Y.Cmd.(*syntax.BinaryCmd); ok && (inner.Op == syntax.Pipe || inner.Op == syntax.PipeAll) {
					piped[inner.X] = true
				}
			}
		case *syntax.Stmt:
			if call, ok := n.Cmd.(*syntax.CallExpr); ok && isReadLikeCall(call) && !piped[n] && !readHasPlausibleSource(call, n.Redirs) {
				emptyReads[call] = true
			}
		case *syntax.CallExpr:
			for _, a := range n.Assigns {
				if a.Name != nil {
					names[a.Name.Value] = true
				}
			}
			// `read x`, `mapfile -t x`, `readarray x` bind their arguments.
			if len(n.Args) > 0 && !emptyReads[n] {
				// literalExecName, not wordLiteral: a spliced `r\ead x` still binds
				// x, and missing it here folds `r${x}m` as if x were unset — a false
				// BLOCK on a command bash runs as `r<value>m` (#3874 review, C4).
				if isReadLikeCall(n) {
					for _, arg := range n.Args[1:] {
						if v := wordLiteral(arg); isIdentifier(v) {
							names[v] = true
						}
					}
				}
			} else if len(n.Args) > 0 && emptyReads[n] {
				for _, arg := range n.Args[1:] {
					if v := wordLiteral(arg); isIdentifier(v) {
						emptyBound[v] = true
					}
				}
			}
		case *syntax.DeclClause:
			for _, a := range n.Args {
				if a.Name != nil {
					names[a.Name.Value] = true
				}
			}
		case *syntax.ForClause:
			if wi, ok := n.Loop.(*syntax.WordIter); ok && wi.Name != nil {
				names[wi.Name.Value] = true
			}
		}
		return true
	})
	return names, emptyBound
}

func isReadLikeCall(call *syntax.CallExpr) bool {
	lit, _ := literalExecName(call)
	return lit == "read" || lit == "mapfile" || lit == "readarray"
}

// readHasPlausibleSource reports whether a read-like builtin could bind a
// non-empty value: stdin is redirected from something other than /dev/null,
// a here-string is non-empty (or not statically known), a heredoc or `<&`
// feeds it, or `-u N` names another descriptor. A bare `read NAME` with no
// stdin source is treated as reading EOF — the hook mediates non-interactive
// commands, so there is no terminal to answer it.
func readHasPlausibleSource(call *syntax.CallExpr, redirs []*syntax.Redirect) bool {
	for _, arg := range call.Args[1:] {
		if v := wordLiteral(arg); strings.HasPrefix(v, "-u") {
			return true
		}
	}
	for _, r := range redirs {
		if r == nil {
			continue
		}
		if r.N != nil && r.N.Value != "0" {
			continue
		}
		switch r.Op {
		case syntax.RdrIn:
			val, ok := literalWordValue(r.Word)
			if !ok || val != "/dev/null" {
				return true
			}
		case syntax.WordHdoc:
			val, ok := literalWordValue(r.Word)
			if !ok || strings.TrimSpace(val) != "" {
				return true
			}
		case syntax.Hdoc, syntax.DashHdoc, syntax.DplIn, syntax.RdrInOut:
			return true
		}
	}
	return false
}

func wordLiteral(w *syntax.Word) string {
	if w == nil || len(w.Parts) != 1 {
		return ""
	}
	lit, ok := w.Parts[0].(*syntax.Lit)
	if !ok {
		return ""
	}
	return lit.Value
}

// wellKnownEnvVars are set in essentially every real shell, so modelling them
// as unset would describe a shell that does not exist. Skipping them costs no
// coverage: an attacker splicing `r${HOME}m` gets `r/Users/xm`, not `rm`.
var wellKnownEnvVars = map[string]bool{
	"HOME": true, "PATH": true, "PWD": true, "OLDPWD": true, "USER": true,
	"LOGNAME": true, "SHELL": true, "TERM": true, "HOSTNAME": true, "HOST": true,
	"TMPDIR": true, "TMP": true, "TEMP": true, "LANG": true, "LC_ALL": true,
	"SHLVL": true, "UID": true, "EUID": true, "PPID": true, "IFS": true,
	"RANDOM": true, "SECONDS": true, "LINENO": true, "BASH": true,
	"BASH_VERSION": true, "BASH_SOURCE": true, "PS1": true, "PS2": true,
	"EDITOR": true, "VISUAL": true, "PAGER": true, "MANPATH": true,
	"LD_LIBRARY_PATH": true, "PYTHONPATH": true, "GOPATH": true, "GOROOT": true,
	"JAVA_HOME": true, "NODE_PATH": true, "VIRTUAL_ENV": true, "CONDA_PREFIX": true,
}
