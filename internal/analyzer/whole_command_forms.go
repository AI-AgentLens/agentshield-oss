package analyzer

import (
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// Alternative renderings of the WHOLE command that mean exactly what the raw
// text means, checked for every rule (not just anchored ones, unlike the
// per-statement candidates below).
//
// The line-continuation form has to live here rather than in the anchored-
// only retry: a backslash-newline lands wherever the line happened to wrap,
// so it breaks patterns in the MIDDLE — `aws\s+ec2\s+terminate-instances`
// fails on `aws \<NL>ec2 ...` even though the rule has no "^" at all (#3055).
// Both this and the joined per-statement forms are needed: this one recovers
// unanchored rules, the per-statement one recovers anchored rules whose
// statement is nested inside a compound.
//
// It returns every such rendering of raw except raw itself, deduplicated, in
// the order the passes add them. dequotedCommand and ifsNormalized are
// shellparse.DequoteCommand(raw) and shellparse.NormalizeIFS(raw), passed in
// because RegexAnalyzer.Analyze has already computed them.
//
// redactedForms (position.go) calls it too, on purpose (#4400): a position
// exclusion holds only if no rendering of the redacted command still matches,
// so subtraction has to see exactly the renderings the matcher matched. A
// hand-kept subset drifted three times in one PR, the last time on the ORDER
// of two passes rather than a missing name.
func buildWholeCommandForms(raw, dequotedCommand, ifsNormalized string) []string {
	var wholeCommandForms []string
	seen := map[string]bool{raw: true}
	addForm := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		wholeCommandForms = append(wholeCommandForms, s)
	}
	addForm(dequotedCommand)
	addForm(ifsNormalized)
	// A backslash/quote splice on the FIRST statement's executable word
	// defeats any cross-statement rule anchored on the ORIGINAL separator
	// (";", "&&", "|"): dequotedCommand above re-renders the whole command
	// through mvdan/sh's printer, which turns a top-level ";" into a
	// newline, so "s\leep 120; curl ..." dequotes to "sleep 120\ncurl ...",
	// and a rule pattern written with ";" between the two statements can
	// never match a "\n" (#3848 class B). FoldLeadingExecWord only touches
	// the first word's own bytes, leaving every separator exactly as
	// written.
	if leadingFolded := shellparse.FoldLeadingExecWord(raw); leadingFolded != "" {
		addForm(leadingFolded)
	}
	// Compose the two: DequoteCommand bails on raw whole-sale
	// the moment ANY word contains a ParamExp — including the ${IFS}/$IFS
	// token itself — so a command combining an ${IFS} separator with an
	// unrelated quote/backslash artifact elsewhere never got dequoted at
	// all via dequotedCommand above. Re-running DequoteCommand on the
	// ALREADY-IFS-normalized text (no more ${IFS} ParamExp left to bail
	// on) recovers it for unanchored rules the same way the per-statement
	// retry already does for anchored ones (#3044's composition, below).
	// Found via #3209: "cat${IFS}/etc\/shadow" downgraded BLOCK -> ALLOW
	// because neither candidate alone was both IFS-split AND dequoted.
	if ifsNormalized != "" {
		addForm(shellparse.DequoteCommand(ifsNormalized))
	}
	if joined := shellparse.JoinLineContinuations(raw); joined != "" {
		addForm(joined)
		addForm(shellparse.DequoteCommand(joined))
		addForm(shellparse.NormalizeIFS(joined))
	}
	// A `printf` format string or an `echo -e` argument whose escape
	// sequences the program EXPANDS, when that text is handed to an executor
	// (#3802). `printf '\\nufw disable\\n' | sh` runs the payload while the
	// two raw characters before it are a backslash and an `n` — both word
	// characters — so a rule opening with `\\b` cannot match. Measured at
	// 30.8% of BLOCKing commands that survive the `echo '<cmd>' | sh`
	// control. A whole-command form rather than an anchored-only retry for
	// the same reason line continuations are one: the escape lands
	// mid-pattern, so it defeats unanchored rules too.
	if emitted := shellparse.DecodeEmittedSeparators(raw); emitted != "" {
		addForm(emitted)
		addForm(shellparse.DequoteCommand(emitted))
		addForm(shellparse.NormalizeIFS(emitted))
	}
	// Indirect executable names ("x=aws; $x ec2 terminate-instances ...",
	// "$(echo aws) ec2 ...") are not substring-monotonic the way
	// quote-stripping/IFS-normalization are — the resolved word ("aws")
	// isn't a literal substring of the original text, so an UNANCHORED
	// rule (which only ever checks whole-command forms, see
	// isPositionSensitive) would never see it without this candidate
	// (#3089). The per-statement version below additionally covers
	// anchored ("^") rules against a resolved statement in isolation.
	if resolved := shellparse.ResolveIndirectExecutables(raw); resolved != "" {
		addForm(resolved)
		addForm(shellparse.DequoteCommand(resolved))
		addForm(shellparse.NormalizeIFS(resolved))
		// Same composition as the per-statement retry below: the
		// resolved text can itself be a wrapper/carrier ("env dd ...",
		// "bash -c 'dd ...'") that needs its own established peel.
		if unwrapped := shellparse.StripExecWrapperPrefix(resolved); unwrapped != "" {
			addForm(unwrapped)
			addForm(shellparse.DequoteCommand(unwrapped))
		}
		for _, frag := range shellparse.InlineCodeFragments(resolved) {
			addForm(frag)
			addForm(shellparse.NormalizeIFS(frag))
		}
	}
	// A brace-expansion group ("~/.{ssh,x}/id_rsa") hides the sensitive path
	// segment as literal text no substring of the raw command contains — the
	// "unanchored regex already saw every substring" argument that gates the
	// position-sensitive-only retry below does not apply here, so every rule
	// gets a shot at each resolved alternative, not just anchored ones (#3085).
	for _, alt := range shellparse.ExpandBraces(raw) {
		addForm(alt)
		// Compose with the other static transforms, same as every other
		// candidate source above (indirect-exec, line-continuation): a
		// brace-expanded alternative can ITSELF still carry a quote-splice
		// or ANSI-C ($'...') encoding that only resolves once dequoted —
		// e.g. "~/.{aws,x}/$'\x63'$'\x72'..." needs BOTH the brace group
		// resolved AND the ANSI-C fragments decoded before "credentials"
		// appears as literal text. Without this, composing brace-expansion
		// hiding with any other encoding reopens the gap each fix closed
		// individually (issue #3099 follow-up).
		addForm(shellparse.DequoteCommand(alt))
		addForm(shellparse.NormalizeIFS(alt))
	}
	// A '?'/'*' pathname-expansion wildcard hides a sensitive path segment
	// one shell-expansion phase after brace expansion — same "unmodeled
	// expansion phase" gap as ExpandBraces above, same reason every rule
	// (not just anchored ones) needs a shot at each resolution (#3102).
	for _, alt := range shellparse.DeglobSensitivePaths(raw) {
		addForm(alt)
		addForm(shellparse.DequoteCommand(alt))
		addForm(shellparse.NormalizeIFS(alt))
	}
	// An unset-parameter splice ("cur${zqx}l", "${zqx:-curl}") is a
	// whole-command concern for the same reason line continuations are:
	// it lands mid-pattern, so it defeats unanchored rules too. Applied
	// as a pass over every form collected above rather than at each
	// addForm site, because it composes with all of them — a brace group,
	// an indirect exec name and a quote-splice can each still carry one.
	//
	// Order matters in the composition with DequoteCommand, and in the
	// opposite direction from the ${IFS} case documented below:
	// DequoteCommand bails on any word containing a ParamExp, so
	// "~/.ss${zqx}h/id_r'sa'" stays undequotable until the splice is
	// folded away FIRST, which is what makes this a pass over the
	// already-collected forms rather than another entry in the list.
	for _, f := range append([]string{raw}, wholeCommandForms...) {
		if folded := shellparse.NormalizeUnsetParamExp(f); folded != "" {
			addForm(folded)
			addForm(shellparse.DequoteCommand(folded))
		}
		// A SINGLE-QUOTED inline-code body — `trap 'cat /${zqx}etc/shadow'
		// EXIT`, `eval '...'`, `bash -c '...'` — contains no ParamExp node
		// at all, because single quotes are fully literal to the parser.
		// The whole-command fold above is therefore a complete no-op on it;
		// the splice only becomes visible once the body is re-read as code.
		//
		// The per-statement candidates below fold these too, but those are
		// only consulted for position-sensitive (anchored) rules — so an
		// UNANCHORED rule matching a substring of the body (the /etc/shadow
		// rule is one) never saw the folded text. Only the folded fragment
		// is promoted here, never the raw one, so this cannot widen what
		// unanchored rules match for any command that has no splice.
		for _, frag := range shellparse.InlineCodeFragments(f) {
			addForm(shellparse.NormalizeUnsetParamExp(frag))
			// The comment just above — "only the folded fragment is
			// promoted, never the raw one" — rested on an assumption that
			// held right up until #3241: that a reconstructed payload is
			// always a SUBSTRING of the text it came from, so an unanchored
			// rule had already seen it. Payload reconstruction used to strip
			// quotes off the two ends of the word; it now performs real
			// quote removal, because that is what the carrier's own shell
			// does. `bash -c rm\ -rf\ /` reconstructs to "rm -rf /", which
			// appears nowhere in the raw command — new literal text, exactly
			// like a brace expansion or a resolved indirect exec name, and
			// needing whole-command promotion for the same reason.
			//
			// Gated on the substring test rather than promoted outright.
			// For every payload whose word boundaries were already visible
			// — `bash -c 'rm -rf /'` and every other ordinary spelling —
			// the fragment IS a substring, nothing is added, and what
			// unanchored rules match is byte-for-byte unchanged. The gate
			// is what keeps this from being a blanket widening.
			if !strings.Contains(f, frag) {
				addForm(frag)
				addForm(shellparse.DequoteCommand(frag))
			}
		}
	}
	// A whole-word brace group ("{rm,-rf,/}") is a DIFFERENT construct
	// from ExpandBraces' path-segment alternatives above: the group IS
	// the entire word, so its items become the command word and its
	// arguments, not alternative candidates for one argument — resolving
	// `{rm,-rf,/}` to alternatives yields "rm", "-rf", "/" as three
	// separate candidates, none of which is the command that runs.
	// Applied as a pass over every form collected so far (same reasoning
	// as the unset-parameter fold above — it composes with quote-splices,
	// indirect-exec names and IFS separators) rather than its own addForm
	// site, so it runs after the unset-parameter fold and sees an
	// already-simplified form (issue #3217).
	for _, f := range append([]string{raw}, wholeCommandForms...) {
		if expanded := shellparse.NormalizeBraceWordList(f); expanded != "" {
			addForm(expanded)
			addForm(shellparse.DequoteCommand(expanded))
			addForm(shellparse.NormalizeIFS(expanded))
		}
	}
	// A split-concat assignment ("P1=~/.ssh; P2=id_rsa; cat $P1/$P2") reads
	// exactly the path a literal-keyed command_regex rule is written
	// against, but the raw text never contains that literal — Layer 2.5
	// (substitution.go) already resolves this for the ~10 protected_paths
	// globs, but none of the other ~1,100 pack rules ever saw it (issue
	// #3249). Applied as a pass over every form collected so far, same
	// reasoning as the brace-word-list pass just above: it composes with
	// quote-splices, IFS separators and brace-expanded alternatives.
	for _, f := range append([]string{raw}, wholeCommandForms...) {
		if materialized := shellparse.MaterializeAssignments(f); materialized != "" {
			addForm(materialized)
			addForm(shellparse.DequoteCommand(materialized))
			addForm(shellparse.NormalizeIFS(materialized))
		}
	}
	// Command-execution literals recovered from inside an interpreter
	// heredoc body (#3697) — "csrutil disable" from a python heredoc
	// calling os.system("csrutil disable"). Checked for every rule, not
	// just anchored ones: this is literal command text a real call would
	// run, exactly like the other whole-command forms above. Use 2 of 2
	// — see InterpreterHeredocExecStatements' doc comment; use 1
	// (per-statement exclusion scoping) is ctx.RawStatements, populated
	// separately via AttributionStatements.
	for _, cand := range InterpreterHeredocExecStatements(raw) {
		addForm(cand)
		addForm(shellparse.DequoteCommand(cand))
	}
	return wholeCommandForms
}
