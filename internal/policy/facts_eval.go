package policy

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/facts"
)

// The back end's evaluator for a dialect lane (ADR-001, step 4 part 1).
//
// A lane reads text in its own grammar and hands over facts.Facts (D3); this
// file decides on them. It knows no dialect: aliases, quoting and variable
// spellings were resolved in the lane, so `gc $env:USERPROFILE\.ssh\id_rsa`
// arrives as a command named get-content and a path `~/.ssh/id_rsa`. It is
// not routed yet: part 2 adds the lane beside the shell pipeline on the
// routing table's rows and combines them with stricterResult (D4).
//
// What it decides, in order:
//
//  1. Self-protection, on a managed host only (decision 3, "only known reads
//     pass"): a text naming AgentShield's config directory is blocked unless
//     it is one plain command on factsReadOnlyCommands. Same rule id, reason
//     and (absent) taxonomy as the shell's sp-block-config-touch.
//  2. Protected paths, with every pattern the shell engine enforces (shipped
//     and customer), under the readings a Windows host needs: as written,
//     letter case folded, and Windows separators. A hit on a whole value
//     (facts.Facts.Paths) BLOCKs as `protected-path` with the taxonomy a bash
//     read of the same file gets.
//  3. The consumer carve-out: a credential path used only in a designated
//     consumer's slot (`ssh -i <key>`) is AUDIT `protected-path-consumer`,
//     as on the shell.
//  4. The PowerShell pack rules (facts_rules.go, ADR-001 step 5), when no
//     protected path decided the text: the most restrictive matching rule
//     decides, as the shell combiner decides on findings, and a protected
//     path's BLOCK keeps its own record, as the shell's protected-path check
//     runs before its pipeline. A consumer's AUDIT record is added after.
//  5. Mentions (facts.Facts.Mentions): a protected path named only inside a
//     longer value or found only by the lane's raw scan is recorded with a
//     path_mention note and floors the decision at AUDIT. It never BLOCKs:
//     naming a file is not reading it. Self-protection (1) still counts
//     mentions, as bash's default-deny sp-block-config-touch counts any
//     naming of the config directory.
//  6. The AUDIT floor (D4): a lane note means the lane was unsure, so the
//     decision is at least AUDIT.
//  7. The dialect note (decision 2) on every result.
//
// The engine's mode applies as on the shell: audit-only lowers a
// protected-path BLOCK unless the self-protection keep accepts it, and never
// lowers a self-protection BLOCK (the hook's middleware does not).
//
// It does not recover from a panic. A lane that fails goes through the
// caller's failSafeDecision (D9), which knows whether the host fails closed;
// a recover here could only guess.

// FactsOptions is what EvaluateFacts needs to know about the host.
type FactsOptions struct {
	// Managed reports a managed host (managed.json), whose AgentShield config
	// directory is self-protected.
	Managed bool
	// Home is the home directory `~` stands for. "" uses the engine's.
	Home string
}

// SelfProtectRuleID is the rule id a managed host's self-protection BLOCK
// records: the hook's enterprise middleware writes it for a shell command
// (internal/cli/hook.go), and EvaluateFacts for a lane's text.
const SelfProtectRuleID = "enterprise-self-protect"

// configTouchRule is the shell's default-deny self-protection rule
// (enterprise.selfProtectRules), which EvaluateFacts mirrors for a lane.
const configTouchRule = "sp-block-config-touch"

// factsReadOnlyCommands are the commands a managed host lets a lane's text
// run against AgentShield's config directory (decision 3: only known reads
// pass), by canonical name. An entry asserts that none of the command's
// parameters writes a file or runs code. Their common parameters
// (-OutVariable, -ErrorVariable and the like) write only session variables.
//
// Their OUTPUT can do more: Get-Item returns a FileInfo, and
// `(Get-Item <policy>).Delete()` deletes the policy while its only command
// is Get-Item. So the exception also needs a Simple text (facts.Facts), in
// which nothing calls a method on the output, pipes it on or redirects it.
//
// Adding an entry is a self-protection decision (Kai, then Gary).
var factsReadOnlyCommands = map[string]string{
	"get-content":      "prints a file's lines; -Wait only blocks, no parameter writes",
	"get-item":         "prints the item; no parameter writes",
	"get-childitem":    "lists a directory; no parameter writes",
	"test-path":        "returns a boolean",
	"select-string":    "prints matching lines; it has no output-file parameter",
	"get-filehash":     "prints a digest",
	"measure-object":   "prints counts and sums of its input",
	"resolve-path":     "prints the resolved path",
	"get-itemproperty": "prints an item's properties; Set-ItemProperty is the writer",
}

// EvaluateFacts decides on what a dialect lane read. cwd is the directory the
// text runs in: a relative path is also read under it.
func (e *Engine) EvaluateFacts(f facts.Facts, cwd string, opt FactsOptions) EvalResult {
	home := opt.Home
	if home == "" {
		home = e.homeDir
	}
	r := EvalResult{
		Decision:       e.policy.Defaults.Decision,
		TriggeredRules: []string{},
		Reasons:        []string{},
		TaxonomyRefs:   []string{},
		Notes:          factsNotes(f),
	}

	selfProtect := opt.Managed && factsNamesPattern(f, ManagedConfigProtectedPath, home, cwd) && !factsKnownRead(f)
	var hits []string
	if selfProtect {
		r.Decision = DecisionBlock
		r.TriggeredRules = []string{SelfProtectRuleID}
		r.Reasons = []string{fmt.Sprintf("Blocked: attempt to modify AgentShield configuration (rule: %s)", configTouchRule)}
		// No taxonomy, as for the shell rule: it blocks reads and writes
		// alike, and a read is not tampering (#4666).
	} else {
		patterns := factsProtectedPatterns(e.policy.Defaults.ProtectedPaths, opt.Managed)
		pattern, matched, hit := factsProtectedPath(f, patterns, home, cwd)
		consumer := ""
		if hit {
			consumer = e.factsConsumerOnly(f, patterns, home, cwd)
		}
		if !hit || consumer != "" {
			// The PowerShell pack rules (ADR-001 step 5), as the shell runs its
			// pipeline: only when no protected path decided the text first.
			r = e.factsRuleResult(r, f, cwd)
		}
		if mentioned, ok := factsMentionedPattern(f, patterns, home, cwd); ok {
			r.Notes = analyzer.AppendNote(r.Notes, analyzer.Note{Kind: analyzer.NotePathMention, Detail: mentioned})
			if preDowngradeRank(r) < preDowngradeRank(EvalResult{Decision: DecisionAudit}) {
				r.Decision = DecisionAudit
			}
		}
		if exe := consumer; hit && exe != "" {
			r.TriggeredRules = append(r.TriggeredRules, ProtectedPathConsumerRuleID)
			r.Reasons = append(r.Reasons, fmt.Sprintf("Protected credential path used by its designated consumer (%s) — recorded, not blocked", exe))
			if r.Decision == DecisionAllow {
				r.Decision = DecisionAudit
			}
		} else if hit {
			hits = matched
			r.Decision = DecisionBlock
			r.TriggeredRules = append(r.TriggeredRules, ProtectedPathRuleID)
			r.Reasons = append(r.Reasons, fmt.Sprintf("Access to protected path denied: %s", pattern))
			r.TaxonomyRefs = addProtectedPathTaxonomy(r.TaxonomyRefs, pattern, factsReceiptHits(f, pattern, hits, home, cwd))
		}
	}

	// D4: a lane that reports uncertainty decides at least AUDIT, whatever
	// the policy's default, so no lower decision of another lane can win.
	if len(f.Notes) > 0 && preDowngradeRank(r) < preDowngradeRank(EvalResult{Decision: DecisionAudit}) {
		r.Decision = DecisionAudit
	}

	if !selfProtect && !e.factsKeepsBlock(r, hits, home, cwd) {
		r = applyModeDowngrade(r, e.mode)
	}
	r.Explanation = buildExplanation(r)
	return r
}

// factsNotes are the result's notes: the dialect, then every lane note.
func factsNotes(f facts.Facts) []analyzer.Note {
	dialect := f.Dialect
	if dialect == "" {
		dialect = "unknown"
	}
	notes := []analyzer.Note{{Kind: analyzer.NoteDialect, Detail: dialect}}
	for _, n := range f.Notes {
		notes = analyzer.AppendNote(notes, analyzer.Note{Kind: string(n.Kind), Detail: n.Detail})
	}
	return notes
}

// factsProtectedPatterns is the protected_paths list the shell engine
// enforces: every pattern, shipped and customer. Not CustomerProtectedPaths,
// the tool-call surfaces' list, which drops every shipped pattern. On a
// managed host the config directory's pattern is left to self-protection,
// whose known reads it would otherwise block.
func factsProtectedPatterns(all []string, managed bool) []string {
	if !managed {
		return all
	}
	out := make([]string, 0, len(all))
	for _, p := range all {
		if p != ManagedConfigProtectedPath {
			out = append(out, p)
		}
	}
	return out
}

// factsReading is one spelling a path is matched under, the readings the
// shell and the tool-call surfaces give a path on a Windows host: as written,
// letter case folded (NTFS and APFS are case-insensitive, #4194), and
// backslashes read as separators (#4243), folded too.
type factsReading struct {
	slashes bool
	fold    bool
}

var factsReadings = []factsReading{{}, {fold: true}, {slashes: true, fold: true}}

// candidates is p under the reading, and p under cwd when it is relative,
// as the shell normalizer resolves an argv path (#4653 for tool calls).
func (rd factsReading) candidates(p, cwd string) []string {
	if rd.slashes {
		if !strings.Contains(p, `\`) {
			return nil // the reading changes nothing
		}
		p = strings.ReplaceAll(p, `\`, "/")
	}
	out := []string{p}
	if filepath.IsAbs(cwd) && !filepath.IsAbs(p) && !strings.HasPrefix(p, "~") && !strings.HasPrefix(p, "/") {
		out = append(out, filepath.Join(cwd, p))
	}
	return out
}

// match returns the first pattern a candidate of p matches, and that
// candidate.
func (rd factsReading) match(patterns []string, home, cwd, p string) (pattern, spelled string, ok bool) {
	for _, c := range rd.candidates(p, cwd) {
		if pat, hit := MatchProtectedPath(patterns, home, c, cwd, rd.fold); hit {
			return pat, c, true
		}
	}
	return "", "", false
}

// factsHit reports whether p matches one of patterns under any reading.
func factsHit(patterns []string, home, cwd, p string) bool {
	for _, rd := range factsReadings {
		if _, _, ok := rd.match(patterns, home, cwd, p); ok {
			return true
		}
	}
	return false
}

// factsNamesPattern reports whether any path the lane found, a whole value
// or a mention, matches pattern: self-protection's test, which counts any
// naming of the config directory.
func factsNamesPattern(f facts.Facts, pattern, home, cwd string) bool {
	for _, list := range [][]string{f.Paths, f.Mentions} {
		for _, p := range list {
			if factsHit([]string{pattern}, home, cwd, p) {
				return true
			}
		}
	}
	return false
}

// factsMentionedPattern returns the first protected pattern a mention
// matches under any reading.
func factsMentionedPattern(f facts.Facts, patterns []string, home, cwd string) (string, bool) {
	for _, rd := range factsReadings {
		for _, p := range f.Mentions {
			if pattern, _, ok := rd.match(patterns, home, cwd, p); ok {
				return pattern, true
			}
		}
	}
	return "", false
}

// factsProtectedPath returns the first protected pattern a path matches,
// trying each reading over every path before the next reading, and every
// path that matches it (the receipt's evidence, #4372), spelled as the
// reading spells it.
func factsProtectedPath(f facts.Facts, patterns []string, home, cwd string) (string, []string, bool) {
	for _, rd := range factsReadings {
		for _, p := range f.Paths {
			pattern, _, ok := rd.match(patterns, home, cwd, p)
			if !ok {
				continue
			}
			var hits []string
			for _, q := range f.Paths {
				for _, rq := range factsReadings {
					if _, spelled, ok := rq.match([]string{pattern}, home, cwd, q); ok {
						hits = append(hits, spelled)
						break
					}
				}
			}
			return pattern, hits, true
		}
	}
	return "", nil, false
}

// factsReceiptHits is sshReceiptHits for a lane: hits when they are provably
// every operand the text names, and otherwise hits plus the ssh directory,
// which attests a key read. Only one plain command whose every argument
// matched the pattern is provable. Anything else could read a key that no
// literal names, so refining below a key read would under-attest it.
func factsReceiptHits(f facts.Facts, pattern string, hits []string, home, cwd string) []string {
	incomplete := append(append([]string{}, hits...), "~/.ssh")
	if !f.Simple || len(f.Commands) != 1 || len(hits) == 0 {
		return incomplete
	}
	for _, el := range f.Commands[0].Elements {
		if el.Value == "" {
			continue // a parameter without a value
		}
		named := false
		for _, p := range el.Paths {
			if factsHit([]string{pattern}, home, cwd, p) {
				named = true
				break
			}
		}
		if !named {
			return incomplete
		}
	}
	return hits
}

// factsConsumerOnly is protectedPathConsumerOnly for a lane: the consumer's
// name when every protected path the text names sits in a designated
// consumer's credential slot, and at least one does, else "".
//
// Narrower than the shell on purpose. It is the one step that lowers a BLOCK,
// so it needs a Simple text with one command: the slots are read off that
// command's elements in order, and nothing else in the text can reach the
// path. A protected path anywhere else (another command, a string, the raw
// scan) counts against it, and so does any reading of the command's name
// that is not a consumer: the stricter reading of a version-dependent alias.
// `ssh -i <key> host; Get-Date` is therefore a BLOCK here and AUDIT on bash.
func (e *Engine) factsConsumerOnly(f facts.Facts, patterns []string, home, cwd string) string {
	consumers := e.policy.Defaults.ProtectedPathConsumers
	if len(consumers) == 0 || !f.Simple || len(f.Commands) != 1 ||
		len(f.Strings) != 0 || len(f.Nested) != 0 || len(f.Notes) != 0 {
		return ""
	}
	c := f.Commands[0]
	var entries []*ProtectedPathConsumer
	for _, name := range c.Names() {
		entry := consumerFor(consumers, name)
		if entry == nil {
			return ""
		}
		entries = append(entries, entry)
	}
	credited := map[string]bool{}
	slots := 0
	for i, el := range c.Elements {
		var elHits []string
		for _, p := range el.Paths {
			if factsHit(patterns, home, cwd, p) {
				elHits = append(elHits, p)
			}
		}
		if len(elHits) == 0 {
			continue
		}
		for _, entry := range entries {
			if !factsConsumerSlot(entry, c.Elements, i) {
				return ""
			}
		}
		slots++
		for _, p := range elHits {
			credited[p] = true
		}
	}
	for _, p := range f.Paths {
		if !credited[p] && factsHit(patterns, home, cwd, p) {
			return ""
		}
	}
	if slots == 0 {
		return ""
	}
	return c.Name
}

// factsConsumerSlot is isConsumerSlot over a command's elements: element i
// is the value of one of the consumer's flags (the element before it, or
// inline `--flag=value`), or a bare operand of a consumer that allows one.
// A value attached to a parameter (`-i:<key>`) is never a slot: a native
// program receives it as one word, and ssh reads `-i:<key>` as the key file
// `:<key>`, so it is not the consumer use the table describes.
func factsConsumerSlot(c *ProtectedPathConsumer, els []facts.Element, i int) bool {
	el := els[i]
	if el.Param != "" {
		return false
	}
	if strings.HasPrefix(el.Value, "-") {
		if eq := strings.IndexByte(el.Value, '='); eq > 0 {
			return containsFlag(c.Flags, el.Value[:eq])
		}
		return false
	}
	if i > 0 && flagTakesThisWord(c.Flags, factsWord(els[i-1])) {
		return true
	}
	return c.Positional
}

// factsWord is an element as the started program receives it, for the flag
// test: a parameter's name as written (`-i`, case kept), or an argument's
// value. A parameter carrying an attached value is no flag of the next
// element.
//
// An argument that only looks like a flag (`'-i'`, quoted) counts: PowerShell
// passes it to the program as `-i`, so it is the flag. The shell keeps its
// quoted twin `"-i"` at BLOCK as a pinned residue (#4289).
func factsWord(el facts.Element) string {
	if el.Param != "" {
		if el.Value != "" {
			return ""
		}
		return el.Param
	}
	return el.Value
}

// factsKnownRead reports whether the text is one plain command whose every
// reading is on factsReadOnlyCommands.
func factsKnownRead(f facts.Facts) bool {
	if !f.Simple || len(f.Commands) != 1 || len(f.Strings) != 0 || len(f.Nested) != 0 || len(f.Notes) != 0 {
		return false
	}
	for _, name := range f.Commands[0].Names() {
		if _, ok := factsReadOnlyCommands[name]; !ok {
			return false
		}
	}
	return true
}

// factsKeepsBlock is the audit-only keep (#4337 review B1) for a lane's
// protected-path BLOCK: it is kept when the keep accepts the files it
// matched. There is no shell text to give the keep, so only its path test
// can accept.
func (e *Engine) factsKeepsBlock(r EvalResult, hits []string, home, cwd string) bool {
	if e.mode != "audit-only" || r.Decision != DecisionBlock || e.selfProtectionKeep == nil || len(hits) == 0 {
		return false
	}
	resolved := make([]string, 0, len(hits))
	for _, h := range hits {
		p := expandHome(h, home)
		if !filepath.IsAbs(p) && filepath.IsAbs(cwd) {
			p = filepath.Join(cwd, p)
		}
		resolved = append(resolved, p)
	}
	return e.selfProtectionKeep("", r.TriggeredRules, resolved)
}
