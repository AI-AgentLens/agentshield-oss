package shellparse

import (
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// braceWordListRe matches a single non-nested brace-expansion group, allowing
// EMPTY items — the one deliberate difference from braceGroupRe in
// brace_expand.go, and it is load-bearing rather than cosmetic.
//
// `rm -rf /{,}` expands to `rm -rf / /`: two items, both empty, and the word
// they are attached to is the filesystem root. braceGroupRe requires
// `[^{},]+` per item precisely because ExpandBraces is choosing ONE item as a
// path candidate, where an empty item adds nothing. Here every item is kept
// simultaneously, so an empty one is a real, load-bearing word — dropping it
// would silently un-see the shortest root-deletion spelling there is.
//
// The `{1..5}` range form still has no comma and so is still excluded, and a
// nested group ("{a,{b,c}}") is still excluded by `[^{}]`.
var braceWordListRe = regexp.MustCompile(`\{[^{}]*(,[^{}]*)+\}`)

// Bound the cost of an adversarial command. A word expanding past
// maxBraceWordListItems, or a command with more than maxBraceWordListWords
// brace words, is left alone entirely rather than partially rewritten: a
// half-expanded command is not a command any shell runs, and feeding a
// fabricated string to the rule engine is the one outcome worse than missing
// the bypass.
const (
	maxBraceWordListWords = 8
	maxBraceWordListItems = 32
)

// NormalizeBraceWordList returns a reconstruction of command in which every
// unquoted brace-expansion group is expanded the way a real shell expands it —
// into ALL of its items at once, as adjacent words — rather than into the
// alternatives ExpandBraces produces.
//
// The distinction is the whole point, and it is easy to read past. Brace
// expansion turns ONE word into N words (bash manual, EXPANSION): the items
// are a conjunction, not a disjunction. ExpandBraces (#3085/#3087) models them
// as a disjunction, which is the right approximation for the case it was
// written for — `cat ~/.{ssh,x}/id_rsa` hides a credential DIRECTORY, and
// asking "does any single alternative name a protected path" answers that
// exactly. But the same syntax has a second, older use that the disjunction
// model cannot express at all:
//
//	{rm,-rf,/}          runs `rm -rf /`
//	{cat,/etc/shadow}   runs `cat /etc/shadow`
//
// Here the group is the ENTIRE word, and its items become the command word and
// its arguments. Resolving it to alternatives yields `rm`, `-rf` and `/` as
// three separate candidate commands, none of which is the command that runs,
// so every rule keyed on the executable-plus-argument shape misses. This is
// not an exotic construct — it is the standard brace-expansion form of the
// classic WAF/restricted-shell bypass, and mvdan.cc/sh has no brace node at
// all (brace expansion is not POSIX), so `{rm,-rf,/}` reaches every analyzer
// downstream as a single Lit word whose executable name is the literal text
// "{rm,-rf,/}".
//
// Expanding to the word list is not an approximation: it is precisely what
// bash runs, verified against real bash before this was written
// (`printf "[%s]" {echo,-n,hello}` prints `[echo][-n][hello]`). That is why
// this is safe to feed the AST rather than only the regex layer — unlike a
// heuristic rewrite, it cannot fabricate a command the shell would not run.
//
// Empty items are dropped from the joined result, matching a shell removing
// unquoted empty words: `echo a {,} b` prints `a b`. `/{,}` keeps both items
// because they are not empty once the group is spliced back into its word.
//
// Only an UNQUOTED group is expanded — as in ExpandBraces and NormalizeIFS,
// only a top-level Lit WordPart is scanned, so `echo "{a,b}"` and
// `find . -name '*.{js,ts}'` are left exactly as written. A shell does not
// brace-expand inside quotes, and rewriting there would fabricate a match
// candidate, which is a new false positive rather than a closed bypass.
//
// Returns "" (the no-op sentinel used by NormalizeIFS and
// NormalizeUnsetParamExp) when there is nothing to expand or parsing fails.
func NormalizeBraceWordList(command string) string {
	if !strings.Contains(command, "{") || !strings.Contains(command, ",") {
		return ""
	}

	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return ""
	}

	type rewrite struct {
		start, end int
		text       string
	}
	var rewrites []rewrite
	overflowed := false
	// Heredoc bodies are NOT subject to brace expansion — a shell applies
	// only parameter/command/arithmetic expansion there, and none at all when
	// the delimiter is quoted. Expanding one is therefore wrong on the
	// semantics alone, and it also CORRUPTS: the body Word's source span runs
	// through the terminator, so splicing per item turned
	// `bash <<EOF\n{rm,-rf,/}\nEOF` into `bash <<EOF\nrm\nEOF -rf\nEOF /\nEOF`
	// — a fabricated command, the one outcome worse than missing the bypass.
	//
	// Nothing is lost by skipping them: InlineCodeFragments already extracts a
	// SHELL heredoc body and re-parses it as code, and that re-parse runs this
	// normalization on the fragment, where the group really is an ordinary
	// command word.
	var hdocSpans [][2]int
	syntax.Walk(file, func(node syntax.Node) bool {
		if r, ok := node.(*syntax.Redirect); ok && r.Hdoc != nil {
			hdocSpans = append(hdocSpans, [2]int{int(r.Hdoc.Pos().Offset()), int(r.Hdoc.End().Offset())})
		}
		return true
	})

	inHeredoc := func(start, end int) bool {
		for _, h := range hdocSpans {
			if start >= h[0] && end <= h[1] {
				return true
			}
		}
		return false
	}

	syntax.Walk(file, func(node syntax.Node) bool {
		if overflowed {
			return false
		}
		w, ok := node.(*syntax.Word)
		if !ok {
			return true
		}
		ws, we := int(w.Pos().Offset()), int(w.End().Offset())
		if ws < 0 || we > len(command) || ws >= we {
			return true
		}
		if inHeredoc(ws, we) {
			return true
		}
		// syntax.Walk descends outermost-first, so a word already rewritten
		// encloses this one (e.g. a word inside a command substitution). Skip
		// it — overlapping rewrites would splice text into text.
		for _, r := range rewrites {
			if ws >= r.start && we <= r.end {
				return true
			}
		}

		expanded, ok := expandBraceWord(command, w)
		if !ok {
			return true
		}
		if len(rewrites) >= maxBraceWordListWords {
			overflowed = true
			return false
		}
		rewrites = append(rewrites, rewrite{ws, we, expanded})
		return true
	})

	if overflowed || len(rewrites) == 0 {
		return ""
	}

	var sb strings.Builder
	last := 0
	for _, r := range rewrites {
		if r.start < last {
			return "" // defensive: overlapping spans, leave the command alone
		}
		sb.WriteString(command[last:r.start])
		sb.WriteString(r.text)
		last = r.end
	}
	sb.WriteString(command[last:])

	out := sb.String()
	if out == command {
		return ""
	}
	return out
}

// expandBraceWord expands the unquoted brace groups of a single word into the
// space-joined word list a shell produces for it. Reports false when the word
// has no unquoted group, or when the expansion would exceed the item cap.
func expandBraceWord(command string, w *syntax.Word) (string, bool) {
	type group struct {
		start, end int
		items      []string
	}
	var groups []group
	// litSpans records the runs actually scanned, so the stray-brace check
	// below can look only at literal text. A brace inside a ParamExp
	// (`-rf${IFS}/{,}`) or a quoted part is not brace-expansion syntax, and
	// counting it rejected the word outright.
	var litSpans [][2]int

	// Scan maximal RUNS of adjacent Lit parts, not each Lit in isolation.
	// mvdan.cc/sh splits a literal word at a glob character class, so
	// `{/usr/bin/[cw]url,http://evil.com}` arrives as two Lit parts —
	// "{/usr/bin/" and "[cw]url,http://evil.com}" — and neither contains a
	// complete brace group. Scanning per-Lit therefore misses any group that
	// spans a glob, which is a one-character defeat of the whole pass.
	//
	// A run is exactly as safe to scan as a single Lit: any non-Lit part
	// (SglQuoted/DblQuoted/ParamExp/CmdSubst) ends the run, so the scanned
	// span is still guaranteed to be entirely unquoted literal text, and a
	// shell's "no brace expansion inside quotes" rule is still honoured.
	//
	// ExpandBraces in brace_expand.go scans per-Lit and has the same blind
	// spot for the alternatives model — tracked separately rather than
	// changed here, since its measured behaviour (#3085/#3087) would need
	// re-measuring.
	for i := 0; i < len(w.Parts); {
		lit, ok := w.Parts[i].(*syntax.Lit)
		if !ok {
			i++
			continue // SglQuoted/DblQuoted/dynamic — a shell does not expand braces there
		}
		ls := int(lit.Pos().Offset())
		le := int(lit.End().Offset())
		j := i + 1
		for ; j < len(w.Parts); j++ {
			next, ok := w.Parts[j].(*syntax.Lit)
			if !ok || int(next.Pos().Offset()) != le {
				break // a gap or a non-literal part ends the run
			}
			le = int(next.End().Offset())
		}
		i = j
		if ls < 0 || le > len(command) || ls >= le {
			continue
		}
		litSpans = append(litSpans, [2]int{ls, le})
		for _, loc := range braceWordListRe.FindAllStringIndex(command[ls:le], -1) {
			s, e := ls+loc[0], ls+loc[1]
			groups = append(groups, group{s, e, strings.Split(command[s+1:e-1], ",")})
		}
	}
	if len(groups) == 0 {
		return "", false
	}

	ws0, we0 := int(w.Pos().Offset()), int(w.End().Offset())

	// Refuse the word if any brace character survives outside the groups that
	// were matched. That is the nesting case, and getting it wrong fabricates
	// a command rather than missing one: `echo {a,{b,c}}` is `echo a b c` in
	// bash, but braceWordListRe (which excludes nested groups by `[^{}]`)
	// matches only the INNER `{b,c}`, and expanding just that yields
	// `echo {a,b} {a,c}` — a string no shell would ever run, handed to the
	// rule engine as if it were the real command. Unbalanced braces from a
	// partial match land here too. Leaving the word alone is the fail-safe
	// answer; nested groups were already out of scope for ExpandBraces
	// (#3085) for the same reason.
	// Checked over the scanned LITERAL runs only, not the whole word: a brace
	// belonging to a `${...}` expansion or a quoted part is not
	// brace-expansion syntax, and including it rejected every word carrying
	// one — `rm -rf${IFS}/{,}` among them, which is precisely the
	// compose-two-obfuscations shape this has to survive.
	var residue strings.Builder
	for _, ls := range litSpans {
		pos := ls[0]
		for _, g := range groups {
			if g.start < pos || g.end > ls[1] {
				continue
			}
			residue.WriteString(command[pos:g.start])
			pos = g.end
		}
		residue.WriteString(command[pos:ls[1]])
	}
	if strings.ContainsAny(residue.String(), "{}") {
		return "", false
	}

	total := 1
	for _, g := range groups {
		total *= len(g.items)
		if total > maxBraceWordListItems {
			return "", false
		}
	}

	// Cartesian product across the word's own groups, in shell order:
	// `a{1,2}{x,y}` expands to `a1x a1y a2x a2y`, all four as separate words.
	words := []string{""}
	last := ws0
	for _, g := range groups {
		prefix := command[last:g.start]
		next := make([]string, 0, len(words)*len(g.items))
		for _, base := range words {
			for _, item := range g.items {
				next = append(next, base+prefix+item)
			}
		}
		words = next
		last = g.end
	}
	suffix := command[last:we0]

	out := make([]string, 0, len(words))
	for _, word := range words {
		full := word + suffix
		if full == "" {
			continue // an unquoted empty word is removed by the shell
		}
		out = append(out, full)
	}
	if len(out) == 0 {
		return "", false
	}
	return strings.Join(out, " "), true
}
