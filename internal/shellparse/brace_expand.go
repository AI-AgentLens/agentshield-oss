package shellparse

import (
	"regexp"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// braceGroupRe matches a single, non-nested brace-expansion group: at least
// one comma, no nested "{"/"}"/"," inside an item. Deliberately excludes the
// "{1..5}" range form (a numeric/alpha sequence, not a credential-path
// evasion vector) and nested groups ("{a,{b,c}}") — both are future work if a
// real bypass surfaces; the comma-list form is what the demonstrated attack
// uses.
var braceGroupRe = regexp.MustCompile(`\{[^{},]+(,[^{},]+)+\}`)

// Bound the cartesian-product blowup from resolving multiple sibling brace
// groups in the same command. maxBraceGroups caps how many groups are
// considered at all; maxBraceAlternatives caps the total alternative strings
// produced — if the full product across the capped groups would exceed it,
// trailing groups are dropped (rightmost first) until it fits, so the
// leftmost group (empirically the credential-directory segment) is always
// still resolved even under a pathological later group.
const (
	maxBraceGroups       = 4
	maxBraceAlternatives = 64
)

// ExpandBraces returns every literal alternative produced by resolving the
// unquoted brace-expansion groups in command — the same alternatives a real
// shell generates, since brace expansion is the very first expansion a shell
// performs (bash manual, EXPANSION section), preceding tilde expansion,
// parameter expansion, and globbing.
//
// `cat ~/.{ssh,xignoreme}/id_rsa` looks unrelated to any SSH-key rule as
// written, but a real shell expands it to two arguments BEFORE tilde
// expansion resolves "~" on each — `~/.ssh/id_rsa` and `~/.xignoreme/id_rsa`
// — so the first one really does read the private key. A corpus-wide parity
// sweep found this degraded 31/70 (44%) of SSH-key-path BLOCKing commands to
// AUDIT/ALLOW purely from a brace group hiding the sensitive path segment
// (issue #3085) — mvdan.cc/sh has no Brace-expansion AST node at all (it is
// not POSIX and this parser does not implement it), so every downstream
// analyzer saw the literal, unexpanded text and never matched the real path.
//
// #3085's original fix resolved only the FIRST group found, on the stated
// assumption that "no surveyed real-world bypass chains more than one." A
// follow-up sweep disproved that: hiding the FILENAME in a second group on
// top of the already-resolved directory group (`~/.{ssh,x}/{id_rsa,x2}`)
// still fully defeated detection — 35/120 (29.2%) of the corpus's BLOCKing
// commands leaked (issue #3087). A credential path naturally has both a
// directory and a filename component, and both are equally valid brace
// targets, so resolving only one was never going to be enough. This
// resolves every sibling (non-nested) group, bounded by maxBraceGroups /
// maxBraceAlternatives above so an adversarial many-group command degrades
// gracefully instead of blowing up regex-layer cost.
//
// Only an UNQUOTED group is expanded — mirroring NormalizeIFS's approach,
// only a TOP-LEVEL Lit WordPart is scanned (never one nested inside SglQuoted
// / DblQuoted / a dynamic expansion), so a real shell's "brace expansion does
// not occur inside quotes" rule is preserved and a quoted literal like
// `echo "the {credentials,secrets} directory"` is left alone — expanding it
// would fabricate a match candidate that doesn't correspond to what the
// shell actually runs, which is exactly the wrong direction (a new FP, not
// a closed bypass).
//
// Returns nil when there is no unquoted brace group, or when parsing fails.
func ExpandBraces(command string) []string {
	if !strings.Contains(command, "{") || !strings.Contains(command, ",") {
		return nil
	}

	reader := strings.NewReader(command)
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(reader, "")
	if err != nil {
		return nil
	}

	type span struct{ start, end int }
	var spans []span
	syntax.Walk(file, func(node syntax.Node) bool {
		w, ok := node.(*syntax.Word)
		if !ok {
			return true
		}
		for _, part := range w.Parts {
			lit, ok := part.(*syntax.Lit)
			if !ok {
				continue // SglQuoted/DblQuoted/dynamic — not a candidate, skip (quoted braces stay literal)
			}
			start := int(lit.Pos().Offset())
			end := int(lit.End().Offset())
			if start < 0 || end > len(command) || start >= end {
				continue
			}
			for _, loc := range braceGroupRe.FindAllStringIndex(command[start:end], -1) {
				spans = append(spans, span{start + loc[0], start + loc[1]})
			}
		}
		return true
	})

	if len(spans) == 0 {
		return nil
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	if len(spans) > maxBraceGroups {
		spans = spans[:maxBraceGroups]
	}

	type group struct {
		span  span
		items []string
	}
	var groups []group
	for _, s := range spans {
		text := command[s.start:s.end]
		items := strings.Split(text[1:len(text)-1], ",")
		if len(items) < 2 {
			continue
		}
		groups = append(groups, group{s, items})
	}
	if len(groups) == 0 {
		return nil
	}
	for {
		total := 1
		for _, g := range groups {
			total *= len(g.items)
		}
		if total <= maxBraceAlternatives || len(groups) <= 1 {
			break
		}
		groups = groups[:len(groups)-1]
	}

	// Cartesian product across the (bounded) groups: every combination
	// substitutes ALL group spans simultaneously, left to right.
	combos := [][]int{{}}
	for gi := range groups {
		next := make([][]int, 0, len(combos)*len(groups[gi].items))
		for _, c := range combos {
			for ii := range groups[gi].items {
				cc := make([]int, len(c)+1)
				copy(cc, c)
				cc[len(c)] = ii
				next = append(next, cc)
			}
		}
		combos = next
	}

	alternatives := make([]string, 0, len(combos))
	for _, combo := range combos {
		var sb strings.Builder
		last := 0
		for gi, ii := range combo {
			g := groups[gi]
			sb.WriteString(command[last:g.span.start])
			sb.WriteString(g.items[ii])
			last = g.span.end
		}
		sb.WriteString(command[last:])
		alternatives = append(alternatives, sb.String())
	}
	return alternatives
}
