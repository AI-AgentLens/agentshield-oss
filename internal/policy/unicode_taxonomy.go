package policy

// unicodeTaxonomy names the taxonomy node a built-in Unicode smuggling finding
// attests to, keyed by the rule id the engine records for it (#4560). The
// built-in scan (internal/unicode) is not a pack rule, so it has no
// `taxonomy:` field, and before this table every one of its BLOCKs reached the
// SaaS as a receipt that attested no control. In October 2026 unicode-zero-width
// was 15 of the 25 production BLOCKs in that state (aiagentlens#309).
//
// One entry, deliberately. The node is the one Gary approved for zero-width
// characters on 2026-10-26; the guardian's unicode_steganography signal and the
// MCP response scanner's tag-block signal already cite it. The other built-in
// categories (bidi-override, homoglyph-*, tag-char, control-char, ...) wait on
// their own taxonomy decision, and an absent ref is better than a guessed one.
//
// Each node is written as a TaxonomyRef field set to a string literal, on
// purpose: scripts/check-taxonomy-refs.sh (CI's taxonomy-refs job) resolves
// exactly that spelling against Comply's taxonomy tree, so a renamed or
// retired node turns CI red instead of shipping a dangling ref. A map of bare
// strings would be invisible to it.
//
// Evidence only: this table never changes a decision, a rule id or a reason.
var unicodeTaxonomy = []struct {
	RuleID      string
	TaxonomyRef string
}{
	{RuleID: "unicode-zero-width", TaxonomyRef: "unauthorized-execution/agentic-attacks/invisible-unicode-prompt-injection"},
}

// unicodeTaxonomyRef is the node for one built-in Unicode rule id, if it has one.
func unicodeTaxonomyRef(ruleID string) (string, bool) {
	for _, m := range unicodeTaxonomy {
		if m.RuleID == ruleID {
			return m.TaxonomyRef, true
		}
	}
	return "", false
}

// addUnicodeTaxonomy appends, once each, the node of every rule in rules that
// has one. It copies before appending, so the caller's slice (which may share
// a backing array with an analyzer's combined result) is never written through.
func addUnicodeTaxonomy(refs []string, rules []string) []string {
	for _, id := range rules {
		ref, ok := unicodeTaxonomyRef(id)
		if !ok || containsTaxonomyRef(refs, ref) {
			continue
		}
		refs = append(append(make([]string, 0, len(refs)+1), refs...), ref)
	}
	return refs
}

func containsTaxonomyRef(refs []string, ref string) bool {
	for _, r := range refs {
		if r == ref {
			return true
		}
	}
	return false
}
