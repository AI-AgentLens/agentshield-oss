package mcp

// genericResponsePoisoningTaxonomy is the node a response-side detection
// attests to when no sentinel rule is loaded for its engine (a community-only
// install has no mcp-sentinel.yaml) or when the sentinel carries no taxonomy.
const genericResponsePoisoningTaxonomy = "unauthorized-execution/agentic-attacks/mcp-tool-response-poisoning"

// sentinelTaxonomyRef is the one place an audit event for a Go-engine
// detection learns its taxonomy node (#3617). The sentinel rule in
// mcp-sentinel.yaml already names the node for every engine; before this,
// seven audit sites in handler.go repeated the generic node as a literal, so
// re-homing a detection in the YAML would have changed the rule's metadata
// while the receipt kept saying "response poisoning". The YAML is the single
// source of truth; the literal survives only as the fallback for installs
// without the pack.
func (h *MessageHandler) sentinelTaxonomyRef(engine string) string {
	if h != nil && h.Evaluator != nil {
		if sent := h.Evaluator.LookupSentinel(engine); sent != nil && sent.Taxonomy != "" {
			return sent.Taxonomy
		}
	}
	return genericResponsePoisoningTaxonomy
}
