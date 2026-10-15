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

// Sentinel engines for SignalHiddenInstructions. One signal, two receipts
// (#4269): a marker in the tool's description (or inputSchema / _meta) is
// description poisoning; a marker in an outputSchema property description or
// title is outputSchema poisoning, a separate rule on a separate node. Until
// #4269 both rules declared mcp-desc-hidden-instructions, the evaluator kept
// the last one it loaded (the outputSchema rule), and every description
// finding cited the outputSchema rule.
//
// The description rule is the one that moved. The outputSchema rule keeps the
// old engine name because that is what it resolved to on every pre-#4269
// binary: an old binary loading the new pack, or a new binary loading an old
// disk pack, cites what main cited and never worse
// (TestHiddenInstructionSentinels_VersionSkew).
const (
	hiddenInstructionsSentinel             = "mcp-desc-hidden-instructions-description"
	outputSchemaHiddenInstructionsSentinel = "mcp-desc-hidden-instructions"
)

// inputSchemaPropInjectionSentinelEngine is the engine of the rule a
// SignalInputSchemaPropDescInjection finding cites,
// mcp-tool-inputschema-injection. Until #4274 the handler looked the finding
// up by that rule's ID. A rule ID is not an engine, so the lookup returned nil
// and no inputSchema-injection receipt named its rule
// (TestSentinelLookups_EveryEngineResolvesToOneRule).
const inputSchemaPropInjectionSentinelEngine = "mcp-desc-inputschema-prop-injection"

// responseAddresseeMarkerSentinelEngine is the engine of
// mcp-response-addressee-marker-sentinel, the rule a
// SignalResponseAddresseeMarker AUDIT cites (AI_risk_compliance#4554). It is a
// named constant, not a literal at the call site, so the #4281 ratchet
// resolves it and the receipt test can name it.
const responseAddresseeMarkerSentinelEngine = "mcp-response-addressee-marker"

// responseAddresseeMarkerGenericRuleID is the pack-less id the AUDIT carries
// whether or not the sentinel is loaded, the same shape as
// mcp-response-indirect-directive-audit. With the premium pack the receipt
// also cites the sentinel; without it, the generic id is the only attribution.
const responseAddresseeMarkerGenericRuleID = "mcp-response-addressee-marker-audit"

// responseTemplateCarrierSentinelEngine is the engine of
// mcp-response-template-carrier-sentinel, the rule a SignalResponseTemplateCarrier
// AUDIT cites (#4279). Named constant so the #4281 ratchet resolves it.
const responseTemplateCarrierSentinelEngine = "mcp-response-template-carrier"

// responseTemplateCarrierGenericRuleID is the pack-less id the AUDIT carries
// whether or not the sentinel is loaded.
const responseTemplateCarrierGenericRuleID = "mcp-response-template-carrier-audit"

// responseTemplateCarrierTaxonomy is the channel node the receipt falls back to
// without the premium pack. The generic response-poisoning node would
// attribute an EchoLeak-shaped carrier to the wrong mechanism.
const responseTemplateCarrierTaxonomy = "data-exfiltration/llm-data-flow/markdown-rendering-exfiltration"

// hiddenInstructionsSentinelEngine picks the sentinel engine for a
// hidden-instruction finding by the surface its match started in.
func hiddenInstructionsSentinelEngine(f PoisonFinding) string {
	if f.Surface == SurfaceOutputSchema {
		return outputSchemaHiddenInstructionsSentinel
	}
	return hiddenInstructionsSentinel
}
