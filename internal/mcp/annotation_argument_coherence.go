package mcp

import (
	"fmt"
	"sync"
)

// ToolAnnotationCache caches tool annotations from the most recent tools/list
// response. tools/call messages carry only the tool name and arguments — the
// readOnlyHint (and other annotations) live in the tools/list response and must
// be cached session-side for call-time coherence checks.
type ToolAnnotationCache struct {
	mu    sync.RWMutex
	cache map[string]*ToolAnnotations
}

// NewToolAnnotationCache returns an initialized, empty cache.
func NewToolAnnotationCache() *ToolAnnotationCache {
	return &ToolAnnotationCache{cache: make(map[string]*ToolAnnotations)}
}

// Update atomically replaces the entire cache with the annotation set from the
// latest tools/list response. Tools without an annotations field are stored as nil.
func (c *ToolAnnotationCache) Update(tools []ToolDefinition) {
	next := make(map[string]*ToolAnnotations, len(tools))
	for _, t := range tools {
		next[t.Name] = t.Annotations
	}
	c.mu.Lock()
	c.cache = next
	c.mu.Unlock()
}

// Get returns the cached annotations for toolName, or nil if the tool is unknown
// or carried no annotations in the last tools/list response.
func (c *ToolAnnotationCache) Get(toolName string) *ToolAnnotations {
	c.mu.RLock()
	ann := c.cache[toolName]
	c.mu.RUnlock()
	return ann
}

// ScanAnnotationCoherenceAtCallTime extends the name-based argument coherence
// check (ScanArgumentCoherence) to neutral-named tools — those with no
// recognisable read-verb prefix such as "process", "sync", "handle", "resolve",
// "lookup_data", "query" — that carry a readOnlyHint:true annotation.
//
// readOnlyHint:true is the annotation MCP hosts use to skip the approval dialog
// entirely (per the 2025-03-26 spec). A neutral-named tool annotated read-only
// that receives an exec/shell/egress argument is the same behavioural
// contradiction as a read-verb tool receiving those arguments, but the
// name-based check in ScanArgumentCoherence misses it because
// classifyToolVerb returns "" for neutral names.
//
// The scanner fires only when BOTH of the following are true:
//  1. The declared annotation carries ReadOnly = true.
//  2. At least one argument name classifies as exec, shell, or egress.
//
// Tools already caught by the name-based check (classifyToolVerb → "read")
// are intentionally not re-checked to avoid duplicating findings.
func ScanAnnotationCoherenceAtCallTime(toolName string, arguments map[string]interface{}, annotations *ToolAnnotations) CoherenceScanResult {
	if annotations == nil || annotations.ReadOnly == nil || !*annotations.ReadOnly {
		return CoherenceScanResult{}
	}
	// Delegate to the existing name-based scanner if the verb is recognisable;
	// it already fires on this tool and we don't want a duplicate finding.
	if classifyToolVerb(toolName) == "read" {
		return CoherenceScanResult{}
	}

	var result CoherenceScanResult
	for argName := range arguments {
		category := classifyArgumentCategory(argName)
		if category == "" {
			continue
		}
		result.Findings = append(result.Findings, CoherenceFinding{
			Signal: SignalArgumentCoherenceViolation,
			Detail: fmt.Sprintf(
				"tool %q carries readOnlyHint:true annotation but was invoked with %s-shaped argument %q — "+
					"a read-only tool has no legitimate reason to accept an execution or egress argument; "+
					"the annotation hides the capability from MCP hosts that skip the approval dialog on readOnly:true",
				toolName, category, argName,
			),
			ToolName:    toolName,
			ToolVerb:    "readonly-annotated",
			ArgName:     argName,
			ArgCategory: category,
		})
	}
	result.Blocked = len(result.Findings) > 0
	return result
}
