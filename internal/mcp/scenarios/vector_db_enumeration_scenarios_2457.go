package scenarios

// VectorDBEnumerationScenarios covers TP + TN cases for
// MCP vector search bulk enumeration detection.
// Taxonomy: data-exfiltration/inference-side-channel/vector-db-enumeration
// Issue: #2457
var VectorDBEnumerationScenarios2457 = []Scenario{
	// === True Positives: large result-limit parameters (≥ 1000) ===

	{
		ID:       "MCP-TP-VECTOR-2457-001",
		ToolName: "chroma_query",
		Arguments: map[string]interface{}{
			"query_texts": []interface{}{"tell me everything"},
			"n_results":   float64(5000),
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "vector-db-bulk-enumeration",
		Description:      "ChromaDB query with n_results=5000 — bulk corpus enumeration pattern",
	},
	{
		ID:       "MCP-TP-VECTOR-2457-002",
		ToolName: "pinecone_query",
		Arguments: map[string]interface{}{
			"index":  "main-kb",
			"vector": []interface{}{0.1, 0.2, 0.3},
			"top_k":  float64(10000),
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "vector-db-bulk-enumeration",
		Description:      "Pinecone query with top_k=10000 — oversized nearest-neighbour retrieval",
	},
	{
		ID:       "MCP-TP-VECTOR-2457-003",
		ToolName: "similarity_search",
		Arguments: map[string]interface{}{
			"query": "budget allocation",
			"top_k": float64(5000),
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "vector-db-bulk-enumeration",
		Description:      "Generic similarity_search with top_k=5000 — top_k is vector-API-specific",
	},
	{
		ID:       "MCP-TP-VECTOR-2457-004",
		ToolName: "faiss_search",
		Arguments: map[string]interface{}{
			"query": "api key",
			"k":     float64(50000),
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "vector-db-bulk-enumeration",
		Description:      "FAISS search with k=50000 — large nearest-neighbour request on vector tool",
	},
	{
		ID:       "MCP-TP-VECTOR-2457-005",
		ToolName: "qdrant_search",
		Arguments: map[string]interface{}{
			"collection_name": "docs",
			"limit":           float64(5000),
			"query_vector":    []interface{}{0.1, 0.2},
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "vector-db-bulk-enumeration",
		Description:      "Qdrant search with limit=5000 on a named vector search tool",
	},

	// === True Negatives: normal result counts (typical RAG, k = 3-20) ===
	// These tools are audited by existing knowledge-base rules (by tool name).
	// The new bulk-enumeration rules must not escalate the decision to BLOCK.
	// Expected: AUDIT (existing rules fire on tool name; new rules don't add BLOCK).

	{
		ID:       "MCP-TN-VECTOR-2457-001",
		ToolName: "chroma_query",
		Arguments: map[string]interface{}{
			"query_texts": []interface{}{"refund policy"},
			"n_results":   float64(5),
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "vector-db-normal-retrieval",
		Description:      "ChromaDB query with n_results=5 — normal RAG retrieval; new rules must not BLOCK",
	},
	{
		ID:       "MCP-TN-VECTOR-2457-002",
		ToolName: "pinecone_query",
		Arguments: map[string]interface{}{
			"index":  "main-kb",
			"vector": []interface{}{0.1, 0.2},
			"top_k":  float64(10),
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "vector-db-normal-retrieval",
		Description:      "Pinecone query with top_k=10 — typical k for RAG; new rules must not BLOCK",
	},
	{
		ID:       "MCP-TN-VECTOR-2457-003",
		ToolName: "qdrant_search",
		Arguments: map[string]interface{}{
			"collection_name": "knowledge",
			"limit":           float64(5),
			"query_vector":    []interface{}{0.1, 0.2},
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "vector-db-normal-retrieval",
		Description:      "Qdrant search with limit=5 — small result set; new rules must not BLOCK",
	},
	{
		ID:       "MCP-TN-VECTOR-2457-004",
		ToolName: "faiss_search",
		Arguments: map[string]interface{}{
			"query": "api reference",
			"k":     float64(10),
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "vector-db-normal-retrieval",
		Description:      "FAISS k=10 — normal nearest-neighbour query; new rules must not BLOCK",
	},
	{
		ID:       "MCP-TN-VECTOR-2457-005",
		ToolName: "github_search_issues",
		Arguments: map[string]interface{}{
			"query": "bug",
			"limit": float64(5000),
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "vector-db-normal-retrieval",
		Description:      "Non-vector tool (GitHub issues) with large limit — vector rules must not fire; AUDIT is the safe system default",
	},
}
