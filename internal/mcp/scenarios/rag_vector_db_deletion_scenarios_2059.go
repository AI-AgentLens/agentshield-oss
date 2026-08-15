// Hand-curated MCP test scenarios for issue #2059:
// RAG vector database destructive operations (deletion/drop/clear).
//
// Rules covered:
//   mcp-kb-block-vector-db-delete-collection  (BLOCK any named-tool vector DB deletion)

package scenarios

var RAGVectorDBDeletionScenarios2059 = []Scenario{
	// TP: Chroma collection deletion → BLOCK
	{
		ID:               "MCP-TP-2059-001",
		ToolName:         "chroma_delete_collection",
		Arguments:        map[string]interface{}{"collection_name": "production-docs"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "rag-vector-db-deletion",
		Description:      "chroma_delete_collection — wipes the entire Chroma collection; irreversible RAG knowledge-base destruction",
	},
	// TP: Pinecone index deletion → BLOCK
	{
		ID:               "MCP-TP-2059-002",
		ToolName:         "pinecone_delete_index",
		Arguments:        map[string]interface{}{"index_name": "main-kb"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "rag-vector-db-deletion",
		Description:      "pinecone_delete_index — deletes entire Pinecone index including all namespaces and vectors",
	},
	// TP: Qdrant collection deletion → BLOCK
	{
		ID:               "MCP-TP-2059-003",
		ToolName:         "qdrant_delete_collection",
		Arguments:        map[string]interface{}{"collection_name": "agents-memory"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "rag-vector-db-deletion",
		Description:      "qdrant_delete_collection — destroys an entire Qdrant collection and its vector data",
	},
	// TP: Weaviate class deletion → BLOCK
	{
		ID:               "MCP-TP-2059-004",
		ToolName:         "weaviate_delete_class",
		Arguments:        map[string]interface{}{"className": "ProductDocumentation"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "rag-vector-db-deletion",
		Description:      "weaviate_delete_class — removes entire Weaviate class schema and all associated objects",
	},
	// TP: Milvus collection drop → BLOCK
	{
		ID:               "MCP-TP-2059-005",
		ToolName:         "milvus_drop_collection",
		Arguments:        map[string]interface{}{"collection_name": "embeddings"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "rag-vector-db-deletion",
		Description:      "milvus_drop_collection — drops entire Milvus collection and all vector data",
	},
	// TP: Qdrant clear collection (wipes all vectors, keeps schema) → BLOCK
	{
		ID:               "MCP-TP-2059-006",
		ToolName:         "qdrant_clear_collection",
		Arguments:        map[string]interface{}{"collection_name": "user-sessions"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "rag-vector-db-deletion",
		Description:      "qdrant_clear_collection — deletes all vectors in a Qdrant collection; functionally equivalent to deletion for RAG use cases",
	},
	// TP: generic vectorstore_delete → BLOCK
	{
		ID:               "MCP-TP-2059-007",
		ToolName:         "vectorstore_delete",
		Arguments:        map[string]interface{}{"store_id": "prod-rag"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "rag-vector-db-deletion",
		Description:      "vectorstore_delete — generic vector store deletion across any provider",
	},
	// TP: delete_documents_from_collection with empty filter (wipes all) → BLOCK
	{
		ID:               "MCP-TP-2059-008",
		ToolName:         "delete_documents_from_collection",
		Arguments:        map[string]interface{}{"collection": "knowledge-base", "filter": map[string]interface{}{}},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "rag-vector-db-deletion",
		Description:      "delete_documents_from_collection — bulk removal from vector collection; empty filter wipes everything",
	},
	// TN: chroma_list_collections — read-only, must NOT be blocked
	{
		ID:               "MCP-TN-2059-001",
		ToolName:         "chroma_list_collections",
		Arguments:        map[string]interface{}{},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "rag-vector-db-deletion",
		Description:      "chroma_list_collections — read-only listing; must NOT trigger the vector DB deletion rule",
	},
	// TN: qdrant_search — benign semantic search, must NOT be blocked
	{
		ID:               "MCP-TN-2059-002",
		ToolName:         "qdrant_search",
		Arguments:        map[string]interface{}{"collection_name": "agents-memory", "query": "deployment guides"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "rag-vector-db-deletion",
		Description:      "qdrant_search — benign similarity search; must NOT trigger the vector DB deletion rule",
	},
	// TN: pinecone_query — benign vector query, must NOT be blocked
	{
		ID:               "MCP-TN-2059-003",
		ToolName:         "pinecone_query",
		Arguments:        map[string]interface{}{"index_name": "main-kb", "query": "how to deploy"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "rag-vector-db-deletion",
		Description:      "pinecone_query — benign index query; must NOT trigger the vector DB deletion rule",
	},
	// TN: weaviate_get_objects — read-only, must NOT be blocked
	{
		ID:               "MCP-TN-2059-004",
		ToolName:         "weaviate_get_objects",
		Arguments:        map[string]interface{}{"className": "ProductDocumentation", "limit": 10},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "rag-vector-db-deletion",
		Description:      "weaviate_get_objects — read-only object retrieval; must NOT trigger the vector DB deletion rule",
	},
}
