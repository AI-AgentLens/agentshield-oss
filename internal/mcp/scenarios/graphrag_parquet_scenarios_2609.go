// Hand-curated MCP scenarios for issue #2609: GraphRAG Parquet artifact write detection.
//
// Rules tested:
//
//	mcp-sc-block-graphrag-parquet-write (BLOCK: write to GraphRAG Parquet index files)
//
// Attack vector:
//
//	An AI agent (or attacker using an MCP write tool) overwrites one of GraphRAG's
//	pre-computed knowledge-graph Parquet artifacts:
//	  - community_reports.parquet — LLM-generated community summaries
//	  - entities.parquet          — entity nodes in the knowledge graph
//	  - relationships.parquet     — relationship edges between entities
//	  - communities.parquet       — community cluster assignments
//	  - covariate_records.parquet — structured claims with evidence citations
//
//	GraphRAG's global search pre-computes community summaries at index time and
//	caches them as Parquet files. A single community_reports.parquet substitution
//	poisons all global queries in the affected semantic cluster without touching
//	model weights or source documents. The poisoning is undetectable at query time.

package scenarios

// GraphRAGParquetScenarios2609 covers GraphRAG Parquet artifact write detection (issue #2609).
var GraphRAGParquetScenarios2609 = []Scenario{

	// ── TP: write_file to community_reports.parquet ──

	{
		ID:               "MCP-TP-2609-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/graphrag/output/community_reports.parquet", "content": "poisoned_community_summary"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-graphrag-parquet-write",
		Description:      "write_file to community_reports.parquet — direct overwrite of GraphRAG community summary artifact; must BLOCK",
	},

	// ── TP: create_file to entities.parquet ──

	{
		ID:               "MCP-TP-2609-002",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/data/graphrag-index/entities.parquet", "content": "injected_entity_data"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-graphrag-parquet-write",
		Description:      "create_file to entities.parquet — overwrites entity node index; must BLOCK",
	},

	// ── TP: str_replace_editor to relationships.parquet ──

	{
		ID:               "MCP-TP-2609-003",
		ToolName:         "str_replace_editor",
		Arguments:        map[string]interface{}{"path": "/app/rag/output/relationships.parquet", "content": "forged_relationships"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-graphrag-parquet-write",
		Description:      "str_replace_editor to relationships.parquet — forges relationship edges in knowledge graph; must BLOCK",
	},

	// ── TP: write_file to communities.parquet ──

	{
		ID:               "MCP-TP-2609-004",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/home/user/graphrag-project/output/communities.parquet", "content": "injected_community_data"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-graphrag-parquet-write",
		Description:      "write_file to communities.parquet — overwrites community cluster assignments; must BLOCK",
	},

	// ── TP: append_file to covariate_records.parquet ──

	{
		ID:               "MCP-TP-2609-005",
		ToolName:         "append_file",
		Arguments:        map[string]interface{}{"path": "/shared/graphrag/covariate_records.parquet", "content": "forged_claim_records"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-graphrag-parquet-write",
		Description:      "append_file to covariate_records.parquet — injects forged structured claims; must BLOCK",
	},

	// ── TN: write to a CSV (not Parquet) ──

	{
		ID:               "MCP-TN-2609-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/graphrag/output/community_reports.csv", "content": "csv analysis"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-block-graphrag-parquet-write",
		Description:      "write_file to community_reports.csv — CSV extension, not a Parquet artifact; rule does not fire",
	},

	// ── TN: read_file of a Parquet artifact (read, not write) ──

	{
		ID:               "MCP-TN-2609-002",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/graphrag/output/community_reports.parquet"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-block-graphrag-parquet-write",
		Description:      "read_file of community_reports.parquet — read-only access; write rule does not fire",
	},

	// ── TN: write to docs about GraphRAG parquet format ──

	{
		ID:               "MCP-TN-2609-003",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/graphrag-index-format.md", "content": "# GraphRAG Index Format\n\nThe community_reports.parquet file contains..."},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-block-graphrag-parquet-write",
		Description:      "write_file to a markdown docs file that mentions community_reports.parquet — path is .md, not a Parquet artifact; rule does not fire",
	},
}
