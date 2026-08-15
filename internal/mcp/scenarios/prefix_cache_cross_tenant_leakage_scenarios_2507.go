// Hand-curated MCP test scenarios for issue #2507:
// vLLM prefix-cache cross-tenant leakage — AI agent writes config with
// enable_prefix_caching=True without per-tenant cache key scoping.
//
// Rules covered:
//   mcp-llminf-audit-vllm-prefix-cache-config-write  (AUDIT write_file with enable_prefix_caching=True)

package scenarios

var PrefixCacheCrossTenantLeakageScenarios2507 = []Scenario{
	// TP: write_file persisting Python engine args with enable_prefix_caching=True → AUDIT
	{
		ID:               "MCP-TP-2507-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/config/vllm_config.py", "content": "engine_args = AsyncEngineArgs(model=MODEL, enable_prefix_caching=True)"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "prefix-cache-cross-tenant-leakage",
		Description:      "write_file persisting vLLM AsyncEngineArgs with enable_prefix_caching=True — must AUDIT",
	},
	// TP: create_file persisting YAML config with enable_prefix_caching: true → AUDIT
	{
		ID:               "MCP-TP-2507-002",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/deploy/vllm.yaml", "content": "enable_prefix_caching: true\nmax_model_len: 4096"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "prefix-cache-cross-tenant-leakage",
		Description:      "create_file persisting vLLM YAML config with enable_prefix_caching: true — must AUDIT",
	},
	// TP: write_file_contents with Python config enable_prefix_caching=True → AUDIT
	{
		ID:               "MCP-TP-2507-003",
		ToolName:         "write_file_contents",
		Arguments:        map[string]interface{}{"path": "/workspace/serving/config.py", "content": "args = EngineArgs(enable_prefix_caching=True, tensor_parallel_size=4)"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "prefix-cache-cross-tenant-leakage",
		Description:      "write_file_contents persisting vLLM EngineArgs with enable_prefix_caching=True — must AUDIT",
	},
	// TN: write_file with enable_prefix_caching=False — must NOT fire
	{
		ID:               "MCP-TN-2507-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/config/vllm_config.py", "content": "engine_args = AsyncEngineArgs(model=MODEL, enable_prefix_caching=False)"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "prefix-cache-cross-tenant-leakage",
		Description:      "write_file with enable_prefix_caching=False — must NOT trigger the prefix-cache rule",
	},
	// TN: write_file with no prefix caching flag at all — must NOT fire
	{
		ID:               "MCP-TN-2507-002",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/config/vllm_config.py", "content": "engine_args = AsyncEngineArgs(model=MODEL, max_model_len=4096)"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "prefix-cache-cross-tenant-leakage",
		Description:      "write_file with no enable_prefix_caching setting — must NOT fire",
	},
}
