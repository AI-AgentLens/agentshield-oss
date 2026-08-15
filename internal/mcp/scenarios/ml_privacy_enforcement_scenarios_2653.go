// Hand-curated MCP scenarios for issue #2653: ML privacy enforcement expansion.
//
// Rules tested:
//
//	mcp-mlpriv-audit-dp-unbounded-sensitivity
//	    (AUDIT: max_grad_norm=float('inf') / l2_norm_clip=math.inf removes the
//	     L2 sensitivity bound required for differential privacy, making the DP
//	     noise negligible relative to unbounded gradient updates)
//
//	mcp-mlpriv-audit-fl-clipping-disabled
//	    (AUDIT: federated learning server config that explicitly disables gradient
//	     clipping — precondition for model-replacement attacks (Bagdasaryan 2018))
//
// Relationship to existing DP budget exhaustion rules (issue #2615):
//
//	The two existing rules cover noise_multiplier=0 (no noise) and epsilon=float('inf')
//	(no budget ceiling). This pack adds the third pillar: max_grad_norm=float('inf')
//	(no sensitivity bound). Together they cover all three components of the DP mechanism.
//	The FL clipping rule adds the aggregator-side defense dimension (federated context).
package scenarios

// MLPrivacyEnforcementScenarios2653 covers ML differential privacy bypass and
// federated learning gradient clipping removal via MCP file-write tools (issue #2653).
var MLPrivacyEnforcementScenarios2653 = []Scenario{

	// ── TP: max_grad_norm=float('inf') removes L2 sensitivity bound → AUDIT ──

	{
		ID:               "MCP-TP-2653-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/train_dp.py", "content": "from opacus import PrivacyEngine\nprivacy_engine = PrivacyEngine()\nmodel, optimizer, dl = privacy_engine.make_private(\n    module=model, optimizer=optimizer, data_loader=train_loader,\n    noise_multiplier=1.1, max_grad_norm=float('inf'))"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-mlpriv-audit-dp-unbounded-sensitivity",
		Description:      "write_file: Opacus make_private with max_grad_norm=float('inf') — removes L2 sensitivity bound, defeats DP guarantee even with non-zero noise_multiplier; must AUDIT",
	},
	{
		ID:               "MCP-TP-2653-002",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/ml/federated/dp_train.py", "content": "import math\nengine = NoisyQueryEngine(noise_multiplier=0.8, l2_norm_clip=math.inf)"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-mlpriv-audit-dp-unbounded-sensitivity",
		Description:      "create_file: Google DP NoisyQueryEngine with l2_norm_clip=math.inf — unbounded sensitivity defeats DP; must AUDIT",
	},
	{
		ID:               "MCP-TP-2653-003",
		ToolName:         "save_file",
		Arguments:        map[string]interface{}{"path": "/project/src/privacy_train.py", "content": "import math\nengine = DPFedAvg(noise_multiplier=0.5, clip_norm=math.inf, num_clients=10)"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-mlpriv-audit-dp-unbounded-sensitivity",
		Description:      "save_file: DPFedAvg with clip_norm=math.inf — covers the clip_norm alias for the sensitivity bound param; must AUDIT",
	},
	{
		ID:               "MCP-TP-2653-004",
		ToolName:         "edit_file",
		Arguments:        map[string]interface{}{"path": "/ml/dp_fedavg.py", "content": "import math\nclient = DPFedAvg(noise_multiplier=0.5, clipping_norm=math.inf, num_clients=10)"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-mlpriv-audit-dp-unbounded-sensitivity",
		Description:      "edit_file: PySyft DPFedAvg with clipping_norm=math.inf — sensitivity bound removed in federated DP training; must AUDIT",
	},

	// ── TN: legitimate max_grad_norm values → AUDIT (no sensitivity bypass) ──

	{
		ID:               "MCP-TN-2653-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/train_dp.py", "content": "model, optimizer, dl = privacy_engine.make_private(noise_multiplier=1.1, max_grad_norm=1.0)"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-mlpriv-audit-dp-unbounded-sensitivity",
		Description:      "write_file: Opacus make_private with legitimate max_grad_norm=1.0 — valid DP training config; must not trigger the rule",
	},
	{
		ID:               "MCP-TN-2653-002",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/dp_guide.md", "content": "Never set max_grad_norm=float('inf') — this removes the L2 sensitivity bound and defeats DP."},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-mlpriv-audit-dp-unbounded-sensitivity",
		Description:      "write_file: documentation warning about unbounded sensitivity — not a Python file triggering the rule; must not fire",
	},
	{
		ID:               "MCP-TN-2653-003",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/config.yaml", "content": "max_grad_norm: 1.0\nnoise_multiplier: 1.1\ntarget_epsilon: 2.0\n"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-mlpriv-audit-dp-unbounded-sensitivity",
		Description:      "write_file: YAML config with bounded max_grad_norm — not a Python file, not matching the path pattern; must not trigger",
	},

	// ── TP: FL server config disabling gradient clipping → AUDIT ──

	{
		ID:               "MCP-TP-2653-005",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/config/config_fed_server.json", "content": "{\"format_version\": 2, \"min_clients\": 2, \"num_rounds\": 100, \"clip_by_norm\": null, \"aggregation\": \"FedAvg\"}"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-mlpriv-audit-fl-clipping-disabled",
		Description:      "write_file: NVIDIA FLARE config_fed_server.json with clip_by_norm: null — disables aggregator-side clipping, enabling model-replacement attacks; must AUDIT",
	},
	{
		ID:               "MCP-TP-2653-006",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/workspace/flare_config.yaml", "content": "min_clients: 3\nnum_rounds: 50\naggregation: FedAvg\ngradient_clip: false\nnoise_multiplier: 0.0\n"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-mlpriv-audit-fl-clipping-disabled",
		Description:      "create_file: FLARE YAML config with gradient_clip: false — removes clipping protection from FL aggregator; must AUDIT",
	},
	{
		ID:               "MCP-TP-2653-007",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/fl_project/plan/plan.yaml", "content": "aggregation:\n  name: FedAvg\n  args:\n    gradient_clip: false\n    min_clients: 2\n"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-mlpriv-audit-fl-clipping-disabled",
		Description:      "write_file: OpenFL plan.yaml with gradient_clip: false under aggregation args — disables defensive clipping; must AUDIT",
	},
	{
		ID:               "MCP-TP-2653-008",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/fl_training/fedml_config.yaml", "content": "fedml:\n  aggregator: FedAvg\n  clip_grad_norm: 0\n  num_rounds: 200\n"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-mlpriv-audit-fl-clipping-disabled",
		Description:      "write_file: FedML config with clip_grad_norm: 0 — zero clipping norm removes gradient norm defense; must AUDIT",
	},

	// ── TN: FL configs with proper clipping → AUDIT (rule must not escalate) ──

	{
		ID:               "MCP-TN-2653-004",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/config/config_fed_server.json", "content": "{\"format_version\": 2, \"min_clients\": 2, \"num_rounds\": 100, \"clip_by_norm\": 1.0, \"aggregation\": \"Krum\"}"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-mlpriv-audit-fl-clipping-disabled",
		Description:      "write_file: FLARE config with clip_by_norm: 1.0 and Krum aggregator — valid secure FL setup; must not trigger the clipping-disabled rule",
	},
	{
		ID:               "MCP-TN-2653-005",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/flare_config.yaml", "content": "min_clients: 3\nnum_rounds: 50\naggregation: FedAvg\ngradient_clip: true\nclip_by_norm: 0.5\nnoise_multiplier: 0.8\n"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-mlpriv-audit-fl-clipping-disabled",
		Description:      "write_file: FLARE YAML config with gradient_clip: true and bounded clip_by_norm — secure configuration; must not trigger",
	},
	{
		ID:               "MCP-TN-2653-006",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/fl-security.md", "content": "Never set gradient_clip: false in production FL — this enables model-replacement attacks."},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-mlpriv-audit-fl-clipping-disabled",
		Description:      "write_file: documentation warning about gradient_clip: false — markdown file, not a config path; must not trigger",
	},
}
