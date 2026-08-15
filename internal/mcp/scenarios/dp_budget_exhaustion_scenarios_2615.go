// Hand-curated MCP test scenarios for issue #2615:
// Differential privacy budget exhaustion — detect ML code writes that disable
// or misconfigure DP enforcement (zero noise_multiplier, unlimited epsilon cap).
//
// Rules covered:
//   mcp-mlpriv-audit-dp-zero-noise        (AUDIT — noise_multiplier=0 in .py writes)
//   mcp-mlpriv-audit-dp-unlimited-epsilon (AUDIT — epsilon=float('inf') / math.inf in .py writes)

package scenarios

// DPBudgetExhaustionScenarios2615 covers MCP premium rules detecting differential
// privacy misconfiguration written via file tools into Python source files.
var DPBudgetExhaustionScenarios2615 = []Scenario{
	// ===== mcp-mlpriv-audit-dp-zero-noise =====

	// TP-001: Opacus make_private with noise_multiplier=0 (complete DP disable)
	{
		ID:               "MCP-TP-2615-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/ml/train_dp.py", "content": "from opacus import PrivacyEngine\nprivacy_engine = PrivacyEngine()\nmodel, optimizer, data_loader = privacy_engine.make_private(\n    module=model, optimizer=optimizer, data_loader=train_loader,\n    noise_multiplier=0, max_grad_norm=1.0)"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-mlpriv-audit-dp-zero-noise",
		Description:      "Opacus make_private with noise_multiplier=0 — completely disables DP Gaussian noise, must AUDIT",
	},
	// TP-002: Federated learning DP engine with zero noise (DPFedAvg)
	{
		ID:               "MCP-TP-2615-002",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/project/federated/dp_aggregator.py", "content": "from pysyft.frameworks.torch.dp import DPFedAvg\naggregator = DPFedAvg(noise_multiplier=0.0, clipping_norm=1.0, num_clients=10)"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-mlpriv-audit-dp-zero-noise",
		Description:      "DPFedAvg initialized with noise_multiplier=0.0 — zero noise in federated DP aggregation, must AUDIT",
	},
	// TP-003: str_replace changing noise_multiplier from valid to zero
	{
		ID:               "MCP-TP-2615-003",
		ToolName:         "str_replace_editor",
		Arguments:        map[string]interface{}{"path": "/src/privacy_train.py", "old_str": "noise_multiplier=1.1", "new_str": "noise_multiplier=0"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-mlpriv-audit-dp-zero-noise",
		Description:      "str_replace_editor zeroing noise_multiplier — attacker replacing valid DP noise with 0, must AUDIT",
	},
	// TP-004: append_file adding zero-noise DP config to existing file
	{
		ID:               "MCP-TP-2615-004",
		ToolName:         "append_file",
		Arguments:        map[string]interface{}{"path": "/workspace/config/dp_settings.py", "content": "NOISE_MULTIPLIER = 0\nmodel = make_private(noise_multiplier=NOISE_MULTIPLIER)"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-mlpriv-audit-dp-zero-noise",
		Description:      "append_file adding noise_multiplier=0 constant — disabling DP noise via config append, must AUDIT",
	},

	// TN-001: Valid noise_multiplier (1.1 is a typical production value)
	{
		ID:               "MCP-TN-2615-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/train.py", "content": "from opacus import PrivacyEngine\nmodel, optimizer, dl = privacy_engine.make_private(\n    noise_multiplier=1.1, max_grad_norm=1.0)"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-mlpriv-audit-dp-zero-noise",
		Description:      "noise_multiplier=1.1 — valid DP configuration, must NOT trigger zero-noise rule",
	},
	// TN-002: Documentation file mentioning noise_multiplier=0 as anti-pattern
	{
		ID:               "MCP-TN-2615-002",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/dp_guide.md", "content": "## Common Mistakes\n\nNever set noise_multiplier=0 in production — this disables DP entirely."},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-mlpriv-audit-dp-zero-noise",
		Description:      "Markdown doc file mentioning noise_multiplier=0 as an anti-pattern — path is .md not .py, must NOT trigger",
	},
	// TN-003: YAML config file (not Python — path filter must exclude it)
	{
		ID:               "MCP-TN-2615-003",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/config/dp.yaml", "content": "noise_multiplier: 0\nmax_grad_norm: 1.0"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-mlpriv-audit-dp-zero-noise",
		Description:      "YAML config with noise_multiplier: 0 — not a Python file, must NOT trigger (path filter)",
	},

	// ===== mcp-mlpriv-audit-dp-unlimited-epsilon =====

	// TP-005: Opacus make_private_with_epsilon with target_epsilon=float('inf')
	{
		ID:               "MCP-TP-2615-005",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/ml/train_unlim.py", "content": "from opacus import PrivacyEngine\nmodel, optimizer, dl = privacy_engine.make_private_with_epsilon(\n    module=model, optimizer=optimizer, data_loader=train_loader,\n    target_epsilon=float('inf'), target_delta=1e-5, max_grad_norm=1.0)"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-mlpriv-audit-dp-unlimited-epsilon",
		Description:      "target_epsilon=float('inf') in make_private_with_epsilon — removes DP budget ceiling, must AUDIT",
	},
	// TP-006: Google DP BudgetAccountant with epsilon=math.inf
	{
		ID:               "MCP-TP-2615-006",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/ml/privacy/accountant.py", "content": "import math\nfrom google.differentialprivacy import BudgetAccountant\naccountant = BudgetAccountant(epsilon=math.inf, delta=1e-5)"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-mlpriv-audit-dp-unlimited-epsilon",
		Description:      "BudgetAccountant(epsilon=math.inf) — removes DP budget limit in Google DP library, must AUDIT",
	},
	// TP-007: Double-quoted float('inf') variant
	{
		ID:               "MCP-TP-2615-007",
		ToolName:         "edit_file",
		Arguments:        map[string]interface{}{"path": "/project/src/dp_config.py", "content": "TARGET_EPSILON = float(\"inf\")  # no budget limit\naccountant = PrivacyAccountant(target_epsilon=float(\"inf\"))"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-mlpriv-audit-dp-unlimited-epsilon",
		Description:      "target_epsilon=float(\"inf\") with double quotes — alternate quoting style, must still AUDIT",
	},

	// TN-004: Bounded epsilon value (epsilon=1.0 is a valid, common DP setting)
	{
		ID:               "MCP-TN-2615-004",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/train_dp.py", "content": "model, optimizer, dl = privacy_engine.make_private_with_epsilon(\n    target_epsilon=1.0, target_delta=1e-5, max_grad_norm=1.0)"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-mlpriv-audit-dp-unlimited-epsilon",
		Description:      "target_epsilon=1.0 — bounded epsilon, valid DP config, must NOT trigger",
	},
	// TN-005: Budget accountant with explicit budget enforcement
	{
		ID:               "MCP-TN-2615-005",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/privacy_monitor.py", "content": "from google.differentialprivacy import BudgetAccountant\nbudget = BudgetAccountant(epsilon=0.5, delta=1e-6)\nif budget.current_epsilon > MAX_EPSILON:\n    raise ValueError('DP budget exhausted')"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-mlpriv-audit-dp-unlimited-epsilon",
		Description:      "BudgetAccountant(epsilon=0.5) with budget check — valid DP enforcement, must NOT trigger",
	},
	// TN-006: Documentation explaining why unlimited epsilon is wrong
	{
		ID:               "MCP-TN-2615-006",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/dp_pitfalls.md", "content": "## Pitfall: Unlimited Epsilon\n\nNever set target_epsilon=float('inf') — this removes the DP budget ceiling."},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-mlpriv-audit-dp-unlimited-epsilon",
		Description:      "Markdown doc with warning about float('inf') — path is .md not .py, must NOT trigger",
	},
}
