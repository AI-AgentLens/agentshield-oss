package testdata

// ---------------------------------------------------------------------------
// MCP Credential-Store Insecure Deserialization — issue #3785
//
// Taxonomy: unauthorized-execution/agentic-attacks/mcp-credential-store-deserialization
// Rules: sc-block-pickle-load-credential-store, sc-block-yaml-unsafe-load-credential-store
//
// Distinct from Shield's existing pickle/yaml coverage (sc-block-pickle-load-url,
// sc-block-cloudpickle-load, sc-audit-yaml-unsafe-load, ts-block-agent-cache-pickle-write),
// which all target ML model-checkpoint loading or agent tool-result caches. This
// mechanism is an MCP server's own steady-state credential/session persistence
// (CVE-2026-76404, CWE-502) — a distinct data class and component, so path-scoped
// to credential/session/token-store-shaped filenames rather than bare pickle.loads().
// ---------------------------------------------------------------------------

var MCPCredentialStoreDeserializationCases = []TestCase{
	{
		ID:               "TP-MCPCREDSTORE-001",
		Command:          `python3 -c "import pickle; creds = pickle.loads(open('/home/user/.splunk-mcp/session_cache.pkl','rb').read())"`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "unauthorized-execution/agentic-attacks/mcp-credential-store-deserialization",
		Analyzer:         "regex",
		Description:      "pickle.loads on an MCP server's own session-cache file — unsafe deserialization of a credential store (CVE-2026-76404 class)",
		Tags:             []string{"tp", "agentic-attack", "mcp", "deserialization"},
	},
	{
		ID:               "TP-MCPCREDSTORE-002",
		Command:          `python3 -c "import pickle, os; pickle.load(open(os.path.expanduser('~/.mcp-creds/token_store.pkl'), 'rb'))"`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "unauthorized-execution/agentic-attacks/mcp-credential-store-deserialization",
		Analyzer:         "regex",
		Description:      "pickle.load on an MCP token-store file — unsafe deserialization of a credential store",
		Tags:             []string{"tp", "agentic-attack", "mcp", "deserialization"},
	},
	{
		ID:               "TP-MCPCREDSTORE-003",
		Command:          `python3 -c "import yaml; session = yaml.load(open('/home/user/.mcp/session_cache.yaml'), Loader=yaml.UnsafeLoader)"`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "unauthorized-execution/agentic-attacks/mcp-credential-store-deserialization",
		Analyzer:         "regex",
		Description:      "yaml.load with UnsafeLoader on an MCP session-cache file — arbitrary object construction via !!python/object tags",
		Tags:             []string{"tp", "agentic-attack", "mcp", "deserialization"},
	},
	{
		ID:               "TP-MCPCREDSTORE-004",
		Command:          `python3 -c "import yaml; creds = yaml.load(open('~/.splunk-mcp/credential_store.yaml'), Loader=yaml.Loader)"`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "unauthorized-execution/agentic-attacks/mcp-credential-store-deserialization",
		Analyzer:         "regex",
		Description:      "yaml.load with yaml.Loader on an MCP credential-store file — unsafe deserialization of a credential store",
		Tags:             []string{"tp", "agentic-attack", "mcp", "deserialization"},
	},
	{
		ID:               "TN-MCPCREDSTORE-001",
		Command:          `python3 -c "import pickle; data = pickle.loads(open('dataframe_cache.pkl','rb').read())"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "unauthorized-execution/agentic-attacks/mcp-credential-store-deserialization",
		Analyzer:         "regex",
		Description:      "pickle.loads on an unrelated, non-credential-shaped path — must not trigger the credential-store-scoped rule",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-MCPCREDSTORE-002",
		Command:          `python3 -c "import json; creds = json.loads(open('/home/user/.splunk-mcp/session_cache.json').read())"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "unauthorized-execution/agentic-attacks/mcp-credential-store-deserialization",
		Analyzer:         "regex",
		Description:      "json.loads (data-only format, no arbitrary object reconstruction) on a credential-store-shaped path — must not trigger",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-MCPCREDSTORE-003",
		Command:          `python3 -c "import yaml; yaml.load(open('dataframe_cache.yaml'), Loader=yaml.UnsafeLoader)"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "unauthorized-execution/agentic-attacks/mcp-credential-store-deserialization",
		Analyzer:         "regex",
		Description:      "yaml.load with UnsafeLoader on an unrelated, non-credential-shaped path — must not trigger the credential-store-scoped rule",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-MCPCREDSTORE-004",
		Command:          `python3 -c "import yaml; session = yaml.safe_load(open('session_cache.yaml'))"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "unauthorized-execution/agentic-attacks/mcp-credential-store-deserialization",
		Analyzer:         "regex",
		Description:      "yaml.safe_load (no unsafe Loader, no arbitrary object reconstruction) on a session-store path — must not trigger",
		Tags:             []string{"tn", "safe"},
	},
}
