package mcp

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/AI-AgentLens/agentshield/internal/mcp/scenarios"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// MCPSelfTestResults holds the aggregate outcome of an MCP self-test run.
type MCPSelfTestResults struct {
	Total     int
	TP        int
	TN        int
	FP        int
	FN        int
	Precision float64
	Recall    float64
	Scenarios []ScenarioResult
}

// ScenarioResult holds the outcome of a single scenario evaluation.
type ScenarioResult struct {
	ID               string
	ToolName         string
	Category         string
	Classification   string
	ExpectedDecision string
	ActualDecision   string
	Pass             bool
	Description      string
}

// FormatMarkdown returns a Markdown-formatted report of the self-test results.
func (r MCPSelfTestResults) FormatMarkdown() string {
	var s string

	s += "## MCP Proxy Self-Test Results\n\n"
	s += fmt.Sprintf("TP: %d | TN: %d | FP: %d | FN: %d\n", r.TP, r.TN, r.FP, r.FN)
	// %.2f, not %.0f. PULL_REQUEST_TEMPLATE.md calls this "the customer-facing
	// precision/recall number", and at %.0f a run with 15 false negatives out
	// of 3,398 printed "Recall: 100%" — observed while mutation-testing this
	// gate on 2026-07-28. The exit status was correct (non-zero), but the line
	// a human actually reads claimed perfection over 15 missed detections.
	s += fmt.Sprintf("Precision: %.2f%% | Recall: %.2f%%\n\n", r.Precision, r.Recall)

	// Count failures
	var failures []ScenarioResult
	for _, sr := range r.Scenarios {
		if !sr.Pass {
			failures = append(failures, sr)
		}
	}

	if len(failures) == 0 {
		s += "### All scenarios passed\n"
	} else {
		s += fmt.Sprintf("### %d scenario(s) failed\n\n", len(failures))
		s += "| ID | Tool | Category | Expected | Got | Description |\n"
		s += "|----|------|----------|----------|-----|-------------|\n"
		for _, f := range failures {
			desc := f.Description
			if len(desc) > 60 {
				desc = desc[:57] + "..."
			}
			s += fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
				f.ID, f.ToolName, f.Category, f.ExpectedDecision, f.ActualDecision, desc)
		}
	}

	return s
}

// RunMCPSelfTest runs all scenarios and returns structured results.
// packsDir should point to the packs/community/mcp/ directory containing YAML packs.
// Additional directories (e.g. premium packs) can be supplied as extraDirs and are
// layered on top in order — mirroring how newTestMCPHandler loads them in tests.
func RunMCPSelfTest(packsDir string, extraDirs ...string) MCPSelfTestResults {
	// Load policy
	mcpPolicy := DefaultMCPPolicy()
	merged, _, err := LoadMCPPacks(packsDir, mcpPolicy)
	if err != nil {
		merged = mcpPolicy
	}

	for _, dir := range extraDirs {
		layered, _, lerr := LoadMCPPacks(dir, merged)
		if lerr == nil {
			merged = layered
		}
	}

	evaluator := NewPolicyEvaluator(merged)
	// Scenario evaluation only consults handler.Evaluator plus stateless
	// scanners, so the trackers wired by newMessageHandler never influence
	// self-test decisions — using the shared constructor keeps the wiring in
	// one place without changing counts.
	handler := newMessageHandler(evaluator, nil, io.Discard, "", "", nil)

	allScenarios := scenarios.AllScenarios()
	var results MCPSelfTestResults
	results.Total = len(allScenarios)

	for _, sc := range allScenarios {
		actual := evaluateScenarioFromDef(handler, sc)
		match := actual == sc.ExpectedDecision

		sr := ScenarioResult{
			ID:               sc.ID,
			ToolName:         sc.ToolName,
			Category:         sc.Category,
			Classification:   sc.Classification,
			ExpectedDecision: sc.ExpectedDecision,
			ActualDecision:   actual,
			Pass:             match,
			Description:      sc.Description,
		}
		results.Scenarios = append(results.Scenarios, sr)

		switch {
		case sc.Classification == "TP" && match:
			results.TP++
		case sc.Classification == "TP" && !match:
			results.FN++
		case sc.Classification == "TN" && match:
			results.TN++
		case sc.Classification == "TN" && !match:
			results.FP++
		}
	}

	if results.TP+results.FP > 0 {
		results.Precision = 100 * float64(results.TP) / float64(results.TP+results.FP)
	}
	if results.TP+results.FN > 0 {
		results.Recall = 100 * float64(results.TP) / float64(results.TP+results.FN)
	}

	return results
}

// evaluateScenarioFromDef runs a single scenario through the full MCP evaluation
// pipeline. This is the non-test version used by RunMCPSelfTest.
func evaluateScenarioFromDef(handler *MessageHandler, sc scenarios.Scenario) string {
	// roots/list response scenario: evaluate declared root URIs against protected paths.
	if sc.RootsListRoots != nil {
		roots := make([]RootInfo, 0, len(sc.RootsListRoots))
		for _, uri := range sc.RootsListRoots {
			roots = append(roots, RootInfo{URI: uri})
		}
		result := handler.Evaluator.EvaluateRootsList(roots)
		return string(result.Decision)
	}

	// Elicitation/create scenario: run elicitation scanner.
	if sc.ElicitationParams != nil {
		params := &ElicitationCreateParams{
			Message: sc.ElicitationParams.Message,
		}
		if len(sc.ElicitationParams.SchemaProperties) > 0 {
			params.RequestedSchema = &ElicitationSchema{
				Properties: make(map[string]*SchemaProperty, len(sc.ElicitationParams.SchemaProperties)),
			}
			for name, prop := range sc.ElicitationParams.SchemaProperties {
				params.RequestedSchema.Properties[name] = &SchemaProperty{
					Title:       prop.Title,
					Description: prop.Description,
				}
			}
		}
		scanResult := ScanElicitationCreate(params)
		switch {
		case scanResult.Blocked:
			return string(policy.DecisionBlock)
		case scanResult.Audited:
			return "AUDIT"
		default:
			return "ALLOW"
		}
	}

	// prompts/get response scenario: scan message content for injection.
	if sc.PromptsGetMessages != nil {
		result := &GetPromptResult{
			Description: sc.PromptsGetDescription,
		}
		for _, m := range sc.PromptsGetMessages {
			result.Messages = append(result.Messages, PromptMessage{
				Role:    m.Role,
				Content: PromptMessageContent{Type: "text", Text: m.Content},
			})
		}
		scanResult := ScanPromptsGetResponse(result)
		if scanResult.Poisoned {
			return string(policy.DecisionBlock)
		}
		return "ALLOW"
	}

	// prompts/list response scenario: scan prompt descriptions for injection seeds.
	if sc.PromptsListEntries != nil {
		result := &ListPromptsResult{}
		for _, e := range sc.PromptsListEntries {
			def := PromptDefinition{
				Name:        e.Name,
				Description: e.Description,
			}
			for _, a := range e.Arguments {
				def.Arguments = append(def.Arguments, PromptArgument{
					Name:        a.Name,
					Description: a.Description,
					Required:    a.Required,
				})
			}
			result.Prompts = append(result.Prompts, def)
		}
		scanResult := ScanPromptsListDescriptions(result)
		if scanResult.Poisoned {
			return string(policy.DecisionBlock)
		}
		return "ALLOW"
	}

	// completion/complete response scenario: scan suggestion values for injection.
	if sc.CompletionValues != nil {
		result := &CompletionCompleteResult{
			Completion: CompletionItems{Values: sc.CompletionValues},
		}
		scanResult := ScanCompletionResponse(result)
		if scanResult.Poisoned {
			return string(policy.DecisionBlock)
		}
		return "ALLOW"
	}

	// notifications/resources/updated scenario: validate the notification URI against
	// the same resource-read policy used by HandleResourcesUpdatedNotification.
	if sc.ResourcesUpdatedURI != "" {
		result := handler.Evaluator.EvaluateResourceRead(sc.ResourcesUpdatedURI)
		return string(result.Decision)
	}

	// structuredContent response scenario (MCP 2025-06-18): scan typed JSON field
	// values for prompt-injection payloads embedded outside the text content array.
	if sc.StructuredContent != nil {
		scResult := ScanStructuredContent(sc.StructuredContent)
		if scResult.Poisoned {
			return string(policy.DecisionBlock)
		}
		return "ALLOW"
	}

	// resources/read response scenario: scan content items for injection payloads.
	if sc.ResourceReadTexts != nil {
		items := make([]ContentItem, 0, len(sc.ResourceReadTexts))
		for _, text := range sc.ResourceReadTexts {
			items = append(items, ContentItem{Type: "text", Text: text})
		}
		scanResult := ScanToolCallResponse(items)
		if scanResult.Poisoned {
			return string(policy.DecisionBlock)
		}
		return "ALLOW"
	}

	// resources/list response scenario: scan URI templates for sensitive path injection.
	if sc.ResourceListURIs != nil {
		resources := make([]ResourceEntry, 0, len(sc.ResourceListURIs))
		for _, uri := range sc.ResourceListURIs {
			resources = append(resources, ResourceEntry{URI: uri})
		}
		listResult := &ResourcesListResult{Resources: resources}
		scanResult := ScanResourcesListResponse(listResult)
		if scanResult.Blocked {
			return string(policy.DecisionBlock)
		}
		return "ALLOW"
	}

	// tools/list manifest flooding scenario.
	if sc.ToolsListTools != nil {
		tools := make([]ToolDefinition, 0, len(sc.ToolsListTools))
		for _, t := range sc.ToolsListTools {
			tools = append(tools, ToolDefinition{Name: t.Name, Description: t.Description})
		}
		// Compute a realistic manifest byte count from the JSON representation.
		result := ListToolsResult{Tools: tools}
		resultBytes, _ := json.Marshal(result)
		scan := ScanToolsListManifest(tools, len(resultBytes))
		return scan.Decision
	}

	// initialize handshake response scenario.
	if sc.InitializeResponse != nil {
		var capBytes json.RawMessage
		if sc.InitializeResponse.Capabilities != nil {
			capBytes, _ = json.Marshal(sc.InitializeResponse.Capabilities)
		}
		initResult := &InitializeResult{
			ProtocolVersion: sc.InitializeResponse.ProtocolVersion,
			Capabilities:    capBytes,
		}
		if sc.InitializeResponse.ServerName != "" {
			initResult.ServerInfo = &ServerInfo{Name: sc.InitializeResponse.ServerName}
		}
		scan := ScanInitializeResponse(initResult)
		return scan.Decision
	}

	// notifications/progress scenario: run progress notification scanner.
	if sc.ProgressNotificationMessage != "" {
		params, err := json.Marshal(map[string]interface{}{
			"progressToken": "test-token",
			"progress":      1,
			"message":       sc.ProgressNotificationMessage,
		})
		if err != nil {
			return "ALLOW" // fail open
		}
		scanResult := ScanProgressNotification(params)
		if scanResult.Blocked {
			return string(policy.DecisionBlock)
		}
		return "ALLOW"
	}

	// notifications/message scenario: run notification scanner.
	if sc.NotificationParams != nil {
		params, err := json.Marshal(map[string]interface{}{
			"level":  sc.NotificationParams.Level,
			"logger": sc.NotificationParams.Logger,
			"data":   sc.NotificationParams.Data,
		})
		if err != nil {
			return "ALLOW" // fail open
		}
		scanResult := ScanNotificationMessage(params)
		if scanResult.Blocked {
			return string(policy.DecisionBlock)
		}
		return "ALLOW"
	}

	// Sampling/createMessage scenario: run sampling scanner instead of tool call pipeline.
	if sc.SamplingMessages != nil {
		params := &SamplingCreateMessageParams{
			SystemPrompt:   sc.SamplingSystemPrompt,
			IncludeContext: sc.SamplingIncludeContext,
		}
		for _, m := range sc.SamplingMessages {
			params.Messages = append(params.Messages, SamplingMessage{
				Role:    m.Role,
				Content: SamplingMessageContent{Type: "text", Text: m.Content},
			})
		}
		scanResult := ScanSamplingMessages(params)
		if scanResult.Blocked {
			return string(policy.DecisionBlock)
		}
		return "AUDIT" // all sampling requests are audited
	}

	// Sampling/createMessage with includeContext only (no messages): run sampling scanner.
	// Handles the case where the scenario only sets SamplingIncludeContext without messages.
	if sc.SamplingIncludeContext != "" {
		params := &SamplingCreateMessageParams{
			IncludeContext: sc.SamplingIncludeContext,
		}
		scanResult := ScanSamplingMessages(params)
		if scanResult.Blocked {
			return string(policy.DecisionBlock)
		}
		return "AUDIT"
	}

	// Step 1: Policy evaluation (with description for semantic classification)
	result := handler.Evaluator.EvaluateToolCallFull(sc.ToolName, sc.Arguments, sc.ToolDescription)

	// Step 2: Content scanning
	if result.Decision != policy.DecisionBlock {
		contentResult := ScanToolCallContent(sc.ToolName, sc.Arguments)
		if contentResult.Blocked {
			result.Decision = policy.DecisionBlock
		}
	}

	// Step 2b: Filesystem path traversal scanning
	// Detects directory boundary violation sequences (../, %2e%2e, %252e%252e,
	// null bytes) in path arguments of MCP filesystem tool calls.
	if result.Decision != policy.DecisionBlock {
		ptResult := ScanFilesystemPathTraversal(sc.ToolName, sc.Arguments)
		if ptResult.Blocked {
			result.Decision = policy.DecisionBlock
		}
	}

	// Step 3: Value limits
	if result.Decision != policy.DecisionBlock {
		vlResult := handler.Evaluator.CheckValueLimits(sc.ToolName, sc.Arguments)
		if vlResult.Blocked {
			result.Decision = policy.DecisionBlock
		}
	}

	// Step 4: Config guard
	if result.Decision != policy.DecisionBlock {
		guardResult := CheckConfigGuard(sc.ToolName, sc.Arguments)
		if guardResult.Blocked {
			result.Decision = policy.DecisionBlock
		}
	}

	// Step 5: Description poisoning scan
	if result.Decision != policy.DecisionBlock && (sc.ToolDescription != "" || sc.InputSchema != "" || sc.ToolTitle != "") {
		tool := ToolDefinition{
			Name:        sc.ToolName,
			Title:       sc.ToolTitle,
			Description: sc.ToolDescription,
		}
		if sc.InputSchema != "" {
			tool.InputSchema = json.RawMessage(sc.InputSchema)
		}
		descResult := ScanToolDescription(tool)
		if descResult.Poisoned {
			result.Decision = policy.DecisionBlock
		}
	}

	return string(result.Decision)
}
