package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// TNPoolEntry represents a TN work item for Baby Kai.
type TNPoolEntry struct {
	RuleID          string `json:"rule_id"`
	TPScenarioID    string `json:"tp_scenario_id"`
	ToolName        string `json:"tool_name"`
	MaliciousPath   string `json:"malicious_path,omitempty"`
	MaliciousURL    string `json:"malicious_url,omitempty"`
	SuggestedTNPath string `json:"suggested_tn_path,omitempty"`
	SuggestedTNURL  string `json:"suggested_tn_url,omitempty"`
	Status          string `json:"status"`
	Difficulty      string `json:"difficulty"`
}

// EmitTNPool generates the TN work queue JSON for Baby Kai.
func EmitTNPool(candidates []Candidate, outPath string, startTPID int) error {
	var pool []TNPoolEntry

	tpID := startTPID
	for _, c := range candidates {
		ruleID := candidateRuleID(c)
		toolName := "read_file"
		if len(c.ToolNames) > 0 {
			toolName = c.ToolNames[0]
		}

		entry := TNPoolEntry{
			RuleID:       ruleID,
			TPScenarioID: fmt.Sprintf("MCP-TP-%03d", tpID),
			ToolName:     toolName,
			Status:       "pending",
			Difficulty:   estimateDifficulty(c),
		}

		if c.Category == "url" && len(c.URLs) > 0 {
			entry.ToolName = "http_request"
			entry.MaliciousURL = c.URLs[0]
			entry.SuggestedTNURL = suggestBenignURL(c.URLs[0])
		} else if len(c.Paths) > 0 {
			entry.MaliciousPath = exampleMaliciousPath(c.Paths[0])
			entry.SuggestedTNPath = suggestBenignPath(c.Paths[0])
		}

		pool = append(pool, entry)
		tpID++
	}

	data, err := json.MarshalIndent(pool, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}

	return os.WriteFile(outPath, data, 0644)
}

// estimateDifficulty assigns easy/medium/hard based on the candidate's properties.
func estimateDifficulty(c Candidate) string {
	if c.Category == "url" {
		return "medium"
	}
	// Paths with narrow globs are easy.
	for _, p := range c.Paths {
		if strings.Count(p, "*") > 2 {
			return "medium"
		}
	}
	return "easy"
}

// suggestBenignPath creates a safe alternative path for TN testing.
func suggestBenignPath(glob string) string {
	// Replace sensitive dirs with benign alternatives.
	replacements := map[string]string{
		".ssh":              "docs/ssh-guide",
		".aws":              "docs/aws-guide",
		".gnupg":            "docs/gpg-guide",
		".kube":             "docs/kubernetes",
		".docker":           "docs/docker",
		".npmrc":            "project/.npmrc.example",
		".pypirc":           "project/pypirc.example",
		".netrc":            "docs/netrc-guide.md",
		".git-credentials":  "docs/git-setup.md",
		".vault-token":      "docs/vault-guide.md",
		".env":              "project/.env.example",
		".terraform.d":      "docs/terraform-guide",
		".config/gcloud":    "docs/gcloud-guide",
		".config/gh":        "docs/gh-guide",
		".azure":            "docs/azure-guide",
		"/etc/shadow":       "/home/user/docs/shadow-guide.md",
		"/etc/master.passwd": "/home/user/docs/passwd-guide.md",
		"169.254.169.254":   "192.168.1.1",
	}

	result := glob
	for sensitive, benign := range replacements {
		if strings.Contains(result, sensitive) {
			result = strings.ReplaceAll(result, sensitive, benign)
			return "/home/user/" + strings.TrimPrefix(result, "**/")
		}
	}

	return "/home/user/docs/readme.md"
}

// suggestBenignURL creates a safe URL for TN testing.
func suggestBenignURL(url string) string {
	return "https://api.github.com/repos/example/repo"
}
