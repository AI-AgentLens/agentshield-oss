package mcp

import (
	"math"
	"net/url"
	"regexp"
	"strings"

	"github.com/security-researcher-ca/agentshield/internal/policy"
)

// MCPToolIntent represents a classified intent for an MCP tool call.
type MCPToolIntent string

const (
	IntentFileRead       MCPToolIntent = "file-read"
	IntentFileWrite      MCPToolIntent = "file-write"
	IntentFileDelete     MCPToolIntent = "file-delete"
	IntentCodeExecute    MCPToolIntent = "code-execute"
	IntentShellCommand   MCPToolIntent = "shell-command"
	IntentNetworkRequest MCPToolIntent = "network-request"
	IntentDatabaseRead   MCPToolIntent = "database-read"
	IntentDatabaseWrite  MCPToolIntent = "database-write"
	IntentCredentialRead MCPToolIntent = "credential-read"
	IntentSystemConfig   MCPToolIntent = "system-config"
	IntentProcessManage  MCPToolIntent = "process-manage"
	IntentUnknown        MCPToolIntent = "unknown"
)

// IntentClassification holds a classified intent with its confidence score.
type IntentClassification struct {
	Intent     MCPToolIntent `json:"intent"`
	Confidence float64       `json:"confidence"`
}

// MCPSemanticResult holds the outcome of semantic intent classification.
type MCPSemanticResult struct {
	Intents []IntentClassification `json:"intents"`
}

// MCPSemanticMatch defines YAML-level semantic match criteria for policy rules.
type MCPSemanticMatch struct {
	IntentAny     []string `yaml:"intent_any,omitempty"`     // any of these intents must be present
	IntentAll     []string `yaml:"intent_all,omitempty"`     // all of these intents must be present
	ConfidenceMin float64  `yaml:"confidence_min,omitempty"` // minimum confidence threshold
}

// MCPSemanticRule is a complete semantic rule including decision metadata.
type MCPSemanticRule struct {
	ID         string           `yaml:"id"`
	Match      MCPSemanticMatch `yaml:"match"`
	Decision   policy.Decision  `yaml:"decision"`
	Reason     string           `yaml:"reason"`
}

// --- Signal keyword maps ---

// intentKeywords maps tool name keywords to intents with base weights.
// Multiple keywords can map to the same intent.
var intentKeywords = map[MCPToolIntent][]keywordEntry{
	IntentFileRead: {
		{keyword: "read", weight: 0.4},
		{keyword: "get", weight: 0.3},
		{keyword: "view", weight: 0.4},
		{keyword: "list", weight: 0.3},
		{keyword: "show", weight: 0.3},
		{keyword: "cat", weight: 0.4},
		{keyword: "open", weight: 0.2},
	},
	IntentFileWrite: {
		{keyword: "write", weight: 0.4},
		{keyword: "save", weight: 0.4},
		{keyword: "create", weight: 0.3},
		{keyword: "update", weight: 0.3},
		{keyword: "put", weight: 0.3},
		{keyword: "set", weight: 0.2},
		{keyword: "edit", weight: 0.4},
		{keyword: "modify", weight: 0.3},
	},
	IntentFileDelete: {
		{keyword: "delete", weight: 0.5},
		{keyword: "remove", weight: 0.5},
		{keyword: "rm", weight: 0.5},
		{keyword: "drop", weight: 0.4},
		{keyword: "truncate", weight: 0.3},
		{keyword: "purge", weight: 0.4},
		{keyword: "erase", weight: 0.4},
		{keyword: "wipe", weight: 0.4},
		{keyword: "cleanup", weight: 0.2},
	},
	IntentCodeExecute: {
		{keyword: "exec", weight: 0.5},
		{keyword: "execute", weight: 0.5},
		{keyword: "eval", weight: 0.5},
		{keyword: "run", weight: 0.4},
		{keyword: "interpret", weight: 0.3},
	},
	IntentShellCommand: {
		{keyword: "shell", weight: 0.5},
		{keyword: "bash", weight: 0.5},
		{keyword: "terminal", weight: 0.5},
		{keyword: "command", weight: 0.4},
		{keyword: "cmd", weight: 0.4},
		{keyword: "console", weight: 0.3},
	},
	IntentNetworkRequest: {
		{keyword: "http", weight: 0.4},
		{keyword: "request", weight: 0.3},
		{keyword: "fetch", weight: 0.3},
		{keyword: "curl", weight: 0.5},
		{keyword: "api", weight: 0.3},
		{keyword: "webhook", weight: 0.4},
		{keyword: "post", weight: 0.3},
		{keyword: "upload", weight: 0.4},
		{keyword: "download", weight: 0.3},
	},
	IntentDatabaseRead: {
		{keyword: "query", weight: 0.4},
		{keyword: "select", weight: 0.3},
		{keyword: "sql", weight: 0.4},
		{keyword: "database", weight: 0.3},
		{keyword: "db", weight: 0.3},
	},
	IntentDatabaseWrite: {
		{keyword: "insert", weight: 0.4},
		{keyword: "upsert", weight: 0.4},
		{keyword: "migrate", weight: 0.3},
	},
	IntentCredentialRead: {
		{keyword: "credential", weight: 0.5},
		{keyword: "secret", weight: 0.5},
		{keyword: "key", weight: 0.3},
		{keyword: "token", weight: 0.4},
		{keyword: "password", weight: 0.5},
		{keyword: "auth", weight: 0.3},
		{keyword: "vault", weight: 0.4},
	},
	IntentSystemConfig: {
		{keyword: "config", weight: 0.3},
		{keyword: "setting", weight: 0.3},
		{keyword: "env", weight: 0.3},
		{keyword: "environment", weight: 0.3},
	},
	IntentProcessManage: {
		{keyword: "kill", weight: 0.5},
		{keyword: "stop", weight: 0.3},
		{keyword: "restart", weight: 0.4},
		{keyword: "process", weight: 0.3},
		{keyword: "pid", weight: 0.4},
		{keyword: "signal", weight: 0.4},
		{keyword: "daemon", weight: 0.3},
	},
}

// argNameSignals maps argument names to intents they reinforce.
var argNameSignals = map[string][]MCPToolIntent{
	"path":       {IntentFileRead, IntentFileWrite, IntentFileDelete},
	"file":       {IntentFileRead, IntentFileWrite, IntentFileDelete},
	"filename":   {IntentFileRead, IntentFileWrite, IntentFileDelete},
	"filepath":   {IntentFileRead, IntentFileWrite, IntentFileDelete},
	"target":     {IntentFileRead, IntentFileWrite, IntentFileDelete},
	"command":    {IntentCodeExecute, IntentShellCommand},
	"cmd":        {IntentCodeExecute, IntentShellCommand},
	"script":     {IntentCodeExecute, IntentShellCommand},
	"code":       {IntentCodeExecute},
	"expression": {IntentCodeExecute},
	"url":        {IntentNetworkRequest},
	"endpoint":   {IntentNetworkRequest},
	"uri":        {IntentNetworkRequest},
	"host":       {IntentNetworkRequest},
	"query":      {IntentDatabaseRead, IntentDatabaseWrite},
	"sql":        {IntentDatabaseRead, IntentDatabaseWrite},
	"statement":  {IntentDatabaseRead, IntentDatabaseWrite},
	"secret":     {IntentCredentialRead},
	"secret_name": {IntentCredentialRead},
	"token":      {IntentCredentialRead},
	"password":   {IntentCredentialRead},
	"credential": {IntentCredentialRead},
	"key":        {IntentCredentialRead},
	"api_key":    {IntentCredentialRead},
	"pid":        {IntentProcessManage},
	"signal":     {IntentProcessManage},
	"process_id": {IntentProcessManage},
}

type keywordEntry struct {
	keyword string
	weight  float64
}

// ClassifyToolIntent performs heuristic intent classification on an MCP tool call.
// It combines signals from tool name, tool description, argument names, and
// argument values to produce a list of intents with confidence scores.
//
// This is purely heuristic — no LLM calls, no external APIs. Deterministic and fast.
func ClassifyToolIntent(toolName string, arguments map[string]interface{}, toolDescription string) MCPSemanticResult {
	// Accumulate scores per intent from all signals
	scores := make(map[MCPToolIntent]float64)

	// Signal 1: Tool name keywords (highest weight)
	classifyToolName(toolName, scores)

	// Signal 2: Tool description keywords
	classifyDescription(toolDescription, scores)

	// Signal 3: Argument names (reinforcing)
	classifyArgNames(arguments, scores)

	// Signal 4: Argument values (confirming)
	classifyArgValues(arguments, scores)

	// Convert scores to classifications, capping at 1.0
	var result MCPSemanticResult
	for intent, score := range scores {
		conf := math.Min(score, 1.0)
		if conf >= 0.2 { // minimum threshold to report
			result.Intents = append(result.Intents, IntentClassification{
				Intent:     intent,
				Confidence: conf,
			})
		}
	}

	// If no intents classified, mark as unknown
	if len(result.Intents) == 0 {
		result.Intents = append(result.Intents, IntentClassification{
			Intent:     IntentUnknown,
			Confidence: 1.0,
		})
	}

	return result
}

// classifyToolName checks the tool name against keyword patterns.
func classifyToolName(toolName string, scores map[MCPToolIntent]float64) {
	lower := strings.ToLower(toolName)
	// Tokenize on common separators: _, -, camelCase boundaries
	tokens := tokenize(lower)

	for intent, keywords := range intentKeywords {
		for _, kw := range keywords {
			for _, token := range tokens {
				if token == kw.keyword {
					scores[intent] += kw.weight
				}
			}
			// Also check substring match for compound names (e.g., "helpful_assistant" won't match but "run_code" will)
			if strings.Contains(lower, kw.keyword) && kw.weight >= 0.4 {
				// Only give partial credit for substring match to avoid false positives
				scores[intent] += kw.weight * 0.5
			}
		}
	}
}

// classifyDescription checks the tool description for intent signals.
func classifyDescription(description string, scores map[MCPToolIntent]float64) {
	if description == "" {
		return
	}
	lower := strings.ToLower(description)

	descSignals := map[MCPToolIntent][]string{
		IntentFileRead:       {"reads file", "read file", "reads a file", "read a file", "file content", "open file", "view file"},
		IntentFileWrite:      {"writes file", "write file", "writes a file", "write a file", "save file", "create file", "modify file"},
		IntentFileDelete:     {"delete file", "remove file", "removes file", "deletes file", "removes files", "erase file", "wipe file"},
		IntentCodeExecute:    {"execute code", "executes code", "run code", "runs code", "runs user-provided code", "code snippet", "eval", "evaluate code", "interpret code"},
		IntentShellCommand:   {"shell command", "execute command", "run command", "terminal command", "bash command", "executes shell"},
		IntentNetworkRequest: {"http request", "network request", "api call", "sends request", "fetches url", "downloads", "uploads"},
		IntentDatabaseRead:   {"query database", "database query", "select from", "reads from database", "fetch records"},
		IntentDatabaseWrite:  {"insert into", "update database", "write to database", "modify database", "migrate database"},
		IntentCredentialRead: {"read credential", "access secret", "fetch secret", "get password", "read token", "access key", "retrieve key"},
		IntentProcessManage:  {"kill process", "stop process", "restart process", "manage process", "manages system process", "send signal", "terminate process"},
		IntentSystemConfig:   {"system config", "modify config", "change setting", "environment variable", "update config"},
	}

	for intent, phrases := range descSignals {
		for _, phrase := range phrases {
			if strings.Contains(lower, phrase) {
				scores[intent] += 0.3
			}
		}
	}
}

// classifyArgNames checks argument names for intent reinforcement.
func classifyArgNames(arguments map[string]interface{}, scores map[MCPToolIntent]float64) {
	if arguments == nil {
		return
	}

	for argName := range arguments {
		lowerArg := strings.ToLower(argName)
		if intents, ok := argNameSignals[lowerArg]; ok {
			for _, intent := range intents {
				scores[intent] += 0.25
			}
		}
	}
}

// classifyArgValues examines argument values for confirming signals.
func classifyArgValues(arguments map[string]interface{}, scores map[MCPToolIntent]float64) {
	if arguments == nil {
		return
	}

	for _, val := range arguments {
		strVal, ok := val.(string)
		if !ok {
			continue
		}

		// Check if value looks like a file path
		if looksLikeFilePath(strVal) {
			scores[IntentFileRead] += 0.15
			scores[IntentFileWrite] += 0.15
			scores[IntentFileDelete] += 0.15
		}

		// Check if value looks like a URL
		if looksLikeURL(strVal) {
			scores[IntentNetworkRequest] += 0.2
		}

		// Check if value looks like SQL
		if looksLikeSQL(strVal) {
			scores[IntentDatabaseRead] += 0.2
			scores[IntentDatabaseWrite] += 0.1
		}

		// Check if value looks like shell command or code
		if looksLikeCode(strVal) {
			scores[IntentCodeExecute] += 0.2
		}

		// Check if value looks like it references credentials
		if looksLikeCredentialRef(strVal) {
			scores[IntentCredentialRead] += 0.2
		}
	}
}

// --- Value pattern detectors ---

var filePathRe = regexp.MustCompile(`^[~./]?/[\w./-]+$`)

func looksLikeFilePath(s string) bool {
	if len(s) < 2 || len(s) > 500 {
		return false
	}
	return filePathRe.MatchString(s)
}

func looksLikeURL(s string) bool {
	if len(s) < 8 {
		return false
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

var sqlKeywordRe = regexp.MustCompile(`(?i)^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE)\s+`)

func looksLikeSQL(s string) bool {
	return sqlKeywordRe.MatchString(s)
}

// looksLikeCode checks if a string looks like executable code or a shell command.
// We look for common code patterns but exclude simple math expressions.
var codePatterns = regexp.MustCompile(`(?i)(import\s+\w+|os\.(system|popen|exec)|subprocess\.|eval\(|exec\(|` +
	`\bsudo\s|;\s*(rm|curl|wget|bash|sh)\b|` +
	`\brm\s+-[rf]|\bcurl\s+|` +
	`#!/bin/(ba)?sh)`)

// simpleMathRe matches expressions that are pure arithmetic (not code).
var simpleMathRe = regexp.MustCompile(`^[\d\s+\-*/().,%^=<>]+$`)

func looksLikeCode(s string) bool {
	if simpleMathRe.MatchString(s) {
		return false
	}
	return codePatterns.MatchString(s)
}

var credentialRefRe = regexp.MustCompile(`(?i)(aws_access_key|aws_secret|api[_-]?key|password|secret[_-]?key|token|credential|private[_-]?key)`)

func looksLikeCredentialRef(s string) bool {
	return credentialRefRe.MatchString(s)
}

// tokenize splits a lowercase string on underscores, hyphens, and camelCase boundaries.
func tokenize(s string) []string {
	// First split on _ and -
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '_' || r == '-' || r == '.' || r == ' '
	})
	return parts
}

// --- Semantic rule matching ---

// matchSemanticRule checks if a set of classified intents matches a semantic rule.
func matchSemanticRule(intents []IntentClassification, rule MCPSemanticRule) bool {
	m := rule.Match
	minConf := m.ConfidenceMin
	if minConf == 0 {
		minConf = 0.5 // default threshold
	}

	// intent_any: at least one of the specified intents must be present above threshold
	if len(m.IntentAny) > 0 {
		anyMatch := false
		for _, wantIntent := range m.IntentAny {
			for _, ic := range intents {
				if string(ic.Intent) == wantIntent && ic.Confidence >= minConf {
					anyMatch = true
					break
				}
			}
			if anyMatch {
				break
			}
		}
		if !anyMatch {
			return false
		}
	}

	// intent_all: all specified intents must be present above threshold
	if len(m.IntentAll) > 0 {
		for _, wantIntent := range m.IntentAll {
			found := false
			for _, ic := range intents {
				if string(ic.Intent) == wantIntent && ic.Confidence >= minConf {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	// Must have specified at least one matcher
	return len(m.IntentAny) > 0 || len(m.IntentAll) > 0
}

// evaluateSemanticRules classifies tool call intent and evaluates against semantic rules.
func evaluateSemanticRules(toolName string, arguments map[string]interface{}, toolDescription string, rules []MCPSemanticRule) (MCPSemanticResult, []MCPSemanticRule) {
	classification := ClassifyToolIntent(toolName, arguments, toolDescription)

	var matched []MCPSemanticRule
	for _, rule := range rules {
		if matchSemanticRule(classification.Intents, rule) {
			matched = append(matched, rule)
		}
	}

	return classification, matched
}
