package mcp

import (
	"strings"
	"testing"
)

// Rule 1 — Prompt NAME / argument-NAME impersonation & injection.
//
// The description-text pipeline never inspects a prompt's name or its argument
// names. Those are slash-command identifiers the host renders verbatim, the user
// selects by sight, and the agent routes on. scanPromptIdentifier closes that
// surface gap: it flags Unicode confusables / invisibles (impersonation), LLM
// role tokens, and hidden-instruction tags in the identifier, while staying
// false-positive-free on the conventional snake_case / kebab-case names servers
// actually publish — including legitimately credential-themed names like
// `get_credentials` that the prose credential-harvest patterns would mis-flag.

func TestScanPromptIdentifier_TruePositives(t *testing.T) {
	cases := []struct {
		name       string
		promptName string
		argName    string // optional; scanned when non-empty
		wantSignal NotificationSignal
	}{
		{
			name:       "cyrillic homoglyph impersonates code_review",
			promptName: "cоde_review", // Cyrillic о (U+043E) in "code"
			wantSignal: SignalNotificationConfusable,
		},
		{
			name:       "zero-width char splits a trusted name",
			promptName: "deploy\u200bprod", // zero-width space
			wantSignal: SignalNotificationConfusable,
		},
		{
			name:       "unicode tag char smuggled into name",
			promptName: "summarize\U000E0041", // Unicode tag block char
			wantSignal: SignalNotificationConfusable,
		},
		{
			name:       "bidi override reorders displayed name",
			promptName: "run_\u202etidua", // RLO makes it read 'audit' reversed
			wantSignal: SignalNotificationConfusable,
		},
		{
			name:       "LLM role token embedded in name",
			promptName: "helper<|im_start|>system",
			wantSignal: SignalNotificationInjection,
		},
		{
			name:       "hidden-instruction tag in name",
			promptName: "doc<important>",
			wantSignal: SignalNotificationInjection,
		},
		{
			name:       "confusable in ARGUMENT name",
			promptName: "review_pr",
			argName:    "pаth", // Cyrillic а in "path"
			wantSignal: SignalNotificationConfusable,
		},
		{
			name:       "role token in ARGUMENT name",
			promptName: "review_pr",
			argName:    "ctx<<SYS>>",
			wantSignal: SignalNotificationInjection,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prompt := PromptDefinition{Name: tc.promptName}
			if tc.argName != "" {
				prompt.Arguments = []PromptArgument{{Name: tc.argName}}
			}
			res := ScanPromptsListDescriptions(&ListPromptsResult{Prompts: []PromptDefinition{prompt}})
			if !res.Poisoned {
				t.Fatalf("expected poisoned=true for %q / arg %q, got clean", tc.promptName, tc.argName)
			}
			found := false
			for _, f := range res.Findings {
				if f.Signal == tc.wantSignal {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected signal %q, got findings: %+v", tc.wantSignal, res.Findings)
			}
		})
	}
}

func TestScanPromptIdentifier_TrueNegatives(t *testing.T) {
	// Realistic, legitimate prompt + argument names a real MCP server publishes.
	// None must fire — especially the credential-themed names, which would
	// false-positive if the prose credential-harvest patterns were applied to
	// identifiers. The argument descriptions intentionally stay empty so this
	// test isolates the identifier scan from the description scan.
	prompts := []PromptDefinition{
		{Name: "code_review", Arguments: []PromptArgument{{Name: "pr_number"}, {Name: "repo"}}},
		{Name: "summarize_pull_request", Arguments: []PromptArgument{{Name: "file_path"}}},
		{Name: "get_credentials", Arguments: []PromptArgument{{Name: "service"}}},      // "credentials" is fine in a NAME
		{Name: "rotate_api_key", Arguments: []PromptArgument{{Name: "api_key_id"}}},    // "api_key" is fine in a NAME
		{Name: "read_env_file", Arguments: []PromptArgument{{Name: "env_name"}}},       // ".env" theme is fine in a NAME
		{Name: "generate-changelog", Arguments: []PromptArgument{{Name: "from-tag"}}},  // kebab-case
		{Name: "explain_code", Arguments: []PromptArgument{{Name: "language"}, {Name: "snippet"}}},
		{Name: "ssh_config_lint", Arguments: []PromptArgument{{Name: "host"}}}, // "ssh" theme is fine in a NAME
	}
	for _, p := range prompts {
		res := ScanPromptsListDescriptions(&ListPromptsResult{Prompts: []PromptDefinition{p}})
		if res.Poisoned {
			t.Errorf("legitimate prompt %q flagged as poisoned: %+v", p.Name, res.Findings)
		}
	}
}

func TestScanPromptIdentifier_FieldAttribution(t *testing.T) {
	// The finding's Field must point at the offending identifier so the audit log
	// is attributable to the name (not a description).
	prompt := PromptDefinition{Name: "cоde_review"}
	res := ScanPromptsListDescriptions(&ListPromptsResult{Prompts: []PromptDefinition{prompt}})
	if !res.Poisoned {
		t.Fatal("expected poisoned")
	}
	if !strings.Contains(res.Findings[0].Field, ".name") {
		t.Fatalf("expected field to reference .name, got %q", res.Findings[0].Field)
	}
}
