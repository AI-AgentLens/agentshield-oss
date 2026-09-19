package mcp

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// TestCheckToolCallArgsAltFormSSRF exercises the decoder-based check in
// isolation (#3675): dotted-octal AWS IMDS, the ECS task-role IMDS octal
// form, an RFC 1918 host in hex, and the negative controls that must NOT fire
// — a standard dotted-decimal host (out of scope; covered by literal-form
// rules elsewhere), a public host, and an alt-form encoding of a PUBLIC
// address.
func TestCheckToolCallArgsAltFormSSRF(t *testing.T) {
	cases := []struct {
		name      string
		args      map[string]interface{}
		wantHit   bool
		wantArg   string
		wantHost  string
		wantCanon string
	}{
		{
			name:      "dotted_octal_aws_imds_url",
			args:      map[string]interface{}{"url": "http://0251.0376.0251.0376/latest/meta-data/"},
			wantHit:   true,
			wantArg:   "url",
			wantHost:  "0251.0376.0251.0376",
			wantCanon: "169.254.169.254",
		},
		{
			name:      "dotted_octal_aws_imds_uri",
			args:      map[string]interface{}{"uri": "http://0251.0376.0251.0376/latest/meta-data/iam/security-credentials/"},
			wantHit:   true,
			wantArg:   "uri",
			wantHost:  "0251.0376.0251.0376",
			wantCanon: "169.254.169.254",
		},
		{
			name:      "ecs_task_role_octal_dotted",
			args:      map[string]interface{}{"endpoint": "http://0251.0376.0251.02/v2/credentials/task"},
			wantHit:   true,
			wantArg:   "endpoint",
			wantHost:  "0251.0376.0251.02",
			wantCanon: "169.254.169.2",
		},
		{
			name:      "rfc1918_hex_dotted",
			args:      map[string]interface{}{"target": "http://0xa.0x0.0x0.0x1/internal"},
			wantHit:   true,
			wantArg:   "target",
			wantHost:  "0xa.0x0.0x0.0x1",
			wantCanon: "10.0.0.1",
		},
		{
			name:    "standard_dotted_decimal_out_of_scope",
			args:    map[string]interface{}{"url": "http://169.254.169.254/latest/meta-data/"},
			wantHit: false, // literal forms are covered by the YAML rules on this surface, not this check
		},
		{
			name:    "public_host_benign",
			args:    map[string]interface{}{"url": "https://api.github.com/repos/example/repo"},
			wantHit: false,
		},
		{
			name:    "alt_form_encoding_of_public_ip",
			args:    map[string]interface{}{"url": "http://0x8.0x8.0x8.0x8/dns-query"}, // 8.8.8.8, public
			wantHit: false,
		},
		{
			name:    "no_recognized_arg_name",
			args:    map[string]interface{}{"path": "http://0251.0376.0251.0376/latest/meta-data/"},
			wantHit: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			argName, rawHost, canon, hit := checkToolCallArgsAltFormSSRF(c.args)
			if hit != c.wantHit {
				t.Fatalf("hit = %v, want %v (argName=%q rawHost=%q canon=%q)", hit, c.wantHit, argName, rawHost, canon)
			}
			if !c.wantHit {
				return
			}
			if argName != c.wantArg {
				t.Errorf("argName = %q, want %q", argName, c.wantArg)
			}
			if rawHost != c.wantHost {
				t.Errorf("rawHost = %q, want %q", rawHost, c.wantHost)
			}
			if canon != c.wantCanon {
				t.Errorf("canon = %q, want %q", canon, c.wantCanon)
			}
		})
	}
}

// TestEvaluateToolCall_AltFormSSRF_Structural is an end-to-end test through
// PolicyEvaluator.EvaluateToolCall — the same entry point `agentshield
// mcp-eval` and the live proxy use — proving the fix closes the reported gap
// (#3675) at the actual evaluation surface, not just at the helper function.
func TestEvaluateToolCall_AltFormSSRF_Structural(t *testing.T) {
	evaluator := newTestMCPEvaluator(t)

	blockCases := []struct {
		name string
		tool string
		args map[string]interface{}
	}{
		{
			name: "dotted_octal_imds_url",
			tool: "http_request",
			args: map[string]interface{}{"url": "http://0251.0376.0251.0376/latest/meta-data/"},
		},
		{
			name: "dotted_octal_imds_uri",
			tool: "resources/read",
			args: map[string]interface{}{"uri": "http://0251.0376.0251.0376/latest/meta-data/iam/security-credentials/"},
		},
	}
	for _, c := range blockCases {
		t.Run(c.name, func(t *testing.T) {
			result := evaluator.EvaluateToolCall(c.tool, c.args)
			if result.Decision != policy.DecisionBlock {
				t.Fatalf("Decision = %v, want BLOCK", result.Decision)
			}
			foundRule := false
			for _, r := range result.TriggeredRules {
				if r == "mcp-agentic-block-ssrf-alt-ip-encoding-structural" {
					foundRule = true
				}
			}
			if !foundRule {
				t.Errorf("TriggeredRules = %v, want to include mcp-agentic-block-ssrf-alt-ip-encoding-structural", result.TriggeredRules)
			}
			foundTaxonomy := false
			for _, ref := range result.TaxonomyRefs {
				if ref == "unauthorized-execution/agentic-attacks/mcp-resource-uri-ssrf" {
					foundTaxonomy = true
				}
			}
			if !foundTaxonomy {
				t.Errorf("TaxonomyRefs = %v, want to include unauthorized-execution/agentic-attacks/mcp-resource-uri-ssrf", result.TaxonomyRefs)
			}
		})
	}

	tnCases := []struct {
		name string
		tool string
		args map[string]interface{}
	}{
		{
			name: "benign_github_api",
			tool: "http_request",
			args: map[string]interface{}{"url": "https://api.github.com/repos/example/repo"},
		},
		{
			name: "docs_mentioning_octal_form_as_prose_value",
			tool: "read_resource",
			args: map[string]interface{}{"uri": "https://docs.example.com/ssrf-guide?example=0251.0376.0251.0376"},
		},
	}
	for _, c := range tnCases {
		t.Run(c.name, func(t *testing.T) {
			result := evaluator.EvaluateToolCall(c.tool, c.args)
			if result.Decision == policy.DecisionBlock {
				t.Fatalf("Decision = BLOCK, want non-BLOCK for benign case; rules=%v reasons=%v", result.TriggeredRules, result.Reasons)
			}
		})
	}
}
