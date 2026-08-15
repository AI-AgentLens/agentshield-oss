package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// TestPrintMCPEvalResultJSON_RoundTrip — `--format=json` is the contract the
// SaaS playground depends on. Pin field names (decision/rules/reasons/taxonomy)
// so a future struct rename can't silently break the playground API.
func TestPrintMCPEvalResultJSON_RoundTrip(t *testing.T) {
	in := mcp.MCPEvalResult{
		Decision:       policy.DecisionBlock,
		TriggeredRules: []string{"mcp-sec-block-ssh-private-key-read"},
		Reasons:        []string{"Read access to SSH private key blocked."},
		TaxonomyRef:    "credential-exposure/credential-files/ssh-private-key",
	}
	var buf bytes.Buffer
	if err := printMCPEvalResultJSON(&buf, in); err != nil {
		t.Fatalf("printMCPEvalResultJSON: %v", err)
	}

	var out mcp.MCPEvalResult
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if out.Decision != in.Decision {
		t.Errorf("decision = %s, want %s", out.Decision, in.Decision)
	}
	if out.TaxonomyRef != in.TaxonomyRef {
		t.Errorf("taxonomy = %q, want %q", out.TaxonomyRef, in.TaxonomyRef)
	}

	for _, key := range []string{`"decision"`, `"rules"`, `"reasons"`, `"taxonomy"`} {
		if !strings.Contains(buf.String(), key) {
			t.Errorf("output missing JSON field %s\n%s", key, buf.String())
		}
	}
}
