package mcp

import (
	"slices"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// #4976 (Gary, 2026-11-19): a url argument that wraps a cloud metadata IPv4
// in a NAT64 (64:ff9b::/96) or IPv4-mapped (::ffff:0:0/96) IPv6 literal
// BLOCKs, as the plain IPv4 form of the same address already does for any
// tool with a url argument. Run through the full MCP evaluator: the inline
// pack rows only call the rule's matcher.
func TestSSRFMetadataIPv6Embedded_RaisedTwins(t *testing.T) {
	ossbuild.SkipPremiumSized(t) // the rule is in packs/premium/mcp/
	const rule = "mcp-agentic-block-ssrf-metadata-ipv6-embedded"
	ev := newTestMCPEvaluator(t)
	const (
		twin   = iota // control: BLOCK on main, by other rules
		raised        // BLOCK, and the raised rule is among the triggers
		below         // not a metadata address: below BLOCK, rule silent
	)
	rows := []struct {
		name, tool, url string
		want            int
	}{
		{"plain: AWS IMDS", "fetch", "http://169.254.169.254/latest/meta-data/", twin},
		{"plain: any tool with a url", "bookmark_add", "http://169.254.169.254/latest/meta-data/", twin},
		{"NAT64: AWS IMDS", "fetch", "http://[64:ff9b::a9fe:a9fe]/latest/meta-data/", raised},
		{"mapped hex: AWS IMDS", "fetch", "http://[::ffff:a9fe:a9fe]/latest/meta-data/", raised},
		{"NAT64: ECS credentials", "fetch", "http://[64:ff9b::a9fe:aa02]/v2/credentials/", raised},
		{"mapped hex: EKS Pod Identity", "fetch", "http://[::ffff:a9fe:aa17]/v1/credentials", raised},
		{"NAT64: Tencent", "fetch", "http://[64:ff9b::a9fe:17]/latest/meta-data/", raised},
		{"NAT64: Alibaba", "fetch_url", "http://[64:ff9b::6464:64c8]/latest/meta-data/", raised},
		{"NAT64 with a port", "fetch", "http://[64:ff9b::a9fe:a9fe]:80/latest/meta-data/", raised},
		{"upper case", "fetch", "HTTP://[::FFFF:A9FE:A9FE]/latest/meta-data/", raised},
		{"the advisory's tool", "gzip_file_as_resource", "http://[64:ff9b::a9fe:a9fe]/latest/meta-data/", raised},
		{"any tool with a url", "bookmark_add", "http://[64:ff9b::a9fe:a9fe]/latest/meta-data/", raised},
		{"NAT64: public DNS", "fetch", "http://[64:ff9b::808:808]/", below},
		{"mapped: public DNS", "fetch", "http://[::ffff:8.8.8.8]/", below},
		{"NAT64 dotted: public DNS", "fetch", "http://[64:ff9b::1.1.1.1]/", below},
		{"mapped hex: public DNS", "fetch", "http://[::ffff:101:101]/", below},
		{"next to the IMDS address", "fetch", "http://[64:ff9b::a9fe:a9ff]/", below},
		{"documentation prefix", "fetch", "http://[2001:db8::1]:8080/health", below},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			res := ev.EvaluateToolCall(r.tool, map[string]interface{}{"url": r.url})
			blocked := string(res.Decision) == "BLOCK"
			named := slices.Contains(res.TriggeredRules, rule)
			switch {
			case r.want != below && !blocked:
				t.Fatalf("tool=%s url=%s: got %s %v, want BLOCK", r.tool, r.url, res.Decision, res.TriggeredRules)
			case r.want == raised && !named:
				t.Fatalf("BLOCK did not name %s: %v", rule, res.TriggeredRules)
			case r.want == below && (blocked || named):
				t.Fatalf("tool=%s url=%s: got %s %v, want below BLOCK with %s silent", r.tool, r.url, res.Decision, res.TriggeredRules, rule)
			}
		})
	}
}
