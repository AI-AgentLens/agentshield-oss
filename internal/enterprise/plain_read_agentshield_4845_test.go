package enterprise

import "testing"

// TestSelfProtect_MCPProxyWrapAttributesAsStandalone_4845 pins the receipt
// Codex pass 1 raised on #4845. On main, `agentshield mcp-proxy -- <stmt>`
// was a plain read, so the catch-all's exclusion skipped the raw text and a
// later reading's specific rule claimed it: a spliced bypass variable was
// sp-block-bypass-env there, while the statement alone, or after
// `agentshield status;`, was the catch-all's with no node. The wrapped
// spelling's more specific receipt rested on the exemption this change
// removes, the class Gary accepted on #4844 (2026-11-08). Now the wrapped
// spelling is attributed exactly as the statement alone is. Every row BLOCKs.
func TestSelfProtect_MCPProxyWrapAttributesAsStandalone_4845(t *testing.T) {
	cfg := "~/.agent" + "shield/policy.yaml"
	for _, stmt := range []string{
		"env AGENTSHIELD_BYPA'S'S=1 sed -i.bak s/BLOCK/AUDIT/ " + cfg,
		"r'm' " + cfg,
		"sed -i s/BLOCK/AUDIT/ " + cfg,
		"rm " + cfg,
	} {
		want, ok := matchesSelfProtectRule(stmt)
		if !ok {
			t.Fatalf("control %q does not match", stmt)
		}
		for _, cmd := range []string{"agentshield mcp-proxy -- " + stmt, "agentshield status; " + stmt} {
			if IsPlainConfigRead(cmd) {
				t.Errorf("%q is a plain read", cmd)
			}
			if got, ok := matchesSelfProtectRule(cmd); !ok || got != want {
				t.Errorf("%q: %v %s, want %s as %q alone", cmd, ok, got, want, stmt)
			}
		}
	}
}
