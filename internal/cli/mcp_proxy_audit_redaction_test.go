package cli

import (
	"os"
	"strings"
	"testing"
)

// The proxies' audit sinks are closures inside the command runners, so they
// cannot be driven from a unit test. This pins the wiring itself (#4463): each
// sink must marshal the redacted entry, never the raw one. The behaviour of
// Redacted is covered in internal/mcp.
func TestMCPProxyAuditSinksMarshalRedactedEntry_4463(t *testing.T) {
	for _, f := range []string{"mcp_proxy.go", "mcp_http_proxy.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(src)
		if !strings.Contains(s, "json.Marshal(entry.Redacted(dlEngine.Scrub))") {
			t.Errorf("%s: audit sink does not marshal entry.Redacted(dlEngine.Scrub)", f)
		}
		if strings.Contains(s, "json.Marshal(entry)") {
			t.Errorf("%s: audit sink marshals a raw AuditEntry", f)
		}
		if !strings.Contains(s, "dlEngine = engine") {
			t.Errorf("%s: dlEngine is never set from the compiled data-label engine", f)
		}
	}
}
