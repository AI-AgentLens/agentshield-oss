package cli

import (
	"os"
	"strings"
	"testing"
)

// The proxies build their audit sinks inside the command runners. This pins
// the wiring (#4463, #4734): both use newMCPProxyAuditSink with the compiled
// data-label engine, and the sink marshals the redacted entry, never the raw
// one. What the sink writes and uploads is covered by mcp_proxy_upload_test.go;
// the behaviour of Redacted by internal/mcp.
func TestMCPProxyAuditSinksMarshalRedactedEntry_4463(t *testing.T) {
	for _, f := range []string{"mcp_proxy.go", "mcp_http_proxy.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(src)
		if !strings.Contains(s, "newMCPProxyAuditSink(auditFile, func() *datalabel.Engine { return dlEngine }, evaluator.RuleTaxonomyRefs)") {
			t.Errorf("%s: audit sink is not newMCPProxyAuditSink with the live data-label engine", f)
		}
		if strings.Contains(s, "json.Marshal(entry)") {
			t.Errorf("%s: audit sink marshals a raw AuditEntry", f)
		}
		if !strings.Contains(s, "dlEngine = engine") {
			t.Errorf("%s: dlEngine is never set from the compiled data-label engine", f)
		}
	}
	src, err := os.ReadFile("mcp_proxy_upload.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	if !strings.Contains(s, "entry.Redacted(dlEngine().Spans)") {
		t.Errorf("mcp_proxy_upload.go: the sink does not redact with the data-label engine")
	}
	if strings.Contains(s, "json.Marshal(entry)") {
		t.Errorf("mcp_proxy_upload.go: the sink marshals a raw AuditEntry")
	}
}
