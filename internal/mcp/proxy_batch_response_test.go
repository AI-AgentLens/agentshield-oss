package mcp

import (
	"strings"
	"testing"
)

// #4070 (stdio batch row): a server line that is a JSON-RPC batch array. Every
// scanner rejects a non-object, so the array was forwarded as one unparseable
// line and its members reached a batch-reading client unscanned. Same
// behaviour as the HTTP proxy's filterBatch, driven through the stdio relay.

func TestStdioProxy_BatchResponseMembersAreScanned_4070(t *testing.T) {
	benign := `{"jsonrpc":"2.0","id":11,"result":{"content":[{"type":"text","text":"72F and sunny"}]}}`
	clean := `[` + benign + `]`

	t.Run("poisoned-tools-list-member", func(t *testing.T) {
		got := driveStdio(t, string(batchBody(t))).got
		if strings.Contains(got, "poisoned_tool") {
			t.Errorf("poisoned batch member reached the client: %.200s", got)
		}
		if !strings.Contains(got, "72F and sunny") {
			t.Errorf("benign member dropped with the poisoned one: %.200s", got)
		}
	})

	t.Run("poisoned-tool-result-member", func(t *testing.T) {
		inj, _ := buildInjectionTestCase(2) // marker: attacker.com
		bad := `{"jsonrpc":"2.0","id":12,"result":{"content":[{"type":"text","text":` + mustJSON(inj) + `}]}}`
		res := driveStdio(t, `[`+benign+`,`+bad+`]`)
		if strings.Contains(res.got, "attacker.com") {
			t.Errorf("poisoned result member reached the client: %.200s", res.got)
		}
		if !strings.Contains(res.got, "72F and sunny") {
			t.Errorf("benign member dropped: %.200s", res.got)
		}
		if len(res.audits) == 0 {
			t.Error("no audit receipt for the blocked member")
		}
	})

	t.Run("poisoned-notification-member-suppressed", func(t *testing.T) {
		inj, _ := buildInjectionTestCase(2)
		note := `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":` + mustJSON(inj) + `}}`
		got := driveStdio(t, `[`+benign+`,`+note+`]`).got
		if strings.Contains(got, "attacker.com") {
			t.Errorf("poisoned notification member reached the client: %.200s", got)
		}
		if !strings.Contains(got, "72F and sunny") {
			t.Errorf("benign member dropped: %.200s", got)
		}
	})

	t.Run("benign-batch-control-byte-identical", func(t *testing.T) {
		res := driveStdio(t, clean)
		if res.got != clean {
			t.Errorf("benign batch altered:\n got: %s\nwant: %s", res.got, clean)
		}
		if len(res.audits) != 0 {
			t.Errorf("benign batch produced audits: %v", auditRuleIDs(res.audits))
		}
	})

	t.Run("single-message-path-unchanged", func(t *testing.T) {
		if got := driveStdio(t, benign).got; got != benign {
			t.Errorf("single clean message altered: %s", got)
		}
	})
}
