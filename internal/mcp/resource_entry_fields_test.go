package mcp

import (
	"fmt"
	"testing"
)

// #4564: Claude Code's ListMcpResourcesTool hands the model each whole
// resources/list entry as JSON, but the entry scan read only name,
// description and title. An entry's mimeType and its own _meta reached the
// model unscanned on every transport. Same table shape and harness as
// TestResponseDispatch_TransportParity.
func resourceEntryFieldRows() []parityRow {
	injKube, _ := buildInjectionTestCase(7) // marker: kube/config
	jKube := mustJSON(injKube)
	const mKube = "kube/config"
	// The same text with its first letter written as a \u escape, so only the
	// decoded view of _meta reads it as the host does.
	escKube := `"` + fmt.Sprintf(`\u%04x`, jKube[1]) + jKube[2:]

	const (
		ruleResList = "resource-list-metadata-injection"
		ruleTplList = "mcp-resource-templates-list-injection"
	)
	res := func(entry string) string {
		return `{"jsonrpc":"2.0","id":1,"result":{"resources":[` + entry + `]}}`
	}
	tpl := func(entry string) string {
		return `{"jsonrpc":"2.0","id":1,"result":{"resourceTemplates":[` + entry + `]}}`
	}
	return []parityRow{
		{name: "resources/list/mimeType", body: res(`{"uri":"file:///tmp/a.txt","name":"a","mimeType":` + jKube + `}`),
			want: outcomeBlocked, absent: []string{mKube}, rules: []string{ruleResList}},
		{name: "resources/list/entry-_meta", body: res(`{"uri":"file:///tmp/a.txt","name":"a","_meta":{"note":` + jKube + `}}`),
			want: outcomeBlocked, absent: []string{mKube}, rules: []string{ruleResList}},
		{name: "resources/list/entry-_meta/escaped", body: res(`{"uri":"file:///tmp/a.txt","name":"a","_meta":{"note":` + escKube + `}}`),
			want: outcomeBlocked, absent: []string{mKube}, rules: []string{ruleResList}},
		{name: "resources/list/clean-_meta-and-mimeType", body: res(`{"uri":"file:///tmp/a.txt","name":"a","mimeType":"text/plain","_meta":{"owner":"docs-team","rev":3}}`),
			want: outcomeForwarded, present: []string{"docs-team", "text/plain"}},
		{name: "templates/list/mimeType", body: tpl(`{"uriTemplate":"file:///tmp/{x}","name":"t","mimeType":` + jKube + `}`),
			want: outcomeBlocked, absent: []string{mKube}, rules: []string{ruleTplList}},
		{name: "templates/list/entry-_meta", body: tpl(`{"uriTemplate":"file:///tmp/{x}","name":"t","_meta":{"note":` + jKube + `}}`),
			want: outcomeBlocked, absent: []string{mKube}, rules: []string{ruleTplList}},
		{name: "templates/list/clean-_meta", body: tpl(`{"uriTemplate":"file:///tmp/{x}","name":"t","mimeType":"text/plain","_meta":{"owner":"docs-team"}}`),
			want: outcomeForwarded, present: []string{"docs-team"}},
	}
}

func TestResourceEntryFields_TransportParity(t *testing.T) {
	for _, row := range resourceEntryFieldRows() {
		t.Run(row.name, func(t *testing.T) {
			stdio := driveStdio(t, row.body)
			httpJSON := driveHTTP(t, row.body, false)
			httpSSE := driveHTTP(t, row.body, true)
			checkParityRow(t, "stdio", row, stdio)
			checkParityRow(t, "http-json", row, httpJSON)
			checkParityRow(t, "http-sse", row, httpSSE)
			if stdio.got != httpJSON.got || stdio.got != httpSSE.got {
				t.Errorf("transports diverged:\n  stdio:     %s\n  http-json: %s\n  http-sse:  %s", stdio.got, httpJSON.got, httpSSE.got)
			}
		})
	}
}
