package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/testhome"
)

// #5001 fix round: the list decides which rules can MATCH; it never changes
// what a receipt resolves. mcp-sec-audit-tool-description-changed is a YAML
// rule with an empty match that labels a Go check: the rug-pull detection in
// the proxies' tools/list handling. Its audit entry names the id and carries
// no taxonomy; the proxies' sink fills the node in from the evaluator
// (withRuleTaxonomy, #4734). With the id listed, 1969203e dropped the rule
// from that lookup and the record lost its node.

const (
	rugPullRule = "mcp-sec-audit-tool-description-changed"
	rugPullNode = "unauthorized-execution/agentic-attacks/mcp-tool-rug-pull"
	rugPullTool = "zz5001_clock"
)

// rugPullToolsResult is a tools/list result with one tool described by desc.
func rugPullToolsResult(desc string) map[string]interface{} {
	return map[string]interface{}{"tools": []interface{}{map[string]interface{}{
		"name": rugPullTool, "description": desc,
		"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
	}}}
}

// TestHelperFakeMCPToolsServer is a stdio MCP server that answers every
// request with a tools/list result whose one tool has the description in
// AGENTSHIELD_FAKE_MCP_TOOLS_DESC.
func TestHelperFakeMCPToolsServer(t *testing.T) {
	desc := os.Getenv("AGENTSHIELD_FAKE_MCP_TOOLS_DESC")
	if desc == "" {
		return
	}
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal(sc.Bytes(), &req) != nil || len(req.ID) == 0 {
			continue
		}
		out, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": rugPullToolsResult(desc)})
		fmt.Println(string(out))
	}
	os.Exit(0)
}

const toolsListRequest = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

// rugPullRecord is the last audit record naming the rug-pull rule in home,
// reduced to what a receipt is made of; nil when there is none.
func rugPullRecord(t *testing.T, home string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, ".agentshield", "audit.jsonl"))
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		var ev map[string]interface{}
		if json.Unmarshal([]byte(lines[i]), &ev) != nil {
			continue
		}
		rules, _ := ev["triggered_rules"].([]interface{})
		for _, r := range rules {
			if r == rugPullRule {
				out := map[string]interface{}{}
				for _, k := range []string{"decision", "triggered_rules", "reasons", "taxonomy", "taxonomy_ref", "source", "tool_name"} {
					out[k] = ev[k]
				}
				return out
			}
		}
	}
	return nil
}

// stdioToolsList runs one tools/list through `agentshield mcp-proxy` against
// the fake tools server describing the tool as desc.
func stdioToolsList(t *testing.T, home, desc string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := proxyHelperCmd(ctx, home, "mcp-proxy", "--", os.Args[0], "-test.run=^TestHelperFakeMCPToolsServer$")
	cmd.Env = append(cmd.Env, "AGENTSHIELD_FAKE_MCP_TOOLS_DESC="+desc)
	cmd.Env = testhome.ChildEnv(cmd.Env)
	cmd.Stdin = strings.NewReader(toolsListRequest + "\n")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("mcp-proxy: %v\nstderr:\n%s", err, stderr.String())
	}
	if !strings.Contains(string(out), rugPullTool) {
		t.Fatalf("tools/list answer did not list %s:\n%s\nstderr:\n%s", rugPullTool, out, stderr.String())
	}
}

// httpToolsList runs one tools/list through `agentshield mcp-http-proxy` to an
// upstream describing the tool as desc.
func httpToolsList(t *testing.T, home, desc string) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		out, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": rugPullToolsResult(desc)})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	}))
	defer upstream.Close()
	port := freePort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := proxyHelperCmd(ctx, home, "mcp-http-proxy", "--upstream", upstream.URL, "--port", fmt.Sprint(port))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	var resp *http.Response
	var err error
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		resp, err = http.Post(url, "application/json", strings.NewReader(toolsListRequest))
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("mcp-http-proxy never answered: %v\nstderr:\n%s", err, stderr.String())
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), rugPullTool) {
		t.Fatalf("tools/list answer did not list %s:\n%s\nstderr:\n%s", rugPullTool, body, stderr.String())
	}
	// The audit line is written before the response is returned; give the
	// process no chance to be killed mid-write.
	time.Sleep(200 * time.Millisecond)
}

// The rug-pull check's record on each proxy: the same with its label rule
// listed as without, node included.
func TestDisableRules5001_RugPullRecordKeepsItsNode(t *testing.T) {
	for _, proxy := range []struct {
		name string
		run  func(t *testing.T, home, desc string)
	}{
		{"stdio", stdioToolsList},
		{"http", httpToolsList},
	} {
		t.Run(proxy.name, func(t *testing.T) {
			record := func(list []string) map[string]interface{} {
				home := dtHome(t, dtOpts{list: list})
				proxy.run(t, home, "Returns the current time.")
				if rec := rugPullRecord(t, home); rec != nil {
					t.Fatalf("first session already recorded a rug-pull: %v", rec)
				}
				proxy.run(t, home, "Returns the current date.")
				rec := rugPullRecord(t, home)
				if rec == nil {
					t.Fatalf("list %v: the description change recorded no %s", list, rugPullRule)
				}
				return rec
			}
			base := record(nil)
			if !reflect.DeepEqual(base["taxonomy"], []interface{}{rugPullNode}) {
				t.Fatalf("setup, no list: taxonomy %v, want [%s]", base["taxonomy"], rugPullNode)
			}
			listed := record([]string{rugPullRule})
			if !reflect.DeepEqual(listed, base) {
				t.Errorf("%s listed:\n  record %v\n  want   %v (the record with nothing listed)", rugPullRule, listed, base)
			}
		})
	}
}
