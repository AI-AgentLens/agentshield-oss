package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// #4356 on the real `agentshield mcp-eval` command. Before, nothing applied
// --mode, so `mcp-eval --mode audit-only` reported BLOCK (exit 2) for any
// would-be block, a value limit included. These use only symbols that exist
// on main, so they also run there: the audit-only rows fail on main and the
// enforce rows pass.

// mcpEvalValueLimitPolicy is an MCP policy with BLOCK value limits, one of
// them carrying a taxonomy node, and a BLOCK rule that carries one. The tool
// names are invented so no embedded community rule matches them.
const mcpEvalValueLimitPolicy = `defaults:
  decision: "AUDIT"
rules:
  - id: test4356-block-payment-to-held-account
    taxonomy: "destructive-ops/resource-commitment/unbounded-transfer"
    match:
      tool_name_any: ["send_payment_4356"]
      argument_patterns:
        recipient: "acct-held-*"
    decision: "BLOCK"
    reason: "Payment to a held account."
value_limits:
  - id: test4356-cap-payment-amount
    tool_name_regex: ".*pay.*"
    argument: "amount"
    max: 1000.0
    decision: "BLOCK"
    reason: "Payment amount exceeds safety limit of $1,000."
  - id: test-vltax-cap-op-amount
    taxonomy: "destructive-ops/resource-commitment/unbounded-transfer"
    tool_name_regex: "^zq_vltax_op_4394$"
    argument: "amount"
    max: 1000.0
    decision: "BLOCK"
    reason: "Amount exceeds 1000."
`

type mcpEvalRunResult struct {
	exitCode int
	stderr   string
	verdict  map[string]interface{}
}

// runMCPEval runs `agentshield mcp-eval --format json <args>` in home and
// returns its exit code and parsed JSON verdict.
func runMCPEval(t *testing.T, home string, args ...string) mcpEvalRunResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := proxyHelperCmd(ctx, home, append([]string{"mcp-eval", "--format", "json"}, args...)...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	res := mcpEvalRunResult{stderr: stderr.String()}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		res.exitCode = exitErr.ExitCode()
	default:
		t.Fatalf("mcp-eval: %v\nstderr:\n%s", err, res.stderr)
	}
	if err := json.Unmarshal(out, &res.verdict); err != nil {
		t.Fatalf("mcp-eval output is not JSON (exit %d): %v\nstdout:\n%s\nstderr:\n%s", res.exitCode, err, out, res.stderr)
	}
	return res
}

func verdictStrings(v map[string]interface{}, key string) []string {
	raw, _ := v[key].([]interface{})
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		s, _ := r.(string)
		out = append(out, s)
	}
	return out
}

func TestMCPEval_AuditOnlyDowngradesEveryBlockSource_EndToEnd(t *testing.T) {
	home := proxyHome(t, "")
	policy := filepath.Join(t.TempDir(), "mcp-policy.yaml")
	if err := os.WriteFile(policy, []byte(mcpEvalValueLimitPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		args      []string
		wantRules []string
		wantTax   string
	}{
		{
			name:      "value limit (the issue's repro)",
			args:      []string{"--tool", "mcp__billing__create_payment", "--json", `{"amount": 5000, "currency": "USD"}`},
			wantRules: []string{"value-limit", "test4356-cap-payment-amount"},
		},
		{
			// The value limit's taxonomy node is on the verdict, in both
			// modes. ValueLimitFinding used to drop it, so this row fails on
			// main. The tool name matches no embedded rule, so the node can
			// only be the value limit's.
			name:      "value limit carries its taxonomy node",
			args:      []string{"--tool", "zq_vltax_op_4394", "--json", `{"amount": 5000}`},
			wantRules: []string{"value-limit", "test-vltax-cap-op-amount"},
			wantTax:   "destructive-ops/resource-commitment/unbounded-transfer",
		},
		{
			name:      "rule BLOCK over a value limit",
			args:      []string{"--tool", "send_payment_4356", "--json", `{"recipient": "acct-held-7", "amount": 5000}`},
			wantRules: []string{"test4356-block-payment-to-held-account"},
			wantTax:   "destructive-ops/resource-commitment/unbounded-transfer",
		},
		{
			name: "embedded community rule BLOCK",
			args: []string{"--tool", "read_file", "--arg", "path=/home/user/.ssh/id_rsa"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := append([]string{"--mcp-policy", policy}, tc.args...)
			enf := runMCPEval(t, home, append([]string{"--mode", "enforce"}, base...)...)
			if enf.exitCode != 2 || enf.verdict["decision"] != "BLOCK" || enf.verdict["original_decision"] != nil {
				t.Fatalf("enforce: exit %d, verdict %v; want exit 2, BLOCK, no original_decision", enf.exitCode, enf.verdict)
			}
			if !containsAllStrings(verdictStrings(enf.verdict, "rules"), tc.wantRules...) {
				t.Fatalf("enforce: rules %v, want them to include %v", enf.verdict["rules"], tc.wantRules)
			}
			if tc.wantTax != "" && !containsAllStrings(verdictStrings(enf.verdict, "taxonomy_refs"), tc.wantTax) {
				t.Fatalf("enforce: taxonomy_refs %v, want %q", enf.verdict["taxonomy_refs"], tc.wantTax)
			}
			// No --mode: enforce, as on main.
			if flagless := runMCPEval(t, home, base...); flagless.exitCode != 2 || !reflect.DeepEqual(flagless.verdict, enf.verdict) {
				t.Errorf("no --mode: exit %d, verdict %v; want enforce mode's exit 2, %v", flagless.exitCode, flagless.verdict, enf.verdict)
			}

			aud := runMCPEval(t, home, append([]string{"--mode", "audit-only"}, base...)...)
			if aud.exitCode != 0 || aud.verdict["decision"] != "AUDIT" || aud.verdict["original_decision"] != "BLOCK" {
				t.Errorf("audit-only: exit %d, verdict %v; want exit 0, AUDIT, original_decision BLOCK", aud.exitCode, aud.verdict)
			}
			// Everything but the decision is enforce mode's record.
			want := map[string]interface{}{}
			for k, v := range enf.verdict {
				want[k] = v
			}
			want["decision"], want["original_decision"] = "AUDIT", "BLOCK"
			if !reflect.DeepEqual(aud.verdict, want) {
				t.Errorf("audit-only verdict\n %v\nwant enforce mode's record with the decision downgraded\n %v", aud.verdict, want)
			}
		})
	}

	t.Run("no-op control: under the limit", func(t *testing.T) {
		args := []string{"--mcp-policy", policy, "--tool", "create_payment", "--json", `{"amount": 25}`}
		enf := runMCPEval(t, home, append([]string{"--mode", "enforce"}, args...)...)
		aud := runMCPEval(t, home, append([]string{"--mode", "audit-only"}, args...)...)
		if enf.exitCode != 0 || enf.verdict["decision"] == "BLOCK" || !reflect.DeepEqual(aud.verdict, enf.verdict) || aud.exitCode != 0 {
			t.Errorf("enforce exit %d %v, audit-only exit %d %v; want the same non-BLOCK verdict, exit 0", enf.exitCode, enf.verdict, aud.exitCode, aud.verdict)
		}
	})

	// Under its limit, the value limit with a node adds neither its rule nor
	// its node.
	t.Run("no-op control: taxonomy, under the limit", func(t *testing.T) {
		args := []string{"--mcp-policy", policy, "--mode", "enforce", "--tool", "zq_vltax_op_4394", "--json", `{"amount": 25}`}
		enf := runMCPEval(t, home, args...)
		if enf.exitCode != 0 || len(verdictStrings(enf.verdict, "rules")) != 0 || len(verdictStrings(enf.verdict, "taxonomy_refs")) != 0 {
			t.Errorf("exit %d, verdict %v; want exit 0, no rules, no taxonomy", enf.exitCode, enf.verdict)
		}
	})
}

// mcp-eval reads only the --mode flag, never the configured mode, and an
// unrecognised flag value enforces with config.Load's warning (#1952's
// fail-safe). Pinned so a change to either is deliberate (#4324 row 6).
func TestMCPEval_ModeResolution_EndToEnd(t *testing.T) {
	args := []string{"--tool", "read_file", "--arg", "path=/home/user/.ssh/id_rsa"}
	cases := []struct {
		name, yaml string
		flag       []string
		wantExit   int
		wantDec    string
		wantWarn   bool
	}{
		{name: "configured audit-only, no flag", yaml: "mode: audit-only\n", wantExit: 2, wantDec: "BLOCK"},
		{name: "new-install default, no flag", yaml: "default_mode: audit-only\n", wantExit: 2, wantDec: "BLOCK"},
		{name: "configured audit-only, --mode enforce", yaml: "mode: audit-only\n", flag: []string{"--mode", "enforce"}, wantExit: 2, wantDec: "BLOCK"},
		{name: "unrecognised --mode", flag: []string{"--mode", "observe"}, wantExit: 2, wantDec: "BLOCK", wantWarn: true},
		{name: "case variant --mode", flag: []string{"--mode", "Audit-Only"}, wantExit: 2, wantDec: "BLOCK", wantWarn: true},
		{name: "--mode audit-only", flag: []string{"--mode", "audit-only"}, wantExit: 0, wantDec: "AUDIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runMCPEval(t, proxyHome(t, tc.yaml), append(tc.flag, args...)...)
			if res.exitCode != tc.wantExit || res.verdict["decision"] != tc.wantDec {
				t.Errorf("exit %d, decision %v; want exit %d, %s", res.exitCode, res.verdict["decision"], tc.wantExit, tc.wantDec)
			}
			wantWarnings := 0
			if tc.wantWarn {
				wantWarnings = 1
			}
			if n := strings.Count(res.stderr, "unrecognized mode"); n != wantWarnings {
				t.Errorf("%d mode warnings, want %d; stderr:\n%s", n, wantWarnings, res.stderr)
			}
		})
	}
}

func containsAllStrings(have []string, want ...string) bool {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}
