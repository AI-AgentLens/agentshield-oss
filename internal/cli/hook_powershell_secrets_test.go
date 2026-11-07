package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/auth"
)

// Inline secrets on Claude Code's PowerShell tool (#4802).
//
// The guardian stage runs in the POSIX pipeline, and Claude Code's PowerShell
// row is Structured + PowerShell, with no POSIX lane. So a token written into
// a cmdlet call, an assignment or a .NET call decided AUDIT with no rule there
// while the Bash tool BLOCKed the same text as guardian-secrets_in_command.
// The PowerShell lane now runs that heuristic, and only that one, over its
// text: each row below first asserts the Bash tool's control (BLOCK by the
// rule), then that the PowerShell tool decides the same with the same rule,
// reason and node, and that neither the audit line nor the hook's stderr
// carries the token.
//
// Token-shaped strings are assembled at run time: the hook on a developer
// machine reads test sources it is asked to run as commands.

const (
	psSecretsRule = "guardian-secrets_in_command"
	psSecretsNode = "credential-exposure/inline-credential/secret-in-command-line"
)

func psGitHubToken() string { return "gh" + "p_" + strings.Repeat("Kq7Z", 9) }
func psAWSKeyID() string    { return "AK" + "IA" + strings.Repeat("Q7", 8) }
func psBearerToken() string { return strings.Repeat("Zx9Lm", 6) }

type psSecretShape struct {
	name, cmd, secret string
}

// psSecretShapes are the issue's four shapes and the spellings around them:
// a here-string, a -Headers hashtable (inline and in a variable),
// [Environment]::SetEnvironmentVariable and a splatted hashtable.
func psSecretShapes() []psSecretShape {
	gh, aws, bearer := psGitHubToken(), psAWSKeyID(), psBearerToken()
	return []psSecretShape{
		{"cmdlet argument", "Write-Output " + gh, gh},
		{"env assignment", "$env:GITHUB_TOKEN = '" + gh + "'; gh repo list", gh},
		{"Invoke-RestMethod header", "Invoke-RestMethod -Uri https://api.github.com/user -Headers @{Authorization='token " + gh + "'}", gh},
		{"native clone URL", "git clone https://" + gh + "@github.com/org/repo.git", gh},
		{"here-string", "$body = @\"\n{\"token\": \"" + gh + "\"}\n\"@\nInvoke-RestMethod -Method Post -Uri https://example.com/api -Body $body", gh},
		{"literal here-string", "$body = @'\ntoken=" + gh + "\n'@\nSet-Content -Path out.txt -Value $body", gh},
		{"headers hashtable variable", "$h = @{ Authorization = \"Bear" + "er " + bearer + "\" }\nInvoke-WebRequest -Uri https://api.example.com/v1 -Headers $h", bearer},
		{"headers hashtable inline", "Invoke-WebRequest -Uri https://api.example.com/v1 -Headers @{ 'X-Api-Key' = '" + gh + "' }", gh},
		{"SetEnvironmentVariable", "[Environment]::SetEnvironmentVariable('GITHUB_TOKEN', '" + gh + "', 'User')", gh},
		{"splatted hashtable", "$p = @{ Uri = 'https://api.github.com/user'; Headers = @{ Authorization = 'token " + gh + "' } }\nInvoke-RestMethod @p", gh},
		{"AWS key id", "$env:AWS_ACCESS_KEY_ID = '" + aws + "'; aws s3 ls", aws},
	}
}

// psSecretEvent is the audit line's fields this test reads.
type psSecretEvent struct {
	Command        string   `json:"command"`
	ToolName       string   `json:"tool_name"`
	Decision       string   `json:"decision"`
	TriggeredRules []string `json:"triggered_rules"`
	Reasons        []string `json:"reasons"`
	Taxonomy       []string `json:"taxonomy"`
	Notes          []struct {
		Kind   string `json:"kind"`
		Detail string `json:"detail"`
	} `json:"notes"`
}

// runSecretHook runs the hook in a child on payload, in a fresh HOME that
// enforces, and returns its exit code, stderr, the one audit event and the
// raw audit log.
func runSecretHook(t *testing.T, payload string, env ...string) (int, string, psSecretEvent, string) {
	t.Helper()
	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	enforceIn(t, configDir)
	code, _, stderr := runHookChild(t, home, payload, env...)
	raw := readFailSafeAuditLog(t, configDir)
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatalf("%d audit lines (stderr %s); want one", len(lines), stderr)
	}
	var e psSecretEvent
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("audit line: %v (%s)", err, lines[0])
	}
	return code, stderr, e, raw
}

// enforceIn pins mode: enforce in a test HOME's config.
func enforceIn(t *testing.T, configDir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(configDir, "agentshield.yaml"), []byte("mode: enforce\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func psLaneReadings(e psSecretEvent) string {
	for _, n := range e.Notes {
		if n.Kind == "lane_readings" {
			return n.Detail
		}
	}
	return ""
}

func TestPowerShellLane_InlineSecrets_ClaudeCodeRowDecidesAsTheBashTool(t *testing.T) {
	for _, s := range psSecretShapes() {
		t.Run(s.name, func(t *testing.T) {
			if !strings.Contains(s.cmd, s.secret) {
				t.Fatal("fixture does not carry its secret")
			}
			_, _, bash, _ := runSecretHook(t, claudeShaped(t, "PreToolUse", "Bash", routingCmd(s.cmd), nil))
			if bash.Decision != "BLOCK" || !slices.Contains(bash.TriggeredRules, psSecretsRule) {
				t.Fatalf("control: the Bash tool decides %s %v; want BLOCK by %s", bash.Decision, bash.TriggeredRules, psSecretsRule)
			}

			code, stderr, ps, raw := runSecretHook(t, claudeShaped(t, "PreToolUse", "PowerShell", routingCmd(s.cmd), nil))
			if code != 2 || ps.Decision != "BLOCK" {
				t.Fatalf("PowerShell: exit %d, %s %v; want BLOCK (exit 2)", code, ps.Decision, ps.TriggeredRules)
			}
			// The rule, reason and node the Bash tool's receipt carries for it.
			i := slices.Index(ps.TriggeredRules, psSecretsRule)
			j := slices.Index(bash.TriggeredRules, psSecretsRule)
			if i < 0 || !slices.Contains(ps.Taxonomy, psSecretsNode) || !slices.Contains(bash.Taxonomy, psSecretsNode) ||
				len(ps.Reasons) <= i || len(bash.Reasons) <= j || ps.Reasons[i] != bash.Reasons[j] {
				t.Errorf("PowerShell receipt %v %v %v; want the Bash receipt's %s, its reason and %s (Bash: %v %v %v)",
					ps.TriggeredRules, ps.Reasons, ps.Taxonomy, psSecretsRule, psSecretsNode, bash.TriggeredRules, bash.Reasons, bash.Taxonomy)
			}
			// Where the Bash receipt is the guardian's alone, the two are equal.
			if slices.Equal(bash.TriggeredRules, []string{psSecretsRule}) &&
				(!slices.Equal(ps.TriggeredRules, bash.TriggeredRules) || !slices.Equal(ps.Taxonomy, bash.Taxonomy)) {
				t.Errorf("PowerShell receipt %v %v, want the Bash receipt %v %v", ps.TriggeredRules, ps.Taxonomy, bash.TriggeredRules, bash.Taxonomy)
			}
			if got := psLaneReadings(ps); !strings.Contains(got, "kept=powershell") {
				t.Errorf("lane_readings %q: want the PowerShell lane's reading kept", got)
			}
			// The receipt: the command is redacted on the line. (The verdict
			// on stderr goes back to the agent that wrote the command, and
			// quotes it for `agentshield check --shell`, as the Bash tool's
			// verdict does; it is not a record.)
			if strings.Contains(raw, s.secret) || !strings.Contains(raw, "[REDACTED]") {
				t.Errorf("audit line carries the token or no [REDACTED] marker:\n%s", raw)
			}
			if !strings.Contains(stderr, psSecretsRule) {
				t.Errorf("stderr names no rule:\n%s", stderr)
			}
		})
	}
}

// TestPowerShellLane_InlineSecrets_WireEntryIsRedacted: the event the hook
// uploads for the PowerShell tool's BLOCK names the rule and its node, and
// carries no token. A logged-in HOME posts (synchronously) to a server
// standing in for the SaaS.
func TestPowerShellLane_InlineSecrets_WireEntryIsRedacted(t *testing.T) {
	srv, bodies := captureAudit(t)
	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	enforceIn(t, configDir)
	if err := auth.Save(&auth.Credentials{Server: srv.URL, Token: "test-agent-token"}); err != nil {
		t.Fatal(err)
	}
	gh := psGitHubToken()
	cmd := "$env:GITHUB_TOKEN = '" + gh + "'; gh repo list"
	code, _, stderr := runHookChild(t, home, claudeShaped(t, "PreToolUse", "PowerShell", routingCmd(cmd), nil), auditUploadEnv+"=sync")
	if code != 2 {
		t.Fatalf("exit %d (stderr %s); want the BLOCK", code, stderr)
	}
	got := bodies()
	if len(got) != 1 {
		t.Fatalf("captured %d /api/audit bodies, want 1 (the positive control: the upload ran)", len(got))
	}
	entry := wireEntry(t, got[0])
	body := got[0]
	if strings.Contains(body, gh) || !strings.Contains(body, "[REDACTED]") {
		t.Errorf("wire entry carries the token or no [REDACTED] marker:\n%s", body)
	}
	if !strings.Contains(body, psSecretsRule) || !strings.Contains(body, psSecretsNode) || entry["decision"] != "BLOCK" {
		t.Errorf("wire entry does not name the BLOCK, %s and %s:\n%s", psSecretsRule, psSecretsNode, body)
	}
}

// TestPowerShellLane_InlineSecrets_CopilotRowsUnchanged: Copilot's two rows
// with the PowerShell lane have a POSIX lane over the raw text, which already
// BLOCKed these texts by the rule. The lane's new reading ties it, and the
// earlier lane keeps its record: same decision, same rules, kept=posix, as on
// main (measured on a3806fa2: kept=posix, rules [guardian-secrets_in_command]).
func TestPowerShellLane_InlineSecrets_CopilotRowsUnchanged(t *testing.T) {
	copilotOnWindows := append([]string{"AGENTSHIELD_AGENT_ID=copilot-cli"}, onWindows...)
	rows := []struct {
		name    string
		payload func(cmd string) string
		env     []string
	}{
		{"compat Bash on Windows", func(cmd string) string { return copilotCompatPayload(t, "secrets", "Bash", shellArgs(cmd)) }, copilotOnWindows},
		{"native powershell", func(cmd string) string { return copilotNativePayload(t, "secrets", "powershell", shellArgs(cmd)) }, nil},
	}
	for _, r := range rows {
		for _, s := range psSecretShapes()[:3] {
			t.Run(r.name+"/"+s.name, func(t *testing.T) {
				_, _, e, _ := runSecretHook(t, r.payload(s.cmd), r.env...)
				if e.Decision != "BLOCK" || !slices.Equal(e.TriggeredRules, []string{psSecretsRule}) {
					t.Errorf("%s %v; want POSIX's BLOCK by %s alone, as on main", e.Decision, e.TriggeredRules, psSecretsRule)
				}
				if got := psLaneReadings(e); !strings.Contains(got, "posix=BLOCK("+psSecretsRule+")") || !strings.HasSuffix(got, "kept=posix") {
					t.Errorf("lane_readings %q: want POSIX's BLOCK kept", got)
				}
			})
		}
	}
}
