package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// The receipt of a shell BLOCK audit-only mode keeps for self-protection, on
// Claude Code's Bash row through the real hook (#5089). A BLOCK the keep kept
// for a reason its rules do not state leads with enterprise-self-protect and
// that reason; the rules that fired follow; the taxonomy is theirs. Enforce
// mode never gains the record. Paths are assembled: this repo dogfoods
// AgentShield.

func keptReceiptHome(t *testing.T, mode string) (home, configDir string) {
	t.Helper()
	home, configDir = newFailSafeHome(t, true, failSafePolicyGood)
	if err := os.WriteFile(filepath.Join(configDir, "agentshield.yaml"), []byte("mode: "+mode+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, configDir
}

func TestHook_KeptBlockReceiptLeadsWithSelfProtect_5089(t *testing.T) {
	mkfs := "mkfs." + "ext4 /dev/sda1"
	mcpConfig := "~/.cursor/" + "mcp.json"
	sp := policy.SelfProtectRuleID
	for _, tc := range []struct {
		name, cmd string
		// block: the row BLOCKs on this OS. A BLOCK's receipt leads with
		// sp whatever the row (the invariant); lead is the reason it leads
		// with when the keep supplied one, "" when sp is the whole record.
		block bool
		lead  string
		rules []string // the receipt's rules exactly, when set
		tax   []string // the receipt's taxonomy exactly, when set
	}{
		// Every OS. The sp-* text rules do not cover an agent's MCP
		// configuration, so the engine decides: ts-block-mkfs, kept because
		// the command names the file.
		{"mkfs, then an agent's MCP configuration", mkfs + "; r" + "m " + mcpConfig, true,
			policy.SelfProtectKeptReasonPrefix + "the command names ~/.cursor/mcp.json (an agent's MCP configuration) and is not a plain read",
			[]string{sp, "ts-block-mkfs"}, []string{"destructive-ops/disk-ops/filesystem-format"}},
		// The issue's Claude Code Bash row. On Windows the keep reads the
		// Windows spelling (#5064) and keeps the mkfs BLOCK; on main the
		// receipt was ts-block-mkfs alone. Elsewhere it does not, and audit-only
		// lowers the BLOCK as on main. Under Git Bash `$env:USERPROFILE\...` is
		// not the policy file, so the Windows BLOCK is an over-block; this row
		// pins its receipt, not that decision.
		{"the issue's Bash row: mkfs, then the policy in its Windows spelling", mkfs + "; r" + "m " + policyFileWindowsSpelling(), runtime.GOOS == "windows", "", nil, nil},
		// The issue's control: the managed middleware blocks first, with its
		// own record. Unchanged.
		{"control: mkfs, then the policy in its POSIX spelling", mkfs + "; r" + "m ~/." + "agent" + "shield/policy.yaml", true, "",
			[]string{sp}, []string{"persistence-evasion/defense-evasion/security-tool-tampering"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, configDir := keptReceiptHome(t, "audit-only")
			code, _, stderr := runHookChild(t, home, spBashPayload(tc.cmd))
			e := oneEvent(t, configDir)
			if (code == 2) != tc.block || (e.Decision == "BLOCK") != tc.block {
				t.Fatalf("exit %d, decision %s (original %q) %v; want BLOCK %v", code, e.Decision, e.OriginalDecision, e.TriggeredRules, tc.block)
			}
			if !tc.block {
				if containsStr(e.TriggeredRules, sp) {
					t.Errorf("lowered BLOCK %v names %s", e.TriggeredRules, sp)
				}
				return
			}
			if len(e.TriggeredRules) == 0 || e.TriggeredRules[0] != sp {
				t.Fatalf("receipt rules %v; want them led by %s, the rule the BLOCK stands on", e.TriggeredRules, sp)
			}
			if tc.lead != "" && (len(e.Reasons) == 0 || e.Reasons[0] != tc.lead) {
				t.Errorf("receipt reasons %q; want %q first", e.Reasons, tc.lead)
			}
			if tc.rules != nil && !reflect.DeepEqual(e.TriggeredRules, tc.rules) {
				t.Errorf("receipt rules %v; want %v", e.TriggeredRules, tc.rules)
			}
			if tc.tax != nil && !reflect.DeepEqual(e.TaxonomyRefs, tc.tax) {
				t.Errorf("receipt taxonomy %v; want %v", e.TaxonomyRefs, tc.tax)
			}
			if !strings.Contains(stderr, "Rule: "+sp) {
				t.Errorf("stderr:\n%s\nwant the rules led by %s", stderr, sp)
			}
			// The disable hint names the rule after the record (#3302): no
			// rule disable lifts the keep.
			if len(e.TriggeredRules) > 1 && !strings.Contains(stderr, "rule "+e.TriggeredRules[1]+" cannot be disabled locally") {
				t.Errorf("stderr:\n%s\nwant the hint to name %s", stderr, e.TriggeredRules[1])
			}
		})
	}
}

// A reading that stands only because another reading of the same command was
// kept (keptOnTie): its receipt leads with what kept the other one (#5091
// pass 1, F1 and Codex's third finding). On 7c270ee1 the Bash rows named
// block-rm-root first and no self-protection rule, and the PowerShell row
// led with the managed lane's own message as if the keep had written it; on
// main all three named only the rules that fired. Everything after the lead
// is enforce mode's record.
func TestHook_TiedReadingLeadsWithWhatKeptTheOther_5091(t *testing.T) {
	rmRoot := "/usr/bin/r" + "m -rf /"
	cfgYAML := "${HOME}/.Agent" + "Shield/agentshield.yaml"
	sp := policy.SelfProtectRuleID
	ps := func(home, cmd string) string {
		return claudeShaped(t, "PreToolUse", "PowerShell", routingCmd(cmd), map[string]interface{}{"cwd": home})
	}
	bash := func(_, cmd string) string { return spBashPayload(cmd) }
	for _, tc := range []struct {
		name    string
		managed bool
		cmd     string
		payload func(home, cmd string) string
		// lead is the reason the receipt leads with, off Windows.
		lead string
	}{
		// The case-fold reading alone reads `.AgentShield` as the config
		// directory, and the program-path reading alone reads /usr/bin/rm;
		// the as-written reading's keep cannot split `${HOME}/…` out of the
		// braces. The folded reading is kept by its self-protection rule.
		{"Bash, unmanaged: rm -rf / beside a mixed-case config truncate", false, rmRoot + " || truncate -s 0 " + cfgYAML, bash,
			policy.SelfProtectKeptReasonPrefix + "the command also matches the self-protection rule ts-block-agentshield-log-truncate"},
		{"Bash, managed: the same", true, rmRoot + " || truncate -s 0 " + cfgYAML, bash,
			policy.SelfProtectKeptReasonPrefix + "the command also matches the self-protection rule ts-block-agentshield-log-truncate"},
		// Claude Code's PowerShell row: `$PWD` names the managed config only
		// in the lexical reading (#4830), whose BLOCK is the managed lane's
		// own; the key read's BLOCK is raised for it.
		{"PowerShell, managed: a key read beside a config write through $PWD", true,
			"Get-Content ~/.ssh/id_" + "rsa; Set-Content \"$PWD\\." + "agent" + "shield\\notes.txt\" x", ps,
			policy.SelfProtectKeptReasonPrefix + "the command also names AgentShield's managed configuration and is not a known read (rule: sp-block-config-touch)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := func(mode string) (int, string, eventRecord) {
				home, configDir := newFailSafeHome(t, tc.managed, failSafePolicyGood)
				if err := os.WriteFile(filepath.Join(configDir, "agentshield.yaml"), []byte("mode: "+mode+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				code, _, stderr := runHookChild(t, home, tc.payload(home, tc.cmd))
				e := oneEvent(t, configDir)
				return code, stderr, eventRecord{e.Decision, e.OriginalDecision, e.TriggeredRules, e.Reasons, e.TaxonomyRefs}
			}
			_, _, enf := record("enforce")
			if enf.decision != "BLOCK" || containsStr(enf.rules, sp) {
				t.Fatalf("control: enforce %s %v; want BLOCK on its own rules", enf.decision, enf.rules)
			}
			code, stderr, a := record("audit-only")
			if code != 2 || a.decision != "BLOCK" || a.original != "" {
				t.Fatalf("audit-only exit %d, %s (original %q) %v; want BLOCK, kept", code, a.decision, a.original, a.rules)
			}
			if len(a.rules) < 2 || a.rules[0] != sp || len(a.reasons) == 0 || !strings.HasPrefix(a.reasons[0], policy.SelfProtectKeptReasonPrefix) {
				t.Fatalf("receipt %v %q; want it led by %s and the reason the BLOCK stands", a.rules, a.reasons, sp)
			}
			if runtime.GOOS != "windows" && a.reasons[0] != tc.lead {
				t.Errorf("lead %q; want %q", a.reasons[0], tc.lead)
			}
			if !reflect.DeepEqual(a.rules[1:], enf.rules) || !reflect.DeepEqual(a.reasons[1:], enf.reasons) || !reflect.DeepEqual(a.tax, enf.tax) {
				t.Errorf("receipt after the lead %v %q %v; want enforce mode's %v %q %v", a.rules[1:], a.reasons[1:], a.tax, enf.rules, enf.reasons, enf.tax)
			}
			if !strings.Contains(stderr, "rule "+a.rules[1]+" cannot be disabled locally") && !strings.Contains(stderr, "agentshield rule disable "+a.rules[1]) {
				t.Errorf("stderr:\n%s\nwant the hint to name %s", stderr, a.rules[1])
			}
		})
	}
}

type eventRecord struct {
	decision, original  string
	rules, reasons, tax []string
}

// Enforce mode: the same commands BLOCK on their own rules, and no record
// gains enterprise-self-protect from the keep (the opposite wrong evidence).
func TestHook_EnforceBlockReceiptUnchanged_5089(t *testing.T) {
	mkfs := "mkfs." + "ext4 /dev/sda1"
	for _, cmd := range []string{
		mkfs,
		mkfs + "; r" + "m ~/.cursor/" + "mcp.json",
		mkfs + "; r" + "m " + policyFileWindowsSpelling(),
	} {
		t.Run(cmd, func(t *testing.T) {
			home, configDir := keptReceiptHome(t, "enforce")
			code, _, stderr := runHookChild(t, home, spBashPayload(cmd))
			e := oneEvent(t, configDir)
			if code != 2 || e.Decision != "BLOCK" || !reflect.DeepEqual(e.TriggeredRules, []string{"ts-block-mkfs"}) {
				t.Errorf("exit %d, %s %v; want BLOCK [ts-block-mkfs] only. stderr:\n%s", code, e.Decision, e.TriggeredRules, stderr)
			}
		})
	}
}
