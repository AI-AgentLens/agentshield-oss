package cli

import (
	"sort"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/spf13/cobra"
)

// agentshieldSubcommandIsRead classifies every agentshield command path for
// the plain-read exemption (#4845). true: it prints or evaluates and changes
// neither the managed config nor what is enforced, so `agentshield <path>
// <config file>` is a plain read, as `cat <config file>` is. false: it writes
// a file, starts a program or talks to the SaaS. A new subcommand fails
// TestPlainRead_AgentshieldSubcommands_4845 until it has a row here.
var agentshieldSubcommandIsRead = map[string]bool{
	"version":           true,  // prints the build
	"status":            true,  // reads the config, credentials and hooks, runs a fixed `launchctl list`; prints
	"log":               true,  // reads the audit log; prints
	"check":             true,  // evaluates a command or a fixture; prints (never runs it)
	"mcp-eval":          true,  // evaluates a simulated tool call; prints
	"pack list":         true,  // lists the packs directory (creates it empty if absent)
	"pack show":         true,  // prints one pack
	"rule list":         true,  // prints the rules
	"pack":              false, // not runnable; its other children write
	"pack enable":       false, // renames a pack file
	"pack disable":      false,
	"rule":              false, // not runnable; its other children write
	"rule allow":        false, // rewrites policy.yaml
	"rule disable":      false,
	"audit-flush":       false, // sends queued events to the SaaS
	"connect":           false, // writes credentials
	"login":             false,
	"logout":            false, // deletes credentials
	"hook":              false, // writes the audit log, uploads events
	"mcp-proxy":         false, // starts the server command it is given
	"mcp-http-proxy":    false, // runs a proxy server
	"pause":             false, // writes the pause state
	"resume":            false,
	"ping":              false, // posts a heartbeat
	"scan":              false, // self-test that calls the SaaS
	"setup":             false, // writes hook and MCP configs
	"setup claude-code": false,
	"setup codex":       false,
	"setup copilot-cli": false,
	"setup cursor":      false,
	"setup gemini-cli":  false,
	"setup mcp":         false,
	"setup openclaw":    false,
	"setup windsurf":    false,
	"update":            false, // replaces the binary
	"watchdog":          false, // re-installs hooks
}

// TestPlainRead_AgentshieldSubcommands_4845 walks the real command tree: every
// command path (and alias) is classified, the classification names no command
// that does not exist, and the shared plain-read regex exempts exactly the
// read-only paths, with a config file as their argument. On main every row
// was exempt, so `agentshield mcp-proxy -- sed -i … <policy>` passed both
// layers that exempt a plain read on a managed host.
func TestPlainRead_AgentshieldSubcommands_4845(t *testing.T) {
	cfg := "~/.agent" + "shield/policy.yaml"
	seen := map[string]bool{}
	var walk func(c *cobra.Command, path []string)
	walk = func(c *cobra.Command, path []string) {
		for _, sub := range c.Commands() {
			if sub.Name() == "help" || sub.Name() == "completion" {
				continue // cobra's own, checked below
			}
			p := append(append([]string{}, path...), sub.Name())
			key := strings.Join(p, " ")
			seen[key] = true
			isRead, ok := agentshieldSubcommandIsRead[key]
			if !ok {
				t.Errorf("agentshield %s is not classified: add it to agentshieldSubcommandIsRead (true only if it neither writes nor runs anything)", key)
			}
			for _, name := range append([]string{sub.Name()}, sub.Aliases...) {
				words := append(append([]string{}, path...), name)
				cmd := "agentshield " + strings.Join(words, " ") + " " + cfg
				if got := enterprise.IsPlainConfigRead(cmd); got != (ok && isRead) {
					t.Errorf("%q: plain read %v, want %v", cmd, got, ok && isRead)
				}
			}
			walk(sub, p)
		}
	}
	walk(rootCmd, nil)
	var phantom []string
	for key := range agentshieldSubcommandIsRead {
		if !seen[key] {
			phantom = append(phantom, key)
		}
	}
	sort.Strings(phantom)
	if len(phantom) > 0 {
		t.Errorf("classified paths that are not agentshield commands: %v", phantom)
	}

	for _, r := range []struct {
		cmd  string
		read bool
	}{
		{"agentshield status", true},
		{"sudo agentshield status " + cfg, true},
		{"agentshield\tpack\tshow x " + cfg, true},
		{"agentshield " + cfg, false},
		{"agentshield --log " + cfg + " status", false}, // a flag first
		{"agentshield statusx " + cfg, false},
		{"agentshield help " + cfg, false},
		{"agentshield completion bash " + cfg, false},
		{"agentshield mcp-proxy -- sed -i s/BLOCK/AUDIT/ " + cfg, false},
		{"agentshield status; rm " + cfg, false},
		{"agentshield status\nrm " + cfg, false},
		{"agentshield\nstatus " + cfg, false}, // words are split by blanks only, never a newline
		{"agentshield pack\nlist " + cfg, false},
	} {
		if got := enterprise.IsPlainConfigRead(r.cmd); got != r.read {
			t.Errorf("%q: plain read %v, want %v", r.cmd, got, r.read)
		}
	}
}

// TestManagedPlainRead_AgentshieldMCPProxy_4845: on a managed host a config
// write behind `agentshield mcp-proxy --` BLOCKs through the Bash tool, as
// the write alone does. On main it exited 0 (AUDIT,
// ts-audit-agentshield-log-modify): both layers read the whole word list as a
// plain read. The control: a read-only subcommand naming the config still
// exits 0. Attack strings are assembled at runtime: the hook reads test
// sources as commands (dogfooding).
func TestManagedPlainRead_AgentshieldMCPProxy_4845(t *testing.T) {
	cfg := "~/.agent" + "shield/policy.yaml"
	edit := "sed -i 's/BLOCK/AUDIT/' " + cfg
	for _, r := range []struct {
		name, cmd string
		want      int
	}{
		{"control write alone", edit, 2},
		{"mcp-proxy write", "agentshield mcp-proxy -- " + edit, 2},
		{"mcp-proxy truncate", "agentshield mcp-proxy -- truncate -s 0 " + cfg, 2},
		{"setup with the config", "agentshield setup claude-code " + cfg, 2},
		{"control check reads the config", "agentshield check --policy " + cfg + " --shell ls", 0},
	} {
		for _, row := range []string{"claude-code Bash", "copilot native bash"} {
			t.Run(r.name+"/"+row, func(t *testing.T) {
				home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
				payload := claudeShaped(t, "PreToolUse", "Bash", routingCmd(r.cmd), nil)
				if row != "claude-code Bash" {
					payload = copilotNativePayload(t, "plainread", "bash", shellArgs(r.cmd))
				}
				code, _, stderr := runHookChild(t, home, payload)
				if code != r.want {
					t.Fatalf("%q exits %d, want %d. stderr:\n%s", r.cmd, code, r.want, stderr)
				}
				if r.want == 2 {
					if e := oneEvent(t, configDir); e.Decision != "BLOCK" {
						t.Errorf("event decision %q rules %v, want BLOCK", e.Decision, e.TriggeredRules)
					}
				}
			})
		}
	}
}
