package enterprise

import (
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// setupDisableRow is one matchesSetupDisable expectation.
type setupDisableRow struct {
	name string
	cmd  string
	want bool
}

// setupDisableRows is TestMatchesSetupDisable's table. The zsh twins in
// setup_disable_zsh_4631_test.go are derived from it, so a row added here is
// also checked behind a zsh-only statement.
var setupDisableRows = []setupDisableRow{
	{"original order", "agentshield setup mcp --disable", true},
	{"remove-managed", "agentshield setup claude-code --remove-managed", true},
	{"remove-managed under sudo", "sudo agentshield setup claude-code --remove-managed", true},
	{"remove-managed before surface", "agentshield setup --remove-managed claude-code", true},
	{"remove-managed true", "agentshield setup claude-code --remove-managed=true", true},
	{"remove-managed path", "/opt/homebrew/bin/agentshield setup claude-code --remove-managed", true},
	{"remove-managed false", "agentshield setup claude-code --remove-managed=false", false},
	{"remove-managed invalid bool", "agentshield setup claude-code --remove-managed=yes", false},
	{"write-managed is not removal", "agentshield setup claude-code --write-managed --on-failure-block", false},
	{"managed snippet is not removal", "agentshield setup claude-code --managed", false},
	{"remove-managed mentioned, not run", "grep -n -- --remove-managed README.md", false},
	{"remove-managed on another program", "otherprog setup claude-code --remove-managed", false},
	{"between surface and flag", "agentshield setup mcp --mode=enforce --disable", true},
	{"empty argument before setup", "agentshield '' setup mcp --mode=enforce --disable", true},
	{"before surface", "agentshield setup --disable mcp", true},
	{"before setup", "agentshield --disable setup mcp", true},
	{"value flag before setup", "agentshield --mode enforce setup mcp --disable", true},
	{"value flag before disable", "agentshield setup mcp --target cursor --disable", true},
	{"root discovery consumes false before leaf bool parsing", "agentshield --disable false setup mcp", true},
	{"bare bool followed by false", "agentshield setup --disable false", true},
	{"false before setup", "agentshield --disable=false setup mcp", false},
	{"false with empty argument", "agentshield '' setup mcp --mode=enforce --disable=false", false},
	{"disable is root flag value", "agentshield --log --disable setup mcp --disable=false", false},
	{"false", "agentshield setup mcp --disable=false", false},
	{"invalid bool", "agentshield setup mcp --disable=yes", false},
	{"empty bool", "agentshield setup mcp --disable=", false},
	{"absolute path", "/opt/bin/agentshield setup --disable mcp", true},
	{"relative path", "./bin/agentshield setup --disable mcp", true},
	{"home path", "~/bin/agentshield setup --disable mcp", true},
	{"quoted path", `"/opt/Agent Shield/agentshield" setup --disable mcp`, true},
	{"quoted argv", `agentshield 'setup' mcp '--disable=true'`, true},
	{"quote splices", "agent'shield' se'tup' mcp --mode=enforce --disa'ble'", true},
	{"unset splices", "agentshield se${zqx}tup mcp --mode=enforce --disa${zqx}ble", true},
	{"default setup", "agentshield ${zqx:-setup} --disable mcp", true},
	{"second command", "echo ready; agentshield setup --disable mcp", true},
	{"pipeline", "printf x | agentshield setup --disable mcp", true},
	{"conditional", "true && agentshield setup --disable mcp", true},
	{"subshell", "(agentshield setup --disable mcp)", true},
	{"substitution", "echo $(agentshield setup --disable mcp)", true},
	{"wrapper", "env agentshield setup --disable mcp", true},
	{"no flag", "agentshield setup mcp", false},
	{"different subcommand", "agentshield status --disable", false},
	{"setup operand", "agentshield status setup --disable", false},
	{"setup as flag value", "agentshield --log setup status --disable", false},
	{"disable as flag value", "agentshield setup mcp --mode --disable", false},
	{"disable as target", "agentshield setup mcp --target --disable", false},
	{"different binary", "other-agentshield setup --disable mcp", false},
	{"directory", "/opt/agentshield/ setup --disable mcp", false},
	{"inert text", "echo 'agentshield setup --disable mcp'", false},
	{"search text", "rg 'agentshield setup --disable mcp' README.md", false},
	{"flag prefix", "agentshield setup --disabled mcp", false},
	{"flag terminator", "agentshield setup mcp -- --disable", false},
	{"flag before terminator", "agentshield setup --disable mcp -- --disable=false", true},
	{"flag in another command", "agentshield setup mcp; echo --disable", false},
	{"setup in another command", "echo setup; agentshield status --disable", false},
	{"comment", "agentshield setup mcp # --disable", false},
	// Neither parser accepts these, so no argv reading exists and the
	// token scan decides: an agentshield word followed by a setup word
	// matches (#4631, part 2). They were no-match rows before #4631.
	{"unparseable", "agentshield setup --disable mcp '", true},
	{"unparseable with substitution prefix", "echo $(agentshield setup --disable mcp)\n'", true},
}

func TestMatchesSetupDisable(t *testing.T) {
	for _, tt := range setupDisableRows {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesSetupDisable(tt.cmd); got != tt.want {
				t.Errorf("matchesSetupDisable(%q) = %v, want %v", tt.cmd, got, tt.want)
			}
		})
	}

	// All spellings accepted by strconv.ParseBool, which pflag uses for bools.
	for _, value := range []string{"1", "t", "T", "TRUE", "true", "True", "0", "f", "F", "FALSE", "false", "False"} {
		t.Run("bool="+value, func(t *testing.T) {
			want, err := strconv.ParseBool(value)
			if err != nil {
				t.Fatal(err)
			}
			cmd := "agentshield setup --disable=" + value + " mcp"
			if got := matchesSetupDisable(cmd); got != want {
				t.Errorf("matchesSetupDisable(%q) = %v, want %v", cmd, got, want)
			}
		})
	}
}

// A statically quoted executable path holding a literal `$` or backtick was an
// accepted residual (Gary, 2026-10-26, #4575 pass 2); #4577 closed it. The
// negative rows keep the reading from widening past one quoted span.
func TestSetupDisable_QuotedExecutableWord_4577(t *testing.T) {
	rows := []struct {
		cmd  string
		want bool
	}{
		{"'/tmp/$/agentshield' setup mcp --mode=enforce --disable", true},
		{"'/tmp/a`b/agentshield' setup mcp --disable", true},
		{`"/tmp/\$/agentshield" setup mcp --disable`, true},
		{"\"/tmp/a\\`b/agentshield\" setup mcp --disable", true},
		{"'/tmp/$/agentshield' setup mcp --disable=true", true},
		{"'/tmp/$/agentshield' setup mcp --mode=enforce", false},
		{"'/tmp/$/agentshield' status --disable", false},
		{"'/tmp/$/notagentshield' setup mcp --disable", false},
		{"'/tmp/$/agentshield/' setup mcp --disable", false},
	}
	for _, r := range rows {
		if got := matchesSetupDisable(r.cmd); got != r.want {
			t.Errorf("matchesSetupDisable(%q) = %v, want %v", r.cmd, got, r.want)
		}
		if r.want {
			if id, matched := matchesSelfProtectRule(r.cmd); !matched || id != "sp-block-setup-disable" {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, %v), want sp-block-setup-disable", r.cmd, id, matched)
			}
		}
	}
}

// setupDisableDiscoveryRow is one TestMatchesSetupDisable_Discovery row.
type setupDisableDiscoveryRow struct {
	name      string
	prefix    []string // argv before mcp --mode=enforce --disable
	discovery bool
	match     bool
}

// args is the row's argv after the binary.
func (r setupDisableDiscoveryRow) args() []string {
	return append(append([]string(nil), r.prefix...), "mcp", "--mode=enforce", "--disable")
}

// cmd is the row's command, every argv word single-quoted.
func (r setupDisableDiscoveryRow) cmd() string {
	return "agentshield '" + strings.Join(r.args(), "' '") + "'"
}

// setupDisableDiscoveryRows is TestMatchesSetupDisable_Discovery's table; the
// zsh twins (#4631) are derived from it too.
var setupDisableDiscoveryRows = []setupDisableDiscoveryRow{
	{"empty", []string{"", "setup"}, true, true},
	{"multiple empty", []string{"", "", "setup"}, true, true},
	{"lone dash", []string{"-", "setup"}, true, true},
	{"empty and dash", []string{"", "-", "setup"}, true, true},
	{"policy value", []string{"--policy", "policy.yaml", "setup"}, true, true},
	{"log value", []string{"--log", "audit.jsonl", "setup"}, true, true},
	{"mode value", []string{"--mode", "enforce", "setup"}, true, true},
	{"policy equals", []string{"--policy=setup", "setup"}, true, true},
	{"log equals", []string{"--log=setup", "setup"}, true, true},
	{"mode equals", []string{"--mode=enforce", "setup"}, true, true},
	{"empty value", []string{"--policy", "", "setup"}, true, true},
	{"dash value", []string{"--log", "-", "setup"}, true, true},
	{"terminator value", []string{"--policy", "--", "setup"}, true, true},
	{"disable value", []string{"--log", "--disable", "setup"}, true, true},
	{"setup is policy value", []string{"--policy", "setup"}, false, false},
	{"setup is log value", []string{"--log", "setup"}, false, false},
	{"setup is mode value", []string{"--mode", "setup"}, false, false},
	{"unknown long value", []string{"--unknown", "value", "setup"}, true, true},
	{"unknown long equals", []string{"--unknown=value", "setup"}, true, true},
	{"unknown short value", []string{"-x", "value", "setup"}, true, true},
	{"short equals", []string{"-x=value", "setup"}, true, true},
	{"short cluster", []string{"-xyz", "setup"}, true, true},
	{"help equals false", []string{"--help=false", "setup"}, true, true},
	{"short help equals false", []string{"-h=false", "setup"}, true, true},
	{"unknown disable consumes false", []string{"--disable", "false", "setup"}, true, true},
	// Discovery consumes setup as these unknown flags' values. Keep the
	// earlier conservative argv matches even though Cobra rejects them.
	{"unknown long consumes setup", []string{"--unknown", "setup"}, false, true},
	{"unknown short consumes setup", []string{"-x", "setup"}, false, true},
	{"disable before setup", []string{"--disable", "setup"}, false, true},
	{"help before setup", []string{"--help", "setup"}, false, true},
	{"short help before setup", []string{"-h", "setup"}, false, true},
	{"terminator", []string{"--", "setup"}, false, false},
	{"first operand wins", []string{"status", "setup"}, false, false},
	{"whitespace operand", []string{" ", "setup"}, false, false},
	{"case sensitive", []string{"Setup"}, false, false},
	{"no prefix matching", []string{"set"}, false, false},
}

func TestMatchesSetupDisable_Discovery(t *testing.T) {
	for _, tt := range setupDisableDiscoveryRows {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args()
			// Mirror internal/cli/root.go's flag definitions and use the actual
			// dependency as a discovery oracle, without executing any handler.
			root := &cobra.Command{Use: "agentshield"}
			for _, name := range []string{"policy", "log", "mode"} {
				root.PersistentFlags().String(name, "", "")
			}
			setup := &cobra.Command{Use: "setup"}
			mcp := &cobra.Command{Use: "mcp"}
			mcp.Flags().Bool("disable", false, "")
			mcp.Flags().String("target", "all", "")
			root.AddCommand(setup, &cobra.Command{Use: "status"})
			setup.AddCommand(mcp)
			found, _, _ := root.Find(args)
			if got := found == setup || found == mcp; got != tt.discovery {
				t.Fatalf("Cobra Find(%q) under setup = %v, want %v", args, got, tt.discovery)
			}
			if got := setupDisableRootIsSetup(args); got != tt.discovery {
				t.Errorf("setupDisableRootIsSetup(%q) = %v, want %v", args, got, tt.discovery)
			}
			cmd := tt.cmd()
			if got := matchesSetupDisable(cmd); got != tt.match {
				t.Errorf("matchesSetupDisable(%q) = %v, want %v", cmd, got, tt.match)
			}
		})
	}
}

func TestSelfProtect_SetupDisable_RegexORParsed(t *testing.T) {
	for _, cmd := range []string{
		"agentshield setup mcp --mode=enforce --disable",    // parsed reading
		"agentshield '' setup mcp --mode=enforce --disable", // empty argv discovery regression
		"agentshield se'tup' mcp --mode=enforce --disable",
		"agentshield se${zqx}tup mcp --mode=enforce --disable",
		"agentshield se't'${zqx}up mcp --mode=enforce --disable",
		"agentshield setup mcp --disable=false", // legacy regex still wins
		"agentshield setup mcp --disable=invalid",
		"echo 'agentshield setup mcp --disable'",
		"agentshield setup mcp --disable '", // parse failure retains regex
		// Neither parser accepts it, so the token scan decides (#4631 part 2);
		// it was a no-match row before #4631.
		"agentshield setup mcp --mode=enforce --disable '",
	} {
		t.Run(cmd, func(t *testing.T) {
			if id, matched := matchesSelfProtectRule(cmd); !matched || id != "sp-block-setup-disable" {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, %v), want (sp-block-setup-disable, true)", cmd, id, matched)
			}
		})
	}
	for _, cmd := range []string{
		"agentshield setup --disable=false mcp",
		"agentshield setup mcp --mode=enforce --disable=false",
		"agentshield status --disable",
		"agentshield setup mcp -- --disable",
		"echo 'agentshield setup --disable mcp'",
	} {
		t.Run(cmd, func(t *testing.T) {
			if id, matched := matchesSelfProtectRule(cmd); matched {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, true), want no match", cmd, id)
			}
		})
	}
}

// Run against the unchanged matcher before the fix: the old regex misses a
// valid persistent flag between the setup surface and --disable (#4565).
func TestSelfProtect_SetupDisable_ReorderedFlagParity(t *testing.T) {
	const cmd = "agentshield setup mcp --mode=enforce --disable"
	for _, rule := range selfProtectRules {
		if rule.ID == "sp-block-setup-disable" && rule.Pattern.MatchString(cmd) {
			t.Fatal("parity command unexpectedly matches the main regex")
		}
	}
	if id, matched := matchesSelfProtectRule(cmd); !matched || id != "sp-block-setup-disable" {
		t.Fatalf("matchesSelfProtectRule(%q) = (%q, %v), want (sp-block-setup-disable, true)", cmd, id, matched)
	}
}
