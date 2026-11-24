package analyzer_test

import (
	"os"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// TestTeeWriteTwins runs the tee forms of two writes through the engine as the
// hook does (#4966). On main the pipe and redirect forms of these writes
// BLOCK and the forms below decided AUDIT:
//
//   - tee into /etc/sudoers or /etc/sudoers.d/, fed by a here-string, a heredoc
//     or a file (the pack rule ts-block-sudoers-write knew tee only after a
//     pipe or with a redirect);
//   - tee into a cron spool file, in any form (the engine's
//     df-block-write-cron-spool read redirects only).
//
// The silent rows are the reason both twins read tee at a command position:
// text that mentions the command, or a path inside a here-string body, is not
// a write.
func TestTeeWriteTwins(t *testing.T) {
	const sudoers, cron = "ts-block-sudoers-write", "df-block-write-cron-spool"
	pol := loadTestPolicy(t)

	// The sudoers pattern must stay free of the two anchor characters: with
	// either one the engine treats the rule as position-bound and drops its
	// whole-command reading (#4968). Start of text is written \A.
	pattern := ""
	for i := range pol.Rules {
		if pol.Rules[i].ID == sudoers {
			pattern = pol.Rules[i].Match.CommandRegex
		}
	}
	if pattern == "" {
		t.Fatalf("rule %s not found in the loaded packs", sudoers)
	}
	if strings.ContainsAny(pattern, "^$") {
		t.Errorf("the pattern of %s contains ^ or $; write the start of text as \\A and classes as positive sets:\n%s", sudoers, pattern)
	}

	engine, err := policy.NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		cmd   string
		rule  string
		fires bool
	}{
		// Controls: the forms main already blocks.
		{"sudoers: pipe into tee", `echo 'dev ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers`, sudoers, true},
		{"cron: redirect", `echo '* * * * * root /tmp/job.sh' > /etc/cron.d/sync`, cron, true},
		// The twins.
		{"sudoers: tee fed by a here-string", `sudo tee -a /etc/sudoers <<< 'dev ALL=(ALL) NOPASSWD:ALL'`, sudoers, true},
		{"sudoers.d: tee fed by a here-string", `sudo tee /etc/sudoers.d/dev <<< 'dev ALL=(ALL) NOPASSWD:ALL'`, sudoers, true},
		{"sudoers.d: tee fed by a heredoc", "sudo tee /etc/sudoers.d/dev <<'EOF'\ndev ALL=(ALL) NOPASSWD:ALL\nEOF", sudoers, true},
		{"sudoers: tee fed by a file", `sudo tee -a /etc/sudoers < /tmp/line`, sudoers, true},
		{"sudoers.d: after another statement, tee by its path", `cd /tmp && sudo -n /usr/bin/tee /etc/sudoers.d/dev < line`, sudoers, true},
		{"cron.d: pipe into tee", `echo '* * * * * root /tmp/job.sh' | sudo tee /etc/cron.d/sync`, cron, true},
		{"crontab: pipe into tee -a", `echo '* * * * * root /tmp/job.sh' | sudo tee -a /etc/crontab`, cron, true},
		{"cron.d: tee fed by a heredoc", "sudo tee /etc/cron.d/sync <<'EOF'\n* * * * * root /tmp/job.sh\nEOF", cron, true},
		{"cron.d: tee fed by a here-string", `sudo tee /etc/cron.d/sync <<< '* * * * * root /tmp/job.sh'`, cron, true},
		// Not writes to those files.
		{"sudoers: prose that mentions the command", `echo "to add a rule, run sudo tee /etc/sudoers.d/dev and paste the line"`, sudoers, false},
		{"sudoers: the path is text in a here-string", `tee /tmp/notes.txt <<< "the file is /etc/sudoers"`, sudoers, false},
		{"cron: the path is text in a here-string", `tee /tmp/notes.txt <<< "jobs live in /etc/cron.d/sync"`, cron, false},
		{"cron: a read of the cron file into tee", `cat /etc/cron.d/sync | tee /tmp/copy`, cron, false},
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
			if c.fires && (res.Decision != policy.DecisionBlock || !named) {
				t.Fatalf("want BLOCK by %s, got %s %v", c.rule, res.Decision, res.TriggeredRules)
			}
			if !c.fires && named {
				t.Fatalf("want %s silent, got %s %v", c.rule, res.Decision, res.TriggeredRules)
			}
		})
	}
}
