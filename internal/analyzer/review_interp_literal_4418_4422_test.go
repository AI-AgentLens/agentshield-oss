package analyzer_test

// Adversarial review of Shield #4418 / #4422 (pass 1, 2026-10-19).
//
// Kept OUT of TestPrivateAliasTmpIsABudgetedGap's sweep on purpose: that sweep
// reads inline pack TPs and testdata.AllTestCases(), never this table.
//
// TestInterpReview4418_AuthorExecGuards is the guard the #4418 author asked for: the
// os.system("...") literal shape and the indirected `cmd = "..."; os.system(cmd)`
// shape for both home-redirect rules, plus the #4422 adb TP shape. Each must
// BLOCK and name the rule.
//
// TestInterpReview4418_ExecChannelsOutsideAllowlist holds bodies that hand the literal
// to a shell or a process through a call hasExecCall does not recognise. Each
// BLOCKs on main via the named rule; a failure here on a branch is a decision
// lowered by the new interp_heredoc_literal exclusion.

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

type reviewCase struct {
	name string
	rule string
	cmd  string
}

func runReviewCases(t *testing.T, cases []reviewCase) {
	t.Helper()
	engine, err := policy.NewEngineWithAnalyzers(interpReviewPolicy(t), 2)
	if err != nil { t.Fatal(err) }
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			n := normalize.NormalizeCommand(c.cmd, "")
			res := engine.EvaluateWithParsed(c.cmd, n.Paths, n.Parsed)
			named := false
			for _, r := range res.TriggeredRules {
				if r == c.rule {
					named = true
				}
			}
			t.Logf("decision=%s rules=%s", res.Decision, strings.Join(res.TriggeredRules, ","))
			if string(res.Decision) != "BLOCK" || !named {
				t.Errorf("want BLOCK by %s, got %s %v", c.rule, res.Decision, res.TriggeredRules)
			}
		})
	}
}

func TestInterpReview4418_AuthorExecGuards(t *testing.T) {
	runReviewCases(t, []reviewCase{
		{"home/os.system-literal", "ts-block-home-redirect",
			"python3 - <<'PY'\nimport os\nos.system(\"export HOME=/tmp/x\")\nPY"},
		{"home/os.system-indirect", "ts-block-home-redirect",
			"python3 - <<'PY'\nimport os\ncmd = \"export HOME=/tmp/x\"\nos.system(cmd)\nPY"},
		{"inline/os.system-literal", "ts-block-home-redirect-inline",
			"python3 - <<'PY'\nimport os\nos.system(\"HOME=/tmp/x ssh host\")\nPY"},
		{"inline/os.system-indirect", "ts-block-home-redirect-inline",
			"python3 - <<'PY'\nimport os\ncmd = \"HOME=/tmp/x ssh host\"\nos.system(cmd)\nPY"},
		{"adb/subprocess.run-shell", "ts-block-adb-am-start-shell-injection",
			"python3 - <<'PY'\nimport subprocess\nsubprocess.run(\"adb shell am start -a android.intent.action.VIEW -d http://x.com;id\", shell=True)\nPY"},
		{"adb/os.system-indirect", "ts-block-adb-am-start-shell-injection",
			"python3 - <<'PY'\nimport os\ncmd = \"adb shell am start -a android.intent.action.VIEW -d http://x.com;id\"\nos.system(cmd)\nPY"},
	})
}

func TestInterpReview4418_ExecChannelsOutsideAllowlist(t *testing.T) {
	const adb = "adb shell am start -a android.intent.action.VIEW -d http://x.com;id"
	runReviewCases(t, []reviewCase{
		// A recognised call whose name is masked by a stray apostrophe: the
		// quotedLiteralRe span opens at `don't` and closes at `that's`.
		{"inline/comment-apostrophe-masks-os.system", "ts-block-home-redirect-inline",
			"python3 - <<'PY'\nimport os\n# don't log the output\nos.system(\"HOME=/tmp/x ssh host\")\n# that's it\nPY"},
		{"adb/comment-apostrophe-masks-os.system", "ts-block-adb-am-start-shell-injection",
			"python3 - <<'PY'\nimport os\n# don't wait for the activity\nos.system(\"" + adb + "\")\n# that's all\nPY"},
		// Python stdlib shell/process calls outside the allowlist.
		{"inline/os.popen", "ts-block-home-redirect-inline",
			"python3 - <<'PY'\nimport os\nprint(os.popen(\"HOME=/tmp/x ssh host\").read())\nPY"},
		{"inline/subprocess.getoutput", "ts-block-home-redirect-inline",
			"python3 - <<'PY'\nimport subprocess\nprint(subprocess.getoutput(\"HOME=/tmp/x git push\"))\nPY"},
		{"inline/from-subprocess-import-run", "ts-block-home-redirect-inline",
			"python3 - <<'PY'\nfrom subprocess import run\nrun(\"HOME=/tmp/x ssh host\", shell=True)\nPY"},
		{"inline/import-subprocess-as-sp", "ts-block-home-redirect-inline",
			"python3 - <<'PY'\nimport subprocess as sp\nsp.run(\"HOME=/tmp/x ssh host\", shell=True)\nPY"},
		{"home/from-os-import-system", "ts-block-home-redirect",
			"python3 - <<'PY'\nfrom os import system\nsystem(\"export HOME=/tmp/x\")\nPY"},
		{"inline/os.execl-sh-c", "ts-block-home-redirect-inline",
			"python3 - <<'PY'\nimport os\nos.execl(\"/bin/sh\", \"sh\", \"-c\", \"HOME=/tmp/x ssh host\")\nPY"},
		{"adb/os.popen", "ts-block-adb-am-start-shell-injection",
			"python3 - <<'PY'\nimport os\nprint(os.popen(\"" + adb + "\").read())\nPY"},
		{"adb/subprocess.getoutput", "ts-block-adb-am-start-shell-injection",
			"python3 - <<'PY'\nimport subprocess\nprint(subprocess.getoutput(\"" + adb + "\"))\nPY"},
		{"adb/from-subprocess-import-check_output", "ts-block-adb-am-start-shell-injection",
			"python3 - <<'PY'\nfrom subprocess import check_output\ncheck_output(\"" + adb + "\", shell=True)\nPY"},
		// Node: the require(...) idioms; the literal 'child_process' is masked.
		{"inline/node-require-execSync", "ts-block-home-redirect-inline",
			"node - <<'JS'\nrequire(\"child_process\").execSync(\"HOME=/tmp/x ssh host\", { stdio: \"inherit\" });\nJS"},
		{"inline/node-destructured-execSync", "ts-block-home-redirect-inline",
			"node - <<'JS'\nconst { execSync } = require(\"child_process\");\nexecSync(\"export HOME=/tmp/x; ssh host\");\nJS"},
		{"adb/node-require-execSync", "ts-block-adb-am-start-shell-injection",
			"node - <<'JS'\nrequire(\"child_process\").execSync(\"" + adb + "\");\nJS"},
		// Ruby / Perl: system and exec without parentheses.
		{"inline/ruby-system-no-parens", "ts-block-home-redirect-inline",
			"ruby <<'RB'\nsystem \"HOME=/tmp/x ssh host\"\nRB"},
		{"inline/perl-system-no-parens", "ts-block-home-redirect-inline",
			"perl <<'PL'\nsystem \"HOME=/tmp/x ssh host\";\nPL"},
		// Deferred execution: the literal is written to a shell startup file.
		{"home/python-appends-to-bashrc", "ts-block-home-redirect",
			"python3 - <<'PY'\nimport os\nopen(os.path.expanduser(\"~/.bashrc\"), \"a\").write(\"export HOME=/tmp/x\\n\")\nPY"},
	})
}
