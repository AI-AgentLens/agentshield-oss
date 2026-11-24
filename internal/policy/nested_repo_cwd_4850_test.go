package policy

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
	"github.com/AI-AgentLens/agentshield/internal/testhome"
)

const nestedRepoRuleID = "ts-audit-git-cd-nested-repo-hook-detonation"

// nestedRepoRows are the #4850 table: does the shipped rule attest
// "embedded bare repository hook execution" for this call? It should when git
// runs in a directory under the call's cwd (the node's nested shape), and not
// for work in another repository, which was 206 of its 223 receipts on the
// dev Mac. Every doubt keeps main's match.
var nestedRepoRows = []struct {
	cmd, cwd string
	fires    bool
	why      string
}{
	{"cd examples/fixtures && git add -A && git commit -m 'update fixtures'", "/Users/u/dev/app", true, "relative subdirectory (the rule's TP)"},
	{"git -C vendor/widget-lib checkout main", "/Users/u/dev/app", true, "git -C under cwd"},
	{"cd /Users/u/dev/app/examples && git commit -m x", "/Users/u/dev/app", true, "absolute under cwd: Claude Code's usual spelling"},
	{"cd ~/dev/app/sub && git pull", "/Users/u/dev/app", true, "tilde under cwd"},
	{"cd /Users/u/dev/app && cd examples && git commit -m x", "/Users/u/dev/app", true, "a later cd names the nested directory"},
	{"cd ~/dev/other && git pull; cd sub && g'i't commit -m x", "/Users/u/dev/app", true, "the nested statement only the dequoted form reads"},
	{"cd $REPO/sub && git commit -m x", "/Users/u/dev/app", true, "unresolvable directory keeps main's match"},
	{"cd /tmp/repo/sub && git commit -m x", "/private/tmp/repo", true, "macOS /private alias"},
	{"cd /Users/u/dev/other && git commit -m x", "", true, "no cwd keeps main's match"},
	// Opus pass 1, finding 1: something between the directory word and git
	// moves git, so the word does not say where git runs. Main's match kept.
	{`cd /Users/u/dev/app && cd "my dir" && git commit -m x`, "/Users/u/dev/app", true, "a second cd, quoted with a space"},
	{`cd /Users/u/dev/app && cd my\ dir && git commit -m x`, "/Users/u/dev/app", true, "a second cd, escaped space"},
	{`cd /Users/u/dev/app && git -C "my dir" commit -m x`, "/Users/u/dev/app", true, "git -C quoted with a space"},
	{"cd /Users/u/dev/app && git -C vendor/lib -c user.name=k commit -m x", "/Users/u/dev/app", true, "git -C, then a global option"},
	{"cd /Users/u/dev/app && git -C sub --no-pager pull", "/Users/u/dev/app", true, "git -C, then --no-pager"},
	{"cd /Users/u/dev/app && git --git-dir=sub/.git --work-tree=sub commit -m x", "/Users/u/dev/app", true, "git pointed at a planted repo"},
	{"cd /Users/u/dev/app && git --git-dir=sub/.git commit -m x", "/Users/u/dev/app", true, "--git-dir alone"},
	{"cd /Users/u/dev/app && export GIT_DIR=sub/.git && git commit -m x", "/Users/u/dev/app", true, "GIT_DIR exported between"},
	{"cd /Users/u/dev/app && pushd sub && git commit -m x", "/Users/u/dev/app", true, "pushd"},
	{"cd /Users/u/dev/app && cd sub 2>/dev/null && git commit -m x", "/Users/u/dev/app", true, "a second cd with a redirect"},
	{"cd /Users/u/dev/app && cd sub || exit 1 && git commit -m x", "/Users/u/dev/app", true, "a second cd, || exit"},
	{"cd /Users/u/dev/app && cd -P sub && git commit -m x", "/Users/u/dev/app", true, "cd -P"},
	{"cd /Users/u/dev/app && cd $(git rev-parse --show-toplevel)/sub && git commit -m x", "/Users/u/dev/app", true, "a cd through a substitution"},
	{`cd ~/dev/other && cd "/Users/u/dev/app/my dir" && git commit -m x`, "/Users/u/dev/app", true, "another repo, then a quoted nested dir"},
	// Opus pass 1, finding 2: Claude Code on Windows runs Git Bash.
	{"cd /c/Users/u/dev/app/sub && git commit -m x", `C:\Users\u\dev\app`, true, "Git Bash drive spelling"},
	{"git -C /c/Users/u/dev/app/sub pull", `C:\Users\u\dev\app`, true, "Git Bash drive spelling, git -C"},
	{"cd /cygdrive/c/Users/u/dev/app/sub && git pull", `C:\Users\u\dev\app`, true, "Cygwin drive spelling"},
	{"cd /c/Users/u/dev/other && git commit -m x", `C:\Users\u\dev\app`, false, "Git Bash drive spelling of another repo"},
	// Follow-up 1: a cwd outside the engine's home is another machine's
	// (shield-server), so its ~ is not this home.
	{"cd ~/dev/app/sub && git commit -m x", "/home/client/dev/app", true, "remote client: ~ unresolved"},
	{"cd /x/sub && git commit -m x", "/", true, "cwd at the root"},
	{"cd /Users/u/dev/other/$X && git commit -m x", "/Users/u/dev/app", true, "a variable after an absolute prefix"},
	{"cd /Users/u/dev/other && git commit -m x", "/Users/u/dev/app", false, "another repository, absolute"},
	{"cd ~/dev/other && git add -A && git commit -m x", "/Users/u/dev/app", false, "another repository, tilde"},
	{"cd \"$HOME/dev/other\" && git pull", "/Users/u/dev/app", false, "another repository, quoted $HOME"},
	{"cd ../other && git merge main", "/Users/u/dev/app", false, "relative sibling"},
	{"git -C ../other checkout main", "/Users/u/dev/app", false, "git -C sibling"},
	{"cd /tmp/scratch; git checkout feature-branch", "/Users/u/dev/app", false, "temp dir outside cwd"},
	{"cd . && git commit -m x", "/Users/u/dev/app", false, "cwd itself runs git where `git commit` does"},
	{"cd /Users/u/dev/app && git commit -m x", "/Users/u/dev/app", false, "cwd itself, absolute"},
	{"cd /Users/u/dev/app && git add -A && git commit -m x", "/Users/u/dev/app", false, "cwd itself, a git statement between"},
}

// nestedRepoFormRows are judged on a form other than the raw text: the
// dequoted form and the executed text a pipe to a shell runs (Opus pass 1's
// rows for mutants M28, M35 and M36, which left those forms ungated).
var nestedRepoFormRows = []struct {
	cmd, cwd string
	fires    bool
	why      string
}{
	{`cd ../other && g"it" commit -m x`, "/Users/u/dev/app", false, "only the dequoted form matches; another repo"},
	{`echo "cd ~/dev/other && git pull" | sh`, "/Users/u/dev/app", false, "executed text; another repo"},
	{`cd sub && g"it" commit -m x`, "/Users/u/dev/app", true, "only the dequoted form matches; nested"},
}

func firedRule(r EvalResult, id string) bool {
	for _, f := range r.TriggeredRules {
		if f == id {
			return true
		}
	}
	return false
}

func nestedRepoRule(t *testing.T, e *Engine) Rule {
	t.Helper()
	for _, r := range e.policy.Rules {
		if r.ID == nestedRepoRuleID {
			if r.Match.CaptureUnderCwd != "dir" {
				t.Fatalf("%s: capture_under_cwd = %q, want dir", r.ID, r.Match.CaptureUnderCwd)
			}
			return r
		}
	}
	t.Fatalf("%s not loaded", nestedRepoRuleID)
	return Rule{}
}

// TestNestedRepoRule_FiresOnlyUnderCwd_4850 runs the shipped premium rule on
// both evaluation paths (the analyzer pipeline and the regex-only fallback).
// Every row the gate excuses must still match the rule's pattern, so the test
// fails if the regex, not the gate, is what stopped it.
func TestNestedRepoRule_FiresOnlyUnderCwd_4850(t *testing.T) {
	// The rule is premium (packs/premium/terminal-safety-advanced.yaml),
	// which the OSS tree does not ship.
	ossbuild.SkipPremiumSized(t)
	testhome.Set(t, "/Users/u")
	pipeline := newAllPacksEngine(t)
	rule := nestedRepoRule(t, pipeline)
	fallback, err := NewEngine(pipeline.policy)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	for _, tc := range append(nestedRepoRows, nestedRepoFormRows...) {
		if !tc.fires && !pipeline.matchRule(tc.cmd, rule) && !strings.ContainsAny(tc.cmd, `'"`) {
			t.Errorf("%s: %q no longer matches the pattern, so the row tests nothing", tc.why, tc.cmd)
		}
		for name, e := range map[string]*Engine{"pipeline": pipeline, "fallback": fallback} {
			r := e.EvaluateWithParsedCwd(tc.cmd, nil, nil, tc.cwd)
			if got := firedRule(r, nestedRepoRuleID); got != tc.fires {
				t.Errorf("%s (%s): %q in %q fired=%v, want %v (rules %v)", tc.why, name, tc.cmd, tc.cwd, got, tc.fires, r.TriggeredRules)
			}
			if r.Decision != DecisionAudit {
				t.Errorf("%s (%s): %q decided %s, want AUDIT either way", tc.why, name, tc.cmd, r.Decision)
			}
		}
	}
}

// TestCaptureUnderCwd_Validation_4850: a gate that would be inert or bind
// only half a rule fails the load.
func TestCaptureUnderCwd_Validation_4850(t *testing.T) {
	for _, tc := range []struct {
		why string
		m   Match
	}{
		{"no command_regex", Match{CommandPrefix: []string{"git"}, CaptureUnderCwd: "dir"}},
		{"beside a prefix", Match{CommandRegex: `cd (?P<dir>\S+)`, CommandPrefix: []string{"cd"}, CaptureUnderCwd: "dir"}},
		{"beside an exact", Match{CommandRegex: `cd (?P<dir>\S+)`, CommandExact: "cd x", CaptureUnderCwd: "dir"}},
		{"undefined group", Match{CommandRegex: `cd (?P<d>\S+)`, CaptureUnderCwd: "dir"}},
		{"beside a structural match", Match{CommandRegex: `cd (?P<dir>\S+)`, Structural: &StructuralMatch{Executable: []string{"git"}}, CaptureUnderCwd: "dir"}},
	} {
		pol := DefaultPolicy()
		pol.Rules = append(pol.Rules, Rule{ID: "t-4850", Match: tc.m, Decision: DecisionAudit})
		if _, err := NewEngineWithAnalyzers(pol, 0); err == nil || !strings.Contains(err.Error(), "capture_under_cwd") {
			t.Errorf("%s: err = %v, want a capture_under_cwd refusal", tc.why, err)
		}
	}
	pol := DefaultPolicy()
	pol.Rules = append(pol.Rules, Rule{ID: "t-4850-ok", Match: Match{CommandRegex: `\bcd (?P<dir>\S+) && git commit`, CaptureUnderCwd: "dir"}, Decision: DecisionAudit})
	if _, err := NewEngineWithAnalyzers(pol, 0); err != nil {
		t.Errorf("a valid gate: %v", err)
	}
}

// TestNestedRepoRule_ExcusedDecidesAsPlainGit_4850: off the default AUDIT
// policy the excusal moves the decision, because a rule's AUDIT finding
// replaces the default (the combiner keeps the findings' most restrictive,
// not the max with the default). Under the shipped template's
// REQUIRE_APPROVAL a sibling-repo `cd … && git commit` rises from AUDIT to
// the template's prompt; under an ALLOW default it lowers to ALLOW. Either
// way it must land exactly where the plain `git <verb>` in the session's own
// repository lands, which is what it was before this rule's false match.
func TestNestedRepoRule_ExcusedDecidesAsPlainGit_4850(t *testing.T) {
	// The rule is premium (packs/premium/terminal-safety-advanced.yaml),
	// which the OSS tree does not ship.
	ossbuild.SkipPremiumSized(t)
	testhome.Set(t, "/Users/u")
	base := newAllPacksEngine(t).policy
	twins := map[string]string{}
	for _, tc := range nestedRepoRows {
		if tc.fires {
			continue
		}
		i := strings.Index(tc.cmd, "git ")
		twins[tc.cmd] = tc.cmd[i:]
		if strings.HasPrefix(twins[tc.cmd], "git -C ") {
			twins[tc.cmd] = "git " + strings.SplitN(twins[tc.cmd], " ", 4)[3]
		}
	}
	for _, def := range []Decision{DecisionAudit, DecisionAllow, DecisionRequireApproval, DecisionBlock} {
		pol := *base
		pol.Defaults.Decision = def
		e, err := NewEngineWithAnalyzers(&pol, 0)
		if err != nil {
			t.Fatalf("default %s: %v", def, err)
		}
		for _, tc := range nestedRepoRows {
			if tc.fires {
				continue
			}
			got := e.EvaluateWithParsedCwd(tc.cmd, nil, nil, tc.cwd)
			want := e.EvaluateWithParsedCwd(twins[tc.cmd], nil, nil, tc.cwd)
			if got.Decision != want.Decision {
				t.Errorf("default %s: %q decided %s, its plain twin %q %s", def, tc.cmd, got.Decision, twins[tc.cmd], want.Decision)
			}
		}
	}
}
