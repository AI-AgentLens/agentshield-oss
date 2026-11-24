package analyzer

import (
	"regexp"
	"strings"
	"testing"
)

// The shipped rule's pattern (ts-audit-git-cd-nested-repo-hook-detonation,
// #4850), copied so the gate's tests do not depend on the pack.
var nestedRepoRe = regexp.MustCompile(`\bcd\s+(?P<dir>\S+)\s*(?:&&|;)\s*(?:[^&;\n]*(?:&&|;)\s*)?git\b[^&;\n]*\b(?:commit|checkout|merge|pull)\b|\bgit\s+-C\s+(?P<dir>\S+)\s+(?:commit|checkout|merge|pull)\b`)

func TestDirInScope_4850(t *testing.T) {
	const cwd, home = "/Users/u/dev/app", "/Users/u"
	for _, tc := range []struct {
		dir  string
		cwd  string
		want bool
		why  string
	}{
		{"examples/fixtures", cwd, true, "relative subdirectory"},
		{"./vendor/lib", cwd, true, "dot-relative subdirectory"},
		{"/Users/u/dev/app/examples", cwd, true, "absolute under cwd"},
		{"~/dev/app/sub", cwd, true, "tilde under cwd"},
		{"$HOME/dev/app/sub", cwd, true, "$HOME under cwd"},
		{"${HOME}/dev/app/sub", cwd, true, "${HOME} under cwd"},
		{"'/Users/u/dev/app/sub dir'", cwd, true, "whole-word quoted"},
		{`"examples"`, cwd, true, "double-quoted relative"},
		{"/USERS/U/DEV/APP/sub", cwd, true, "case folded: a spelling difference keeps the match"},
		{"/tmp/repo/sub", "/private/tmp/repo", true, "macOS /private alias on cwd"},
		{"/private/tmp/repo/sub", "/tmp/repo", true, "macOS /private alias on the dir"},
		{`C:/w/app/sub`, `C:\w\app`, true, "Windows cwd with backslashes"},
		{"$REPO/sub", cwd, true, "unresolvable: a variable"},
		{"$(git rev-parse --show-toplevel)", cwd, true, "unresolvable: a substitution"},
		{"sub*", cwd, true, "unresolvable: a glob"},
		{`su\b`, cwd, true, "unresolvable: an escape"},
		{"-P", cwd, true, "unresolvable: an option word"},
		{"-", cwd, true, "unresolvable: cd -"},
		{"~other/repo", cwd, true, "unresolvable: ~user"},
		{"a&&b", cwd, true, "unresolvable: an operator inside the word"},
		{"x'y'", cwd, true, "unresolvable: a quote splice"},
		{"/Users/u/dev/other", "", true, "no cwd"},
		{"/Users/u/dev/other", "relative/cwd", true, "relative cwd"},
		{"~/dev/other", cwd, false, "tilde sibling repo"},
		{"/Users/u/dev/other", cwd, false, "absolute sibling repo"},
		{"$HOME/dev/other", cwd, false, "$HOME sibling repo"},
		{"..", cwd, false, "parent"},
		{"../other", cwd, false, "relative sibling"},
		{"sub/../../other", cwd, false, "climbs out after a descent"},
		{".", cwd, false, "cwd itself"},
		{"/Users/u/dev/app", cwd, false, "cwd itself, absolute"},
		{"/Users/u/dev/app/", cwd, false, "cwd itself, trailing slash"},
		{"/Users/u/dev/apple", cwd, false, "a sibling sharing the prefix"},
		{"/tmp/scratch", cwd, false, "temp dir"},
		{"/", cwd, false, "root"},
		{"/c/w/app/sub", `C:\w\app`, true, "Git Bash drive spelling under a drive cwd"},
		{"/mnt/c/w/app/sub", `C:\w\app`, true, "WSL drive spelling"},
		{"/cygdrive/c/w/app/sub", `C:\w\app`, true, "Cygwin drive spelling"},
		{"/c/w/other", `C:\w\app`, false, "Git Bash spelling of a sibling"},
		{"/c/x", "/", true, "a POSIX /c under a root cwd is not folded"},
		{"~/dev/app/sub", "/home/client/dev/app", true, "cwd outside home: ~ is not this home"},
	} {
		if got := dirInScope(tc.dir, tc.cwd, home); got != tc.want {
			t.Errorf("%s: dirInScope(%q, %q) = %v, want %v", tc.why, tc.dir, tc.cwd, got, tc.want)
		}
	}
	if !dirInScope("~/dev/other", "/Users/u/dev/app", "") {
		t.Error("an unknown home must leave ~ unresolved, which keeps the match")
	}
}

func TestCaptureInScope_4850(t *testing.T) {
	const cwd, home = "/Users/u/dev/app", "/Users/u"
	for _, tc := range []struct {
		cmd  string
		want bool
		why  string
	}{
		{"cd examples/fixtures && git add -A && git commit -m x", true, "the rule's own TP"},
		{"git -C vendor/lib checkout main", true, "git -C under cwd"},
		{"cd ~/dev/other && git commit -m x", false, "sibling repo"},
		{"git -C ../other pull", false, "git -C sibling"},
		{"cd /Users/u/dev/app && cd examples && git commit -m x", true, "a later cd's directory: overlapping match starts"},
		{"cd ~/dev/other && git pull; cd sub && git commit -m x", true, "a second match under cwd"},
		{"cd ~/dev/other && git pull; cd ../b && git commit -m x", false, "every match outside"},
		{"echo nothing here", true, "no match in this form: main's verdict stands"},
		{"cd /Users/u/dev/app && cd \"my dir\" && git commit -m x", true, "a second cd between: the word does not say where git runs"},
		{"cd /Users/u/dev/app && git --work-tree=sub commit", true, "--work-tree"},
		{"cd /Users/u/dev/app && export GIT_DIR=sub/.git && git commit", true, "GIT_DIR exported between"},
		{"cd /Users/u/dev/app && git --git-dir=sub/.git commit", true, "--git-dir alone"},
		{"cd /Users/u/dev/app && eval x && git commit", true, "eval between"},
		{"cd /Users/u/dev/app && git add -A && git commit -m x", false, "a plain git statement between moves nothing"},
	} {
		if got := CaptureInScope(nestedRepoRe, tc.cmd, "dir", cwd, home, false); got != tc.want {
			t.Errorf("%s: CaptureInScope(%q) = %v, want %v", tc.why, tc.cmd, got, tc.want)
		}
	}
	if !CaptureInScope(nestedRepoRe, "cd ~/dev/other && git pull", "nosuch", cwd, home, false) {
		t.Error("a group the regex does not define must keep the match")
	}
	if !CaptureInScope(nil, "cd ~/dev/other && git pull", "dir", cwd, home, false) {
		t.Error("a nil regexp must keep the match")
	}
}

// The scan is bounded, and each bound keeps main's match.
func TestCaptureInScope_Bounds_4850(t *testing.T) {
	const cwd, home = "/Users/u/dev/app", "/Users/u"
	outside := "cd ~/dev/other && git pull; "
	under := func(n int) string { return strings.Repeat(outside, n) }
	if CaptureInScope(nestedRepoRe, under(maxCwdCaptureMatches-1), "dir", cwd, home, false) {
		t.Errorf("%d matches outside cwd: want excused", maxCwdCaptureMatches-1)
	}
	if !CaptureInScope(nestedRepoRe, under(maxCwdCaptureMatches), "dir", cwd, home, false) {
		t.Errorf("%d matches: past the match bound, want main's match kept", maxCwdCaptureMatches)
	}
	long := outside + strings.Repeat("x", maxCwdCaptureBytes)
	if !CaptureInScope(nestedRepoRe, long, "dir", cwd, home, false) {
		t.Error("a text past the byte bound: want main's match kept")
	}
	if CaptureInScope(nestedRepoRe, outside+strings.Repeat("x", maxCwdCaptureBytes-len(outside)), "dir", cwd, home, false) {
		t.Error("a text at the byte bound: want excused")
	}
}

// A form only the separator fold matches is judged on the folded text.
func TestCaptureInScope_FoldSeparators_4850(t *testing.T) {
	re := regexp.MustCompile(`\bcd (?P<dir>\S+) && git commit`)
	const cwd, home = "/Users/u/dev/app", "/Users/u"
	nbsp := "cd sub &&\u00a0git commit"
	if !CaptureInScope(re, nbsp, "dir", cwd, home, true) {
		t.Error("folded form under cwd: want the match kept")
	}
	if CaptureInScope(re, "cd ../x &&\u00a0git commit", "dir", cwd, home, true) {
		t.Error("folded form outside cwd: want excused")
	}
}

func TestCaptureGroupDefined_4850(t *testing.T) {
	if !CaptureGroupDefined(nestedRepoRe.String(), "dir") {
		t.Error("dir is defined")
	}
	if CaptureGroupDefined(nestedRepoRe.String(), "nope") || CaptureGroupDefined("(", "dir") {
		t.Error("a missing group or a bad pattern is not defined")
	}
}
