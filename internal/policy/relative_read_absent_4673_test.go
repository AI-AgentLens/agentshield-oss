package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// #4673: a customer's relative protected path (`.env`) BLOCKed a shell write
// and every file tool in the working directory, while a shell read of the
// same bare name decided AUDIT when the file did not exist at evaluation time
// (a remote shield-server never sees the client's files; `git checkout .env
// && cat .env` creates it mid-command). The read now matches the way the
// write path and the file tools do: cwd-relative, existence not required.
// Names are assembled at runtime: the hook reads test sources as commands.

func relReadEngine(t *testing.T, patterns ...string) *Engine {
	t.Helper()
	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = append(pol.Defaults.ProtectedPaths, patterns...)
	engine, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func relReadEval(engine *Engine, cmd, cwd string) EvalResult {
	nc := normalize.NormalizeCommand(cmd, cwd)
	return engine.EvaluateWithParsedCwd(cmd, nc.Paths, nc.Parsed, cwd)
}

func relReadHasRule(r EvalResult, id string) bool {
	for _, got := range r.TriggeredRules {
		if got == id {
			return true
		}
	}
	return false
}

func relReadHasRef(r EvalResult, ref string) bool {
	for _, got := range r.TaxonomyRefs {
		if got == ref {
			return true
		}
	}
	return false
}

func TestRelativeProtectedPath_ShellReadOfAbsentFile_4673(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	env := "." + "env"
	repo, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	engine := relReadEngine(t, env)

	// Controls, BLOCK on main with the file absent: the write path and the
	// file tools' matcher.
	if r := relReadEval(engine, "echo x > "+env, repo); r.Decision != DecisionBlock || !relReadHasRule(r, ProtectedPathRuleID) {
		t.Fatalf("control, shell write: %v %v; want BLOCK protected-path", r.Decision, r.TriggeredRules)
	}
	if _, ok := MatchProtectedPath([]string{env}, os.Getenv("HOME"), filepath.Join(repo, env), repo, false); !ok {
		t.Fatal("control, file tools: the relative pattern must match <cwd>/.env")
	}

	for _, cmd := range []string{
		"cat " + env, "less " + env, "head -5 " + env, "cp " + env + " /tmp/x",
		"cat ./" + env, "cat < " + env, "tail -n 3 " + env, "source " + env, "sudo cat " + env,
		"git checkout -- " + env + " && cat " + env, "cat " + env + " | base64",
	} {
		r := relReadEval(engine, cmd, repo)
		if r.Decision != DecisionBlock || !relReadHasRule(r, ProtectedPathRuleID) || !relReadHasRef(r, ProtectedPathNode) {
			t.Errorf("%q: %v rules=%v refs=%v; want BLOCK protected-path [%s]", cmd, r.Decision, r.TriggeredRules, r.TaxonomyRefs, ProtectedPathNode)
		}
	}

	// Pinned residual: the grep family is not on the absent-read list, because
	// the walk does not know grep's value-taking flags and `grep -A 3 .env
	// README.md` would read `.env` as a file (a false BLOCK). With the file
	// present, main's reading already BLOCKs `grep KEY .env`. Closing the
	// absent case has to be deliberate.
	if r := relReadEval(engine, "grep KEY "+env, repo); relReadHasRule(r, ProtectedPathRuleID) {
		t.Errorf("grep KEY .env, file absent: %v %v; the pinned residual changed, update the comment and fileReadOperandCommands together", r.Decision, r.TriggeredRules)
	}
	if r := relReadEval(engine, "grep -A 3 "+env+" README.md", repo); r.Decision == DecisionBlock {
		t.Errorf("grep -A 3 .env README.md: %v %v; a search for the name must not BLOCK", r.Decision, r.TriggeredRules)
	}

	// Relative patterns are cwd-relative (#4020, #4653): from a subdirectory
	// `.env` names sub/.env, exactly as the write path reads it there, and a
	// parent's .env is outside the pattern for both.
	sub := filepath.Join(repo, "sub")
	for _, cmd := range []string{"cat " + env, "echo x > " + env} {
		if r := relReadEval(engine, cmd, sub); r.Decision != DecisionBlock || !relReadHasRule(r, ProtectedPathRuleID) {
			t.Errorf("cwd=sub %q: %v %v; want BLOCK protected-path", cmd, r.Decision, r.TriggeredRules)
		}
	}
	for _, cmd := range []string{"cat ../" + env, "echo x > ../" + env} {
		if r := relReadEval(engine, cmd, sub); relReadHasRule(r, ProtectedPathRuleID) {
			t.Errorf("cwd=sub %q: %v %v; a parent's file is outside a cwd-relative pattern", cmd, r.Decision, r.TriggeredRules)
		}
	}

	// TNs: a same-named file outside the cwd, an unlisted name, the name as
	// text.
	other := filepath.Join(t.TempDir(), "other")
	for _, cmd := range []string{
		"cat " + filepath.Join(other, env), "cat ../other/" + env, "cat " + env + ".example",
		"echo " + env, `git commit -m "document the ` + env + ` file"`, "grep " + env + " notes.txt",
		"kubectl get secrets",
	} {
		if r := relReadEval(engine, cmd, repo); relReadHasRule(r, ProtectedPathRuleID) {
			t.Errorf("%q: %v %v; must not match the relative pattern", cmd, r.Decision, r.TriggeredRules)
		}
	}
}

// The relative form reaches relative patterns only. An absolute customer
// pattern (and every shipped one) keeps main's reading of a bare operand:
// existing entry only, which #4401 pins for `cat nosuchfile` inside ~/.ssh.
func TestRelativeProtectedPath_AbsentReadLeavesAbsolutePatternsAlone_4673(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	acme := filepath.Join(root, "acme")
	if err := os.MkdirAll(acme, 0o700); err != nil {
		t.Fatal(err)
	}
	engine := relReadEngine(t, acme+"/**")
	// control: the same absent name spelled ./ matches the absolute pattern
	if r := relReadEval(engine, "cat ./absent.txt", acme); r.Decision != DecisionBlock {
		t.Fatalf("control cat ./absent.txt: %v %v; want BLOCK", r.Decision, r.TriggeredRules)
	}
	if r := relReadEval(engine, "cat absent.txt", acme); relReadHasRule(r, ProtectedPathRuleID) {
		t.Errorf("absolute pattern, absent bare read: %v %v; main's existence-gated reading must hold", r.Decision, r.TriggeredRules)
	}
	if err := os.WriteFile(filepath.Join(acme, "present.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := relReadEval(engine, "cat present.txt", acme); r.Decision != DecisionBlock || !relReadHasRule(r, ProtectedPathRuleID) {
		t.Errorf("absolute pattern, existing bare read: %v %v; want BLOCK as on main", r.Decision, r.TriggeredRules)
	}
}
