package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// #4689: a customer protected path covering a file BLOCKed `wc <file>` but not
// `wc -m <file>` (ALLOW ts-allow-readonly), `sort -m`, `less -m` or `pr -m`:
// the path walk's universal -m text flag (meant for `git commit -m`) read
// every later word as message text. A path-qualified `/usr/bin/grep -m 1`
// had no grep spec at all. A customer pattern has no regex backstop, so path
// extraction is the only layer. Helpers are #4673's (relReadEngine etc.).
func TestProtectedPath_MFlagReaderFileOperand_4689(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	acme := filepath.Join(root, "acme")
	if err := os.MkdirAll(acme, 0o700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(acme, "notes.txt")
	g := filepath.Join(acme, "other.txt")
	for _, p := range []string{f, g, filepath.Join(root, "README.md")} {
		if err := os.WriteFile(p, []byte("KEY=dummy\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	engine := relReadEngine(t, acme+"/**")

	// Control, BLOCK on main.
	if r := relReadEval(engine, "wc "+f, root); r.Decision != DecisionBlock || !relReadHasRule(r, ProtectedPathRuleID) {
		t.Fatalf("control wc <file>: %v %v; want BLOCK protected-path", r.Decision, r.TriggeredRules)
	}

	for _, cmd := range []string{
		"wc -m " + f,
		"wc -lm " + f,
		"sort -m " + f + " " + g,
		"less -m " + f,
		"pr -m " + f + " " + g,
		"/usr/bin/grep -m 1 KEY " + f,
		"/usr/bin/grep -e KEY " + f,
	} {
		r := relReadEval(engine, cmd, root)
		if r.Decision != DecisionBlock || !relReadHasRule(r, ProtectedPathRuleID) || !relReadHasRef(r, ProtectedPathNode) {
			t.Errorf("%q: %v rules=%v refs=%v; want BLOCK protected-path [%s]", cmd, r.Decision, r.TriggeredRules, r.TaxonomyRefs, ProtectedPathNode)
		}
	}

	// A commit message is text, not a file, and README.md is not protected.
	for _, cmd := range []string{
		`git commit -m "` + f + `"`,
		"wc -m README.md",
		"/usr/bin/grep -m 1 " + f + " README.md",
	} {
		if r := relReadEval(engine, cmd, root); relReadHasRule(r, ProtectedPathRuleID) {
			t.Errorf("%q: %v %v; the protected path is not a file this command reads", cmd, r.Decision, r.TriggeredRules)
		}
	}
}
