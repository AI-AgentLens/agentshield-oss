package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// #4676: a customer protected path covering a file BLOCKed `grep KEY <file>`
// but not `grep -e KEY <file>`: when an option supplies the pattern the path
// walk dropped the file operand. A customer pattern has no regex backstop, so
// path extraction is the only layer. Helpers are #4673's (relReadEngine etc.).
func TestProtectedPath_GrepPatternOptionFileOperand_4676(t *testing.T) {
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
	for _, p := range []string{f, filepath.Join(root, "pats"), filepath.Join(root, "README.md")} {
		if err := os.WriteFile(p, []byte("KEY=dummy\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	engine := relReadEngine(t, acme+"/**")

	// Control, BLOCK on main: the positional pattern.
	if r := relReadEval(engine, "grep KEY "+f, root); r.Decision != DecisionBlock || !relReadHasRule(r, ProtectedPathRuleID) {
		t.Fatalf("control grep KEY <file>: %v %v; want BLOCK protected-path", r.Decision, r.TriggeredRules)
	}

	for _, cmd := range []string{
		"grep -e KEY " + f,
		"grep -e KEY -n " + f,
		"grep --regexp=KEY " + f,
		"grep -eKEY " + f,
		"grep -e A -e B " + f,
		"grep -f pats " + f,
		"grep -f pats -e X " + f,
		"rg -e KEY " + f,
		"grep -rn -e KEY " + acme,
		"grep " + f + " -e KEY",
		"grep -f " + f + " README.md", // the pattern file is read
	} {
		r := relReadEval(engine, cmd, root)
		if r.Decision != DecisionBlock || !relReadHasRule(r, ProtectedPathRuleID) || !relReadHasRef(r, ProtectedPathNode) {
			t.Errorf("%q: %v rules=%v refs=%v; want BLOCK protected-path [%s]", cmd, r.Decision, r.TriggeredRules, r.TaxonomyRefs, ProtectedPathNode)
		}
	}

	// The protected path as pattern text, or a pattern with no file operand.
	for _, cmd := range []string{
		"grep -e " + f + " README.md",
		"grep --regexp=" + f + " README.md",
		"grep -e KEY README.md",
		"echo x | grep -e KEY",
		"echo x | grep -e " + f,
		"grep " + f + " README.md",
		"rg -tconf " + f + " README.md",
	} {
		if r := relReadEval(engine, cmd, root); relReadHasRule(r, ProtectedPathRuleID) {
			t.Errorf("%q: %v %v; the protected path is pattern text here, not a file", cmd, r.Decision, r.TriggeredRules)
		}
	}
}
