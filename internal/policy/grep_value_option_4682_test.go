package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// #4682: a customer protected path covering a file BLOCKed `grep KEY <file>`
// but not `grep -m 1 KEY <file>`: grep's max-count -m is the path walk's
// universal -m text flag, so every later word, the file included, was read as
// message text. A customer pattern has no regex backstop, so path extraction
// is the only layer. Helpers are #4673's (relReadEngine etc.).
func TestProtectedPath_GrepValueOptionFileOperand_4682(t *testing.T) {
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
	for _, p := range []string{f, filepath.Join(root, "README.md")} {
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
		"grep -m 1 KEY " + f,
		"grep -m1 KEY " + f,
		"grep -rnm 5 KEY " + acme,
		"grep -m 1 KEY -n " + f,
		"egrep -m1 KEY " + f,
		"rg -m 1 KEY " + f,
		// BLOCK on main too; they must stay so.
		"grep -A 3 KEY " + f,
		"grep -C2 KEY " + f,
		"grep --max-count=1 KEY " + f,
		"grep -m 1 -e KEY " + f,
	} {
		r := relReadEval(engine, cmd, root)
		if r.Decision != DecisionBlock || !relReadHasRule(r, ProtectedPathRuleID) || !relReadHasRef(r, ProtectedPathNode) {
			t.Errorf("%q: %v rules=%v refs=%v; want BLOCK protected-path [%s]", cmd, r.Decision, r.TriggeredRules, r.TaxonomyRefs, ProtectedPathNode)
		}
	}

	// The protected path as an option's value or as the pattern, or a search
	// with no file operand.
	absent := filepath.Join(acme, "absent.txt")
	for _, cmd := range []string{
		"grep --exclude " + f + " KEY README.md",
		"grep -m 1 --exclude " + f + " KEY README.md",
		"grep " + f + " README.md",
		"grep -m 1 " + f + " README.md",
		"grep -m 1 " + absent + " README.md",
		"grep -m 1 KEY README.md",
		"echo x | grep -m 1 KEY",
	} {
		if r := relReadEval(engine, cmd, root); relReadHasRule(r, ProtectedPathRuleID) {
			t.Errorf("%q: %v %v; the protected path is not a file this command searches", cmd, r.Decision, r.TriggeredRules)
		}
	}
}
