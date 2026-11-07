package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// #4689, the ag and ack rows: a customer protected path BLOCKed `ag KEY <file>`
// but `ag -m 1 KEY <file>` and `ack -m 1 KEY <file>` decided AUDIT with no
// rule, because the walk's universal -m text flag read the file as message
// text. Helpers are #4673's (relReadEngine etc.).
func TestProtectedPath_AgAckMFlagFileOperand_4689(t *testing.T) {
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

	// Controls, BLOCK on main.
	for _, cmd := range []string{"ag KEY " + f, "ack KEY " + f} {
		if r := relReadEval(engine, cmd, root); r.Decision != DecisionBlock || !relReadHasRule(r, ProtectedPathRuleID) {
			t.Fatalf("control %q: %v %v; want BLOCK protected-path", cmd, r.Decision, r.TriggeredRules)
		}
	}

	for _, cmd := range []string{
		"ag -m 1 KEY " + f,
		"ag -m1 KEY " + f,
		"ag KEY -m 1 " + f,
		"/opt/homebrew/bin/ag -m 1 KEY " + f,
		"ag -g notes -m 1 " + f,
		"ack -m 1 KEY " + f,
		"ack -im 1 KEY " + f,
		"ack --match KEY -m 1 " + f,
	} {
		r := relReadEval(engine, cmd, root)
		if r.Decision != DecisionBlock || !relReadHasRule(r, ProtectedPathRuleID) || !relReadHasRef(r, ProtectedPathNode) {
			t.Errorf("%q: %v rules=%v refs=%v; want BLOCK protected-path [%s]", cmd, r.Decision, r.TriggeredRules, r.TaxonomyRefs, ProtectedPathNode)
		}
	}

	// A pattern that names the protected path is a search for its string in
	// README.md, not a read of it (#3780).
	for _, cmd := range []string{
		"ag " + f + " README.md",
		"ag -m 1 " + f + " README.md",
		"ack -m 1 " + f + " README.md",
		"ack --match " + f + " -m 1 README.md",
	} {
		if r := relReadEval(engine, cmd, root); relReadHasRule(r, ProtectedPathRuleID) {
			t.Errorf("%q: %v %v; the protected path is the pattern, not a file", cmd, r.Decision, r.TriggeredRules)
		}
	}
}
