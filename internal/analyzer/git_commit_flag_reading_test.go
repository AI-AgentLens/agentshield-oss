package analyzer

import "testing"

// #4606 + #4612 on the structural flag reading of `git commit`.
//
// #4606 widens: a rule naming the hook-skipping long flag also reads git's
// unique-prefix spellings of it.
// #4612 narrows: for `git commit`, the generic n <-> dry-run alias is a
// misread (-n is the hook-skipping short flag there, --dry-run is its own
// long option), so a rule naming `n` no longer fires on --dry-run.
//
// Flags are assembled at runtime: the hook reads test sources as commands.
func TestStructuralRule_GitCommitFlagReading_4606_4612(t *testing.T) {
	long := "no-" + "verify"
	rule := StructuralRule{
		Executable: []string{"git"}, SubCommand: "commit",
		FlagsAny: []string{"n", long},
		Decision: "BLOCK",
	}
	stem := "--no-" + "ver"
	for _, tc := range []struct {
		command string
		want    bool
	}{
		{"git commit --" + long + " -m wip", true},
		{"git commit -n -m wip", true},
		{"git commit " + stem + "i -m wip", true},
		{"git commit " + stem + "if -m wip", true},
		{"git commit -m wip " + stem + "i", true},
		{"git commit " + stem + " -m wip", false}, // ambiguous: git rejects it
		{"git commit --dry-run -m t", false},      // #4612
		{"git commit --dry-r -m t", false},
		{"git commit -m wip", false},
	} {
		if got := MatchStructuralRule(parseCommand(t, tc.command), rule); got != tc.want {
			t.Errorf("MatchStructuralRule(%q) = %v, want %v", tc.command, got, tc.want)
		}
	}

	// The n <-> dry-run alias is unchanged for every other command: a rule
	// naming dry-run still reads -n elsewhere (git push -n is --dry-run).
	other := StructuralRule{Executable: []string{"git"}, SubCommand: "push", FlagsAny: []string{"dry-run"}, Decision: "AUDIT"}
	if !MatchStructuralRule(parseCommand(t, "git push -n origin main"), other) {
		t.Errorf("git push -n no longer reads as dry-run; the #4612 exception must be scoped to git commit")
	}
}
