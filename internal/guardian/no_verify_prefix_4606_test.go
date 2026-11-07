package guardian

import "testing"

// #4606: git accepts any unambiguous prefix of a long option, so the four-
// and five-letter stems of the hook-skipping flag run as the full flag. The
// three-letter stem is ambiguous with the verbose negation and git rejects
// it, so it must not fire. Flags are assembled at runtime: the hook reads
// test sources as commands.
func TestHeuristicProvider_NoVerifyUniquePrefix_4606(t *testing.T) {
	p := NewHeuristicProvider()
	stem := "--no-" + "ver"
	for _, tc := range []struct {
		cmd  string
		want bool
	}{
		{"git push " + stem + "ify origin main", true}, // control
		{"git push " + stem + "i origin main", true},
		{"git push " + stem + "if origin main", true},
		{"git commit " + stem + "i -m wip", true},
		{"git commit -m wip " + stem + "if", true},
		{"git commit " + stem + " -m wip", false},     // ambiguous: git rejects it
		{"git commit " + stem + "bose -m wip", false}, // the other candidate
		{"git commit -m wip", false},
	} {
		resp, err := p.Analyze(GuardianRequest{RawCommand: tc.cmd})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := hasSignal(resp.Signals, "disable_security"); got != tc.want {
			t.Errorf("%q: disable_security=%v, want %v (signals %v)", tc.cmd, got, tc.want, signalIDs(resp.Signals))
		}
	}
}
