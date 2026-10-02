package analyzer_test

import "testing"

// TestDdAllowWithheldPipelineDecisions pins the full-pipeline decision for
// two Codex pass-3 witnesses from #3997 that are deliberately NOT in the
// shared corpus. The carrier-parity sweeps (env -S, man -P, watch, stdin)
// wrap every corpus TP, and neither of these compound shapes is decomposed
// inside those carriers. That is a pre-existing carrier gap, unrelated to
// the dd ALLOW, and adding them to the corpus would only spend those sweeps'
// leak budgets. Here they assert what #3997 is about: no ALLOW, the BLOCK
// stands.
func TestDdAllowWithheldPipelineDecisions(t *testing.T) {
	engine := newPipelineEngine(t)
	for _, tc := range []struct{ name, cmd string }{
		{"xargs-run dd beside a harmless dd", "printf x | xargs -I{} dd if=/dev/zero of=/dev/sda; dd if=/dev/zero of=/tmp/x count=0"},
		{"group stderr routed onto a disk", "true; { dd if=/dev/zero of=/dev/null count=1; } 2>/dev/sda"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.Evaluate(tc.cmd, nil)
			for _, r := range got.TriggeredRules {
				if r == "st-allow-dd-to-file" {
					t.Fatalf("%q earned st-allow-dd-to-file (decision %s)", tc.cmd, got.Decision)
				}
			}
			if got.Decision != "BLOCK" {
				t.Errorf("%q: got %s %v, want BLOCK", tc.cmd, got.Decision, got.TriggeredRules)
			}
		})
	}
}

// TestDdAllowUsesHookCwd drives the same entry point the hook uses
// (EvaluateWithParsedCwd, internal/cli/hook.go) to prove the working directory
// actually reaches the dd gate. `cd /dev` in one Bash call and `dd … of=sda` in
// the next is a real two-step, because Claude Code keeps cwd between calls.
func TestDdAllowUsesHookCwd(t *testing.T) {
	engine := newPipelineEngine(t)
	cmd := "dd if=/dev/zero of=sda count=1"

	inDev := engine.EvaluateWithParsedCwd(cmd, nil, nil, "/dev")
	if inDev.Decision != "BLOCK" {
		t.Errorf("cwd=/dev %q: got %s %v, want BLOCK", cmd, inDev.Decision, inDev.TriggeredRules)
	}
	// Control: the same text in a project directory is a file write and
	// keeps the ALLOW, so the BLOCK above is the cwd, not the text.
	inProj := engine.EvaluateWithParsedCwd(cmd, nil, nil, "/home/u/proj")
	if inProj.Decision != "ALLOW" {
		t.Errorf("cwd=/home/u/proj %q: got %s %v, want ALLOW", cmd, inProj.Decision, inProj.TriggeredRules)
	}
}
