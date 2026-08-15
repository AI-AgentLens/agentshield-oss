package cli

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// A pack that fails to parse contributes ZERO rules. Before #3035, `check`
// discarded the PackInfo slices returned by the loaders, so a single `: ` in an
// unquoted YAML scalar dropped an entire pack and every command quietly
// degraded to the default AUDIT — with no warning anywhere in the output. The
// hook and scan surfaces already warned (#2188); check was the one silent
// surface, and it is the one rule authors use to decide whether their rule
// works.
func TestWarnFailedPacks_IsLoudAndActionable(t *testing.T) {
	var buf bytes.Buffer
	warnFailedPacks(&buf, []policy.PackInfo{{
		Name:      "terminal-safety.yaml",
		Path:      "(embedded)",
		LoadError: errors.New("yaml: line 1170: mapping values are not allowed in this context"),
	}})
	out := buf.String()

	// The pack identity, the consequence, and the underlying parse error must
	// all be present — a warning that omits any of the three is not actionable.
	for _, want := range []string{
		"CRITICAL",
		"(embedded)",
		"NOT loaded",
		"line 1170",
		"DEGRADED",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("warning missing %q\ngot:\n%s", want, out)
		}
	}
}

// Silence when healthy: a warning that fires on every clean run trains people
// to ignore it, which would defeat the purpose.
func TestWarnFailedPacks_QuietWhenHealthy(t *testing.T) {
	if got := policy.FailedPacks([]policy.PackInfo{
		{Name: "a.yaml", RuleCount: 10},
		{Name: "b.yaml", RuleCount: 20},
	}); len(got) != 0 {
		t.Fatalf("FailedPacks on healthy infos = %v, want empty", got)
	}
}

// noteFailedPacks warns once per process. A --fixture run re-resolves the
// policy once per case, so without this the CRITICAL banner repeats for every
// case and buries the fixture results it is meant to qualify.
func TestNoteFailedPacks_WarnsOnce(t *testing.T) {
	checkFailedPacks = nil
	checkWarnOnce = onceForTest()

	failed := []policy.PackInfo{{Name: "p.yaml", Path: "(embedded)", LoadError: errors.New("boom")}}
	noteFailedPacks(failed)
	noteFailedPacks(failed)
	noteFailedPacks(failed)

	if len(checkFailedPacks) != 1 {
		t.Fatalf("checkFailedPacks = %d, want 1 — the count drives the non-zero exit code", len(checkFailedPacks))
	}
}

// onceForTest returns a fresh sync.Once so tests can exercise noteFailedPacks
// independently of process-global state.
func onceForTest() sync.Once { return sync.Once{} }
