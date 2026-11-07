package analyzer_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// zsh reading parity — the fitness function for #4598.
//
// On a stock Mac the Bash tool runs commands through /bin/zsh, and every
// parser here reads bash. A zsh-only construct the bash parser rejects, even
// in a harmless statement of its own, used to switch off the AST stages and
// the per-statement split, so the command decided AUDIT naming no rule. The
// issue measured, over the single-line BLOCKing corpus on the hook path:
// `: ${(U)HOME}; C` 21.8% lowered, `{ C }` 24.5%, `() { C }` 22.4%.
//
// Each zsh column sits beside a bash-valid control column that wraps the
// command the same way bash accepts (`: ${HOME}; C`, `{ C; }`), and the
// assertion is relative: a zsh spelling may leak only what its control leaks.
// The control's residue is shared machinery (a prefix or a brace group around
// a command some rule reads whole), not this class, so a rise in the control
// column points away from the zsh reading. Equality with the control is the
// claim. Hook path, as the issue measured it (NormalizeCommand +
// EvaluateWithParsed).
//
// Not swept: the short `for i (1) C` form, which the zsh parser rejects too;
// TestZshReading_ShortForIsAPinnedResidual_4598 (internal/policy) pins it.
//
// maxLeaks is the residue beyond the control, and every leak in it must be a
// command the zsh parser (mvdan.cc/sh v3.14.1 LangZsh) rejects, so there is
// no reading to evaluate: the test fails on any leak that has one. Measured at
// the fix, all 15 are one shape: a declaration builtin (`declare`, `export`,
// `local`, `readonly`, `let`) as the last statement of a brace group with no
// separator, `{ export X=$(...) }`. zsh 5.9 runs it; the dialect rejects it
// ("reached EOF without matching `{` with `}`"), so the command decides as
// written, as on main. Closing it is a parser change, not this reading.
var zshReadingColumns = []struct {
	name             string
	maxLeaks         int
	zsh, bashControl func(string) string
}{
	{"parameter-flags-prefix", 0,
		func(c string) string { return ": ${(U)HOME}; " + c },
		func(c string) string { return ": ${HOME}; " + c }},
	{"parameter-flags-suffix", 0,
		func(c string) string { return c + "; : ${(U)HOME}" },
		func(c string) string { return c + "; : ${HOME}" }},
	{"brace-group-no-separator", 8,
		func(c string) string { return "{ " + c + " }" },
		func(c string) string { return "{ " + c + "; }" }},
	{"anonymous-function", 7,
		func(c string) string { return "() { " + c + " }" },
		func(c string) string { return "{ " + c + "; }" }},
}

func TestZshReadingParity(t *testing.T) {
	// The floor below is sized for the full corpus; the OSS tree strips
	// packs/premium/, so far fewer commands BLOCK there.
	ossbuild.SkipPremiumSized(t)
	t.Parallel()
	engine, allBlocking := blockingBaseline(t)
	decide := func(cmd string) policy.EvalResult {
		n := normalize.NormalizeCommand(cmd, "")
		return engine.EvaluateWithParsed(cmd, n.Paths, n.Parsed)
	}
	// The bare command must BLOCK on the hook path too, or the row measures
	// a rule gap rather than the spelling.
	var base []string
	for _, tc := range allBlocking {
		if strings.Contains(tc.Command, "\n") {
			continue
		}
		if decide(tc.Command).Decision == policy.DecisionBlock {
			base = append(base, tc.Command)
		}
	}
	assertProbeNotVacuous(t, "zsh reading parity", len(base), 1500)

	leaks := func(spell func(string) string) map[string]string {
		out := map[string]string{}
		for _, c := range base {
			if got := decide(spell(c)); got.Decision != policy.DecisionBlock {
				out[c] = fmt.Sprintf("BLOCK -> %s %v", got.Decision, got.TriggeredRules)
			}
		}
		return out
	}
	for _, col := range zshReadingColumns {
		t.Run(col.name, func(t *testing.T) {
			control := leaks(col.bashControl)
			got := leaks(col.zsh)
			var extra, withReading []string
			for c, why := range got {
				if _, ok := control[c]; ok {
					continue
				}
				extra = append(extra, fmt.Sprintf("%s : %s", why, col.zsh(c)))
				if r := shellparse.ZshReading(col.zsh(c)); r != "" {
					withReading = append(withReading, fmt.Sprintf("%s : %s (reading %q)", why, col.zsh(c), r))
				}
			}
			sort.Strings(extra)
			sort.Strings(withReading)
			t.Logf("%s: %d/%d leaked (bash-valid control: %d), %d beyond the control (budget %d)",
				col.name, len(got), len(base), len(control), len(extra), col.maxLeaks)
			if len(withReading) > 0 {
				t.Errorf("%s: %d commands with a zsh reading decided lower than their bash-valid control; "+
					"the reading itself lost them, see #4598.\n%s", col.name, len(withReading), joinLines(withReading))
			}
			if len(extra) > col.maxLeaks {
				t.Errorf("%s decided lower than its bash-valid control on %d/%d BLOCKing commands (budget %d). "+
					"The zsh spelling runs the same command, see #4598.\n%s",
					col.name, len(extra), len(base), col.maxLeaks, joinLines(extra))
			}
		})
	}
}
