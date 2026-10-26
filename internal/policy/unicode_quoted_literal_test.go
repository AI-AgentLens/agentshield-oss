package policy

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// TestInvisibleCharInsideQuotedStringStaysBlock pins a policy decision, not a
// bug: a literal invisible character BLOCKs even when it sits inside a quoted
// string (Gary, 2026-10-23, on #4492). What a reviewer sees on screen differs
// from what runs, and that is the thing a reviewer cannot check. Quoting does
// not change it. The supported spelling is the language's ASCII escape
// (backslash, u, 200b), which does not fire.
//
// The #4492 dry run met this four times in real work (a zero-width space in a
// text-cleaning call, invisible characters written into test fixtures) and
// counts them as true positives. A future "FP: invisible char in a quoted
// string" fix has to delete this test on purpose.
//
// The characters are built with rune() so this file stays plain ASCII: a raw
// invisible character in source is the same review hazard the rule exists for.
func TestInvisibleCharInsideQuotedStringStaysBlock(t *testing.T) {
	base := DefaultPolicy()
	merged, _, err := LoadEmbeddedShellPacks(base)
	if err != nil {
		t.Fatalf("LoadEmbeddedShellPacks failed: %v", err)
	}
	engine, err := NewEngineWithAnalyzers(merged, 0)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers failed: %v", err)
	}
	eval := func(command string) EvalResult {
		normalized := normalize.NormalizeCommand(command, "")
		return engine.EvaluateWithParsed(command, normalized.Paths, normalized.Parsed)
	}
	zwsp, rlo := string(rune(0x200B)), string(rune(0x202E))

	blocked := []struct {
		name, command, wantRule string
	}{
		{"zero-width space in a quoted Python string", "python3 -c \"print(s.replace('" + zwsp + "', ''))\"", "unicode-zero-width"},
		{"bidi override in a quoted fixture write", "printf '%s\\n' 'abc" + rlo + "def' > fixture.txt", "unicode-bidi-override"},
	}
	for _, tt := range blocked {
		t.Run(tt.name, func(t *testing.T) {
			r := eval(tt.command)
			if r.Decision != DecisionBlock || !containsRule(r.TriggeredRules, tt.wantRule) {
				t.Errorf("%q: decision %s rules %v, want BLOCK with %s", tt.command, r.Decision, r.TriggeredRules, tt.wantRule)
			}
		})
	}

	// The workaround must stay open, or the decision becomes "never write one".
	escaped := "python3 -c \"print(s.replace('" + `\` + "u200b', ''))\""
	if r := eval(escaped); r.Decision == DecisionBlock || hasUnicodeRule(r.TriggeredRules) {
		t.Errorf("%q: decision %s rules %v; the ASCII escape spelling must not BLOCK", escaped, r.Decision, r.TriggeredRules)
	}
}

func hasUnicodeRule(rules []string) bool {
	for _, r := range rules {
		if strings.HasPrefix(r, "unicode-") {
			return true
		}
	}
	return false
}
