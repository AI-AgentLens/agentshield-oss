package mcp

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Unicode-simple-fold hazard on NEGATIVE tool-name predicates (#3771).
//
// Go's `(?i)` folds by Unicode simple folding, not ASCII case. U+017F LONG S
// folds to `s`; U+212A KELVIN SIGN folds to `k`. So a long-s spelling of an
// excluded tool name SATISFIES a `(?i)` exclusion, while the positive matchers
// (matchToolNameCaseInsensitive -> ToLower + normalizeSeparators; and the
// semantic classifier) leave U+017F alone and match nothing. #3757 shipped that
// pairing on mcp-struct-block-credential-path-access: the fold switched the
// catch-all OFF and neither dedicated rule fired, so a credential-file read
// decided AUDIT with zero rules where base BLOCKed.
//
// Every fixture below is built from a \u escape so this source file stays pure
// ASCII on disk and no editor/shell normalisation can quietly turn the
// non-ASCII byte into something else. TestFoldFixturesAreNonASCII is the
// self-check: without it a normalised fixture would make every assertion here
// pass over ASCII input and prove nothing.

const (
	longS  = "\u017f" // LATIN SMALL LETTER LONG S -> folds to 's'
	kelvin = "\u212a" // KELVIN SIGN               -> folds to 'k'
)

func TestFoldFixturesAreNonASCII(t *testing.T) {
	for name, s := range map[string]string{"longS": longS, "kelvin": kelvin} {
		if s == "" {
			t.Fatalf("%s fixture is empty", name)
		}
		if asciiOnlyWireName(s) {
			t.Fatalf("%s fixture %q is ASCII on disk -- the escape was normalised and every fold test below is vacuous", name, s)
		}
	}
	// And prove the hazard is real, not assumed: Go's (?i) must actually fold
	// these to ASCII. If a future Go release stops doing so, this test tells us
	// the guard is now belt-and-braces rather than load-bearing.
	for _, tc := range []struct{ pattern, input string }{
		{"(?i)^contents$", "content" + longS},
		{"(?i)^ok$", "o" + kelvin},
	} {
		re, err := cachedRegexp(tc.pattern)
		if err != nil {
			t.Fatalf("cachedRegexp(%q): %v", tc.pattern, err)
		}
		if !re.MatchString(tc.input) {
			t.Errorf("Go (?i) no longer folds %q into %q -- the #3771 hazard may have changed shape", tc.input, tc.pattern)
		}
	}
}

// TestExcludeWhenNeverMatchesNonASCIIName is the unit-level guard: the carve-out
// must not apply to a folded spelling, so the rule stays live.
func TestExcludeWhenNeverMatchesNonASCIIName(t *testing.T) {
	m := MCPStructuralMatch{
		ToolNameRegex: ".*",
		ExcludeWhen: &StructuralExcludeClause{
			// Deliberately contains both an 's' (long-s vector) and a 'k'
			// (KELVIN vector) so one clause covers both fold characters.
			ToolNameRegex: "(?i)^(?:get[_-]file[_-]contents|kv[_-]read)$",
			ArgsMatch: map[string]ArgFieldMatch{
				"path": {PatternAny: []string{"(?:^|/)\\.pypirc$"}},
			},
		},
		ArgsMatch: map[string]ArgFieldMatch{
			"path": {PatternAny: []string{"\\.pypirc$"}},
		},
	}
	args := map[string]interface{}{"path": "/home/user/.pypirc"}

	// ASCII controls: the carve-out works, i.e. the exclusion is not simply dead.
	for _, tool := range []string{"get_file_contents", "GET_FILE_CONTENTS", "get-file-contents", "kv_read"} {
		if matchStructural(tool, args, m) {
			t.Errorf("ASCII %q should be carved out (exclusion must still work for real names)", tool)
		}
	}

	// The hazard: folded spellings must NOT be carved out.
	folded := []string{
		"get_file_content" + longS,  // trailing s
		longS + "tr_replace_editor", // leading s (shape from #3771)
		kelvin + "v_read",           // KELVIN -> k
	}
	for _, tool := range folded {
		if !matchStructural(tool, args, m) {
			t.Errorf("FAIL-OPEN: folded name %q satisfied the carve-out and switched the rule OFF; "+
				"a non-ASCII wire name must never match a negative predicate (#3771)", tool)
		}
	}
}

// TestSemanticToolNameExcludeNeverMatchesNonASCIIName: same guard on the other
// exclusion site in the class.
func TestSemanticToolNameExcludeNeverMatchesNonASCIIName(t *testing.T) {
	rule := MCPSemanticRule{Match: MCPSemanticMatch{
		IntentAny:            []string{"credential-read"},
		ToolNameRegexExclude: "(?i)(^|[_-])(rotate|reset)([_-]|$)",
	}}
	intents := []IntentClassification{{Intent: "credential-read", Confidence: 1.0}}

	if matchSemanticRule("reset_vault_token", intents, rule) {
		t.Error("ASCII reset_vault_token should be carved out -- the exclusion must still work")
	}
	if !matchSemanticRule("re"+longS+"et_vault_token", intents, rule) {
		t.Error("FAIL-OPEN: a folded verb satisfied the semantic carve-out (#3771)")
	}
}

// TestPkgmgrFoldedToolNamesStillBlock is the POLICY-LEVEL regression, evaluated
// through the real loaded packs in BOTH build configs -- the same shape as the
// measured base-vs-merge table in #3771.
func TestPkgmgrFoldedToolNamesStillBlock(t *testing.T) {
	pypirc := "/home/user/." + "pypirc"
	gradle := "/home/user/.gradle/gradle." + "properties"

	foldedTools := []string{
		"get_file_content" + longS,  // folds to get_file_contents
		longS + "tr_replace_editor", // folds to str_replace_editor
	}

	builds := []struct {
		name string
		dirs []string
	}{
		{"community-only", []string{mcpPacksDir()}},
		{"full", []string{mcpPacksDir(), premiumMCPPacksDir()}},
	}

	for _, b := range builds {
		b := b
		t.Run(b.name, func(t *testing.T) {
			eval := mcpEvaluatorFromDirs(t, b.dirs...)

			for _, path := range []string{pypirc, gradle} {
				for _, tool := range foldedTools {
					res := eval.EvaluateToolCall(tool, map[string]interface{}{"path": path})
					if res.Decision != policy.DecisionBlock {
						t.Errorf("FAIL-OPEN: folded tool %q on %q decided %s with %d rule(s) %v, want BLOCK.\n"+
							"  A Unicode-fold spelling of an excluded name must fall back to the catch-all (#3771).",
							tool, path, res.Decision, len(res.TriggeredRules), res.TriggeredRules)
					}
				}
			}

			// ASCII control: the double-fire fix still holds -- exactly one rule,
			// one taxonomy. Without this the guard could "pass" by disabling the
			// carve-out entirely.
			res := eval.EvaluateToolCall("get_file_contents", map[string]interface{}{"path": pypirc})
			if res.Decision != policy.DecisionBlock {
				t.Errorf("ASCII control decided %s, want BLOCK", res.Decision)
			}
			if len(res.TriggeredRules) != 1 {
				t.Errorf("ASCII control fired %d rules %v, want exactly 1 -- the #3735 carve-out regressed",
					len(res.TriggeredRules), res.TriggeredRules)
			}

			// Exotic control: an unrecognised ASCII name still reaches the catch-all.
			ex := eval.EvaluateToolCall("quantum_blob_reader", map[string]interface{}{"path": pypirc})
			if ex.Decision != policy.DecisionBlock || len(ex.TriggeredRules) != 1 {
				t.Errorf("exotic control: got %s with %v, want BLOCK via the catch-all alone",
					ex.Decision, ex.TriggeredRules)
			}
			if len(ex.TriggeredRules) == 1 && !strings.Contains(ex.TriggeredRules[0], "struct-block-credential-path-access") {
				t.Errorf("exotic control fired %q, expected the catch-all", ex.TriggeredRules[0])
			}
		})
	}
}
