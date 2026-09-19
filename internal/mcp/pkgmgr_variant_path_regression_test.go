package mcp

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Policy-level regression guard for the #3735 fail-open caught in review.
//
// The first cut of the double-fire fix put a tool-name-only exclude on
// mcp-struct-block-credential-path-access. That catch-all matches credential
// path VARIANTS the dedicated rules' `**/` globs do not — `release.pypirc`,
// `.gradle/gradle.properties.bak`, `...~` — so excluding the six read tool
// names dropped those variants from BLOCK to AUDIT with no rule, on the
// COMMUNITY pack. This test evaluates a full decision through the real loaded
// packs (not just matchStructural), on both build configs, and asserts every
// variant still BLOCKs.
//
// It is a positive control for its own fix: run it against the tool-name-only
// exclude (or against no exclude with the patterns moved out of the catch-all)
// and the community-build variant rows fail.

// mcpEvaluatorFromDirs builds a PolicyEvaluator over the packs in the given
// dirs, merged in order. One dir = the community-only (OSS) build; community
// then premium = the full build.
func mcpEvaluatorFromDirs(t *testing.T, dirs ...string) *PolicyEvaluator {
	t.Helper()
	base := DefaultMCPPolicy()
	pol := base
	for _, dir := range dirs {
		merged, infos, err := LoadMCPPacks(dir, pol)
		if err != nil {
			t.Fatalf("LoadMCPPacks(%s): %v", dir, err)
		}
		for _, info := range infos {
			if info.LoadError != nil {
				t.Fatalf("pack %q failed to load: %v", info.Name, info.LoadError)
			}
		}
		pol = merged
	}
	return NewPolicyEvaluator(pol)
}

func TestPkgmgrVariantPathsStillBlock(t *testing.T) {
	// The six read tool names carved out by exclude_when, both separator
	// spellings, so a regression on either is caught.
	readTools := []string{
		"read_file", "cat_file", "open_file", "view_file",
		"get_file_contents", "str_replace_editor",
		"read-file", "cat-file", // hyphen spellings fold to the same names
	}

	// Variant credential paths the catch-all matched but the dedicated globs
	// (**/.pypirc, **/.gradle/gradle.properties) do NOT — the exact fail-open
	// set. These MUST stay BLOCK on every read tool, in every build.
	variantPaths := []string{
		"/home/user/release.pypirc",
		"/home/user/.gradle/gradle.properties.bak",
		"/home/user/.gradle/gradle.properties~",
	}

	// Exact paths a dedicated rule owns — carved out for the read tools, so
	// exactly ONE rule (the dedicated one) fires and its taxonomy is the only
	// node on the event. This is the original #3735 fix; assert it did not
	// regress alongside the variant fix.
	exactPypirc := "/home/user/.pypirc"

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

			// The regression: variants must BLOCK on every read tool.
			for _, path := range variantPaths {
				for _, tool := range readTools {
					res := eval.EvaluateToolCall(tool, map[string]interface{}{"path": path})
					if res.Decision != policy.DecisionBlock {
						t.Errorf("FAIL-OPEN: tool=%q path=%q decided %s, want BLOCK (rules=%v)\n"+
							"  a credential-file variant the dedicated globs do not cover must keep the catch-all's fallback",
							tool, path, res.Decision, res.TriggeredRules)
					}
				}
			}

			// The original double-fire fix: exact .pypirc + a read tool fires
			// exactly one rule with exactly one taxonomy node.
			res := eval.EvaluateToolCall("read_file", map[string]interface{}{"path": exactPypirc})
			if res.Decision != policy.DecisionBlock {
				t.Errorf("exact .pypirc read decided %s, want BLOCK", res.Decision)
			}
			if got := len(res.AllTaxonomyRefs()); got != 1 {
				t.Errorf("exact .pypirc read carried %d taxonomy nodes %v, want exactly 1 — the double-fire fix regressed",
					got, res.AllTaxonomyRefs())
			}
			if len(res.TriggeredRules) != 1 {
				t.Errorf("exact .pypirc read fired %d rules %v, want exactly 1 (mcp-sec-block-pypirc)",
					len(res.TriggeredRules), res.TriggeredRules)
			}
		})
	}
}
