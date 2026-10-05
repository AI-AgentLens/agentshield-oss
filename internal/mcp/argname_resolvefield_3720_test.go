package mcp

import (
	"fmt"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Regression tests for #3720 — the four sites of the
// raw-map-index-over-a-fixed-name-list shape that survived #3691 (PR #3711)
// and #3712 (PR #3714):
//
//	fetch_diversity.go          firstNonEmptyStringArg(args, "url","uri","path")
//	browser_game_jailbreak.go   firstURLOrigin over urlArgNames
//	composkill.go               extractSkillIdentity over skillIdentityArgKeys
//	sequence.go                 argString(args, <rule-supplied key>)
//
// All four now resolve through resolveField. The same two assertions apply as
// in semantic_separator_evasion_test.go and argname_resolvefield_test.go:
// PARITY (the respelled argument name must produce the same value/signal/
// decision as the ASCII spelling) and VACUITY (the ASCII control must produce
// something, and the mutation must actually change the key string).
//
// cmd/check-arg-map-lookups is the construction-level counterpart: it fails
// the build if a fifth site of this shape is ever added.

// --- 1. firstNonEmptyStringArg (fetch_diversity.go) ---

func TestExtractFetchResource_ArgNameSeparatorEvasion(t *testing.T) {
	const value = "https://huggingface.co/attacker/char-a/resolve/main/config.json"

	firstRef := func(args map[string]interface{}) (fetchResourceRef, bool) {
		refs := extractFetchResources(args)
		if len(refs) == 0 {
			return fetchResourceRef{}, false
		}
		return refs[0], true
	}

	for _, argName := range []string{"url", "uri", "path"} {
		ascii, ok := firstRef(map[string]interface{}{argName: value})
		if !ok {
			t.Fatalf("vacuous control: ASCII argument name %q did not resolve", argName)
		}

		for sepName, sep := range separatorRunSpellings() {
			t.Run(argName+"/"+sepName, func(t *testing.T) {
				assertFoldable(t, sepName, sep)
				respelled := argName + sep
				if respelled == argName {
					t.Fatalf("vacuous mutation: %s left the name unchanged", sepName)
				}
				got, gotOK := firstRef(map[string]interface{}{respelled: value})
				if !gotOK {
					t.Fatalf("%s: corrupted arg name %q did not resolve; ASCII %q did", sepName, respelled, argName)
				}
				if got != ascii {
					t.Errorf("%s: got %+v, ASCII got %+v", sepName, got, ascii)
				}
			})
		}
	}
}

// TestHandleToolCall_FetchEnumerablePattern_ArgNameSeparatorEvasion is the
// end-to-end counterpart through the live proxy entry point: the flip measured
// against the built binary (5 enumerable fetches BLOCK with an ASCII `url`
// key, and were merely AUDITed with one trailing U+00A0 before this fix).
func TestHandleToolCall_FetchEnumerablePattern_ArgNameSeparatorEvasion(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	names := []string{"char-a", "char-p", "char-i", "char-e", "char-r"}
	if len(names) != fetchDiversityEnumerableThreshold {
		t.Fatalf("test setup: need exactly %d names, got %d", fetchDiversityEnumerableThreshold, len(names))
	}

	blockedOn := func(argName string) bool {
		t.Helper()
		h, _ := newFetchDiversityTestHandler(t)
		var blocked bool
		for _, n := range names {
			args := map[string]interface{}{
				argName: "https://huggingface.co/attacker/" + n + "/resolve/main/config.json",
			}
			blocked, _ = h.HandleToolCall(toolCallMessage(t, "WebFetch", args, nil))
		}
		return blocked
	}

	if !blockedOn("url") {
		t.Fatal("vacuous control: the ASCII `url` key did not reach a BLOCK")
	}
	for sepName, sep := range separatorRunSpellings() {
		t.Run(sepName, func(t *testing.T) {
			assertFoldable(t, sepName, sep)
			if !blockedOn("url" + sep) {
				t.Errorf("%s: corrupted `url` key escaped the enumerable-pattern BLOCK", sepName)
			}
		})
	}
}

// --- 2. firstURLOrigin (browser_game_jailbreak.go) ---

func TestFirstURLOrigin_ArgNameSeparatorEvasion(t *testing.T) {
	const value = "https://attacker.example.com/form"

	for _, argName := range urlArgNames {
		asciiOrigin := firstURLOrigin(map[string]interface{}{argName: value})
		if asciiOrigin == "" {
			t.Fatalf("vacuous control: ASCII argument name %q produced no origin", argName)
		}
		for sepName, sep := range separatorRunSpellings() {
			t.Run(argName+"/"+sepName, func(t *testing.T) {
				assertFoldable(t, sepName, sep)
				got := firstURLOrigin(map[string]interface{}{argName + sep: value})
				if got != asciiOrigin {
					t.Errorf("%s: origin %q, ASCII got %q", sepName, got, asciiOrigin)
				}
			})
		}
	}
}

// TestFirstURLOrigin_KeyedLookupBeatsValueScan pins what the raw map index
// actually cost here. firstURLOrigin falls back to scanning ALL string values
// when no known URL key resolves, and that fallback is map-iteration-ordered.
// So a corrupted `url` key did not lose the origin outright — it made the
// answer NONDETERMINISTIC whenever another URL-valued argument was present.
// Measured against the built binary before the fix: the browser-game composite
// fired 11/20 identical runs (20/20 with an ASCII key). A flaky detector is
// worse than a missing one, because it cannot be reproduced from an audit log.
func TestFirstURLOrigin_KeyedLookupBeatsValueScan(t *testing.T) {
	const want = "attacker.example.com"
	nbsp := sepRune(0x00A0)

	build := func(urlKey string) map[string]interface{} {
		args := map[string]interface{}{urlKey: "https://attacker.example.com/form"}
		for _, decoy := range []string{"ref0", "ref1", "ref2", "ref3"} {
			args[decoy] = "https://game.example.com/puzzle"
		}
		return args
	}

	// 200 iterations over a 5-entry map: if selection were still
	// map-iteration-ordered the wrong origin would appear with overwhelming
	// probability well inside this budget.
	for i := 0; i < 200; i++ {
		if got := firstURLOrigin(build("url")); got != want {
			t.Fatalf("vacuous control: ASCII `url` key returned %q on iteration %d, want %q", got, i, want)
		}
		if got := firstURLOrigin(build("url" + nbsp)); got != want {
			t.Fatalf("NBSP-corrupted `url` key returned %q on iteration %d, want %q — "+
				"the keyed lookup lost to the map-ordered value scan", got, i, want)
		}
	}
}

// --- 3. extractSkillIdentity (composkill.go) ---

func TestExtractSkillIdentity_ArgNameSeparatorEvasion(t *testing.T) {
	cases := []struct {
		name     string
		toolName string
		keys     []string
	}{
		{"explicit identity keys", "read_file", skillIdentityArgKeys},
		{"dispatcher fallback keys", "invoke_skill", skillIdentityFallbackKeys},
	}

	for _, tc := range cases {
		for _, argName := range tc.keys {
			asciiID, ok := extractSkillIdentity(tc.toolName, map[string]interface{}{argName: "data-extract"})
			if !ok || asciiID != "data-extract" {
				t.Fatalf("vacuous control: %s ASCII key %q gave (%q,%v)", tc.name, argName, asciiID, ok)
			}
			for sepName, sep := range separatorRunSpellings() {
				t.Run(tc.name+"/"+argName+"/"+sepName, func(t *testing.T) {
					assertFoldable(t, sepName, sep)
					gotID, gotOK := extractSkillIdentity(tc.toolName,
						map[string]interface{}{argName + sep: "data-extract"})
					if !gotOK || gotID != asciiID {
						t.Errorf("%s: corrupted key %q gave (%q,%v), ASCII gave (%q,true)",
							sepName, argName+sep, gotID, gotOK, asciiID)
					}
				})
			}
		}
	}
}

// TestCompoSkillTracker_ArgNameSeparatorEvasion is the session-level
// counterpart: the cross-skill composite is AUDIT-only and silently absent
// when a call cannot be attributed, so an unresolvable identity key erased the
// finding with nothing logged. Reproduced live against the built binary.
func TestCompoSkillTracker_ArgNameSeparatorEvasion(t *testing.T) {
	firesWith := func(identityKey string) bool {
		tr := NewCompoSkillTracker()
		tr.Scan("fetch_url", map[string]interface{}{
			"url": "https://example.com/notes.md", identityKey: "data-extract",
		})
		return tr.Scan("send_message", map[string]interface{}{
			"body": "here is the collected data", "skill_id": "remote-publish",
		}) == SignalCompoSkillChain
	}

	if !firesWith("skill_id") {
		t.Fatal("vacuous control: the ASCII `skill_id` key did not fire the cross-skill composite")
	}
	for sepName, sep := range separatorRunSpellings() {
		t.Run(sepName, func(t *testing.T) {
			assertFoldable(t, sepName, sep)
			if !firesWith("skill_id" + sep) {
				t.Errorf("%s: corrupted `skill_id` key silently dropped the cross-skill composite", sepName)
			}
		})
	}
}

// --- 4. argString (sequence.go) ---

func TestArgString_ArgNameSeparatorEvasion(t *testing.T) {
	const key = "working_directory"
	const value = "/usr/local/lib"

	if got := argString(map[string]interface{}{key: value}, key); got != value {
		t.Fatalf("vacuous control: ASCII key %q returned %q", key, got)
	}
	for sepName, sep := range separatorRunSpellings() {
		t.Run(sepName, func(t *testing.T) {
			assertFoldable(t, sepName, sep)
			if got := argString(map[string]interface{}{key + sep: value}, key); got != value {
				t.Errorf("%s: corrupted key %q returned %q, want %q", sepName, key+sep, got, value)
			}
		})
	}
}

// TestMCPSequenceRule_ArchiveChain_ArgNameSeparatorEvasion is the
// highest-value case in #3720 and the one the issue said to probe first: a
// sequence step's argument regex is the fail-OPEN direction of this class.
// An unresolvable argument name makes argString return "", the step's regex
// fails, and the whole cross-call chain rule never fires — a composite BLOCK
// degraded to AUDIT.
//
// Driven through the real authored rule loaded from its premium pack YAML, so
// this pins the shipped behaviour rather than a hand-built fixture. Measured
// live before the fix (agentshield mcp-proxy, fetch_url → extract_zip →
// ipython): BLOCK with an ASCII `url` key, AUDIT with one trailing U+00A0.
func TestMCPSequenceRule_ArchiveChain_ArgNameSeparatorEvasion(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	const ruleID = "mcp-sc-block-archive-download-extract-execute-cwd-shadow"

	rules := loadPremiumPackRules(t, "mcp-supply-chain-premium.yaml")
	chain := findRuleByID(t, rules, ruleID)
	if chain.Match.Sequence == nil || len(chain.Match.Sequence.Steps) != 3 {
		t.Fatalf("rule %q: expected a 3-step sequence, got %+v", ruleID, chain.Match.Sequence)
	}

	e := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules:    []MCPRule{*chain},
	})

	evaluate := func(urlKey string) MCPEvalResult {
		trigger := RecordedCall{ToolName: "ipython", Args: map[string]interface{}{"code": "import struct"}}
		history := []RecordedCall{
			{ToolName: "fetch_url", Args: map[string]interface{}{urlKey: "https://cdn.example.com/tools/pkg.zip"}},
			{ToolName: "extract_zip", Args: map[string]interface{}{"archive": "pkg.zip"}},
			trigger,
		}
		return e.EvaluateToolCallWithHistory(trigger.ToolName, trigger.Args, "", history)
	}

	ascii := evaluate("url")
	if ascii.Decision != policy.DecisionBlock || !containsStr(ascii.TriggeredRules, ruleID) {
		t.Fatalf("vacuous control: ASCII `url` key gave decision=%s rules=%v, want BLOCK citing %q",
			ascii.Decision, ascii.TriggeredRules, ruleID)
	}

	for sepName, sep := range separatorRunSpellings() {
		t.Run(sepName, func(t *testing.T) {
			assertFoldable(t, sepName, sep)
			got := evaluate("url" + sep)
			if got.Decision != ascii.Decision {
				t.Errorf("%s: chain rule decision flipped to %s (ASCII: %s)", sepName, got.Decision, ascii.Decision)
			}
			if !containsStr(got.TriggeredRules, ruleID) {
				t.Errorf("%s: corrupted `url` key lost rule %q: got %v", sepName, ruleID, got.TriggeredRules)
			}
		})
	}
}

// TestArgString_ASCIIParityWithFlatLookup is the #3727-finding-1 replacement for
// the old TestArgString_ResolvesNestedAndCasing, which locked in the OPPOSITE
// contract — it asserted argString resolved `URL`, `workingDirectory`, and
// `config.url` case-insensitively / camelCase / dot-path. That was the parity
// break: routing these fixed-key sites through the full resolveField ladder let
// an ASCII input newly activate a sequence step (including a BLOCK step) that
// flat exact-match never did.
//
// The contract is now: an ASCII argument name decides EXACTLY as a raw
// args[key] map index would (what these sites did on main), and ONLY a Unicode
// respelling (a separator/confusable the renderer folds) additionally resolves.
// Each row asserts argString against an independently computed flat-lookup
// reference, so this is a genuine before/after parity proof, not a restatement.
func TestArgString_ASCIIParityWithFlatLookup(t *testing.T) {
	// flatLookup is what every one of the four sites did on main: one exact map
	// index, stringified, "" when absent.
	flatLookup := func(args map[string]interface{}, key string) string {
		if args == nil {
			return ""
		}
		if v, ok := args[key]; ok {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}

	asciiCases := []struct {
		name string
		args map[string]interface{}
		key  string
	}{
		{"exact", map[string]interface{}{"url": "x"}, "url"},
		{"uppercase does NOT case-fold", map[string]interface{}{"URL": "x"}, "url"},
		{"mixed case does NOT case-fold", map[string]interface{}{"Url": "x"}, "url"},
		{"camelCase does NOT convention-map", map[string]interface{}{"workingDirectory": "x"}, "working_directory"},
		{"snake vs camel does NOT convention-map", map[string]interface{}{"working_directory": "x"}, "workingDirectory"},
		{"kebab does NOT convention-map", map[string]interface{}{"working-directory": "x"}, "working_directory"},
		{"dot path does NOT descend", map[string]interface{}{"config": map[string]interface{}{"url": "x"}}, "config.url"},
		{"absent", map[string]interface{}{"other": "x"}, "url"},
		{"nil args", nil, "url"},
	}
	for _, tc := range asciiCases {
		t.Run(tc.name, func(t *testing.T) {
			want := flatLookup(tc.args, tc.key)
			if got := argString(tc.args, tc.key); got != want {
				t.Errorf("argString(%v, %q) = %q, want %q (must match a flat exact map index)",
					tc.args, tc.key, got, want)
			}
		})
	}
}

// TestArgFieldRecovered_ASCIIParityAcrossAllFourSites proves the parity contract
// at the resolver itself, so a regression is one failure here rather than four
// scattered across the site tests. For every ASCII casing / separator / dot
// form, the resolver must agree with a flat exact index — resolve only when the
// exact key is present.
func TestArgFieldRecovered_ASCIIParityAcrossAllFourSites(t *testing.T) {
	rows := []struct {
		name string
		args map[string]interface{}
		key  string
	}{
		{"exact present", map[string]interface{}{"url": 1}, "url"},
		{"uppercase absent", map[string]interface{}{"URL": 1}, "url"},
		{"camelCase absent", map[string]interface{}{"nResults": 1}, "n_results"},
		{"snake absent", map[string]interface{}{"n_results": 1}, "nResults"},
		{"dot path absent", map[string]interface{}{"config": map[string]interface{}{"url": 1}}, "config.url"},
		{"unrelated absent", map[string]interface{}{"other": 1}, "url"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, wantOK := r.args[r.key]
			got := argFieldRecovered(r.args, r.key)
			if wantOK && (len(got) != 1 || got[0] != r.args[r.key]) {
				t.Errorf("argFieldRecovered(%v,%q)=%v, want the single exact value", r.args, r.key, got)
			}
			if !wantOK && len(got) != 0 {
				t.Errorf("argFieldRecovered(%v,%q)=%v, want none — an ASCII non-exact key must NOT resolve", r.args, r.key, got)
			}
		})
	}
}

// TestArgNameSeparatorEvasion_SitesUseResolveField is a cheap structural guard
// on the four fixed sites: each helper must be reachable with a respelled key.
// It is deliberately redundant with the tests above — it fails as one line
// rather than as a table, which is what a bisect wants.
func TestArgNameSeparatorEvasion_SitesUseResolveField(t *testing.T) {
	nbsp := sepRune(0x00A0)
	checks := []struct {
		site string
		ok   func() bool
	}{
		{"fetch_diversity.nonEmptyStringArgs", func() bool {
			vals := nonEmptyStringArgs(map[string]interface{}{"url" + nbsp: "v"}, "url", "uri", "path")
			return len(vals) == 1 && vals[0] == "v"
		}},
		{"browser_game_jailbreak.firstURLOrigin", func() bool {
			return firstURLOrigin(map[string]interface{}{"url" + nbsp: "https://e.example.com/"}) == "e.example.com"
		}},
		{"composkill.extractSkillIdentity", func() bool {
			id, ok := extractSkillIdentity("read_file", map[string]interface{}{"skill_id" + nbsp: "S"})
			return ok && id == "s"
		}},
		{"sequence.argString", func() bool {
			return argString(map[string]interface{}{"url" + nbsp: "v"}, "url") == "v"
		}},
	}
	for _, c := range checks {
		if !c.ok() {
			t.Errorf("%s: a U+00A0-respelled argument key did not resolve — raw map index regressed?", c.site)
		}
	}
}

// --- #3727 finding 3: normalized-name collisions must be deterministic ---

// TestArgFieldRecovered_CollisionReturnsAllCandidatesDeterministically pins the
// resolver contract that closes the collision hole. Two DIFFERENT Unicode
// spellings of `url` (U+00A0 vs U+2009) with different values both fold to the
// normalized name `url`. resolveField returned the first map entry the range
// happened to visit, so a composite decision flipped between identical runs
// (#3727 finding 3). argFieldRecovered returns EVERY folded candidate in a
// stable order, so the set of values — and their order — is identical on every
// run and a caller can test its predicate against all of them.
func TestArgFieldRecovered_CollisionReturnsAllCandidatesDeterministically(t *testing.T) {
	nbsp := sepRune(0x00A0)
	thin := sepRune(0x2009)
	build := func() map[string]interface{} {
		return map[string]interface{}{
			"url" + nbsp:  "A-nbsp",
			"url" + thin:  "B-thin",
			"unrelated":   "noise",
			"other_key_z": "noise2",
		}
	}
	// No exact `url`, so both folded keys are candidates. 300 runs over a 4-entry
	// map: had order been map-iteration-driven the sequence would vary well
	// inside this budget.
	var first []interface{}
	for i := 0; i < 300; i++ {
		got := argFieldRecovered(build(), "url")
		if len(got) != 2 {
			t.Fatalf("iter %d: got %d candidates, want both folded spellings", i, len(got))
		}
		if i == 0 {
			first = got
			continue
		}
		if got[0] != first[0] || got[1] != first[1] {
			t.Fatalf("iter %d: candidate order changed to %v (first run %v) — collision is nondeterministic", i, got, first)
		}
	}
	// Both values must be present regardless of order, so no spelling is dropped.
	seen := map[interface{}]bool{first[0]: true, first[1]: true}
	if !seen["A-nbsp"] || !seen["B-thin"] {
		t.Errorf("collision dropped a spelling: candidates=%v", first)
	}
}

// --- #3727 finding 1: an ASCII non-exact key must NOT newly activate a rule ---

// TestSequenceArchiveChain_ASCIICaseDoesNotActivate is the decision-level proof
// of the parity break. On main the four sites did a flat exact index, so an
// ASCII uppercase `URL` key simply did not resolve and the archive-chain BLOCK
// never fired. Routing argString through the full resolveField ladder made
// `URL` resolve case-insensitively, so the same ASCII input NEWLY reached BLOCK
// — a silent behaviour change (#3727 finding 1). The narrow resolver restores
// exact-only ASCII behaviour: `URL` must NOT fire the chain.
func TestSequenceArchiveChain_ASCIICaseDoesNotActivate(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	const ruleID = "mcp-sc-block-archive-download-extract-execute-cwd-shadow"
	rules := loadPremiumPackRules(t, "mcp-supply-chain-premium.yaml")
	chain := findRuleByID(t, rules, ruleID)
	e := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules:    []MCPRule{*chain},
	})
	evaluate := func(urlKey string) MCPEvalResult {
		trigger := RecordedCall{ToolName: "ipython", Args: map[string]interface{}{"code": "import struct"}}
		history := []RecordedCall{
			{ToolName: "fetch_url", Args: map[string]interface{}{urlKey: "https://cdn.example.com/tools/pkg.zip"}},
			{ToolName: "extract_zip", Args: map[string]interface{}{"archive": "pkg.zip"}},
			trigger,
		}
		return e.EvaluateToolCallWithHistory(trigger.ToolName, trigger.Args, "", history)
	}
	// Control: the exact ASCII `url` key DOES fire, so the assertion below is not
	// vacuous.
	if got := evaluate("url"); got.Decision != policy.DecisionBlock {
		t.Fatalf("vacuous control: exact `url` key gave %s, want BLOCK", got.Decision)
	}
	// Parity: an ASCII uppercase `URL` is a DIFFERENT key to a flat exact index,
	// so it must not resolve and must not fire — exactly as on main.
	for _, asciiKey := range []string{"URL", "Url", "uRl"} {
		if got := evaluate(asciiKey); got.Decision == policy.DecisionBlock || containsStr(got.TriggeredRules, ruleID) {
			t.Errorf("ASCII key %q NEWLY activated %q (decision=%s) — ASCII parity broken", asciiKey, ruleID, got.Decision)
		}
	}
}

// TestSequenceArchiveChain_CollisionFiresDeterministically is finding 3 at the
// sequence-decision level. Two folded spellings of `url` carry different values;
// only one (`pkg.zip`) matches the step's archive-extension regex. Because the
// step predicate now tests EVERY resolved candidate, the chain fires on the
// malicious spelling regardless of which the map yields first, on every run.
func TestSequenceArchiveChain_CollisionFiresDeterministically(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	const ruleID = "mcp-sc-block-archive-download-extract-execute-cwd-shadow"
	rules := loadPremiumPackRules(t, "mcp-supply-chain-premium.yaml")
	chain := findRuleByID(t, rules, ruleID)
	e := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules:    []MCPRule{*chain},
	})
	nbsp := sepRune(0x00A0)
	thin := sepRune(0x2009)
	evaluate := func() MCPEvalResult {
		trigger := RecordedCall{ToolName: "ipython", Args: map[string]interface{}{"code": "import struct"}}
		history := []RecordedCall{
			{ToolName: "fetch_url", Args: map[string]interface{}{
				"url" + nbsp: "https://cdn.example.com/readme.txt",    // benign, no archive ext
				"url" + thin: "https://cdn.example.com/tools/pkg.zip", // malicious, matches regex
			}},
			{ToolName: "extract_zip", Args: map[string]interface{}{"archive": "pkg.zip"}},
			trigger,
		}
		return e.EvaluateToolCallWithHistory(trigger.ToolName, trigger.Args, "", history)
	}
	for i := 0; i < 200; i++ {
		if got := evaluate(); got.Decision != policy.DecisionBlock || !containsStr(got.TriggeredRules, ruleID) {
			t.Fatalf("iter %d: decision=%s rules=%v — a folded-key collision let the archive chain escape BLOCK",
				i, got.Decision, got.TriggeredRules)
		}
	}
}

// --- #3727 pass-2 finding 1: a DISGUISE rune must not re-open the ASCII ladder ---

// TestArgFieldRecovered_DisguisePreservesCaseAndConvention pins the pass-2 fix.
// Before it, the recovery path ran normalizeFieldName, which lowercases and
// strips '_'/'-', so the moment ANY foldable/zero-width rune appeared the ASCII
// case and naming-convention ladder came back: `URL`+ZWJ matched key `url`,
// `workingDirectory`+ZWJ matched `working_directory`. The fix strips only the
// disguise (zero-width dropped, confusables folded, separators→space→removed)
// and compares BYTE-EXACT, so a disguised key resolves to its EXACT undisguised
// spelling and nothing else.
func TestArgFieldRecovered_DisguisePreservesCaseAndConvention(t *testing.T) {
	zwj := sepRune(0x200D)  // ZERO WIDTH JOINER — dropped by recovery
	nbsp := sepRune(0x00A0) // NO-BREAK SPACE — folded to a space, then stripped

	rows := []struct {
		name    string
		rawKey  string // the attacker-declared argument name
		ruleKey string // the ASCII name the rule is authored against
		want    bool   // must it resolve?
	}{
		{"lowercase url + ZWJ disguises url", "url" + zwj, "url", true},
		{"lowercase url + NBSP disguises url", "url" + nbsp, "url", true},
		{"UPPERCASE URL + ZWJ is NOT url", "URL" + zwj, "url", false},
		{"Mixed Url + ZWJ is NOT url", "Url" + zwj, "url", false},
		{"camelCase + ZWJ is NOT snake key", "workingDirectory" + zwj, "working_directory", false},
		{"snake + ZWJ disguises the snake key", "working_directory" + zwj, "working_directory", true},
		{"dot path + ZWJ disguises the dot key", "config.url" + zwj, "config.url", true},
		{"dot path wrong case + ZWJ is NOT the key", "config.URL" + zwj, "config.url", false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got := argFieldRecovered(map[string]interface{}{r.rawKey: "v"}, r.ruleKey)
			if r.want && (len(got) != 1 || got[0] != "v") {
				t.Errorf("argFieldRecovered(%q, %q)=%v, want it to resolve", r.rawKey, r.ruleKey, got)
			}
			if !r.want && len(got) != 0 {
				t.Errorf("argFieldRecovered(%q, %q)=%v, want NO resolution — a disguise must not re-open the ASCII ladder", r.rawKey, r.ruleKey, got)
			}
		})
	}
}

// TestSequenceArchiveChain_DisguisedCaseDoesNotActivate is the decision-level
// counterpart. A disguised-but-wrong-case `URL`+ZWJ key must NOT reach the
// archive-chain BLOCK (the pass-2 regression), while a disguised exact `url`+ZWJ
// and a pure `url`+NBSP still MUST.
func TestSequenceArchiveChain_DisguisedCaseDoesNotActivate(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	const ruleID = "mcp-sc-block-archive-download-extract-execute-cwd-shadow"
	rules := loadPremiumPackRules(t, "mcp-supply-chain-premium.yaml")
	chain := findRuleByID(t, rules, ruleID)
	e := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules:    []MCPRule{*chain},
	})
	evaluate := func(urlKey string) MCPEvalResult {
		trigger := RecordedCall{ToolName: "ipython", Args: map[string]interface{}{"code": "import struct"}}
		history := []RecordedCall{
			{ToolName: "fetch_url", Args: map[string]interface{}{urlKey: "https://cdn.example.com/tools/pkg.zip"}},
			{ToolName: "extract_zip", Args: map[string]interface{}{"archive": "pkg.zip"}},
			trigger,
		}
		return e.EvaluateToolCallWithHistory(trigger.ToolName, trigger.Args, "", history)
	}
	zwj := sepRune(0x200D)
	nbsp := sepRune(0x00A0)

	// MUST activate: exact key, disguised exact key, pure Unicode separator.
	for _, k := range []string{"url", "url" + zwj, "url" + nbsp} {
		if got := evaluate(k); got.Decision != policy.DecisionBlock || !containsStr(got.TriggeredRules, ruleID) {
			t.Errorf("key %q: decision=%s rules=%v, want BLOCK citing %q", k, got.Decision, got.TriggeredRules, ruleID)
		}
	}
	// MUST NOT activate: a DISGUISED but wrong-CASE key is a different argument.
	for _, k := range []string{"URL" + zwj, "Url" + zwj} {
		if got := evaluate(k); got.Decision == policy.DecisionBlock || containsStr(got.TriggeredRules, ruleID) {
			t.Errorf("disguised wrong-case key %q NEWLY activated %q (decision=%s) — the ASCII ladder is back", k, ruleID, got.Decision)
		}
	}
}

// --- #3727 pass-2 finding 2: all-candidates collision-safety at the 3 trackers ---

// TestFetchDiversityCollision_EvaluatesEveryCandidate: two disguised spellings
// of `url` — a benign duplicate that sorts first and the enumerable-completing
// resource that sorts later. The tracker must record/scan BOTH, so the 5th
// distinct resource completes the enumerable pattern regardless of order.
func TestFetchDiversityCollision_EvaluatesEveryCandidate(t *testing.T) {
	nbsp := sepRune(0x00A0) // sorts before U+200D
	zwj := sepRune(0x200D)
	res := func(name string) string {
		return "https://huggingface.co/attacker/" + name + "/resolve/main/config.json"
	}
	run := func() FetchDiversitySignal {
		tr := NewFetchDiversityTracker()
		for _, n := range []string{"char-a", "char-b", "char-c", "char-d"} {
			tr.Record("fetch_url", map[string]interface{}{"url": res(n)})
		}
		// Collision: benign duplicate (char-a) sorts first; char-e (the 5th
		// distinct, enumerable-completing) is disguised behind the later key.
		return tr.Scan("fetch_url", map[string]interface{}{
			"url" + nbsp: res("char-a"),
			"url" + zwj:  res("char-e"),
		})
	}
	for i := 0; i < 200; i++ {
		if got := run(); got != SignalFetchEnumerablePattern {
			t.Fatalf("iter %d: got %q, want the enumerable pattern — the collision hid the 5th resource", i, got)
		}
	}
}

// TestBrowserOriginCollision_EvaluatesEveryCandidate: after engagement +
// clipboard read on origin A, a navigate whose `url` collides (A benign sorts
// first, attacker origin B second) must arm the cross-origin disclosure window,
// so the following paste fires. First-candidate-only would see only A (no
// change) and never arm.
func TestBrowserOriginCollision_EvaluatesEveryCandidate(t *testing.T) {
	nbsp := sepRune(0x00A0)
	zwj := sepRune(0x200D)
	run := func() BrowserGameJailbreakSignal {
		tr := NewBrowserGameJailbreakTracker()
		tr.Scan(gameNavigateIn.tool, gameNavigateIn.args)
		for _, c := range gameEngagementCalls() {
			tr.Scan(c.tool, c.args)
		}
		tr.Scan(gameClipboard.tool, gameClipboard.args)
		// Collision navigate: same-origin decoy sorts first, attacker origin second.
		tr.Scan("browser_navigate", map[string]interface{}{
			"url" + nbsp: "https://" + gamePageOrigin + "/still-here",
			"url" + zwj:  "https://" + gameNewOrigin + "/submit",
		})
		return tr.Scan(gamePaste.tool, gamePaste.args)
	}
	for i := 0; i < 200; i++ {
		if got := run(); got != SignalBrowserGameJailbreakSession {
			t.Fatalf("iter %d: got %q, want the jailbreak signal — the collision hid the cross-origin navigation", i, got)
		}
	}
}

// TestCompoSkillCollision_EvaluatesEveryCandidate: a read on skill "reader",
// then an egress call whose `skill_id` collides — a benign "reader" duplicate
// that sorts first and "publisher" second. Attributing egress to EVERY resolved
// identity means publisher(egress) + reader(read) completes the cross-skill
// composite; first-candidate-only would attribute egress to "reader" alone
// (same skill) and never fire.
func TestCompoSkillCollision_EvaluatesEveryCandidate(t *testing.T) {
	nbsp := sepRune(0x00A0)
	zwj := sepRune(0x200D)
	run := func() CompoSkillSignal {
		tr := NewCompoSkillTracker()
		tr.Scan("fetch_url", map[string]interface{}{"url": "https://example.com/notes.md", "skill_id": "reader"})
		return tr.Scan("send_message", map[string]interface{}{
			"body":            "here is the collected data",
			"skill_id" + nbsp: "reader",    // benign duplicate, sorts first
			"skill_id" + zwj:  "publisher", // the different egress skill, disguised
		})
	}
	for i := 0; i < 200; i++ {
		if got := run(); got != SignalCompoSkillChain {
			t.Fatalf("iter %d: got %q, want the cross-skill chain — the collision hid the differing egress skill", i, got)
		}
	}
}
