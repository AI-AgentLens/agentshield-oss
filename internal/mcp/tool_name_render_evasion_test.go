package mcp

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// Non-ASCII is expressed numerically so this file stays ASCII-only: writing a
// literal confusable here trips AgentShield's own hook on every edit, and the
// repo convention is to build such fixtures from escapes.
const (
	cyrE   = rune(0x0435) // CYRILLIC SMALL LETTER IE  — renders as Latin 'e'
	cyrO   = rune(0x043E) // CYRILLIC SMALL LETTER O   — renders as Latin 'o'
	fwR    = rune(0xFF52) // FULLWIDTH LATIN SMALL LETTER R
	zeroW  = rune(0x200B) // ZERO WIDTH SPACE
	nbspCP = rune(0x00A0) // NO-BREAK SPACE
)

// renderEvasions are the spellings of a tool name that a host renders
// identically (or invisibly differently) to the ASCII original, while the MCP
// server resolves them exactly as it declared them.
var asciiToConfusable = map[rune]rune{
	'a': rune(0x0430), 'e': rune(0x0435), 'o': rune(0x043E), 'p': rune(0x0440),
	'c': rune(0x0441), 'x': rune(0x0445), 'i': rune(0x0456), 's': rune(0x0455),
}

// subConfusable replaces the first ASCII letter that has a rendering-identical
// Cyrillic counterpart. Rune-wise, never byte-wise: the mutated name must stay
// valid UTF-8, or the "bypass" is just a malformed fixture.
func subConfusable(s string) string {
	rs := []rune(s)
	for i, r := range rs {
		if c, ok := asciiToConfusable[r]; ok {
			rs[i] = c
			return string(rs)
		}
	}
	return s
}

func subFullwidth(s string) string {
	rs := []rune(s)
	for i, r := range rs {
		if r >= 'a' && r <= 'z' {
			rs[i] = r - 'a' + rune(0xFF41)
			return string(rs)
		}
	}
	return s
}

func insertZeroWidth(s string) string {
	rs := []rune(s)
	if len(rs) < 2 {
		return s
	}
	return string(rs[:1]) + string(zeroW) + string(rs[1:])
}

func nbspSeparator(s string) string {
	return strings.Replace(s, "_", string(nbspCP), 1)
}

// renderEvasions are the spellings of a tool name that a host renders
// identically (or invisibly differently) to the ASCII original, while the MCP
// server resolves them exactly as it declared them.
var renderEvasions = []struct {
	name string
	fn   func(string) string
}{
	{"cyrillic-confusable", subConfusable},
	{"fullwidth", subFullwidth},
	{"zero-width-insert", insertZeroWidth},
	{"nbsp-separator", nbspSeparator},
	{"combined-axes", func(s string) string {
		return insertZeroWidth(nbspSeparator(subConfusable(s)))
	}},
}

func renderEvasionEvaluator(t *testing.T) *PolicyEvaluator {
	t.Helper()
	base, _, err := LoadEmbeddedMCPPacks(DefaultMCPPolicy())
	if err != nil {
		t.Fatalf("embedded packs: %v", err)
	}
	merged, _, err := LoadMCPPacks("../../packs/premium/mcp", base)
	if err != nil {
		t.Fatalf("premium packs: %v", err)
	}
	return NewPolicyEvaluator(merged)
}

// TestToolNameRenderEvasionParity is the fitness function for the tool-name
// fold. An MCP tool name is the one identifier the ATTACKER both declares and
// resolves, so a rendering-identical spelling costs nothing — unlike a
// homoglyph in a shell word, which simply fails to execute.
//
// Every row asserts its ASCII control BLOCKs first: a row whose control is
// silent is NOT MEASURED, not clean.
func TestToolNameRenderEvasionParity(t *testing.T) {
	e := renderEvasionEvaluator(t)

	controls := []struct {
		tool string
		args map[string]interface{}
	}{
		{"read_file", map[string]interface{}{"path": "/home/user/.ssh/id_rsa"}},
		{"write_file", map[string]interface{}{"path": "/home/user/.ssh/authorized_keys", "content": "x"}},
		{"execute_command", map[string]interface{}{"command": "id"}},
		{"terraform_apply", map[string]interface{}{"auto_approve": true}},
	}

	for _, c := range controls {
		c := c
		t.Run(c.tool, func(t *testing.T) {
			base := e.EvaluateToolCall(c.tool, c.args)
			if base.Decision != "BLOCK" {
				t.Fatalf("CONTROL %q evaluated %s, want BLOCK — a row whose control is silent measures nothing",
					c.tool, base.Decision)
			}
			for _, ev := range renderEvasions {
				mutated := ev.fn(c.tool)
				if mutated == c.tool {
					t.Fatalf("%s: mutation did not change %q — pick a control that exercises this axis", ev.name, c.tool)
				}
				if !utf8.ValidString(mutated) {
					t.Fatalf("%s: mutation produced invalid UTF-8 for %q", ev.name, c.tool)
				}
				got := e.EvaluateToolCall(mutated, c.args)
				// Assert the CONTROL'S OWN rules fired, not merely that
				// something did. mcp-agentic-block-tool-name-render-evasion
				// blocks any mixed-script name outright, so a bare
				// Decision=="BLOCK" assertion would stay green even if the
				// fold regressed completely — verified by mutation.
				if !sharesRule(base.TriggeredRules, got.TriggeredRules) {
					t.Errorf("%s: EvaluateToolCall(%+q) = %s via %v, want the control's own rules %v to still fire",
						ev.name, mutated, got.Decision, got.TriggeredRules, base.TriggeredRules)
				}
			}
		})
	}
}

// TestToolNameRenderEvasionCorpusRatchet sweeps every shipped rule's own TP
// fixtures. Only the strongest axis is swept: this package already sits near
// its CI timeout (#3158) and the per-axis rows above cover the rest.
func TestToolNameRenderEvasionCorpusRatchet(t *testing.T) {
	e := renderEvasionEvaluator(t)

	combined := renderEvasions[len(renderEvasions)-1]

	denom, leaked := 0, 0
	examples := []string{}
	// One fixture per (rule, tool name): the mutation touches only the NAME, so
	// re-running the same rule against the same name with different arguments
	// measures the same thing again. Deduping keeps every rule/name path and
	// keeps this package inside its CI timeout (#3158).
	seen := map[string]bool{}
	for _, r := range e.policy.Rules {
		if r.Tests == nil {
			continue
		}
		for _, tc := range r.Tests.TP {
			if tc.Tool == "" || seen[r.ID+"\x00"+tc.Tool] {
				continue
			}
			seen[r.ID+"\x00"+tc.Tool] = true
			args, err := tc.ResolvedArgs()
			if err != nil {
				continue
			}
			base := e.EvaluateToolCall(tc.Tool, args)
			if base.Decision != "BLOCK" {
				continue
			}
			mutated := combined.fn(tc.Tool)
			if mutated == tc.Tool {
				continue
			}
			denom++
			// Same discrimination as the parity rows: the control's own rules
			// must still fire, not just any rule.
			if got := e.EvaluateToolCall(mutated, args); !sharesRule(base.TriggeredRules, got.TriggeredRules) {
				leaked++
				if len(examples) < 8 {
					examples = append(examples, fmt.Sprintf("  [%s] %q -> %+q blocked by %v",
						r.ID, tc.Tool, mutated, base.TriggeredRules))
				}
			}
		}
	}

	// Vacuity guard: a sweep that measured nothing must not read as clean.
	if denom < 900 {
		t.Fatalf("only %d BLOCKing fixtures were mutable — the sweep is vacuous, not clean", denom)
	}
	t.Logf("combined-axes: %d/%d leaked over %d BLOCKing fixtures", leaked, denom, denom)
	for _, ex := range examples {
		t.Log(ex)
	}
	if leaked != 0 {
		t.Errorf("%d/%d BLOCKing tool calls downgraded under a rendering-identical tool name", leaked, denom)
	}
}

// TestToolNameFormsExcludesNegativePredicates pins the asymmetry: a positive
// predicate gets the recovered form, a negative one must not. Folding an
// exclusion widens it, so a confusable-spelled name would start satisfying a
// carve-out and switch the rule OFF — the inversion of this fix.
func TestToolNameFormsExcludesNegativePredicates(t *testing.T) {
	name := string(cyrE) + "xecute_command"

	forms := toolNameForms(name)
	if len(forms) != 2 || forms[0] != name {
		t.Fatalf("toolNameForms(%+q) = %+q, want [wire, recovered] with the wire form first", name, forms)
	}
	if forms[1] != "execute_command" {
		t.Errorf("recovered form = %q, want %q", forms[1], "execute_command")
	}

	// The exclusion path compiles the same regex but must consult the wire
	// name only. Assert that directly against the raw name, which is what
	// semantic.go's ToolNameRegexExclude and ToolNameNotPrefixAny do.
	re := regexp.MustCompile("^execute_")
	if re.MatchString(name) {
		t.Fatal("precondition: the confusable name must not match the exclusion pattern raw")
	}
	if !toolNameRegexMatches(re, name) {
		t.Error("toolNameRegexMatches should match the recovered form — that is the positive path")
	}
	if len(toolNameForms("execute_command")) != 1 {
		t.Error("an ASCII name must produce exactly one form (no allocation on the hot path)")
	}
}

// TestToolNameRenderFoldFPBoundary pins that folding does not invent matches
// for names that merely happen to be non-ASCII. Recovery maps confusables onto
// the Latin letters they impersonate; a script with no Latin lookalike is left
// alone, so a genuinely localized tool name is unaffected.
func TestToolNameRenderFoldFPBoundary(t *testing.T) {
	e := renderEvasionEvaluator(t)

	benign := []struct {
		label string
		tool  string
	}{
		// Japanese: "file_read" — no confusable maps into ASCII.
		{"japanese", string([]rune{0x30D5, 0x30A1, 0x30A4, 0x30EB, 0x8AAD, 0x307F, 0x8FBC, 0x307F})},
		// Cyrillic word with no Latin homoglyph run ("chitat" spelled in
		// letters that do not impersonate Latin).
		{"cyrillic-word", string([]rune{0x0447, 0x0438, 0x0442, 0x0430, 0x0442, 0x044C})},
		// Ordinary ASCII tools that must stay benign.
		{"ascii-benign", "list_directory"},
		{"ascii-benign-2", "get_weather"},
	}
	args := map[string]interface{}{"path": "/workspace/project/README.md"}
	for _, b := range benign {
		got := e.EvaluateToolCall(b.tool, args)
		if got.Decision == "BLOCK" {
			t.Errorf("%s: EvaluateToolCall(%+q) = BLOCK via %v, want no block — folding must not invent matches",
				b.label, b.tool, got.TriggeredRules)
		}
	}
}

func TestPatternTargetsNonASCII(t *testing.T) {
	cases := []struct {
		pattern string
		want    bool
	}{
		{`^(insert|add)_(message|turn)$`, false},
		{`(?i)^read_`, false},
		{`[A-Za-z0-9_][\x{0400}-\x{04FF}]`, true},
		{`\p{Cyrillic}`, true},
		{`\P{L}`, true},
		{"literal-" + string(cyrE), true},
		// A bare \x escape without braces is an ASCII byte escape, not a
		// Unicode class — must not disable the recovered form.
		{`\x41bc`, false},
	}
	for _, c := range cases {
		if got := patternTargetsNonASCII(c.pattern); got != c.want {
			t.Errorf("patternTargetsNonASCII(%q) = %v, want %v", c.pattern, got, c.want)
		}
	}
}

// sharesRule reports whether got contains at least one rule id from want.
func sharesRule(want, got []string) bool {
	set := make(map[string]bool, len(got))
	for _, id := range got {
		set[id] = true
	}
	for _, id := range want {
		if set[id] {
			return true
		}
	}
	return false
}

// --------------------------------------------------------------------------
// Argument NAMES are the same surface as tool names, for the same reason: the
// server declares the parameter in its inputSchema, the model fills that key,
// and the server reads it back. An unresolved field makes matchRule return
// false — the rule does not fire at all.
// --------------------------------------------------------------------------

func renameKeys(args map[string]interface{}, fn func(string) string) (map[string]interface{}, bool) {
	out := make(map[string]interface{}, len(args))
	changed := false
	for k, v := range args {
		nk := fn(k)
		if nk != k {
			changed = true
		}
		out[nk] = v
	}
	return out, changed
}

// TestArgNameRenderEvasionParity sweeps every shipped rule's own TP fixtures,
// renaming the argument keys. As with the tool-name rows, a leak is "the
// control's own rules stopped firing", not merely "the decision dropped".
func TestArgNameRenderEvasionParity(t *testing.T) {
	e := renderEvasionEvaluator(t)

	// One axis, not three: all three reach the corpus through the same
	// normalizeFieldName / classifyArgNames pair, so sweeping each would
	// measure the same thing three times at ~57s a pass in a package already
	// near its CI timeout (#3158). The per-axis breadth is carried by the
	// cheap tool-name rows above, which share the recovery helper.
	for _, m := range []struct {
		name string
		fn   func(string) string
	}{
		{"combined-axes", func(s string) string { return insertZeroWidth(subConfusable(s)) }},
	} {
		m := m
		t.Run(m.name, func(t *testing.T) {
			denom, leaked := 0, 0
			examples := []string{}
			seen := map[string]bool{}
			for _, r := range e.policy.Rules {
				if r.Tests == nil {
					continue
				}
				for _, tc := range r.Tests.TP {
					if tc.Tool == "" || seen[r.ID+"\x00"+tc.Tool] {
						continue
					}
					args, err := tc.ResolvedArgs()
					if err != nil || len(args) == 0 {
						continue
					}
					base := e.EvaluateToolCall(tc.Tool, args)
					if base.Decision != "BLOCK" {
						continue
					}
					mutated, changed := renameKeys(args, m.fn)
					if !changed {
						continue
					}
					seen[r.ID+"\x00"+tc.Tool] = true
					denom++
					if got := e.EvaluateToolCall(tc.Tool, mutated); !sharesRule(base.TriggeredRules, got.TriggeredRules) {
						leaked++
						if len(examples) < 6 {
							examples = append(examples, fmt.Sprintf("  [%s] tool=%q %v -> %v", r.ID, tc.Tool, base.TriggeredRules, got.TriggeredRules))
						}
					}
				}
			}
			if denom < 900 {
				t.Fatalf("only %d BLOCKing fixtures had renamable arguments — the sweep is vacuous, not clean", denom)
			}
			t.Logf("%s: %d/%d leaked", m.name, leaked, denom)
			for _, ex := range examples {
				t.Log(ex)
			}
			if leaked != 0 {
				t.Errorf("%d/%d BLOCKing tool calls lost their rule under a rendering-identical argument name", leaked, denom)
			}
		})
	}
}

// TestArgNameRenderEvasionFPBoundary pins that folding argument names does not
// start resolving keys that merely happen to be non-ASCII onto rule fields.
func TestArgNameRenderEvasionFPBoundary(t *testing.T) {
	e := renderEvasionEvaluator(t)

	// Japanese key name: recovery leaves it alone, so it must not resolve as
	// "path" and pull the value into a credential-path rule.
	jpKey := string([]rune{0x30D1, 0x30B9}) // "pasu"
	got := e.EvaluateToolCall("read_file", map[string]interface{}{jpKey: "/home/user/.ssh/id_rsa"})
	if got.Decision == "BLOCK" {
		t.Errorf("EvaluateToolCall with key %+q = BLOCK via %v; folding must not invent field resolutions",
			jpKey, got.TriggeredRules)
	}

	// And the ASCII control still resolves, so the row above is not vacuous.
	ctl := e.EvaluateToolCall("read_file", map[string]interface{}{"path": "/home/user/.ssh/id_rsa"})
	if ctl.Decision != "BLOCK" {
		t.Fatalf("CONTROL read_file(path=<ssh key>) = %s, want BLOCK", ctl.Decision)
	}
}

// TestNumericArgResolutionFallback pins the one argument lookup that used a
// direct map index and so skipped the whole resolution ladder — a value_limits
// cap was the only predicate a renamed parameter could still walk past.
func TestNumericArgResolutionFallback(t *testing.T) {
	args := map[string]interface{}{string(cyrO) + "unt": 42.0}
	if _, ok := extractNumericArg(args, "ount"); !ok {
		t.Error("extractNumericArg should resolve a confusable-spelled key through resolveField")
	}
	if v, ok := extractNumericArg(map[string]interface{}{"amount": "1500"}, "amount"); !ok || v != 1500 {
		t.Errorf("exact string-typed lookup regressed: got %v, %v", v, ok)
	}
	if _, ok := extractNumericArg(map[string]interface{}{"amount": 1.0}, "quantity"); ok {
		t.Error("an absent key must stay absent")
	}
}
