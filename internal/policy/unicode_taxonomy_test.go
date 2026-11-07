package policy

import (
	"reflect"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// Issue #4560: the built-in unicode-zero-width BLOCK carries the taxonomy node
// Gary approved for it, so its receipt attests a control instead of none. The
// mapping is evidence only: decision, rule ids, reasons and the audit-only
// downgrade must be exactly what they were without it.

const zeroWidthNode = "unauthorized-execution/agentic-attacks/invisible-unicode-prompt-injection"

// The test inputs are assembled from code points, never written as literal
// invisible characters: a literal one in source is unreviewable, and this repo
// dogfoods AgentShield.
var (
	zwSpace     = string(rune(0x200B)) // ZERO WIDTH SPACE
	rtlOverride = string(rune(0x202E)) // RIGHT-TO-LEFT OVERRIDE
	cyrillicA   = string(rune(0x0430)) // CYRILLIC SMALL LETTER A
	zwCommand   = "echo hel" + zwSpace + "lo"
	zwWithUfw   = "ufw disable; echo hel" + zwSpace + "lo"
	bidiCmd     = "echo abc" + rtlOverride + "def"
	homoglyphC  = "echo c" + cyrillicA + "fe"
)

func shippedEngine(t *testing.T) *Engine {
	t.Helper()
	merged, _, err := LoadEmbeddedShellPacks(DefaultPolicy())
	if err != nil {
		t.Fatalf("LoadEmbeddedShellPacks: %v", err)
	}
	engine, err := NewEngineWithAnalyzers(merged, 0)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	return engine
}

// bareEngine has no rules and no analyzer registry, so the only thing that
// can decide is a built-in intercept. That isolates the built-ins from pack
// rules and guardian signals that may cite a node for the same input.
func bareEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := NewEngine(&Policy{Version: "0.1", Defaults: Defaults{Decision: DecisionAllow}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func evalCmd(e *Engine, command string) EvalResult {
	n := normalize.NormalizeCommand(command, "")
	return e.EvaluateWithParsedCwd(command, n.Paths, n.Parsed, "")
}

func hasRule(rules []string, want string) bool {
	for _, r := range rules {
		if r == want {
			return true
		}
	}
	return false
}

// TestUnicodeZeroWidthBlock_CarriesInvisibleUnicodeNode is the contract: a
// zero-width BLOCK records exactly the approved node, on the shipped pipeline
// and on a rule-less engine where the built-in alone decides.
func TestUnicodeZeroWidthBlock_CarriesInvisibleUnicodeNode(t *testing.T) {
	for name, engine := range map[string]*Engine{
		"shipped packs + analyzers": shippedEngine(t),
		"built-in only":             bareEngine(t),
	} {
		t.Run(name, func(t *testing.T) {
			r := evalCmd(engine, zwCommand)
			if r.Decision != DecisionBlock {
				t.Fatalf("decision = %s, want BLOCK (rules=%v)", r.Decision, r.TriggeredRules)
			}
			if !hasRule(r.TriggeredRules, "unicode-zero-width") {
				t.Fatalf("rules = %v, want unicode-zero-width among them", r.TriggeredRules)
			}
			if want := []string{zeroWidthNode}; !reflect.DeepEqual(r.TaxonomyRefs, want) {
				t.Errorf("taxonomy = %v, want exactly %v", r.TaxonomyRefs, want)
			}
		})
	}
}

// TestUnicodeZeroWidthBlock_EqualSeverityFoldKeepsPackNode covers the other
// branch of finish(): a pack BLOCK and the zero-width BLOCK at the same
// severity union their rule ids, so their nodes union too. The pack's own node
// must survive; the zero-width node is added once.
func TestUnicodeZeroWidthBlock_EqualSeverityFoldKeepsPackNode(t *testing.T) {
	engine := shippedEngine(t)

	alone := evalCmd(engine, "ufw disable")
	if alone.Decision != DecisionBlock || len(alone.TaxonomyRefs) == 0 {
		t.Fatalf("precondition: `ufw disable` alone = %s with taxonomy %v; want a BLOCK that cites a node", alone.Decision, alone.TaxonomyRefs)
	}

	r := evalCmd(engine, zwWithUfw)
	if r.Decision != DecisionBlock {
		t.Fatalf("decision = %s, want BLOCK (rules=%v)", r.Decision, r.TriggeredRules)
	}
	if !hasRule(r.TriggeredRules, "unicode-zero-width") || !hasRule(r.TriggeredRules, "ts-block-ufw-disable") {
		t.Fatalf("rules = %v, want both ts-block-ufw-disable and unicode-zero-width", r.TriggeredRules)
	}
	want := append(append([]string{}, alone.TaxonomyRefs...), zeroWidthNode)
	if !reflect.DeepEqual(r.TaxonomyRefs, want) {
		t.Errorf("taxonomy = %v, want %v (pack node kept, zero-width node added once)", r.TaxonomyRefs, want)
	}
}

// TestUnicodeZeroWidthBlock_AuditOnlyKeepsNode: audit-only records the BLOCK as
// AUDIT with OriginalDecision BLOCK, and the shadow block still attests.
func TestUnicodeZeroWidthBlock_AuditOnlyKeepsNode(t *testing.T) {
	engine := bareEngine(t)
	engine.SetMode("audit-only")
	r := evalCmd(engine, zwCommand)
	if r.Decision != DecisionAudit || r.OriginalDecision != DecisionBlock {
		t.Fatalf("decision = %s (original %s), want AUDIT (original BLOCK)", r.Decision, r.OriginalDecision)
	}
	if want := []string{zeroWidthNode}; !reflect.DeepEqual(r.TaxonomyRefs, want) {
		t.Errorf("taxonomy = %v, want exactly %v", r.TaxonomyRefs, want)
	}
}

// TestUnicodeBuiltins_OtherCategoriesCarryNoTaxonomy is the control: the
// exception is unicode-zero-width only. Another BLOCK-level Unicode built-in
// (bidi-override) and an AUDIT-level one (homoglyph-cyrillic) still record no
// node, on the same rule-less engine where zero-width records one.
func TestUnicodeBuiltins_OtherCategoriesCarryNoTaxonomy(t *testing.T) {
	engine := bareEngine(t)
	cases := []struct {
		name         string
		command      string
		wantDecision Decision
		wantRule     string
	}{
		{"bidi-override BLOCK", bidiCmd, DecisionBlock, "unicode-bidi-override"},
		{"homoglyph-cyrillic AUDIT", homoglyphC, DecisionAudit, "unicode-homoglyph-cyrillic"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := evalCmd(engine, tc.command)
			if r.Decision != tc.wantDecision {
				t.Fatalf("decision = %s, want %s (rules=%v)", r.Decision, tc.wantDecision, r.TriggeredRules)
			}
			if want := []string{tc.wantRule}; !reflect.DeepEqual(r.TriggeredRules, want) {
				t.Fatalf("rules = %v, want %v", r.TriggeredRules, want)
			}
			if len(r.TaxonomyRefs) != 0 {
				t.Errorf("taxonomy = %v, want none: only unicode-zero-width has an approved node (#4560)", r.TaxonomyRefs)
			}
		})
	}
}

// TestUnicodeTaxonomy_ChangesNoDecision proves the mapping is evidence only:
// with the table emptied, every input gets the same decision, original
// decision, rule ids and reasons, and the taxonomy differs by exactly the
// zero-width node.
func TestUnicodeTaxonomy_ChangesNoDecision(t *testing.T) {
	engines := map[string]*Engine{
		"shipped packs + analyzers": shippedEngine(t),
		"built-in only":             bareEngine(t),
	}
	commands := []string{zwCommand, zwWithUfw, bidiCmd, homoglyphC, "ufw disable", "ls -la"}

	type key struct{ engine, command string }
	with := map[key]EvalResult{}
	for en, e := range engines {
		for _, c := range commands {
			with[key{en, c}] = evalCmd(e, c)
		}
	}

	saved := unicodeTaxonomy
	unicodeTaxonomy = nil
	defer func() { unicodeTaxonomy = saved }()

	for en, e := range engines {
		for _, c := range commands {
			got, without := with[key{en, c}], evalCmd(e, c)
			if got.Decision != without.Decision || got.OriginalDecision != without.OriginalDecision ||
				!reflect.DeepEqual(got.TriggeredRules, without.TriggeredRules) ||
				!reflect.DeepEqual(got.Reasons, without.Reasons) {
				t.Errorf("%s / %q: the mapping changed the verdict: with = {%s %v %v}, without = {%s %v %v}",
					en, c, got.Decision, got.TriggeredRules, got.Reasons, without.Decision, without.TriggeredRules, without.Reasons)
			}
			wantTax := without.TaxonomyRefs
			if hasRule(got.TriggeredRules, "unicode-zero-width") {
				wantTax = append(append([]string{}, without.TaxonomyRefs...), zeroWidthNode)
			}
			if len(got.TaxonomyRefs) != len(wantTax) || (len(wantTax) > 0 && !reflect.DeepEqual(got.TaxonomyRefs, wantTax)) {
				t.Errorf("%s / %q: taxonomy = %v, want %v", en, c, got.TaxonomyRefs, wantTax)
			}
		}
	}
}

func TestAddUnicodeTaxonomy(t *testing.T) {
	if got := addUnicodeTaxonomy(nil, []string{"unicode-homoglyph-cyrillic"}); got != nil {
		t.Errorf("no mapped rule: got %v, want nil (byte-identical to the pre-#4560 reset)", got)
	}
	if got := addUnicodeTaxonomy(nil, []string{"unicode-zero-width", "unicode-zero-width"}); !reflect.DeepEqual(got, []string{zeroWidthNode}) {
		t.Errorf("repeated rule: got %v, want the node once", got)
	}
	in := make([]string, 1, 4)
	in[0] = "a/b/c"
	got := addUnicodeTaxonomy(in, []string{"unicode-zero-width"})
	if !reflect.DeepEqual(got, []string{"a/b/c", zeroWidthNode}) {
		t.Errorf("append: got %v", got)
	}
	if spare := in[:2]; spare[1] != "" {
		t.Errorf("wrote through the caller's backing array: %q", spare[1])
	}
}
