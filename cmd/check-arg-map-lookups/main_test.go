package main

import (
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

// A gate ships with a test that makes it fail (CLAUDE.md, #3130). Every case
// below states the shape it is about in its own name, because a lint that
// silently stops flagging is indistinguishable from a clean tree.

func check(t *testing.T, src string) ([]Finding, []Exemption) {
	t.Helper()
	findings, exemptions, err := CheckSource("x.go", []byte("package mcp\n"+src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	return findings, exemptions
}

func TestFlagsFixedNameListIndexedIntoArgs(t *testing.T) {
	findings, _ := check(t, `
var urlArgNames = []string{"url", "uri"}

func firstURL(args map[string]interface{}) string {
	for _, k := range urlArgNames {
		if v, ok := args[k]; ok {
			return v.(string)
		}
	}
	return ""
}
`)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for args[k] over a fixed list, got %d: %+v", len(findings), findings)
	}
	if findings[0].Kind != "identifier key" {
		t.Errorf("kind = %q, want %q", findings[0].Kind, "identifier key")
	}
}

func TestFlagsStringLiteralKey(t *testing.T) {
	findings, _ := check(t, `
func hasPath(args map[string]interface{}) bool {
	_, ok := args["path"]
	return ok
}
`)
	if len(findings) != 1 || findings[0].Kind != "string literal key" {
		t.Fatalf("expected 1 string-literal finding, got %+v", findings)
	}
}

func TestFlagsRuleSuppliedKeyParameter(t *testing.T) {
	// sequence.go:197's shape — the key is a function parameter, not a member
	// of a fixed list. It is still a name that did not come from the map.
	findings, _ := check(t, `
func argString(args map[string]interface{}, key string) string {
	if v, ok := args[key]; ok {
		return v.(string)
	}
	return ""
}
`)
	if len(findings) != 1 {
		t.Fatalf("expected the rule-supplied-key shape to be flagged, got %+v", findings)
	}
}

func TestFlagsArgsFieldSelector(t *testing.T) {
	findings, _ := check(t, `
type RecordedCall struct{ Args map[string]interface{} }

func get(call RecordedCall, key string) interface{} {
	return call.Args[key]
}
`)
	if len(findings) != 1 {
		t.Fatalf("expected call.Args[key] to be flagged, got %+v", findings)
	}
}

func TestFlagsAliasOfAnArgumentsMap(t *testing.T) {
	// The naming heuristic must not be defeated by one assignment.
	findings, _ := check(t, `
type params struct{ Arguments map[string]interface{} }

func get(p params) interface{} {
	a := p.Arguments
	return a["url"]
}
`)
	if len(findings) != 1 {
		t.Fatalf("expected an alias of an arguments map to be flagged, got %+v", findings)
	}
}

func TestIgnoresSelfIterationOverTheSameMap(t *testing.T) {
	// hasPayloadArg's shape. Enumerating the map's OWN keys visits a respelled
	// key under its own spelling, so nothing can be missed.
	findings, _ := check(t, `
func hasPayload(args map[string]interface{}) bool {
	for k := range args {
		if v, ok := args[k]; ok && v != nil {
			return true
		}
	}
	return false
}
`)
	if len(findings) != 0 {
		t.Fatalf("self-iteration over the args map must not be flagged, got %+v", findings)
	}
}

func TestFlagsIterationOverADifferentMap(t *testing.T) {
	// The mirror image of the case above: the key came from somewhere else, so
	// the exemption must not apply just because a range statement is in scope.
	findings, _ := check(t, `
func lookup(args map[string]interface{}, wanted map[string]bool) interface{} {
	for k := range wanted {
		if v, ok := args[k]; ok {
			return v
		}
	}
	return nil
}
`)
	if len(findings) != 1 {
		t.Fatalf("indexing args by another map's key must be flagged, got %+v", findings)
	}
}

func TestIgnoresWrites(t *testing.T) {
	// handler.go:967 / types.go:638. Building a map resolves nothing.
	findings, _ := check(t, `
func copyArgs(args map[string]interface{}) map[string]interface{} {
	newArgs := make(map[string]interface{}, len(args))
	for k, v := range args {
		newArgs[k] = v
	}
	newArgs["method"] = "POST"
	return newArgs
}
`)
	if len(findings) != 0 {
		t.Fatalf("writes must not be flagged, got %+v", findings)
	}
}

func TestIgnoresResolveField(t *testing.T) {
	findings, _ := check(t, `
func firstURL(args map[string]interface{}, keys []string) interface{} {
	for _, k := range keys {
		if v, ok := resolveField(args, k); ok {
			return v
		}
	}
	return nil
}
`)
	if len(findings) != 0 {
		t.Fatalf("a resolveField lookup must not be flagged, got %+v", findings)
	}
}

func TestIgnoresNonArgumentMaps(t *testing.T) {
	// schema_walk.go's shape: a JSON Schema document indexed by SCHEMA
	// KEYWORDS. Respelling `properties` buys an attacker nothing, because
	// nothing downstream then treats it as `properties` either.
	findings, _ := check(t, `
func walk(node map[string]interface{}) interface{} {
	if props, ok := node["properties"]; ok {
		return props
	}
	for _, kw := range []string{"allOf", "anyOf"} {
		if v, ok := node[kw]; ok {
			return v
		}
	}
	return nil
}
`)
	if len(findings) != 0 {
		t.Fatalf("JSON Schema traversal must not be flagged, got %+v", findings)
	}
}

// TestFlagsNormalizedComputedIndex is #3727 pass-2 finding 3(a): a normalized
// INDEX is no longer exempt. Normalizing the lookup key (args[normalizeFieldName(key)])
// does not normalize the STORED key, so it still misses a disguised key — the
// only correct mitigation is a resolver CALL, not an index.
func TestFlagsNormalizedComputedIndex(t *testing.T) {
	findings, _ := check(t, `
func get(args map[string]interface{}, key string) interface{} {
	return args[normalizeFieldName(key)]
}
`)
	if len(findings) != 1 || findings[0].Kind != "computed key" {
		t.Fatalf("a normalized INDEX must be flagged (a resolver CALL is the fix), got %+v", findings)
	}
}

func TestExemptionNeedsAReason(t *testing.T) {
	withReason, exempt := check(t, `
func hasPath(args map[string]interface{}) bool {
	// argmaplookup:allow presence probe only
	_, ok := args["path"]
	return ok
}
`)
	if len(withReason) != 0 || len(exempt) != 1 {
		t.Fatalf("a directive with a reason must exempt: findings=%+v exemptions=%+v", withReason, exempt)
	}
	if !strings.Contains(exempt[0].Reason, "presence probe") {
		t.Errorf("reason = %q, want it to carry the stated justification", exempt[0].Reason)
	}

	bare, _ := check(t, `
func hasPath(args map[string]interface{}) bool {
	// argmaplookup:allow
	_, ok := args["path"]
	return ok
}
`)
	if len(bare) != 1 {
		t.Fatalf("a bare directive with no reason must NOT exempt, got %+v", bare)
	}
}

func TestExemptionOnTheSameLine(t *testing.T) {
	findings, exempt := check(t, `
func hasPath(args map[string]interface{}) bool {
	_, ok := args["path"] // argmaplookup:allow presence probe only
	return ok
}
`)
	if len(findings) != 0 || len(exempt) != 1 {
		t.Fatalf("a trailing directive must exempt: findings=%+v exemptions=%+v", findings, exempt)
	}
}

func TestExemptionDoesNotLeakToTheNextLookup(t *testing.T) {
	findings, exempt := check(t, `
func two(args map[string]interface{}) (interface{}, interface{}) {
	// argmaplookup:allow the first one only
	a := args["one"]
	b := args["two"]
	return a, b
}
`)
	if len(exempt) != 1 || len(findings) != 1 {
		t.Fatalf("a directive must cover one lookup: findings=%+v exemptions=%+v", findings, exempt)
	}
	if !strings.Contains(findings[0].Expr, `"two"`) {
		t.Errorf("wrong lookup exempted; still-flagged expr = %q", findings[0].Expr)
	}
}

func TestSkipsTestFiles(t *testing.T) {
	vulnerable := `package mcp

func firstURL(args map[string]interface{}, keys []string) interface{} {
	for _, k := range keys {
		if v, ok := args[k]; ok {
			return v
		}
	}
	return nil
}
`
	fsys := fstest.MapFS{
		"pkg/a_test.go": &fstest.MapFile{Data: []byte(vulnerable)},
		"pkg/a.go":      &fstest.MapFile{Data: []byte("package mcp\n")},
	}
	findings, _, err := Check(fsys, "pkg")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("_test.go files must be skipped, got %+v", findings)
	}
}

// TestCheckFailsOnAThrowawayVulnerableFile is the positive control for the
// gate as a whole, driven through Check (directory walk) rather than
// CheckSource: drop one file with the shape into a package and the gate goes
// red.
func TestCheckFailsOnAThrowawayVulnerableFile(t *testing.T) {
	fsys := fstest.MapFS{
		"pkg/clean.go": &fstest.MapFile{Data: []byte("package mcp\n")},
		"pkg/bad.go": &fstest.MapFile{Data: []byte(`package mcp

var skillIdentityArgKeys = []string{"skill_id", "skill_name"}

func identity(args map[string]interface{}) (string, bool) {
	for _, k := range skillIdentityArgKeys {
		if s, ok := args[k].(string); ok {
			return s, true
		}
	}
	return "", false
}
`)},
	}
	findings, _, err := Check(fsys, "pkg")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the throwaway vulnerable file to fail the gate, got %+v", findings)
	}
	if findings[0].File != "pkg/bad.go" {
		t.Errorf("finding attributed to %q, want pkg/bad.go", findings[0].File)
	}
}

func TestCheckRefusesAVacuousPass(t *testing.T) {
	// A directory with no files must be an error, not "OK — 0 findings".
	// Same shape as the vacuous-probe traps in CLAUDE.md.
	fsys := fstest.MapFS{"pkg/.keep": &fstest.MapFile{Data: []byte("")}}
	if _, _, err := Check(fsys, "empty"); err == nil {
		t.Fatal("scanning a missing directory must error, not report a clean pass")
	}
}

// pinnedExemption identifies one allowed raw lookup by BOTH its file and its
// exact index expression. Collapsing the ratchet to map[file]bool (the
// pre-#3727 shape) let a FOURTH argmaplookup:allow added to an already-approved
// file pass unnoticed: the map keys were unchanged (#3727 finding 5). Pinning by
// (file, expr) and asserting the exact count closes that.
type pinnedExemption struct {
	File, Expr, Why string
}

// expectedExemptions is the entire escape hatch. Growing it must be a visible
// edit here — a new (file, expr) row — reviewed for the reason it is correct.
var expectedExemptions = []pinnedExemption{
	{"internal/mcp/argfield_recover.go", "args[key]", "exact fast path of argFieldRecovered (exact-then-render-recovery)"},
	{"internal/mcp/sequence.go", "call.Args[arg]", "ArgumentNotContains — negative predicate"},
	{"internal/mcp/structural.go", `arguments["method"]`, "method presence probe before synthesis"},
}

// ratchetViolations compares the exemptions the gate actually found against the
// pinned set, returning one message per divergence (empty == exactly the
// expected set, no more, no fewer, none duplicated). Factored out so the live
// ratchet and its self-test drive the SAME logic.
func ratchetViolations(got []Exemption, expected []pinnedExemption) []string {
	var msgs []string

	type key struct{ file, expr string }
	wantCount := map[key]int{}
	for _, e := range expected {
		wantCount[key{e.File, e.Expr}]++
	}
	gotCount := map[key]int{}
	for _, e := range got {
		if strings.TrimSpace(e.Reason) == "" {
			msgs = append(msgs, e.File+": exemption with no reason")
		}
		gotCount[key{e.File, e.Expr}]++
	}

	if len(got) != len(expected) {
		msgs = append(msgs, "exemption count "+itoa(len(got))+" != expected "+itoa(len(expected))+
			" — a new argmaplookup:allow (even a duplicate in an approved file) must be pinned in expectedExemptions or removed")
	}
	for k, want := range wantCount {
		if gotCount[k] < want {
			msgs = append(msgs, "expected exemption missing: "+k.file+" "+k.expr+" — was the site fixed? remove its row")
		}
	}
	for k, n := range gotCount {
		want := wantCount[k]
		if n > want {
			msgs = append(msgs, "unexpected exemption: "+k.file+" "+k.expr+
				" — add it to expectedExemptions with the reason it is correct, or fix the site")
		}
	}
	return msgs
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// TestLiveTreeHasNoUnexcusedLookups is the ratchet. internal/mcp must stay at
// zero findings, and its exemptions must be EXACTLY the pinned set — same file,
// same expression, same count.
func TestLiveTreeHasNoUnexcusedLookups(t *testing.T) {
	root := os.DirFS("../..")
	findings, exemptions, err := Check(root, "internal/mcp")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	for _, f := range findings {
		t.Errorf("unexcused raw arguments-map lookup: %s:%d %s (%s)", f.File, f.Line, f.Expr, f.Kind)
	}
	for _, m := range ratchetViolations(exemptions, expectedExemptions) {
		t.Error(m)
	}
}

// TestRatchetRejectsSecondExemptionInApprovedFile is finding 5's own falsifier:
// a SECOND exemption added to an already-approved file (a different expression,
// so map[file]bool would still hold the same keys) must fail the ratchet.
func TestRatchetRejectsSecondExemptionInApprovedFile(t *testing.T) {
	// Start from the exact pinned set, then add a fourth exemption in
	// sequence.go — an approved file — with a NEW expression.
	got := make([]Exemption, 0, len(expectedExemptions)+1)
	for _, e := range expectedExemptions {
		got = append(got, Exemption{File: e.File, Expr: e.Expr, Reason: e.Why})
	}
	got = append(got, Exemption{
		File:   "internal/mcp/sequence.go",
		Expr:   `call.Args["extra"]`,
		Reason: "a plausible-looking but unreviewed second exemption",
	})

	msgs := ratchetViolations(got, expectedExemptions)
	if len(msgs) == 0 {
		t.Fatal("a second exemption in an approved file must fail the ratchet, but ratchetViolations reported none")
	}

	// And a duplicate of an APPROVED expression (same file+expr) must also fail,
	// via the exact-count assertion — the map-of-bools shape would have missed
	// this too.
	dup := append([]Exemption{}, got[:len(expectedExemptions)]...)
	dup = append(dup, Exemption{File: "internal/mcp/structural.go", Expr: `arguments["method"]`, Reason: "duplicate"})
	if len(ratchetViolations(dup, expectedExemptions)) == 0 {
		t.Error("a duplicate exemption of an approved expression must fail the exact-count assertion")
	}
}

// --- #3727 finding 4: the three false-negative bypasses, each must now flag ---

func TestFlagsComputedConcatKey(t *testing.T) {
	// args["u"+"rl"] is a computed index; before #3727 every computed index was
	// skipped, so the exact vulnerable shape could be reconstructed from pieces.
	findings, _ := check(t, `
func firstURL(args map[string]interface{}) interface{} {
	return args["u"+"rl"]
}
`)
	if len(findings) != 1 || findings[0].Kind != "computed key" {
		t.Fatalf("expected 1 computed-key finding for a concatenated index, got %+v", findings)
	}
}

func TestFlagsComputedCallKey(t *testing.T) {
	// args[key()] hides the key behind an unrecognised call. Only a recognised
	// normalizer (normalizeFieldName) may be trusted to close the class.
	findings, _ := check(t, `
func firstURL(args map[string]interface{}) interface{} {
	return args[key()]
}
`)
	if len(findings) != 1 || findings[0].Kind != "computed key" {
		t.Fatalf("expected 1 computed-key finding for a call index, got %+v", findings)
	}
}

func TestFlagsComputedToLowerKeyIsNotNormalization(t *testing.T) {
	// strings.ToLower folds case but not separators, so it does NOT close the
	// Unicode-separator class — it must be flagged, unlike normalizeFieldName.
	findings, _ := check(t, `
func firstURL(args map[string]interface{}, key string) interface{} {
	return args[strings.ToLower(key)]
}
`)
	if len(findings) != 1 || findings[0].Kind != "computed key" {
		t.Fatalf("expected strings.ToLower(key) to be flagged as computed, got %+v", findings)
	}
}

func TestFlagsPassThroughLookupHelper(t *testing.T) {
	// A generic lookup helper whose map is a NON-args-named map[string]any
	// parameter, indexed by a key parameter — the shape that let a caller route
	// a fixed-key lookup through an indirection the gate did not see (#3727 4b).
	findings, _ := check(t, `
func lookup(m map[string]any, k string) any {
	return m[k]
}
`)
	if len(findings) != 1 || findings[0].Kind != "identifier key" {
		t.Fatalf("expected the pass-through lookup helper to be flagged, got %+v", findings)
	}
}

func TestPassThroughHelperLiteralAndRangeKeysStayClean(t *testing.T) {
	// The mirror image, guarding against a false positive: a non-args-named
	// map[string]any indexed by a LITERAL or by a range variable is JSON-Schema
	// traversal, not the class, and must NOT be flagged even though the map is a
	// bare parameter now in scope.
	findings, _ := check(t, `
func walk(node map[string]any) interface{} {
	if props, ok := node["properties"]; ok {
		return props
	}
	for _, kw := range []string{"allOf", "anyOf"} {
		if v, ok := node[kw]; ok {
			return v
		}
	}
	return nil
}
`)
	if len(findings) != 0 {
		t.Fatalf("schema traversal over a bare map param must stay clean, got %+v", findings)
	}
}

func TestSelfIterationDoesNotMaskAnEarlierDifferentMapLoop(t *testing.T) {
	// #3727 finding 4c: a SAFE `for k := range args` appearing LATER in the
	// function must not excuse an EARLIER vulnerable `for k := range names {
	// args[k] }` that reuses the key name `k`. Function-wide range collection
	// matched the two by name alone and reported this file clean.
	findings, _ := check(t, `
func f(args map[string]interface{}, names map[string]bool) interface{} {
	for k := range names {
		if v, ok := args[k]; ok {
			return v
		}
	}
	for k := range args {
		_ = k
	}
	return nil
}
`)
	if len(findings) != 1 || findings[0].Kind != "identifier key" {
		t.Fatalf("expected the vulnerable different-map loop to be flagged despite a later self-iteration, got %+v", findings)
	}
}

func TestLexicalSelfIterationStillExemptsGenuineSelfIteration(t *testing.T) {
	// The positive control for the lexical change: a genuine self-iteration is
	// still recognised (the index is inside the range body over that map).
	findings, _ := check(t, `
func hasPayload(args map[string]interface{}) bool {
	for k := range args {
		if v, ok := args[k]; ok && v != nil {
			return true
		}
	}
	return false
}
`)
	if len(findings) != 0 {
		t.Fatalf("a genuine self-iteration must stay exempt, got %+v", findings)
	}
}

// --- #3727 pass-2 finding 3: three more lint bypasses, each must now flag ---

func TestFlagsAliasedKeyIntoHelperMap(t *testing.T) {
	// `k := key; m[k]` — the key parameter is copied to a local before the index.
	// Tracking the single-hop alias keeps the pass-through lookup helper flagged.
	findings, _ := check(t, `
func lookup(m map[string]any, key string) any {
	k := key
	return m[k]
}
`)
	if len(findings) != 1 || findings[0].Kind != "identifier key" {
		t.Fatalf("an aliased key into a helper map must be flagged, got %+v", findings)
	}
}

func TestFlagsArgsMapOnANonStandardStructField(t *testing.T) {
	// A map carried on a struct field named args-like but NOT exactly
	// Args/Arguments (.RawArgs) is still an arguments map — the .Args-only
	// selector match used to miss it.
	findings, _ := check(t, `
type call struct{ RawArgs map[string]interface{} }

func get(c call, key string) interface{} {
	return c.RawArgs[key]
}
`)
	if len(findings) != 1 {
		t.Fatalf("an arguments map on a .RawArgs field must be flagged, got %+v", findings)
	}
}

func TestIgnoresCacheKeyedByToolNameOnAStructField(t *testing.T) {
	// The false-positive guard for the finding-3 selector change: a cache or
	// registry keyed by a string parameter, carried on a NON-args-like struct
	// field (.cache, .SentinelRules), must NOT be flagged — those are the shapes
	// that appear in the live tree (tool_description_cache.go, policy.go).
	findings, _ := check(t, `
type cacheT struct{ cache map[string]interface{}; SentinelRules map[string]interface{} }

func (c *cacheT) get(toolName string, engine string) interface{} {
	if v, ok := c.cache[toolName]; ok {
		return v
	}
	return c.SentinelRules[engine]
}
`)
	if len(findings) != 0 {
		t.Fatalf("a cache/registry keyed by a string param on a non-args-like field must stay clean, got %+v", findings)
	}
}

func TestFlagsLookupThroughATypeAssertion(t *testing.T) {
	// #3740 finding 4: `args.(map[string]interface{})[key]`. The indexed
	// expression is a TypeAssertExpr, not an Ident or a SelectorExpr, so the
	// gate used to walk straight past the one shape that needs no local at all.
	// The lookup-helper shape `m := args.(map[string]any); m[key]` was already
	// flagged through the alias pass — dropping the local must not launder it.
	findings, _ := check(t, `
func lookup(args interface{}, key string) interface{} {
	return args.(map[string]interface{})[key]
}
`)
	if len(findings) != 1 || findings[0].Kind != "identifier key" {
		t.Fatalf("a lookup through a type assertion on an args-like operand must be flagged, got %+v", findings)
	}
}

func TestFlagsLookupThroughATypeAssertionOnAnArgsField(t *testing.T) {
	// The same shape with the assertion on a struct field: `c.RawArgs` is
	// args-like by the convention isArgsMapExpr already uses for selectors.
	findings, _ := check(t, `
type call struct{ RawArgs interface{} }

func get(c call, key string) interface{} {
	return c.RawArgs.(map[string]any)[key]
}
`)
	if len(findings) != 1 {
		t.Fatalf("a type-asserted args-like field indexed by a key parameter must be flagged, got %+v", findings)
	}
}

func TestIgnoresTypeAssertionOnNonArgsOperands(t *testing.T) {
	// The false-positive guard for the finding-4 change. Two shapes that must
	// stay clean: a JSON-Schema node asserted to a map and indexed by a keyword
	// (the schema_walk.go family), and an args-like operand asserted to a type
	// that is NOT an arguments map.
	findings, _ := check(t, `
func walk(node interface{}, kw string) interface{} {
	return node.(map[string]interface{})[kw]
}

func nth(args interface{}, i int) interface{} {
	return args.([]interface{})[i]
}
`)
	if len(findings) != 0 {
		t.Fatalf("non-args type assertions must stay clean, got %+v", findings)
	}
}
