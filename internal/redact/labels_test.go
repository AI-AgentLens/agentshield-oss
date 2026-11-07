package redact

import (
	"encoding/json"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
	"github.com/AI-AgentLens/agentshield/internal/datalabel"
)

// #4813: secrets and data-label values are masked together, both found on the
// text as written. Every secret and label value in this file is assembled at
// runtime: AgentShield guards the machine it is written on and reads test
// sources as content.

// mainRedactArguments is RedactArguments as it was on main (c4458c7e),
// frozen, over plainRedact: the reference the refactor onto redactor is held
// to. Only the comments are dropped.
func mainRedactArguments(args map[string]interface{}) map[string]interface{} {
	return mainRedactObject("", args)
}

func mainRedactObject(parentKey string, args map[string]interface{}) map[string]interface{} {
	if args == nil {
		return nil
	}
	name, _ := args["name"].(string)
	out := make(map[string]interface{}, len(args))
	for k, v := range args {
		out[k] = mainRedactJSONValue(k, v, parentKey)
		if s, ok := v.(string); ok && k == "value" && name != "" {
			out[k] = mainRedactKeyedString(name, s)
		}
		if s, ok := out[k].(string); ok && s != redactedPlaceholder && parentKey != "" {
			if _, isStr := v.(string); isStr {
				out[k] = mainRedactKeyedString(parentKey, s)
			}
		}
	}
	return out
}

func mainRedactJSONValue(key string, v interface{}, parentKey string) interface{} {
	switch t := v.(type) {
	case string:
		return mainRedactKeyedString(key, t)
	case map[string]interface{}:
		return mainRedactObject(mainInheritedKey(key, parentKey), t)
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, e := range t {
			out[i] = mainRedactJSONValue(key, e, parentKey)
		}
		return out
	case float64, json.Number, int, int64:
		if mainInheritedKey(key, parentKey) != "" {
			return redactedPlaceholder
		}
		return v
	default:
		return v
	}
}

func mainInheritedKey(key, parentKey string) string {
	if key != "" && plainRedact(key+"=xxxxxxxxxxxxxxxxxxxxxxxxxxxx") != key+"=xxxxxxxxxxxxxxxxxxxxxxxxxxxx" {
		return key
	}
	return parentKey
}

func mainRedactKeyedString(key, value string) string {
	redacted := plainRedact(value)
	if key == "" {
		return redacted
	}
	if plainRedact(key+"="+value) != key+"="+redacted {
		return redactedPlaceholder
	}
	return redacted
}

// mainScrubTree is main's logger.scrubArguments: s over every string value,
// keys left alone.
func mainScrubTree(s func(string) string, v interface{}) interface{} {
	switch t := v.(type) {
	case string:
		return s(t)
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, e := range t {
			out[k] = mainScrubTree(s, e)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, e := range t {
			out[i] = mainScrubTree(s, e)
		}
		return out
	}
	return v
}

// argumentsOf wraps s in an MCP arguments object under every kind of key the
// walk judges differently: a plain key, a secret key, a k8s name/value pair,
// a secret parent key, and an array.
func argumentsOf(s string) map[string]interface{} {
	return map[string]interface{}{
		"content":       s,
		"pass" + "word": s,
		"env":           []interface{}{map[string]interface{}{"name": "DB_PASS" + "WORD", "value": s}},
		"nested":        map[string]interface{}{"to" + "ken": map[string]interface{}{"value": s}, "list": []interface{}{s, 3.0, true}},
		"n":             42.0,
	}
}

func jsonOf(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// noSpans is a scrubber that finds nothing: a host with labels, on a text no
// label matches.
func noSpans(string) []datalabel.Span { return nil }

// labelEngine compiles labels for a test.
func labelEngine(t testing.TB, labels ...datalabel.DataLabelConfig) *datalabel.Engine {
	t.Helper()
	e, err := datalabel.NewEngine(labels)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func custLabel() datalabel.DataLabelConfig {
	return datalabel.DataLabelConfig{ID: "customer-records", Patterns: []datalabel.PatternConfig{{Regex: `CUST-[0-9]{6}`}}}
}

func emailLabel() datalabel.DataLabelConfig {
	return datalabel.DataLabelConfig{ID: "email", Patterns: []datalabel.PatternConfig{{Regex: `[A-Za-z0-9._%+-]+@corp\.example\.com`}}}
}

// gate1Corpus is the redact prescan corpus (which carries the analyzer
// corpus) and the #4812 secret-value rules' TPs and TNs.
func gate1Corpus(t *testing.T) []string {
	corpus := prescanCorpus()
	for _, sr := range secretValueRules {
		r := loadSecretRule(t, sr.pack, sr.id)
		corpus = append(corpus, r.Tests.TP...)
		corpus = append(corpus, r.Tests.TN...)
	}
	return corpus
}

// TestRedactWithLabels_NoLabelSpanIsMain_4813 is gate 1: with no scrubber,
// and with one that finds no label in the text, each of the three functions
// returns byte for byte what main returned (frozen copies: plainRedact,
// plainRedactArgs, mainRedactArguments), over the prescan corpus, the
// analyzer corpus and the #4812 secret-rule TPs. RedactArguments itself, now
// a walk shared with the label-aware form, is held to main the same way. The
// positive control counts inputs the redaction changes, so a vacuous corpus
// fails.
func TestRedactWithLabels_NoLabelSpanIsMain_4813(t *testing.T) {
	corpus := gate1Corpus(t)
	changed, argsChanged, objChanged := 0, 0, 0
	for _, in := range corpus {
		want := plainRedact(in)
		args := strings.Fields(in)
		wantArgs := plainRedactArgs(args)
		obj := argumentsOf(in)
		wantObj := jsonOf(mainRedactArguments(obj))
		if got := jsonOf(RedactArguments(obj)); got != wantObj {
			t.Fatalf("RedactArguments(%q)\n got %s\nwant %s", in, got, wantObj)
		}
		for name, f := range map[string]func(string) []datalabel.Span{"no scrubber": nil, "scrubber, no span": noSpans} {
			if got := RedactWithLabels(in, f); got != want {
				t.Fatalf("%s: RedactWithLabels(%q)\n got %q\nwant %q", name, in, got, want)
			}
			if got := RedactArgsWithLabels(args, f); len(got) != len(wantArgs) || !slices.Equal(got, wantArgs) {
				t.Fatalf("%s: RedactArgsWithLabels(%q)\n got %q\nwant %q", name, args, got, wantArgs)
			}
			if got := jsonOf(RedactArgumentsWithLabels(obj, f)); got != wantObj {
				t.Fatalf("%s: RedactArgumentsWithLabels(%q)\n got %s\nwant %s", name, in, got, wantObj)
			}
		}
		if want != in {
			changed++
		}
		if !slices.Equal(wantArgs, args) {
			argsChanged++
		}
		if wantObj != jsonOf(obj) {
			objChanged++
		}
	}
	// nil stays nil, and RedactArgs' nil-to-empty is kept.
	if RedactArgumentsWithLabels(nil, noSpans) != nil {
		t.Error("nil arguments came back non-nil")
	}
	if got := RedactArgsWithLabels(nil, noSpans); got == nil || len(got) != 0 {
		t.Errorf("RedactArgsWithLabels(nil) = %#v, want the empty list RedactArgs returns", got)
	}
	t.Logf("%d inputs: %d texts, %d argument lists, %d argument objects changed by redaction; all identical to main", len(corpus), changed, argsChanged, objChanged)
	if changed < 50 || argsChanged < 50 {
		t.Fatalf("only %d texts and %d argument lists are redacted: the equivalence says little", changed, argsChanged)
	}
}

// TestSecretSpans_MatchPlainRegexp_4813: the secret spans the union masks are
// exactly every raw pattern's matches on the text, over the corpus and its
// fold-rune variants, so the prescan (regexlit.FindAllStringIndex) never
// drops one. Positive control: spans are found.
func TestSecretSpans_MatchPlainRegexp_4813(t *testing.T) {
	var inputs []string
	for _, s := range gate1Corpus(t) {
		inputs = append(inputs, s)
		inputs = append(inputs, foldRuneVariants(s)...)
	}
	found := 0
	for _, in := range inputs {
		got := appendSecretSpans(nil, in, 3)
		var want []span
		for _, re := range rawSensitivePatterns {
			for _, loc := range re.FindAllStringIndex(in, -1) {
				if loc[1] > loc[0] {
					want = append(want, span{start: loc[0] + 3, end: loc[1] + 3})
				}
			}
		}
		if !slices.Equal(got, want) {
			t.Fatalf("appendSecretSpans(%q)\n got %v\nwant %v", in, got, want)
		}
		found += len(got)
	}
	t.Logf("%d inputs, %d secret spans, each the raw regexp's", len(inputs), found)
	if found < 100 {
		t.Fatalf("only %d spans found: the check is close to vacuous", found)
	}
}

// TestRedactWithLabels_IssueShape_4813 is the issue's own row, and the two
// orders the fix replaces as controls: scrub-first (main) leaves the
// secret's tail, redact-first leaves the email's domain.
func TestRedactWithLabels_IssueShape_4813(t *testing.T) {
	eng := labelEngine(t, custLabel(), emailLabel())
	tail := "zz9yy8xx7ww6vv5u"
	key := "TO" + "KEN="
	rows := []struct {
		name, in string
		gone     []string
		want     string
	}{
		{"label inside the secret (#4813)", "export " + key + "abcdefghijklmn" + "CUST-104233" + tail,
			[]string{tail, "CUST-104233", "abcdefghijklmn"}, "export [REDACTED]"},
		{"secret run into an email", key + "abcdefghijklmn" + "alice@corp.example.com",
			[]string{"corp.example", "alice", "abcdefghijklmn"}, "[REDACTED]"},
	}
	for _, r := range rows {
		got := RedactWithLabels(r.in, eng.Spans)
		for _, g := range r.gone {
			if strings.Contains(got, g) {
				t.Errorf("%s: %q survived in %q", r.name, g, got)
			}
		}
		if got != r.want {
			t.Errorf("%s: got %q, want %q", r.name, got, r.want)
		}
	}
	// Controls: each order alone leaks, so the rows above can fail.
	if main := plainRedact(eng.Scrub(rows[0].in)); !strings.Contains(main, tail) {
		t.Fatalf("control: scrub-first no longer leaves the tail (%q); the row proves nothing", main)
	}
	if first := eng.Scrub(plainRedact(rows[1].in)); !strings.Contains(first, "corp.example") {
		t.Fatalf("control: redact-first no longer leaves the domain (%q); the row proves nothing", first)
	}
}

// TestRedactWithLabels_MultiByteEnd_4813 (Opus pass 1): a range main's order
// hid that ends on a multi-byte character. Origins were set per rune, so the
// character's last byte had none and the range was dropped from the mask,
// showing bytes main's record hid. Each row records as main does; the
// control is that main hides the tail, so the row can fail.
func TestRedactWithLabels_MultiByteEnd_4813(t *testing.T) {
	person := labelEngine(t, datalabel.DataLabelConfig{ID: "person", Patterns: []datalabel.PatternConfig{{Keywords: []string{"Jane Doe"}}}})
	pk := "-----BEGIN OPENSSH PRI" + "VATE KEY-----"
	rows := []struct {
		name string
		eng  *datalabel.Engine
		in   string
		want string
	}{
		{"a label with a space, then a tail ending on ä", person,
			"MYSQL_" + "PWD=abcdefghJane Doe!Sommerä mysql -u root", "MYSQL_[REDACTED] mysql -u root"},
		{"a key header, then a tail ending on ü", labelEngine(t, custLabel()),
			"echo sec" + "ret=abcdefgh@" + pk + "tailtailü CUST-104233", "echo [REDACTED] [LABEL:customer-records]"},
	}
	for _, r := range rows {
		if main := plainRedact(r.eng.Scrub(r.in)); main != r.want {
			t.Fatalf("%s: control: main records %q, not %q; the row proves nothing", r.name, main, r.want)
		}
		if got := RedactWithLabels(r.in, r.eng.Spans); got != r.want {
			t.Errorf("%s: got %q, want main's %q", r.name, got, r.want)
		}
	}
}

// TestRedactArgsWithLabels_LinePassProvenance_4813 (Opus pass 1, M11): a
// label holding a quote, inside a --password value. Main's line pass hides
// the flag and the whole value; the line's own spans stop at the label, so
// only main's line-pass provenance hides the value's tail.
func TestRedactArgsWithLabels_LinePassProvenance_4813(t *testing.T) {
	eng := labelEngine(t, datalabel.DataLabelConfig{ID: "person", Patterns: []datalabel.PatternConfig{{Keywords: []string{"O'Brien"}}}})
	args := []string{"mysql", "--pass" + "word", "abcO'Brienxyzsecretpart", "-u", "root"}
	want := []string{"mysql", "[REDACTED]", "-u", "root"}
	scrubbed := make([]string, len(args))
	for i, a := range args {
		scrubbed[i] = eng.Scrub(a)
	}
	if main := plainRedactArgs(scrubbed); !slices.Equal(main, want) {
		t.Fatalf("control: main gave %q, not %q", main, want)
	}
	if got := RedactArgsWithLabels(args, eng.Spans); !slices.Equal(got, want) {
		t.Fatalf("got %q, want main's %q", got, want)
	}
}

// TestRedactArgsWithLabels_MultiByteArgumentBefore_4813 (Opus pass 2): a
// multi-byte character in an argument before the labelled secret. Each
// argument's origins start at its byte offset in the line; counted in runes
// they land short, and the line's spans miss the secret's bytes.
func TestRedactArgsWithLabels_MultiByteArgumentBefore_4813(t *testing.T) {
	eng := labelEngine(t, custLabel())
	tail := "zz9yy8xx7ww6vv5u"
	args := []string{"ü", "TO" + "KEN=abcdefghijklmn" + "CUST-104233" + tail}
	want := []string{"ü", "[REDACTED]"}
	got := RedactArgsWithLabels(args, eng.Spans)
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	// Control: main's order leaves the tail, so the row can fail.
	if main := plainRedactArgs([]string{args[0], eng.Scrub(args[1])}); !strings.Contains(strings.Join(main, " "), tail) {
		t.Fatalf("control: main's order no longer leaves the tail (%q); the row proves nothing", main)
	}
}

// TestMask_PlaceholderRule_4813: a run of overlapping spans that holds a
// secret is [REDACTED]; a label alone keeps [LABEL:<id>], as before; spans
// that only touch stay separate; the earliest label names a label-only run.
func TestMask_PlaceholderRule_4813(t *testing.T) {
	lab := func(s, e int, id string) span { return span{start: s, end: e, placeholder: "[LABEL:" + id + "]"} }
	sec := func(s, e int) span { return span{start: s, end: e} }
	text := "0123456789abcdefghij"
	rows := []struct {
		name  string
		spans []span
		want  string
	}{
		{"label alone", []span{lab(2, 5, "a")}, "01[LABEL:a]56789abcdefghij"},
		{"secret alone", []span{sec(2, 5)}, "01[REDACTED]56789abcdefghij"},
		{"label inside a secret", []span{sec(2, 12), lab(4, 6, "a")}, "01[REDACTED]cdefghij"},
		{"secret inside a label", []span{lab(2, 12, "a"), sec(4, 6)}, "01[REDACTED]cdefghij"},
		{"straddle", []span{lab(2, 6, "a"), sec(4, 9)}, "01[REDACTED]9abcdefghij"},
		{"touching stay apart", []span{sec(2, 5), lab(5, 8, "a")}, "01[REDACTED][LABEL:a]89abcdefghij"},
		{"two labels overlap", []span{lab(2, 6, "a"), lab(4, 9, "b")}, "01[LABEL:a]9abcdefghij"},
		{"a secret bridges two labels", []span{lab(2, 4, "a"), sec(3, 8), lab(7, 10, "b")}, "01[REDACTED]abcdefghij"},
		{"unsorted input", []span{lab(12, 14, "b"), sec(2, 4)}, "01[REDACTED]456789ab[LABEL:b]efghij"},
	}
	for _, r := range rows {
		if got := mask(text, append([]span(nil), r.spans...)); got != r.want {
			t.Errorf("%s: got %q, want %q", r.name, got, r.want)
		}
	}
}

// TestRedactArgsWithLabels_SecretAcrossArguments_4813: a Bearer token is its
// own argument, so only the line finds it; a label inside the token must not
// cut it short there either. Control: main's order leaves the token's tail.
func TestRedactArgsWithLabels_SecretAcrossArguments_4813(t *testing.T) {
	eng := labelEngine(t, custLabel())
	tail := "q9w8e7r6t5y4u3i2o1p0"
	args := []string{"curl", "-H", "Bea" + "rer", "abcdefghij" + "CUST-104233" + tail, "https://x.example"}
	got := RedactArgsWithLabels(args, eng.Spans)
	if s := strings.Join(got, " "); strings.Contains(s, tail) || strings.Contains(s, "CUST-104233") || strings.Contains(s, "abcdefghij") {
		t.Fatalf("the token or the label survived: %q", got)
	}
	scrubbed := make([]string, len(args))
	for i, a := range args {
		scrubbed[i] = eng.Scrub(a)
	}
	if main := strings.Join(plainRedactArgs(scrubbed), " "); !strings.Contains(main, tail) {
		t.Fatalf("control: main's order no longer leaves the tail (%q); the row proves nothing", main)
	}
	// A label with no secret around it keeps its placeholder and the
	// argument list its shape.
	plain := []string{"echo", "CUST-104233", "done"}
	if got := RedactArgsWithLabels(plain, eng.Spans); !slices.Equal(got, []string{"echo", "[LABEL:customer-records]", "done"}) {
		t.Fatalf("label-only arguments: got %q", got)
	}
}

// TestRedactArgumentsWithLabels_KeyedValue_4813: a value under a secret key
// that carries a label is replaced whole, and an unkeyed value is masked as a
// text; a label under a plain key keeps its placeholder.
func TestRedactArgumentsWithLabels_KeyedValue_4813(t *testing.T) {
	eng := labelEngine(t, custLabel())
	tail := "zz9yy8xx7ww6vv5u"
	v := "TO" + "KEN=abcdefghijklmn" + "CUST-104233" + tail
	in := map[string]interface{}{
		"command":       "export " + v,
		"pass" + "word": "ab" + "CUST-104233",
		"note":          "see CUST-104233",
		"env":           []interface{}{map[string]interface{}{"name": "API" + "_TOKEN", "value": "x" + "CUST-104233" + tail}},
	}
	out := jsonOf(RedactArgumentsWithLabels(in, eng.Spans))
	for _, g := range []string{tail, "CUST-104233", "abcdefghijklmn"} {
		if strings.Contains(out, g) {
			t.Errorf("%q survived: %s", g, out)
		}
	}
	if !strings.Contains(out, `"note":"see [LABEL:customer-records]"`) {
		t.Errorf("a label under a plain key lost its placeholder: %s", out)
	}
	// Control: main's order leaves the tail in the command.
	if main := jsonOf(mainRedactArguments(mainScrubTree(eng.Scrub, in).(map[string]interface{}))); !strings.Contains(main, tail) {
		t.Fatalf("control: main's order no longer leaves the tail (%s)", main)
	}
}

// labelledLine is n bytes of the analyzer corpus as one command, a labelled
// secret every few hundred bytes.
func labelledLine(n int) string {
	var sb strings.Builder
	cases := testdata.AllTestCases()
	for i := 0; sb.Len() < n; i++ {
		sb.WriteString(cases[i%len(cases)].Command + "\n")
		if i%40 == 7 {
			sb.WriteString("export TO" + "KEN=abcdefghijklmn" + "CUST-" + "104233" + "zz9yy8xx7ww6vv5u\n")
		}
	}
	return sb.String()
}

// allocated returns the bytes f allocates.
func allocated(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// TestRedactWithLabels_GrowsLinearly_4813: the record is written on the
// harness's hook clock (#4772, #4785), so a labelled command must cost about
// linearly in its size. The first cut joined the argument list's origins one
// argument at a time, copying the whole line each time: a 1 MiB labelled
// command allocated 514 GB and took 87 s. Allocation is the deterministic
// measure: from 32 KiB to 256 KiB it may grow about 8x, never the 64x a
// quadratic step gives. Control: the inputs carry labels and secrets.
func TestRedactWithLabels_GrowsLinearly_4813(t *testing.T) {
	eng := labelEngine(t, custLabel())
	small, large := labelledLine(32<<10), labelledLine(256<<10)
	if len(eng.Spans(small)) < 10 || RedactWithLabels(small, eng.Spans) == small {
		t.Fatal("control: the small input carries too few labels")
	}
	sa, la := strings.Fields(small), strings.Fields(large)
	for name, f := range map[string]func(s string, a []string){
		"text": func(s string, _ []string) { _ = RedactWithLabels(s, eng.Spans) },
		"args": func(_ string, a []string) { _ = RedactArgsWithLabels(a, eng.Spans) },
		"arguments": func(s string, _ []string) {
			_ = RedactArgumentsWithLabels(map[string]interface{}{"command": s}, eng.Spans)
		},
	} {
		s := allocated(func() { f(small, sa) })
		l := allocated(func() { f(large, la) })
		ratio := float64(l) / float64(s)
		t.Logf("%s: %d bytes at 32 KiB, %d at 256 KiB (%.1fx)", name, s, l, ratio)
		if ratio > 16 {
			t.Errorf("%s: allocation grew %.1fx for 8x the input: not linear", name, ratio)
		}
	}
}

// TestRedactArgumentsWithLabels_KeyJudgements_4813: each key judgement the
// label-aware walk adds is load-bearing. Main judged a value's key on the
// value with its label spans replaced, so:
//   - a value whose key names a secret only as written, {"api_key":
//     "<head><label><tail>"}, was not replaced: the key's pattern stops at
//     the placeholder, and main showed the secret's head and tail. The
//     judgement on the value as written replaces it whole, for a direct
//     value, an array item and a value under a secret parent key;
//   - a value main replaced whole only because the placeholder made it long
//     enough, {"password": ["ab<short label>"]}, must still be replaced whole:
//     as written it is too short for the key's pattern.
func TestRedactArgumentsWithLabels_KeyJudgements_4813(t *testing.T) {
	eng := labelEngine(t, custLabel(), datalabel.DataLabelConfig{ID: "kw", Patterns: []datalabel.PatternConfig{{Keywords: []string{"OSP"}, CaseSensitive: true}}})
	head, tail := "abcdefgh", "ijklmnop"
	v := head + "CUST-" + "104233" + tail
	short := "ab" + "OSP"
	key, pw, tok := "api"+"_key", "pass"+"word", "to"+"ken"
	at := func(m map[string]interface{}, path ...string) string {
		var cur interface{} = m
		for _, p := range path {
			switch c := cur.(type) {
			case map[string]interface{}:
				cur = c[p]
			case []interface{}:
				cur = c[0]
			}
		}
		return cur.(string)
	}
	rows := []struct {
		name      string
		in        map[string]interface{}
		path      []string
		mainLeaks bool // main showed the head or tail; else main replaced the value whole
	}{
		{"direct value, own key", map[string]interface{}{key: v}, []string{key}, true},
		{"array item, own key", map[string]interface{}{key: []interface{}{v}}, []string{key, "0"}, true},
		{"direct value, secret parent key", map[string]interface{}{tok: map[string]interface{}{"note": v}}, []string{tok, "note"}, true},
		{"array item, short label", map[string]interface{}{pw: []interface{}{short}}, []string{pw, "0"}, false},
		{"direct value, short label", map[string]interface{}{pw: short}, []string{pw}, false},
		// The k8s name sibling as main judged it: the placeholder puts a
		// word boundary before "token" that the name as written lacks.
		{"name sibling, as main scrubbed it", map[string]interface{}{"env": []interface{}{map[string]interface{}{"name": "OSP" + tok, "value": "q1w2e3r4t5y6u7i8"}}}, []string{"env", "0", "value"}, false},
	}
	for _, r := range rows {
		got := at(RedactArgumentsWithLabels(r.in, eng.Spans), r.path...)
		if got != redactedPlaceholder {
			t.Errorf("%s: got %q, want the value replaced whole", r.name, got)
		}
		main := at(mainRedactArguments(mainScrubTree(eng.Scrub, r.in).(map[string]interface{})), r.path...)
		if r.mainLeaks && !strings.Contains(main, head) && !strings.Contains(main, tail) {
			t.Fatalf("control, %s: main's record %q shows neither the head nor the tail; the row proves nothing", r.name, main)
		}
		if !r.mainLeaks && (main != redactedPlaceholder || keyRedacts(pw, short) || keyRedacts("OSP"+tok, "q1w2e3r4t5y6u7i8")) {
			t.Fatalf("control, %s: main gave %q, or the text as written is judged a secret on its own; the row proves nothing", r.name, main)
		}
	}
}

// TestRedactArgsWithLabels_KeepsMainsElements_4813: when the line finds no
// more than the arguments, the list keeps its elements, as main's RedactArgs
// does: an argument holding a space and a label stays one element.
func TestRedactArgsWithLabels_KeepsMainsElements_4813(t *testing.T) {
	eng := labelEngine(t, custLabel())
	args := []string{"echo", "a " + "CUST-" + "104233" + " b"}
	want := []string{"echo", "a [LABEL:customer-records] b"}
	if got := RedactArgsWithLabels(args, eng.Spans); !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	if main := plainRedactArgs([]string{eng.Scrub(args[0]), eng.Scrub(args[1])}); !slices.Equal(main, want) {
		t.Fatalf("control: main gave %q", main)
	}
}

// TestRedactArgumentsWithLabels_ScansEachStringOnce_4813: the label scan is
// the scrubber's whole cost on a value with no label (main ran it once per
// string), and an MCP argument can be a MiB-scale file body, so each string
// is scanned once. Control: the scan is counted at all.
func TestRedactArgumentsWithLabels_ScansEachStringOnce_4813(t *testing.T) {
	seen := map[string]int{}
	count := func(s string) []datalabel.Span { seen[s]++; return nil }
	in := map[string]interface{}{
		"content":       "plain text",
		"pass" + "word": "q1w2e3r4",
		"env":           []interface{}{map[string]interface{}{"name": "DB_HOST", "value": "db.internal"}},
		"nested":        map[string]interface{}{"to" + "ken": map[string]interface{}{"value": "z9y8x7w6"}, "list": []interface{}{"item one"}},
	}
	RedactArgumentsWithLabels(in, count)
	for _, s := range []string{"plain text", "q1w2e3r4", "db.internal", "z9y8x7w6", "item one"} {
		if seen[s] != 1 {
			t.Errorf("%q scanned %d times, want once", s, seen[s])
		}
	}
	if len(seen) == 0 {
		t.Fatal("control: nothing was scanned")
	}
}
