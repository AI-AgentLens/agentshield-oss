package redact

import (
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/datalabel"
)

// Gate 2 of #4813: a generator over every secret pattern x label placements,
// held to one property with a scrubber attached. No byte of any secret
// pattern's match and no byte of any label's match, both found on the text
// as written, survives in the record. A second property holds the result to
// main: every byte main's record hid stays hidden.
//
// "Survives" is judged on the output alone, by hides: the output must read as
// the text with ranges replaced by placeholders and every required byte
// inside a replaced range. It does not look at how the output was made, so
// the same oracle grades main's order (scrub, then redact) and the
// redact-first order as controls.

// hides reports whether out reads as orig with ranges replaced by
// placeholders such that every byte need marks lies inside a replaced range.
// A dynamic program over (orig offset, out offset, inside a placeholder?):
// outside, a byte of out is an unmarked byte of orig or the start of a
// placeholder; inside, any byte of orig may be consumed.
func hides(orig, out string, need []bool, placeholders []string) bool {
	n, m := len(orig), len(out)
	w := m + 1
	starts := make([][]int, m+1)
	for j := 0; j < m; j++ {
		for _, p := range placeholders {
			if strings.HasPrefix(out[j:], p) {
				starts[j] = append(starts[j], len(p))
			}
		}
	}
	free := make([]bool, (n+1)*w)
	in := make([]bool, (n+1)*w)
	free[0] = true
	for i := 0; i <= n; i++ {
		for j := 0; j <= m; j++ {
			c := i*w + j
			if in[c] {
				free[c] = true
				if i < n {
					in[c+w] = true
				}
			}
			if !free[c] {
				continue
			}
			if i < n && j < m && !need[i] && orig[i] == out[j] {
				free[c+w+1] = true
			}
			for _, l := range starts[j] {
				in[c+l] = true
			}
		}
	}
	return free[n*w+m]
}

// track is a text under sequential replacement that keeps each byte's
// origin: at[i] is cur[i]'s offset in the original, -1 for a byte a
// placeholder wrote. It is how the test knows which bytes main's record hid.
type track struct {
	cur string
	at  []int
}

func newTrack(s string) track {
	at := make([]int, len(s))
	for i := range at {
		at[i] = i
	}
	return track{s, at}
}

// replace replaces the sorted, disjoint ranges locs, the i-th with repl(i),
// and marks every original byte a replaced range held in hidden.
func (t track) replace(locs [][]int, repl func(int) string, hidden []bool) track {
	if len(locs) == 0 {
		return t
	}
	var sb strings.Builder
	var at []int
	pos := 0
	for i, l := range locs {
		sb.WriteString(t.cur[pos:l[0]])
		at = append(at, t.at[pos:l[0]]...)
		for _, o := range t.at[l[0]:l[1]] {
			if o >= 0 {
				hidden[o] = true
			}
		}
		r := repl(i)
		sb.WriteString(r)
		for k := 0; k < len(r); k++ {
			at = append(at, -1)
		}
		pos = l[1]
	}
	sb.WriteString(t.cur[pos:])
	at = append(at, t.at[pos:]...)
	return track{sb.String(), at}
}

func (t track) concat(sep string, u track, shift int) track {
	at := append(append([]int(nil), t.at...), make([]int, len(sep))...)
	for k := range sep {
		at[len(t.at)+k] = -1
	}
	for _, o := range u.at {
		if o >= 0 {
			o += shift
		}
		at = append(at, o)
	}
	return track{t.cur + sep + u.cur, at}
}

// scrubTrack is main's scrub: the label spans, each by its placeholder.
func scrubTrack(t track, eng *datalabel.Engine, hidden []bool) track {
	sp := eng.Spans(t.cur)
	locs := make([][]int, len(sp))
	for i, s := range sp {
		locs[i] = []int{s.Start, s.End}
	}
	return t.replace(locs, func(i int) string { return sp[i].Placeholder() }, hidden)
}

// redactTrack is plainRedact with each byte's origin kept.
func redactTrack(t track, hidden []bool) track {
	for _, re := range rawSensitivePatterns {
		t = t.replace(re.FindAllStringIndex(t.cur, -1), func(int) string { return redactedPlaceholder }, hidden)
	}
	return t
}

// mainHidden returns main's record of text (scrub, then redact) and the
// original bytes it hid.
func mainHidden(text string, eng *datalabel.Engine) (string, []bool) {
	hidden := make([]bool, len(text))
	t := redactTrack(scrubTrack(newTrack(text), eng, hidden), hidden)
	return t.cur, hidden
}

// mainArgsHidden returns main's record of args (each scrubbed, then
// RedactArgs) joined by spaces, and the bytes of the joined line it hid.
func mainArgsHidden(args []string, eng *datalabel.Engine) (string, []bool) {
	line := strings.Join(args, " ")
	hidden := make([]bool, len(line))
	var joined track
	off := 0
	for i, a := range args {
		h := make([]bool, len(a))
		at := redactTrack(scrubTrack(newTrack(a), eng, h), h)
		for k, v := range h {
			hidden[off+k] = hidden[off+k] || v
		}
		if i == 0 {
			joined = track{at.cur, at.at}
		} else {
			joined = joined.concat(" ", at, off)
		}
		off += len(a) + 1
	}
	if len(args) == 0 {
		joined = newTrack("")
	}
	if after := redactTrack(joined, hidden); after.cur != joined.cur {
		return strings.Join(strings.Fields(after.cur), " "), hidden
	}
	return joined.cur, hidden
}

// required marks every byte of every raw secret pattern's match and every
// label span, found on text itself.
func required(text string, eng *datalabel.Engine) []bool {
	need := make([]bool, len(text))
	mark := func(s, e int) {
		for k := s; k < e; k++ {
			need[k] = true
		}
	}
	for _, re := range rawSensitivePatterns {
		for _, l := range re.FindAllStringIndex(text, -1) {
			mark(l[0], l[1])
		}
	}
	for _, s := range eng.Spans(text) {
		mark(s.Start, s.End)
	}
	return need
}

// secretShape is a text that one secret pattern matches whole:
// prefix+value+suffix. Labels go into the value.
type secretShape struct {
	pat                   int
	prefix, value, suffix string
}

func (s secretShape) text() string { return s.prefix + s.value + s.suffix }

// secretShapes returns one shape for every pattern in rawSensitivePatterns,
// assembled at runtime from r.
func secretShapes(r *rand.Rand) []secretShape {
	const upper, lower, digit = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789"
	alnum := upper + lower + digit
	gen := func(alpha string, n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = alpha[r.IntN(len(alpha))]
		}
		return string(b)
	}
	pk := "PRIV" + "ATE KEY-----"
	sym := alnum + "!#%&*,;<>?^|~"
	return []secretShape{
		{0, "aws" + "_secret_access_key=", gen(alnum+"/+", 40), ""},
		{1, "AK" + "IA", gen(upper+digit, 16), ""},
		{2, "github" + "_token=", gen(alnum+"_-", 32), ""},
		{3, "ghp" + "_", gen(alnum, 36), ""},
		{4, "gho" + "_", gen(alnum, 36), ""},
		{5, "ghu" + "_", gen(alnum, 36), ""},
		{6, "ghs" + "_", gen(alnum, 36), ""},
		{7, "ghr" + "_", gen(alnum, 36), ""},
		{8, "api" + "_key=", gen(alnum+"_-", 20), ""},
		{9, "-----BEGIN RSA " + pk + "\n", gen(alnum+"+/", 40), "\n-----END RSA " + pk},
		{10, "-----BEGIN EC " + pk, "", ""},
		{11, "Bea" + "rer ", gen(alnum+"_.~+/=-", 30), ""},
		{12, "Authorization: Bea" + "rer ", gen(sym, 8), ""},
		{13, "https://user:", gen(alnum+"!#%&*", 12), "@"},
		{14, "redis://u:", gen(alnum+"!#%&*", 12), "@"},
		{15, "--to" + "ken ", "k" + gen(sym, 13), ""},
		{16, " -u admin:", gen(sym, 12), ""},
		{17, "TO" + "KEN=", gen(alnum+"_.~+/=-", 16), ""},
		{18, "sk-" + "ant-", gen(alnum+"_-", 24), ""},
		{19, "sk" + "-", gen(alnum, 24), ""},
		{20, "AI" + "za", gen(alnum+"_-", 35), ""},
		{21, "xox" + "b-1234567890-1234567890", gen(alnum+"-", 10), ""},
		{22, "sk_" + "live_", gen(alnum, 24), ""},
		{23, "rk_" + "live_", gen(alnum, 24), ""},
		{24, "pass" + "word=", gen(sym, 12), ""},
	}
}

// fixedLabels are the label set every case carries: a regex id, a
// case-sensitive keyword, an email, a project wrapper whose value can hold a
// whole secret, and a name with a space in it, which ends a secret pattern
// on the text as written while main's placeholder lets it run on.
func fixedLabels() []datalabel.DataLabelConfig {
	return []datalabel.DataLabelConfig{
		{ID: "customer-records", Patterns: []datalabel.PatternConfig{{Regex: `CUST-[0-9]{6}`}}},
		{ID: "codename", Patterns: []datalabel.PatternConfig{{Keywords: []string{"PHOENIX"}, CaseSensitive: true}}},
		{ID: "email", Patterns: []datalabel.PatternConfig{{Regex: `[A-Za-z0-9._%+-]+@corp\.example\.com`}}},
		{ID: "project", Patterns: []datalabel.PatternConfig{{Regex: `PRJ\{[^}]+\}`}}},
		{ID: "person", Patterns: []datalabel.PatternConfig{{Keywords: []string{"Jane Doe"}}}},
	}
}

var propertyPlaceholders = []string{"[REDACTED]", "[LABEL:customer-records]", "[LABEL:codename]", "[LABEL:email]", "[LABEL:project]", "[LABEL:person]", "[LABEL:kw]"}

// propCase is one generated text; kw, when set, is one more label: a
// case-sensitive keyword cut from the text itself, so it can sit anywhere
// against the secret, straddling its start or end included.
type propCase struct {
	family, text, kw string
}

func propertyCases(r *rand.Rand) []propCase {
	shapes := secretShapes(r)
	// The last context glues a two-byte character to the secret's end, so a
	// range main hid can end inside a multi-byte character (Opus pass 1 on
	// #4813: origins were set per rune, and such a range was dropped).
	contexts := [][2]string{{"", ""}, {"export ", " && ls -la"}, {"curl -s -H 'X-Auth: ", "' https://api.example.net/v1"}, {"export ", "\u00fc && ls"}}
	values := []string{"CUST-" + "104233", "PHOE" + "NIX", "alice" + "@corp.example.com", "Jane" + " Doe"}
	emailLocal := regexp.MustCompile(`^[A-Za-z0-9._%+-]+$`)
	var out []propCase
	add := func(family, text, kw string) { out = append(out, propCase{family, text, kw}) }
	for _, s := range shapes {
		for _, c := range contexts {
			pre, post := c[0], c[1]
			v := s.value
			if v != "" {
				for _, lv := range values {
					for name, k := range map[string]int{"prefix": 0, "middle": len(v) / 2, "suffix": len(v)} {
						add("label at the value's "+name, pre+s.prefix+v[:k]+lv+v[k:]+s.suffix+post, "")
					}
				}
				k1, k2 := len(v)/3, 2*len(v)/3
				add("two labels, one secret", pre+s.prefix+v[:k1]+values[0]+v[k1:k2]+values[1]+v[k2:]+s.suffix+post, "")
			}
			add("secret inside a project label", pre+"PRJ{"+s.text()+"}"+post, "")
			if emailLocal.MatchString(s.text()) {
				add("secret inside an email label", pre+s.text()+"@corp.example.com"+post, "")
			}
			text := pre + s.text() + post
			a, b := len(pre), len(pre)+len(s.text())
			vs, ve := a+len(s.prefix), a+len(s.prefix)+len(v)
			if len(v) >= 8 {
				mid := (vs + ve) / 2
				add("keyword over the value's prefix", text, text[vs:vs+4])
				add("keyword over the value's middle", text, text[mid-2:mid+2])
				add("keyword over the value's suffix", text, text[ve-4:ve])
			}
			if a >= 3 {
				add("keyword straddling the secret's start", text, text[a-3:a+3])
			}
			if len(post) >= 3 {
				add("keyword straddling the secret's end", text, text[b-3:b+3])
			}
			add("keyword holding the whole secret", text, text[max(0, a-2):min(len(text), b+2)])
		}
	}
	for i, s := range shapes {
		u := shapes[(i+1)%len(shapes)]
		if u.value != "" {
			k := len(u.value) / 2
			add("adjacent secrets, label inside the second", "x "+s.text()+u.prefix+u.value[:k]+values[0]+u.value[k:]+u.suffix, "")
		}
		add("adjacent secrets, label between", "x "+s.text()+values[1]+u.text(), "")
	}
	add("the #4813 shape", "export TO"+"KEN=abcdefghijklmn"+values[0]+"zz9yy8xx7ww6vv5u", "")
	add("a secret run into an email", "TO"+"KEN=abcdefghijklmn"+values[2], "")
	return out
}

// engineFor returns the case's label engine, cached by keyword.
func engineFor(t testing.TB, cache map[string]*datalabel.Engine, kw string) *datalabel.Engine {
	if e, ok := cache[kw]; ok {
		return e
	}
	labels := fixedLabels()
	if kw != "" {
		labels = append(labels, datalabel.DataLabelConfig{ID: "kw", Patterns: []datalabel.PatternConfig{{Keywords: []string{kw}, CaseSensitive: true}}})
	}
	e := labelEngine(t, labels...)
	cache[kw] = e
	return e
}

// TestSecretShapes_CoverEveryPattern: the generator has a shape for every
// secret pattern, and each shape is matched whole by its own pattern, so a
// pattern added to rawSensitivePatterns without a shape fails here.
func TestSecretShapes_CoverEveryPattern(t *testing.T) {
	shapes := secretShapes(rand.New(rand.NewPCG(4813, 1)))
	seen := make([]bool, len(rawSensitivePatterns))
	for _, s := range shapes {
		txt := s.text()
		loc := rawSensitivePatterns[s.pat].FindStringIndex(txt)
		if loc == nil || loc[0] != 0 || loc[1] != len(txt) {
			t.Errorf("pattern %d (%s) does not match its shape %q whole: %v", s.pat, rawSensitivePatterns[s.pat], txt, loc)
		}
		seen[s.pat] = true
	}
	for i, ok := range seen {
		if !ok {
			t.Errorf("no shape for pattern %d (%s)", i, rawSensitivePatterns[i])
		}
	}
}

// surfaceResult counts one surface's cases.
type surfaceResult struct {
	cases, fail, mainFail, firstFail, weaker int
	examples                                 []string
}

func (s *surfaceResult) example(format string, a ...any) {
	if len(s.examples) < 5 {
		s.examples = append(s.examples, fmt.Sprintf(format, a...))
	}
}

// TestRedactWithLabels_Property_4813 is gate 2. For every generated case, on
// three surfaces (a text, the argument list strings.Fields makes of it, and
// an MCP arguments object carrying it), the record hides every secret and
// label byte found on the original, and every byte main's record hid. The
// controls are main's order (scrub, then redact) and the redact-first order,
// graded by the same oracle on the text surface; both must fail somewhere.
func TestRedactWithLabels_Property_4813(t *testing.T) {
	cases := propertyCases(rand.New(rand.NewPCG(4813, 2)))
	cache := map[string]*datalabel.Engine{}
	var text, args, obj surfaceResult
	families := map[string]int{}
	mainByFamily := map[string]int{}
	for _, c := range cases {
		eng := engineFor(t, cache, c.kw)
		families[c.family]++

		// Text.
		text.cases++
		need := required(c.text, eng)
		got := RedactWithLabels(c.text, eng.Spans)
		if !hides(c.text, got, need, propertyPlaceholders) {
			text.fail++
			text.example("%s: %q -> %q", c.family, c.text, got)
		}
		mainOut, mainHid := mainHidden(c.text, eng)
		if mainOut != plainRedact(eng.Scrub(c.text)) {
			t.Fatalf("the provenance model of main's record is wrong: %q vs %q", mainOut, plainRedact(eng.Scrub(c.text)))
		}
		if !hides(c.text, mainOut, need, propertyPlaceholders) {
			text.mainFail++
			mainByFamily[c.family]++
		}
		if first := eng.Scrub(plainRedact(c.text)); !hides(c.text, first, need, propertyPlaceholders) {
			text.firstFail++
		}
		if !hides(c.text, got, mainHid, propertyPlaceholders) {
			text.weaker++
			text.example("weaker than main, %s: %q -> %q (main %q)", c.family, c.text, got, mainOut)
		}

		// The argument list.
		fields := strings.Fields(c.text)
		line := strings.Join(fields, " ")
		args.cases++
		aneed := required(line, eng)
		off := 0
		for _, f := range fields {
			for k, v := range required(f, eng) {
				aneed[off+k] = aneed[off+k] || v
			}
			off += len(f) + 1
		}
		gotArgs := strings.Join(RedactArgsWithLabels(fields, eng.Spans), " ")
		if !hides(line, gotArgs, aneed, propertyPlaceholders) {
			args.fail++
			args.example("%s: %q -> %q", c.family, line, gotArgs)
		}
		mainArgs, mainArgsHid := mainArgsHidden(fields, eng)
		if !hides(line, mainArgs, aneed, propertyPlaceholders) {
			args.mainFail++
		}
		if !hides(line, gotArgs, mainArgsHid, propertyPlaceholders) {
			args.weaker++
			args.example("weaker than main, %s: %q -> %q (main %q)", c.family, line, gotArgs, mainArgs)
		}

		// An MCP arguments object: an unkeyed string, an array item, a value
		// under a secret parent key and a k8s name/value pair.
		obj.cases++
		in := map[string]interface{}{
			"content": c.text,
			"list":    []interface{}{c.text},
			"auth":    map[string]interface{}{"to" + "ken": map[string]interface{}{"value": c.text}},
			"env":     []interface{}{map[string]interface{}{"name": "API" + "_TOKEN", "value": c.text}},
		}
		o := RedactArgumentsWithLabels(in, eng.Spans)
		m := mainRedactArguments(mainScrubTree(eng.Scrub, in).(map[string]interface{}))
		value := func(v map[string]interface{}, path ...string) string {
			var cur interface{} = v
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
		for _, path := range [][]string{{"content"}, {"list", "0"}, {"auth", "to" + "ken", "value"}, {"env", "0", "value"}} {
			g, mo := value(o, path...), value(m, path...)
			if !hides(c.text, g, need, propertyPlaceholders) {
				obj.fail++
				obj.example("%v %s: %q -> %q", path, c.family, c.text, g)
			}
			if !hides(c.text, mo, need, propertyPlaceholders) {
				obj.mainFail++
			}
			// What main's record hid: all of it when the key replaced the
			// value whole, otherwise what its text redaction hid.
			mh := mainHid
			if mo == redactedPlaceholder {
				mh = make([]bool, len(c.text))
				for k := range mh {
					mh[k] = true
				}
			} else if mo != mainOut {
				t.Fatalf("%v: main recorded %q, neither its text redaction %q nor a whole replacement", path, mo, mainOut)
			}
			if !hides(c.text, g, mh, propertyPlaceholders) {
				obj.weaker++
				obj.example("weaker than main, %v %s: %q -> %q (main %q)", path, c.family, c.text, g, mo)
			}
		}
	}
	t.Logf("text: %d cases; leaking records: this change %d, main (scrub then redact) %d, redact-first %d; weaker than main %d",
		text.cases, text.fail, text.mainFail, text.firstFail, text.weaker)
	t.Logf("args: %d cases; leaking records: this change %d, main %d; weaker than main %d", args.cases, args.fail, args.mainFail, args.weaker)
	t.Logf("arguments: %d cases x 4 placements; leaking strings: this change %d, main %d; weaker than main %d", obj.cases, obj.fail, obj.mainFail, obj.weaker)
	for name, s := range map[string]*surfaceResult{"text": &text, "args": &args, "arguments": &obj} {
		for _, e := range s.examples {
			t.Errorf("%s: %s", name, e)
		}
		if s.fail != 0 || s.weaker != 0 {
			t.Errorf("%s: %d leaks, %d weaker than main", name, s.fail, s.weaker)
		}
	}
	t.Logf("families: %v", families)
	t.Logf("main's leaks by family: %v", mainByFamily)
	// Controls: the oracle can fail, on both orders the union replaces.
	if text.mainFail == 0 || text.firstFail == 0 || args.mainFail == 0 || obj.mainFail == 0 {
		t.Fatalf("control: main %d / redact-first %d / main args %d / main arguments %d leaks; the property proves nothing",
			text.mainFail, text.firstFail, args.mainFail, obj.mainFail)
	}
	if len(cases) < 1000 {
		t.Fatalf("only %d cases", len(cases))
	}
}

// TestRedactWithLabels_CorpusWithLabels_4813: the corpus under a label set
// that matches ordinary command text (path words, numbers, an email), so
// labels and secrets meet the way real commands make them meet. Every
// record hides the union and every byte main's record hid. The denominator
// is the inputs where a label matched.
func TestRedactWithLabels_CorpusWithLabels_4813(t *testing.T) {
	eng := labelEngine(t,
		datalabel.DataLabelConfig{ID: "paths", Patterns: []datalabel.PatternConfig{{Keywords: []string{"etc", "ssh", "aws", "admin", "user"}}}},
		datalabel.DataLabelConfig{ID: "digits", Patterns: []datalabel.PatternConfig{{Regex: `[0-9]{4,}`}}},
		emailLabel(),
	)
	ph := []string{"[REDACTED]", "[LABEL:paths]", "[LABEL:digits]", "[LABEL:email]"}
	labelled, differs, skipped, mainLeaks := 0, 0, 0, 0
	for _, in := range gate1Corpus(t) {
		if len(eng.Spans(in)) == 0 {
			continue
		}
		labelled++
		got := RedactWithLabels(in, eng.Spans)
		mainOut, mainHid := mainHidden(in, eng)
		if got == mainOut {
			continue
		}
		differs++
		if len(in)*len(got) > 4_000_000 {
			skipped++
			continue
		}
		need := required(in, eng)
		if !hides(in, got, need, ph) {
			t.Errorf("leak: %q -> %q", in, got)
		}
		if !hides(in, got, mainHid, ph) {
			t.Errorf("weaker than main: %q -> %q (main %q)", in, got, mainOut)
		}
		if !hides(in, mainOut, need, ph) {
			mainLeaks++
		}
	}
	t.Logf("%d corpus inputs carry a label; %d record differently from main, %d of those too long for the oracle; main leaks on %d of them", labelled, differs, skipped, mainLeaks)
	if labelled < 500 || differs < 20 {
		t.Fatalf("only %d labelled inputs and %d differing records: the check says little", labelled, differs)
	}
}

// TestRedactWithLabels_RandomSplices_4813: random texts spliced from the
// secret shapes, their prefixes, label values and separators, so secrets and
// labels meet at places the structured generator does not choose. Same
// property, same oracle; main's order is the control.
func TestRedactWithLabels_RandomSplices_4813(t *testing.T) {
	r := rand.New(rand.NewPCG(4813, 3))
	var parts []string
	for _, s := range secretShapes(r) {
		parts = append(parts, s.text(), s.prefix, s.value)
	}
	parts = append(parts, "CUST-"+"104233", "PHOE"+"NIX", "alice"+"@corp.example.com", "PRJ{", "}", " ", "=", ":", "'", "@", "/", "-", "\n", "x", "0123")
	eng := labelEngine(t, fixedLabels()...)
	n, labelled, fail, weaker, mainFail := 20000, 0, 0, 0, 0
	for i := 0; i < n; i++ {
		var sb strings.Builder
		for k := 2 + r.IntN(6); k > 0; k-- {
			sb.WriteString(parts[r.IntN(len(parts))])
		}
		in := sb.String()
		if len(eng.Spans(in)) == 0 {
			continue
		}
		labelled++
		got := RedactWithLabels(in, eng.Spans)
		need := required(in, eng)
		mainOut, mainHid := mainHidden(in, eng)
		if !hides(in, got, need, propertyPlaceholders) {
			fail++
			if fail <= 5 {
				t.Errorf("leak: %q -> %q", in, got)
			}
		}
		if !hides(in, got, mainHid, propertyPlaceholders) {
			weaker++
			if weaker <= 5 {
				t.Errorf("weaker than main: %q -> %q (main %q)", in, got, mainOut)
			}
		}
		if !hides(in, mainOut, need, propertyPlaceholders) {
			mainFail++
		}
	}
	t.Logf("%d random texts, %d carry a label; leaking records: this change %d, main %d; weaker than main %d", n, labelled, fail, mainFail, weaker)
	if labelled < 2000 || mainFail == 0 {
		t.Fatalf("control: %d labelled texts, main leaks on %d; the property proves nothing", labelled, mainFail)
	}
}
