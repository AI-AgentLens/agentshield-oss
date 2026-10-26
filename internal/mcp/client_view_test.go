package mcp

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

// The response rows of #4407 (one per surface, control-first, both key
// orders) are in parityRows, http_proxy_dispatch_parity_test.go, driven
// through all three transports. This file holds what that table cannot
// express: server→client requests, whose blocked form differs by transport
// by design; the view builder itself; and the two fitness functions that keep
// the view complete and stateless.

func TestClientView(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		// ok=false: the message is screened as it decodes, and only so.
		{name: "no fold pair", in: `{"a":1,"description":"x"}`},
		{name: "an exact duplicate is not a fold pair", in: `{"description":"a","description":"b"}`},
		{name: "a fold pair no struct decodes", in: `{"Zq":"a","zq":"b"}`},
		{name: "no exact member: the client reads neither", in: `{"Text":"a","TEXT":"b"}`},
		{name: "bytes after the object", in: `{"text":"p","Text":"d"} x`},
		{name: "a top-level array", in: `[{"text":"p","Text":"d"}]`},
		{name: "malformed", in: `{"text":"p","Text":`},

		// ok=true: the exact spelling is kept in each fold group.
		{name: "exact then fold", in: `{"description":"p","Description":"d"}`, want: `{"description":"p"}`},
		{name: "fold then exact", in: `{"Description":"d","description":"p"}`, want: `{"description":"p"}`},
		{name: "three spellings", in: `{"Description":"a","DESCRIPTION":"b","description":"c"}`, want: `{"description":"c"}`},
		{name: "nested in an array", in: `{"result":{"tools":[{"name":"t","description":"p","Description":"d"}]}}`, want: `{"result":{"tools":[{"description":"p","name":"t"}]}}`},
		{name: "envelope", in: `{"result":{"x":1},"Result":null}`, want: `{"result":{"x":1}}`},
		{name: "U+017F folds to s", in: `{"structuredContent":{"x":1},"ſtructuredContent":{"x":2}}`, want: `{"structuredContent":{"x":1}}`},
		{name: "an escaped key is folded as it decodes", in: `{"description":"p","Description":"d"}`, want: `{"description":"p"}`},
		{name: "a number keeps its literal", in: `{"maxTokens":1e400,"text":"p","Text":"d"}`, want: `{"maxTokens":1e400,"text":"p"}`},
		{name: "markup is not escaped", in: `{"text":"<b>&</b>","Text":"d"}`, want: `{"text":"<b>&</b>"}`},
		{name: "one leading BOM, as the client strips it", in: string(utf8BOM) + `{"text":"p","Text":"d"}`, want: `{"text":"p"}`},
		{name: "user-data groups without an exact field stay", in: `{"text":"p","Text":"d","structuredContent":{"Zq":1,"zq":2}}`, want: `{"structuredContent":{"Zq":1,"zq":2},"text":"p"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := clientView([]byte(c.in))
			if c.want == "" {
				if ok {
					t.Fatalf("clientView(%s) = %s, want no view", c.in, got)
				}
				return
			}
			if !ok || string(got) != c.want {
				t.Fatalf("clientView(%s) = %s (ok=%v), want %s", c.in, got, ok, c.want)
			}
		})
	}
}

// TestScreenAsClientReads_ServerRequests covers the two envelope keys of a
// server→client request. `Params` empties the sampling request the decoder
// reads, and `Method` makes it a ping, so on main both reached the client.
// Each variant must be screened exactly as its control is, on every
// transport.
func TestScreenAsClientReads_ServerRequests(t *testing.T) {
	injSSH, _ := buildInjectionTestCase(3)
	const marker = "id_rsa"
	params := `{"messages":[{"role":"user","content":{"type":"text","text":` + mustJSON(injSSH) + `}}],"maxTokens":200}`
	control := `{"jsonrpc":"2.0","id":5,"method":"sampling/createMessage","params":` + params + `}`
	variants := map[string]string{
		"Params-decoy": `{"jsonrpc":"2.0","id":5,"method":"sampling/createMessage","params":` + params + `,"Params":{}}`,
		"Method-decoy": `{"jsonrpc":"2.0","id":5,"method":"sampling/createMessage","Method":"ping","params":` + params + `}`,
	}
	for _, tr := range screenTransports(t) {
		cOut, cActed := tr.screen([]byte(control))
		if screenRank(cOut, cActed) != rankBlocked {
			t.Fatalf("%s: control not blocked (%s): the rows below would prove nothing", tr.name, cOut)
		}
		for name, body := range variants {
			out, acted := tr.screen([]byte(body))
			if got, want := screenRank(out, acted), screenRank(cOut, cActed); got != want {
				t.Errorf("%s/%s: outcome %d, control %d (out: %s)", tr.name, name, got, want, out)
			}
			if bytes.Contains(out, []byte(marker)) {
				t.Errorf("%s/%s: the injection reached the client: %s", tr.name, name, out)
			}
		}
	}
}

type screenTransport struct {
	name   string
	screen func([]byte) ([]byte, bool)
}

func screenTransports(t *testing.T) []screenTransport {
	t.Helper()
	p := NewProxy(ProxyConfig{Evaluator: NewPolicyEvaluator(parityPolicy()), Stderr: io.Discard, SchemaDriftCacheDir: t.TempDir()})
	hp := NewHTTPProxy(HTTPProxyConfig{UpstreamURL: "http://127.0.0.1:1", Evaluator: NewPolicyEvaluator(parityPolicy()), Stderr: io.Discard, SchemaDriftCacheDir: t.TempDir()})
	return []screenTransport{
		{"stdio", p.screenServerMessage},
		{"http-json", func(b []byte) ([]byte, bool) {
			out, acted := hp.filterJSONOne(b)
			if !acted {
				return nil, false
			}
			return out, true
		}},
		{"http-sse", hp.filterSSEData},
	}
}

// TestScreenAsClientReads_Chooser drives the outcome and receipt rules with a
// fake screen that answers according to which reading it was handed, so
// every pairing is reachable, including the two no real scanner produces on
// demand: a rewrite that passed a fold pair through, and a forward that
// leaves a receipt.
func TestScreenAsClientReads_Chooser(t *testing.T) {
	const body = `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"p","Text":"d"}]}}`
	blocked := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"blocked"}}`)
	canonical := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"d"}]}}`)
	passedThrough := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"p","Text":"d"}],"note":"x"}}`)
	viewRewrite := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)
	type screen struct {
		out   []byte
		acted bool
		rule  string // the receipt this screen writes, if any
	}
	cases := []struct {
		name          string
		decoded, view screen
		wantOut       []byte
		wantActed     bool
		wantRules     []string // in order; a trailing "*" means marked as the client view's
	}{
		{"view blocks, decoded forwards", screen{nil, false, ""}, screen{blocked, true, "r1"}, blocked, true, []string{"r1*"}},
		{"decoded blocks, view rewrites", screen{blocked, true, "r1"}, screen{viewRewrite, true, "r2"}, blocked, true, []string{"r1"}},
		{"both rewrite, decoded re-encoded", screen{canonical, true, "r1"}, screen{viewRewrite, true, "r2"}, canonical, true, []string{"r1"}},
		// The documented residual: a rewrite that passed a fold pair through
		// still stands, as main's. No scanner here does that.
		{"both rewrite, decoded passed a pair through", screen{passedThrough, true, "r1"}, screen{viewRewrite, true, "r2"}, passedThrough, true, []string{"r1"}},
		{"view blocks, decoded rewrote", screen{canonical, true, "r1"}, screen{blocked, true, "r2"}, blocked, true, []string{"r1", "r2*"}},
		{"both forward, each with its own receipt", screen{nil, false, "r1"}, screen{nil, false, "r2"}, nil, false, []string{"r1", "r2*"}},
		{"both forward, the same receipt", screen{nil, false, "r1"}, screen{nil, false, "r1"}, nil, false, []string{"r1"}},
		{"both block, the same receipt", screen{blocked, true, "r1"}, screen{blocked, true, "r1"}, blocked, true, []string{"r1"}},
		{"view blocks with the decoded screen's receipt too", screen{nil, false, "r1"}, screen{blocked, true, "r1"}, blocked, true, []string{"r1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got []string
			h := &MessageHandler{Stderr: io.Discard, OnAudit: func(e AuditEntry) {
				r := e.TriggeredRules[0]
				for _, reason := range e.Reasons {
					if reason == clientViewReason {
						r += "*"
					}
				}
				got = append(got, r)
			}}
			one := func(h *MessageHandler, b []byte) ([]byte, bool) {
				s := c.view
				if _, foldPair := clientView(b); foldPair {
					s = c.decoded // only the original bytes still carry the pair
				}
				if s.rule != "" {
					h.OnAudit(AuditEntry{TriggeredRules: []string{s.rule}, Decision: "AUDIT"})
				}
				return s.out, s.acted
			}
			out, acted := h.screenAsClientReads([]byte(body), one)
			if acted != c.wantActed || !bytes.Equal(out, c.wantOut) {
				t.Errorf("outcome (%s, %v), want (%s, %v)", out, acted, c.wantOut, c.wantActed)
			}
			if strings.Join(got, ",") != strings.Join(c.wantRules, ",") {
				t.Errorf("receipts %v, want %v", got, c.wantRules)
			}
		})
	}
}

// TestScreenAsClientReads_OneMessageOneReceipt: a message whose poison both
// screens find is recorded once, and a receipt only the client's view
// produced says so.
func TestScreenAsClientReads_OneMessageOneReceipt(t *testing.T) {
	injIgnore, _ := buildInjectionTestCase(2)
	j := mustJSON(injIgnore)
	cases := []struct {
		name, body  string
		viewReceipt bool // the only receipt is the client view's
	}{
		{name: "both screens see it", body: `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","Text":"ok","text":` + j + `}]}}`},
		{name: "only the client's view sees it", body: `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":` + j + `,"Text":"ok"}]}}`, viewReceipt: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var mu sync.Mutex
			var audits []AuditEntry
			p := NewProxy(ProxyConfig{
				Evaluator:           NewPolicyEvaluator(parityPolicy()),
				OnAudit:             func(e AuditEntry) { mu.Lock(); audits = append(audits, e); mu.Unlock() },
				Stderr:              io.Discard,
				SchemaDriftCacheDir: t.TempDir(),
			})
			out, _ := p.screenServerMessage([]byte(c.body))
			if !isErrorEnvelope(out) {
				t.Fatalf("not blocked: %s", out)
			}
			var hits []AuditEntry
			for _, a := range audits {
				for _, r := range a.TriggeredRules {
					if r == "tool-response-poisoning" {
						hits = append(hits, a)
						break
					}
				}
			}
			if len(hits) != 1 {
				t.Fatalf("want exactly one tool-response-poisoning receipt, got %d: %+v", len(hits), audits)
			}
			marked := false
			for _, r := range hits[0].Reasons {
				marked = marked || r == clientViewReason
			}
			if marked != c.viewReceipt {
				t.Errorf("receipt marked as the client view's = %v, want %v: %v", marked, c.viewReceipt, hits[0].Reasons)
			}
		})
	}
}

// TestClientViewFieldNamesCoverEveryTag derives the set of keys this
// package's structs decode from their json tags, and holds
// clientViewFieldNames to it in both directions. A name missing from the set
// is a field whose fold variants are never reduced: the #4407 bypass, for
// that field. It also refuses a struct that mixes tagged and untagged
// exported fields, because an untagged field is decoded under its Go name,
// folded, and has no exact spelling here to keep.
func TestClientViewFieldNamesCoverEveryTag(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	tags := map[string]bool{}
	parsed := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		parsed++
		ast.Inspect(f, func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok {
				return true
			}
			tagged := 0
			var untagged []string
			for _, field := range st.Fields.List {
				if len(field.Names) == 0 {
					continue // embedded: its own struct is inspected on its own
				}
				name := ""
				if field.Tag != nil {
					tag := reflect.StructTag(strings.Trim(field.Tag.Value, "`")).Get("json")
					if tag == "-" {
						continue
					}
					name = strings.Split(tag, ",")[0]
				}
				if name == "" {
					for _, id := range field.Names {
						if id.IsExported() {
							untagged = append(untagged, id.Name)
						}
					}
					continue
				}
				tagged++
				tags[name] = true
			}
			if tagged > 0 && len(untagged) > 0 {
				t.Errorf("%s: a struct with json tags also has untagged exported fields %v, which encoding/json decodes under their Go names: tag them", fset.Position(st.Pos()), untagged)
			}
			return true
		})
	}
	if parsed < 20 || len(tags) < 100 {
		t.Fatalf("vacuous: parsed %d files, found %d tags", parsed, len(tags))
	}
	var missing, stale []string
	for name := range tags {
		if _, ok := clientViewFieldNames[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range clientViewFieldNames {
		if !tags[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("json tags missing from clientViewFieldNames (add them): %q", missing)
	}
	if len(stale) > 0 {
		t.Errorf("clientViewFieldNames entries no struct decodes any more (remove them): %q", stale)
	}
	// Two fold-equal names would make "the exact spelling" ambiguous.
	byFold := map[string]string{}
	for name := range clientViewFieldNames {
		if other, ok := byFold[foldKey(name)]; ok {
			t.Errorf("fold-equal field names %q and %q: the client view cannot pick one", other, name)
		}
		byFold[foldKey(name)] = name
	}
}

// TestStatelessCloneSharesNoSessionState fills every field of a handler and
// requires the client-view clone to have dropped each one that is not shared
// on purpose. A new tracker added to MessageHandler fails here until someone
// decides which side of the line it is on.
func TestStatelessCloneSharesNoSessionState(t *testing.T) {
	sharedOnPurpose := map[string]string{
		"Evaluator":          "the policy; reading it records nothing",
		"OnAudit":            "replaced by the held sink (checked below)",
		"Stderr":             "replaced by a buffer (checked below)",
		"DataLabelScanner":   "a detection engine with no session state",
		"ManagedHost":        "a predicate",
		"SelfProtectCommand": "a predicate",
	}
	var h MessageHandler
	v := reflect.ValueOf(&h).Elem()
	for i := 0; i < v.NumField(); i++ {
		f, sf := v.Field(i), v.Type().Field(i)
		if !f.CanSet() {
			t.Fatalf("unexported field %s: decide whether the client-view clone may share it", sf.Name)
		}
		switch f.Kind() {
		case reflect.Ptr:
			f.Set(reflect.New(f.Type().Elem()))
		case reflect.Func:
			f.Set(reflect.MakeFunc(f.Type(), func(args []reflect.Value) []reflect.Value {
				out := make([]reflect.Value, f.Type().NumOut())
				for j := range out {
					out[j] = reflect.Zero(f.Type().Out(j))
				}
				return out
			}))
		case reflect.Interface:
			f.Set(reflect.ValueOf(io.Discard))
		case reflect.Map:
			f.Set(reflect.MakeMap(f.Type()))
		case reflect.Slice:
			f.Set(reflect.MakeSlice(f.Type(), 0, 0))
		case reflect.Chan:
			f.Set(reflect.MakeChan(f.Type(), 0))
		}
	}
	var held heldAudits
	var buf bytes.Buffer
	c := h.statelessClone(&held, &buf)
	cv := reflect.ValueOf(c).Elem()
	for i := 0; i < cv.NumField(); i++ {
		f, name := cv.Field(i), cv.Type().Field(i).Name
		switch f.Kind() {
		case reflect.Ptr, reflect.Func, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan:
		default:
			continue // a value: copied, so never shared
		}
		if _, ok := sharedOnPurpose[name]; ok {
			continue
		}
		if !f.IsNil() {
			t.Errorf("%s is shared with the client-view screen: nil it in statelessClone, or add it to sharedOnPurpose with the reason it holds no session state", name)
		}
	}
	c.OnAudit(AuditEntry{ToolName: "x"})
	if len(held.entries) != 1 {
		t.Errorf("the clone's OnAudit does not write to the held sink")
	}
	if c.Stderr != &buf {
		t.Errorf("the clone's Stderr is not the buffer it was given")
	}
}

// The detection pass runs on every server→client message, so its cost is
// measured beside the dispatch it sits in front of (benchResponse is the
// dispatch benchmark's 64KB tools/call body).
func BenchmarkClientViewDetection(b *testing.B) {
	for _, c := range []struct {
		name string
		data []byte
	}{
		{"tools-call-64KB", benchResponse()},
		{"tools-list-500", benchToolsList(500)},
	} {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(c.data)))
			for i := 0; i < b.N; i++ {
				if _, ok := clientView(c.data); ok {
					b.Fatal("a clean message produced a client view")
				}
			}
		})
	}
}

func benchToolsList(n int) []byte {
	var sb strings.Builder
	sb.WriteString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`{"name":"tool_` + strings.Repeat("x", 8) + `","description":"Reads a file from the workspace and returns its contents.","inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"path"}},"required":["path"]},"annotations":{"readOnlyHint":true}}`)
	}
	sb.WriteString(`]}}`)
	return []byte(sb.String())
}
