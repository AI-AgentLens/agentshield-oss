package analyzer

import (
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// This is deliberately a small recognizer, not a general interpreter parser.
// The fixture-derived core is assignment, containers, print/repr, open/io.open,
// file.write and string.join (ufw/sudo-alternatives TNs and review t01/t02/a02).
// The closed extensions below cover string, regex, JSON and path operations and
// their synchronous Node equivalents. Ruby supports data assignment and
// File.read/write only; Perl has no admitted grammar. Unknown syntax fails closed.
//
// Values carry provenance: a method name alone is never sufficient. No function
// references, computed calls, callbacks, aliasing of callables, rebinding of
// builtins/modules, definitions, interpolation, decorators or dynamic imports
// are admitted. In particular, allowing *.write or merely checking identifiers
// before '(' would recreate the open-ended execution-channel problem.
var inertPythonCalls = map[string]string{
	"print": "data", "repr": "text", "str": "text", "len": "data",
	"sorted": "data", "enumerate": "data", "range": "data", "min": "data", "max": "data", "sum": "data",
	"set": "data", "list": "data", "dict": "data", "tuple": "data", "int": "data", "float": "data", "bool": "data",
	"any": "data", "all": "data", "zip": "data", "isinstance": "data", "reversed": "data",
	"open": "file", "io.open": "file",
	"re.escape": "text", "re.sub": "text", "re.search": "data", "re.match": "data", "re.findall": "data", "re.split": "data",
	"re.finditer": "data", "re.fullmatch": "data",
	"json.loads": "data", "json.load": "data", "json.dumps": "text", "json.dump": "data",
	"Path": "path", "pathlib.Path": "path",
	"os.path.join": "path", "os.path.expanduser": "path", "os.path.basename": "text", "os.path.dirname": "path",
	"os.listdir": "data", "os.walk": "data", "os.makedirs": "data",
	"os.path.exists": "data", "os.path.isfile": "data", "os.path.isdir": "data",
	"os.path.relpath": "text", "os.path.abspath": "text", "os.path.splitext": "data",
	"glob.glob": "data", "glob.iglob": "data",
	"sys.exit": "data", "sys.stdout.write": "data", "sys.stderr.write": "data",
}
var inertNodeCalls = map[string]string{
	"console.log": "data", "console.error": "data",
	"JSON.parse": "data", "JSON.stringify": "text",
	"fs.readFileSync": "text", "fs.writeFileSync": "data", "fs.appendFileSync": "data",
	"path.join": "path", "path.resolve": "path", "path.basename": "text", "path.dirname": "path",
}
var inertTextMethods = map[string]bool{
	"join": true, "replace": true, "split": true, "rsplit": true, "strip": true,
	"lstrip": true, "rstrip": true, "lower": true, "upper": true,
}

// These methods cannot introduce callable objects. Receivers and every argument
// must already be admitted data; file/path capabilities are handled separately.
var inertPythonDataMethods = map[string]bool{
	"append": true, "extend": true, "insert": true, "pop": true,
	"update": true, "setdefault": true, "count": true, "index": true,
	"find": true, "rfind": true, "startswith": true, "endswith": true,
	"partition": true, "rpartition": true, "items": true, "keys": true,
	"values": true, "get": true, "splitlines": true, "sort": true,
	"group": true, "groups": true,
}
var inertNodeTextMethods = map[string]bool{
	"trim": true, "trimStart": true, "trimEnd": true,
	"toLowerCase": true, "toUpperCase": true, "replace": true, "split": true,
}
var inertNodeDataMethods = map[string]bool{
	"push": true, "pop": true, "sort": true, "indexOf": true, "lastIndexOf": true,
	"startsWith": true, "endsWith": true,
}

// Encoding cookies can change the source bytes before Python lexes them. This
// recognizer accepts the supplied UTF-8 source only, never a second decoding.
var inertEncodingCookieRe = regexp.MustCompile(`coding[:=]\s*[-\w.]+`)

type inertToken struct {
	text, kind string
	start, end int
}

// scanInertBody is used ONLY by this exclusion. Comments cannot open literals;
// ordinary quotes cannot cross raw newlines, even after a backslash. Python
// triple quotes remain multiline. Unsupported lexical forms are rejected.
func scanInertBody(lang, body string) (tokens []inertToken, spans [][]int, ok bool) {
	py := lang == "python" || lang == "python2" || lang == "python3"
	for i := 0; i < len(body); {
		if len(tokens) > 20000 {
			return nil, nil, false
		}
		c := body[i]
		if c == ' ' || c == '\t' {
			i++
			continue
		}
		if (c == '#' && (py || lang == "ruby" || lang == "perl")) || (lang == "node" && strings.HasPrefix(body[i:], "//")) {
			start := i
			for i < len(body) && body[i] != '\n' && body[i] != '\r' && !strings.HasPrefix(body[i:], "\u2028") && !strings.HasPrefix(body[i:], "\u2029") {
				i++
			}
			if py && inertEncodingCookieRe.MatchString(body[start:i]) {
				return nil, nil, false
			}
			continue
		}
		if lang == "node" && strings.HasPrefix(body[i:], "/*") {
			end := strings.Index(body[i+2:], "*/")
			if end < 0 {
				return nil, nil, false
			}
			i += end + 4
			continue
		}
		prefix := ""
		if py {
			// Only non-interpolating prefixes. Keep spans on the quotes, as
			// before, so prefix bytes never enlarge the legacy intersection.
			for _, width := range []int{2, 1} {
				if i+width < len(body) && (body[i+width] == '\'' || body[i+width] == '"') {
					candidate := strings.ToLower(body[i : i+width])
					if candidate == "r" || candidate == "b" || candidate == "u" || candidate == "rb" || candidate == "br" {
						prefix = candidate
						break
					}
				}
			}
		}
		rawString := strings.Contains(prefix, "r")
		if prefix != "" {
			i += len(prefix)
			c = body[i]
		}
		start := i
		if c == '\r' {
			tokens = append(tokens, inertToken{"\n", "punct", i, i + 1})
			i++
			continue
		}
		if c == '\'' || c == '"' {
			width := 1
			if py && strings.HasPrefix(body[i:], strings.Repeat(string(c), 3)) {
				width = 3
			}
			i += width
			closed := false
			for i < len(body) {
				if width == 1 && (body[i] == '\n' || body[i] == '\r') {
					return nil, nil, false
				}
				if body[i] == '\\' {
					if i+1 >= len(body) || (width == 1 && (body[i+1] == '\n' || body[i+1] == '\r')) {
						return nil, nil, false
					}
					i += 2
					continue
				}
				if strings.HasPrefix(body[i:], strings.Repeat(string(c), width)) {
					i += width
					closed = true
					break
				}
				i++
			}
			if !closed {
				return nil, nil, false
			}
			raw := body[start+width : i-width]
			if strings.Contains(prefix, "b") {
				// Python bytes literals require ASCII source characters. Escaped
				// non-ASCII bytes stay data, with unknown filesystem spelling.
				for j := 0; j < len(raw); j++ {
					if raw[j] >= 0x80 {
						return nil, nil, false
					}
				}
			}
			if lang == "ruby" && c == '"' && strings.Contains(raw, "#") {
				return nil, nil, false
			}
			kind := "string"
			if rawString {
				kind = "rawstring"
			}
			tokens = append(tokens, inertToken{raw, kind, start, i})
			spans = append(spans, []int{start, i})
			continue
		}
		if inertIdentStart(c) {
			i++
			for i < len(body) && (inertIdentStart(body[i]) || body[i] >= '0' && body[i] <= '9') {
				i++
			}
			tokens = append(tokens, inertToken{body[start:i], "id", start, i})
			continue
		}
		if c >= '0' && c <= '9' {
			i++
			for i < len(body) && body[i] >= '0' && body[i] <= '9' {
				i++
			}
			tokens = append(tokens, inertToken{body[start:i], "number", start, i})
			continue
		}
		if py && (c == '=' || c == '!' || c == '<' || c == '>') && i+1 < len(body) && body[i+1] == '=' {
			i += 2
			tokens = append(tokens, inertToken{body[start:i], "punct", start, i})
			continue
		}
		if py && (c == '+' || c == '-') && i+1 < len(body) && body[i+1] == '=' {
			i += 2
			tokens = append(tokens, inertToken{body[start:i], "punct", start, i})
			continue
		}
		if !strings.ContainsRune("\n;=.,:()[]{}+-", rune(c)) && !(py && (c == '<' || c == '>')) {
			return nil, nil, false
		}
		i++
		tokens = append(tokens, inertToken{body[start:i], "punct", start, i})
	}
	return tokens, spans, true
}
func inertIdentStart(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' }

// Intersect byte ranges, not just literal identities: the old regex can split
// escaped quotes or overlap triples. Never redact a byte absent from either set.
func intersectInertLiteralSpans(lang, legacyBody, body string) [][]int {
	_, current, ok := scanInertBody(lang, body)
	if !ok {
		return nil
	}
	var out [][]int
	oldSpans := interpLiteralSpansForLang(lang, legacyBody)
	sort.Slice(oldSpans, func(i, j int) bool { return oldSpans[i][0] < oldSpans[j][0] })
	last := 0
	for _, old := range oldSpans {
		if old[0] < last {
			continue
		}
		last = old[1]
		for _, now := range current {
			start, end := max(old[0], now[0]), min(old[1], now[1])
			if start < end {
				out = append(out, []int{start, end})
			}
		}
	}
	// Both inputs are disjoint and ordered. Keep adjacent spans separate, as
	// the old redactor did, so item matching cannot gain a concatenated literal.
	return out
}

type inertValue struct {
	kind, constant string
	known          bool
}
type inertParser struct {
	lang       string
	tokens     []inertToken
	pos, depth int
	ok         bool
	vars       map[string]inertValue
	modules    map[string]bool
	loops      int
	blocks     int
	predicate  bool
}

func closedInertBody(lang, body string) bool {
	switch lang {
	case "python", "python2", "python3", "node", "ruby":
	default:
		return false
	}
	tokens, _, ok := scanInertBody(lang, body)
	if !ok {
		return false
	}
	if strings.HasPrefix(lang, "python") {
		tokens, ok = inertPythonLayout(body, tokens)
		if !ok {
			return false
		}
	}
	p := inertParser{lang: lang, tokens: tokens, ok: true, vars: map[string]inertValue{}, modules: map[string]bool{}}
	if p.py() {
		p.pythonBlock(false)
		return p.ok && p.pos == len(tokens)
	}
	for p.ok && p.pos < len(tokens) {
		if p.take("\n") || p.take(";") {
			continue
		}
		p.statement()
		if p.pos < len(tokens) && p.peek() != "\n" && p.peek() != ";" {
			p.ok = false
		}
	}
	return p.ok
}
func (p *inertParser) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	if p.tokens[p.pos].kind == "string" || p.tokens[p.pos].kind == "rawstring" || p.tokens[p.pos].kind == "number" {
		return "<data>"
	}
	return p.tokens[p.pos].text
}
func (p *inertParser) take(s string) bool {
	if p.peek() != s {
		return false
	}
	p.pos++
	return true
}
func (p *inertParser) need(s string) {
	if !p.take(s) {
		p.ok = false
	}
}
func (p *inertParser) id() string {
	if p.pos >= len(p.tokens) || p.tokens[p.pos].kind != "id" {
		p.ok = false
		return ""
	}
	s := p.peek()
	p.pos++
	return s
}
func (p *inertParser) py() bool { return strings.HasPrefix(p.lang, "python") }
func inertProtectedName(name string) bool {
	if name == "" || strings.Contains(name, "__") || name == "File" || name == "require" {
		return true
	}
	for call := range inertPythonCalls {
		if strings.Split(call, ".")[0] == name {
			return true
		}
	}
	for call := range inertNodeCalls {
		if strings.Split(call, ".")[0] == name {
			return true
		}
	}
	// Keywords are never binding targets or unbound predicate data.
	return strings.Contains(" False None True and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield ", " "+name+" ")
}

func (p *inertParser) bind(name string, v inertValue) {
	if inertProtectedName(name) || p.modules[name] {
		p.ok = false
		return
	}
	// A fresh sequence of strings can prove an immediate loop/index result is
	// text. Once bound, aliases and list mutation can change its contents, so
	// that stronger provenance must not survive assignment.
	if v.kind == "textseq" {
		v = inertValue{kind: "data"}
	}
	p.vars[name] = v
}
func (p *inertParser) statement() {
	if p.py() && p.take("import") {
		for p.ok {
			name := p.id()
			switch name {
			case "io", "re", "json", "pathlib", "os", "sys", "glob":
				p.modules[name] = true
			default:
				p.ok = false
			}
			if !p.take(",") {
				break
			}
		}
		return
	}
	if p.py() && p.take("from") {
		p.need("pathlib")
		p.need("import")
		p.need("Path")
		p.modules["Path"] = true
		return
	}
	if p.lang == "node" && (p.peek() == "const" || p.peek() == "let" || p.peek() == "var") {
		p.pos++
	}
	if p.py() && p.pos+1 < len(p.tokens) && p.tokens[p.pos].kind == "id" && (p.tokens[p.pos+1].text == "+=" || p.tokens[p.pos+1].text == "-=") {
		name := p.id()
		op := p.peek()
		p.pos++
		lhs, exists := p.vars[name]
		rhs := p.expr()
		if !exists || !inertSubscriptable(lhs) || !inertSubscriptable(rhs) {
			p.ok = false
		}
		result := inertValue{kind: "data"}
		if op == "+=" {
			result = addInertValues(lhs, rhs)
		}
		p.bind(name, result)
		return
	}
	if p.pos+1 < len(p.tokens) && p.tokens[p.pos].kind == "id" && p.tokens[p.pos+1].text == "=" {
		name := p.id()
		p.need("=")
		if p.lang == "node" && p.take("require") {
			p.need("(")
			v := p.expr()
			p.need(")")
			if !v.known || (v.constant != "fs" && v.constant != "path" && v.constant != "node:fs" && v.constant != "node:path") || name != strings.TrimPrefix(v.constant, "node:") {
				p.ok = false
				return
			}
			p.modules[name] = true
			return
		}
		v := p.expr()
		p.bind(name, v)
		return
	}
	p.expr()
}

// Precedence matters for destinations: comparisons and boolean selection must
// never inherit a constant from their left operand.
func (p *inertParser) expr() inertValue {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 100 || !p.ok {
		p.ok = false
		return inertValue{}
	}
	v := p.boolean("or")
	if p.py() && p.take("if") {
		p.condition()
		p.need("else")
		rhs := p.expr()
		v = mergeInertValue(v, rhs)
	}
	return v
}

func (p *inertParser) condition() {
	old := p.predicate
	p.predicate = true
	p.boolean("or")
	p.predicate = old
}

func (p *inertParser) boolean(op string) inertValue {
	var next func() inertValue
	if op == "or" {
		next = func() inertValue { return p.boolean("and") }
	} else {
		next = p.comparison
	}
	v := next()
	for p.py() && p.ok && p.take(op) {
		next()
		v = inertValue{kind: "data"}
	}
	return v
}

func (p *inertParser) comparison() inertValue {
	negated := false
	for p.py() && p.take("not") {
		negated = true
	}
	v := p.addition()
	for p.py() && p.ok {
		switch p.peek() {
		case "==", "!=", "<", ">", "<=", ">=", "in":
			p.pos++
			p.addition()
		case "not":
			p.pos++
			p.need("in")
			p.addition()
		case "is":
			p.pos++
			p.need("None")
		default:
			if negated {
				v = inertValue{kind: "data"}
			}
			return v
		}
		v = inertValue{kind: "data"}
	}
	return v
}

func (p *inertParser) addition() inertValue {
	v := p.postfix()
	for p.ok && p.take("+") {
		v = addInertValues(v, p.postfix())
	}
	return v
}

func addInertValues(a, b inertValue) inertValue {
	if a.kind == "text" && b.kind == "text" {
		if a.known && b.known {
			return inertValue{kind: "text", constant: a.constant + b.constant, known: true}
		}
		return inertValue{kind: "text"}
	}
	return inertValue{kind: "data"}
}

func inertSubscriptable(v inertValue) bool {
	return v.kind == "data" || v.kind == "text" || v.kind == "textseq"
}

func (p *inertParser) postfix() inertValue {
	v := p.atom()
	for p.ok {
		if p.take(".") {
			method := p.id()
			p.need("(")
			args := p.args(")", "."+method)
			v = p.method(v, method, args)
		} else if p.py() && p.take("[") {
			// Container contents never convey file/path/callable provenance.
			if !inertSubscriptable(v) {
				p.ok = false
			}
			// Both bounds are expressions, never uninterpreted source. Slices
			// keep the receiver's data kind but cannot prove a filename constant.
			if p.peek() != ":" {
				p.expr()
			}
			slice := p.take(":")
			if slice && p.peek() != "]" {
				p.expr()
			}
			p.need("]")
			if slice {
				v = inertValue{kind: v.kind}
			} else if v.kind == "textseq" || v.kind == "text" {
				// Bytes indexing can also yield an inert integer.
				v = inertValue{kind: "text"}
			} else {
				v = inertValue{kind: "data"}
			}
		} else {
			break
		}
	}
	return v
}

func (p *inertParser) atom() inertValue {
	if p.pos >= len(p.tokens) {
		p.ok = false
		return inertValue{}
	}
	tok := p.tokens[p.pos]
	p.pos++
	switch tok.kind {
	case "rawstring":
		return inertValue{"text", tok.text, true}
	case "string":
		// Decode only simple escapes. Other language-specific escapes remain data,
		// but cannot prove a filesystem destination safe.
		s, known := inertString(tok.text)
		return inertValue{"text", s, known}
	case "number":
		return inertValue{kind: "data"}
	case "id":
		if strings.Contains(tok.text, "__") {
			p.ok = false
			return inertValue{}
		}
		if v, exists := p.vars[tok.text]; exists {
			return v
		}
		switch tok.text {
		case "True", "False", "None", "true", "false", "null":
			return inertValue{kind: "data"}
		}
		name := tok.text
		// The only admitted attribute value is sys.argv. Stop before postfix
		// data methods; all other module attributes must be exact listed calls.
		if p.py() && name == "sys" && p.pos+1 < len(p.tokens) && p.peek() == "." && p.tokens[p.pos+1].text == "argv" {
			p.pos += 2
			if !p.modules["sys"] {
				p.ok = false
			}
			return inertValue{kind: "data"}
		}
		if p.py() && p.predicate && p.peek() != "." && p.peek() != "(" && !inertProtectedName(name) {
			// Preserve the historical data-only predicate's unbound references.
			// Such a reference raises at runtime; it cannot grant a capability.
			return inertValue{kind: "data"}
		}
		for p.take(".") {
			name += "." + p.id()
		}
		p.need("(")
		args := p.args(")", name)
		return p.call(name, args)
	case "punct":
		end := ""
		switch tok.text {
		case "(":
			end = ")"
		case "[":
			end = "]"
		case "{":
			end = "}"
		}
		if end != "" {
			args := p.args(end, "")
			if p.py() && tok.text == "(" && len(args.pos) == 1 && !args.comma {
				// Parentheses group an expression; only a comma makes a tuple.
				// Preserve read-only files and checked Paths as well as text.
				return args.pos[0]
			}
			if p.py() && tok.text != "{" && len(args.pos) > 0 {
				allText := true
				for _, item := range args.pos {
					allText = allText && item.kind == "text"
				}
				if allText {
					return inertValue{kind: "textseq"}
				}
			}
			return inertValue{kind: "data"}
		}
	}
	p.ok = false
	return inertValue{}
}

type inertArgs struct {
	pos   []inertValue
	kw    map[string]inertValue
	comma bool
}

// Callable-argument forms (re.sub, str.replace, JSON.parse/stringify, fs
// callbacks) are rejected by structure, not by an explicit rule: a bare
// callable is a value kind no API here accepts. The "callback" and
// "node-callback" cases in TestInterpInertClosedConstructs pin that; widen the
// argument handling below and those cases trip first (#4426).
func (p *inertParser) args(end, call string) inertArgs {
	// Historical unbound predicate references must not become callable values
	// supplied to an API (e.g. re.sub('x', eval, text) inside an if).
	oldPredicate := p.predicate
	if call != "" {
		p.predicate = false
	}
	defer func() { p.predicate = oldPredicate }()
	args := inertArgs{kw: map[string]inertValue{}}
	for p.ok {
		for p.take("\n") {
		}
		if p.take(end) {
			return args
		}
		keyword := ""
		if p.pos+1 < len(p.tokens) && p.tokens[p.pos].kind == "id" && p.tokens[p.pos+1].text == "=" {
			keyword = p.id()
			p.need("=")
			if !inertKeyword(call, keyword) {
				p.ok = false
			}
			if _, duplicate := args.kw[keyword]; duplicate {
				p.ok = false
			}
		} else if call == "" && p.lang == "node" && p.pos+1 < len(p.tokens) && p.tokens[p.pos].kind == "id" && p.tokens[p.pos+1].text == ":" {
			p.pos += 2
		}
		var v inertValue
		if p.py() && call == "isinstance" && len(args.pos) == 1 && keyword == "" {
			p.instanceType()
			v = inertValue{kind: "data"}
		} else {
			v = p.expr()
		}
		if keyword != "" {
			args.kw[keyword] = v
		} else {
			if len(args.kw) != 0 {
				p.ok = false
			}
			args.pos = append(args.pos, v)
		}
		if call == "" && p.take(":") {
			args.pos = append(args.pos, p.expr())
		}
		for p.take("\n") {
		}
		if p.take(end) {
			return args
		}
		p.need(",")
		args.comma = true
	}
	return args
}

// New calls take only positional data, except the explicitly requested options.
// Keep the old options tied to their APIs rather than enabling them globally.
func inertKeyword(call, keyword string) bool {
	switch call {
	case "sorted", ".sort":
		return keyword == "reverse"
	case ".mkdir":
		return keyword == "parents" || keyword == "exist_ok"
	case "os.makedirs":
		return keyword == "exist_ok"
	case "open", "io.open":
		return keyword == "encoding" || keyword == "errors" || keyword == "newline" || keyword == "mode"
	case ".read_text", ".write_text":
		return keyword == "encoding" || keyword == "errors" || keyword == "newline"
	case "json.dumps", "json.dump":
		return keyword == "indent" || keyword == "sort_keys" || keyword == "ensure_ascii"
	}
	return false
}

// Type names are allowed only in isinstance's second argument. They cannot be
// assigned, returned by an expression, passed as hooks, or called indirectly.
func (p *inertParser) instanceType() {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 100 || !p.ok {
		p.ok = false
		return
	}
	if p.take("(") {
		for p.ok && !p.take(")") {
			p.instanceType()
			if p.take(")") {
				return
			}
			p.need(",")
		}
		return
	}
	switch p.id() {
	case "str", "int", "float", "bool", "list", "dict", "tuple", "set":
	default:
		p.ok = false
	}
}
func (p *inertParser) call(name string, arguments inertArgs) inertValue {
	args := arguments.pos
	result := ""
	if p.py() {
		result = inertPythonCalls[name]
		root := strings.Split(name, ".")[0]
		if (strings.Contains(name, ".") || name == "Path") && !p.modules[root] {
			result = ""
		}
	} else if p.lang == "node" {
		result = inertNodeCalls[name]
		root := strings.Split(name, ".")[0]
		if (root == "fs" || root == "path") && !p.modules[root] {
			result = ""
		}
	} else if p.lang == "ruby" {
		if name == "File.write" {
			result = "data"
		}
		if name == "File.read" {
			result = "text"
		}
	}
	if result == "" {
		p.ok = false
		return inertValue{}
	}
	v := inertValue{kind: result}
	if p.py() && (name == "glob.glob" || name == "glob.iglob" || name == "os.listdir") {
		v.kind = "textseq"
	}
	if p.py() && (name == "sorted" || name == "list" || name == "tuple" || name == "reversed") && len(args) == 1 && args[0].kind == "textseq" {
		v.kind = "textseq"
	}
	// Unknown Python filenames may only produce a read-only capability. In
	// particular argv/loop/subscript values must never authorize a write. Check
	// the actual mode (including its keyword spelling) before relaxing a read.
	if p.py() && (name == "open" || name == "io.open") && len(args) > 0 && !args[0].known {
		mode := inertValue{kind: "text", constant: "r", known: true}
		if len(args) > 1 {
			mode = args[1]
		}
		if keywordMode, exists := arguments.kw["mode"]; exists {
			if len(args) > 1 {
				p.ok = false
			}
			mode = keywordMode
		}
		if !mode.known || (mode.constant != "r" && mode.constant != "rt" && mode.constant != "rb") {
			p.ok = false
		}
		return inertValue{kind: "readfile"}
	}
	// All write destinations and path constructors remain statically known.
	// Never guess that a write through a variable cannot reach an autorun file.
	file := name == "open" || name == "io.open" || strings.HasPrefix(name, "fs.") || strings.HasPrefix(name, "File.")
	if file || result == "path" || name == "os.makedirs" {
		if len(args) == 0 || !args[0].known {
			p.ok = false
			return v
		}
		dest := args[0].constant
		if strings.HasSuffix(name, ".join") || name == "path.resolve" || name == "Path" || name == "pathlib.Path" {
			for _, a := range args[1:] {
				if !a.known {
					p.ok = false
					return v
				}
				// Python path joins/Path and Node resolve reset on an absolute
				// component; Node path.join does not.
				if name != "path.join" && path.IsAbs(a.constant) {
					dest = a.constant
				} else {
					dest = path.Join(dest, a.constant)
				}
			}
		}
		if strings.HasSuffix(name, ".dirname") {
			dest = path.Dir(dest)
		}
		if strings.HasPrefix(dest, "|") || shellparse.IsDeferredExecTarget(dest) {
			p.ok = false
		}
		if result == "path" {
			v.constant, v.known = dest, true
		}
	}
	return v
}
func (p *inertParser) method(v inertValue, name string, arguments inertArgs) inertValue {
	if (v.kind == "file" || v.kind == "readfile") && p.py() {
		switch name {
		case "read", "readline":
			return inertValue{kind: "text"}
		case "readlines":
			return inertValue{kind: "textseq"}
		case "close":
			return inertValue{kind: "data"}
		case "write", "writelines":
			if v.kind == "file" {
				return inertValue{kind: "data"}
			}
		}
	}
	if v.kind == "path" && p.py() {
		switch name {
		case "read_text":
			return inertValue{kind: "text"}
		case "write_text":
			if !v.known || shellparse.IsDeferredExecTarget(v.constant) {
				p.ok = false
			}
			return inertValue{kind: "data"}
		case "exists", "is_file", "is_dir", "glob", "rglob":
			return inertValue{kind: "data"}
		case "mkdir":
			if !v.known || shellparse.IsDeferredExecTarget(v.constant) {
				p.ok = false
			}
			return inertValue{kind: "data"}
		}
	}
	if (v.kind == "text" || v.kind == "data" || v.kind == "textseq") && p.py() && inertPythonDataMethods[name] {
		// sort's key is never accepted, even None. Positional hooks cannot be
		// smuggled in as callable references because expressions reject them.
		// "group" on a data receiver can also reach Path.group, a read-only
		// owner lookup; it opens nothing and runs nothing, so it stays admitted.
		if name == "splitlines" || name == "partition" || name == "rpartition" {
			return inertValue{kind: "textseq"}
		}
		return inertValue{kind: "data"}
	}
	if (v.kind == "text" || v.kind == "data") && p.lang == "node" && inertNodeDataMethods[name] {
		if name == "sort" && (len(arguments.pos) != 0 || len(arguments.kw) != 0) {
			p.ok = false
		}
		return inertValue{kind: "data"}
	}
	// Path.replace renames a file. A container/loop result that might contain
	// a Path must not acquire that method merely because strings also have it.
	pythonText := p.py() && (v.kind == "text" || v.kind == "data" && name != "replace") && inertTextMethods[name]
	if pythonText || (v.kind == "text" && p.lang == "node" && inertNodeTextMethods[name]) {
		if name == "split" || name == "rsplit" {
			if p.py() {
				return inertValue{kind: "textseq"}
			}
			return inertValue{kind: "data"}
		}
		return inertValue{kind: "text"}
	}
	p.ok = false
	return inertValue{}
}
func inertString(raw string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			b.WriteByte(raw[i])
			continue
		}
		i++
		if i == len(raw) {
			return "", false
		}
		switch raw[i] {
		case '\\', '\'', '"':
			b.WriteByte(raw[i])
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		default:
			return "", false
		}
	}
	return b.String(), true
}
