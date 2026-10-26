package analyzer

import "strings"

// Add layout tokens without changing literal offsets. Blank/comment lines and
// newlines inside delimiters do not affect Python's logical indentation. Exact
// whitespace prefixes deliberately reject ambiguous mixtures of tabs/spaces.
func inertPythonLayout(body string, tokens []inertToken) ([]inertToken, bool) {
	var out []inertToken
	indents := []string{""}
	var delimiters []string
	lineStart := true
	for _, tok := range tokens {
		if tok.kind == "punct" && tok.text == "\n" {
			if len(delimiters) == 0 {
				out = append(out, tok)
				lineStart = true
			}
			continue
		}
		if lineStart {
			start := strings.LastIndexAny(body[:tok.start], "\r\n") + 1
			end := start
			for end < len(body) && (body[end] == ' ' || body[end] == '\t') {
				end++
			}
			indent := body[start:end]
			previous := indents[len(indents)-1]
			if indent != previous {
				if strings.HasPrefix(indent, previous) {
					indents = append(indents, indent)
					out = append(out, inertToken{"<indent>", "layout", tok.start, tok.start})
				} else {
					for len(indents) > 1 && indent != indents[len(indents)-1] {
						indents = indents[:len(indents)-1]
						out = append(out, inertToken{"<dedent>", "layout", tok.start, tok.start})
					}
					if indent != indents[len(indents)-1] {
						return nil, false
					}
				}
			}
			lineStart = false
		}
		if tok.kind == "punct" {
			switch tok.text {
			case "(", "[", "{":
				delimiters = append(delimiters, tok.text)
			case ")", "]", "}":
				if len(delimiters) == 0 || !strings.Contains("() [] {}", delimiters[len(delimiters)-1]+tok.text) {
					return nil, false
				}
				delimiters = delimiters[:len(delimiters)-1]
			}
		}
		out = append(out, tok)
	}
	if len(delimiters) != 0 {
		return nil, false
	}
	out = append(out, inertToken{"\n", "punct", len(body), len(body)})
	for len(indents) > 1 {
		indents = indents[:len(indents)-1]
		out = append(out, inertToken{"<dedent>", "layout", len(body), len(body)})
	}
	return out, true
}

func (p *inertParser) pythonBlock(nested bool) {
	p.blocks++
	defer func() { p.blocks-- }()
	if p.blocks > 100 {
		p.ok = false
		return
	}
	for p.ok && p.pos < len(p.tokens) {
		if p.take("\n") {
			continue
		}
		if nested && p.take("<dedent>") {
			return
		}
		switch p.peek() {
		case "if":
			p.pythonIf()
		case "for", "while":
			p.pythonLoop()
		case "with":
			p.pos++
			v := p.expr()
			if v.kind != "file" && v.kind != "readfile" {
				p.ok = false
			}
			p.need("as")
			p.bind(p.id(), v)
			p.pythonSuite()
		default:
			p.pythonSimpleLine()
		}
	}
	if nested {
		p.ok = false
	}
}

func (p *inertParser) pythonSimpleLine() {
	for p.ok {
		switch p.peek() {
		case "assert":
			p.pos++
			p.condition()
			if p.take(",") {
				// Inspect even a message which would not be evaluated at runtime.
				// Assertions do not establish filename or callable provenance.
				if message := p.expr(); message.kind != "text" {
					p.ok = false
				}
			}
		case "break", "continue":
			if p.loops == 0 {
				p.ok = false
			}
			p.pos++
		case "pass":
			p.pos++
		default:
			p.statement()
		}
		if !p.take(";") || p.peek() == "\n" {
			break
		}
	}
	p.need("\n")
}

func (p *inertParser) pythonSuite() {
	p.need(":")
	if p.take("\n") {
		for p.take("\n") {
		}
		p.need("<indent>")
		p.pythonBlock(true)
	} else {
		p.pythonSimpleLine()
	}
}

func cloneInertVars(vars map[string]inertValue) map[string]inertValue {
	out := make(map[string]inertValue, len(vars))
	for name, v := range vars {
		out[name] = v
	}
	return out
}

func mergeInertValue(a, b inertValue) inertValue {
	if a == b {
		return a
	}
	if a.kind == "text" && b.kind == "text" {
		return inertValue{kind: "text"}
	}
	return inertValue{kind: "data"}
}

// A constant or file/path capability survives a join only if all routes agree.
// An unbound name on one route may raise, but must never inherit a destination
// from the other route. Values here contain no mutable container contents.
func mergeInertVars(a, b map[string]inertValue) map[string]inertValue {
	out := cloneInertVars(a)
	for name, v := range b {
		if old, exists := a[name]; exists {
			out[name] = mergeInertValue(old, v)
		} else {
			out[name] = inertValue{kind: "data"}
		}
	}
	for name := range a {
		if _, exists := b[name]; !exists {
			out[name] = inertValue{kind: "data"}
		}
	}
	return out
}

func (p *inertParser) pythonIf() {
	p.need("if")
	p.condition()
	base := cloneInertVars(p.vars)
	p.pythonSuite()
	joined := p.vars
	for p.take("\n") {
	}
	for p.ok && p.take("elif") {
		p.vars = cloneInertVars(base)
		p.condition()
		p.pythonSuite()
		joined = mergeInertVars(joined, p.vars)
		for p.take("\n") {
		}
	}
	if p.take("else") {
		p.vars = cloneInertVars(base)
		p.pythonSuite()
		p.vars = mergeInertVars(joined, p.vars)
	} else {
		p.vars = mergeInertVars(joined, base)
	}
}

// Find the whole loop before interpreting it, including nested suites. Values
// assigned anywhere in a loop are unknown at its entry: a later iteration may
// see an assignment below the current read, or a continue/break may skip one.
func (p *inertParser) loopBindings() map[string]bool {
	bound := map[string]bool{}
	brackets, indent := 0, 0
	colon, multiline := false, false
	for i := p.pos; i < len(p.tokens); i++ {
		t := p.tokens[i]
		if t.kind == "id" {
			if i+1 < len(p.tokens) {
				switch p.tokens[i+1].text {
				case "=", "+=", "-=":
					bound[t.text] = true
				}
			}
			if t.text == "as" && i+1 < len(p.tokens) {
				bound[p.tokens[i+1].text] = true
			}
			if t.text == "for" {
				for j := i + 1; j < len(p.tokens) && p.tokens[j].text != "in"; j++ {
					if p.tokens[j].kind == "id" {
						bound[p.tokens[j].text] = true
					} else if p.tokens[j].text != "," {
						break
					}
				}
			}
		}
		if t.kind == "punct" {
			switch t.text {
			case "(", "[", "{":
				brackets++
			case ")", "]", "}":
				brackets--
			case ":":
				if brackets == 0 && !colon {
					colon = true
					multiline = i+1 < len(p.tokens) && p.tokens[i+1].text == "\n"
				}
			case "\n":
				if colon && !multiline {
					return bound
				}
			}
		}
		if t.kind == "layout" {
			if t.text == "<indent>" {
				indent++
			} else {
				indent--
				if indent == 0 {
					return bound
				}
			}
		}
	}
	return bound
}

func (p *inertParser) pythonLoop() {
	bound := p.loopBindings()
	for name := range bound {
		if _, exists := p.vars[name]; exists {
			p.vars[name] = inertValue{kind: "data"}
		}
	}
	if p.take("for") {
		var targets []string
		for p.ok {
			targets = append(targets, p.id())
			if !p.take(",") {
				break
			}
		}
		p.need("in")
		iterable := p.expr()
		element := inertValue{kind: "data"}
		if iterable.kind == "textseq" || iterable.kind == "text" || iterable.kind == "file" || iterable.kind == "readfile" {
			element.kind = "text"
		}
		for _, name := range targets {
			p.bind(name, element)
		}
	} else {
		p.need("while")
		p.condition()
	}
	p.loops++
	p.pythonSuite()
	p.loops--
	for name := range bound {
		if _, exists := p.vars[name]; exists {
			p.vars[name] = inertValue{kind: "data"}
		}
	}
}
