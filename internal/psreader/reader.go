package psreader

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/facts"
)

// This file is the tokenizer ported from the #4245 experiment
// (~/dev/docs/pwsh-reader-experiment-4245/goreader/main.go, frozen by hash
// a3c3a3ad…). It has no grammar tables and no cmdlet metadata: it reads just
// enough of PowerShell to report commands, parameters, argument values and the
// strings inside expressions, and its output is held to PowerShell's own
// parser by the expected-facts differential (differential_test.go).
//
// Changes from the experiment, each one a production concern rather than a
// grammar change:
//   - every command keeps its elements in order, with their source text, so
//     nested interpreters (`powershell -c …`, `cmd /c …`) can be read;
//   - notes are structured (detail and position);
//   - nesting is bounded (maxDepth): a Go stack overflow is fatal and cannot
//     be recovered, so deep input must stop the reader, not the process;
//   - slices of the source are clamped, and a `${` or `<#` left open no
//     longer moves the cursor past the end;
//   - a switch body that does not advance is skipped one rune at a time;
//   - the text of `$(…)rest` is cut at the start of `rest`, not at its decoded
//     length.

type kind int

const (
	kStr   kind = iota // string literal or bareword, variables left unexpanded
	kVar               // a bare variable
	kExpr              // anything else
	kBlock             // a script-block literal: its contents are read in place
)

type value struct {
	text   string
	k      kind
	static bool // no expansion inside: usable as a command name
	plain  bool // a bareword with no quotes, escapes or variables
	// dyn are the byte ranges of a kStr text that are computed at run time,
	// each kept as its source text: a variable or a subexpression (#4768).
	// The rest of the text is literal. Empty when static.
	dyn []span
	// items are an array argument's elements (`a,b`), which a native
	// program receives as separate arguments (#4768); the value itself is
	// an expression.
	items []value
}

// span is a byte range [a, b) of a value's text.
type span struct{ a, b int }

// shifted appends src to dst, each range moved by off.
func shifted(dst, src []span, off int) []span {
	for _, s := range src {
		dst = append(dst, span{s.a + off, s.b + off})
	}
	return dst
}

var (
	exprV  = value{text: facts.Expr, k: kExpr}
	blockV = value{text: facts.Expr, k: kBlock}
)

// element is one command element after the name, in source order.
type element struct {
	param    string // "-name", lower-cased; "" for an argument
	raw      string // the element's source text
	val      value  // an argument's value, or a parameter's `-name:value`
	hasVal   bool
	verbatim bool // the text after --%, passed on exactly as written
	// start and end are the rune offsets of the element's source text.
	// Two elements with no space between them (`-Dfoo.bar` is the
	// parameter `-Dfoo` and the argument `.bar`) are one native argument.
	start, end int
}

type rawCommand struct {
	name     string // as written; facts.Dynamic when computed
	nameRaw  string // source text of the name element
	nameKind kind
	op       string // "&", "." or ""
	params   []string
	args     []string
	elems    []element
	// start and end are the rune offsets of the command (its name through
	// its last element), and pipeStart the offset its pipeline starts at:
	// the commands whose start lies in [pipeStart, end), other than this
	// one, are the ones whose output can reach it (facts.Command.InputFrom).
	start, end, pipeStart int
}

type rawNote struct {
	detail string
	pos    int
}

// rawCall is one .NET method call (facts.Call): name as written, prefixed
// `<type>::` or `.`; start and end its rune offsets (the type literal's `[`
// or the `.`, through the closing parenthesis); strFrom and strTo the
// strings its arguments added to reader.strs.
type rawCall struct {
	name           string
	start, end     int
	strFrom, strTo int
}

// maxDepth bounds bracket nesting. Real scripts nest a few dozen levels; the
// bound exists so that adversarial input ends the read with a parse_error
// note instead of exhausting the goroutine stack.
const maxDepth = 256

type reader struct {
	s    []rune
	p    int
	cmds []*rawCommand
	// calls are the .NET method calls read, in the order their argument
	// lists open (read sorts them by start).
	calls []*rawCall
	strs  []string
	// redirs are the literal targets of output redirections (`> x`, `>> x`,
	// `2> x`, `*> x`), each also in strs: a file the text writes.
	redirs []string
	notes  []rawNote
	steps  int
	depth  int
	// pipeStart is the offset the pipeline being read starts at.
	pipeStart int
	// pipes maps a pipeline's start offset to its statement chain and the
	// operator before it (facts.Facts.Native, #4768); chainStart and chainOp
	// are the chain being read.
	pipes      map[int]pipeInfo
	chainStart int
	chainOp    string
	// panicAt, when positive, makes the reader panic at that step. Tests use
	// it to prove that Read survives an internal failure.
	panicAt int
}

// In argument mode a signed number (-1) is a plain string, so the sign is not
// part of the pattern; a statement that starts with -1 is an expression anyway.
var numberRe = regexp.MustCompile(`^(0[xX][0-9a-fA-F]+|(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?)([kKmMgGtTpP][bB])?[lLdDnNuUsSyY]*$`)

var numberPrefixRe = regexp.MustCompile(`^(0[xX][0-9a-fA-F]+|\d+(\.\d+)?([eE][+-]?\d+)?)([kKmMgGtTpP][bB])?`)

var keywords = map[string]bool{
	"if": true, "elseif": true, "else": true, "while": true, "until": true, "for": true,
	"foreach": true, "switch": true, "do": true, "try": true, "catch": true, "finally": true,
	"trap": true, "function": true, "filter": true, "workflow": true, "configuration": true,
	"param": true, "begin": true, "process": true, "end": true, "dynamicparam": true, "clean": true,
	"return": true, "throw": true, "exit": true, "break": true, "continue": true, "using": true,
	"class": true, "enum": true, "data": true,
}

func isDash(c rune) bool { return c == '-' || c == '\u2013' || c == '\u2014' || c == '\u2015' }
func isSQ(c rune) bool {
	return c == '\'' || c == '\u2018' || c == '\u2019' || c == '\u201a' || c == '\u201b'
}
func isDQ(c rune) bool    { return c == '"' || c == '\u201c' || c == '\u201d' || c == '\u201e' }
func isSpace(c rune) bool { return c == ' ' || c == '\t' || c == '\f' || c == '\v' || c == '\u00a0' }
func isNL(c rune) bool    { return c == '\n' || c == '\r' }
func isLetter(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c > 127 && c != '\u00a0'
}
func isDigit(c rune) bool { return c >= '0' && c <= '9' }
func isVarChar(c rune) bool {
	return isLetter(c) || isDigit(c) || c == '_' || c == '?'
}
func isVarStart(c rune) bool { return isVarChar(c) || c == '{' || c == '$' || c == '^' }
func isParamStart(c rune) bool {
	return isLetter(c) || c == '_' || c == '?'
}

func (r *reader) peek(k int) rune {
	if i := r.p + k; i >= 0 && i < len(r.s) {
		return r.s[i]
	}
	return 0
}
func (r *reader) eof() bool { return r.p >= len(r.s) }
func (r *reader) at(lit string) bool {
	i := 0
	for _, c := range lit {
		if r.peek(i) != c {
			return false
		}
		i++
	}
	return true
}
func (r *reader) note(s string) { r.notes = append(r.notes, rawNote{detail: s, pos: r.p}) }

// text returns the source between a and b, clamped to the input.
func (r *reader) text(a, b int) string {
	if a < 0 {
		a = 0
	}
	if b > len(r.s) {
		b = len(r.s)
	}
	if a >= b {
		return ""
	}
	return string(r.s[a:b])
}

// advance moves the cursor by n, never past the end.
func (r *reader) advance(n int) {
	r.p += n
	if r.p > len(r.s) {
		r.p = len(r.s)
	}
}

// enter records one level of nesting. When the bound is reached it notes
// the fact and moves to the end of input, so every caller unwinds.
func (r *reader) enter() bool {
	if r.depth >= maxDepth {
		r.note(fmt.Sprintf("nesting deeper than %d", maxDepth))
		r.p = len(r.s)
		return false
	}
	r.depth++
	return true
}

func (r *reader) leave() { r.depth-- }

func escapeRune(c rune) rune {
	switch c {
	case '0':
		return 0
	case 'a':
		return '\a'
	case 'b':
		return '\b'
	case 'e':
		return 0x1b
	case 'f':
		return '\f'
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	case 't':
		return '\t'
	case 'v':
		return '\v'
	}
	return c
}

func (r *reader) skipSpace() {
	for !r.eof() {
		c := r.peek(0)
		switch {
		case isSpace(c):
			r.p++
		case c == '`' && isNL(r.peek(1)):
			r.p += 2
			if r.peek(-1) == '\r' && r.peek(0) == '\n' {
				r.p++
			}
		case c == '<' && r.peek(1) == '#':
			r.p += 2
			for !r.eof() && !(r.peek(0) == '#' && r.peek(1) == '>') {
				r.p++
			}
			r.advance(2)
		case c == '#':
			for !r.eof() && !isNL(r.peek(0)) {
				r.p++
			}
		default:
			return
		}
	}
}

func (r *reader) skipSpaceNL() {
	for {
		r.skipSpace()
		if isNL(r.peek(0)) {
			r.p++
			continue
		}
		return
	}
}

// statements reads statements until closer (consumed) or EOF.
func (r *reader) statements(closer rune) {
	if !r.enter() {
		return
	}
	defer r.leave()
	for {
		r.steps++
		if r.panicAt > 0 && r.steps >= r.panicAt {
			panic("psreader: forced failure (test)")
		}
		if r.steps > 50*(len(r.s)+10) {
			r.note("step limit")
			r.p = len(r.s)
			return
		}
		r.skipSpaceNL()
		if r.eof() {
			if closer != 0 {
				r.note("unclosed " + string(closer))
			}
			return
		}
		c := r.peek(0)
		if c == ';' {
			r.p++
			continue
		}
		if closer != 0 && c == closer {
			r.p++
			return
		}
		if c == ')' || c == '}' || c == ']' {
			if closer == 0 {
				r.note("stray " + string(c))
				r.p++
				continue
			}
			r.note("mismatched " + string(c))
			return
		}
		before := r.p
		r.chain(closer)
		if r.p == before {
			r.note(fmt.Sprintf("stuck %q", c))
			r.p++
		}
	}
}

// pipeInfo is the statement chain a pipeline belongs to (the offset the
// chain starts at) and the operator before it in that chain: `&&`, `||`, or
// "" for the chain's first pipeline.
type pipeInfo struct {
	chain int
	op    string
}

func (r *reader) chain(closer rune) {
	savedStart, savedOp := r.chainStart, r.chainOp
	defer func() { r.chainStart, r.chainOp = savedStart, savedOp }()
	r.skipSpace()
	r.chainStart, r.chainOp = r.p, ""
	for {
		r.pipeline(closer)
		r.skipSpace()
		if r.at("&&") || r.at("||") {
			r.chainOp = r.text(r.p, r.p+2)
			r.p += 2
			r.skipSpaceNL()
			continue
		}
		return
	}
}

func (r *reader) pipeline(closer rune) {
	saved := r.pipeStart
	r.skipSpace()
	r.pipeStart = r.p
	defer func() { r.pipeStart = saved }()
	if _, seen := r.pipes[r.p]; !seen && r.pipes != nil {
		r.pipes[r.p] = pipeInfo{chain: r.chainStart, op: r.chainOp}
	}
	first := true
	for {
		r.skipSpace()
		r.element(closer, first)
		first = false
		r.skipSpace()
		if r.peek(0) == '|' && r.peek(1) != '|' {
			r.p++
			r.skipSpaceNL()
			continue
		}
		if r.peek(0) == '&' && r.peek(1) != '&' { // background job (PowerShell 7)
			r.p++
		}
		return
	}
}

func (r *reader) peekIdent() string {
	i := r.p
	for i < len(r.s) && (r.s[i] >= 'a' && r.s[i] <= 'z' || r.s[i] >= 'A' && r.s[i] <= 'Z') {
		i++
	}
	return string(r.s[r.p:i])
}

func (r *reader) keywordAt() string {
	w := r.peekIdent()
	if w == "" || !keywords[strings.ToLower(w)] {
		return ""
	}
	n := r.peek(len(w)) // ASCII letters only: bytes == runes
	if n == 0 || isSpace(n) || isNL(n) || n == '(' || n == '{' || n == ';' || n == ')' || n == '}' {
		return strings.ToLower(w)
	}
	return ""
}

func (r *reader) peekWord() string {
	i := r.p
	for i < len(r.s) && !isSpace(r.s[i]) && !isNL(r.s[i]) && !strings.ContainsRune(";|&(){},]", r.s[i]) {
		i++
	}
	return string(r.s[r.p:i])
}

func (r *reader) element(closer rune, first bool) {
	c := r.peek(0)
	if c == 0 || isNL(c) || c == ';' || c == ')' || c == '}' || (c == ']' && closer == ']') {
		return
	}
	if c == '&' && r.peek(1) != '&' {
		r.p++
		r.skipSpace()
		r.command("&", closer)
		return
	}
	if c == '.' {
		n := r.peek(1)
		if isSpace(n) || n == '{' || n == '$' || n == '(' || isSQ(n) || isDQ(n) {
			r.p++
			r.skipSpace()
			r.command(".", closer)
			return
		}
	}
	if first {
		if kw := r.keywordAt(); kw != "" {
			r.keyword(kw, closer)
			return
		}
	}
	if r.startsExpression(c) {
		r.expression(closer)
		return
	}
	r.command("", closer)
}

func (r *reader) startsExpression(c rune) bool {
	switch {
	case c == '$', isSQ(c), isDQ(c), c == '(', c == '[', c == '@', c == '!', c == ',', c == '+', c == '{':
		return true
	case isDigit(c) || c == '.' && isDigit(r.peek(1)):
		// a number token followed by an operator (100/[double]$n, 0..5) is
		// an expression; 7z.exe is a command name
		w := r.peekWord()
		m := numberPrefixRe.FindString(w)
		rest := strings.TrimPrefix(w, m)
		return m != "" && (rest == "" || strings.ContainsAny(rest[:1], "+-*/%=.[]"))
	case isDash(c):
		n := r.peek(1)
		return isDigit(n) || isLetter(n) || n == '.'
	}
	return false
}

func (r *reader) block() {
	r.skipSpaceNL()
	if r.peek(0) == '{' {
		r.p++
		r.statements('}')
	}
}

// typeLiteral reads [Type], [Type[]] and [Attribute(args)]; attribute
// arguments are expressions, so their strings count.
func (r *reader) typeLiteral() {
	r.p++
	depth := 1
	for !r.eof() && depth > 0 {
		switch r.peek(0) {
		case '(':
			r.p++
			r.attributeArgs()
			continue
		case '[':
			depth++
		case ']':
			depth--
		}
		r.p++
	}
}

// attributeArgs reads (Mandatory, Position = 0, 'a', 'b'): bare names and
// Name = are syntax, never commands; the values are expressions.
func (r *reader) attributeArgs() {
	if !r.enter() {
		return
	}
	defer r.leave()
	for {
		r.skipSpaceNL()
		c := r.peek(0)
		switch {
		case c == 0:
			return
		case c == ')':
			r.p++
			return
		case c == ',':
			r.p++
		case isLetter(c) || c == '_':
			r.peekAndSkipIdent()
			r.skipSpace()
			if r.peek(0) == '=' {
				r.p++
				r.expression(')')
			}
		default:
			before := r.p
			r.expression(')')
			if r.p == before {
				r.p++
			}
		}
	}
}

func (r *reader) skipBalanced(open, close rune) {
	depth := 0
	for !r.eof() {
		c := r.peek(0)
		r.p++
		if c == open {
			depth++
		} else if c == close {
			depth--
			if depth == 0 {
				return
			}
		}
	}
}

func (r *reader) keyword(kw string, closer rune) {
	r.p += len(kw)
	switch kw {
	case "if", "elseif", "while", "until", "for":
		r.skipSpaceNL()
		if r.peek(0) == '(' {
			r.p++
			r.statements(')')
		}
		r.block()
		if kw == "if" || kw == "elseif" {
			save := r.p
			r.skipSpaceNL()
			if next := r.keywordAt(); next == "elseif" || next == "else" {
				if !r.enter() {
					return
				}
				r.keyword(next, closer)
				r.leave()
			} else {
				r.p = save
			}
		}
	case "foreach":
		r.flags()
		r.skipSpaceNL()
		if r.peek(0) == '(' {
			r.p++
			r.skipSpaceNL()
			if r.peek(0) == '$' {
				r.variable()
			}
			r.skipSpaceNL()
			if strings.EqualFold(r.peekIdent(), "in") {
				r.p += 2
			}
			r.skipSpaceNL()
			r.chain(')')
			r.skipSpaceNL()
			if r.peek(0) == ')' {
				r.p++
			}
		}
		r.block()
	case "switch":
		r.flags()
		r.skipSpaceNL()
		if r.peek(0) == '(' {
			r.p++
			r.statements(')')
		}
		r.skipSpaceNL()
		if r.peek(0) == '{' {
			r.p++
			r.switchBody()
		}
	case "data":
		r.skipSpace()
		if isLetter(r.peek(0)) {
			r.peekAndSkipIdent()
		}
		r.block()
	case "else", "try", "finally", "begin", "process", "end", "dynamicparam", "clean", "do":
		r.block()
	case "catch", "trap":
		for {
			r.skipSpaceNL()
			if r.peek(0) == '[' {
				r.typeLiteral()
				continue
			}
			if r.peek(0) == ',' {
				r.p++
				continue
			}
			break
		}
		r.block()
	case "function", "filter", "workflow", "configuration":
		r.skipSpace()
		r.bareword(0)
		r.skipSpace()
		if r.peek(0) == '(' {
			r.p++
			r.statements(')')
		}
		r.block()
	case "param":
		r.skipSpaceNL()
		if r.peek(0) == '(' {
			r.p++
			r.statements(')')
		}
	case "return", "throw", "exit":
		r.skipSpace()
		r.pipeline(closer)
	case "break", "continue":
		r.skipSpace()
		if isLetter(r.peek(0)) {
			r.peekAndSkipIdent()
		}
	case "using":
		r.skipSpace()
		r.peekAndSkipIdent() // namespace | module | assembly
		r.skipSpace()
		if v := r.argSingle(closer, false); v.k == kStr {
			r.strs = append(r.strs, v.text)
		}
	case "class", "enum":
		r.note(kw + " body not read")
		for !r.eof() && r.peek(0) != '{' {
			r.p++
		}
		r.skipBalanced('{', '}')
	}
}

func (r *reader) peekAndSkipIdent() {
	for !r.eof() && (isVarChar(r.peek(0)) || r.peek(0) == '.') {
		r.p++
	}
}

// flags skips -Regex / -Parallel style switches after foreach/switch.
func (r *reader) flags() {
	for {
		r.skipSpace()
		if isDash(r.peek(0)) && isLetter(r.peek(1)) {
			r.p++
			r.peekAndSkipIdent()
			continue
		}
		return
	}
}

func (r *reader) switchBody() {
	if !r.enter() {
		return
	}
	defer r.leave()
	for {
		r.skipSpaceNL()
		c := r.peek(0)
		before := r.p
		switch {
		case c == 0:
			r.note("unclosed switch")
			return
		case c == '}':
			r.p++
			return
		case c == ';':
			r.p++
			continue
		case c == '{':
			r.p++
			r.statements('}')
		case isSQ(c):
			r.strs = append(r.strs, r.singleQuoted())
		case isDQ(c):
			r.strs = append(r.strs, r.doubleQuoted().text)
		case c == '$':
			r.variable()
		case c == '(':
			r.p++
			r.statements(')')
		default:
			w := r.bareword(0)
			if !strings.EqualFold(w.text, "default") && !numberRe.MatchString(w.text) {
				r.strs = append(r.strs, w.text)
			}
		}
		if r.p == before {
			// a rune no case consumes (`|`, `,`, `>` …): the experiment
			// looped here forever
			r.note(fmt.Sprintf("switch stuck %q", c))
			r.p++
			continue
		}
		r.skipSpace()
		if r.peek(0) == '{' {
			r.p++
			r.statements('}')
		}
	}
}

func (r *reader) hashtable() {
	if !r.enter() {
		return
	}
	defer r.leave()
	for {
		r.skipSpaceNL()
		c := r.peek(0)
		switch {
		case c == 0:
			r.note("unclosed @{")
			return
		case c == '}':
			r.p++
			return
		case c == ';':
			r.p++
			continue
		case isSQ(c):
			r.strs = append(r.strs, r.singleQuoted())
		case isDQ(c):
			r.strs = append(r.strs, r.doubleQuoted().text)
		case c == '$':
			r.variable()
		case c == '(':
			r.p++
			r.statements(')')
		default:
			start := r.p
			for !r.eof() && !isSpace(r.peek(0)) && !isNL(r.peek(0)) && r.peek(0) != '=' && r.peek(0) != '}' && r.peek(0) != ';' {
				r.p++
			}
			if r.p > start {
				r.strs = append(r.strs, r.text(start, r.p))
			} else {
				r.p++
			}
		}
		r.skipSpace()
		if r.peek(0) == '=' {
			r.p++
			r.skipSpaceNL()
			r.chain('}')
		}
	}
}

func (r *reader) number() {
	for !r.eof() && (isVarChar(r.peek(0)) || r.peek(0) == '.') {
		if r.peek(0) == '.' && r.peek(1) == '.' { // range operator 1..5
			return
		}
		r.p++
	}
}

// member reads a member name after `.` or `::` and, when an argument list
// follows, the call's arguments. A call is recorded (facts.Call) when prefix
// is not empty and the name is literal: prefix is `<type>::` for a static
// call on a type literal and `.` for an instance call, and start is the
// call's offset. A static member of a value (`$t::M()`) passes "".
func (r *reader) member(prefix string, start int) {
	r.skipSpace()
	c := r.peek(0)
	name, literal := "", true
	switch {
	case isSQ(c):
		name = r.singleQuoted()
	case isDQ(c):
		v := r.doubleQuoted()
		name, literal = v.text, v.static
	case c == '$':
		r.variable()
		literal = false
	default:
		from := r.p
		for !r.eof() && isVarChar(r.peek(0)) {
			r.p++
		}
		name = r.text(from, r.p)
	}
	if r.peek(0) != '(' {
		return
	}
	var call *rawCall
	if prefix != "" && literal && name != "" {
		call = &rawCall{name: prefix + name, start: start, strFrom: len(r.strs)}
		r.calls = append(r.calls, call)
	}
	r.p++
	r.statements(')')
	if call != nil {
		call.end, call.strTo = r.p, len(r.strs)
	}
}

// postfix consumes .Member, ::Static, (args) and [index] after a value.
func (r *reader) postfix() {
	for {
		switch {
		case r.peek(0) == '.' && (isVarChar(r.peek(1)) || isSQ(r.peek(1)) || isDQ(r.peek(1)) || r.peek(1) == '$'):
			at := r.p
			r.p++
			r.member(".", at)
		case r.peek(0) == ':' && r.peek(1) == ':':
			r.p += 2
			r.member("", 0)
		case r.peek(0) == '[':
			r.p++
			r.statements(']')
		default:
			return
		}
	}
}

func (r *reader) expression(closer rune) {
	if !r.enter() {
		return
	}
	defer r.leave()
	expectOperand, lastType := true, false
	// typeAt and typeEnd are the offsets of the last type literal read, so a
	// `::` right after it is a static call on that type (facts.Call).
	typeAt, typeEnd := -1, -1
	for {
		if expectOperand {
			r.skipSpaceNL()
		} else {
			r.skipSpace()
		}
		c := r.peek(0)
		if c == 0 || isNL(c) || c == ';' || c == ')' || c == '}' || c == '|' || c == '&' || (c == ']' && closer == ']') {
			return
		}
		if r.redirection() {
			expectOperand = false
			continue
		}
		if c != '[' {
			lastType = false
		}
		switch {
		case isSQ(c):
			r.strs = append(r.strs, r.singleQuoted())
			expectOperand = false
		case isDQ(c):
			r.strs = append(r.strs, r.doubleQuoted().text)
			expectOperand = false
		case c == '@' && (isSQ(r.peek(1)) || isDQ(r.peek(1))):
			if v, ok := r.hereString(); ok {
				r.strs = append(r.strs, v.text)
			} else {
				r.p++
			}
			expectOperand = false
		case c == '@' && r.peek(1) == '(':
			r.p += 2
			r.statements(')')
			expectOperand = false
		case c == '@' && r.peek(1) == '{':
			r.p += 2
			r.hashtable()
			expectOperand = false
		case c == '$':
			if r.peek(1) == '(' {
				r.p += 2
				r.statements(')')
			} else {
				r.variable()
			}
			expectOperand = false
		case c == '(':
			r.p++
			r.statements(')')
			expectOperand = false
		case c == '{':
			r.p++
			r.statements('}')
			expectOperand = false
		case c == '[':
			// [Type] and [Attribute()] stack before a value; only a [ right
			// after a value is an index.
			if expectOperand || lastType {
				typeAt = r.p
				r.typeLiteral()
				typeEnd = r.p
				lastType = true
				continue
			}
			r.p++
			r.statements(']')
			expectOperand = false
		case c == ':' && r.peek(1) == ':':
			prefix, at := "", 0
			if r.p == typeEnd && typeEnd-typeAt > 2 {
				prefix, at = r.text(typeAt+1, typeEnd-1)+"::", typeAt
			}
			r.p += 2
			r.member(prefix, at)
			expectOperand = false
		case c == '.' && !expectOperand && r.peek(1) != '.':
			at := r.p
			r.p++
			r.member(".", at)
			expectOperand = false
		case c == ',':
			r.p++
			expectOperand = true
		case c == '=':
			r.p++
			r.skipSpaceNL()
			r.chain(closer)
			return
		case strings.ContainsRune("+*/%", c) && r.peek(1) == '=' || isDash(c) && r.peek(1) == '=':
			r.p += 2
			r.skipSpaceNL()
			r.chain(closer)
			return
		case c == '?' && r.peek(1) == '?' && r.peek(2) == '=':
			r.p += 3
			r.skipSpaceNL()
			r.chain(closer)
			return
		case isDash(c) && isLetter(r.peek(1)):
			r.p++
			r.peekAndSkipIdent()
			expectOperand = true
		case isDigit(c) || c == '.' && isDigit(r.peek(1)):
			r.number()
			expectOperand = false
		case isLetter(c) || c == '_':
			r.peekAndSkipIdent()
			expectOperand = true
		default:
			r.p++
			expectOperand = true
		}
	}
}

func (r *reader) cmdEnd(c rune, closer rune) bool {
	return c == 0 || isNL(c) || c == ';' || c == '|' || c == '&' || c == ')' || c == '}' || (c == ']' && closer == ']')
}

func (r *reader) command(op string, closer rune) {
	cmd := &rawCommand{op: op, params: []string{}, args: []string{}, start: r.p, pipeStart: r.pipeStart}
	r.cmds = append(r.cmds, cmd)
	// A command that reads nothing (a stray `|`) still covers its own start.
	defer func() { cmd.end = max(r.p, cmd.start+1) }()
	nameStart := r.p
	nv := r.argSingle(closer, true)
	cmd.nameRaw = r.text(nameStart, r.p)
	cmd.nameKind = nv.k
	cmd.name = nv.text
	if nv.k != kStr || !nv.static {
		cmd.name = facts.Dynamic
	}
	endOfParams := false
	for {
		r.skipSpace()
		c := r.peek(0)
		if r.cmdEnd(c, closer) {
			return
		}
		if r.redirection() {
			continue
		}
		start := r.p
		if c == '-' && r.peek(1) == '-' && r.peek(2) == '%' {
			r.p += 3
			cmd.args = append(cmd.args, "--%")
			cmd.elems = append(cmd.elems, element{raw: "--%", start: start, end: r.p})
			restStart := r.p
			for !r.eof() && !isNL(r.peek(0)) && r.peek(0) != '|' {
				r.p++
			}
			rest := strings.TrimLeft(r.text(restStart, r.p), " \t")
			cmd.args = append(cmd.args, rest)
			cmd.elems = append(cmd.elems, element{raw: rest, val: value{text: rest, k: kStr, static: true}, hasVal: true, verbatim: true,
				start: r.p - len([]rune(rest)), end: r.p})
			continue
		}
		if c == '-' && r.peek(1) == '-' && !r.continuesAt(2) && !endOfParams {
			// a bare -- ends parameter binding; every later -x is an argument
			r.p += 2
			cmd.params = append(cmd.params, "--")
			cmd.elems = append(cmd.elems, element{param: "--", raw: "--", start: start, end: r.p})
			endOfParams = true
			continue
		}
		if isDash(c) && isParamStart(r.peek(1)) && !endOfParams {
			r.p++
			nameStart := r.p
			for !r.eof() {
				d := r.peek(0)
				if isSpace(d) || isNL(d) || d == ':' || d == '.' || strings.ContainsRune(";|&(){},", d) {
					break
				}
				r.p++
			}
			param := "-" + strings.ToLower(r.text(nameStart, r.p))
			cmd.params = append(cmd.params, param)
			el := element{param: param}
			if r.peek(0) == ':' {
				r.p++
				v := r.argValue(closer)
				cmd.args = append(cmd.args, v.text)
				el.val, el.hasVal = v, true
			}
			el.raw = r.text(start, r.p)
			el.start, el.end = start, r.p
			cmd.elems = append(cmd.elems, el)
			continue
		}
		v := r.argValue(closer)
		if r.p == start {
			r.note(fmt.Sprintf("arg stuck %q", c))
			r.p++
			continue
		}
		cmd.args = append(cmd.args, v.text)
		cmd.elems = append(cmd.elems, element{raw: r.text(start, r.p), val: v, hasVal: true, start: start, end: r.p})
	}
}

func (r *reader) argValue(closer rune) value {
	v := r.argSingle(closer, false)
	save := r.p
	r.skipSpace()
	if r.peek(0) != ',' {
		r.p = save
		return v
	}
	elems := []value{v}
	for r.peek(0) == ',' {
		r.p++
		r.skipSpaceNL()
		elems = append(elems, r.argSingle(closer, false))
		save = r.p
		r.skipSpace()
		if r.peek(0) != ',' {
			r.p = save
		}
	}
	for _, e := range elems {
		if e.k == kStr {
			r.strs = append(r.strs, e.text)
		}
	}
	return value{text: facts.Expr, k: kExpr, items: elems}
}

func (r *reader) argSingle(closer rune, isName bool) value {
	if !r.enter() {
		return exprV
	}
	defer r.leave()
	c := r.peek(0)
	switch {
	case isSQ(c):
		return value{text: r.singleQuoted(), k: kStr, static: true}
	case isDQ(c):
		return r.doubleQuoted()
	case c == '@' && (isSQ(r.peek(1)) || isDQ(r.peek(1))):
		if v, ok := r.hereString(); ok {
			return v
		}
	case c == '@' && r.peek(1) == '(':
		r.p += 2
		r.statements(')')
		r.postfix()
		return exprV
	case c == '@' && r.peek(1) == '{':
		r.p += 2
		r.hashtable()
		return exprV
	case c == '@' && isVarChar(r.peek(1)):
		r.p++
		start := r.p
		for !r.eof() && isVarChar(r.peek(0)) {
			r.p++
		}
		return value{text: "$" + r.text(start, r.p), k: kVar}
	case c == '(':
		r.p++
		r.statements(')')
		r.postfix()
		return exprV
	case c == '{':
		r.p++
		r.statements('}')
		return blockV
	case c == '$':
		start := r.p
		if r.peek(1) == '(' {
			r.p += 2
			r.statements(')')
			if r.continuesToken(closer) {
				restStart := r.p
				rest := r.bareword(closer)
				head := r.text(start, restStart)
				return value{text: head + rest.text, k: kStr, dyn: shifted([]span{{0, len(head)}}, rest.dyn, len(head))}
			}
			r.postfix()
			return exprV
		}
		name := r.variable()
		d := r.peek(0)
		if d == '.' && (isVarChar(r.peek(1)) || r.peek(1) == '$') || d == '[' || d == ':' && r.peek(1) == ':' {
			r.postfix()
			return exprV
		}
		if r.continuesToken(closer) {
			head := r.text(start, r.p)
			rest := r.bareword(closer)
			return value{text: head + rest.text, k: kStr, dyn: shifted([]span{{0, len(head)}}, rest.dyn, len(head))}
		}
		return value{text: name, k: kVar}
	case c == ',':
		r.p++
		r.skipSpace()
		if inner := r.argSingle(closer, false); inner.k == kStr {
			r.strs = append(r.strs, inner.text)
		}
		return exprV
	}
	b := r.bareword(closer)
	if !isName && b.plain && numberRe.MatchString(b.text) {
		return exprV
	}
	return b
}

func (r *reader) continuesAt(k int) bool {
	c := r.peek(k)
	return !(c == 0 || isSpace(c) || isNL(c) || strings.ContainsRune(";|&(){},<>", c))
}

func (r *reader) continuesToken(closer rune) bool {
	c := r.peek(0)
	return !(c == 0 || isSpace(c) || isNL(c) || strings.ContainsRune(";|&(){},<>", c) || c == ']' && closer == ']')
}

func (r *reader) bareword(closer rune) value {
	var b strings.Builder
	var dyn []span
	static, plain := true, true
	for !r.eof() {
		c := r.peek(0)
		if isSpace(c) || isNL(c) || strings.ContainsRune(";|&(){},<>", c) || c == ']' && closer == ']' {
			break
		}
		if c == '`' {
			if isNL(r.peek(1)) {
				break
			}
			b.WriteRune(escapeRune(r.peek(1)))
			r.advance(2)
			plain = false
			continue
		}
		if isSQ(c) {
			b.WriteString(r.singleQuoted())
			plain = false
			continue
		}
		if isDQ(c) {
			v := r.doubleQuoted()
			dyn = shifted(dyn, v.dyn, b.Len())
			b.WriteString(v.text)
			static = static && v.static
			plain = false
			continue
		}
		if c == '$' && (isVarStart(r.peek(1)) || r.peek(1) == '(') {
			start := r.p
			if r.peek(1) == '(' {
				r.p += 2
				r.statements(')')
			} else {
				r.variable()
			}
			off := b.Len()
			b.WriteString(r.text(start, r.p))
			dyn = append(dyn, span{off, b.Len()})
			static, plain = false, false
			continue
		}
		b.WriteRune(c)
		r.p++
	}
	return value{text: b.String(), k: kStr, static: static, plain: plain, dyn: dyn}
}

func (r *reader) singleQuoted() string {
	r.p++
	var b strings.Builder
	for !r.eof() {
		c := r.peek(0)
		if isSQ(c) {
			if isSQ(r.peek(1)) {
				b.WriteRune(c)
				r.p += 2
				continue
			}
			r.p++
			return b.String()
		}
		b.WriteRune(c)
		r.p++
	}
	r.note("unclosed '")
	return b.String()
}

// expandable reads string content up to end (exclusive; -1 = closing double
// quote), processing escapes and recording nested commands in $(...).
func (r *reader) expandable(end int) value {
	var b strings.Builder
	var dyn []span
	static := true
	for !r.eof() && (end < 0 || r.p < end) {
		c := r.peek(0)
		if end < 0 && isDQ(c) {
			if isDQ(r.peek(1)) {
				b.WriteRune(c)
				r.p += 2
				continue
			}
			r.p++
			return value{text: b.String(), k: kStr, static: static, dyn: dyn}
		}
		if c == '`' && r.p+1 < len(r.s) {
			b.WriteRune(escapeRune(r.peek(1)))
			r.p += 2
			continue
		}
		if c == '$' && (r.peek(1) == '(' || isVarStart(r.peek(1))) {
			start := r.p
			if r.peek(1) == '(' {
				r.p += 2
				r.statements(')')
			} else {
				r.variable()
			}
			off := b.Len()
			b.WriteString(r.text(start, r.p))
			dyn = append(dyn, span{off, b.Len()})
			static = false
			continue
		}
		b.WriteRune(c)
		r.p++
	}
	if end < 0 {
		r.note("unclosed \"")
	}
	return value{text: b.String(), k: kStr, static: static, dyn: dyn}
}

func (r *reader) doubleQuoted() value {
	r.p++
	return r.expandable(-1)
}

func (r *reader) hereString() (value, bool) {
	q := r.peek(1)
	i := r.p + 2
	for i < len(r.s) && isSpace(r.s[i]) {
		i++
	}
	if i >= len(r.s) || !isNL(r.s[i]) {
		return value{}, false
	}
	if r.s[i] == '\r' && i+1 < len(r.s) && r.s[i+1] == '\n' {
		i++
	}
	body := i + 1
	end := -1
	for j := body; j+2 < len(r.s); j++ {
		if r.s[j] == '\n' && (r.s[j+1] == q || isSQ(q) && isSQ(r.s[j+1]) || isDQ(q) && isDQ(r.s[j+1])) && r.s[j+2] == '@' {
			end = j
			break
		}
	}
	if end < 0 {
		r.note("unclosed here-string")
		end = len(r.s)
	}
	textEnd := end
	if textEnd > body && r.s[textEnd-1] == '\r' {
		textEnd--
	}
	var v value
	if isSQ(q) {
		v = value{text: r.text(body, textEnd), k: kStr, static: true}
	} else {
		r.p = body
		v = r.expandable(textEnd)
	}
	r.p = end
	r.advance(3)
	return v, true
}

// variable reads $name, ${name}, $scope:name, $$, $?, $^ and returns $userPath.
func (r *reader) variable() string {
	r.p++
	c := r.peek(0)
	if c == '{' {
		r.p++
		var b strings.Builder
		for !r.eof() && r.peek(0) != '}' {
			if r.peek(0) == '`' {
				r.p++
			}
			if r.eof() {
				break
			}
			b.WriteRune(r.peek(0))
			r.p++
		}
		if r.eof() {
			r.note("unclosed ${")
		} else {
			r.p++
		}
		return "$" + b.String()
	}
	if c == '$' || c == '^' {
		r.p++
		return "$" + string(c)
	}
	start := r.p
	for !r.eof() && isVarChar(r.peek(0)) {
		r.p++
	}
	if r.peek(0) == ':' && isVarChar(r.peek(1)) {
		r.p++
		for !r.eof() && isVarChar(r.peek(0)) {
			r.p++
		}
	}
	return "$" + r.text(start, r.p)
}

// redirection consumes >, >>, 2>, *>, n>&1 and records a file target string.
func (r *reader) redirection() bool {
	i := 0
	c := r.peek(0)
	if c == '*' || c >= '1' && c <= '6' {
		if r.peek(1) != '>' {
			return false
		}
		i = 1
	}
	if r.peek(i) != '>' {
		return false
	}
	i++
	if r.peek(i) == '>' {
		i++
	}
	if r.peek(i) == '&' && isDigit(r.peek(i+1)) {
		r.p += i + 2
		return true
	}
	r.p += i
	r.skipSpace()
	if v := r.argSingle(0, false); v.k == kStr {
		r.strs = append(r.strs, v.text)
		r.redirs = append(r.redirs, v.text)
	}
	return true
}
