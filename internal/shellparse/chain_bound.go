package shellparse

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// The chain bound (#4778, Gary 2026-11-04: "AUDIT").
//
// mvdan's parser builds a `|`, `|&`, `||` or `&&` chain as a left-nested
// BinaryCmd tree, one level per operator, and a recursive walker over that tree
// (syntax.Walk, which dozens of readings here use) takes one Go stack frame
// set per level. Past about 320 000 levels the walk passes Go's 1 GB
// goroutine stack, and a stack overflow is fatal: the process dies with no
// verdict and no record, and on shield-server every in-flight request dies
// with it. A text past the bound is therefore not parsed. Each surface decides
// it the way it decides every evaluation failure (the hook: failSafeDecision,
// AUDIT, BLOCK under managed fail_closed; shield-server: AUDIT), with a
// chain_too_long note.

// MaxChainOperators is the most chain operators (ChainOperators) a text may
// hold for AgentShield to parse it.
//
// Measured on 2026-11-04 (darwin/arm64, Go 1.27.3, the hook's POSIX lane on a
// Claude Code Bash call, `a|a|…`): 310 000 stages decided (exit 0 in 17.9 s),
// 330 000 overflowed the stack in buildExecSymbols' syntax.Walk, the first
// walker on the path; `&&` and `||` chains build the same tree. The bound is
// about a tenth of that, so a walker that spends up to ten times the stack per
// level, or a platform with larger frames, still fits. Real traffic is far
// below it: the largest count in this Mac's audit log (7 291 commands, the
// live file and one rotation) was 177, the 99.9th percentile 49. A text at the
// bound decides in about 2 s on the hook and 1.6 s on shield-server; one past
// it, or 1 MiB, in 0.1-1.7 s (no parse; recording a 1 MiB event is most of
// it).
const MaxChainOperators = 32768

// ChainOperators counts the chain operators in text, quoted or not: `||`,
// `|&` and `&&` count once each, a lone `|` once, a lone `&` (a background
// job, which does not nest) not at all. It is an upper bound on the depth of
// any chain the parser builds from text, because every level of that tree is
// one of these operators; a quoted or escaped one is counted too, which errs
// only toward the bound. It stops counting once the count passes
// MaxChainOperators.
func ChainOperators(text string) int {
	n := 0
	for i := 0; i < len(text) && n <= MaxChainOperators; i++ {
		switch text[i] {
		case '|':
			n++
			if i+1 < len(text) && (text[i+1] == '|' || text[i+1] == '&') {
				i++
			}
		case '&':
			if i+1 < len(text) && text[i+1] == '&' {
				n++
				i++
			}
		}
	}
	return n
}

// ChainTooLongError is a text past MaxChainOperators: the call's own text, or
// a text derived from it that a reading was about to parse (Derived), such as
// a nested shell's text after its variables were substituted.
type ChainTooLongError struct {
	// Operators is the count ChainOperators returned (it stops just past
	// the bound, so this is "more than MaxChainOperators").
	Operators int
	// Derived is true when the text past the bound was not the call's own
	// but one a reading derived from it.
	Derived bool
}

func (e *ChainTooLongError) Error() string {
	what := "the command"
	if e.Derived {
		what = "a text derived from the command (a nested shell's text, after variables were substituted)"
	}
	return fmt.Sprintf("%s has more than %d chain operators (|, |&, ||, &&), past the bound the parser's tree can be walked within (#4778); it was not parsed", what, MaxChainOperators)
}

// NoteDetail is the detail of the chain_too_long note a surface writes for e
// (analyzer.NoteChainTooLong).
func (e *ChainTooLongError) NoteDetail() string {
	what := "the command had"
	if e.Derived {
		what = "a text derived from the command (a nested shell's text after variable substitution) had"
	}
	return fmt.Sprintf("%s more than %d chain operators (|, |&, ||, &&); it was not parsed", what, MaxChainOperators)
}

// CheckChainBound returns a *ChainTooLongError when text has more than
// MaxChainOperators chain operators, and nil otherwise.
func CheckChainBound(text string) *ChainTooLongError {
	if n := ChainOperators(text); n > MaxChainOperators {
		return &ChainTooLongError{Operators: n}
	}
	return nil
}

// panicPastChainBound is the guard a parse of a derived text runs first:
// past the bound it panics with a *ChainTooLongError, which GuardChainBound
// turns back into an error at the surface. A derived text can be much longer
// than the call's own (`X=<chain>; bash -c "$X|$X|…"` reads 40 copies of X
// in a 20 KiB command), so the call's own text passing the bound does not
// bound what the readings parse; the panic gets the answer out of the reading
// without threading an error through every caller. A panic, unlike the stack
// overflow it replaces, can be recovered.
func panicPastChainBound(text string) {
	if n := ChainOperators(text); n > MaxChainOperators {
		panic(&ChainTooLongError{Operators: n, Derived: true})
	}
}

// ParseText is the one place a shell text is parsed (#4778): mvdan's parser
// with opts over text, unless text is past the chain bound, where it panics
// with a *ChainTooLongError instead (panicPastChainBound). Every parse in the
// module goes through it, so no reading, whatever text it derives (a nested
// shell's text, a decoded $'...', a fold's output), can hand the parser a
// chain whose tree overflows the stack when walked; internal/archtest's
// TestShellParsesGoThroughParseText fails on a direct syntax.NewParser.
// A caller outside an evaluation surface that could see such a text checks
// CheckChainBound first (hookentry) or reads through GuardChainBound.
func ParseText(text string, opts ...syntax.ParserOption) (*syntax.File, error) {
	panicPastChainBound(text)
	return syntax.NewParser(opts...).Parse(strings.NewReader(text), "")
}

// GuardChainBound reads text with read unless text is past the bound, and
// returns the *ChainTooLongError that stopped it: text's own (read is not
// run), or a derived text's that a parse inside read panicked with. It
// returns nil when read ran to completion. Any other panic is not touched.
func GuardChainBound(text string, read func()) (err *ChainTooLongError) {
	if err := CheckChainBound(text); err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			e, ok := p.(*ChainTooLongError)
			if !ok {
				panic(p)
			}
			err = e
		}
	}()
	read()
	return nil
}

// rethrowChainBound re-raises p when it is the chain bound's panic. A reading
// that recovers its own panics (ZshReadingErased) calls it first, so the
// bound's answer reaches the surface instead of reading as "no reading".
func rethrowChainBound(p any) {
	if e, ok := p.(*ChainTooLongError); ok {
		panic(e)
	}
}
