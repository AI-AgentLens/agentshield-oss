package shellparse

import (
	"sort"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
	"mvdan.cc/sh/v3/syntax"
)

// ZshReading returns command written so the bash parser accepts it, for a
// command the bash parser rejects and the zsh parser accepts (#4598). It
// returns "" when command parses as bash, when the zsh parser rejects it too,
// or when no bash-parseable text can be derived.
//
// # Why
//
// Every parser in this package is built with syntax.LangBash, while Claude
// Code's Bash tool runs commands through the user's shell, which on a stock
// Mac is /bin/zsh. A zsh-only construct anywhere in a command, even in a
// harmless statement of its own (`: ${(U)HOME};` is a no-op in zsh), makes
// the bash parse fail. That switches off the structural, semantic, dataflow
// and stateful stages (#3211), and collapses the regex stage's per-statement
// split and guardian's per-statement retry (#4291) into one statement for the
// whole text. The issue measured 21.8–24.5% of the corpus's single-line
// BLOCKs lowered to AUDIT by one such prefix or wrapper.
//
// # The reading
//
// The text is parsed with syntax.LangZsh (mvdan.cc/sh v3.14.1, which follows
// zsh 5.9 and marks the dialect experimental). When that parser rejects it
// too, it is parsed once more with #3211's obfuscating backslashes folded
// (`export FO\O=1` is `FOO` to both shells), the text DequoteCommand already
// hands the bash parser; a command the fold alone makes bash has no zsh
// reading. Every byte of the parsed text is kept except:
//
//   - a parameter expansion bash rejects (`${(U)HOME}`, `${${x}:h}`,
//     `${+x}`, `${=x}`) is written as the bash expansion of the same name with
//     the zsh flags, modifiers and option prefixes dropped (`${HOME}`); a
//     nested one is written as its inner expansion;
//   - a brace group whose last statement has no separator before the `}`
//     (`{ C }`) gets one (`{ C ; }`);
//   - an anonymous function (`() { C }`, `function { C }`), which zsh runs
//     where it is written, is written as its body; a multi-name declaration
//     (`function a b { C }`) is written with its first name only;
//   - a `=(...)` process substitution is written `<(...)`, and the zsh
//     disown terminators `&|` and `&!` are written `&`;
//   - a leaf statement that still does not parse as bash on its own (for
//     example `: $((1.5))`, floating-point arithmetic) is written `:`, so the
//     statements around it keep their own boundaries. "Parses" includes the
//     retry DequoteCommand already makes after folding obfuscating
//     backslashes (#3211), so `export PAT\H=...` stays as written.
//
// Every edit maps a zsh construct onto the bash construct that names the same
// words, or removes a statement; none can join two words into one or turn
// text into a command, so the reading cannot invent a statement the command
// does not contain. The result is returned only if the bash parser accepts
// it (with that same retry).
//
// # The guarantee lives with the caller
//
// This is a SECOND reading, never a replacement (Gary, 2026-10-28, on #4598):
// policy.Engine.EvaluateZshReading evaluates the command as written exactly as
// before, evaluates this reading independently, and keeps it only when it is
// strictly more restrictive. Swapping the main parser to LangZsh was rejected
// because a replacing reading is not additive (#4540 measured a replacing
// fix lowering 6 of 88 decisions).
//
// # What it does not reach
//
//   - A command the zsh parser rejects too. The short `for i (1) C` form is
//     the measured one; the issue pins it as a residual.
//   - A leaf statement that carries a heredoc and still does not parse: the
//     body would be left behind as text, so there is no reading at all.
//   - A zsh construct inside a carrier's quoted payload (`zsh -c '...'`):
//     the outer command parses as bash, so no reading is made.
//   - Commands that parse in both dialects with different meanings (zsh does
//     not word-split an unquoted `$x`). The parse failure is the trigger, not
//     shell detection.
//
// A panic anywhere in the zsh parse or the rewrite means there is no reading.
func ZshReading(command string) (reading string) {
	reading, _ = ZshReadingErased(command)
	return reading
}

// ZshReadingErased is ZshReading plus the source text of every leaf
// statement the reading writes as `:` (#4631). Those statements are gone from
// the reading, so a caller that reads only the reading cannot see what they
// run: `X=$((1.5)) agentshield setup mcp --disable` is a statement zsh runs
// and the reading writes `:`. Each erased entry is one statement's own text
// (its command and redirects, as zshStmtBodyEnd bounds it), sliced from the
// text the zsh parser read, which is the command as written or its #3211
// backslash fold. erased is nil whenever reading is "".
//
// ZshReading's output is exactly this reading; this only reports what it
// dropped. A panic means there is no reading and nothing erased, except the
// chain bound's (#4778: parsesAsBash reads through parseBashFile), which goes
// on to the surface that decides it.
func ZshReadingErased(command string) (reading string, erased []string) {
	defer func() {
		if p := recover(); p != nil {
			rethrowChainBound(p)
			reading, erased = "", nil
		}
	}()
	if strings.TrimSpace(command) == "" || parsesAsBash(command) {
		return "", nil
	}
	// src is the text the edits index: the command as written, or, when
	// the zsh parser rejects that, the command with #3211's obfuscating
	// backslashes folded (`export FO\O=1` is bash's and zsh's `FOO`), which
	// is the reading DequoteCommand already gives the bash parser.
	src := command
	file := parseZshFile(src)
	if file == nil {
		folded, changed := pathnorm.FoldObfuscatingBackslashesUnquoted(command)
		// A command the fold alone makes bash is #3211's, not zsh's.
		if !changed || parsesAsBash(folded) {
			return "", nil
		}
		if file = parseZshFile(folded); file == nil {
			return "", nil
		}
		src = folded
	}

	var edits []zshEdit
	syntax.Walk(file, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.ParamExp:
			if e, ok := zshParamExpEdit(src, x); ok {
				edits = append(edits, e)
				// The rendering covers everything inside the expansion.
				return false
			}
		case *syntax.ProcSubst:
			if x.Op == syntax.CmdInTemp {
				o := zshOffset(x.OpPos)
				edits = append(edits, zshEdit{o, o + 1, "<"})
			}
		case *syntax.Block:
			if e, ok := zshBlockSeparatorEdit(src, x); ok {
				edits = append(edits, e)
			}
		case *syntax.FuncDecl:
			if e, ok := zshFuncDeclEdit(x); ok {
				edits = append(edits, e)
			}
		case *syntax.Stmt:
			if x.Disown && x.Semicolon.IsValid() {
				o := zshOffset(x.Semicolon) + 1
				if o < len(src) && (src[o] == '|' || src[o] == '!') {
					edits = append(edits, zshEdit{o, o + 1, " "})
				}
			}
		}
		return true
	})

	// A leaf statement that the edits above do not make bash-parseable on
	// its own is written `:`. Pipelines are split, so `a | <zsh-only>` keeps
	// `a` as a statement of its own.
	var leaves []*syntax.Stmt
	for _, s := range file.Stmts {
		collectStmts(s, &leaves, true)
	}
	for _, leaf := range leaves {
		start := zshOffset(leaf.Pos())
		end := zshStmtBodyEnd(leaf)
		window := end
		heredoc := false
		for _, r := range leaf.Redirs {
			if r.Hdoc != nil {
				heredoc = true
				if e := zshOffset(r.Hdoc.End()); e > window {
					window = e
				}
			}
		}
		if start < 0 || start > end || window > len(src) {
			return "", nil
		}
		check := applyZshEdits(src[start:end], edits, start)
		if heredoc {
			// The body starts on the line after the statement; whatever
			// else shares that line belongs to other statements.
			if nl := strings.IndexByte(src[end:window], '\n'); nl >= 0 {
				check += applyZshEdits(src[end+nl:window], edits, end+nl)
			}
		}
		if bashReads(check) {
			continue
		}
		if heredoc {
			// Writing the statement `:` would leave its body as commands.
			return "", nil
		}
		kept := edits[:0]
		for _, e := range edits {
			if e.start >= start && e.start < end {
				continue
			}
			kept = append(kept, e)
		}
		edits = append(kept, zshEdit{start, end, ":"})
		erased = append(erased, src[start:end])
	}

	out := applyZshEdits(src, edits, 0)
	if out == command || !bashReads(out) {
		return "", nil
	}
	return out, erased
}

// zshEdit replaces src[start:end] with text (an insertion when start ==
// end). Offsets are into the text the zsh parser read.
type zshEdit struct {
	start, end int
	text       string
}

// applyZshEdits applies every edit that lies inside src, where src begins at
// offset base of the command the edits index. An edit that overlaps one
// already applied is skipped.
func applyZshEdits(src string, edits []zshEdit, base int) string {
	var in []zshEdit
	for _, e := range edits {
		if e.start >= base && e.end <= base+len(src) && e.start <= e.end {
			in = append(in, e)
		}
	}
	if len(in) == 0 {
		return src
	}
	sort.SliceStable(in, func(i, j int) bool { return in[i].start < in[j].start })
	var b strings.Builder
	last := base
	for _, e := range in {
		if e.start < last {
			continue
		}
		b.WriteString(src[last-base : e.start-base])
		b.WriteString(e.text)
		last = e.end
	}
	b.WriteString(src[last-base:])
	return b.String()
}

func parseZshFile(s string) *syntax.File {
	file, err := ParseText(s, syntax.KeepComments(false), syntax.Variant(syntax.LangZsh))
	if err != nil {
		return nil
	}
	return file
}

func parsesAsBash(s string) bool {
	return parseBashFile(s) != nil
}

// bashReads is parsesAsBash, or the bash parse DequoteCommand retries after
// folding obfuscating backslashes (#3211): `export PAT\H=...` is rejected by
// the parser and run by bash, and the as-written pipeline already reads it
// that way, so a statement like it stays in the reading as written.
func bashReads(s string) bool {
	if parsesAsBash(s) {
		return true
	}
	folded, changed := pathnorm.FoldObfuscatingBackslashesUnquoted(s)
	return changed && parsesAsBash(folded)
}

func zshOffset(p syntax.Pos) int {
	if !p.IsValid() {
		return -1
	}
	return int(p.Offset())
}

// zshStmtBodyEnd is where a statement's own text ends on its line: its
// command and its redirects, without the `;` or `&` that terminates it and
// without a heredoc body (which follows the next newline).
func zshStmtBodyEnd(s *syntax.Stmt) int {
	end := zshOffset(s.Position)
	if s.Negated {
		end++
	}
	if s.Cmd != nil {
		if e := zshOffset(s.Cmd.End()); e > end {
			end = e
		}
	}
	for _, r := range s.Redirs {
		re := r.End()
		if r.Hdoc != nil && r.Word != nil {
			re = r.Word.End()
		}
		if e := zshOffset(re); e > end {
			end = e
		}
	}
	return end
}

// zshParamExpEdit writes a parameter expansion bash rejects as the bash
// expansion of the same parameter, or reports false when the expansion is
// already bash or no bash rendering parses.
func zshParamExpEdit(src string, pe *syntax.ParamExp) (zshEdit, bool) {
	if pe.Short {
		return zshEdit{}, false
	}
	start, end := zshOffset(pe.Pos()), zshOffset(pe.End())
	if start < 0 || end > len(src) || start >= end {
		return zshEdit{}, false
	}
	if parsesAsBash(": " + src[start:end]) {
		return zshEdit{}, false
	}
	// A nested expansion (`${${x}:h}`, `${(f)"$(cmd)"}`) is written as the
	// expansion it wraps.
	var target syntax.WordPart = pe
	for {
		p, ok := target.(*syntax.ParamExp)
		if !ok || p.Param != nil || p.NestedParam == nil {
			break
		}
		target = p.NestedParam
	}
	syntax.Walk(target, func(n syntax.Node) bool {
		if p, ok := n.(*syntax.ParamExp); ok {
			p.Flags = nil
			p.IsSet = false
			p.Split = syntax.OptUnset
			p.GlobSubst = syntax.OptUnset
			p.RcExpand = syntax.OptUnset
			p.Modifiers = nil
			if fa, ok := p.Index.(*syntax.FlagsArithm); ok {
				p.Index = fa.X
			}
		}
		return true
	})
	if p, ok := target.(*syntax.ParamExp); ok && p.Param == nil {
		return zshEdit{}, false
	}
	var b strings.Builder
	if err := syntax.NewPrinter().Print(&b, target); err != nil {
		return zshEdit{}, false
	}
	rendered := b.String()
	if rendered == "" || !parsesAsBash(": "+rendered) {
		return zshEdit{}, false
	}
	return zshEdit{start, end, rendered}, true
}

// zshBlockSeparatorEdit gives `{ C }` the separator bash needs before `}`.
func zshBlockSeparatorEdit(src string, b *syntax.Block) (zshEdit, bool) {
	r := zshOffset(b.Rbrace)
	if r < 0 || r > len(src) {
		return zshEdit{}, false
	}
	if len(b.Stmts) == 0 {
		return zshEdit{r, r, ": ; "}, true
	}
	last := b.Stmts[len(b.Stmts)-1]
	if last.Semicolon.IsValid() {
		return zshEdit{}, false
	}
	e := zshStmtBodyEnd(last)
	if e < 0 || e > r {
		return zshEdit{}, false
	}
	// Only blanks between the statement and `}`: a newline (or a heredoc
	// body, which follows one) already separates them.
	if strings.Trim(src[e:r], " \t") != "" {
		return zshEdit{}, false
	}
	return zshEdit{r, r, "; "}, true
}

// zshFuncDeclEdit writes an anonymous function as its body (zsh runs it where
// it is written) and a multi-name declaration with its first name.
func zshFuncDeclEdit(f *syntax.FuncDecl) (zshEdit, bool) {
	if f.Body == nil {
		return zshEdit{}, false
	}
	start, body := zshOffset(f.Position), zshOffset(f.Body.Pos())
	if start < 0 || body < start {
		return zshEdit{}, false
	}
	switch {
	case f.Name == nil && len(f.Names) == 0:
		return zshEdit{start, body, ""}, true
	case f.Name == nil && len(f.Names) > 0 && f.Names[0] != nil:
		return zshEdit{start, body, f.Names[0].Value + "() "}, true
	}
	return zshEdit{}, false
}
