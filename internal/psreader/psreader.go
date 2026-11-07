// Package psreader reads PowerShell text into facts.Facts: the PowerShell
// lane of ADR-001 (docs/architecture/adr-001-tool-routing-dialect-lanes.md).
//
// It reads the text as characters and never runs or evaluates it, and it
// imports nothing but internal/facts and the standard library: no PowerShell
// process and no .NET, at run time, build time or in CI (ADR-001, D7).
// internal/archtest enforces the imports.
//
// # What it reports
//
//   - Commands, nested ones included, in source order: the canonical name
//     through the built-in alias table (aliases.go), the parameters
//     lower-cased, the argument values. A computed name is facts.Dynamic and
//     carries a dynamic_name note.
//   - Strings: every string literal outside command elements, the same set
//     PowerShell's parser yields for StringConstant and ExpandableString
//     nodes whose parent is not a command element.
//   - Paths: the command names, arguments and strings whose WHOLE value,
//     resolved (paths.go), is path-like. A `--%` remainder counts word by
//     word, as the native program receives it.
//   - Mentions: every other path-like spelling, a word inside a longer value
//     or a suffix after `=`, `@` or `:`, together with what a second,
//     grammar-free scan of the raw text finds (paths.go). The scan only adds.
//   - Nested: `powershell`/`pwsh` -Command and -EncodedCommand (decoded),
//     `Invoke-Expression`/`iex` with one string argument, `cmd /c` and `/k`,
//     `bash -c`, `sh -c` and `wsl`. The reader does not read nested text
//     itself; the router does, with a depth bound (ADR-001, D6).
//   - Notes: parse_error when the reader is unsure, dynamic_name,
//     dynamic_nested and decode_failed.
//
// # Accuracy
//
// The reader is held to PowerShell's own parser by an expected-facts
// differential over corpora checked in under testdata/, with expected facts
// produced once by PowerShell 7.6 and Windows PowerShell 5.1
// (differential_test.go). It reads the 7.x grammar on both versions: text
// that only 7.x accepts (`&&`, `?:`) fails to parse on 5.1 and never runs
// there, so reading it as 7.x does is stricter, never looser.
//
// # Failure
//
// Read never panics. An internal failure in any stage ends that stage with a
// parse_error note, and every other stage still reports.
package psreader

import (
	"fmt"
	"sort"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/facts"
)

// Read reads PowerShell text.
func Read(text string, env Env) facts.Facts {
	return read(text, env, 0)
}

// Bounds on one read (Opus pass 2 on #4245): the lane runs inside a hook a
// harness times out, and Copilot fails open on a timeout, so its work must be
// bounded whatever the text. Past a bound the read notes it (parse_error),
// which floors the call at AUDIT. Within the text bound no bound drops a
// whole-value path: their count and length are what the text holds.
const (
	// maxReadBytes is the longest text the reader parses. Past it only the
	// raw scan reads the text (its finds are mentions, bounded below) and
	// a note says so: no command, no nested text, no whole-value path.
	// Agent commands are far shorter; the rows a long text reaches keep
	// their other lane (MCP policy, or the bash pipeline, which decides as
	// on main).
	maxReadBytes = 128 << 10
	// maxMentions and maxMentionBytes bound the mentions one read reports,
	// each of which the back end matches against every pattern.
	maxMentions     = 1024
	maxMentionBytes = 256 << 10
)

// read is Read with a test hook: a positive panicAt makes the reader fail at
// that step.
func read(text string, env Env, panicAt int) facts.Facts {
	f := facts.Facts{Dialect: facts.DialectPowerShell}
	res := newResolver(env)
	r := &reader{panicAt: panicAt, pipes: map[int]pipeInfo{}}
	parse := len(text) <= maxReadBytes
	if parse {
		r.s = []rune(text)
		stage(&f, "reader", func() { r.statements(0) })
	} else {
		f.Notes = append(f.Notes, facts.Note{Kind: facts.NoteParseError,
			Detail: fmt.Sprintf("text of %d bytes is past the reader's bound of %d bytes; only the raw scan read it", len(text), maxReadBytes)})
	}
	for _, n := range r.notes {
		f.Notes = append(f.Notes, facts.Note{Kind: facts.NoteParseError,
			Detail: fmt.Sprintf("%s at offset %d", n.detail, n.pos)})
	}

	isPath, isMention := map[string]bool{}, map[string]bool{}
	addPath := func(p string) {
		if !isPath[p] {
			isPath[p] = true
			f.Paths = append(f.Paths, p)
		}
	}
	mentionBytes, mentionsBounded := 0, false
	addMention := func(p string) {
		if isMention[p] {
			return
		}
		if len(f.Mentions) >= maxMentions || mentionBytes+len(p) > maxMentionBytes {
			mentionsBounded = true
			return
		}
		isMention[p] = true
		mentionBytes += len(p)
		f.Mentions = append(f.Mentions, p)
	}

	stage(&f, "commands", func() {
		starts := make([]int, len(r.cmds))
		for i, c := range r.cmds {
			starts[i] = c.start
		}
		for _, c := range r.cmds {
			name, alts := canonical(c.name)
			f.Commands = append(f.Commands, facts.Command{
				Name: name, Alternatives: alts, Written: c.name,
				Params: c.params, Args: c.args, Elements: elements(c, res),
				// r.cmds is in source order (a command is recorded where it
				// starts), so the commands starting in [pipeStart, end) are
				// one range: the earlier stages, this command, its arguments.
				InputFrom: sort.SearchInts(starts, c.pipeStart),
				InputTo:   sort.SearchInts(starts, c.end),
			})
			if c.name == facts.Dynamic && c.nameKind != kBlock {
				f.Notes = append(f.Notes, facts.Note{Kind: facts.NoteDynamicName,
					Detail: fmt.Sprintf("command name %q is computed", clipWord(c.nameRaw, 80))})
			}
		}
		f.Strings = append(f.Strings, r.strs...)
	})

	// .NET calls (facts.Call), each with what its arguments hold; a
	// command's CallsFrom/CallsTo by the rule InputFrom/InputTo follow.
	stage(&f, "calls", func() {
		sort.SliceStable(r.calls, func(i, j int) bool { return r.calls[i].start < r.calls[j].start })
		cmdStarts := make([]int, len(r.cmds))
		for i, c := range r.cmds {
			cmdStarts[i] = c.start
		}
		callStarts := make([]int, len(r.calls))
		for i, c := range r.calls {
			callStarts[i] = c.start
		}
		for _, c := range r.calls {
			f.Calls = append(f.Calls, facts.Call{
				Name:      callName(c.name),
				InputFrom: sort.SearchInts(cmdStarts, c.start),
				InputTo:   sort.SearchInts(cmdStarts, c.end),
				CallsFrom: sort.SearchInts(callStarts, c.start),
				CallsTo:   sort.SearchInts(callStarts, c.end),
				// clamped: the strings stage above may have stopped early
				StringsFrom: min(c.strFrom, len(f.Strings)),
				StringsTo:   min(c.strTo, len(f.Strings)),
			})
		}
		for i := range f.Commands {
			if i < len(r.cmds) {
				f.Commands[i].CallsFrom = sort.SearchInts(callStarts, r.cmds[i].pipeStart)
				f.Commands[i].CallsTo = sort.SearchInts(callStarts, r.cmds[i].end)
			}
		}
	})

	routed := make([]bool, len(r.cmds)) // a command whose own text goes to the router
	stage(&f, "nested", func() {
		for i, c := range r.cmds {
			n, ok, encoded, notes := nested(c)
			f.Notes = append(f.Notes, notes...)
			if ok {
				f.Nested = append(f.Nested, n)
			}
			routed[i] = ok
			if encoded && i < len(f.Commands) {
				f.Commands[i].EncodedCommand = true
			}
			if exe := exeName(c.name); (exe == "powershell" || exe == "pwsh") && c.name != facts.Dynamic && i < len(f.Commands) {
				f.Commands[i].StdinScript = powershellStdin(argv(c))
			}
		}
	})

	stage(&f, "native", func() { f.Native = nativeStatements(r.cmds, routed, r.pipes) })

	stage(&f, "paths", func() {
		for _, c := range r.cmds {
			if c.name != facts.Dynamic {
				res.valuePaths(c.name, addPath, addMention)
			}
			for _, el := range c.elems {
				for _, v := range elementValues(el) {
					res.argumentValuePaths(v, addPath, addMention)
				}
			}
			// a file curl uploads is a whole value (uploads.go)
			for _, file := range uploadFiles(c) {
				for _, p := range res.argumentPaths(file) {
					addPath(p)
				}
			}
		}
		for _, s := range r.strs {
			res.valuePaths(s, addPath, addMention)
		}
		// A redirection target is a file the text writes, whatever its
		// spelling: a bare name too, read under cwd like a bare argument.
		for _, t := range r.redirs {
			if p, ok := res.redirectionTarget(t); ok {
				addPath(p)
			}
		}
	})

	// The raw scan's finds are mentions: it sees what a reader mistake drops,
	// and also comments and text no one runs, so it never makes a path alone.
	stage(&f, "raw path scan", func() {
		res.rawPaths(text, addMention)
		// encoded text is not in the raw text, so scan what it decodes to
		for _, n := range f.Nested {
			res.rawPaths(n.Text, addMention)
		}
	})
	f.Mentions = withoutAny(f.Mentions, isPath)
	if res.bounded || mentionsBounded {
		f.Notes = append(f.Notes, facts.Note{Kind: facts.NoteParseError,
			Detail: fmt.Sprintf("path extraction bounded (at most %d suffix spellings a word, %d mentions, %d bytes of mentions): some mentions were not read",
				maxSuffixesPerWord, maxMentions, maxMentionBytes)})
	}

	// Last, so a failure in any stage above (a note) leaves it false.
	if parse {
		stage(&f, "simple", func() { f.Simple = simple(text, f) })
	}
	return f
}

// elements is a command's parameters and arguments in source order
// (facts.Command.Elements), each argument's paths resolved as the paths
// stage resolves Args.
func elements(c *rawCommand, res *resolver) []facts.Element {
	out := make([]facts.Element, 0, len(c.elems))
	uploads := uploadFiles(c)
	for i, el := range c.elems {
		e := facts.Element{Raw: el.raw}
		switch {
		case el.param != "":
			// The name as written, its case kept: `-I` is not `-i` to a
			// native program. Params holds it lower-cased.
			e.Param, _, _ = strings.Cut(el.raw, ":")
		case !el.hasVal:
			e.Value = el.raw // the --% marker, which Args holds as written
		}
		if el.hasVal {
			e.Value = el.val.text
			for _, item := range el.val.items {
				e.Items = append(e.Items, item.text)
			}
		}
		for _, v := range elementValues(el) {
			for _, p := range res.argumentPaths(v) {
				e.Paths = appendUnique(e.Paths, p)
			}
		}
		if file, ok := uploads[i]; ok {
			for _, p := range res.argumentPaths(file) {
				e.Paths = appendUnique(e.Paths, p)
			}
		}
		out = append(out, e)
	}
	return out
}

// elementValues are the values an element hands its command, each a whole
// value: its value, or each word of a `--%` remainder, which a native
// program receives as separate arguments. None for a parameter without a
// value, the `--%` marker or an expression.
func elementValues(el element) []string {
	if !el.hasVal || el.val.text == "" || el.val.text == facts.Expr {
		return nil
	}
	if el.verbatim {
		return splitWindowsArgs(el.val.text)
	}
	return []string{el.val.text}
}

// callName is a call's name as facts.Call holds it: ASCII lower case, the
// type without surrounding space or a leading `System.`.
func callName(raw string) string {
	n := asciiLower(raw)
	if typ, method, static := strings.Cut(n, "::"); static {
		typ = strings.TrimSpace(typ)
		typ = strings.TrimPrefix(typ, "system.")
		return typ + "::" + method
	}
	return n
}

// withoutAny is list without the entries drop holds, order kept.
func withoutAny(list []string, drop map[string]bool) []string {
	var out []string
	for _, s := range list {
		if !drop[s] {
			out = append(out, s)
		}
	}
	return out
}

// stage runs one part of a read. A panic ends that part only, with a
// parse_error note; what it had already added stays.
func stage(f *facts.Facts, name string, fn func()) {
	defer func() {
		if e := recover(); e != nil {
			f.Notes = append(f.Notes, facts.Note{Kind: facts.NoteParseError,
				Detail: fmt.Sprintf("internal error in %s: %v", name, e)})
		}
	}()
	fn()
}
