package psreader

import (
	"slices"
	"sort"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/facts"
)

// The native programs a text runs (facts.Facts.Native, #4768).
//
// PowerShell runs a cross-platform program (git, kubectl, terraform, gh …)
// with the same arguments bash would give it, so the shell rules for those
// programs apply to it. The bash parser cannot read the PowerShell text
// around them (that produced false BLOCKs, ADR-001 step 4), so the lane
// reports each native program's argument vector instead, and a surface whose
// row has no POSIX lane hands those to the POSIX lane as rebuilt command
// lines (internal/assembly, the native-command bridge).
//
// A command is native when, in some reading, its name resolves to an
// external program: not a cmdlet (an approved verb, a dash, a noun), not one
// of PowerShell's built-in functions, and not an alias of either. A
// version-dependent alias (curl, wget, sc) is native in one version, so it
// counts: stricter wins. A PowerShell script (.ps1) is not native, and
// neither is powershell or pwsh, whose text is PowerShell; a command whose
// own text the reader hands to the router (Nested: bash -c, cmd /c, wsl …)
// is left out, because that text is read in its own lane already.

// approvedVerbs are PowerShell's approved verbs (Get-Verb, PowerShell 7.4).
// A name `<verb>-<noun>` is a cmdlet or a function named like one; a native
// program named that way (rare) is read as a cmdlet, so the bridge does not
// read it, which is main's reading.
var approvedVerbs = map[string]bool{}

func init() {
	for _, v := range strings.Fields(`add approve assert backup block build checkpoint clear close compare
		complete compress confirm connect convert convertfrom convertto copy debug deny deploy disable
		disconnect dismount edit enable enter exit expand export find format get grant group hide
		import initialize install invoke join limit lock measure merge mount move new open optimize out
		ping pop protect publish push read receive redo register remove rename repair request reset
		resize resolve restart restore resume revoke save search select send set show skip split
		start step stop submit suspend switch sync test trace unblock undo uninstall unlock unprotect
		unpublish unregister update use wait watch write`) {
		approvedVerbs[v] = true
	}
}

// builtinCommands are PowerShell's built-in commands that the verb rule does
// not recognise, lower-cased: the functions whose names are not verb-noun (a
// clean PowerShell 7 and 5.1 session on Windows), and the four cmdlets whose
// verb is not an approved one (Get-Command in pwsh 7.6; no alias in the
// alias table targets another).
var builtinCommands = map[string]bool{
	"cd..": true, "help": true, "mkdir": true, "more": true, "oss": true,
	"pause": true, "prompt": true, "tabexpansion2": true, "importsystemmodules": true,
	"foreach-object": true, "where-object": true, "sort-object": true, "tee-object": true,
}

// nativeExtensions are the program extensions Windows runs without being
// named (PATHEXT), dropped from a native program's name.
var nativeExtensions = []string{".exe", ".com", ".bat", ".cmd"}

// nativeProgram is the program a command runs when, in some reading, it is
// native: its name lower-cased, with no directory and no program extension.
func nativeProgram(c *rawCommand) (string, bool) {
	if c.name == facts.Dynamic {
		return "", false
	}
	name, alts := canonical(c.name)
	for _, n := range append([]string{name}, alts...) {
		if prog, ok := nativeName(n); ok {
			return prog, true
		}
	}
	return "", false
}

// nativeName reports whether a canonical command name is a native program,
// and the program's name.
func nativeName(n string) (string, bool) {
	if strings.Contains(n, "=") {
		// `a=/x/y` is no program PowerShell finds, and to bash it is an
		// assignment; reading its last path component would invent one.
		return "", false
	}
	if i := strings.LastIndexAny(n, `/\`); i >= 0 {
		n = n[i+1:]
	}
	for _, ext := range nativeExtensions {
		if strings.HasSuffix(n, ext) {
			n = strings.TrimSuffix(n, ext)
			break
		}
	}
	switch {
	case n == "", builtinCommands[n], n == "powershell", n == "pwsh":
		return "", false
	case strings.HasSuffix(n, ".ps1"), strings.HasSuffix(n, ".psm1"), strings.HasSuffix(n, ".psd1"):
		return "", false
	}
	if verb, noun, ok := strings.Cut(n, "-"); ok && noun != "" && approvedVerbs[verb] {
		return "", false
	}
	// A name the bash parser would read as something other than a program
	// word (a quote, a space, a `$`) is not one a shell rule names.
	for i := 0; i < len(n); i++ {
		if !programNameByte(n[i]) {
			return "", false
		}
	}
	return n, true
}

func programNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("._+-", c) >= 0
}

// nativeStatements groups the native commands of a read as the text joins
// them. routed marks the commands whose own text the reader hands to the
// router (Nested), which are left out.
func nativeStatements(cmds []*rawCommand, routed []bool, pipes map[int]pipeInfo) []facts.NativeStatement {
	type stage struct {
		pipe int
		argv facts.Argv
	}
	byChain := map[int][]stage{}
	var chains []int
	for i, c := range cmds {
		if i < len(routed) && routed[i] {
			continue
		}
		var argv facts.Argv
		if prog, ok := nativeProgram(c); ok {
			argv = nativeArgv(c, prog)
		} else if argv, ok = startProcessArgv(c); !ok {
			continue
		}
		chain := c.pipeStart
		if info, ok := pipes[c.pipeStart]; ok {
			chain = info.chain
		}
		if _, seen := byChain[chain]; !seen {
			chains = append(chains, chain)
		}
		byChain[chain] = append(byChain[chain], stage{pipe: c.pipeStart, argv: argv})
	}
	// Statements in the order they start; a statement nested in another's
	// argument (`git log $(git rev-parse HEAD)`) follows it.
	sort.Ints(chains)
	out := make([]facts.NativeStatement, 0, len(chains))
	for _, chain := range chains {
		stages := byChain[chain]
		sort.SliceStable(stages, func(i, j int) bool { return stages[i].pipe < stages[j].pipe })
		var st facts.NativeStatement
		for i, s := range stages {
			if i > 0 && s.pipe == stages[i-1].pipe {
				p := &st.Pipelines[len(st.Pipelines)-1]
				p.Stages = append(p.Stages, s.argv)
				continue
			}
			op := ""
			if len(st.Pipelines) > 0 {
				op = pipes[s.pipe].op
			}
			st.Pipelines = append(st.Pipelines, facts.NativePipeline{Op: op, Stages: []facts.Argv{s.argv}})
		}
		out = append(out, st)
	}
	return out
}

// nativeArgv is the argument vector a native program receives from a
// command: its name, then each element's value. A parameter is passed as
// written (`-auto-approve`, `--force`), with an attached value
// (`-name:value`) as one argument. An array (`a,b`) is one argument per
// element. Elements with no space between them are one argument
// (`-Dfoo.bar`, which the reader splits at the dot). The `--%` marker is not
// passed on; the text after it is split as a Windows program splits its
// command line.
//
// `@name` with more of the word after it (`@scope-name/pkg`) is one string to
// PowerShell's parser (pwsh 7.6 ParseInput: a StringConstantExpressionAst),
// which the reader reads as a splat followed by `-name` and `/pkg`. The argv
// reads the run as the one word it is. The reader's own facts keep the
// splat: reading the string there would lower a PowerShell rule's match
// (`Set-MpPreference @x-DisableRealtimeMonitoring $true` BLOCKs on main,
// though PowerShell never binds that parameter), which is not this
// change's call.
func nativeArgv(c *rawCommand, prog string) facts.Argv {
	argv := facts.Argv{{{Text: prog}}}
	prevEnd := -1
	for i := 0; i < len(c.elems); i++ {
		el := c.elems[i]
		if run := adjacentRun(c.elems, i); el.val.k == kVar && strings.HasPrefix(el.raw, "@") && run > i+1 {
			var src strings.Builder
			for _, e := range c.elems[i:run] {
				src.WriteString(e.raw)
			}
			r := &reader{s: []rune(src.String())}
			argv = append(argv, endAtNUL(valueWord(r.bareword(0), src.String())))
			prevEnd = c.elems[run-1].end
			i = run - 1
			continue
		}
		switch {
		case el.raw == "--%" && el.param == "" && !el.hasVal:
			prevEnd = -1
			continue
		case el.verbatim:
			for _, w := range splitWindowsArgs(el.val.text) {
				argv = append(argv, endAtNUL(literalWord(w)))
			}
			prevEnd = -1
			continue
		case el.param == "" && len(el.val.items) > 0:
			for _, item := range el.val.items {
				argv = append(argv, endAtNUL(valueWord(item, "")))
			}
			prevEnd = -1
			continue
		}
		w := endAtNUL(nativeElementWord(el))
		if prevEnd >= 0 && el.start == prevEnd && len(argv) > 1 {
			last := &argv[len(argv)-1]
			*last = joinParts(*last, w)
		} else {
			argv = append(argv, w)
		}
		prevEnd = el.end
	}
	return argv
}

// Start-Process's parameters (PowerShell 7.4 and 5.1), each with its
// aliases: the two that name what runs, and the others that take a value.
// Every other parameter is a switch. A name is matched by decision 1's
// prefix rule.
var (
	startProcessFile      = []string{"-FilePath", "-PSPath", "-Path"}
	startProcessArgs      = []string{"-ArgumentList", "-Args"}
	startProcessValueOpts = []string{"-Credential", "-RunAs", "-WorkingDirectory", "-RedirectStandardError", "-RSE",
		"-RedirectStandardInput", "-RSI", "-RedirectStandardOutput", "-RSO", "-Verb", "-WindowStyle", "-Environment",
		"-ErrorAction", "-WarningAction", "-InformationAction", "-ProgressAction", "-ErrorVariable", "-WarningVariable",
		"-InformationVariable", "-OutVariable", "-OutBuffer", "-PipelineVariable"}
)

func paramIn(written string, names []string) bool {
	for _, n := range names {
		if facts.ParamMatches(written, n) {
			return true
		}
	}
	return false
}

// startProcessArgv is the argument vector a program started by
// Start-Process (or its aliases start and saps) receives (Windows round 3):
// the program -FilePath names (or the first positional argument), then the
// -ArgumentList words (or the second positional argument), split as a
// Windows program splits its command line. Start-Process joins an array's
// items with spaces before the program splits them, so each item is split
// in turn. ok is false when the command is not Start-Process, or the
// program is not a literal native program (a computed path, a script,
// powershell or pwsh). An argument after a parameter is read as that
// parameter's value when the parameter takes one; a switch takes none.
func startProcessArgv(c *rawCommand) (facts.Argv, bool) {
	if c.name == facts.Dynamic {
		return nil, false
	}
	name, alts := canonical(c.name)
	if name != "start-process" && !slices.Contains(alts, "start-process") {
		return nil, false
	}
	var file, args *element
	var positional []*element
	for i := 0; i < len(c.elems); i++ {
		el := &c.elems[i]
		if el.param == "" {
			if el.hasVal && !el.verbatim {
				positional = append(positional, el)
			}
			continue
		}
		written, _, attached := strings.Cut(el.raw, ":")
		var slot **element
		switch {
		case paramIn(written, startProcessFile):
			slot = &file
		case paramIn(written, startProcessArgs):
			slot = &args
		case !paramIn(written, startProcessValueOpts):
			continue // a switch
		}
		var v *element
		if attached {
			if el.hasVal {
				v = el
			}
		} else if i+1 < len(c.elems) && c.elems[i+1].param == "" {
			i++
			v = &c.elems[i]
		}
		if slot != nil && v != nil {
			*slot = v
		}
	}
	for _, p := range positional {
		switch {
		case file == nil:
			file = p
		case args == nil:
			args = p
		}
	}
	if file == nil || file.val.k != kStr || !file.val.static {
		return nil, false
	}
	prog, ok := nativeName(asciiLower(file.val.text))
	if !ok {
		return nil, false
	}
	argv := facts.Argv{{{Text: prog}}}
	if args == nil {
		return argv, true
	}
	items := args.val.items
	if len(items) == 0 {
		items = []value{args.val}
	}
	for _, it := range items {
		if it.k == kStr && it.static {
			for _, w := range splitWindowsArgs(it.text) {
				argv = append(argv, endAtNUL(literalWord(w)))
			}
			continue
		}
		argv = append(argv, endAtNUL(valueWord(it, it.text)))
	}
	return argv, true
}

// adjacentRun is the end of the run of elements from i on with no space
// between them.
func adjacentRun(elems []element, i int) int {
	j := i + 1
	for j < len(elems) && elems[j].start == elems[j-1].end && !elems[j].verbatim && elems[j].raw != "--%" {
		j++
	}
	return j
}

// nativeElementWord is the argument one element hands a native program.
func nativeElementWord(el element) facts.Word {
	if el.param != "" {
		name, valRaw, attached := strings.Cut(el.raw, ":")
		w := paramWord(name)
		if attached && el.hasVal {
			// The value's own source text, so a number attached to a
			// parameter is the number PowerShell passes (`-keepVersions:0`
			// is `-keepVersions:0`), as the same number is unattached.
			return joinParts(joinParts(w, literalWord(":")), valueWord(el.val, valRaw))
		}
		if attached {
			return joinParts(w, literalWord(":"))
		}
		return w
	}
	return valueWord(el.val, el.raw)
}

// paramWord is a parameter's name as the program receives it. Written plain
// it is the text itself; with a quote, an escape or a variable in it
// (`-S'x'`), PowerShell's parser reads it as one string, quotes removed, so
// it is read as a bareword.
func paramWord(name string) facts.Word {
	if !strings.ContainsAny(name, "'\"`$‘’‚‛“”„") {
		return literalWord(name)
	}
	r := &reader{s: []rune(name)}
	return valueWord(r.bareword(0), name)
}

// valueWord is a value as a native argument: literal text, with what is
// computed at run time as unknown parts. A decimal integer is the number
// PowerShell passes (`0777` is 777); any other number or expression is
// unknown.
func valueWord(v value, raw string) facts.Word {
	switch v.k {
	case kStr:
		var w facts.Word
		at := 0
		for _, d := range v.dyn {
			if d.a < at || d.b > len(v.text) || d.a > d.b {
				continue // never expected; a range out of order is dropped
			}
			w = joinParts(w, literalWord(v.text[at:d.a]))
			w = joinParts(w, facts.Word{unknownPart(v.text[d.a:d.b])})
			at = d.b
		}
		return joinParts(w, literalWord(v.text[at:]))
	case kVar:
		return facts.Word{unknownPart(v.text)}
	case kExpr:
		if n, ok := decimalInteger(raw); ok {
			return literalWord(n)
		}
	}
	return facts.Word{{Unknown: true}}
}

// unknownPart is a computed value, named when it is one variable: `$b`,
// `${b}`, `$env:HOME` (HOME), `@args` read as `$args`.
func unknownPart(src string) facts.WordPart {
	if !strings.HasPrefix(src, "$") || strings.HasPrefix(src, "$(") {
		return facts.WordPart{Unknown: true}
	}
	name := strings.TrimPrefix(src, "$")
	name = strings.TrimSuffix(strings.TrimPrefix(name, "{"), "}")
	if i := strings.LastIndexByte(name, ':'); i >= 0 {
		name = name[i+1:]
	}
	return facts.WordPart{Unknown: true, Var: name}
}

// decimalInteger is a decimal integer literal as PowerShell passes it to a
// native program: leading zeros dropped. Longer numbers become a different
// type, so they are not read.
func decimalInteger(raw string) (string, bool) {
	if raw == "" || len(raw) > 18 {
		return "", false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return "", false
		}
	}
	n := strings.TrimLeft(raw, "0")
	if n == "" {
		n = "0"
	}
	return n, true
}

// literalWord is literal text as one word.
func literalWord(s string) facts.Word {
	return facts.Word{{Text: s}}
}

// endAtNUL is a word as a program receives it: a C string, which ends at
// its first NUL. (On Windows the whole command line ends there; the later
// arguments are kept, which is the stricter reading.)
func endAtNUL(w facts.Word) facts.Word {
	for i, p := range w {
		if p.Unknown {
			continue
		}
		if j := strings.IndexByte(p.Text, 0); j >= 0 {
			out := append(facts.Word(nil), w[:i]...)
			if j > 0 || i == 0 {
				out = append(out, facts.WordPart{Text: p.Text[:j]})
			}
			return out
		}
	}
	return w
}

// joinParts appends b's parts to a, merging adjacent literal parts and
// adjacent unknown parts (two unknowns side by side are one unknown value).
func joinParts(a, b facts.Word) facts.Word {
	for _, p := range b {
		if !p.Unknown && p.Text == "" && len(a) > 0 {
			continue
		}
		if n := len(a); n > 0 {
			last := &a[n-1]
			switch {
			case !last.Unknown && !p.Unknown:
				last.Text += p.Text
				continue
			case last.Unknown && p.Unknown:
				last.Var = ""
				continue
			case !last.Unknown && last.Text == "":
				a[n-1] = p
				continue
			}
		}
		a = append(a, p)
	}
	return a
}
