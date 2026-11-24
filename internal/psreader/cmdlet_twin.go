package psreader

import (
	"regexp"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/facts"
)

// The cmdlet bridge (facts.Facts.Twins).
//
// The bash rules for file operations (a recursive delete of a home
// directory, a write to a shell profile, a read of a key) read `rm`, `cp`,
// `cat` and `>`. PowerShell does the same with cmdlets, which the
// native-command bridge never reads, so on a row with no POSIX lane (Claude
// Code's PowerShell tool) those rules never saw it. A file cmdlet call is
// read here as its POSIX twin, the command line a bash user would write for
// the same effect:
//
//	Get-Content  (cat, type, gc)                   -> cat P…
//	Copy-Item    (cp, copy, cpi)                   -> cp [-r] [-f] P… D
//	Move-Item    (mv, move, mi)                    -> mv [-f] P… D
//	Remove-Item  (rm, del, erase, rd, rmdir, ri)   -> rm [-r|-f|-rf] P…
//	Set-Content  (sc in 5.1), Out-File             -> echo x > P   (Out-File -Append: >>)
//	Add-Content  (ac)                              -> echo x >> P
//
// and each redirection of the success stream to a literal file (`> f`,
// `>> f`, `1> f`, `*> f`) as `echo x > f`, which is Out-File on the
// statement's output. The twins stand in their commands' places among the
// native programs (Facts.Twins); a surface reads that as a second POSIX text
// beside Facts.Native's and keeps the stricter reading, so a twin can only
// raise a decision.
//
// A path is written as the reader resolves it (paths.go): the home
// directory as `~`, `\` as `/`, a known environment variable replaced by its
// value. So `Remove-Item -Recurse $env:USERPROFILE\.ssh` is `rm -r ~/.ssh`,
// the spelling the bash rules are written against.
//
// What has no twin, so reads as main read it:
//   - -WhatIf: nothing is done (`-WhatIf:$false` is off, so it has a twin).
//   - -Filter, -Include, -Exclude: they narrow what is touched, and a twin
//     without them over-reads (`rm -rf C:\x\*` for one *.log delete).
//   - -Credential, -FromSession, -ToSession: another principal or another
//     host, where a bash rule's local-path meaning does not hold. -Stream:
//     an alternate data stream, not the file.
//   - No path in the text: the path comes down the pipeline
//     (`gci … | Remove-Item`), which ps-block-remove-piped-system reads.
//   - A path on another provider: a drive name longer than one letter
//     (`HKLM:`, `HKCU:`, `Env:`, `Function:`, `Alias:`, `Variable:`,
//     `Cert:`, `WSMan:`) or a provider-qualified path other than
//     FileSystem's (`Registry::…`). Those are not files.
//   - The stop-parsing token `--%`, and a dot-sourced call.
//
// A switch given `:$false` (or `:0`) is off. A parameter PowerShell would
// not bind (`rm -rf x`: there is no -rf; `-f` is ambiguous between -Filter
// and -Force) is passed to the twin as written: the twin reads the intent.
// A literal -Path with a wildcard is written bare when bash reads its other
// bytes literally, so it is a glob to both (facts.WordPart.Bare). A write's
// content is not carried: `echo x` stands for it, so only rules keyed on the
// target fire.

type twinRole int

const (
	rPath    twinRole = iota // -Path: a path, wildcards expanded
	rLPath                   // -LiteralPath (and Out-File -FilePath): a path as written
	rDest                    // -Destination
	rValue                   // a value the twin does not carry (-Value, -InputObject)
	rRecurse                 // -Recurse
	rForce                   // -Force (Copy-Item, Move-Item, Remove-Item)
	rAppend                  // Out-File -Append
	rWhatIf                  // -WhatIf: nothing is done, so no twin
	rBail                    // a parameter the twin cannot express: no twin
	rOpt                     // takes a value the twin drops
	rSwitch                  // a switch the twin drops
)

// twinParam is one parameter name or alias and what it is to the twin.
type twinParam struct {
	name string
	role twinRole
}

// commonTwinParams are PowerShell's common parameters (7.4 and 5.1) and
// their aliases.
var commonTwinParams = []twinParam{
	{"-ErrorAction", rOpt}, {"-ea", rOpt}, {"-WarningAction", rOpt}, {"-wa", rOpt},
	{"-InformationAction", rOpt}, {"-infa", rOpt}, {"-ProgressAction", rOpt}, {"-proga", rOpt},
	{"-ErrorVariable", rOpt}, {"-ev", rOpt}, {"-WarningVariable", rOpt}, {"-wv", rOpt},
	{"-InformationVariable", rOpt}, {"-iv", rOpt}, {"-OutVariable", rOpt}, {"-ov", rOpt},
	{"-OutBuffer", rOpt}, {"-ob", rOpt}, {"-PipelineVariable", rOpt}, {"-pv", rOpt},
	{"-Verbose", rSwitch}, {"-vb", rSwitch}, {"-Debug", rSwitch}, {"-db", rSwitch},
	{"-Confirm", rSwitch}, {"-cf", rSwitch}, {"-WhatIf", rWhatIf}, {"-wi", rWhatIf},
	{"-UseTransaction", rSwitch}, {"-usetx", rSwitch},
}

var twinPathParams = []twinParam{
	{"-Path", rPath}, {"-LiteralPath", rLPath}, {"-PSPath", rLPath}, {"-LP", rLPath},
}

var twinNarrowingParams = []twinParam{
	{"-Filter", rBail}, {"-Include", rBail}, {"-Exclude", rBail}, {"-Credential", rBail},
}

// twinSpec is one cmdlet's twin: the POSIX program (`>` and `>>` for a
// write), its parameters, and what each position binds.
type twinSpec struct {
	verb       string
	params     []twinParam
	positional []twinRole
}

func twinParams(lists ...[]twinParam) []twinParam {
	var out []twinParam
	for _, l := range lists {
		out = append(out, l...)
	}
	return append(out, commonTwinParams...)
}

// twinSpecs are the file cmdlets by canonical name (aliases are resolved by
// canonical), with their parameters in PowerShell 7.4 and 5.1.
var twinSpecs = map[string]twinSpec{
	"get-content": {"cat", twinParams(twinPathParams, twinNarrowingParams, []twinParam{
		{"-ReadCount", rOpt}, {"-TotalCount", rOpt}, {"-First", rOpt}, {"-Head", rOpt},
		{"-Tail", rOpt}, {"-Last", rOpt}, {"-Delimiter", rOpt}, {"-Encoding", rOpt},
		{"-Stream", rBail}, {"-Force", rSwitch}, {"-Wait", rSwitch}, {"-Raw", rSwitch},
		{"-AsByteStream", rSwitch},
	}), []twinRole{rPath}},
	"copy-item": {"cp", twinParams(twinPathParams, twinNarrowingParams, []twinParam{
		{"-Destination", rDest}, {"-Container", rSwitch}, {"-Force", rForce}, {"-Recurse", rRecurse},
		{"-PassThru", rSwitch}, {"-FromSession", rBail}, {"-ToSession", rBail},
	}), []twinRole{rPath, rDest}},
	"move-item": {"mv", twinParams(twinPathParams, twinNarrowingParams, []twinParam{
		{"-Destination", rDest}, {"-Force", rForce}, {"-PassThru", rSwitch},
	}), []twinRole{rPath, rDest}},
	"remove-item": {"rm", twinParams(twinPathParams, twinNarrowingParams, []twinParam{
		{"-Recurse", rRecurse}, {"-Force", rForce}, {"-Stream", rBail},
	}), []twinRole{rPath}},
	"set-content": {">", twinParams(twinPathParams, twinNarrowingParams, []twinParam{
		{"-Value", rValue}, {"-PassThru", rSwitch}, {"-NoNewline", rSwitch}, {"-Force", rSwitch},
		{"-Encoding", rOpt}, {"-AsByteStream", rSwitch}, {"-Stream", rBail},
	}), []twinRole{rPath, rValue}},
	"add-content": {">>", twinParams(twinPathParams, twinNarrowingParams, []twinParam{
		{"-Value", rValue}, {"-PassThru", rSwitch}, {"-NoNewline", rSwitch}, {"-Force", rSwitch},
		{"-Encoding", rOpt}, {"-AsByteStream", rSwitch}, {"-Stream", rBail},
	}), []twinRole{rPath, rValue}},
	"out-file": {">", twinParams([]twinParam{
		{"-FilePath", rLPath}, {"-Path", rLPath}, {"-LiteralPath", rLPath}, {"-PSPath", rLPath}, {"-LP", rLPath},
		{"-Encoding", rOpt}, {"-Append", rAppend}, {"-Force", rSwitch}, {"-NoClobber", rSwitch},
		{"-Width", rOpt}, {"-NoNewline", rSwitch}, {"-InputObject", rValue},
	}), []twinRole{rLPath, rOpt}},
}

// bindTwinParam binds a parameter as written by PowerShell's rule: an exact
// name or alias, else a unique prefix (facts.ParamMatches). ok is false when
// none or several match, which PowerShell refuses.
func bindTwinParam(written string, params []twinParam) (twinRole, bool) {
	for _, p := range params {
		if strings.EqualFold(written, p.name) {
			return p.role, true
		}
	}
	var hit []twinParam
	for _, p := range params {
		if facts.ParamMatches(written, p.name) {
			hit = append(hit, p)
		}
	}
	if len(hit) == 1 {
		return hit[0].role, true
	}
	return 0, false
}

// twinStatements are Facts.Twins: the native programs grouped as
// nativeStatements groups them, with each file cmdlet call's twin in its
// place, then each output redirection to a literal file as a statement of
// its own. Nil when no command and no redirection has a twin.
func twinStatements(cmds []*rawCommand, routed []bool, pipes map[int]pipeInfo, redirs []outRedir, res *resolver) []facts.NativeStatement {
	twinned := false
	stmts := groupStatements(cmds, routed, pipes, func(c *rawCommand) (facts.Argv, bool) {
		if argv, ok := nativeCommandArgv(c); ok {
			return argv, true
		}
		argv, ok := cmdletTwinArgv(c, res)
		twinned = twinned || ok
		return argv, ok
	})
	for _, rd := range redirs {
		if st, ok := redirectionTwin(rd, res); ok {
			stmts = append(stmts, st)
			twinned = true
		}
	}
	if !twinned {
		return nil
	}
	return stmts
}

// cmdletTwinArgv is the POSIX twin of a file cmdlet call, as one argument
// vector; ok is false when the command is not one, or the call has no twin.
func cmdletTwinArgv(c *rawCommand, res *resolver) (facts.Argv, bool) {
	if c.name == facts.Dynamic || c.op == "." {
		return nil, false
	}
	name, alts := canonical(c.name)
	spec, found := twinSpecs[name]
	for _, n := range alts {
		if !found {
			spec, found = twinSpecs[n]
		}
	}
	if !found {
		return nil, false
	}
	var paths, dests, flags []facts.Word
	recurse, force, appends := false, false, false
	pos := 0
	named := map[twinRole]bool{} // the positions a named parameter already bound
	add := func(role twinRole, el *element) bool {
		if role != rPath && role != rLPath && role != rDest {
			return true // a value the twin does not carry
		}
		ws, ok := twinWords(el, role, res)
		if !ok {
			return false
		}
		switch role {
		case rPath, rLPath:
			paths = append(paths, ws...)
		case rDest:
			dests = append(dests, ws...)
		}
		return true
	}
	for i := 0; i < len(c.elems); i++ {
		el := &c.elems[i]
		if el.verbatim || el.raw == "--%" {
			return nil, false
		}
		if el.param == "" {
			if !el.hasVal {
				continue
			}
			role := rPath
			for pos < len(spec.positional) && named[spec.positional[pos]] {
				pos++
			}
			if pos < len(spec.positional) {
				role = spec.positional[pos]
			} else if spec.verb == "cp" || spec.verb == "mv" {
				// PowerShell has no position left for it, so the call does
				// not bind; bash's last operand is the destination.
				paths = append(paths, dests...)
				dests = nil
				role = rDest
			}
			pos++
			if !add(role, el) {
				return nil, false
			}
			continue
		}
		written, _, attached := strings.Cut(el.raw, ":")
		role, ok := bindTwinParam(written, spec.params)
		if !ok {
			flags = append(flags, facts.Word{{Text: written}})
			continue
		}
		if role == rLPath {
			named[rPath] = true
		}
		named[role] = true
		var v *element
		takesValue := role == rPath || role == rLPath || role == rDest || role == rValue || role == rOpt
		if takesValue {
			if attached {
				if el.hasVal {
					v = el
				}
			} else if i+1 < len(c.elems) && c.elems[i+1].param == "" && !c.elems[i+1].verbatim {
				i++
				v = &c.elems[i]
			}
		}
		// A switch given `:$false` (or `:0`) is off. A number's value is
		// Expr; its source text after the colon says which.
		val := el.val.text
		if val == facts.Expr {
			_, val, _ = strings.Cut(el.raw, ":")
		}
		if attached && el.hasVal && (strings.EqualFold(val, "$false") || val == "0") {
			switch role {
			case rRecurse, rForce, rAppend, rWhatIf:
				continue
			}
		}
		switch role {
		case rBail, rWhatIf:
			return nil, false
		case rRecurse:
			recurse = true
		case rForce:
			force = true
		case rAppend:
			appends = true
		case rPath, rLPath, rDest:
			if v != nil && !add(role, v) {
				return nil, false
			}
		}
	}
	if len(paths) == 0 {
		return nil, false
	}
	switch spec.verb {
	case ">", ">>":
		op := spec.verb
		if appends {
			op = ">>"
		}
		argv := facts.Argv{literalWord("echo"), literalWord("x")}
		for _, p := range paths {
			argv = append(argv, facts.Word{{Text: op, Bare: true}}, p)
		}
		return argv, true
	}
	argv := facts.Argv{literalWord(spec.verb)}
	switch {
	case recurse && force:
		argv = append(argv, literalWord("-rf"))
	case recurse:
		argv = append(argv, literalWord("-r"))
	case force && spec.verb != "cat":
		argv = append(argv, literalWord("-f"))
	}
	argv = append(argv, flags...)
	argv = append(argv, paths...)
	if spec.verb == "cp" || spec.verb == "mv" {
		if len(dests) == 0 {
			dests = []facts.Word{literalWord(".")}
		}
		argv = append(argv, dests...)
	}
	return argv, true
}

// twinWords are one value's path words: each array item, each a path word.
// ok is false when one of them is on a provider other than FileSystem, which
// leaves the call with no twin.
func twinWords(el *element, role twinRole, res *resolver) ([]facts.Word, bool) {
	items := el.val.items
	raws := []string(nil)
	if len(items) == 0 {
		items = []value{el.val}
		raws = []string{el.raw}
	}
	out := make([]facts.Word, 0, len(items))
	for i, it := range items {
		if it.k == kStr && providerPath(it.text) {
			return nil, false
		}
		raw := ""
		if raws != nil {
			raw = raws[i]
		}
		out = append(out, twinPathWord(it, raw, role, res))
	}
	return out, true
}

// twinPathWord is one path as the twin writes it: resolved as the reader
// resolves a whole-value path (home as `~`, `/` separators) when it is
// path-like, else as the native bridge writes an argument. A literal -Path
// with a wildcard bash reads alike is written bare (globSafe).
func twinPathWord(v value, raw string, role twinRole, res *resolver) facts.Word {
	if v.k == kStr && res != nil {
		if p, ok := res.wholeValue(v.text); ok && !strings.Contains(p, facts.Expr) {
			v = value{text: p, k: kStr, static: true}
		}
	}
	if v.k == kStr && v.static && role == rPath && globSafe(v.text) {
		return facts.Word{{Text: v.text, Bare: true}}
	}
	return endAtNUL(valueWord(v, raw))
}

// globSafe reports a literal -Path value with a wildcard whose every other
// byte bash takes literally, so it can be written bare (a glob to both).
func globSafe(s string) bool {
	if !strings.ContainsAny(s, "*?[") || (len(s) > 1 && s[0] == '~' && s[1] != '/') {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("_@%+=:,./-~^*?[]", c) >= 0) {
			return false
		}
	}
	return true
}

// providerQualifierRe is a provider-qualified path (`Registry::HKLM\…`,
// `Microsoft.PowerShell.Core\Registry::…`); a FileSystem one is stripped
// before this is asked (stripFileSystemProvider).
var providerQualifierRe = regexp.MustCompile(`^[A-Za-z0-9_.\\/]+::`)

// providerDriveRe is a path on a drive whose name is longer than one letter:
// `HKLM:`, `Env:`, `Function:`, `Cert:` … A one-letter drive is a
// FileSystem drive (`C:`).
var providerDriveRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{2,}:`)

// providerPath reports a value that names a path on a PowerShell provider
// other than FileSystem: not a file, so no twin.
func providerPath(text string) bool {
	s := stripFileSystemProvider(trimQuotes(text))
	return providerQualifierRe.MatchString(s) || providerDriveRe.MatchString(s)
}

// outRedir is one redirection of the success stream (`>`, `>>`, `1>`,
// `*>`) to a literal target.
type outRedir struct {
	appends bool
	val     value
}

// redirectionTwin is the statement `echo x > target` (`>>` when appending)
// for one output redirection: PowerShell's `>` is Out-File on the
// statement's output. None for `$null`, `NUL` or a provider path.
func redirectionTwin(rd outRedir, res *resolver) (facts.NativeStatement, bool) {
	t := trimQuotes(rd.val.text)
	if t == "" || strings.EqualFold(t, "$null") || strings.EqualFold(t, "nul") || providerPath(rd.val.text) {
		return facts.NativeStatement{}, false
	}
	op := ">"
	if rd.appends {
		op = ">>"
	}
	argv := facts.Argv{literalWord("echo"), literalWord("x"), facts.Word{{Text: op, Bare: true}},
		twinPathWord(rd.val, rd.val.text, rLPath, res)}
	return facts.NativeStatement{Pipelines: []facts.NativePipeline{{Stages: []facts.Argv{argv}}}}, true
}
