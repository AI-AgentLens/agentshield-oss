// Package facts is the contract between a dialect lane and the shared back end
// (ADR-001, D3). A lane reads text in its own grammar and hands the back end a
// Facts value and nothing else, so dialect knowledge (aliases, quoting,
// grammar) stays in the lane and never reaches rules.
//
// The package holds data only. It imports nothing but the standard library,
// and internal/archtest keeps it that way.
package facts

// Placeholders a lane writes where a value is computed at run time. A lane
// reads text and never evaluates it, so these mark "something is here, and the
// reader does not know what".
const (
	// Dynamic is the Name and Written of a command whose name is computed,
	// for example `& $exe` or `& (Get-Tool)`.
	Dynamic = "<dynamic>"
	// Expr is an argument whose value is an expression, for example
	// `(Get-Date)` or `$a.Path`. A bare variable is written as `$name`
	// instead, and a string keeps its text with variables unexpanded.
	Expr = "<expr>"
)

// DialectPowerShell is the Dialect of facts the PowerShell lane read.
const DialectPowerShell = "powershell"

// Facts is what one lane read in one piece of text.
type Facts struct {
	// Dialect names the lane that read the text (DialectPowerShell). The back
	// end records it on the receipt (ADR-001, decision 2) and never decides
	// on it, so a new lane is a new value here, not a back-end change.
	Dialect string
	// Simple reports that the text is exactly one command and nothing else:
	// no pipeline, separator, redirection, assignment, expression,
	// subexpression, script block, member access or method call, and every
	// argument a literal word or string. A lane sets it only when it is
	// sure, so the zero value is the safe one. The back end grants a narrow
	// exception only to a Simple text (a known read of a self-protected path,
	// a credential in a consumer's slot): Commands alone cannot show that
	// `(Get-Item x).Delete()` deletes, because its only command is Get-Item.
	Simple bool
	// Commands in source order, commands nested in arguments and script
	// blocks included.
	Commands []Command
	// Strings are the string literals outside command elements: in
	// assignments, arrays, hashtables, redirection targets and the arguments
	// of [Type]::Method('…') calls. They are read, never run. A path an agent
	// reads often appears only here (`$p = '…'; Get-Content $p`).
	Strings []string
	// Paths are the WHOLE values that are paths: a command name, an argument
	// or a string literal (an expression string included) whose entire value,
	// resolved, is path-like. Resolved means the home directory is spelled `~`
	// (from `~`, $HOME, the user-profile variables, or the home directory
	// written out), separators are `/`, and environment references are
	// replaced by their values. Letter case is kept as written: folding it is
	// a filesystem fact, not a dialect fact, and belongs to the back end.
	// A path here is one the text hands to something as a path, so the back
	// end may BLOCK on it.
	Paths []string
	// Mentions are path-like spellings that are not whole values: a word
	// inside a longer string or argument (`git commit -m "fix ~/.ssh/config"`,
	// `--key=~/.ssh/id`), and every path only the lane's raw-text scan found
	// (a comment, a construct the reader does not follow, text an encoded
	// command decodes to). The scan still sees what a reader mistake drops,
	// but a mention is evidence of naming, not of use: the back end records
	// it and never BLOCKs on it alone. Resolved as Paths are; none is also
	// in Paths.
	Mentions []string
	// Nested are the interpreters this text starts with text of their own
	// (`powershell -EncodedCommand …`, `cmd /c …`, `bash -c …`). The router
	// reads each one again in its own lane (ADR-001, D6); a lane does not
	// recurse.
	Nested []Nested
	// Notes are what the reader is unsure of. The back end treats a note as
	// uncertainty: the decision is at least AUDIT (ADR-001, D4).
	Notes []Note
	// Native are the native programs the text runs (an external executable,
	// not a cmdlet, a function or an alias of one), each as the argument
	// vector it receives, grouped as the text joins them: statements, the
	// `&&`/`||` chains of pipelines in one statement, and the stages of one
	// pipeline (#4768). A program the reader already hands to the router with
	// text of its own (Nested) is left out. The back end does not read it; a
	// surface whose row has no POSIX lane reads it with the POSIX lane (the
	// native-command bridge), so the shell rules for cross-platform programs
	// (git, kubectl, terraform …) read the argv the program receives, not the
	// PowerShell text around it.
	Native []NativeStatement
	// Calls are the .NET method calls the text makes, in source order
	// (Windows round 3): a static call on a type literal
	// (`[Convert]::ToBase64String(…)`) and an instance call
	// (`$wc.UploadString(…)`). A call is not a command: it never appears in
	// Commands, so nothing that reads commands (names, the native bridge,
	// Simple) changes. Not recorded: a call whose method name is computed
	// (`$o.$m()`), a static call on a type held in a variable (`$t::M()`),
	// and property reads, which take no arguments.
	Calls []Call
}

// Call is one .NET method call.
type Call struct {
	// Name is `type::method` for a static call, the type as written
	// without its brackets and a leading `System.` (`convert::tobase64string`,
	// `io.file::readallbytes`), or `.method` for an instance call, whose type
	// a reader of text does not know (`.uploadstring`). ASCII lower case.
	Name string
	// InputFrom and InputTo bound the commands inside the call's arguments,
	// at any depth: Facts.Commands[InputFrom:InputTo]. The zero value is the
	// empty range.
	InputFrom, InputTo int
	// CallsFrom and CallsTo bound the calls inside its arguments, at any
	// depth, and this call itself, as a Command's input range holds the
	// command: Facts.Calls[CallsFrom:CallsTo].
	CallsFrom, CallsTo int
	// StringsFrom and StringsTo bound the string literals inside its
	// arguments, at any depth: Facts.Strings[StringsFrom:StringsTo].
	StringsFrom, StringsTo int
}

// NativeStatement is one statement's native programs: its pipelines in
// source order, each joined to the one before it by Op.
type NativeStatement struct {
	Pipelines []NativePipeline
}

// NativePipeline is the native programs of one pipeline, in stage order.
type NativePipeline struct {
	// Op is the operator before this pipeline in its statement, `&&` or
	// `||`, as written; "" when it starts the statement or follows a
	// pipeline that runs no native program.
	Op string
	// Stages are the native commands of the pipeline, each its argument
	// vector. A stage that is a cmdlet or a function is left out, so two
	// native stages it sat between are adjacent here, as their data still
	// flows from one to the other.
	Stages []Argv
}

// Argv is the argument vector a native program receives: the program's name
// (ASCII lower case, its directory and its .exe, .com, .bat or .cmd
// extension dropped), then each argument.
type Argv []Word

// Word is one argument as parts, so a value the reader cannot resolve keeps
// the literal text around it: `refs/heads/$b` is the literal `refs/heads/`
// then the unknown `$b`.
type Word []WordPart

// WordPart is literal text, or a value computed at run time.
type WordPart struct {
	// Text is the literal text; empty for an unknown part.
	Text string
	// Unknown marks a value the reader cannot resolve: a variable, a
	// subexpression, a script block or any other expression.
	Unknown bool
	// Var is an unknown part's variable name when it is one variable
	// (`$b`, `$env:HOME` names HOME, `@args` names args), without its `$`
	// and scope; "" for an expression.
	Var string
}

// Command is one command invocation.
type Command struct {
	// Name is the canonical name: ASCII lower case, aliases resolved
	// (`rm`, `del` and `ri` are all `remove-item`). Dynamic when the name is
	// computed.
	Name string
	// Alternatives are the other canonical names the same invocation can
	// resolve to, when that depends on something the reader cannot see, such
	// as the version of the interpreter that runs it. Example: `curl` is
	// Invoke-WebRequest in Windows PowerShell 5.1 and the native curl.exe in
	// PowerShell 7, so Name is `invoke-webrequest` and Alternatives is
	// [`curl`]. Stricter wins, so a rule must consider every reading: match
	// on Names(), not on Name alone.
	Alternatives []string
	// Written is the name as it appears in the text, quotes and escapes
	// removed; Dynamic when the name is computed.
	Written string
	// Params are the parameter names as written, lower-cased, with their
	// leading dash (`-recurse`). A bare `--` is kept: it ends parameter
	// binding.
	Params []string
	// Args are the argument values in order: string text with variables
	// unexpanded, `$name` for a bare variable, Expr for anything else.
	Args []string
	// Elements are the parameters and arguments together, in source order.
	// Params and Args hold the same elements split by kind, which loses
	// which argument follows which parameter: `scp -i k f host:` and
	// `scp f -i k host:` have the same Params and Args, and only the first
	// hands f to -i.
	Elements []Element
	// InputFrom and InputTo bound the commands whose output can reach this
	// one (ADR-001 step 5): Facts.Commands[InputFrom:InputTo], this command
	// excluded. They are the commands in the earlier stages of its pipeline
	// (`irm $u | iex`) and the commands inside its own arguments
	// (`iex (iwr $u).Content`), each at any depth. Commands are in source
	// order, so the set is one range, and this command sits inside it. The
	// zero value is the empty range: no input known. Not covered: data that
	// reaches a command through a variable (`$s = irm $u; iex $s`) or
	// through `$_` in a script block a later stage runs.
	InputFrom, InputTo int
	// CallsFrom and CallsTo bound the .NET calls whose output can reach this
	// command, by the rule InputFrom and InputTo follow (earlier stages of its
	// pipeline, and its own arguments, at any depth): Facts.Calls[CallsFrom:CallsTo].
	// `[Convert]::ToBase64String($b) | irm $u` and
	// `irm $u -Body ([Convert]::ToBase64String($b))` both put the call in
	// irm's range.
	CallsFrom, CallsTo int
	// EncodedCommand reports that the command starts PowerShell with
	// encoded command text: -EncodedCommand in any spelling the
	// powershell.exe and pwsh command lines accept (`-enc`, `-e`, `-ec`,
	// `/enc` …), whether or not the text decoded. The decoded text is in
	// Facts.Nested; text that did not decode leaves a decode_failed note.
	EncodedCommand bool
	// StdinScript reports that the command starts PowerShell whose command
	// line runs its standard input as the script (Windows round 3): `-`,
	// `-Command -` or `-File -`, or no script at all (no -Command, -File,
	// -EncodedCommand or -CommandWithArgs and no script argument, only
	// switches and options that take a value, such as -ExecutionPolicy
	// Bypass). Fed by a pipeline, such a PowerShell runs what it is fed.
	StdinScript bool
}

// Element is one parameter or argument of a command.
type Element struct {
	// Param is a parameter as written: its dash and its letter case kept,
	// because a native program reads `-I` and `-i` as different flags.
	// Empty for an argument.
	Param string
	// Value is an argument's value, as Args holds it, or the value written
	// after a parameter's colon (`-Path:x`). Empty for a parameter without
	// one.
	Value string
	// Paths are the paths Value is, as a whole value, resolved as Facts.Paths
	// are: the value itself, or each word of a `--%` remainder, which a
	// native program receives as separate arguments. Each is also in
	// Facts.Paths. A path inside a longer value is a Facts.Mentions entry,
	// except where the lane knows the program reads it as a file (a curl
	// upload, `-F name=@<file>`), which is a path here too.
	Paths []string
	// Raw is the element as the text spells it: an argument's source text,
	// quotes and escapes kept, or a parameter's name and any attached
	// `:value`. Value is Expr for a number or any other expression; Raw
	// still shows `0` from `1` (ADR-001 step 5: a [bool] parameter's value).
	Raw string
	// Items are the elements of an array value written with commas
	// (`WinDefend,WdNisSvc`, or attached: `-Name:a,b`), each as Args holds
	// an argument: string text with variables unexpanded, `$name` for a bare
	// variable, Expr for anything else. Value is Expr for such an array. A
	// cmdlet binds the array to one parameter; a native program receives
	// each item as an argument. Windows round 3; empty for any other value.
	Items []string
}

// ParamMatches reports whether a parameter as written binds to ruleParam
// under PowerShell's abbreviation rule, read as ADR-001 decision 1 decides
// (Gary, 2026-11-02): both start with a dash, and written is a prefix of
// ruleParam that names at least one character after the dash, ASCII letter
// case ignored. `-Rec`, `-re` and `-recurse` match `-Recurse`; `-`, `--` and
// "" match nothing. PowerShell accepts only a unique prefix, and a rule
// cannot know the other parameters, so this over-matches slightly, on
// commands the rule already names: the stricter reading.
//
// Case is folded for ASCII letters only. PowerShell compares parameter names
// ordinally, so U+212A KELVIN SIGN does not bind to `-Key` and must not
// match it here (the same trap as #3771 on the shell side).
func ParamMatches(written, ruleParam string) bool {
	if len(written) < 2 || written[0] != '-' || written[1] == '-' {
		return false
	}
	if len(ruleParam) < len(written) || ruleParam[0] != '-' {
		return false
	}
	for i := 1; i < len(written); i++ {
		if asciiLower(written[i]) != asciiLower(ruleParam[i]) {
			return false
		}
	}
	return true
}

func asciiLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// Names returns Name followed by Alternatives: every canonical name this
// command can run as.
func (c Command) Names() []string {
	out := make([]string, 0, 1+len(c.Alternatives))
	out = append(out, c.Name)
	return append(out, c.Alternatives...)
}

// Nested is an interpreter started with command text of its own.
type Nested struct {
	// Exe is the interpreter's name, lower-cased, without directory or
	// `.exe`: `powershell`, `pwsh`, `cmd`, `bash`, `sh`, `wsl`.
	Exe string
	// Text is the command text the interpreter runs, decoded where the
	// command line encodes it.
	Text string
}

// NoteKind names a kind of uncertainty.
type NoteKind string

const (
	// NoteParseError: the reader could not follow the text (an unclosed
	// quote, a stray bracket, a construct it does not read, or an internal
	// failure). What it did read is still reported.
	NoteParseError NoteKind = "parse_error"
	// NoteDynamicName: a command's name is computed at run time.
	NoteDynamicName NoteKind = "dynamic_name"
	// NoteDynamicNested: an interpreter is started with command text that is
	// computed at run time (`powershell -Command $cmd`), so there is no text
	// to read again.
	NoteDynamicNested NoteKind = "dynamic_nested"
	// NoteDecodeFailed: encoded command text (`-EncodedCommand`) did not
	// decode.
	NoteDecodeFailed NoteKind = "decode_failed"
)

// Note is one thing the reader is unsure of.
type Note struct {
	Kind   NoteKind
	Detail string
}
