package assembly

import (
	"strings"
	"unicode/utf8"

	"github.com/AI-AgentLens/agentshield/internal/facts"
)

// The native-command bridge (#4768).
//
// PowerShell runs cross-platform programs (git, kubectl, terraform, gh,
// docker, cloud CLIs …) with the arguments bash would give them, and the
// shell rules for those programs live in the POSIX pipeline. Reading the
// PowerShell text itself with the bash parser produced false BLOCKs (ADR-001
// step 4), so a row with no POSIX lane (Claude Code's PowerShell tool) had
// none of those rules. The bridge reads only what the native programs
// receive: the PowerShell lane reports each one's argument vector
// (facts.Facts.Native), NativePOSIXText writes them as POSIX command lines,
// each word quoted so bash sees exactly that argv, and PowerShellLane reads
// all of one call's lines in ONE nested POSIX reading. Because the lines are
// built here, no unclosed quote, heredoc or continuation carries from one to
// the next, which is what made joining the nested bash -c texts unsafe.

// unknownName is the bash variable an unknown value that is not one
// variable reads as (an expression, a subexpression, a script block, a
// variable bash would read differently): unset, as bash reads a value it
// cannot see.
const unknownName = "E"

// BridgeWindow is the longest pipeline, in stages, and the longest `&&`/`||`
// chain, in pipelines, the bridge writes as one. The POSIX pipeline's cost is
// superlinear in both (main, a Claude Code Bash call: 32 KiB of one-letter
// stages take 32.5 s as one pipeline and 1.84 s as pipelines of 16), so a
// longer one is written in windows of BridgeWindow that overlap
// by one, one a line: every pair of neighbours is still read together, and
// a relation further apart is not (Windowed).
const BridgeWindow = 16

// BridgeText is the POSIX text the bridge reads for one call.
type BridgeText struct {
	Text string
	// Cut reports a line not written because the text reached its limit.
	Cut bool
	// Windowed reports a pipeline or chain longer than BridgeWindow,
	// written in windows.
	Windowed bool
}

// NativePOSIXText writes native programs as POSIX shell text: a statement a
// line, its pipelines joined by their `&&`/`||`, stages by ` | `, words by
// spaces (a long pipeline or chain in windows, BridgeWindow). limit bounds
// the text in bytes (0 is none); a line that would pass it is not written,
// and Cut reports that.
//
// Each word of the text is at most twice its PowerShell spelling, and so is
// each separator, so the text is at most twice the PowerShell text
// (TestNativePOSIXText_WithinTwiceTheInput) unless the reader could not
// follow it (an unclosed bracket) or a window's overlap pushes a one-letter
// pipeline past that. The lane's limit is tighter, the input plus
// BridgeSlack: on real text the rebuilt lines are much shorter than the
// input.
func NativePOSIXText(stmts []facts.NativeStatement, limit int) BridgeText {
	var out BridgeText
	var b strings.Builder
	for _, st := range stmts {
		for _, line := range nativeLines(st, &out.Windowed) {
			n := len(line)
			if b.Len() > 0 {
				n++
			}
			if limit > 0 && b.Len()+n > limit {
				out.Cut = true
				continue
			}
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(line)
		}
	}
	out.Text = b.String()
	return out
}

// nativePipeline is one pipeline as written: its operator and its stages.
type nativePipeline struct {
	op     string
	stages []string
}

// nativeLines writes one statement: its chains of pipelines, each a line (a
// pipeline that follows one running no program a rule names, with no
// operator of its own, starts a new one), and a long pipeline or chain in
// windows.
func nativeLines(st facts.NativeStatement, windowed *bool) []string {
	var chains [][]nativePipeline
	for _, p := range st.Pipelines {
		np := nativePipeline{op: p.Op}
		for _, argv := range p.Stages {
			if shellNamedProgram(argv) {
				np.stages = append(np.stages, nativeCommand(argv))
			}
		}
		if len(np.stages) == 0 {
			continue
		}
		if len(chains) == 0 || (np.op != "&&" && np.op != "||") {
			np.op = ""
			chains = append(chains, nil)
		}
		chains[len(chains)-1] = append(chains[len(chains)-1], np)
	}
	var lines []string
	for _, chain := range chains {
		longPipeline := false
		for _, p := range chain {
			longPipeline = longPipeline || len(p.stages) > BridgeWindow
		}
		switch {
		case longPipeline:
			// A long pipeline breaks its chain: each pipeline is read on its
			// own, a long one in windows.
			*windowed = true
			for _, p := range chain {
				for _, w := range windows(len(p.stages)) {
					lines = append(lines, strings.Join(p.stages[w[0]:w[1]], " | "))
				}
			}
		case len(chain) > BridgeWindow:
			*windowed = true
			for _, w := range windows(len(chain)) {
				part := append([]nativePipeline(nil), chain[w[0]:w[1]]...)
				part[0].op = ""
				lines = append(lines, chainLine(part))
			}
		default:
			lines = append(lines, chainLine(chain))
		}
	}
	return lines
}

// chainLine writes pipelines joined by their operators.
func chainLine(chain []nativePipeline) string {
	var b strings.Builder
	for i, p := range chain {
		if i > 0 {
			b.WriteString(" " + p.op + " ")
		}
		b.WriteString(strings.Join(p.stages, " | "))
	}
	return b.String()
}

// windows splits n items into ranges of at most BridgeWindow that overlap
// by one: [0,16), [15,31), …
func windows(n int) [][2]int {
	if n <= BridgeWindow {
		return [][2]int{{0, n}}
	}
	var out [][2]int
	for start := 0; ; start += BridgeWindow - 1 {
		end := min(start+BridgeWindow, n)
		out = append(out, [2]int{start, end})
		if end == n {
			return out
		}
	}
}

// shellNamedProgram reports whether a program is one bash runs by that name:
// not a reserved word (`if`, `time`), which no shell rule names as a program.
// The program word is never an unknown: the lane reports only literal names.
func shellNamedProgram(argv facts.Argv) bool {
	return len(argv) > 0 && len(argv[0]) == 1 && !argv[0][0].Unknown && !bashReserved[argv[0][0].Text]
}

// nativeCommand writes one argument vector.
func nativeCommand(argv facts.Argv) string {
	var b strings.Builder
	for i, w := range argv {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(posixWord(w))
	}
	return b.String()
}

// bashReserved are the words bash reads as syntax in command position.
var bashReserved = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "fi": true, "case": true, "esac": true,
	"for": true, "select": true, "while": true, "until": true, "do": true, "done": true, "in": true,
	"function": true, "time": true, "coproc": true, "!": true, "[[": true, "]]": true, "{": true, "}": true,
}

// posixWord writes one word: each literal part in its shortest quoting, each
// unknown part as a bash variable. An empty word is two single quotes.
func posixWord(w facts.Word) string {
	if len(w) == 0 {
		return "''"
	}
	var b strings.Builder
	for i, p := range w {
		if !p.Unknown {
			if p.Text == "" && len(w) == 1 {
				return "''"
			}
			b.WriteString(literalText(p.Text))
			continue
		}
		name := unknownName
		if bashVariable(p.Var) {
			name = p.Var
		}
		// `$name` runs on through identifier characters, so a literal that
		// starts with one needs the braces.
		if i+1 < len(w) && !w[i+1].Unknown && w[i+1].Text != "" && identByte(w[i+1].Text[0]) {
			b.WriteString("${" + name + "}")
		} else {
			b.WriteString("$" + name)
		}
	}
	return b.String()
}

// bashVariable reports whether a PowerShell variable's name is one bash
// reads as the same plain variable. IFS is not (bash splits words on it),
// and neither is `_` (bash's last argument, PowerShell's pipeline item).
func bashVariable(name string) bool {
	if name == "" || name == "IFS" || name == "_" || !(identByte(name[0]) && (name[0] < '0' || name[0] > '9')) {
		return false
	}
	for i := 1; i < len(name); i++ {
		if !identByte(name[i]) {
			return false
		}
	}
	return true
}

func identByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// literalText writes literal text so bash reads exactly it, spelled the way
// a shell user writes it, because the shell rules' patterns are written
// against that spelling: bare when every character is literal to bash;
// otherwise quoted whole (`--principal '*'`), or after its `=` when the part
// up to it is literal (`-o jsonpath='{.a}'`, `-c key='!x'`), single quotes
// unless double quotes are shorter. Rules allow an optional quote
// (`['"]?`), never a backslash, so escaping each special character is the
// fallback, used only when quoting would pass twice the text plus one byte
// (the bridge's size bound).
func literalText(s string) string {
	if s == "" {
		return "''"
	}
	// `~user` (and bash's `~0`, `~+`) is a tilde prefix bash expands;
	// PowerShell hands it to the program as written, so it is quoted. A bare
	// `~` or `~/…` stays bare (safeByte).
	tildePrefix := s[0] == '~' && len(s) > 1 && s[1] != '/'
	if bareSafe(s) && !tildePrefix {
		return s
	}
	i := 0
	for i < len(s) && (s[i] >= utf8.RuneSelf || safeByte(s[i])) {
		i++
	}
	i = strings.LastIndexByte(s[:i], '=') + 1
	if tildePrefix {
		i = 0
	}
	quoted := singleQuoted(s[i:])
	if d := doubleQuoted(s[i:]); len(d) < len(quoted) {
		quoted = d
	}
	if i+len(quoted) <= 2*len(s)+1 {
		return s[:i] + quoted
	}
	if e := escaped(s); len(e) < i+len(quoted) {
		return e
	}
	return s[:i] + quoted
}

// safeByte reports an ASCII byte bash takes literally anywhere in a word.
// `~` is among them: bash expands a leading one to the home directory, as
// PowerShell 7 does for a native program's argument and as the PowerShell
// lane resolves paths, which is the stricter reading.
func safeByte(c byte) bool {
	return identByte(c) || strings.IndexByte("@%+=:,./-~^", c) >= 0
}

func bareSafe(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < utf8.RuneSelf && !safeByte(c) {
			return false
		}
	}
	return true
}

func singleQuoted(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func doubleQuoted(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '"' || c == '\\' || c == '$' || c == '`' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('"')
	return b.String()
}

// escaped writes every special byte with a backslash before it; a newline,
// which a backslash would join to the next line, is single-quoted.
func escaped(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '~' && i == 0:
			b.WriteString(`\~`)
		case c >= utf8.RuneSelf || safeByte(c):
			b.WriteByte(c)
		case c == '\n':
			b.WriteString("'\n'")
		default:
			b.WriteByte('\\')
			b.WriteByte(c)
		}
	}
	return b.String()
}
