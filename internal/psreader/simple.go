package psreader

import (
	"regexp"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/facts"
)

// simpleRe recognises, as the whole text, one command whose arguments are
// literals, and nothing else (facts.Facts.Simple). It is a recogniser
// anchored at both ends, the shape of the bash layer's plainReadRe and
// binaryReplaceMCPWordRe: a text it does not match in full is not Simple,
// and that is always the safe answer.
//
// It admits printable ASCII only. That one choice shuts out every Unicode
// spelling PowerShell treats as syntax: the curly quotes (‘ closes a string
// that ' opened), the en and em dashes of a parameter, and the no-break space
// between words. Beyond that, every character with a meaning in argument mode
// is absent from all positions: `@` at the start of a word (splatting,
// `@(…)`), `( ) { } [ ]`, `; | &`, `< >` (redirection), the backtick
// (escape), `#` (a comment), `'` and `"` outside a whole string, a newline
// inside the text, and `$` except in one form below.
//
// The parts:
//   - the command: a name of letters, digits, `_` and `-`, so not `&`, `.`, a
//     path, a drive-qualified name or a module-qualified one;
//   - a parameter: a dash and a name, nothing attached (`-Path:x` is not
//     Simple);
//   - a `--name` or `--name=value` word, the spelling a native program's long
//     option takes, which PowerShell passes as an ordinary argument;
//   - a word: no quote, `$` or bracket; `@` only after its first character
//     (`deploy@host`), and not starting with `-`, `=` or `,`;
//   - a word that starts with `$HOME` or `$env:NAME` and goes on, if at all,
//     with a separator (`$env:USERPROFILE\.ssh\id_ed25519`, the spelling a
//     Windows user types). Expanding a variable runs nothing; a member
//     access would need `.`, `[` or `(` right after the name, and none can
//     stand there;
//   - a whole single-quoted string (no `'` inside, so no `''` escape) or a
//     whole double-quoted one in which `$` appears only as `$HOME` or
//     `$env:NAME` and no backtick does. Inside a string a `.` after the name
//     is text, not a member access.
//
// Words are separated by spaces or tabs, and the text may begin and end with
// blank lines.
var simpleRe = regexp.MustCompile(`^[ \t\r\n]*` +
	`[A-Za-z][A-Za-z0-9_-]*` +
	`(?:[ \t]+(?:` +
	`-[A-Za-z][A-Za-z0-9_]*` +
	`|--[A-Za-z][A-Za-z0-9_-]*(?:=` + simpleWordRest + `)?` +
	`|[A-Za-z0-9_.\\/~:%+*?]` + simpleWordRest +
	`|` + simpleVarRef + `(?:[\\/]` + simpleWordRest + `)?` +
	`|'[ -&(-~]*'` +
	`|"(?:[ !#%-_a-~]|` + simpleVarRef + `)*"` +
	`))*` +
	`[ \t\r\n]*$`)

// simpleWordRest is what may follow the first character of a word.
const simpleWordRest = `[A-Za-z0-9_.\\/~:%+*?@=,-]*`

// simpleVarRef is the one variable reference a Simple text may hold: $HOME or
// $env:NAME, any letter case. Its value is a string, so expanding it runs
// nothing, and the lane resolves both to a path.
const simpleVarRef = `\$(?i:home|env:[a-z_][a-z0-9_]*)`

// simple reports whether text is Simple, given what the reader found in it:
// the recogniser must match, and the reader must agree that there is one
// command, that it is the text's first word, and that nothing is beside it.
// The first-word check keeps a keyword out: in `return Get-Content x` the
// recogniser's command is `return` and the reader's is Get-Content.
func simple(text string, f facts.Facts) bool {
	if !simpleRe.MatchString(text) {
		return false
	}
	if len(f.Commands) != 1 || len(f.Strings) != 0 || len(f.Nested) != 0 || len(f.Notes) != 0 {
		return false
	}
	words := strings.Fields(text)
	c := f.Commands[0]
	return len(words) > 0 && c.Written == words[0] && c.Name != facts.Dynamic
}
