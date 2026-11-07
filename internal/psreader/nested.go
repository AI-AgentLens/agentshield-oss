package psreader

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf16"

	"github.com/AI-AgentLens/agentshield/internal/facts"
)

// item is one command-line word as the started program receives it.
type item struct {
	text    string // the value, or the source text when it is computed
	dynamic bool   // computed at run time: a variable or an expression
	block   bool   // a script-block literal, already read in place
}

// argv turns a command's elements into the words its program receives. A
// `--%` remainder is split the way a Windows program splits its command line.
func argv(c *rawCommand) []item {
	var out []item
	for _, e := range c.elems {
		switch {
		case e.raw == "--%" && e.param == "" && !e.hasVal:
			// the stop-parsing marker itself is not passed on
		case e.verbatim:
			for _, w := range splitWindowsArgs(e.val.text) {
				out = append(out, item{text: w})
			}
		case e.param != "":
			name, src, attached := strings.Cut(e.raw, ":")
			out = append(out, item{text: name})
			if attached && e.hasVal {
				out = append(out, valueItem(e.val, src))
			}
		default:
			out = append(out, valueItem(e.val, e.raw))
		}
	}
	return out
}

func valueItem(v value, raw string) item {
	switch {
	case v.k == kStr:
		return item{text: v.text}
	case v.k == kBlock:
		return item{text: raw, block: true}
	default:
		return item{text: raw, dynamic: true}
	}
}

// exeName is a command name reduced to the program it starts: no directory,
// lower case, no `.exe`.
func exeName(written string) string {
	if i := strings.LastIndexAny(written, `/\`); i >= 0 {
		written = written[i+1:]
	}
	return strings.TrimSuffix(asciiLower(written), ".exe")
}

// nested reports the interpreter a command starts with text of its own, and
// whether the command line hands it encoded text (-EncodedCommand), decoded
// or not.
func nested(c *rawCommand) (n facts.Nested, ok, encoded bool, notes []facts.Note) {
	if c.name == facts.Dynamic {
		return facts.Nested{}, false, false, nil
	}
	if name, _ := canonical(c.name); name == "invoke-expression" {
		text, ok, dyn := iexText(c)
		if dyn {
			notes = append(notes, facts.Note{Kind: facts.NoteDynamicNested,
				Detail: "invoke-expression runs command text computed at run time"})
		}
		if !ok {
			return facts.Nested{}, false, false, notes
		}
		return facts.Nested{Exe: "powershell", Text: text}, true, false, notes
	}
	exe := exeName(c.name)
	var text string
	var dyn bool
	switch exe {
	case "powershell", "pwsh":
		var ns []facts.Note
		text, ok, dyn, encoded, ns = powershellText(argv(c))
		notes = append(notes, ns...)
	case "cmd":
		text, ok, dyn = cmdText(argv(c))
	case "bash", "sh":
		text, ok, dyn = posixText(argv(c))
	case "wsl":
		text, ok, dyn = wslText(argv(c))
	default:
		return facts.Nested{}, false, false, nil
	}
	if dyn {
		notes = append(notes, facts.Note{Kind: facts.NoteDynamicNested,
			Detail: fmt.Sprintf("%s starts command text computed at run time", exe)})
	}
	if !ok {
		return facts.Nested{}, false, encoded, notes
	}
	return facts.Nested{Exe: exe, Text: text}, true, encoded, notes
}

// iexText reads Invoke-Expression's one argument, the command text it runs
// in this session: given positionally or as -Command (any prefix), as a
// string. ok is false for anything else (no argument, more than one, a script
// block, which the reader has already read in place); dyn reports an argument
// computed at run time (a variable, an expression), whose text the reader
// cannot see. A string that expands variables counts as its text: the lane
// resolves the environment references in it, as for powershell -Command.
func iexText(c *rawCommand) (text string, ok, dyn bool) {
	var vals []value
	for _, e := range c.elems {
		switch {
		case e.param != "":
			name, _, _ := strings.Cut(e.raw, ":")
			if !facts.ParamMatches(name, "-Command") {
				return "", false, false
			}
			if e.hasVal {
				vals = append(vals, e.val)
			}
		case e.hasVal && !e.verbatim:
			vals = append(vals, e.val)
		default:
			return "", false, false
		}
	}
	if len(vals) != 1 {
		return "", false, false
	}
	switch v := vals[0]; v.k {
	case kStr:
		return v.text, true, false
	case kBlock:
		return "", false, false
	default:
		return "", false, true
	}
}

// cliOption reads a word as a PowerShell CLI option: `-x`, `--x` or `/x`,
// where the dash may be any of the dashes PowerShell accepts.
func cliOption(it item) (string, bool) {
	t := it.text
	if r := []rune(t); len(r) > 0 && isDash(r[0]) && r[0] != '-' {
		t = "-" + string(r[1:])
	}
	switch {
	case strings.HasPrefix(t, "--") && len(t) > 2:
		return asciiLower(t[2:]), true
	case (strings.HasPrefix(t, "-") || strings.HasPrefix(t, "/")) && len(t) > 1:
		return asciiLower(t[1:]), true
	}
	return "", false
}

// prefixOf reports whether key spells option full, at least minLen long:
// PowerShell's CLI accepts any such prefix (`-c`, `-com`, `-command`).
func prefixOf(key, full string, minLen int) bool {
	return len(key) >= minLen && strings.HasPrefix(full, key)
}

// psValueOptions are the PowerShell CLI options that take a value, as
// (full name, shortest accepted prefix) plus exact short forms.
var psValueOptions = []struct {
	full   string
	minLen int
}{
	{"executionpolicy", 2}, {"ep", 2},
	{"inputformat", 3}, {"if", 2},
	{"outputformat", 1}, {"of", 2},
	{"windowstyle", 1},
	{"workingdirectory", 2}, {"wd", 2},
	{"configurationname", 6},
	{"configurationfile", 17},
	{"custompipename", 14},
	{"settingsfile", 8},
	{"psconsolefile", 13},
	{"version", 1},
}

// powershellText reads powershell.exe / pwsh arguments (5.1 and 7 CLI). The
// command text is what -Command (any prefix, from -c), -CommandWithArgs
// (-cwa) or -EncodedCommand (any prefix from -e, or -ec) carries. A first
// positional word starts the command text too: that is 5.1's default, while
// pwsh reads it as a script path, and reading a script path as a command can
// only add.
//
// encoded reports that the text is given encoded (-EncodedCommand in any
// accepted spelling), whether or not it decoded.
func powershellText(items []item) (text string, ok, dyn, encoded bool, notes []facts.Note) {
	for i := 0; i < len(items); i++ {
		key, isOpt := cliOption(items[i])
		if !isOpt {
			text, ok, dyn = joinFrom(items[i:], false)
			return text, ok, dyn, false, nil
		}
		switch {
		case key == "commandwithargs" || key == "cwa":
			if i+1 < len(items) {
				text, ok, dyn, notes = firstText(items[i+1])
				return text, ok, dyn, false, notes
			}
			return "", false, false, false, nil
		case prefixOf(key, "command", 1):
			text, ok, dyn = joinFrom(items[i+1:], false)
			if ok && text == "-" { // read from stdin
				return "", false, false, false, nil
			}
			return text, ok, dyn, false, nil
		case prefixOf(key, "encodedcommand", 1) || key == "ec":
			if i+1 >= len(items) {
				return "", false, false, true, nil
			}
			enc := items[i+1]
			if enc.dynamic {
				return "", false, true, true, nil
			}
			dec, err := decodeEncodedCommand(enc.text)
			if err != nil {
				return "", false, false, true, []facts.Note{{Kind: facts.NoteDecodeFailed,
					Detail: fmt.Sprintf("-EncodedCommand %q: %v", clip(enc.text, 40), err)}}
			}
			return dec, true, false, true, nil
		case prefixOf(key, "file", 1):
			return "", false, false, false, nil // a script path; its arguments are its own
		}
		for _, o := range psValueOptions {
			if prefixOf(key, o.full, o.minLen) {
				i++ // skip the value
				break
			}
		}
	}
	return "", false, false, false, nil
}

// powershellStdin reports whether a powershell.exe / pwsh command line runs
// its standard input as the script (facts.Command.StdinScript): `-` as the
// script, as -Command's or as -File's value, or no script at all, only
// switches and options that take a value. Any other script (text, a path,
// encoded text, a computed word) and a help request read none.
func powershellStdin(items []item) bool {
	isStdin := func(i int) bool { return i < len(items) && !items[i].dynamic && items[i].text == "-" }
	for i := 0; i < len(items); i++ {
		key, isOpt := cliOption(items[i])
		if !isOpt {
			return isStdin(i)
		}
		switch {
		case key == "commandwithargs" || key == "cwa":
			return false
		case prefixOf(key, "command", 1), prefixOf(key, "file", 1):
			return isStdin(i + 1)
		case prefixOf(key, "encodedcommand", 1) || key == "ec":
			return false
		case key == "?" || prefixOf(key, "help", 1):
			return false
		}
		for _, o := range psValueOptions {
			if prefixOf(key, o.full, o.minLen) {
				i++ // skip the value
				break
			}
		}
	}
	return true
}

func firstText(it item) (string, bool, bool, []facts.Note) {
	if it.dynamic {
		return "", false, true, nil
	}
	if it.block {
		return "", false, false, nil
	}
	return it.text, true, false, nil
}

// joinFrom joins the words that form the command text. A first word that is
// computed means there is no text to read; a script block was read in place.
func joinFrom(items []item, quote bool) (string, bool, bool) {
	if len(items) == 0 {
		return "", false, false
	}
	if items[0].dynamic {
		return "", false, true
	}
	if items[0].block {
		return "", false, false
	}
	return joinItems(items, quote), true, false
}

// joinItems joins words with spaces. With quote, a word holding whitespace is
// double-quoted, the way PowerShell rebuilds a native command line.
func joinItems(items []item, quote bool) string {
	words := make([]string, len(items))
	for i, it := range items {
		w := it.text
		if quote && strings.ContainsAny(w, " \t") {
			w = `"` + w + `"`
		}
		words[i] = w
	}
	return strings.Join(words, " ")
}

// cmdText reads cmd.exe arguments: the text after the first /c, /k or /r
// (also attached: /cdir, and in a joined run: /d/c, cmdRunSwitch).
func cmdText(items []item) (string, bool, bool) {
	for i, it := range items {
		if it.dynamic {
			continue
		}
		rest, ok := cmdRunSwitch(it.text)
		if !ok {
			continue
		}
		rest = strings.TrimSpace(rest)
		tail := items[i+1:]
		if rest == "" {
			text, ok, dyn := joinFrom(tail, true)
			return cmdStripQuotes(text), ok, dyn
		}
		if len(tail) > 0 {
			rest += " " + joinItems(tail, true)
		}
		return cmdStripQuotes(rest), true, false
	}
	return "", false, false
}

// cmdRunSwitch reads one word of cmd.exe switches. cmd takes them joined:
// `cmd /d/c echo x` and `cmd /s/c "echo x"` run the command (measured on
// Windows by Opus pass 2 on #4245), so the first /c, /k or /r in a run of
// switches starts the command, and what follows it in the word is the
// command's first text (`/cdir`, `/d/cdir`). A switch after it is that text:
// `cmd /c/d …` reads `/d …`, which runs nothing.
func cmdRunSwitch(w string) (string, bool) {
	for i := 0; i+1 < len(w) && w[i] == '/'; {
		switch w[i+1] {
		case 'c', 'C', 'k', 'K', 'r', 'R':
			return w[i+2:], true
		}
		j := strings.IndexByte(w[i+1:], '/')
		if j < 0 {
			break
		}
		i += 1 + j
	}
	return "", false
}

// cmdStripQuotes applies cmd's rule for the text after /c: when it starts
// with a quote, that quote and the last quote on the line are removed (the
// `cmd /?` "otherwise" case, which is what PowerShell's quoting produces).
func cmdStripQuotes(s string) string {
	if !strings.HasPrefix(s, `"`) {
		return s
	}
	s = s[1:]
	if i := strings.LastIndexByte(s, '"'); i >= 0 {
		s = s[:i] + s[i+1:]
	}
	return s
}

// posixText reads bash/sh arguments: with -c (alone or in a cluster such as
// -lc), the first word that is not an option is the command text.
func posixText(items []item) (string, bool, bool) {
	sawC := false
	for i := 0; i < len(items); i++ {
		t := items[i].text
		switch {
		case t == "--":
			if sawC && i+1 < len(items) {
				return joinFrom(items[i+1:i+2], false)
			}
			return "", false, false
		case strings.HasPrefix(t, "--"):
			if t == "--rcfile" || t == "--init-file" {
				i++
			}
		case len(t) > 1 && (t[0] == '-' || t[0] == '+') && !items[i].dynamic:
			if t[0] == '-' && strings.ContainsRune(t[1:], 'c') {
				sawC = true
			}
			if strings.ContainsAny(t[1:], "oO") {
				i++ // -o option
			}
		default:
			if !sawC {
				return "", false, false // a script file
			}
			return joinFrom(items[i:i+1], false)
		}
	}
	return "", false, false
}

// wslText reads wsl.exe arguments: the command after its own options, after
// -e/--exec, or after --. A management option (--install, -l …) runs none.
func wslText(items []item) (string, bool, bool) {
	for i := 0; i < len(items); i++ {
		switch asciiLower(items[i].text) {
		case "-d", "--distribution", "-u", "--user", "--cd", "--shell-type", "--distribution-id":
			i++
			continue
		case "--system":
			continue
		case "-e", "--exec", "--":
			return joinFrom(items[i+1:], true)
		}
		if strings.HasPrefix(items[i].text, "-") && !items[i].dynamic {
			return "", false, false
		}
		return joinFrom(items[i:], true)
	}
	return "", false, false
}

// decodeEncodedCommand decodes -EncodedCommand: base64 of UTF-16LE text.
// Whitespace is ignored and missing padding tolerated, so the decode is at
// least as lenient as .NET's; a trailing odd byte is dropped.
func decodeEncodedCommand(s string) (string, error) {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
	}
	if err != nil {
		return "", fmt.Errorf("not base64")
	}
	if len(b) < 2 {
		return "", fmt.Errorf("decodes to %d bytes", len(b))
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	text := string(utf16.Decode(u))
	return strings.TrimPrefix(text, "\uFEFF"), nil
}

// splitWindowsArgs splits a command line the way a Windows program's C
// runtime does, closely enough for reading: whitespace separates words, and
// double quotes group them.
func splitWindowsArgs(s string) []string {
	var out []string
	var b strings.Builder
	inQ, have := false, false
	for _, c := range s {
		switch {
		case c == '"':
			inQ = !inQ
			have = true
		case (c == ' ' || c == '\t') && !inQ:
			if have {
				out = append(out, b.String())
				b.Reset()
				have = false
			}
		default:
			b.WriteRune(c)
			have = true
		}
	}
	if have {
		out = append(out, b.String())
	}
	return out
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// clipWord is clip for text that can quote a secret, such as a computed
// command name. A cut inside a word drops the rest of that word too, so a
// note never ends in the first part of a token. The audit redactor
// recognises whole tokens only, so a token's first part would reach the
// receipt in plain text.
func clipWord(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	cut := n
	for cut > 0 && tokenRune(r[cut]) && tokenRune(r[cut-1]) {
		cut--
	}
	return string(r[:cut]) + "…"
}

// tokenRune reports whether r can occur inside a credential token: letters,
// digits and the punctuation of base64, base64url and JWTs.
func tokenRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("_-+/=.~", r)
}
