package cli

import (
	"os"
	"regexp"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// sp-block-config-touch's receipt (#4666, Gary 2026-11-09). The rule is a
// default-deny: it blocks every command that names a managed config file and
// is not a plain read, so its BLOCKs mix reads (less, sed -n, grep, jq) with
// writes. A write cites security-tool-tampering; anything else cites no node,
// because the node's own good example is "reading policy is safe". Evidence
// only: the decision is BLOCK either way. Gary: keep it simple; no customer
// has validated managed-host receipts yet.
//
// A write needs positive evidence in one parsed statement: its command word is
// the writer, and the managed file is the operand that writer writes.
//   - sed with -i/--in-place (alone or after argument-less switches: -ni,
//     -Ei), or perl with -i after argument-less switches (-pi, -0pi; never
//     -Mstrict or -Ilib): the file is the last operand.
//   - tee: any operand. truncate: any operand but -r/--reference's.
//   - dd: of=<file>.
//   - any statement: a > or >> redirect into the file.
//   - python or node: code (an argument or a heredoc body) that
//     opens the literal file in a write mode, Path(...).write_text/bytes, or
//     fs.writeFile*/appendFile*.
// Everything else gets no node: a mention in an argument (grep "sed -i" <cfg>,
// a commit message), the file as input (tee x < <cfg>, sed -i -f <cfg> x,
// truncate -r <cfg> x), a path in a variable, a command that does not parse,
// and a text past the chain bound (selfProtectTaxonomyRefsUnparsed). That is
// an honest gap, not a guess (#4666 Opus pass 1).

// configTouchManagedFileRe is a managed config file under a home spelling,
// whole path: sp-block-config-touch's file set
// (TestConfigTouchFileSetMatchesTheRule_4666). A file elsewhere, or one with a
// longer name (managed.json.bak), is not AgentShield's.
var configTouchManagedFileRe = regexp.MustCompile(`^(?:~|\$HOME|\$\{HOME\}|/Users/[^/]+|/home/[^/]+|/root)/\.agentshield/(?:policy\.yaml|managed\.json|agentshield\.yaml|credentials\.json|packs(?:/[^\s/$\x60()]+)*)$`)

// isManagedConfigFile reports whether word, with its quotes removed, names a
// managed config file (also under the process's own home directory).
func isManagedConfigFile(word string) bool {
	p := strings.NewReplacer(`'`, "", `"`, "").Replace(word)
	if configTouchManagedFileRe.MatchString(p) {
		return true
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" && strings.HasPrefix(p, home+"/") {
		return configTouchManagedFileRe.MatchString("~" + p[len(home):])
	}
	return false
}

var (
	// sed: -i, -i.bak, -i'', --in-place[=suf], or argument-less switches
	// before i (-ni, -Ei); BSD -I too.
	configTouchSedInPlaceRe = regexp.MustCompile(`^(?:--in-place(?:=.*)?|-[nrsuzE]*[iI].*)$`)
	// perl: argument-less switches before i (-i, -pi, -0pi, -i.bak). Not
	// -M/-I/-e/-E/-x, which take an argument or are not switches.
	configTouchPerlInPlaceRe = regexp.MustCompile(`^-[0-9aclnpsuUwWX]*i.*$`)
	// An interpreter writing a literal path. The path is checked separately.
	configTouchCodeWriteRes = []*regexp.Regexp{
		regexp.MustCompile(`\bopen\s*\(\s*['"]([^'"]+)['"]\s*,\s*(?:mode\s*=\s*)?['"][rbt]*[wax+][rwaxbt+]*['"]`),
		regexp.MustCompile(`\bPath\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\.write_(?:text|bytes)\s*\(`),
		regexp.MustCompile(`\b(?:writeFileSync|appendFileSync|writeFile|appendFile)\s*\(\s*['"]([^'"]+)['"]`),
	}
	configTouchInterpreters = map[string]bool{"python": true, "python3": true, "python2": true, "node": true}
	// A redirect word: <, >, >>, 2>, &>, <<< and the like, with or without its
	// target attached.
	configTouchRedirectWordRe = regexp.MustCompile(`^[0-9&]*(?:<<<|<<-?|<>|>>|>\||<|>)`)
)

// configTouchTaxonomyRefs is the receipt of an sp-block-config-touch BLOCK:
// the tampering node when some statement writes a managed config file, else
// none.
func configTouchTaxonomyRefs(command string) []string {
	parsed := shellparse.Parse(command, 1)
	if parsed == nil || parsed.Fallback {
		return nil
	}
	for _, seg := range everyStatement(parsed) {
		if configTouchStatementWrites(seg) {
			return spTargetRefs(spTargetConfig)
		}
	}
	return nil
}

func configTouchStatementWrites(seg shellparse.CommandSegment) bool {
	for _, r := range seg.Redirects {
		if (r.Op == ">" || r.Op == ">>" || r.Op == ">|" || r.Op == "&>" || r.Op == "&>>") && isManagedConfigFile(r.Path) {
			return true
		}
	}
	words := configTouchOperands(seg.Raw)
	switch seg.Executable {
	case "sed":
		return configTouchLastIsManaged(words, configTouchSedInPlaceRe)
	case "perl":
		return configTouchLastIsManaged(words, configTouchPerlInPlaceRe)
	case "tee":
		for _, w := range words {
			if !strings.HasPrefix(w, "-") && isManagedConfigFile(w) {
				return true
			}
		}
	case "truncate":
		for i, w := range words {
			if strings.HasPrefix(w, "-") || (i > 0 && (words[i-1] == "-r" || words[i-1] == "--reference")) {
				continue
			}
			if isManagedConfigFile(w) {
				return true
			}
		}
	case "dd":
		for _, w := range words {
			if strings.HasPrefix(w, "of=") && isManagedConfigFile(w[len("of="):]) {
				return true
			}
		}
	}
	if configTouchInterpreters[seg.Executable] {
		code := strings.Join(seg.Args, " ") + "\n" + seg.HeredocBody + "\n" + seg.InterpHeredocBody
		for _, re := range configTouchCodeWriteRes {
			for _, m := range re.FindAllStringSubmatch(code, -1) {
				if isManagedConfigFile(m[1]) {
					return true
				}
			}
		}
	}
	return false
}

// configTouchLastIsManaged reports whether the statement's words carry an
// in-place flag (inPlace) and its last word is a managed config file.
func configTouchLastIsManaged(words []string, inPlace *regexp.Regexp) bool {
	if len(words) == 0 || !isManagedConfigFile(words[len(words)-1]) {
		return false
	}
	for _, w := range words[:len(words)-1] {
		if inPlace.MatchString(strings.NewReplacer(`'`, "", `"`, "").Replace(w)) {
			return true
		}
	}
	return false
}

// configTouchOperands splits a statement's raw text into its words after the
// command word, quotes kept, with exec wrappers (sudo, env, …) and redirects
// (the operator and its target) removed. A word holding a substitution
// ($(…), a backtick, <(…), >(…)) is unresolved: it becomes a placeholder no
// managed path matches, so a pack path inside it is never read as the operand
// (#4666 Opus pass 2, F-A).
func configTouchOperands(raw string) []string {
	words := shellparse.StripExecWrappers(configTouchFields(raw))
	if len(words) == 0 {
		return nil
	}
	var out []string
	for i := 1; i < len(words); i++ {
		w := words[i]
		if m := configTouchRedirectWordRe.FindString(w); m != "" {
			if m == w {
				i++ // the target is the next word
			}
			continue
		}
		if strings.Contains(w, "$(") || strings.Contains(w, "`") || strings.Contains(w, "<(") || strings.Contains(w, ">(") {
			w = "\x00unresolved"
		}
		out = append(out, w)
	}
	return out
}

// configTouchFields splits text on unquoted blanks, keeping quotes. A
// substitution ($(…), <(…), >(…), a backtick span) stays inside its word.
func configTouchFields(text string) []string {
	var out []string
	var cur strings.Builder
	var quote byte
	depth := 0
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case depth > 0:
			cur.WriteByte(c)
			if c == '(' {
				depth++
			} else if c == ')' {
				depth--
			}
		case quote == 0 && (c == '$' || c == '<' || c == '>') && i+1 < len(text) && text[i+1] == '(':
			cur.WriteByte(c)
			cur.WriteByte('(')
			i++
			depth = 1
		case quote == '`':
			cur.WriteByte(c)
			if c == '`' {
				quote = 0
			}
		case quote == 0 && c == '`':
			quote = c
			cur.WriteByte(c)
		case quote != 0:
			cur.WriteByte(c)
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
			cur.WriteByte(c)
		case c == '\\' && i+1 < len(text):
			cur.WriteByte(c)
			cur.WriteByte(text[i+1])
			i++
		case c == ' ' || c == '\t' || c == '\n':
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
