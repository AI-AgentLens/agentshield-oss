package psreader

import (
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/facts"
)

// Uploads (ADR-001 step 5, #4245). curl reads a file and sends its bytes
// when an option's value names it with `@` (or `<` in a form field):
// `-F name=@<file>`, `--form name=<<file>`, `-d @<file>`, `--data-binary
// @<file>`, `--data-urlencode name@<file>`, `--json @<file>`, and the option
// words `--data=@<file>` and `--form=name=@<file>`. The generic reading keeps
// such a file as a mention (a path inside a longer value), so a key upload
// decided AUDIT where bash's `curl -F f=@<key>` BLOCKs. For a command that
// can run as curl, the file is a whole value: a facts.Facts path, and a path
// of the element that carries it. A bare name is read under cwd, as a bare
// argument is.
//
// Only curl: `-T`/`--upload-file <file>` and wget's `--post-file <file>` /
// `--body-file=<file>` are whole values already, and Invoke-WebRequest and
// Invoke-RestMethod take a file as -InFile, a whole value too. On Windows
// PowerShell 5.1 `curl` is Invoke-WebRequest, which has no such options; the
// reader keeps both readings of the name, and stricter wins.
//
// Options are case-sensitive, as curl reads them (`-D` dumps headers, `-d`
// sends data). `--data-raw` and `--form-string` send their value literally
// and are left out. Not covered: a short option with its value attached
// (`-d@<file>`), a quoted file name inside a form value
// (`name=@"a;b"`), and a `--%` remainder.

// curlUploadOptions maps a curl option to how its value names a file.
var curlUploadOptions = map[string]uploadKind{
	"-F": uploadForm, "--form": uploadForm,
	"-d": uploadData, "--data": uploadData, "--data-binary": uploadData, "--data-ascii": uploadData,
	"--json":           uploadData,
	"--data-urlencode": uploadURLEncode,
}

type uploadKind int

const (
	uploadForm uploadKind = iota + 1
	uploadData
	uploadURLEncode
)

// runsAsCurl reports whether any reading of a command's name is curl: the
// program, with or without a directory and `.exe`.
func runsAsCurl(c *rawCommand) bool {
	if c.name == "" || c.name == facts.Dynamic {
		return false
	}
	name, alts := canonical(c.name)
	for _, n := range append([]string{name}, alts...) {
		if exeName(n) == "curl" {
			return true
		}
	}
	return false
}

// uploadFiles maps an element index of a curl command to the file its value
// uploads, as written. Nothing for any other command.
func uploadFiles(c *rawCommand) map[int]string {
	if !runsAsCurl(c) {
		return nil
	}
	var out map[int]string
	add := func(i int, file string) {
		if file == "" || file == "-" { // `@-` reads stdin
			return
		}
		if out == nil {
			out = map[int]string{}
		}
		out[i] = file
	}
	for i := 0; i < len(c.elems); i++ {
		word, ok := elementWord(c.elems[i])
		if !ok {
			continue
		}
		if kind, ok := curlUploadOptions[word]; ok {
			if i+1 < len(c.elems) {
				if v, ok := argumentText(c.elems[i+1]); ok {
					add(i+1, uploadFile(kind, v))
					i++
				}
			}
			continue
		}
		// an option word: --data=@<file>, --form=name=@<file>
		if opt, v, ok := strings.Cut(word, "="); ok && strings.HasPrefix(opt, "--") {
			if kind, ok := curlUploadOptions[opt]; ok {
				add(i, uploadFile(kind, v))
			}
		}
	}
	return out
}

// elementWord is an element as curl receives it, for option matching: a
// parameter's name as written (`-F`, its case kept), or an argument's text.
// A parameter with an attached value (`-F:x`) is no option of curl's.
func elementWord(el element) (string, bool) {
	if el.param != "" {
		if el.hasVal {
			return "", false
		}
		name, _, _ := strings.Cut(el.raw, ":")
		return name, true
	}
	return argumentText(el)
}

// argumentText is an argument's literal text, when it has one.
func argumentText(el element) (string, bool) {
	if el.param != "" || !el.hasVal || el.verbatim || el.val.k != kStr {
		return "", false
	}
	return el.val.text, true
}

// uploadFile is the file an option's value names, as written, or "".
func uploadFile(kind uploadKind, v string) string {
	switch kind {
	case uploadForm:
		// name=@file[;type=…] uploads the file, name=<file sends its content
		_, rest, ok := strings.Cut(v, "=")
		if !ok || rest == "" || (rest[0] != '@' && rest[0] != '<') {
			return ""
		}
		file, _, _ := strings.Cut(rest[1:], ";")
		return file
	case uploadData:
		if strings.HasPrefix(v, "@") {
			return v[1:]
		}
	case uploadURLEncode:
		// @file, or name@file when no `=` comes first (curl's man page)
		at := strings.IndexByte(v, '@')
		if eq := strings.IndexByte(v, '='); at >= 0 && (eq < 0 || at < eq) {
			return v[at+1:]
		}
	}
	return ""
}
