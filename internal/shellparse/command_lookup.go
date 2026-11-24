package shellparse

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// # What a command NAME means (#5092)
//
// The doc-text exemptions trust a command by its name: `cat` copies its
// stdin, so a heredoc body fed to `cat` is data. That holds only while the
// name means the program the shell finds by default. A shell resolves a
// command word in a fixed order — function, alias, builtin, hash table, then
// a search of PATH (bash(1) and zshmisc(1), "COMMAND EXECUTION") — and a word
// that contains a slash names a file directly. The MECHANISMS by which one
// line can change what `cat` means are therefore few, and this file refuses
// these spellings of them:
//
//   - The command word contains a slash (commandWordNamesUntrustedFile):
//     `/tmp/cat`, `./cat`, `~/bin/cat`. The line names a file, and nothing
//     vouches for what the file is.
//   - A function or alias is defined. Purity already refuses both: a FuncDecl
//     is impure, and alias/unalias/functions/autoload/enable are not on the
//     pure list.
//   - The hash table is written: `hash` with anything but `-r`
//     (pureHashCall), bash's BASH_CMDS[…]= and zsh's commands[…]=.
//   - The search path changes: any assignment to PATH, zsh's path or bash's
//     EXECIGNORE, in any spelling (lineRebindsCommandLookup), or
//     read/mapfile/readarray/unset naming one (bindsLookupParam).
//   - zsh's parameter tables are written: functions, aliases, galiases,
//     saliases, commands.
//
// Every entry was run in bash 3.2, bash 5.3 and zsh 5.9 with a harmless body
// before it went in (the #5092 PR has the table).
//
// # Not a complete list of spellings (#5104, adversarial pass 1)
//
// The mechanisms are few, but their SPELLINGS are not closed. Known open,
// each found by pass 1 and executing in bash or zsh:
//
//   - PATH written outside an assignment node: `for PATH in`, `let PATH=0`,
//     `((PATH=0))`, `$((PATH=0))`, `[[ 1 -eq PATH=0 ]]`, `x[PATH=0]=1`, zsh
//     `set -A path`, bash `set -k`, bash 5.1+ `wait -p PATH`;
//   - a sink word the shell reads differently from NormalizeExecName:
//     `"\/bin/cat"`, `'"/bin/cat'`, `'=/bin/cat'`, bash `=/bin/cat` (each a
//     cwd-relative file), and zsh `$"/bin/cat"`.
//
// So this only removes exemptions; it never establishes that a name is the
// program. A narrowing must not rely on it as a guarantee: that is why #5092's
// mirror of heredoc_body onto ts-block-agentshield-log-truncate was dropped.
// The exemptions it gates were already open to these spellings on main.
//
// # The residual, on purpose
//
// A shell finds `cat` by searching PATH's DIRECTORIES, so a program named
// `cat` placed in a directory that comes before /bin (on a stock Homebrew Mac,
// /opt/homebrew/bin) changes what the bare name means without anything in this
// list. That can happen in an earlier tool call, where no line-level gate can
// see it (the same two-call residual as MessageSlotsSurviveImpureLine), or on
// the same line through any write: a link, a copy, or a redirect through an
// existing symlink. File names can be computed, so the same-line half is not
// enumerable either. TestCommandLookupResidual pins it.

// lookupParams are the parameters whose value decides what a bare command
// name resolves to.
var lookupParams = map[string]bool{
	"PATH":         true, // the search path
	"path":         true, // zsh: the array tied to PATH
	"EXECIGNORE":   true, // bash 4.4+: executables the PATH search skips
	"BASH_CMDS":    true, // bash 4+: the hash table as an associative array
	"BASH_ALIASES": true, // bash 4+: the alias table
	// zsh/parameter: writing a key defines the function, alias or hash entry.
	"functions": true, "aliases": true, "galiases": true, "saliases": true, "commands": true,
}

// systemCommandDirs hold the programs a bare name resolves to by default and
// that a non-root process cannot replace: root-owned on Linux, and on macOS
// the signed read-only system volume. `/usr/bin/cat` names the same program a
// bare `cat` would, with less room for a stand-in, so it stays trusted.
// /usr/local/bin and /opt/homebrew/bin are user-writable on a stock Homebrew
// Mac, so they are not here.
var systemCommandDirs = map[string]bool{"/bin": true, "/usr/bin": true}

// commandWordNamesUntrustedFile reports whether word, a command word with
// shell quoting removed, names a program file directly (it contains a slash)
// anywhere but a system command directory. A spelling path.Clean would change
// (`/bin/../tmp/cat`, `/usr/bin//cat`) is not trusted either.
func commandWordNamesUntrustedFile(word string) bool {
	if !strings.Contains(word, "/") {
		return false
	}
	return path.Clean(word) != word || !systemCommandDirs[path.Dir(word)]
}

// lookupParamName returns the parameter an assignment-shaped word writes:
// `PATH=/x`, `PATH+=/x`, `functions[cat]=sh`, or a bare `PATH` (a
// declaration with no value, or a read/unset operand). It strips an index
// and the `+` of an append.
func lookupParamName(word string) string {
	name, _, _ := strings.Cut(word, "=")
	name = strings.TrimSuffix(name, "+")
	name, _, _ = strings.Cut(name, "[")
	return name
}

// lineRebindsCommandLookup reports whether an assignment or declaration
// anywhere in file can change what a bare command name resolves to: it
// writes a lookup parameter, declares a nameref (whose writes land on another
// name), or declares a name only known at run time (`export "$v=/x"`).
func lineRebindsCommandLookup(file *syntax.File) bool {
	rebinds := false
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.Assign:
			if assignRebindsLookup(n) {
				rebinds = true
			}
		case *syntax.DeclClause:
			if declaresNameref(n) {
				rebinds = true
			}
		}
		return !rebinds
	})
	return rebinds
}

func assignRebindsLookup(a *syntax.Assign) bool {
	if a.Name != nil {
		return lookupParams[a.Name.Value]
	}
	if !a.Naked || a.Value == nil {
		return false
	}
	// A declaration argument with no parsed name: `export 'PATH=/x'`, an
	// option such as -x, `export "FOO=$v"`, or a computed `export "$v=/x"`.
	prefix := leadingLiteral(a.Value)
	if strings.HasPrefix(prefix, "-") || strings.HasPrefix(prefix, "+") {
		return false // an option; namerefs are declaresNameref's
	}
	name, _, named := strings.Cut(prefix, "=")
	if !named {
		if _, whole := literalWordValue(a.Value); !whole {
			return true // the name is decided at run time
		}
	}
	return lookupParams[lookupParamName(name)]
}

// leadingLiteral returns the literal text w starts with, up to its first
// expansion, with quotes removed.
func leadingLiteral(w *syntax.Word) string {
	var sb strings.Builder
	for _, p := range w.Parts {
		switch part := p.(type) {
		case *syntax.Lit:
			sb.WriteString(part.Value)
		case *syntax.SglQuoted:
			sb.WriteString(part.Value)
		case *syntax.DblQuoted:
			for _, dp := range part.Parts {
				lit, ok := dp.(*syntax.Lit)
				if !ok {
					return sb.String()
				}
				sb.WriteString(lit.Value)
			}
		default:
			return sb.String()
		}
	}
	return sb.String()
}

// declaresNameref: `declare -n r=PATH; r=/x` writes PATH through r (bash
// 4.3+, zsh 5.10+). Any -n among a declare/typeset/local's options counts.
func declaresNameref(d *syntax.DeclClause) bool {
	if d.Variant == nil {
		return false
	}
	switch d.Variant.Value {
	case "nameref":
		return true
	case "declare", "typeset", "local":
	default:
		return false
	}
	for _, a := range d.Args {
		if a.Name != nil || !a.Naked || a.Value == nil {
			continue
		}
		opt := leadingLiteral(a.Value)
		if !strings.HasPrefix(opt, "-") {
			continue
		}
		if _, whole := literalWordValue(a.Value); !whole || strings.ContainsRune(opt, 'n') {
			return true // -n, or an option spelled at run time
		}
	}
	return false
}

// sinkWordsRebindLookup reports whether the words of a heredoc's statement up
// to and including its sink (exec wrappers, their operands, the sink itself)
// name a program by file or set the search path, so the sink's name cannot
// vouch for it: `/tmp/e/cat`, `/tmp/e/nohup cat`, `env PATH=/tmp/e cat`,
// `chroot /x cat`. An operand with a slash counts too: it costs nothing,
// because every wrapper is impure on its own.
func sinkWordsRebindLookup(words []string) bool {
	for _, w := range words {
		w = NormalizeExecName(w)
		if commandWordNamesUntrustedFile(w) || (strings.Contains(w, "=") && lookupParams[lookupParamName(w)]) {
			return true
		}
	}
	return false
}

// pureHashCall: `hash` lists the table and `hash -r` empties it; anything
// else can write it (bash `hash -p FILE NAME`, zsh `hash NAME=FILE`) or is
// not worth telling apart from a write.
func pureHashCall(args []string) bool {
	for _, a := range args {
		if a != "-r" {
			return false
		}
	}
	return true
}

// bindsLookupParam reports whether a read/mapfile/readarray/unset call names
// a lookup parameter: `read -r PATH <<< /x` sets the search path, `unset
// PATH` makes bash search the current directory. An option bundle is
// checked by substring (`-aPATH` attaches the name), and an operand whose
// value is unknown here counts.
func bindsLookupParam(args []string) bool {
	for _, a := range args {
		if strings.ContainsAny(a, "$`") {
			return true
		}
		if strings.HasPrefix(a, "-") {
			for p := range lookupParams {
				if strings.Contains(a, p) {
					return true
				}
			}
			continue
		}
		if lookupParams[lookupParamName(a)] {
			return true
		}
	}
	return false
}
