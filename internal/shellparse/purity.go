package shellparse

import (
	"path"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// CommandLineIsPure reports whether every command in command is on a closed
// list of commands that never run their input as a program. It is the gate
// for the doc-text exemptions (#3798, Gary 2026-09-23, "strict purity"): the
// inertness labels (is_doc_text, in_heredoc, in_interpreter_heredoc) and the
// data-text positions (heredoc_body, quoted_program_arg,
// interp_heredoc_literal) apply only to a pure command line.
//
// # Why an allowlist here, when the rule is "only deny what you can justify"
//
// The exemptions used to be granted from statement SHAPE and withdrawn per
// known executor channel: pipe (#3797), write-then-execute (#3800), command
// substitution (#3814), indirect executors (#3798), executed substitution
// output (#3976). Each missed channel was a silent fail-open found only by
// adversarial review, one issue and one PR each, five times. That set is not
// enumerable. The set of commands that never run their input is: cat, echo,
// git commit, gh issue comment and a few dozen more. An unknown command
// voids the EXEMPTION, not the command: the rule that matched attack text
// still has to match for anything to block, so this changes which exceptions
// apply, never the basis for a denial.
//
// Measured before landing, on 4,594 real agent commands (3 days of the local
// audit log): stripping every exemption flips 30 to BLOCK, all in five shapes
// this list keeps (heredoc to a file, interpreter-heredoc literals, the commit
// idiom, gh --body, printf to a file). What the strict gate still costs is
// reported in the PR.
//
// # The closed list
//
//   - pureCommands: always pure (file and text utilities, git/gh read and
//     write subcommands handled separately below).
//   - git and gh: pure only for listed subcommands and without `git -c`
//     (which can set an alias or pager to a shell command).
//   - find, sed, awk: pure unless their arguments use the construct that
//     executes (-exec/-ok, the e command or s///e flag, system()/pipes).
//   - Code interpreters (python*, node, ruby, perl): pure only when the
//     program is a quoted heredoc on stdin that interpHeredocExecFree accepts
//     (the same exec-free analysis interp_heredoc_literal already uses). A nil
//     callback means interpreters are never pure.
//   - Anything else — shells, eval, source, exec, xargs, env/sudo/timeout and
//     other wrappers, build tools, a path to a script, a function defined in
//     the line, a command word with any expansion — is impure.
//
// A write into a git hooks directory (`.git/hooks/`, `.husky/`) is impure
// too: git runs those on commit, so writing one and committing executes it.
// So is a write into a shell/session startup file or an autorun cron/profile
// path (isAutoRunPath, #4039) — a shell sources `~/.zshenv` on every
// invocation with no execute statement in the command line at all, the same
// "deferred execution, no pipe, no explicit run" shape #3797/#3800/#3814/
// #3976 each closed for a synchronous channel. Unparseable input is impure
// (no exemption), the same fail-closed posture as the rest of the
// attribution code.
func CommandLineIsPure(command string, interpHeredocExecFree func(lang, body string) bool) bool {
	if strings.TrimSpace(command) == "" {
		return true
	}
	src := ifsNormalized(command)
	file := parseBashFile(src)
	if file == nil {
		return false
	}
	pure := true
	syntax.Walk(file, func(node syntax.Node) bool {
		if !pure {
			return false
		}
		switch n := node.(type) {
		case *syntax.FuncDecl, *syntax.CoprocClause:
			// A function defined in the line is a new command name nothing
			// here can vouch for; a coprocess runs asynchronously.
			pure = false
			return false
		case *syntax.Stmt:
			if stmtWritesDeferredExecTarget(n) {
				pure = false
				return false
			}
			if call, ok := n.Cmd.(*syntax.CallExpr); ok && len(call.Args) > 0 {
				if !callIsPure(src, n, call, interpHeredocExecFree) {
					pure = false
					return false
				}
			}
		}
		return true
	})
	return pure
}

var pureCommands = map[string]bool{
	// text in, text out
	"cat": true, "tee": true, "echo": true, "printf": true, "head": true, "tail": true,
	"wc": true, "sort": true, "uniq": true, "cut": true, "tr": true, "paste": true,
	"column": true, "grep": true, "egrep": true, "fgrep": true, "rg": true, "diff": true,
	"cmp": true, "comm": true, "jq": true, "base64": true, "xxd": true, "od": true,
	"hexdump": true, "shasum": true, "sha256sum": true, "md5": true, "md5sum": true,
	"cksum": true, "fold": true, "fmt": true, "nl": true, "rev": true, "tac": true,
	"expand": true, "unexpand": true, "strings": true,
	// filesystem, no execution
	"cd": true, "pwd": true, "pushd": true, "popd": true, "mkdir": true, "rmdir": true,
	"rm": true, "cp": true, "mv": true, "ln": true, "ls": true, "touch": true,
	"chmod": true, "stat": true, "file": true, "du": true, "df": true, "realpath": true,
	"readlink": true, "basename": true, "dirname": true, "mktemp": true, "tree": true,
	// shell builtins that never run text
	"true": true, "false": true, ":": true, "test": true, "[": true, "exit": true,
	"return": true, "set": true, "unset": true, "shift": true, "wait": true,
	"read": true, "mapfile": true, "readarray": true, "export": true, "local": true,
	"declare": true, "typeset": true, "readonly": true, "type": true, "which": true,
	"hash": true, "printenv": true,
	// time, identity and transport: they report or fetch data, never run it
	"date": true, "sleep": true, "curl": true, "wget": true, "whoami": true, "id": true,
	"hostname": true, "uname": true, "nproc": true, "arch": true, "groups": true,
}

var gitPureSubcommands = map[string]bool{
	"add": true, "commit": true, "status": true, "log": true, "diff": true, "show": true,
	"branch": true, "checkout": true, "switch": true, "restore": true, "reset": true,
	"fetch": true, "pull": true, "push": true, "rev-parse": true, "rev-list": true,
	"stash": true, "rm": true, "mv": true, "tag": true, "remote": true, "worktree": true,
	"merge-base": true, "ls-files": true, "ls-remote": true, "grep": true, "blame": true,
	"cherry-pick": true, "merge": true, "rebase": true, "describe": true, "shortlog": true,
	"clone": true, "init": true, "apply": true, "format-patch": true, "cat-file": true,
}

var ghPureSubcommands = map[string]bool{
	"issue": true, "pr": true, "api": true, "run": true, "repo": true, "release": true,
	"search": true, "label": true, "workflow": true, "auth": true, "browse": true,
	"gist": true, "status": true, "project": true, "secret": true, "variable": true,
}

var codeInterpreters = map[string]string{
	"python": "python", "python2": "python2", "python3": "python3",
	"node": "node", "ruby": "ruby", "perl": "perl",
}

var (
	// sed's `e` command at a command position, after an optional address.
	sedECmdRe = regexp.MustCompile(`(^|[;\n{}])\s*(\d+|\$|/(\\.|[^/\\])*/)?(\s*,\s*(\d+|\$|/(\\.|[^/\\])*/))?\s*!?\s*e(\s|;|$)`)
	// A `/`-delimited substitute command; group 3 is its flag set.
	sedSlashSubstRe = regexp.MustCompile(`s/(\\.|[^/\\\n])*/(\\.|[^/\\\n])*/([a-zA-Z0-9]*)`)
	// An s command with any other delimiter (`s|a|b|e`): Go's regexp has no
	// backreferences to find its flag set, so it is treated as impure.
	sedOtherDelimRe = regexp.MustCompile(`(^|[;\n{}]\s*)s[^/\sa-zA-Z0-9\\]`)
	// awk's system(), a pipe to or from a command, and a coprocess.
	awkExecRe = regexp.MustCompile(`\bsystem\s*\(|\|\s*getline|\|&|print[f]?\b[^;{}]*\|\s*"`)
)

// sedScripts returns sed's script arguments: every -e/--expression value, or
// the first operand when there is none. ok=false for -f (the script is a file
// this cannot read).
func sedScripts(args []string) (scripts []string, ok bool) {
	explicit := false
	for i := 0; i < len(args); i++ {
		w := args[i]
		switch {
		case w == "-f" || strings.HasPrefix(w, "--file"):
			return nil, false
		case w == "-e" || w == "--expression":
			explicit = true
			if i+1 < len(args) {
				scripts = append(scripts, args[i+1])
				i++
			}
		case strings.HasPrefix(w, "--expression="):
			explicit = true
			scripts = append(scripts, strings.TrimPrefix(w, "--expression="))
		}
	}
	if !explicit {
		for _, w := range args {
			if !strings.HasPrefix(w, "-") {
				return []string{w}, true
			}
		}
	}
	return scripts, true
}

func sedScriptExecutes(script string) bool {
	if sedECmdRe.MatchString(script) || sedOtherDelimRe.MatchString(script) {
		return true
	}
	for _, m := range sedSlashSubstRe.FindAllStringSubmatch(script, -1) {
		if strings.ContainsRune(m[3], 'e') {
			return true
		}
	}
	return false
}

func callIsPure(src string, stmt *syntax.Stmt, call *syntax.CallExpr, interpHeredocExecFree func(lang, body string) bool) bool {
	if !wordIsStatic(call.Args[0]) {
		return false // `$x`, `$(…)`, `` `…` ``: the program is whatever the expansion says
	}
	// Dequoted: a sed/awk script, a git subcommand or a find predicate is
	// judged by the value the program receives, not its quoted spelling.
	words := callWordsDequoted(call)
	name := path.Base(NormalizeExecName(words[0]))
	args := words[1:]
	if pureCommands[name] {
		if name == "tee" {
			for _, w := range args {
				if isDeferredExecTarget(w) {
					return false
				}
			}
		}
		return true
	}
	switch name {
	case "command":
		// `command -v x` is a lookup; `command x` runs x.
		return len(args) > 0 && (args[0] == "-v" || args[0] == "-V")
	case "git":
		sub := ""
		for i := 0; i < len(args); i++ {
			w := args[i]
			if w == "-c" || strings.HasPrefix(w, "-c") && len(w) > 2 && !strings.HasPrefix(w, "--") {
				return false // an inline config can point an alias or pager at a shell
			}
			if strings.HasPrefix(w, "--exec-path") || strings.HasPrefix(w, "--config-env") {
				return false
			}
			if w == "-C" || w == "--git-dir" || w == "--work-tree" || w == "--namespace" {
				i++
				continue
			}
			if strings.HasPrefix(w, "-") {
				continue
			}
			sub = w
			break
		}
		return gitPureSubcommands[sub]
	case "gh":
		return len(args) > 0 && ghPureSubcommands[args[0]]
	case "find":
		for _, w := range args {
			switch w {
			case "-exec", "-execdir", "-ok", "-okdir":
				return false
			}
		}
		return true
	case "sed", "gsed":
		scripts, ok := sedScripts(args)
		if !ok {
			return false
		}
		for _, sc := range scripts {
			if sedScriptExecutes(sc) {
				return false
			}
		}
		return true
	case "awk", "gawk", "mawk", "nawk":
		for _, w := range args {
			if w == "-f" || awkExecRe.MatchString(w) {
				return false
			}
		}
		return true
	}
	if lang, ok := codeInterpreters[name]; ok && interpHeredocExecFree != nil {
		return interpreterHeredocIsPure(src, stmt, lang, args, interpHeredocExecFree)
	}
	return false
}

// interpreterHeredocIsPure: `python3 - <<'PY' … PY` (optionally with plain
// argv operands after the `-`) whose quoted body the exec-free analysis
// accepts. Any inline-program flag, a script operand, or more than one
// heredoc is impure.
func interpreterHeredocIsPure(src string, stmt *syntax.Stmt, lang string, args []string, execFree func(lang, body string) bool) bool {
	if len(args) > 0 && args[0] != "-" {
		return false // a script path or an option: the program is not the heredoc
	}
	var body string
	heredocs := 0
	for _, r := range stmt.Redirs {
		switch r.Op {
		case syntax.Hdoc, syntax.DashHdoc:
			heredocs++
			// An unquoted delimiter expands $(…) and $x inside the body; a body
			// with no expansion in it is the same program either way.
			if r.Hdoc == nil || !wordIsStatic(r.Word) || (!heredocDelimiterQuoted(r.Word) && !wordIsStatic(r.Hdoc)) {
				return false
			}
			from, to := int(r.Hdoc.Pos().Offset()), int(r.Hdoc.End().Offset())
			if from < 0 || to > len(src) || from > to {
				return false
			}
			body = src[from:to]
		case syntax.WordHdoc:
			return false
		}
	}
	return heredocs == 1 && execFree(lang, body)
}

func heredocDelimiterQuoted(w *syntax.Word) bool {
	for _, p := range w.Parts {
		switch p.(type) {
		case *syntax.SglQuoted, *syntax.DblQuoted:
			return true
		}
	}
	return false
}

// wordIsStatic reports whether w is literal text: no parameter, command,
// process or arithmetic expansion anywhere in it.
func wordIsStatic(w *syntax.Word) bool {
	static := true
	syntax.Walk(w, func(n syntax.Node) bool {
		switch n.(type) {
		case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ArithmExp, *syntax.ExtGlob:
			static = false
		}
		return static
	})
	return static
}

func stmtWritesDeferredExecTarget(stmt *syntax.Stmt) bool {
	for _, r := range stmt.Redirs {
		switch r.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.ClbOut:
			if r.Word != nil && isDeferredExecTarget(WordToString(r.Word)) {
				return true
			}
		}
	}
	return false
}

// isDeferredExecTarget reports whether p is a path a later, unrelated event
// — a commit, a new shell, a login, a cron tick — runs without the command
// line itself containing an execute statement.
func isDeferredExecTarget(p string) bool {
	return isHookPath(p) || isAutoRunPath(p)
}

func isHookPath(p string) bool {
	return strings.Contains(p, ".git/hooks/") || strings.Contains(p, ".husky/")
}

// autoRunBasenames are interactive-shell and session startup files a shell
// or session manager sources on its own — no pipe, no explicit `bash`/
// `source`, no execute statement anywhere in the writing command. Matched on
// path.Base so `~/.zshenv`, `$HOME/.zshenv` and a bare `.zshenv` (cwd ==
// $HOME) all match, and a same-family non-startup name like `.bashrc.bak`
// does not (#4039 — deliberately narrower than a substring match, unlike
// isHookPath, to keep this closed list from swallowing editor backups).
var autoRunBasenames = map[string]bool{
	".zshenv": true, ".zshrc": true, ".zprofile": true, ".zlogin": true,
	".bashrc": true, ".bash_profile": true, ".bash_login": true, ".profile": true,
	".kshrc": true, ".cshrc": true, ".tcshrc": true,
	".pam_environment": true, ".xprofile": true, ".xinitrc": true,
}

// isAutoRunPath extends isHookPath to shell/session startup files and the
// cron/profile.d autorun directories (#4039). Scope is deliberately limited
// to paths whose write-then-nothing-else already executes on a real system:
// systemd EnvironmentFile= and launchd plists are left out because writing
// one is a configuration change a service manager parses, not a shell
// sourcing the bytes as commands — a different mechanism, tracked as a
// residual rather than folded in here.
func isAutoRunPath(p string) bool {
	if autoRunBasenames[path.Base(p)] {
		return true
	}
	if strings.HasSuffix(p, "/.config/fish/config.fish") || p == ".config/fish/config.fish" {
		return true
	}
	if p == "/etc/profile" || p == "/etc/environment" {
		return true
	}
	for _, prefix := range []string{
		"/etc/profile.d/",
		"/etc/cron.d/", "/etc/cron.hourly/", "/etc/cron.daily/",
		"/etc/cron.weekly/", "/etc/cron.monthly/",
		"/var/spool/cron/",
	} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return p == "/etc/crontab"
}
