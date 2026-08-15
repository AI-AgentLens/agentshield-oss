package shellparse

import (
	"path"
	"strings"
)

// Shell-source carriers: programs that take shell source as a flag VALUE or as
// a trailing POSITIONAL operand and hand it to a shell, rather than behind the
// `-c` of an interpreter (issue #3232).
//
// Why this is a distinct table from everything already here. AgentShield had
// three models of "this command runs another command", and none of them
// describes this shape:
//
//	ExecWrappers            the target is a COMMAND WORD in argv    (sudo rm -rf /)
//	PrivilegeShellCarriers  the target is a STRING behind -c        (su -c 'rm -rf /')
//	CodeInterpreters        the target is source in another language (python3 -c ...)
//
// A program like `man` takes neither. `man -P PAGER page` runs PAGER through
// the shell, so the pager string is shell source — but `man` is not a wrapper
// (the command does not follow it in argv), not a privilege carrier, and not an
// interpreter. It fell through all three.
//
// Measured over the 1830-command single-quote-free BLOCKing baseline, fifteen
// such programs leaked between 31.2% and 34.5%, against a 1.8% `bash -c`
// control and a 1.5% `sudo` control:
//
//	fzf --preview / watch / parallel / flock -c   34.5%
//	env -S 34.4%   tmux new-session 34.4%   xargs -I{} sh -c 34.2%
//	docker exec ... sh -c 34.1%   apt-get -o ...Pre-Invoke:: 33.9%
//	ssh host 'CMD' 33.7%   git -c core.pager 33.0%   zip -TT 32.7%
//	wget --use-askpass 32.2%   tar -I 31.6%   rsync -e 31.4%
//	man -P 31.2%  (and man -P leaked to ALLOW, not AUDIT — see below)
//
// Fifteen numbers inside a three-point band is the signature of ONE shared
// defect, not fifteen gaps: the payload never reaches a layer that can classify
// it. So this is one table and one parity sweep, not fifteen rules.
//
// `env -S` is the cautionary entry. wrapperValueFlags deliberately excluded it,
// with a comment saying its value "IS the command string, a different shape
// (inline code) that belongs to ExtractInlineCode". ExtractInlineCode had no
// env branch. That is #3223's lesson recurring inside the same file, one flag
// over: a comment that delegates to another component is a claim, and an
// unverified claim reads exactly like coverage. Both halves are now true — `-S`
// is in wrapperValueFlags so the operand walk skips it, and here so the value
// is decomposed.
//
// ## Populating this table: the FP/FN asymmetry is INVERTED versus wrapperValueFlags
//
// This is the one thing to get right before adding an entry. wrapperValueFlags
// fails toward a MISS in both directions, which is what made "omission is the
// safe default, guess if unsure" correct there. This table does not: a wrong
// entry makes AgentShield parse an ordinary DATA argument as shell source and
// evaluate every rule against it, which is a FALSE POSITIVE — the exact shape of
// #3224, where a grep PATTERN naming a protected path got treated as an access.
//
//	grep -e 'rm -rf /' file     if -e were listed, this SEARCH becomes a BLOCK
//
// So the rule for extending this table is stricter than the one next door:
// include a flag only when the program's own documentation says the value is
// executed, and prefer the flag that has no data-carrying reading at all. Every
// entry below is a documented exec path (most are catalogued GTFOBins escapes).
//
// Deliberately NOT here, and why:
//
//   - ssh -o ProxyCommand=, ssh -o LocalCommand=, git -c alias.x=!CMD,
//     git -c core.sshCommand=, gdb -ex, find -exec, tar --to-command,
//     vim -c ':!' — all measured 0.0-0.7%, i.e. already blocked by existing
//     rules on the invocation SHAPE. Adding them would buy nothing and would
//     put an FP-capable entry in the table for no detection.
//   - strace -o '|CMD' — the pipe-prefixed form is shell source, but plain
//     `-o FILE` is a filename and the two are told apart only by a leading `|`.
//     `-o` is already in wrapperValueFlags as a token to SKIP; listing it here
//     too would make the two tables contradict each other. Left open (19.9%).
//   - git -c KEY=CMD, apt-get -o KEY::=CMD — a KEYED shape: the value is
//     `KEY=SOURCE` and only some keys are source. That needs a per-key table,
//     not a per-flag one. Left open (33.0%), pinned as a negative control.
//   - xargs -I{} sh -c 'CMD', docker exec C sh -c 'CMD', tmux new-session -d
//     'CMD', ssh host 'CMD' — here the carrier is a nested `sh -c` (or a remote
//     shell) that is not in executable position. A different mechanism: "some
//     argument names a shell, and the rest is its source". Left open (33.7-34.4%),
//     pinned as negative controls.
//   - parallel ::: 'CMD' — GNU parallel's grammar puts the command TEMPLATE
//     before `:::` and DATA after it, and with no template the data items are
//     themselves commands. Modelling only one of those readings would be wrong
//     half the time in the FP direction. Left open (34.5%), negative control.
var shellSourceFlags = map[string]map[string]bool{
	// coreutils/util-linux
	"env":   setOf("-S", "--split-string"),
	"flock": setOf("-c", "--command"),
	"sort":  setOf("--compress-program"),
	// man(1) runs its pager via the shell. This one is worse than a miss: `man`
	// is on ts-allow-readonly's "read-only tool" prefix list, so the payload was
	// not merely unanalysed, the command was affirmatively decided ALLOW —
	// BELOW the AUDIT default. An allowlist keyed on a command NAME is only as
	// safe as that command's most dangerous flag.
	"man": setOf("-P", "--pager"),
	// GNU tar's -I/--use-compress-program executes PROG. bsdtar spells -I as a
	// synonym for -T (a file list), so on macOS the value is a filename — which
	// parses as a harmless unknown executable and fires nothing. The asymmetry
	// is safe in the direction that matters.
	"tar":   setOf("-I", "--use-compress-program"),
	"rsync": setOf("-e", "--rsh"),
	"zip":   setOf("-TT", "--unzip-command"),
	"wget":  setOf("--use-askpass"),
	"curl":  setOf("--use-askpass"),
	"fzf":   setOf("--preview"),
}

// shellSourcePositionalOpts lists the value-taking options of programs whose
// TRAILING OPERANDS are shell source — the positional half of this class.
//
// `watch -n1 'rm -rf /'` and `watch -n 1 rm -rf /` both hand the joined
// operands to `sh -c`, exactly as eval does with its argv (see evalCode). So
// the only thing needed to find where the source starts is which of the
// program's own options consume the token after them.
//
// watch's `-d/--differences` takes an OPTIONAL value, and only in the `=`
// spelling, so it must NOT be listed: treating `watch -d 'rm -rf /'` as
// "-d consumes the payload" would lose the source entirely.
var shellSourcePositionalOpts = map[string]map[string]bool{
	"watch": setOf("-n", "--interval"),
}

// lookupShellSource resolves a command word to its entry in either table,
// accepting an absolute or home-anchored path the way isExecWrapper does
// (`/usr/bin/man` is `man`). A relative `./man` is deliberately not resolved —
// far more likely a project script that shares the name.
func lookupShellSource(tbl map[string]map[string]bool, word string) (map[string]bool, bool) {
	name := NormalizeExecName(word)
	if v, ok := tbl[name]; ok {
		return v, true
	}
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "~/") {
		v, ok := tbl[path.Base(name)]
		return v, ok
	}
	return nil, false
}

// ShellSourceArg returns the shell source carried by words, or "" when words
// does not name a shell-source carrier. words[0] is the program.
//
// Flag-value form: the value of the first matching flag, in either spelling
// (`-P CMD`, `--pager CMD`, `--pager=CMD`). Only the FIRST match is returned;
// a second one would be a different fragment, and returning one string keeps
// this the same shape as every other ExtractInlineCode source.
//
// Positional form: every trailing operand from the first non-option token,
// joined with a single space — what a real `watch` hands to `sh -c`.
func ShellSourceArg(words []string) string {
	if len(words) == 0 {
		return ""
	}
	if flags, ok := lookupShellSource(shellSourceFlags, words[0]); ok {
		return shellSourceFlagValue(flags, words[1:])
	}
	if opts, ok := lookupShellSource(shellSourcePositionalOpts, words[0]); ok {
		return shellSourcePositional(opts, words[1:])
	}
	return ""
}

func shellSourceFlagValue(flags map[string]bool, rest []string) string {
	for i, w := range rest {
		if eq := strings.Index(w, "="); eq > 0 && flags[w[:eq]] {
			return w[eq+1:]
		}
		if flags[w] && i+1 < len(rest) {
			return rest[i+1]
		}
	}
	return ""
}

func shellSourcePositional(valueOpts map[string]bool, rest []string) string {
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		if w == "--" {
			if i+1 < len(rest) {
				return strings.Join(rest[i+1:], " ")
			}
			return ""
		}
		if strings.HasPrefix(w, "-") && len(w) > 1 {
			// A value-taking option consumes the NEXT token, but never the last
			// one — swallowing it would leave no source and silently turn a
			// carrier invocation into a benign-looking one. Same fail-safe as
			// wrapperTargetIndex.
			if valueOpts[w] {
				if i+2 > len(rest) {
					return ""
				}
				i++
			}
			continue
		}
		return strings.Join(rest[i:], " ")
	}
	return ""
}
