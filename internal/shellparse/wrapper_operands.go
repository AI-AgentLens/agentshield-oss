package shellparse

import (
	"path"
	"strings"
)

// Value-taking options of the execution wrappers in ExecWrappers — the ones
// that consume the FOLLOWING token as their value (issue #3221).
//
// Why this table has to exist. isWrapperOption models a wrapper's operands by
// token SHAPE alone: "starts with a dash, or is KEY=VALUE, or is numeric". That
// is a complete model only for a wrapper whose options are all boolean. The
// moment an option takes its value as a separate token, the shape model skips
// the option, sees the VALUE, decides it is not option-shaped, and hands it to
// the caller as the command being run:
//
//	sudo -u root rm -rf /   ->  Executable=="root", Args==["rm", "/"]
//
// Every downstream layer that reads the parsed executable — structural,
// semantic, dataflow, stateful — is then reasoning about a command named
// "root", and the `-rf` has been filed as flags of the wrong command, so even
// a flags_all rule cannot recover. Measured over the BLOCKing corpus this cost
// 21.3% (524/2460), against a 1.1% floor for the same wrappers with no
// value-taking flag — the control that isolates this from wrapper
// transparency itself, which works fine.
//
// What makes the class worth a table rather than a heuristic is that it is not
// obfuscation. `sudo -u postgres pg_dump`, `strace -o trace.log ./app`,
// `timeout -s KILL 30 ./job`, `env -u LD_PRELOAD prog` and `taskset -c 0-3
// ./bench` are the ordinary spellings of those commands. An attacker does not
// have to write anything that looks evasive, and an agent can wander into the
// blind spot by accident.
//
// Scope rules used when populating this, and worth keeping if you extend it:
//
//   - Only options whose value is a SEPARATE token. `-uroot` and `--user=root`
//     carry their own value and the existing shape model already handles them.
//   - When a short option is ambiguous across versions (sudo's `-h` is
//     --host in current sudo and help in older builds), LEAVE IT OUT. An
//     omission is the status quo — the pre-#3221 bypass for that one flag —
//     whereas a wrong entry skips a token too many and re-targets analysis
//     onto an argument. Both directions fail toward a miss rather than a false
//     positive, so accuracy here buys detection, not usability; that is the
//     trade that makes omission the safe default.
//   - env's `-S` IS here, and the reason it belongs is the opposite of the one
//     this line used to give. It said `-S` was "deliberately absent: its value
//     IS the command string, a different shape (inline code) that belongs to
//     ExtractInlineCode" — which had no env branch, so `env -S 'rm -rf /'`
//     belonged to nobody and leaked 34.4% of the BLOCKing corpus (#3232). It is
//     listed here so the operand walk SKIPS it (leaving `env` in executable
//     position instead of naming the payload string as the command) and in
//     shellSourceFlags so the value is decomposed. Both halves are now true.
//     A comment that delegates to another component is a claim; grep the
//     component before believing it (#3223).
var wrapperValueFlags = map[string]map[string]bool{
	"sudo": setOf("-u", "--user", "-g", "--group", "-p", "--prompt",
		"-C", "--close-from", "-D", "--chdir", "-R", "--chroot",
		"-r", "--role", "-t", "--type", "-T", "--command-timeout",
		"-U", "--other-user"),
	"doas": setOf("-u", "-C"),
	"env":  setOf("-u", "--unset", "-C", "--chdir", "-S", "--split-string"),
	"nice": setOf("-n", "--adjustment"),
	"ionice": setOf("-c", "--class", "-n", "--classdata", "-p", "--pid",
		"-P", "--pgid", "-u", "--uid"),
	"timeout": setOf("-s", "--signal", "-k", "--kill-after"),
	"stdbuf":  setOf("-i", "--input", "-o", "--output", "-e", "--error"),
	"strace": setOf("-o", "--output", "-e", "--trace", "-p", "--attach",
		"-s", "--string-limit", "-E", "--env", "-P", "--trace-path",
		"-u", "--user", "-a", "--columns", "-b", "--detach-on",
		"-I", "--interruptible", "-X", "--const-print-style",
		"-O", "--syscall-overhead", "-S", "--sort-by", "-U", "--columns-set"),
	"ltrace": setOf("-o", "--output", "-e", "-p", "--pid", "-s", "--string-size",
		"-l", "--library", "-x", "-n", "--indent", "-a", "--align", "-u"),
	"taskset": setOf("-c", "--cpu-list", "-p", "--pid"),
	"chrt": setOf("-p", "--pid", "-T", "--sched-runtime",
		"-P", "--sched-period", "-D", "--sched-deadline"),
	"systemd-run": setOf("-u", "--unit", "-p", "--property", "-M", "--machine",
		"-E", "--setenv", "--slice", "--description", "--uid", "--gid",
		"--nice", "--on-active", "--on-calendar", "--working-directory"),
	"caffeinate":   setOf("-t", "-w"),
	"arch":         setOf("-arch"),
	"exec":         setOf("-a"),
	"proxychains":  setOf("-f"),
	"proxychains4": setOf("-f"),
	"torsocks":     setOf("-u", "-p", "-a", "-P"),
	"torify":       setOf("-u", "-p", "-a", "-P"),
}

func setOf(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

// consumesNextToken reports whether tok, appearing among wrapper's options,
// takes the FOLLOWING token as its value.
//
// A token carrying its own value is excluded on both spellings a shell user
// has available: the attached short form (`-uroot`) is not a table key, and
// the long `--opt=value` form is rejected outright — otherwise `--setenv=A=B`
// would eat the command after it.
func consumesNextToken(wrapper, tok string) bool {
	if len(tok) < 2 || tok[0] != '-' || tok == "--" || strings.Contains(tok, "=") {
		return false
	}
	return wrapperValueFlags[wrapper][tok]
}

// wrapperTargetIndex returns the index into words at which the command a
// wrapper actually runs begins. words[0] must be the wrapper itself. A return
// of len(words) means the wrapper has no target and should stay the executable.
//
// Two departures from the plain isWrapperOption loop it replaces:
//
//   - A value-taking option consumes the token after it (the #3221 fix).
//   - A bare `--` ends option parsing, so the very next token is the command
//     whatever it looks like. Without this, `sudo -- -rf` style commands keep
//     skipping into the arguments; with it, the end-of-options marker means
//     what POSIX says it means.
//
// The fail-safe is the `i+2 > len(words)` guard: a value-taking option must
// never consume the last word. Doing so would leave no target and, worse,
// could make a wrapper invocation with no command look like one that has a
// benign command.
func wrapperTargetIndex(words []string) int {
	if len(words) == 0 {
		return 0
	}
	wrapper := path.Base(NormalizeExecName(words[0]))
	i := 1
	for i < len(words) {
		tok := words[i]
		if tok == "--" {
			return i + 1
		}
		if !isWrapperOption(tok) {
			return i
		}
		if consumesNextToken(wrapper, tok) {
			if i+2 > len(words) {
				return len(words) // would swallow the last word — refuse
			}
			i += 2
			continue
		}
		i++
	}
	return i
}
