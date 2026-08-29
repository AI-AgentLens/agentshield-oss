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

	// Added with wrapperPositionalOperands (#3227).
	"pkexec":  setOf("-u", "--user"),
	"runuser": setOf("-u", "--user", "-g", "--group", "-G", "--supp-group", "-s", "--shell"),
	"setpriv": setOf("--reuid", "--regid", "--groups", "--inh-caps",
		"--ambient-caps", "--bounding-set", "--securebits", "--pdeathsig",
		"--selinux-label", "--apparmor-profile", "--landlock-access",
		"--landlock-rule", "--reset-env-name"),
	"aa-exec": setOf("-p", "--profile", "-n", "--namespace"),
	"chroot":  setOf("--userspec", "--groups"),
	// flock's `-c` is listed so the operand walk SKIPS it rather than naming
	// its value as the command. The value is a shell string run through
	// `/bin/sh -c`, i.e. an inline-code carrier — the same shape env's `-S`
	// is excluded for, and decomposing it belongs to ExtractInlineCode, not
	// here. Tracked in #3227.
	"flock": setOf("-w", "--timeout", "-E", "--conflict-exit-code",
		"-c", "--command"),
}

// Wrappers that take a fixed number of bare POSITIONAL operands between their
// options and the command they run (issue #3227).
//
// Why the flag table alone was not enough. wrapperValueFlags (#3221) taught the
// operand walk that an option can consume the next token. It still assumed the
// first token that is neither an option nor an option's value IS the command.
// That is false for a whole family of wrappers whose grammar puts a bare
// operand first:
//
//	flock /var/lock/deploy.lock rm -rf /   ->  Executable=="/var/lock/deploy.lock"
//	chroot /mnt/rootfs rm -rf /            ->  Executable=="/mnt/rootfs"
//
// This is the same defect #3221 fixed, one shape further out, and it was
// already known: the ExecWrappers table excluded flock in a comment saying the
// flag-only operand model "would mis-target the first path as the command".
// The exclusion was correct at the time; it is what this table removes.
//
// The measured cost is not per-wrapper. Every execution wrapper absent from
// ExecWrappers leaks the SAME ~22% of the BLOCKing corpus (549/2486 for flock,
// chroot, setarch, busybox, setpriv, valgrind, linux64, toybox and aa-exec
// alike, against a 1.1% floor for wrappers already in the table). Fifteen
// measurements inside 0.7% of each other are one shared defect — a command
// displaced from the executable position reaches no layer that can classify it
// — not fifteen gaps. So the fix is the operand model plus table entries, and
// the parity sweep asserts the whole family together.
//
// Populating rules, in addition to the ones on wrapperValueFlags:
//
//   - Count only operands that are ALWAYS present when a command follows.
//     An optional one is safe anyway (see the guard below), but a count that
//     is too high on the common spelling silently re-targets analysis onto an
//     argument.
//   - The count is bare operands, not tokens: options and their values are
//     consumed by the existing walk before any of these are counted, so
//     `flock -w 5 /tmp/x rm -rf /` needs the same 1 as `flock /tmp/x rm -rf /`.
//
// The optional-operand case falls out of the existing "must leave a target"
// guard rather than needing its own rule. `setarch --addr-no-randomize ./prog`
// omits the arch, so the walk consumes `./prog` as the positional, finds
// nothing after it, and returns len(words) — the wrapper stays the executable,
// exactly as it does today. `setarch x86_64 -R ./prog` consumes the arch, skips
// the option, and correctly targets `./prog`.
var wrapperPositionalOperands = map[string]int{
	"flock":   1, // lockfile or directory to lock
	"chroot":  1, // NEWROOT
	"setarch": 1, // ARCH (optional in modern util-linux — see above)
}

// carriesInlineCodeFlag reports whether a privilege carrier's operands include
// the flag whose value is shell SOURCE rather than a command word.
//
// This is the gate that lets `runuser` be an ExecWrapper at all. Its two
// invocation forms need opposite handling and only the flags distinguish them:
//
//	runuser -u root -- rm -rf /      unwrap: `rm` is a command word
//	runuser -u root -c 'rm -rf /'    do NOT unwrap: the payload is a STRING
//
// Unwrapping the second would name the whole quoted script as an executable and
// take it away from PrivilegeShellCarriers (#3223), which decomposes it
// properly. Refusing costs nothing: not unwrapping is the pre-#3227 status quo
// for that spelling, and the inline-code path was already handling it.
//
// The `=` check mirrors consumesNextToken: `--command=X` still carries source,
// so the prefix match must catch it, but a bare `-c` at the end of the operands
// is enough on its own.
//
// The scan MUST stop at the first token that is not one of the wrapper's own
// options — otherwise `-c` belonging to the WRAPPED command (not the wrapper)
// reads as the wrapper's own inline-code flag. `runuser -u root taskset -c 0
// chmod -R 777 /usr` has no `-c` of runuser's own; taskset's `-c` sits inside
// the command being run. Scanning past the option region into that command
// found this: measured on the corpus, 12 commands that should unwrap through
// runuser instead stayed wrapped because a later, unrelated tool's `-c`
// (taskset, script, python3, frpc, wfuzz, chrpath, pass, bloodhound-python -
// all take a bare `-c`) was mistaken for runuser's own.
//
// One exception to "stop at the first non-option token": runuser's OTHER
// invocation form omits `-u` entirely and names the user positionally —
// `runuser root -c 'CMD'` (pinned by TestPrivilegeCarrierInlineCode's
// "runuser positional" case, #3223, predating this file). "root" there is
// runuser's own operand, not the wrapped command, so the scan must look past
// exactly one bare token before concluding the wrapped command has started —
// but only when no `-u`/`-g`/`-G` flag already supplied the user. Once one of
// those has been consumed, runuser's grammar has no second, positional way to
// name the user, so the next bare token can only be the wrapped command
// (`runuser -u root taskset ...` must NOT re-apply this exception, or it
// regresses right back into reading taskset's `-c` as runuser's own).
func carriesInlineCodeFlag(words []string) bool {
	if len(words) == 0 {
		return false
	}
	wrapper := path.Base(NormalizeExecName(words[0]))
	userFlagSeen := false
	skippedPositionalUser := false
	i := 1
	for i < len(words) {
		tok := words[i]
		if tok == "--" {
			return false // end of options reached with no -c seen
		}
		switch {
		case tok == "-c" || tok == "--command" || tok == "--session-command":
			return true
		case strings.HasPrefix(tok, "--command=") || strings.HasPrefix(tok, "--session-command="):
			return true
		}
		if isWrapperOption(tok) {
			switch tok {
			case "-u", "--user", "-g", "--group", "-G", "--supp-group":
				userFlagSeen = true
			}
			if consumesNextToken(wrapper, tok) {
				i += 2
				continue
			}
			i++
			continue
		}
		if wrapper == "runuser" && !userFlagSeen && !skippedPositionalUser {
			skippedPositionalUser = true
			i++
			continue
		}
		return false // reached the wrapped command; nothing before it was -c
	}
	return false
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
// Three departures from the plain isWrapperOption loop it replaces:
//
//   - A value-taking option consumes the token after it (the #3221 fix).
//   - A bare `--` ends option parsing, so a following token is the command
//     whatever it looks like. Without this, `sudo -- -rf` style commands keep
//     skipping into the arguments; with it, the end-of-options marker means
//     what POSIX says it means.
//   - A wrapper with positional operands consumes that many bare words before
//     the command (the #3227 fix).
//
// `--` ends OPTION parsing, not operand parsing, so positional consumption
// continues past it: `flock -- /tmp/x rm -rf /` still locks /tmp/x and runs rm.
// For the wrappers that have no positionals — every entry that predates #3227 —
// this is identical to the old `return i + 1`.
//
// Two guards, both failing the same safe direction. A value-taking option must
// never consume the last word (`i+2 > len(words)`), and a positional operand
// must leave something behind to be the command: both return len(words), which
// callers read as "no target, keep the wrapper as the executable". Losing the
// target would be worse than not unwrapping, because a wrapper invocation with
// no command would start looking like one with a benign command.
func wrapperTargetIndex(words []string) int {
	if len(words) == 0 {
		return 0
	}
	wrapper := path.Base(NormalizeExecName(words[0]))
	if PrivilegeShellCarriers[wrapper] && carriesInlineCodeFlag(words) {
		return len(words)
	}
	positionals := wrapperPositionalOperands[wrapper]
	endOfOpts := false
	i := 1
	for i < len(words) {
		tok := words[i]
		if !endOfOpts {
			if tok == "--" {
				endOfOpts = true
				i++
				continue
			}
			if isWrapperOption(tok) {
				if consumesNextToken(wrapper, tok) {
					if i+2 > len(words) {
						return len(words) // would swallow the last word — refuse
					}
					i += 2
					continue
				}
				i++
				continue
			}
		}
		if positionals > 0 {
			if i+2 > len(words) {
				return len(words) // no command would be left — refuse
			}
			positionals--
			i++
			continue
		}
		return i
	}
	return i
}
