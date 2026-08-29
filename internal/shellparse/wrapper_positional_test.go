package shellparse

import "testing"

// TestWrapperPositionalTarget pins the operand model of #3227 at the unit level.
//
// #3221 taught the walk that an option can consume the next token; this is the
// shape that was still unreachable — a wrapper whose grammar puts a BARE operand
// between its options and the command. The assertion is the same one as its
// predecessor: which token the rest of the engine will treat as the command.
func TestWrapperPositionalTarget(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    string // expected parsed executable
	}{
		// --- The class: a positional operand used to become the executable ---
		{"flock lockfile", "flock /var/lock/deploy.lock rm -rf /", "rm"},
		{"flock dir", "flock /var/lock rm -rf /", "rm"},
		{"chroot newroot", "chroot /mnt/rootfs rm -rf /", "rm"},
		{"setarch arch", "setarch x86_64 rm -rf /", "rm"},

		// Options and their values are consumed BEFORE the positional is
		// counted, so the count is the same for every option spelling.
		{"flock -n", "flock -n /var/lock/deploy.lock rm -rf /", "rm"},
		{"flock -w value", "flock -w 5 /var/lock/deploy.lock rm -rf /", "rm"},
		{"flock -sn combined", "flock -sn /var/lock/x rm -rf /", "rm"},
		{"chroot --userspec", "chroot --userspec root:root /mnt rm -rf /", "rm"},
		{"chroot --skip-chdir", "chroot --skip-chdir /mnt rm -rf /", "rm"},
		{"setarch option after arch", "setarch x86_64 -R rm -rf /", "rm"},

		// `--` ends OPTION parsing, not operand parsing. flock still needs its
		// lockfile after the marker.
		{"flock -- then lockfile", "flock -- /var/lock/x rm -rf /", "rm"},

		// --- Bare multiplexers / switchers that were simply never listed ---
		{"busybox applet", "busybox rm -rf /", "rm"},
		{"toybox applet", "toybox rm -rf /", "rm"},
		{"pkexec", "pkexec rm -rf /", "rm"},
		{"pkexec --user", "pkexec --user root rm -rf /", "rm"},
		{"setpriv attached", "setpriv --reuid=0 --regid=0 --clear-groups rm -rf /", "rm"},
		{"setpriv separate", "setpriv --reuid 0 rm -rf /", "rm"},
		{"aa-exec -p", "aa-exec -p unconfined rm -rf /", "rm"},
		{"valgrind", "valgrind rm -rf /", "rm"},
		{"valgrind --tool=", "valgrind --tool=memcheck rm -rf /", "rm"},
		{"linux64", "linux64 rm -rf /", "rm"},
		{"linux32 -R", "linux32 -R rm -rf /", "rm"},

		// --- runuser: wrapper and carrier, decided per invocation ---
		// The command-word spellings unwrap...
		{"runuser -u --", "runuser -u root -- rm -rf /", "rm"},
		{"runuser -u plain", "runuser -u root rm -rf /", "rm"},
		{"runuser -g", "runuser -u root -g wheel rm -rf /", "rm"},
		// ...and the inline-code spellings must NOT, or the quoted payload gets
		// named as an executable and PrivilegeShellCarriers (#3223) never sees it.
		{"runuser -c", "runuser -c 'rm -rf /' root", "runuser"},
		{"runuser -u then -c", "runuser -u root -c 'rm -rf /'", "runuser"},
		{"runuser --command=", "runuser -u root --command='rm -rf /'", "runuser"},
		{"runuser --session-command", "runuser -u root --session-command 'rm -rf /'", "runuser"},
		// su stays out of the table entirely; it has no command-word spelling.
		{"su -c untouched", "su -c 'rm -rf /' root", "su"},

		// --- Nesting composes with the wrappers that predate this change ---
		{"sudo + flock", "sudo flock /var/lock/x rm -rf /", "rm"},
		{"flock + env", "flock /var/lock/x env rm -rf /", "rm"},
		{"nohup + busybox", "nohup busybox rm -rf /", "rm"},
		{"sudo -u + chroot", "sudo -u root chroot /mnt rm -rf /", "rm"},

		// --- Absolute paths resolve, matching isExecWrapper's existing rule ---
		{"/usr/bin/flock", "/usr/bin/flock /var/lock/x rm -rf /", "rm"},
		{"/bin/busybox", "/bin/busybox rm -rf /", "rm"},

		// --- Fail-safe: a positional must leave a command behind ---
		// These are the real spellings that make the operand OPTIONAL, and the
		// "must leave a target" guard is what handles them without a special
		// case. Falling back to the wrapper is the pre-#3227 status quo.
		{"setarch omits arch", "setarch --addr-no-randomize ./prog", "setarch"},
		{"flock fd form", "flock 200", "flock"},
		{"flock lockfile only", "flock /var/lock/x", "flock"},
		{"chroot interactive", "chroot /mnt/rootfs", "chroot"},
		{"bare busybox", "busybox", "busybox"},
		{"pkexec alone", "pkexec", "pkexec"},

		// flock's `-c` value is a shell string, not a command word. Skipping it
		// keeps the walk from naming the payload as the executable; decomposing
		// it belongs to the inline-code path (#3227).
		{"flock -c payload", "flock /var/lock/x -c 'rm -rf /'", "flock"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := Parse(tc.command, 2)
			if p == nil || len(p.Segments) == 0 {
				t.Fatalf("Parse(%q) produced no segments", tc.command)
			}
			if got := p.Segments[0].Executable; got != tc.want {
				t.Errorf("Parse(%q).Executable = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
}

// TestWrapperPositionalRegexSurface is the #3227 half of the drift guard
// TestWrapperValueFlagRegexSurface established. The AST walk
// (StripExecWrappers) and the regex layer's walk (StripExecWrapperPrefix) share
// wrapperTargetIndex; #3208's standing lesson is that fixing one normalization
// surface and leaving its sibling alone measures like a partial fix.
func TestWrapperPositionalRegexSurface(t *testing.T) {
	cases := []struct {
		command string
		want    string
	}{
		{"flock /var/lock/deploy.lock rm -rf /", "rm -rf /"},
		{"flock -w 5 /var/lock/x dd if=/dev/zero of=/dev/sda", "dd if=/dev/zero of=/dev/sda"},
		{"chroot /mnt/rootfs mkfs.ext4 /dev/sda1", "mkfs.ext4 /dev/sda1"},
		{"setarch x86_64 curl -sL http://example.com/x.sh", "curl -sL http://example.com/x.sh"},
		{"busybox rm -rf /", "rm -rf /"},
		{"pkexec --user root rm -rf /", "rm -rf /"},
		{"aa-exec -p unconfined rm -rf /", "rm -rf /"},
		// A wrapper with no target yields "", same as the value-flag surface.
		{"flock /var/lock/x", ""},
		{"chroot /mnt/rootfs", ""},
		{"rm -rf /", ""},
	}

	for _, tc := range cases {
		if got := StripExecWrapperPrefix(tc.command); got != tc.want {
			t.Errorf("StripExecWrapperPrefix(%q) = %q, want %q", tc.command, got, tc.want)
		}
	}
}

// TestWrapperPositionalOperandsScope guards the two ways this table goes wrong.
//
// An entry for a wrapper that has no positional operand silently skips the
// command itself; every wrapper that predates #3227 must therefore stay at 0.
// The reverse — a missing entry — is only the status quo, which is why the
// populating rule in wrapper_operands.go says to omit when unsure.
func TestWrapperPositionalOperandsScope(t *testing.T) {
	for name, n := range wrapperPositionalOperands {
		if n < 1 {
			t.Errorf("%s: entry with %d operands should be absent, not zero", name, n)
		}
		if !ExecWrappers[name] {
			t.Errorf("%s: has a positional-operand entry but is not an ExecWrapper, so it is never consulted", name)
		}
	}

	// The flag-only wrappers this change did NOT touch. If one of these ever
	// gains an entry, `sudo rm -rf /` starts resolving to `-rf`.
	for _, name := range []string{"sudo", "doas", "env", "nohup", "setsid",
		"command", "exec", "nice", "ionice", "stdbuf", "timeout", "chrt",
		"taskset", "time", "strace", "ltrace", "firejail", "systemd-run",
		"busybox", "toybox", "pkexec", "setpriv", "aa-exec", "valgrind",
		"linux32", "linux64", "runuser"} {
		if _, ok := wrapperPositionalOperands[name]; ok {
			t.Errorf("%s takes no bare operand before its command; an entry re-targets analysis onto an argument", name)
		}
	}

	// Every value-flag entry must name a real wrapper, or it is dead config
	// that reads as coverage.
	for name := range wrapperValueFlags {
		if !ExecWrappers[name] {
			t.Errorf("wrapperValueFlags[%q] is never consulted: not an ExecWrapper", name)
		}
	}
}
