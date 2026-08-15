package shellparse

import "testing"

// TestWrapperValueFlagTarget pins the operand model of #3221 at the unit level:
// which token a wrapper's options end at, and therefore which token the rest of
// the engine will treat as the command.
func TestWrapperValueFlagTarget(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    string // expected parsed executable
	}{
		// --- The class: a value-taking flag used to become the executable ---
		{"sudo -u", "sudo -u root rm -rf /", "rm"},
		{"sudo -g", "sudo -g wheel dd if=/dev/zero of=/dev/sda", "dd"},
		{"sudo -p prompt", "sudo -p Password: rm -rf /", "rm"},
		{"strace -o", "strace -o /tmp/t.log rm -rf /", "rm"},
		{"timeout -s", "timeout -s KILL 5 rm -rf /", "rm"},
		{"env -u", "env -u LD_PRELOAD rm -rf /", "rm"},
		{"taskset -c", "taskset -c 0-3 rm -rf /", "rm"},
		{"systemd-run -u", "systemd-run -u myjob rm -rf /", "rm"},
		{"stdbuf -o detached", "stdbuf -o L rm -rf /", "rm"},
		{"exec -a", "exec -a login rm -rf /", "rm"},

		// --- Spellings that already worked; they must keep working ---
		{"attached short value", "sudo -uroot rm -rf /", "rm"},
		{"long form with =", "sudo --user=root rm -rf /", "rm"},
		{"numeric operand", "nice -n 10 rm -rf /", "rm"},
		{"bare wrapper", "sudo rm -rf /", "rm"},
		{"nested wrappers", "sudo nice -n 19 rm -rf /", "rm"},
		{"assignment operand", "strace -e trace=file rm -rf /", "rm"},
		{"two value flags", "timeout -k 5 10 rm -rf /", "rm"},

		// --- End-of-options marker ---
		{"-- after value flag", "sudo -u root -- rm -rf /", "rm"},
		{"-- alone", "sudo -- rm -rf /", "rm"},
		// `--` means the NEXT word is the command whatever it looks like. A
		// dash-leading target after `--` is the only way to express this, and
		// the plain shape model could never reach it.
		{"-- then dash-leading target", "sudo -- ./-weird-name", "./-weird-name"},

		// --- Fail-safe: a value flag must never consume the last word ---
		{"no target after value flag", "sudo -u root", "sudo"},
		{"no target, env", "env -u LD_PRELOAD", "env"},
		{"bare wrapper alone", "sudo", "sudo"},
		{"boolean flag only", "sudo -i", "sudo"},

		// --- Flags deliberately NOT in the table stay unconsumed ---
		// sudo's `-h` is --host in current sudo and help in older builds. An
		// omission is the pre-#3221 status quo for that one flag; a wrong entry
		// would skip a token too many and re-target analysis onto an argument.
		{"ambiguous flag not consumed", "sudo -h rm -rf /", "rm"},
		{"boolean flag then command", "sudo -n rm -rf /", "rm"},
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

// TestWrapperValueFlagRegexSurface pins the OTHER half of the fix.
//
// StripExecWrappers (AST) and StripExecWrapperPrefix (regex layer) walk
// wrappers separately, and #3208 is the standing lesson that fixing one
// normalization surface while leaving a sibling unnormalized measures like a
// partial fix. Both now share wrapperTargetIndex; this asserts they agree, so a
// future edit to one cannot silently desynchronize them.
func TestWrapperValueFlagRegexSurface(t *testing.T) {
	cases := []struct {
		command string
		want    string
	}{
		{"sudo -u root rm -rf /", "rm -rf /"},
		{"strace -o /tmp/t.log dd if=/dev/zero of=/dev/sda", "dd if=/dev/zero of=/dev/sda"},
		{"timeout -s KILL 5 mkfs.ext4 /dev/sda1", "mkfs.ext4 /dev/sda1"},
		{"env -u LD_PRELOAD curl -sL http://example.com/x.sh", "curl -sL http://example.com/x.sh"},
		{"sudo -u root -- rm -rf /", "rm -rf /"},
		{"taskset -c 0-3 rm -rf /", "rm -rf /"},
		// No wrapper to peel, and a wrapper with no target, both yield "".
		{"rm -rf /", ""},
		{"sudo -u root", ""},
	}

	for _, tc := range cases {
		if got := StripExecWrapperPrefix(tc.command); got != tc.want {
			t.Errorf("StripExecWrapperPrefix(%q) = %q, want %q", tc.command, got, tc.want)
		}
	}
}

// TestConsumesNextToken pins the three ways a token carries its own value and
// therefore must NOT consume the following one. Getting any of these wrong eats
// the wrapped command instead of an option value.
func TestConsumesNextToken(t *testing.T) {
	cases := []struct {
		wrapper, tok string
		want         bool
	}{
		{"sudo", "-u", true},
		{"sudo", "--user", true},
		{"sudo", "-uroot", false},      // attached short form carries its value
		{"sudo", "--user=root", false}, // long form carries its value
		{"sudo", "--", false},          // end-of-options, handled separately
		{"sudo", "-i", false},          // boolean
		{"sudo", "-", false},           // stdin convention, not an option
		{"sudo", "", false},
		{"rm", "-u", false},                    // not a wrapper at all
		{"systemd-run", "--setenv=A=B", false}, // '=' rule protects this shape
		{"systemd-run", "--setenv", true},
	}

	for _, tc := range cases {
		if got := consumesNextToken(tc.wrapper, tc.tok); got != tc.want {
			t.Errorf("consumesNextToken(%q, %q) = %v, want %v", tc.wrapper, tc.tok, got, tc.want)
		}
	}
}
