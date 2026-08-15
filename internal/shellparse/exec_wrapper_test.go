package shellparse

import (
	"reflect"
	"testing"
)

// TestStripExecWrappers verifies that execution-wrapper commands are peeled off
// so the real target command becomes the parsed executable. This closes a class
// of structural-rule evasions where an attacker prefixes a dangerous command
// with a transparent wrapper ("nice rm -rf /", "env rm -rf /", ...).
func TestStripExecWrappers(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		// No wrapper — unchanged.
		{"plain", []string{"rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},

		// Simple single wrappers.
		{"env", []string{"env", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"nohup", []string{"nohup", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"setsid", []string{"setsid", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"command", []string{"command", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"sudo", []string{"sudo", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"doas", []string{"doas", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},

		// Wrappers with their own flags.
		{"stdbuf-flag", []string{"stdbuf", "-oL", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"ionice-flag", []string{"ionice", "-c3", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"env-i", []string{"env", "-i", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},

		// Wrappers with KEY=VALUE assignments.
		{"env-assign", []string{"env", "FOO=bar", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"env-multi-assign", []string{"env", "A=1", "B=2", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},

		// Wrappers that take a positional numeric/duration argument.
		{"timeout-num", []string{"timeout", "5", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"timeout-dur", []string{"timeout", "5s", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"nice-n", []string{"nice", "-n", "10", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"chrt", []string{"chrt", "-f", "99", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"taskset-cpu", []string{"taskset", "-c", "0", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"taskset-hex", []string{"taskset", "0x3", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},

		// Nested wrappers.
		{"sudo-nice", []string{"sudo", "nice", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"nohup-setsid", []string{"nohup", "setsid", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"env-nice-mix", []string{"env", "FOO=bar", "nice", "-n", "5", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},

		// Guard: bare wrapper with no target command stays as the executable.
		{"bare-env", []string{"env"}, []string{"env"}},
		{"env-i-only", []string{"env", "-i"}, []string{"env", "-i"}},
		{"sudo-i-only", []string{"sudo", "-i"}, []string{"sudo", "-i"}},

		// Benign inner command preserved (no over-stripping).
		{"timeout-npm", []string{"timeout", "30", "npm", "test"}, []string{"npm", "test"}},
		{"nice-make", []string{"nice", "-n", "19", "make", "build"}, []string{"make", "build"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StripExecWrappers(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("StripExecWrappers(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestNormalizeExecName verifies that shell quoting/escaping is stripped from
// the executable position so obfuscated command names match their real name.
func TestNormalizeExecName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"rm", "rm"},                 // plain — unchanged
		{`\rm`, "rm"},                // backslash escape
		{`"rm"`, "rm"},               // double quotes
		{`'rm'`, "rm"},               // single quotes
		{`r""m`, "rm"},               // embedded empty double quotes
		{`rm''`, "rm"},               // trailing empty single quotes
		{`r\m`, "rm"},                // internal backslash
		{"/usr/bin/rm", "/usr/bin/rm"}, // path — unchanged
		{"./script.sh", "./script.sh"}, // relative path — unchanged
		{"$CMD", "$CMD"},             // dynamic — left alone
		{"$(echo rm)", "$(echo rm)"}, // command substitution — left alone
		{"`rm`", "`rm`"},             // backtick — left alone
		{"", ""},                     // empty
	}
	for _, tt := range tests {
		if got := NormalizeExecName(tt.in); got != tt.want {
			t.Errorf("NormalizeExecName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestExecWrapperParseIntegration verifies the full parser resolves the real
// executable for wrapped commands, including the `time` reserved word which bash
// parses as a TimeClause rather than a CallExpr.
func TestExecWrapperParseIntegration(t *testing.T) {
	tests := []struct {
		cmd      string
		wantExec string
	}{
		{"nice rm -rf /", "rm"},
		{"env FOO=bar rm -rf /", "rm"},
		{"timeout 5 rm -rf /", "rm"},
		{"sudo nice rm -rf /", "rm"},
		{"time rm -rf /", "rm"},
		{"env node app.js", "node"},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			pc := Parse(tt.cmd, 2)
			if pc == nil || len(pc.Segments) == 0 {
				t.Fatalf("Parse(%q) produced no segments", tt.cmd)
			}
			if got := pc.Segments[0].Executable; got != tt.wantExec {
				t.Errorf("Parse(%q) executable = %q, want %q", tt.cmd, got, tt.wantExec)
			}
		})
	}
}
