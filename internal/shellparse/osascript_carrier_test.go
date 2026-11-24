package shellparse

import (
	"strings"
	"testing"
)

// TestOsascriptDoShellScript pins what Shield reads out of
// `osascript -e '... do shell script "CMD" ...'` (#4900): CMD, exactly as
// /bin/sh -c receives it, through the same InlineCodeFragments path every
// other shell-source carrier uses.
//
// The want column is the shell source after BOTH quoting layers are removed:
// the outer shell's quote removal on the -e word, then AppleScript's string
// escapes (\" and \\, plus \n \r \t) inside the literal.
func TestOsascriptDoShellScript(t *testing.T) {
	cases := []struct {
		name, command, want string
	}{
		{"canonical", `osascript -e 'do shell script "rm -rf /"'`, "rm -rf /"},
		{"several -e, the call in the second", `osascript -e 'set x to 1' -e 'do shell script "rm -rf /"'`, "rm -rf /"},
		{"two calls in two -e", `osascript -e 'do shell script "id"' -e 'do shell script "rm -rf /"'`, "id\nrm -rf /"},
		{"escaped quotes", `osascript -e 'do shell script "rm -rf \"/\""'`, `rm -rf "/"`},
		{"escaped backslash", `osascript -e 'do shell script "rm -rf \\/"'`, `rm -rf \/`},
		{"newline escape splits statements", `osascript -e 'do shell script "echo hi\nrm -rf /"'`, "echo hi\nrm -rf /"},
		{"with administrator privileges", `osascript -e 'do shell script "rm -rf /" with administrator privileges'`, "rm -rf /"},
		{"shell double-quoted -e", `osascript -e "do shell script \"rm -rf /\""`, "rm -rf /"},
		{"attached -e value", `osascript -e'do shell script "rm -rf /"'`, "rm -rf /"},
		{"absolute path", `/usr/bin/osascript -e 'do shell script "rm -rf /"'`, "rm -rf /"},
		{"behind sudo", `sudo osascript -e 'do shell script "rm -rf /"'`, "rm -rf /"},
		{"keywords are case-insensitive", `osascript -e 'Do Shell Script "rm -rf /"'`, "rm -rf /"},
		{"inside a tell", `osascript -e 'tell application "Terminal" to do shell script "rm -rf /"'`, "rm -rf /"},
		{"-s option value before -e", `osascript -s o -e 'do shell script "rm -rf /"'`, "rm -rf /"},
		{"explicit AppleScript language", `osascript -l AppleScript -e 'do shell script "rm -rf /"'`, "rm -rf /"},
		{"literal concatenation", `osascript -e 'do shell script "rm -rf " & "/"'`, "rm -rf /"},
		{"parenthesised concatenation", `osascript -e 'do shell script ("rm -rf " & "/")'`, "rm -rf /"},
		{"quoted form of a literal", `osascript -e 'do shell script "rm -rf " & quoted form of "/"'`, "rm -rf '/'"},
		// A non-literal operand (a variable, `POSIX path of …`) has no static
		// value; it reads as a neutral placeholder word, so the literal text
		// around it is still evaluated.
		{"non-literal operand keeps the rest", `osascript -e 'do shell script "cd " & p & "; rm -rf /"'`, "cd __applescript_expr__; rm -rf /"},
		{"raw event code", `osascript -e '«event sysoexec» "rm -rf /"'`, "rm -rf /"},
		{"block comment before the parameter", `osascript -e 'do shell script (* x *) "rm -rf /"'`, "rm -rf /"},
		{"¬ continues the call onto the next -e line", `osascript -e 'do shell script ¬' -e '"rm -rf /"'`, "rm -rf /"},
		{"a call nested in another call's parameter", `osascript -e 'do shell script "echo " & (do shell script "id")'`, "echo __applescript_expr__\nid"},
		{"single quote inside the command survives", `osascript -e "do shell script \"echo 'a b'\""`, "echo 'a b'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := InlineCodeFragments(tc.command)
			if len(got) != 1 || got[0] != tc.want {
				t.Errorf("InlineCodeFragments(%q) = %q, want [%q]", tc.command, got, tc.want)
			}
		})
	}
}

// TestOsascriptNotShellSource is the other half: AppleScript that runs no
// shell command, or a `do shell script` this reading deliberately does not
// claim, must yield no fragment. A wrong fragment here is a false positive —
// the same asymmetry shellSourceFlags documents.
func TestOsascriptNotShellSource(t *testing.T) {
	cases := []struct{ name, command string }{
		{"notification", `osascript -e 'display notification "build done" with title "make"'`},
		{"tell Finder", `osascript -e 'tell application "Finder" to activate'`},
		{"the phrase inside a string", `osascript -e 'display dialog "do shell script \"rm -rf /\""'`},
		{"the phrase ending a string before a concatenation", `osascript -e 'set msg to "tip: do shell script" & "rm -rf /"'`},
		{"line comment", `osascript -e '-- do shell script "rm -rf /"'`},
		{"hash comment", `osascript -e '# do shell script "rm -rf /"'`},
		{"block comment across -e", `osascript -e '(* note:' -e 'do shell script "rm -rf /" *)' -e 'beep'`},
		{"identifier, not the command", `osascript -e 'set undo shell script to 1'`},
		{"empty command", `osascript -e 'do shell script ""'`},
		{"wholly non-literal command", `osascript -e 'do shell script cmd'`},
		{"an & inside a trailing comment joins nothing", `osascript -e 'do shell script cmd -- & "rm -rf /"'`},
		{"unterminated string never compiles", `osascript -e 'do shell script "rm -rf /'`},
		{"JXA is out of scope", `osascript -l JavaScript -e 'app.doShellScript("rm -rf /")'`},
		{"JXA source is not read as AppleScript", `osascript -l JavaScript -e '// do shell script "rm -rf /"'`},
		{"script file: later words are its argv", `osascript build.scpt 'do shell script "rm -rf /"'`},
		{"operands after -e are the script's argv", `osascript -e 'on run argv' -e 'end run' 'do shell script "rm -rf /"'`},
		{"-e with no value", `osascript -e`},
		{"not osascript", `grep -e 'do shell script "rm -rf /"' notes.txt`},
		{"relative ./osascript is not resolved", `./osascript -e 'do shell script "rm -rf /"'`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := InlineCodeFragments(tc.command); len(got) != 0 {
				t.Errorf("InlineCodeFragments(%q) = %q, want none", tc.command, got)
			}
		})
	}
}

// TestOsascriptDecomposes pins the sub-parse: the command must become a real
// Subcommand so structural, semantic and dataflow rules see `rm` as an
// executable, not one opaque argument (#3223's partial-fix lesson).
func TestOsascriptDecomposes(t *testing.T) {
	for _, cmd := range []string{
		`osascript -e 'do shell script "rm -rf /"'`,
		`osascript -e 'do shell script "rm -rf /" with administrator privileges'`,
		`osascript -e 'set x to 1' -e 'do shell script "rm -rf \"/\""'`,
	} {
		pc := Parse(cmd, 3)
		if pc == nil {
			t.Fatalf("Parse(%q) returned nil", cmd)
		}
		var execs []string
		for _, sub := range pc.Subcommands {
			for _, seg := range sub.Segments {
				execs = append(execs, seg.Executable)
			}
		}
		if !strings.Contains(" "+strings.Join(execs, " ")+" ", " rm ") {
			t.Errorf("Parse(%q): sub-segment executables %q, want rm among them", cmd, execs)
		}
	}
}
