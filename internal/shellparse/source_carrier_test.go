package shellparse

import "testing"

func TestShellSourceArg(t *testing.T) {
	cases := []struct {
		name  string
		words []string
		want  string
	}{
		// flag value, separate token
		{"man -P", []string{"man", "-P", "'rm -rf /'", "ls"}, "'rm -rf /'"},
		{"man --pager", []string{"man", "--pager", "'rm -rf /'", "ls"}, "'rm -rf /'"},
		// flag value, = form
		{"man --pager=", []string{"man", "--pager='rm -rf /'", "ls"}, "'rm -rf /'"},
		{"sort --compress-program=", []string{"sort", "--compress-program=/bin/sh", "f"}, "/bin/sh"},
		// short flag whose spelling is a two-letter cluster
		{"zip -TT", []string{"zip", "-T", "-TT", "'rm -rf /'", "a.zip"}, "'rm -rf /'"},
		// value-taking option BEFORE the source flag must not confuse it
		{"flock lockfile then -c", []string{"flock", "/tmp/x", "-c", "'rm -rf /'"}, "'rm -rf /'"},
		{"flock -w then -c", []string{"flock", "-w", "30", "/tmp/x", "-c", "'make deploy'"}, "'make deploy'"},
		// env -S: the entry whose absence was documented as "handled elsewhere"
		{"env -S", []string{"env", "-S", "'rm -rf /'"}, "'rm -rf /'"},
		{"env --split-string=", []string{"env", "--split-string='rm -rf /'"}, "'rm -rf /'"},

		// positional source
		{"watch bare", []string{"watch", "'rm -rf /'"}, "'rm -rf /'"},
		{"watch -n attached", []string{"watch", "-n1", "'rm -rf /'"}, "'rm -rf /'"},
		{"watch -n separate", []string{"watch", "-n", "1", "'rm -rf /'"}, "'rm -rf /'"},
		{"watch unquoted operands join", []string{"watch", "-n", "1", "rm", "-rf", "/"}, "rm -rf /"},
		// -d takes an OPTIONAL value and only in the = spelling, so it must NOT
		// consume the payload. Listing it would lose the source entirely.
		{"watch -d does not consume", []string{"watch", "-d", "'rm -rf /'"}, "'rm -rf /'"},
		{"watch -- ends options", []string{"watch", "--", "rm", "-rf", "/"}, "rm -rf /"},

		// path-resolved program name
		{"/usr/bin/man -P", []string{"/usr/bin/man", "-P", "'rm -rf /'", "ls"}, "'rm -rf /'"},
		// a relative ./man is far more likely a project script than the tool
		{"./man not resolved", []string{"./man", "-P", "'rm -rf /'", "ls"}, ""},

		// fail-safe: a source flag with nothing after it must not swallow the
		// last word or invent a payload
		{"man -P at end", []string{"man", "-P"}, ""},
		{"watch with no operand", []string{"watch", "-n", "1"}, ""},
		{"empty", nil, ""},

		// not a carrier
		{"grep is not a carrier", []string{"grep", "-e", "'rm -rf /'", "file"}, ""},
		{"ls", []string{"ls", "-la"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShellSourceArg(tc.words); got != tc.want {
				t.Errorf("ShellSourceArg(%q) = %q, want %q", tc.words, got, tc.want)
			}
		})
	}
}

// TestShellSourceArgValue pins the values form the substitution layer reads
// through (#4903): argv words that are already runtime values in, the source
// as a value out. Each row also gives the raw spelling of the same argv, and
// the two readings must agree once the raw one is dequoted the way
// ExtractInlineCode dequotes it: one table, two quote conventions.
func TestShellSourceArgValue(t *testing.T) {
	cases := []struct {
		name   string
		values []string
		raw    []string
		want   string
	}{
		{"man -P", []string{"man", "-P", "cat x", "ls"}, []string{"man", "-P", "'cat x'", "ls"}, "cat x"},
		{"man --pager=", []string{"man", "--pager=cat x", "ls"}, []string{"man", "--pager='cat x'", "ls"}, "cat x"},
		{"env -S", []string{"env", "-S", "cat x"}, []string{"env", "-S", "'cat x'"}, "cat x"},
		{"flock -c", []string{"flock", "/tmp/l", "-c", "cat x"}, []string{"flock", "/tmp/l", "-c", "'cat x'"}, "cat x"},
		{"watch quoted operand", []string{"watch", "-n", "1", "cat x"}, []string{"watch", "-n", "1", "'cat x'"}, "cat x"},
		{"osascript", []string{"osascript", "-e", `do shell script "cat x"`}, []string{"osascript", "-e", `'do shell script "cat x"'`}, "cat x"},
		{"osascript, call in a later -e", []string{"osascript", "-e", "set x to 1", "-e", `do shell script "cat x"`},
			[]string{"osascript", "-e", "'set x to 1'", "-e", `'do shell script "cat x"'`}, "cat x"},
		// A single quote in the command is a value here, not shell quoting to
		// undo: the raw reading has to escape it into its synthesized word.
		{"osascript, quote in the command", []string{"osascript", "-e", `do shell script "cat 'a b'"`},
			[]string{"osascript", "-e", `"do shell script \"cat 'a b'\""`}, "cat 'a b'"},
		{"osascript -l JavaScript", []string{"osascript", "-l", "JavaScript", "-e", `do shell script "cat x"`},
			[]string{"osascript", "-l", "JavaScript", "-e", `'do shell script "cat x"'`}, ""},
		{"osascript string, not a call", []string{"osascript", "-e", `display dialog "do shell script"`},
			[]string{"osascript", "-e", `'display dialog "do shell script"'`}, ""},
		{"man -M is data", []string{"man", "-M", "cat x", "ls"}, []string{"man", "-M", "'cat x'", "ls"}, ""},
		{"grep is not a carrier", []string{"grep", "-e", "cat x", "f"}, []string{"grep", "-e", "'cat x'", "f"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShellSourceArgValue(tc.values); got != tc.want {
				t.Errorf("ShellSourceArgValue(%q) = %q, want %q", tc.values, got, tc.want)
			}
			raw := ShellSourceArg(tc.raw)
			if raw != "" {
				raw = payloadValue(raw)
			}
			if raw != tc.want {
				t.Errorf("raw reading of %q = %q, want %q: the two conventions disagree", tc.raw, raw, tc.want)
			}
		})
	}
	// The positional form joins values with one space, which is what watch
	// hands to sh -c: an operand's inner spacing is its own.
	if got := ShellSourceArgValue([]string{"watch", "-n", "1", "cat", "a  b"}); got != "cat a  b" {
		t.Errorf("watch positional values = %q, want %q", got, "cat a  b")
	}
}

// TestShellSourceCarrierDecomposes pins the end-to-end path: the captured
// SourceArg must become a real Subcommand, not just sit in the struct. #3223
// measured what a partial fix looks like — teaching the extractor alone left
// structural and semantic rules seeing one opaque argument and read like a fix
// that had not worked.
func TestShellSourceCarrierDecomposes(t *testing.T) {
	cases := []struct {
		name, command, wantExec string
	}{
		{"man pager", "man -P 'rm -rf /' ls", "rm"},
		{"sort compressor", "sort --compress-program='rm -rf /' /etc/hostname", "rm"},
		{"flock", "flock /tmp/x -c 'rm -rf /'", "rm"},
		{"env -S", "env -S 'rm -rf /'", "rm"},
		{"watch", "watch -n1 'rm -rf /'", "rm"},
		{"tar -I", "tar -I 'rm -rf /' -cf /dev/null /etc/hostname", "rm"},
		// wrapper prefix composed with a carrier
		{"sudo man", "sudo man -P 'rm -rf /' ls", "rm"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc := Parse(tc.command, 3)
			if pc == nil {
				t.Fatalf("Parse(%q) returned nil", tc.command)
			}
			if len(pc.Subcommands) == 0 {
				t.Fatalf("Parse(%q): no Subcommands — the payload was captured but never sub-parsed, "+
					"so structural/semantic/dataflow still see one opaque argument", tc.command)
			}
			var found bool
			for _, sub := range pc.Subcommands {
				for _, seg := range sub.Segments {
					if seg.Executable == tc.wantExec {
						found = true
					}
				}
			}
			if !found {
				t.Errorf("Parse(%q): no sub-segment with Executable==%q; subcommands=%+v",
					tc.command, tc.wantExec, pc.Subcommands)
			}
		})
	}
}

// TestCarriesShellSourceExcludesInterpreters guards the one thing this
// predicate must NOT admit. A `python3 -c` payload is Python, and matching
// shell rules against it re-creates the inert string-literal false positives of
// #1570/#2995 — a Python string that MENTIONS ~/.ssh/id_rsa is text being
// processed, not an access being performed.
func TestCarriesShellSourceExcludesInterpreters(t *testing.T) {
	pc := Parse("python3 -c 'import os'", 2)
	if pc == nil || len(pc.Segments) == 0 {
		t.Fatal("parse failed")
	}
	seg := pc.Segments[0]
	if seg.SourceArg != "" {
		t.Errorf("python3 must not populate SourceArg, got %q", seg.SourceArg)
	}
	if CarriesShellSource(seg) {
		t.Error("CarriesShellSource must be false for a code interpreter — " +
			"InlineCodeFragments uses it to decide what gets matched against SHELL rules")
	}
}

// TestEnvSplitStringSkippedByOperandWalk pins the other half of the env -S fix.
// Before it, StripExecWrappers walked past -S, found the payload string, and
// named the whole quoted script as the executable. Listing -S in
// wrapperValueFlags leaves env in executable position so the carrier lookup can
// find it.
func TestEnvSplitStringSkippedByOperandWalk(t *testing.T) {
	got := StripExecWrappers([]string{"env", "-S", "rm -rf /"})
	if len(got) == 0 || got[0] != "env" {
		t.Errorf("StripExecWrappers(env -S ...) = %q; want env kept in executable "+
			"position (a wrapper with no bare command word has no target)", got)
	}
	// The ordinary env-as-wrapper behaviour must be untouched.
	if got := StripExecWrappers([]string{"env", "rm", "-rf", "/"}); len(got) == 0 || got[0] != "rm" {
		t.Errorf("StripExecWrappers(env rm -rf /) = %q; want rm", got)
	}
	if got := StripExecWrappers([]string{"env", "-u", "LD_PRELOAD", "rm", "-rf", "/"}); len(got) == 0 || got[0] != "rm" {
		t.Errorf("StripExecWrappers(env -u LD_PRELOAD rm -rf /) = %q; want rm", got)
	}
}
