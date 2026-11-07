package assembly

import (
	"slices"
	"testing"
)

// TestCmdCommands: a cmd line split into its commands' words, as cmd hands
// them to a program (Windows round 4).
func TestCmdCommands(t *testing.T) {
	rows := []struct {
		in   string
		want [][]string
	}{
		{`rd /s /q C:\`, [][]string{{"rd", "/s", "/q", `C:\`}}},
		{`  del /q "C:\Program Files\x" `, [][]string{{"del", "/q", `C:\Program Files\x`}}},
		{`@rd /s /q C:\`, [][]string{{"rd", "/s", "/q", `C:\`}}},
		{`@ rd C:\x`, [][]string{{"rd", `C:\x`}}},
		{`a.exe x & b.exe y && c z || d | e`, [][]string{{"a.exe", "x"}, {"b.exe", "y"}, {"c", "z"}, {"d"}, {"e"}}},
		{`del a.txt,b.txt;c.txt d=e`, [][]string{{"del", "a.txt", "b.txt", "c.txt", "d", "e"}}},
		{`echo x > out.txt & type out.txt`, [][]string{{"echo", "x"}, {"type", "out.txt"}}},
		{`sort < in.txt > out.txt`, [][]string{{"sort"}}},
		{`echo x >"a b.txt" y`, [][]string{{"echo", "x", "y"}}},
		{`rd /s /q C:\^&x`, [][]string{{"rd", "/s", "/q", `C:\&x`}}},
		{`rd /s /q "C:\a&b"`, [][]string{{"rd", "/s", "/q", `C:\a&b`}}},
		{"a x\r\nb y", [][]string{{"a", "x"}, {"b", "y"}}},
		{"", nil},
		{"  &  ", nil},
	}
	for _, r := range rows {
		got := CmdCommands(r.in)
		if !slices.EqualFunc(got, r.want, func(a, b []string) bool { return slices.Equal(a, b) }) {
			t.Errorf("CmdCommands(%q) = %q, want %q", r.in, got, r.want)
		}
	}
}

// TestCmdDeleteAsPowerShell: cmd's delete built-ins read as the Remove-Item
// call with the same targets, `/s` as -Recurse. Anything else is not read.
func TestCmdDeleteAsPowerShell(t *testing.T) {
	rows := []struct{ in, want string }{
		{`rd /s /q C:\`, `Remove-Item -Path 'C:\' -Recurse -Force`},
		{`RD /S /Q C:\`, `Remove-Item -Path 'C:\' -Recurse -Force`},
		{`rmdir /s /q "C:\Program Files"`, `Remove-Item -Path 'C:\Program Files' -Recurse -Force`},
		{`rd/s/q C:\Windows`, `Remove-Item -Path 'C:\Windows' -Recurse -Force`},
		{`@rd /s /q C:\`, `Remove-Item -Path 'C:\' -Recurse -Force`},
		{`  del /s /q C:\*`, `Remove-Item -Path 'C:\*' -Recurse -Force`},
		{`del /f/s/q C:\*.*`, `Remove-Item -Path 'C:\*.*' -Recurse -Force`},
		{`rd /s C:\x`, `Remove-Item -Path 'C:\x' -Recurse`},
		{`erase /q C:\x.txt`, `Remove-Item -Path 'C:\x.txt' -Force`},
		{`del /q a.txt b.txt`, `Remove-Item -Path 'a.txt','b.txt' -Force`},
		{`rd /s /q %SystemDrive%\`, `Remove-Item -Path '%SystemDrive%\' -Recurse -Force`},
		{`del /q "it's.txt"`, `Remove-Item -Path 'it''s.txt' -Force`},
	}
	for _, r := range rows {
		cmds := CmdCommands(r.in)
		if len(cmds) != 1 {
			t.Fatalf("CmdCommands(%q) = %q, want one command", r.in, cmds)
		}
		got, ok := CmdDeleteAsPowerShell(cmds[0])
		if !ok || got != r.want {
			t.Errorf("CmdDeleteAsPowerShell(%q) = %q, %v; want %q", cmds[0], got, ok, r.want)
		}
	}
	for _, words := range [][]string{nil, {"dir", `C:\`}, {"rd", "/s", "/q"}, {"del"}, {"rdx", "/s", `C:\`}, {"echo", "rd", `C:\`}, {"rd", "/?"}} {
		if got, ok := CmdDeleteAsPowerShell(words); ok {
			t.Errorf("CmdDeleteAsPowerShell(%q) = %q, want no reading", words, got)
		}
	}
}

// TestCmdNative: one cmd command is one native argv of literal words.
func TestCmdNative(t *testing.T) {
	st := cmdNative([]string{"wevtutil", "cl", "Security"})
	if len(st.Pipelines) != 1 || len(st.Pipelines[0].Stages) != 1 {
		t.Fatalf("statement %+v, want one pipeline of one stage", st)
	}
	argv := st.Pipelines[0].Stages[0]
	if len(argv) != 3 || argv[2][0].Text != "Security" || argv[2][0].Unknown {
		t.Errorf("argv %+v, want three literal words", argv)
	}
}
