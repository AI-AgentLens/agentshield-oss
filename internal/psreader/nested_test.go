package psreader

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/AI-AgentLens/agentshield/internal/facts"
)

// encodeCommand builds an -EncodedCommand payload the way PowerShell's own
// docs do: base64 of the UTF-16LE text. Payloads are built at run time so
// the source holds no encoded attack text.
func encodeCommand(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func hasNote(f facts.Facts, k facts.NoteKind) bool {
	for _, n := range f.Notes {
		if n.Kind == k {
			return true
		}
	}
	return false
}

func TestRead_Nested(t *testing.T) {
	inner := "Remove-Item -Recurse " + `C:\tmp\x`
	enc := encodeCommand(inner)
	cases := []struct {
		name string
		in   string
		want []facts.Nested
	}{
		{"powershell -Command", `powershell -Command "` + inner + `"`, nst("powershell", inner)},
		{"pwsh -c, unquoted words joined", `pwsh -c Get-Item x -Force`, nst("pwsh", "Get-Item x -Force")},
		{"prefix -com", `powershell -com "Get-Item x"`, nst("powershell", "Get-Item x")},
		{"slash option", `powershell /Command "Get-Item x"`, nst("powershell", "Get-Item x")},
		{"double dash option", `pwsh --command "Get-Item x"`, nst("pwsh", "Get-Item x")},
		{"en dash option", "powershell \u2013Command 'Get-Item x'", nst("powershell", "Get-Item x")},
		{"value options skipped", `powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Get-Item x"`, nst("powershell", "Get-Item x")},
		{"-ep short form", `powershell -ep bypass -c "Get-Item x"`, nst("powershell", "Get-Item x")},
		{"colon-attached value", `powershell -Command:"Get-Item x"`, nst("powershell", "Get-Item x")},
		{"exe with path", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c "Get-Item x"`, nst("powershell", "Get-Item x")},
		{"call operator, quoted path", `& 'C:\Program Files\PowerShell\7\pwsh.exe' -c 'Get-Item x'`, nst("pwsh", "Get-Item x")},
		{"positional command (5.1 default)", `powershell "Get-Process"`, nst("powershell", "Get-Process")},
		{"-EncodedCommand", "powershell -EncodedCommand " + enc, nst("powershell", inner)},
		{"-enc", "powershell -enc " + enc, nst("powershell", inner)},
		{"-e", "pwsh -e " + enc, nst("pwsh", inner)},
		{"-ec", "pwsh -ec " + enc, nst("pwsh", inner)},
		{"-encodedc", "powershell -encodedc " + enc, nst("powershell", inner)},
		{"unpadded base64", "powershell -enc " + strings.TrimRight(encodeCommand("Get-Item xy"), "="), nst("powershell", "Get-Item xy")},
		{"-CommandWithArgs", `pwsh -CommandWithArgs 'Get-Item $args[0]' x`, nst("pwsh", "Get-Item $args[0]")},
		{"cmd /c", `cmd /c del C:\tmp\x`, nst("cmd", `del C:\tmp\x`)},
		{"cmd.exe /C quoted", `cmd.exe /C "type C:\tmp\x"`, nst("cmd", `type C:\tmp\x`)},
		{"cmd /k", `cmd /k dir`, nst("cmd", "dir")},
		{"cmd switches first", `cmd /d /s /c "dir C:\"`, nst("cmd", `dir C:\`)},
		{"cmd /cdir attached", `cmd /cdir`, nst("cmd", "dir")},
		{"cmd after --%", `cmd --% /c type "%USERPROFILE%\x"`, nst("cmd", `type %USERPROFILE%\x`)},
		{"cmd keeps a quoted word whole", `cmd /c type 'C:\a b\x'`, nst("cmd", `type "C:\a b\x"`)},
		// cmd takes its switches joined (Opus pass 2 on #4245, run on Windows)
		{"cmd joined /d/c", `cmd /d/c echo x`, nst("cmd", "echo x")},
		{"cmd joined /s/c, quoted", `cmd /s/c "echo x"`, nst("cmd", "echo x")},
		{"cmd joined /d/s/c", `cmd /d/s/c dir`, nst("cmd", "dir")},
		{"cmd joined /q/d/c", `cmd /q/d/c dir`, nst("cmd", "dir")},
		{"cmd joined /D/K", `cmd /D/K dir`, nst("cmd", "dir")},
		{"cmd joined /e:on/c", `cmd /e:on/c dir`, nst("cmd", "dir")},
		{"cmd joined, text attached", `cmd /d/cdir`, nst("cmd", "dir")},
		{"cmd /c/d: the switch after /c is the text", `cmd /c/d echo x`, nst("cmd", "/d echo x")},
		{"bash -c", `bash -c "rm -rf ~/x"`, nst("bash", "rm -rf ~/x")},
		{"bash -lc", `bash -lc 'ls -la'`, nst("bash", "ls -la")},
		{"bash --login -c", `bash --login -c 'ls'`, nst("bash", "ls")},
		{"bash -o value", `bash -o pipefail -c 'ls'`, nst("bash", "ls")},
		{"sh -c", `sh -c 'id'`, nst("sh", "id")},
		{"git bash by path", `& 'C:\Program Files\Git\bin\bash.exe' -c 'ls'`, nst("bash", "ls")},
		{"wsl command", `wsl rm -rf /tmp/x`, nst("wsl", "rm -rf /tmp/x")},
		{"wsl options then --", `wsl -d Ubuntu -u root -- cat /etc/hostname`, nst("wsl", "cat /etc/hostname")},
		{"wsl -e", `wsl -e ls -la`, nst("wsl", "ls -la")},
		{"nested inside a pipeline", `Get-Date | ForEach-Object { cmd /c echo hi }`, nst("cmd", "echo hi")},
		// no command text
		{"-File", `powershell -File C:\x.ps1 -Arg 1`, nil},
		{"-Command - reads stdin", `powershell -Command -`, nil},
		{"script block is read in place", `powershell -Command { Get-Process }`, nil},
		{"bash script file", `bash ./build.sh -c x`, nil},
		{"wsl management", `wsl --install`, nil},
		{"wsl list", `wsl -l -v`, nil},
		{"cmd without /c", `cmd /?`, nil},
		{"cmd joined, no /c", `cmd /d/q`, nil},
		{"not an interpreter", `git -c core.x=y status`, nil},
		{"Start-Process is not read (follow-up)", `Start-Process powershell -ArgumentList '-c','Get-Item x'`, nil},
	}
	for _, tc := range cases {
		f := Read(tc.in, Env{})
		if !reflect.DeepEqual(f.Nested, tc.want) {
			t.Errorf("%s: Read(%q).Nested = %q, want %q", tc.name, tc.in, f.Nested, tc.want)
		}
		if hasNote(f, facts.NoteParseError) {
			t.Errorf("%s: unexpected parse_error: %+v", tc.name, f.Notes)
		}
	}
}

// TestRead_NestedEncodedTextReachesMentions: the decoded text is not in the
// raw text, so the raw scan reads it separately. What it finds is a mention
// of the outer text; the router reads the decoded text again as text of its
// own (ADR-001 D6), where the read is a path.
func TestRead_NestedEncodedTextReachesMentions(t *testing.T) {
	inner := `Get-Content $env:USERPROFILE\.ssh\id_rsa`
	f := Read("powershell -enc "+encodeCommand(inner), testEnv)
	if !contains(f.Mentions, "~/.ssh/id_rsa") {
		t.Fatalf("Mentions = %q, want the path inside the encoded command", f.Mentions)
	}
	if len(f.Nested) != 1 || !contains(Read(f.Nested[0].Text, testEnv).Paths, "~/.ssh/id_rsa") {
		t.Fatalf("Nested = %q; want the decoded text, whose own read has the path", f.Nested)
	}
}

func TestRead_NestedNotes(t *testing.T) {
	cases := []struct {
		in   string
		kind facts.NoteKind
	}{
		{`powershell -enc "!!not base64!!"`, facts.NoteDecodeFailed},
		{`powershell -enc A`, facts.NoteDecodeFailed},
		{`powershell -enc $payload`, facts.NoteDynamicNested},
		{`pwsh -c $cmd`, facts.NoteDynamicNested},
		{`pwsh -c (Get-Content cmd.txt -Raw)`, facts.NoteDynamicNested},
		{`bash -c $script`, facts.NoteDynamicNested},
		{`cmd /c $line`, facts.NoteDynamicNested},
	}
	for _, tc := range cases {
		f := Read(tc.in, Env{})
		if !hasNote(f, tc.kind) {
			t.Errorf("Read(%q).Notes = %+v, want a %s note", tc.in, f.Notes, tc.kind)
		}
		if len(f.Nested) != 0 {
			t.Errorf("Read(%q).Nested = %q, want none", tc.in, f.Nested)
		}
	}
}

func TestDecodeEncodedCommand(t *testing.T) {
	want := "Write-Host 'é ✓'"
	got, err := decodeEncodedCommand(encodeCommand(want))
	if err != nil || got != want {
		t.Fatalf("decode = %q, %v; want %q", got, err, want)
	}
	// a byte-order mark is dropped; whitespace in the payload is ignored
	spaced := encodeCommand("\uFEFFGet-Date")
	spaced = spaced[:8] + "\n  " + spaced[8:]
	if got, err := decodeEncodedCommand(spaced); err != nil || got != "Get-Date" {
		t.Fatalf("decode with BOM and whitespace = %q, %v", got, err)
	}
	for _, bad := range []string{"", "!!!!", "A", "QQ=="} {
		if _, err := decodeEncodedCommand(bad); err == nil {
			t.Errorf("decode(%q) succeeded, want an error", bad)
		}
	}
}

func TestSplitWindowsArgs(t *testing.T) {
	got := splitWindowsArgs(`/c type "C:\a b\x" 2>NUL  last`)
	want := []string{"/c", "type", `C:\a b\x`, "2>NUL", "last"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitWindowsArgs = %q, want %q", got, want)
	}
}

func nst(exe, text string) []facts.Nested { return []facts.Nested{{Exe: exe, Text: text}} }

// TestCmdRunSwitch: the first /c, /k or /r in one word of joined cmd.exe
// switches starts the command (Opus pass 2 on #4245); what follows it in the
// word is the command's first text.
func TestCmdRunSwitch(t *testing.T) {
	rows := []struct {
		in, rest string
		ok       bool
	}{
		{"/c", "", true},
		{"/C", "", true},
		{"/k", "", true},
		{"/K", "", true},
		{"/r", "", true},
		{"/R", "", true},
		{"/cdir", "dir", true},
		{"/d/c", "", true},
		{"/s/c", "", true},
		{"/d/s/c", "", true},
		{"/q/d/c", "", true},
		{"/D/K", "", true},
		{"/e:on/c", "", true},
		{"/d/cdir", "dir", true},
		{"/c/d", "/d", true},
		{"/d", "", false},
		{"/d/q", "", false},
		{"/d/", "", false},
		{"/", "", false},
		{"", "", false},
		{"d/c", "", false},
		{"dir", "", false},
	}
	for _, r := range rows {
		rest, ok := cmdRunSwitch(r.in)
		if rest != r.rest || ok != r.ok {
			t.Errorf("cmdRunSwitch(%q) = %q, %v; want %q, %v", r.in, rest, ok, r.rest, r.ok)
		}
	}
}
