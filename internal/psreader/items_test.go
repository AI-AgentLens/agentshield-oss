package psreader

import (
	"reflect"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/facts"
)

// Windows round 3: facts.Element.Items, the elements of an array value
// written with commas, which a cmdlet binds to one parameter.
func TestRead_ElementItems(t *testing.T) {
	cases := []struct {
		in   string
		want [][]string // per element of the first command
	}{
		{"Stop-Service WinDefend,WdNisSvc", [][]string{{"WinDefend", "WdNisSvc"}}},
		{"Stop-Service -Name Spooler, 'WinDefend' -Force", [][]string{nil, {"Spooler", "WinDefend"}, nil}},
		{"Stop-Service -Name:a,b", [][]string{{"a", "b"}}},
		{"Stop-Service $a,$b", [][]string{{"$a", "$b"}}},
		{"Stop-Service (Get-X),b", [][]string{{facts.Expr, "b"}}},
		{"Stop-Service WinDefend", [][]string{nil}},
		{"Stop-Service @('a','b')", [][]string{nil}}, // an array subexpression: not read
	}
	for _, tc := range cases {
		f := Read(tc.in, Env{})
		if len(f.Commands) == 0 {
			t.Fatalf("%q: no command", tc.in)
		}
		var got [][]string
		for _, el := range f.Commands[0].Elements {
			got = append(got, el.Items)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Read(%q) items %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Windows round 3: facts.Command.StdinScript, a powershell or pwsh whose
// command line runs its standard input as the script.
func TestRead_StdinScript(t *testing.T) {
	cases := []struct {
		in    string
		stdin bool
	}{
		{"powershell", true},
		{"pwsh -NoProfile -NoLogo", true},
		{"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden", true},
		{"pwsh -nop -ep bypass -w hidden", true},
		{"powershell -", true},
		{"powershell -NoProfile -Command -", true},
		{"pwsh -c -", true},
		{"powershell -File -", true},
		{"powershell -Command:-", true},
		{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonInteractive`, true},
		{"pwsh -File process.ps1", false},
		{"pwsh process.ps1", false},
		{"powershell Get-Date", false},
		{"powershell -Command Get-Date", false},
		{"powershell -c", false}, // -Command with nothing after it: an error, not stdin
		{"powershell -EncodedCommand RwBlAHQALQBEAGEAdABlAA==", false},
		{"pwsh -e RwBlAHQALQBEAGEAdABlAA==", false},
		{"pwsh -CommandWithArgs '$args' a", false},
		{"pwsh -?", false},
		{"powershell -Help", false},
		{"powershell $script", false}, // a computed script word
		{"powershell -ExecutionPolicy Bypass -File x.ps1", false},
		{"pwsh -WorkingDirectory C:\\src -NoProfile", true}, // the option's value is no script
		{"Write-Output -", false},                           // not PowerShell
	}
	for _, tc := range cases {
		f := Read(tc.in, Env{})
		got := false
		for _, c := range f.Commands {
			got = got || c.StdinScript
		}
		if got != tc.stdin {
			t.Errorf("Read(%q): StdinScript %v, want %v", tc.in, got, tc.stdin)
		}
	}
}
