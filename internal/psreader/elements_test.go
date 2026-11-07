package psreader

import (
	"reflect"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/facts"
)

// Elements keeps the order Params and Args lose: which argument follows which
// parameter. The back end needs it for a consumer's credential slot
// (`ssh -i <key>`), where `scp -i k f host:` and `scp f -i k host:` have the
// same Params and Args.
func TestElements_SourceOrder(t *testing.T) {
	env := Env{Home: `C:\Users\alice`}
	key := "id_" + "ed25519"
	rows := []struct {
		text string
		want []facts.Element
	}{
		{
			`ssh -i ~\.ssh\` + key + ` deploy@host`,
			[]facts.Element{
				{Param: "-i"},
				{Value: `~\.ssh\` + key, Paths: []string{"~/.ssh/" + key}},
				// a bare word is a path relative to cwd (bareArgument)
				{Value: "deploy@host", Paths: []string{"deploy@host"}},
			},
		},
		{
			// the other order: same Params and Args, different slot
			`scp ` + `C:\Users\alice\.ssh\` + key + ` -i other host:`,
			[]facts.Element{
				{Value: `C:\Users\alice\.ssh\` + key, Paths: []string{"~/.ssh/" + key}},
				{Param: "-i"},
				{Value: "other", Paths: []string{"other"}},
				{Value: "host:", Paths: []string{"host:"}},
			},
		},
		{
			// the parameter's case as written; Params lower-cases it
			`ssh -I x host`,
			[]facts.Element{{Param: "-I"}, {Value: "x", Paths: []string{"x"}}, {Value: "host", Paths: []string{"host"}}},
		},
		{
			// a value written after the colon stays on its parameter
			`Get-Content -Path:$HOME\notes.txt`,
			[]facts.Element{{Param: "-Path", Value: `$HOME\notes.txt`, Paths: []string{"~/notes.txt"}}},
		},
		{
			// a long option is an argument to PowerShell
			`kubectl --kubeconfig=~\.kube\config get pods`,
			[]facts.Element{
				// an option word's value is a whole value, as in `--kubeconfig <path>`
				{Value: `--kubeconfig=~\.kube\config`, Paths: []string{"--kubeconfig=~/.kube/config", "~/.kube/config"}},
				{Value: "get", Paths: []string{"get"}},
				{Value: "pods", Paths: []string{"pods"}},
			},
		},
		{
			// an expression has no value to resolve
			`Get-Content (Get-Location)`,
			[]facts.Element{{Value: facts.Expr}},
		},
		{
			// a path inside a longer value is a mention, never an element path
			`Write-Host "key: ~\.ssh\id_rsa"`,
			[]facts.Element{{Value: `key: ~\.ssh\id_rsa`, Paths: []string{"key: ~/.ssh/id_rsa"}}},
		},
		{
			`git -- log`,
			[]facts.Element{{Param: "--"}, {Value: "log", Paths: []string{"log"}}},
		},
		{
			`icacls --% C:\x /grant y`,
			[]facts.Element{
				{Value: "--%"},
				// a --% remainder is read word by word, as the program receives it
				{Value: `C:\x /grant y`, Paths: []string{"C:/x", "/grant", "y"}},
			},
		},
	}
	for _, r := range rows {
		f := Read(r.text, env)
		if len(f.Commands) == 0 {
			t.Errorf("%s: no command", r.text)
			continue
		}
		got := f.Commands[0].Elements
		raw := make([]facts.Element, len(got))
		copy(raw, got)
		for i := range raw {
			raw[i].Raw = "" // TestRead_ElementRaw
		}
		if !reflect.DeepEqual(raw, r.want) {
			t.Errorf("%s:\n got %#v\nwant %#v", r.text, got, r.want)
		}
		// Params and Args are the same elements split by kind.
		var params, args []string
		for _, e := range got {
			switch {
			case e.Param != "" && e.Value != "":
				params = append(params, asciiLower(e.Param))
				args = append(args, e.Value)
			case e.Param != "":
				params = append(params, asciiLower(e.Param))
			default:
				args = append(args, e.Value)
			}
		}
		c := f.Commands[0]
		if !reflect.DeepEqual(params, nilIfEmpty(c.Params)) || !reflect.DeepEqual(args, nilIfEmpty(c.Args)) {
			t.Errorf("%s: Elements split = %q %q, Params %q Args %q", r.text, params, args, c.Params, c.Args)
		}
		// Every element path is in Paths.
		for _, e := range got {
			for _, p := range e.Paths {
				if !contains(f.Paths, p) {
					t.Errorf("%s: element path %q missing from Paths %q", r.text, p, f.Paths)
				}
			}
		}
	}
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

func TestDialect(t *testing.T) {
	if got := Read("Get-Date", Env{}).Dialect; got != facts.DialectPowerShell {
		t.Fatalf("Dialect = %q, want %q", got, facts.DialectPowerShell)
	}
	// Even a text the reader cannot follow names its lane.
	if got := Read("Get-Date '", Env{}).Dialect; got != facts.DialectPowerShell {
		t.Fatalf("Dialect on a parse error = %q", got)
	}
}

// TestRead_ElementRaw: an element's source text, which a rule reads where
// Value is Expr: a number (`0`, `1`) is an expression to the parser, and a
// [bool] parameter's value is decided by it (ADR-001 step 5).
func TestRead_ElementRaw(t *testing.T) {
	f := Read(`Set-MpPreference -DisableIOAVProtection 1 -DisableRealtimeMonitoring:$false 'x y' "a`+"`"+`tb"`, Env{})
	if len(f.Commands) != 1 {
		t.Fatalf("commands %d", len(f.Commands))
	}
	var raws []string
	for _, e := range f.Commands[0].Elements {
		raws = append(raws, e.Raw)
	}
	want := []string{"-DisableIOAVProtection", "1", "-DisableRealtimeMonitoring:$false", "'x y'", "\"a`tb\""}
	if !reflect.DeepEqual(raws, want) {
		t.Errorf("Raw = %q, want %q", raws, want)
	}
	if v := f.Commands[0].Elements[1].Value; v != facts.Expr {
		t.Errorf("a number's Value = %q, want %q (it is Raw that carries the digits)", v, facts.Expr)
	}
}
