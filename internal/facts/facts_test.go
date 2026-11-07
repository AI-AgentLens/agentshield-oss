package facts

import (
	"reflect"
	"testing"
)

func TestCommandNames(t *testing.T) {
	c := Command{Name: "invoke-webrequest", Alternatives: make([]string, 1, 4)}
	c.Alternatives[0] = "curl"
	got := c.Names()
	if want := []string{"invoke-webrequest", "curl"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Names() = %q, want %q", got, want)
	}
	// Names returns a new slice: writing to it never reaches the command.
	got[1] = "changed"
	if c.Alternatives[0] != "curl" {
		t.Fatalf("Names() aliases Alternatives")
	}
	if got := (Command{Name: "get-date"}).Names(); !reflect.DeepEqual(got, []string{"get-date"}) {
		t.Fatalf("Names() without alternatives = %q", got)
	}
}

// ADR-001 decision 1: a rule's parameter matches every non-empty prefix of
// it, letter case ignored.
func TestParamMatches(t *testing.T) {
	rows := []struct {
		written, rule string
		want          bool
	}{
		{"-recurse", "-Recurse", true},
		{"-Recurse", "-recurse", true},
		{"-Rec", "-Recurse", true},
		{"-re", "-Recurse", true},
		{"-r", "-Recurse", true},
		{"-REC", "-Recurse", true},
		{"-recursex", "-Recurse", false}, // longer than the parameter
		{"-rek", "-Recurse", false},
		{"-force", "-Recurse", false},
		{"-", "-Recurse", false},  // a dash names no parameter
		{"", "-Recurse", false},   // nothing written
		{"--", "-Recurse", false}, // ends parameter binding
		{"--rec", "-Recurse", false},
		{"rec", "-Recurse", false}, // an argument, not a parameter
		{"-rec", "", false},
		{"-rec", "-", false},
		{"-rec", "Recurse", false},          // a rule parameter needs its dash
		{"-Key", "-Key", false},        // KELVIN SIGN: not ASCII k, as PowerShell compares
		{"-key", "-Key", true},         // plain ASCII spelled with an escape
		{"-encodedcommand", "-EncodedCommand", true},
		{"-e", "-EncodedCommand", true}, // the abbreviation the rule exists for
	}
	for _, r := range rows {
		if got := ParamMatches(r.written, r.rule); got != r.want {
			t.Errorf("ParamMatches(%q, %q) = %v, want %v", r.written, r.rule, got, r.want)
		}
	}
}
