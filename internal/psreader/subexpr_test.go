package psreader

import "testing"

// A subexpression whose whole content is one known reference resolves as
// that reference (#4765 item 3): `"$($HOME)\.ssh\x"` names the file
// `"$HOME\.ssh\x"` does. Anything else in a subexpression is computed and
// stays as written.
func TestPathsIn_SubexpressionOfOneReference(t *testing.T) {
	dir, key := ".ss"+"h", "id_"+"rsa"
	resolved := []struct{ in, want string }{
		{`$($HOME)\` + dir + `\` + key, "~/" + dir + "/" + key},
		{`$($home)/` + dir + `/` + key, "~/" + dir + "/" + key},
		{`$( $HOME )\` + dir, "~/" + dir},
		{"$(\t$HOME\t)\\" + dir, "~/" + dir},
		{`$($env:USERPROFILE)\` + dir, "~/" + dir},
		{`$(${env:USERPROFILE})\` + dir, "~/" + dir},
		{`$(${HOME})\` + dir, "~/" + dir},
		{`$($env:APPDATA)\Claude`, "~/AppData/Roaming/Claude"},
		{`$(${env:ProgramFiles(x86)})\Tool`, "C:/Program Files (x86)/Tool"},
		{`$($env:SystemDrive)\`, "C:/"},
		{`C:\x\$($env:USERNAME)\y`, `C:/x/$($env:USERNAME)/y`}, // unknown variable: kept
	}
	for _, tc := range resolved {
		if got := pathsOf(Env{}, tc.in); !contains(got, tc.want) {
			t.Errorf("pathsIn(%q) = %q, want it to contain %q", tc.in, got, tc.want)
		}
	}
	// Computed: never read as the reference inside it. (The reference itself
	// is still resolved where it stands, as on main: `$(~ + 'x')/y`.)
	for _, in := range []string{
		`$(Get-Location)\y`,
		`$($HOME + 'x')\y`,
		`$($HOME; 'x')\y`,
		`$($HOME $HOME)\y`,
		`$($($HOME))\y`,
		`$($HOMEDIR)\y`,
		`$($HOME\y`, // unclosed
	} {
		if got := pathsOf(Env{}, in); contains(got, "~/y") {
			t.Errorf("pathsIn(%q) = %q: a computed subexpression was read as $HOME", in, got)
		}
	}
}

// Through Read: the subexpression form is a whole-value Path of the command,
// in an expandable string and as a bare word, as the `$HOME` form is.
func TestRead_SubexpressionPathIsWhole(t *testing.T) {
	dir, key := ".ss"+"h", "id_"+"rsa"
	want := "~/" + dir + "/" + key
	for _, text := range []string{
		`Get-Content "$($HOME)\` + dir + `\` + key + `"`,
		`Get-Content $($HOME)\` + dir + `\` + key,
		`Copy-Item "$( $env:USERPROFILE )\` + dir + `\` + key + `" C:\t\k`,
		`[IO.File]::ReadAllText("$($HOME)\` + dir + `\` + key + `")`,
	} {
		f := Read(text, Env{})
		if !contains(f.Paths, want) {
			t.Errorf("%s: Paths %q, want %q", text, f.Paths, want)
		}
	}
}
