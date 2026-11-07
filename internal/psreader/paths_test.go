package psreader

import (
	"sort"
	"strings"
	"testing"
)

func pathsOf(env Env, v string) []string {
	var out []string
	newResolver(env).pathsIn(v, func(p string) { out = append(out, p) })
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestPathsIn_Resolution(t *testing.T) {
	withHomeVars := Env{Home: `C:\Users\alice`, Vars: map[string]string{
		"HOMEDRIVE": "C:", "HOMEPATH": `\Users\alice`, "Temp": `D:\tmp`,
	}}
	cases := []struct {
		name string
		env  Env
		in   string
		want string
	}{
		{"tilde", Env{}, `~\.ssh\id_rsa`, "~/.ssh/id_rsa"},
		{"$HOME", Env{}, `$HOME\.ssh\id_rsa`, "~/.ssh/id_rsa"},
		{"$Home any case", Env{}, `$Home/.ssh/id_rsa`, "~/.ssh/id_rsa"},
		{"${HOME}", Env{}, `${HOME}\.ssh\id_rsa`, "~/.ssh/id_rsa"},
		{"$env:USERPROFILE", Env{}, `$env:USERPROFILE\.aws\credentials`, "~/.aws/credentials"},
		{"$ENV:userprofile", Env{}, `$ENV:userprofile\.aws\credentials`, "~/.aws/credentials"},
		{"${env:USERPROFILE}", Env{}, `${env:USERPROFILE}\.aws\credentials`, "~/.aws/credentials"},
		{"${Env:UserProfile}", Env{}, `${Env:UserProfile}\.aws\credentials`, "~/.aws/credentials"},
		{"%USERPROFILE%", Env{}, `%USERPROFILE%\.ssh\id_rsa`, "~/.ssh/id_rsa"},
		{"APPDATA default", Env{}, `$env:APPDATA\Claude\config.json`, "~/AppData/Roaming/Claude/config.json"},
		{"LOCALAPPDATA default", Env{}, `$env:LOCALAPPDATA\x`, "~/AppData/Local/x"},
		{"APPDATA from Env, folded", testEnv, `$env:APPDATA\Claude`, "~/AppData/Roaming/Claude"},
		{"TEMP from Env, any case", withHomeVars, `$env:TEMP\x.ps1`, "D:/tmp/x.ps1"},
		{"HOMEDRIVE+HOMEPATH", withHomeVars, `$env:HOMEDRIVE$env:HOMEPATH\.ssh\id_rsa`, "~/.ssh/id_rsa"},
		{"ProgramFiles(x86)", Env{}, `${env:ProgramFiles(x86)}\Tool\x.exe`, "C:/Program Files (x86)/Tool/x.exe"},
		{"home written out", testEnv, `C:\Users\alice\.ssh\id_rsa`, "~/.ssh/id_rsa"},
		{"home written out, other case", testEnv, `c:/USERS/Alice/.ssh/id_rsa`, "~/.ssh/id_rsa"},
		{"home itself", testEnv, `C:\Users\alice`, "~"},
		{"home prefix is not a longer name", testEnv, `C:\Users\alicex\y`, "C:/Users/alicex/y"},
		{"POSIX home", Env{Home: "/Users/alice/"}, "/Users/alice/.ssh/id_rsa", "~/.ssh/id_rsa"},
		{"doubled separators", testEnv, `C:\\Users\\alice\\.ssh`, "~/.ssh"},
		{"UNC keeps its prefix", Env{}, `\\server\share\x`, "//server/share/x"},
		{"file URL", testEnv, "file:///C:/Users/alice/.ssh/id_rsa", "~/.ssh/id_rsa"},
		{"unknown variable kept", Env{}, `$env:NOPE\x`, "$env:NOPE/x"},
		{"other variable kept", Env{}, `$dir\x`, "$dir/x"},
		{"case kept", Env{}, `~\Library\Keychains`, "~/Library/Keychains"},
		{"drive letter alone", Env{}, `D:`, "D:"},
	}
	for _, tc := range cases {
		got := pathsOf(tc.env, tc.in)
		if !contains(got, tc.want) {
			t.Errorf("%s: pathsIn(%q) = %q, want it to contain %q", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestPathsIn_SuffixAfterAnchor(t *testing.T) {
	cases := map[string]string{
		`--key-file=$HOME\.ssh\id_rsa`: "~/.ssh/id_rsa",
		`-Path:C:\secrets\x`:           "C:/secrets/x",
		`a,~\.ssh\config`:              "~/.ssh/config",
		`@~\.aws\credentials`:          "~/.aws/credentials",
	}
	for in, want := range cases {
		if got := pathsOf(Env{}, in); !contains(got, want) {
			t.Errorf("pathsIn(%q) = %q, want it to contain %q", in, got, want)
		}
	}
}

func TestPathsIn_NotPaths(t *testing.T) {
	for _, in := range []string{"", "hello", "Get-Process", "/", "//", "-Recurse", "'quoted'"} {
		if got := pathsOf(testEnv, in); len(got) != 0 {
			t.Errorf("pathsIn(%q) = %q, want none", in, got)
		}
	}
}

// TestRead_PathsFromExpressionStrings: the ADR's reason Strings is in the
// contract. A path that appears only in an assignment or a .NET call is
// still in Paths.
func TestRead_PathsFromExpressionStrings(t *testing.T) {
	cases := map[string]string{
		`$p = '~\.ssh\id_rsa'; Get-Content $p`:                           "~/.ssh/id_rsa",
		`[IO.File]::ReadAllText("$env:USERPROFILE\.aws\credentials")`:    "~/.aws/credentials",
		`$k = @{ Path = "$HOME\.kube\config" }; Get-Item @k`:             "~/.kube/config",
		`Get-Content -Path $env:USERPROFILE\.ssh\id_rsa`:                 "~/.ssh/id_rsa",
		`type C:\Users\alice\.ssh\id_rsa`:                                "~/.ssh/id_rsa",
		`Copy-Item -Destination:"$env:APPDATA\x" -Path ~\.netrc`:         "~/.netrc",
		"Get-Content ~\\.s`sh\\id_rsa":                                   "~/.ssh/id_rsa",
		`cmd /c type "%USERPROFILE%\.ssh\id_rsa"`:                        "~/.ssh/id_rsa",
		`Get-Item "${env:ProgramFiles(x86)}\Microsoft\Edge\Application"`: "C:/Program Files (x86)/Microsoft/Edge/Application",
	}
	for in, want := range cases {
		if got := Read(in, testEnv).Paths; !contains(got, want) {
			t.Errorf("Read(%q).Paths = %q, want it to contain %q", in, got, want)
		}
	}
}

// TestRead_RawScanFindsWhatTheReaderSkips: a class body is not read (it
// carries a parse_error note), and a comment is not a command, yet a path in
// either reaches Mentions through the raw-text scan. Not Paths: the scan
// cannot tell a use from a mention, so it never makes a path alone.
func TestRead_RawScanFindsWhatTheReaderSkips(t *testing.T) {
	cases := map[string]string{
		`class C { [string] M() { return (Get-Content ~\.ssh\id_rsa) } }`: "~/.ssh/id_rsa",
		`Get-Date # then $env:USERPROFILE\.aws\credentials`:               "~/.aws/credentials",
	}
	for in, want := range cases {
		f := Read(in, testEnv)
		if !contains(f.Mentions, want) || contains(f.Paths, want) {
			t.Errorf("Read(%q): Paths %q, Mentions %q; want %q among the mentions only", in, f.Paths, f.Mentions, want)
		}
	}
	// An unclosed quote is read to the end of the text: the reader still
	// has the argument, so it is a whole value (and a parse_error note).
	in := `Get-Content 'C:\Users\alice\.ssh\id_rsa`
	if f := Read(in, testEnv); !contains(f.Paths, "~/.ssh/id_rsa") {
		t.Errorf("Read(%q).Paths = %q, want the unclosed argument's path", in, f.Paths)
	}
}

// TestRead_PathsAreReaderUnionRawScan: Paths and Mentions together are
// exactly the reader's spellings plus the raw scan's. The scan adds; it never
// removes or replaces. Paths are the whole values among them (each value's
// own spelling, a `--%` remainder word by word); Mentions are the rest, and
// none is in both.
func TestRead_PathsAreReaderUnionRawScan(t *testing.T) {
	var n int
	for _, c := range corpusSpecs {
		rows, _ := loadCorpus(t, "testdata", c.name, 76)
		for _, row := range rows {
			text := row.Command
			res := newResolver(testEnv)
			r := &reader{s: []rune(text)}
			r.statements(0)
			want, wantWhole := map[string]bool{}, map[string]bool{}
			add := func(p string) { want[p] = true }
			whole := func(p string) { want[p], wantWhole[p] = true, true }
			for _, cmd := range r.cmds {
				if cmd.name != "<dynamic>" {
					res.valuePaths(cmd.name, whole, add)
				}
				for _, el := range cmd.elems {
					for _, v := range elementValues(el) {
						res.argumentValuePaths(v, whole, add)
					}
				}
			}
			for _, s := range r.strs {
				res.valuePaths(s, whole, add)
			}
			for _, rt := range r.redirs {
				if p, ok := res.redirectionTarget(rt); ok {
					whole(p)
				}
			}
			readerOnly := len(want)
			res.rawPaths(text, add)
			f := Read(text, testEnv)
			for _, nst := range f.Nested {
				res.rawPaths(nst.Text, add)
			}
			got := map[string]bool{}
			for _, p := range f.Paths {
				got[p] = true
				if !wantWhole[p] {
					t.Errorf("%s: Paths holds %q, which is not a whole value", idKey(row.ID), p)
				}
			}
			for p := range wantWhole {
				if !got[p] {
					t.Errorf("%s: whole value %q missing from Paths", idKey(row.ID), p)
				}
			}
			for _, p := range f.Mentions {
				if got[p] {
					t.Errorf("%s: %q is in both Paths and Mentions", idKey(row.ID), p)
				}
				got[p] = true
			}
			if len(got) != len(f.Paths)+len(f.Mentions) {
				t.Fatalf("%s: Paths or Mentions holds duplicates", idKey(row.ID))
			}
			if len(got) != len(want) || readerOnly > len(got) {
				var miss, extra []string
				for p := range want {
					if !got[p] {
						miss = append(miss, p)
					}
				}
				for p := range got {
					if !want[p] {
						extra = append(extra, p)
					}
				}
				sort.Strings(miss)
				sort.Strings(extra)
				t.Errorf("%s: Paths ∪ Mentions is not reader ∪ raw scan: missing %q, unexpected %q", idKey(row.ID), miss, extra)
			}
			n++
		}
	}
	if n < 450 {
		t.Fatalf("checked %d inputs, want >= 450", n)
	}
}

func TestRawPaths_QuotedSpanKeepsSpaces(t *testing.T) {
	var got []string
	newResolver(Env{}).rawPaths(`Remove-Item -LiteralPath 'C:\Program Files\Tool\x.dll' -Force`, func(p string) { got = append(got, p) })
	if !contains(got, "C:/Program Files/Tool/x.dll") {
		t.Fatalf("raw scan = %q, want the quoted path whole", got)
	}
	if strings.Contains(strings.Join(got, "|"), "'") {
		t.Errorf("raw scan kept a quote: %q", got)
	}
}
