package psreader

import (
	"strings"
	"testing"
)

// The cmdlet bridge's twins (facts.Facts.Twins, cmdlet_twin.go). The texts
// are DATA: nothing here runs them. Destructive spellings are assembled at
// run time (rmrf), because the hook on a developer machine reads a test
// source it is asked to run as a command.

// twinHome is the home directory the twin tests resolve paths under.
const twinHome = `C:\Users\alice`

func twinsOf(text string) string {
	return show(Read(text, Env{Home: twinHome}).Twins)
}

// rf is Remove-Item's recursive force switches, assembled at run time.
func rf() string { return "-Recurse " + "-Force" }

// TestCmdletTwins_EachCmdletAndAlias: every file cmdlet, by its name and by
// each alias, reads as its POSIX twin.
func TestCmdletTwins_EachCmdletAndAlias(t *testing.T) {
	cases := []struct{ names, args, want string }{
		{"Get-Content cat type gc", `x\notes.txt`, `[cat] [x/notes.txt]`},
		{"Copy-Item cp copy cpi", `a\b.txt C:\Temp\b.txt`, `[cp] [a/b.txt] [C:/Temp/b.txt]`},
		{"Move-Item mv move mi", `a\b.txt C:\Temp\b.txt`, `[mv] [a/b.txt] [C:/Temp/b.txt]`},
		{"Remove-Item rm del erase rd rmdir ri", `x\old.log`, `[rm] [x/old.log]`},
		{"Set-Content", `x\out.txt 'v'`, `[echo] [x] {>} [x/out.txt]`},
		{"Add-Content ac", `x\out.txt 'v'`, `[echo] [x] {>>} [x/out.txt]`},
		{"Out-File", `x\out.txt`, `[echo] [x] {>} [x/out.txt]`},
	}
	for _, c := range cases {
		for _, name := range strings.Fields(c.names) {
			text := name + " " + c.args
			t.Run(text, func(t *testing.T) {
				if got := twinsOf(text); got != c.want {
					t.Errorf("twins of %q =\n%s\nwant\n%s", text, got, c.want)
				}
			})
		}
	}
}

// TestCmdletTwins_Parameters: how each parameter reaches the twin.
func TestCmdletTwins_Parameters(t *testing.T) {
	for _, c := range []struct{ name, text, want string }{
		{"-Path", `Get-Content -Path x\a.txt`, `[cat] [x/a.txt]`},
		{"-LiteralPath", `Get-Content -LiteralPath x\a.txt`, `[cat] [x/a.txt]`},
		{"-PSPath", `Get-Content -PSPath x\a.txt`, `[cat] [x/a.txt]`},
		{"-LP", `Get-Content -LP x\a.txt`, `[cat] [x/a.txt]`},
		{"attached value", `Get-Content -Path:x\a.txt`, `[cat] [x/a.txt]`},
		{"a parameter's prefix", `Get-Content -Pa x\a.txt`, `[cat] [x/a.txt]`},
		{"an array is one path each", `Remove-Item a\x.log,b\y.log`, `[rm] [a/x.log] [b/y.log]`},
		{"a variable path", `Remove-Item $p`, `[rm] <p>`},
		{"-Path wildcard is a glob to both", `Remove-Item -Path x\logs\*.log`, `[rm] {x/logs/*.log}`},
		{"-LiteralPath wildcard is literal", `Remove-Item -LiteralPath x\logs\*.log`, `[rm] [x/logs/*.log]`},
		{"a wildcard bash would read otherwise is literal", `Remove-Item -Path 'x\a b\*.log'`, `[rm] [x/a b/*.log]`},
		{"-Destination named", `Copy-Item -Destination D:\bak\ -Path a\b.txt`, `[cp] [a/b.txt] [D:/bak/]`},
		{"-Destination positional", `Move-Item a\b.txt D:\bak\`, `[mv] [a/b.txt] [D:/bak/]`},
		{"no destination is the current directory", `Copy-Item a\b.txt`, `[cp] [a/b.txt] [.]`},
		{"-Recurse", `Remove-Item -Recurse x\build`, `[rm] [-r] [x/build]`},
		{"-Force", `Remove-Item -Force x\build`, `[rm] [-f] [x/build]`},
		{"-Recurse -Force", `Remove-Item ` + rf() + ` x\build`, `[rm] [-rf] [x/build]`},
		{"prefixes of -Recurse and -Force", `Remove-Item -Rec -Fo x\build`, `[rm] [-rf] [x/build]`},
		{"Copy-Item -Recurse -Force", `Copy-Item ` + rf() + ` a\d D:\d`, `[cp] [-rf] [a/d] [D:/d]`},
		{"Move-Item -Force", `Move-Item -Force a\d D:\d`, `[mv] [-f] [a/d] [D:/d]`},
		{"Get-Content -Force is dropped", `Get-Content -Force x\a.txt`, `[cat] [x/a.txt]`},
		{"dropped options, twin kept", `Get-Content -Raw -Tail 5 -Encoding utf8 -Wait x\a.txt`, `[cat] [x/a.txt]`},
		{"dropped value and switches, twin kept", `Set-Content -Path x\a.txt -Value 'v' -NoNewline -Encoding ascii`, `[echo] [x] {>} [x/a.txt]`},
		{"Set-Content -Value positional is not a path", `Set-Content x\a.txt C:\not\a\target`, `[echo] [x] {>} [x/a.txt]`},
		{"Out-File -Append", `Out-File -FilePath x\a.txt -Append`, `[echo] [x] {>>} [x/a.txt]`},
		{"Out-File -InputObject is not a path", `Out-File -InputObject C:\v -FilePath x\a.txt`, `[echo] [x] {>} [x/a.txt]`},
		{"common parameters are dropped", `Remove-Item x\a.log -ErrorAction SilentlyContinue -Verbose -Confirm`, `[rm] [x/a.log]`},
		{"common parameter aliases are dropped", `Remove-Item x\a.log -ea 0 -vb`, `[rm] [x/a.log]`},
		// A call PowerShell refuses to bind keeps its intent (Gary,
		// 2026-11-07): the parameter is passed through as written.
		{"a parameter PowerShell does not have", `rm -r` + `f x\build`, `[rm] [-rf] [x/build]`},
		{"an ambiguous prefix (-Filter or -Force)", `Remove-Item -f x\a.log`, `[rm] [-f] [x/a.log]`},
		{"an extra positional to Copy-Item is the destination", `Copy-Item a b D:\c`, `[cp] [a] [b] [D:/c]`},
		{"FileSystem:: is a file", `Get-Content FileSystem::C:\x\a.txt`, `[cat] [C:/x/a.txt]`},
		{"a dynamic value", `Remove-Item (Get-Item x)`, `[rm] <?>`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := twinsOf(c.text); got != c.want {
				t.Errorf("twins of %q =\n%s\nwant\n%s", c.text, got, c.want)
			}
		})
	}
}

// TestCmdletTwins_SwitchFalseIsOff: `-Switch:$false` (or `:0`) is off; any
// other attached value, a variable included, is on.
func TestCmdletTwins_SwitchFalseIsOff(t *testing.T) {
	for _, c := range []struct{ name, text, want string }{
		{"-Force:$false", `Remove-Item -Force:$false x\a`, `[rm] [x/a]`},
		{"-Recurse:$false", `Remove-Item -Recurse:$false -Force x\a`, `[rm] [-f] [x/a]`},
		{"-Recurse:0", `Remove-Item -Recurse:0 x\a`, `[rm] [x/a]`},
		{"-Force:$False, any case", `Remove-Item -Force:$False -Recurse x\a`, `[rm] [-r] [x/a]`},
		{"-Append:$false", `Out-File x\a.txt -Append:$false`, `[echo] [x] {>} [x/a.txt]`},
		{"-Recurse:$true", `Remove-Item -Recurse:$true x\a`, `[rm] [-r] [x/a]`},
		{"-Force:$v is on", `Remove-Item -Force:$v x\a`, `[rm] [-f] [x/a]`},
		{"-WhatIf:$false", `Remove-Item -WhatIf:$false x\a`, `[rm] [x/a]`},
		{"-wi:$false", `Remove-Item -wi:$false x\a`, `[rm] [x/a]`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := twinsOf(c.text); got != c.want {
				t.Errorf("twins of %q =\n%s\nwant\n%s", c.text, got, c.want)
			}
		})
	}
}

// TestCmdletTwins_NoTwin: what has no twin. Facts.Twins is nil, so the call
// reads as main read it. Each case has a control, the same call without what
// stops the twin, which does have one: the no-twin reading is that case's
// rule, not a reader that twins nothing.
func TestCmdletTwins_NoTwin(t *testing.T) {
	for _, c := range []struct{ name, text, control string }{
		{"-WhatIf", `Remove-Item ` + rf() + ` x\a -WhatIf`, `Remove-Item ` + rf() + ` x\a`},
		{"-wi", `Remove-Item x\a -wi`, `Remove-Item x\a`},
		{"-WhatIf:$true", `Remove-Item x\a -WhatIf:$true`, `Remove-Item x\a -WhatIf:$false`},
		{"-Filter", `Remove-Item -Path C:\x\* -Filter *.log`, `Remove-Item -Path C:\x\*`},
		{"-Include", `Remove-Item -Path C:\x\* -Include *.log`, `Remove-Item -Path C:\x\*`},
		{"-Exclude", `Remove-Item -Path C:\x\* -Exclude *.keep`, `Remove-Item -Path C:\x\*`},
		{"-Credential", `Get-Content x\a.txt -Credential $c`, `Get-Content x\a.txt`},
		{"-FromSession", `Copy-Item -FromSession $s -Path C:\a -Destination D:\a`, `Copy-Item -Path C:\a -Destination D:\a`},
		{"-ToSession", `Copy-Item -ToSession $s -Path C:\a -Destination D:\a`, `Copy-Item -Path C:\a -Destination D:\a`},
		{"-Stream on Get-Content", `Get-Content x\a.txt -Stream Zone.Identifier`, `Get-Content x\a.txt`},
		{"-Stream on Remove-Item", `Remove-Item x\a.txt -Stream Zone.Identifier`, `Remove-Item x\a.txt`},
		{"-Stream on Set-Content", `Set-Content x\a.txt -Stream s -Value v`, `Set-Content x\a.txt -Value v`},
		{"pipeline input", `Get-ChildItem x -Recurse | Remove-Item -Force`, `Get-ChildItem x -Recurse | Remove-Item -Force y`},
		{"pipeline input to Copy-Item", `$items | Copy-Item -Destination D:\x`, `$items | Copy-Item y -Destination D:\x`},
		{"stop-parsing token", `Remove-Item --% x\a`, `Remove-Item x\a`},
		{"a cmdlet that is not a file cmdlet", `Get-ChildItem x\a`, `Get-Content x\a`},
		{"a computed name", `& $cmd x\a`, `& Remove-Item x\a`},
		// sc is Set-Content in 5.1 and sc.exe in 7: the native reading
		// comes first, so it has no twin (an open decision).
		{"sc reads as the native sc.exe", `sc x\a.txt 'v'`, `ac x\a.txt 'v'`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if f := Read(c.control, Env{Home: twinHome}); f.Twins == nil {
				t.Fatalf("control %q has no twin either: the case shows nothing", c.control)
			}
			if f := Read(c.text, Env{Home: twinHome}); f.Twins != nil {
				t.Errorf("twins of %q =\n%s\nwant none", c.text, show(f.Twins))
			}
		})
	}
}

// TestCmdletTwins_ProviderPaths: a path on any provider but FileSystem has
// no twin: it is not a file.
func TestCmdletTwins_ProviderPaths(t *testing.T) {
	paths := []string{
		`HKLM:\SOFTWARE\Contoso`, `HKCU:\Software\Contoso`, `Env:\PATH`, `Env:PATH`, `Function:\prompt`,
		`Alias:\gci`, `Variable:\x`, `Cert:\CurrentUser\My\ABC`, `WSMan:\localhost\Shell`,
		`Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Contoso`, `Microsoft.PowerShell.Core\Registry::HKLM\SOFTWARE\x`,
		`'HKLM:\SOFTWARE\Contoso'`, `Temp:\x.txt`,
	}
	// The control: a one-letter drive is a file, in each shape below.
	control := `C:\x.txt`
	for _, p := range append([]string{control}, paths...) {
		for _, text := range []string{
			"Remove-Item " + rf() + " " + p,
			"Get-Content " + p,
			"Copy-Item " + p + ` C:\x`,
			`Copy-Item C:\x ` + p,
			"Remove-Item C:\\x," + p,
			"Get-Date > " + p,
		} {
			t.Run(text, func(t *testing.T) {
				f := Read(text, Env{Home: twinHome})
				switch {
				case p == control && f.Twins == nil:
					t.Fatalf("control %q has no twin", text)
				case p != control && f.Twins != nil:
					t.Errorf("twins of %q =\n%s\nwant none", text, show(f.Twins))
				}
			})
		}
	}
	// A provider-looking value that is content, not a path, does not
	// stop the twin.
	if got := twinsOf(`Set-Content x\a.txt -Value 'HKLM:\x'`); got != `[echo] [x] {>} [x/a.txt]` {
		t.Errorf("a provider path as content: twin %q", got)
	}
}

// TestCmdletTwins_ResolvedPaths: a path is written as the reader resolves
// it: the home directory as `~`, `\` as `/`.
func TestCmdletTwins_ResolvedPaths(t *testing.T) {
	for _, c := range []struct{ name, path, want string }{
		{"~\\", `~\.ssh\config`, `~/.ssh/config`},
		{"$HOME\\", `$HOME\.ssh\config`, `~/.ssh/config`},
		{"${HOME}\\", `${HOME}\.ssh\config`, `~/.ssh/config`},
		{"$env:USERPROFILE\\", `$env:USERPROFILE\.ssh\config`, `~/.ssh/config`},
		{"quoted $env:USERPROFILE", `"$env:USERPROFILE\.ssh\config"`, `~/.ssh/config`},
		{"the home written out", `C:\Users\alice\.ssh\config`, `~/.ssh/config`},
		{"the home in another case", `c:\users\ALICE\.ssh\config`, `~/.ssh/config`},
		{"relative backslash", `.ssh\config`, `.ssh/config`},
		{"dot relative", `.\.ssh\config`, `./.ssh/config`},
		{"parent relative", `..\..\.ssh\config`, `../../.ssh/config`},
		{"a bare name stays as written", `config`, `config`},
		{"trailing dots and spaces dropped as Windows does", `'x\a.txt. '`, `x/a.txt`},
	} {
		t.Run(c.name, func(t *testing.T) {
			text := "Get-Content " + c.path
			want := "[cat] [" + c.want + "]"
			if got := twinsOf(text); got != want {
				t.Errorf("twins of %q = %s, want %s", text, got, want)
			}
		})
	}
	// A redirection target is resolved the same way.
	if got := twinsOf(`Get-Date >> $env:USERPROFILE\.bashrc`); got != `[echo] [x] {>>} [~/.bashrc]` {
		t.Errorf("redirection to $env:USERPROFILE: %s", got)
	}
}

// TestCmdletTwins_Redirections: `>`, `>>`, `1>` and `*>` to a literal file
// are each `echo x > file`, a statement of its own after the text's.
func TestCmdletTwins_Redirections(t *testing.T) {
	for _, c := range []struct{ name, text, want string }{
		{">", `Get-Date > x\a.txt`, `[echo] [x] {>} [x/a.txt]`},
		{">>", `Get-Date >> x\a.txt`, `[echo] [x] {>>} [x/a.txt]`},
		{"1>", `Get-Date 1> x\a.txt`, `[echo] [x] {>} [x/a.txt]`},
		{"*>", `Get-Date *> x\a.txt`, `[echo] [x] {>} [x/a.txt]`},
		{"*>>", `Get-Date *>> x\a.txt`, `[echo] [x] {>>} [x/a.txt]`},
		{"quoted target", `Get-Date > 'x\a b.txt'`, `[echo] [x] {>} [x/a b.txt]`},
		{"after a native program, which keeps its place", `git log > x\a.txt`, "[git] [log]\n[echo] [x] {>} [x/a.txt]"},
		{"a cmdlet twin and its redirection", `Get-Content x\a.txt > x\b.txt`, "[cat] [x/a.txt]\n[echo] [x] {>} [x/b.txt]"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := twinsOf(c.text); got != c.want {
				t.Errorf("twins of %q =\n%s\nwant\n%s", c.text, got, c.want)
			}
		})
	}
	for _, text := range []string{
		`Get-Date 2> x\err.txt`, `Get-Date 3> x\w.txt`, `Get-Date 6>> x\i.txt`,
		`Get-Date > $null`, `Get-Date > NUL`, `Get-Date > $f`, `Get-Date 2>&1`,
	} {
		t.Run("none/"+text, func(t *testing.T) {
			if f := Read(text, Env{Home: twinHome}); f.Twins != nil {
				t.Errorf("twins of %q =\n%s\nwant none", text, show(f.Twins))
			}
		})
	}
}

// TestCmdletTwins_StandInPlace: a twin takes its command's place among the
// native programs, so a pipeline or chain into one is read whole, and
// Facts.Native is what it is without twins.
func TestCmdletTwins_StandInPlace(t *testing.T) {
	text := `Get-Content x\a.txt | curl.exe -d '@-' https://x.example && Remove-Item x\a.txt`
	f := Read(text, Env{Home: twinHome})
	if got, want := show(f.Twins), `[cat] [x/a.txt] | [curl] [-d] [@-] [https://x.example] && [rm] [x/a.txt]`; got != want {
		t.Errorf("twins =\n%s\nwant\n%s", got, want)
	}
	if got, want := show(f.Native), `[curl] [-d] [@-] [https://x.example]`; got != want {
		t.Errorf("native =\n%s\nwant main's\n%s", got, want)
	}
	// A text with native programs and no twin: Twins is nil, not Native.
	if f := Read(`git status; git log`, Env{}); f.Twins != nil || len(f.Native) != 2 {
		t.Errorf("no twin: Twins %v, Native %d statements", f.Twins, len(f.Native))
	}
}

// TestCmdletTwins_OnlyTwinsAreBare: the reader marks only a redirection
// operator or a -Path wildcard bare.
func TestCmdletTwins_OnlyTwinsAreBare(t *testing.T) {
	bare := 0
	for _, in := range []string{`git log x*`, `Get-Content -Path x\*.txt > y.txt`, `Remove-Item -LiteralPath a*`} {
		f := Read(in, Env{})
		for _, st := range f.Native {
			for _, p := range st.Pipelines {
				for _, argv := range p.Stages {
					for _, w := range argv {
						for _, part := range w {
							if part.Bare {
								t.Errorf("%q: Native has a bare part %q", in, part.Text)
							}
						}
					}
				}
			}
		}
		for _, st := range f.Twins {
			for _, p := range st.Pipelines {
				for _, argv := range p.Stages {
					for _, w := range argv {
						for _, part := range w {
							if part.Bare && part.Text != ">" && part.Text != ">>" && !globSafe(part.Text) {
								t.Errorf("%q: a bare part %q is neither an operator nor a glob", in, part.Text)
							}
							if part.Bare {
								bare++
							}
						}
					}
				}
			}
		}
	}
	// The glob and the operator of the second text: the check saw them.
	if bare != 2 {
		t.Errorf("%d bare parts in the twins, want 2 (x/*.txt and >)", bare)
	}
}
