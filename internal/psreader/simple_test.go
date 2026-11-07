package psreader

import "testing"

// facts.Facts.Simple: one command with literal arguments, and nothing else.
// The back end's narrow exceptions (a known read of a self-protected path, a
// credential in a consumer's slot) rest on it, so a false "simple" is a
// bypass and a false "not simple" is only a stricter decision.
func TestSimple(t *testing.T) {
	cfg := `~\.agentshield\policy.yaml`
	simple := []string{
		`Get-Content ` + cfg,
		`Get-Content -Path ` + cfg + ` -Raw`,
		`gc ` + cfg,
		`Get-Content '` + cfg + `'`,
		`Get-Content "` + cfg + `"`,
		`Select-String -Path ` + cfg + ` -Pattern mode`,
		`Get-Content ` + cfg + ` -Tail 5`,
		`Get-ChildItem C:\Users\alice\.agentshield -Recurse`,
		`ssh -i ~\.ssh\id_ed25519 deploy@host.example`,
		`kubectl --kubeconfig=~\.kube\config get pods`,
		`kubectl --kubeconfig ~\.kube\config get pods`,
		`ssh-add ~\.ssh\id_ed25519`,
		"  Get-Content x\r\n", // surrounding blank lines
		`Get-Content "a;b|c"`, // separators inside a string are text
		`Get-Content 'a$b'`,   // single quotes expand nothing
		`Get-Item *.yaml`,
		`Get-Content $env:USERPROFILE\.ssh\id_ed25519`,
		`Get-Content $HOME/notes.txt`,
		`Get-Content $env:userprofile`,
		`Get-Content "$env:USERPROFILE\notes.txt"`,
		`Get-Content "$HOME.old"`, // in a string the dot is text
	}
	for _, text := range simple {
		if f := Read(text, Env{}); !f.Simple {
			t.Errorf("not Simple, want Simple: %s\n  facts %+v", text, f)
		}
	}

	notSimple := []string{
		// code the commands do not show
		`(Get-Item ` + cfg + `).Delete()`,
		`[IO.File]::WriteAllText((Resolve-Path ` + cfg + `), $null)`,
		`$x = Get-Item ` + cfg,
		`Get-Item ` + cfg + ` | Remove-Item`,
		`Get-Content ` + cfg + ` > ~\x`,
		`Get-Content ` + cfg + `; Remove-Item ~\x`,
		"Get-Content x\nRemove-Item y",
		"Get-Content x\rRemove-Item y",
		`Get-Content ` + cfg + ` &`,
		`Get-Content $(Remove-Item x)`,
		`Get-Content "$(Remove-Item x)"`,
		`Get-Content "` + "`" + `$x"`,
		`Get-Content $p`,
		`Get-Content $env:USERPROFILE.Length`, // a member access
		`Get-Content $HOME.Length`,
		`Get-Content $home[0]`,
		`Get-Content $p\x`, // only $HOME and $env:NAME
		`Get-Content $env:A:b`,
		`Get-Content "${env:USERPROFILE}"`,
		`Get-Content "$p"`,
		`Get-Content a$b`,             // `$` mid-word expands a variable
		`Get-Content ~\$p`,            // likewise after a separator
		`kubectl --kubeconfig=$p get`, // likewise after `=`
		`Get-Content @args`,
		`Get-Content @{a=1}`,
		`Get-Content -Path:` + cfg, // an attached value
		`Get-Content a,b`,         // an array
		`Get-Content {Remove-Item x}`,
		`Get-Content [x]`,
		`Get-Content x # comment`,
		`Get-Content x ` + "`",
		`& Get-Content x`,
		`. Get-Content x`,
		`.\tool.ps1 x`,
		`C:\Windows\notepad.exe x`,
		`Microsoft.PowerShell.Management\Get-Content x`,
		`Get-Content --% x`,
		`Get-Content -- x`,
		`Get-Content 'a''b'`, // an escaped quote
		`Get-Content 'a'b`,   // a string joined to a word
		`if (1) { Get-Content x }`,
		`return x`,
		"",
		"Get-Content x\u00a0y",            // no-break space
		"Get-Content \u2013Path x",        // en dash parameter
		"Get-Content 'a\u2018; rm x; \u2019'", // a curly quote closes the string
		`cmd /c type x`,                   // nested text is read again, not here
	}
	for _, text := range notSimple {
		if f := Read(text, Env{}); f.Simple {
			t.Errorf("Simple, want not Simple: %q\n  facts %+v", text, f)
		}
	}
}

// A reader that fails part way leaves Simple false: the failure is a note,
// and Simple needs none.
func TestSimple_FalseAfterAnInternalFailure(t *testing.T) {
	text := "Get-Content x -Raw"
	if !Read(text, Env{}).Simple {
		t.Fatal("control: want Simple")
	}
	failed := 0
	for step := 1; step <= 50; step++ {
		f := read(text, Env{}, step)
		if len(f.Notes) == 0 {
			continue // the reader finished before this step
		}
		failed++
		if f.Simple {
			t.Errorf("panic at step %d: Simple stayed true (notes %v)", step, f.Notes)
		}
	}
	if failed == 0 {
		t.Fatal("no step failed: the test checked nothing")
	}
}
