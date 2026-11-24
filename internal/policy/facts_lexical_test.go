package policy

import (
	"reflect"
	"slices"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/facts"
	"github.com/AI-AgentLens/agentshield/internal/psreader"
)

// #4830: the lexical second reading of a lane's facts. Attack paths are
// assembled at runtime (asDir, sshKey): the hook reads test sources it runs.

func TestLexicalPath(t *testing.T) {
	const home = "C:/Users/alice"
	cases := []struct {
		in, home, want string
		ok             bool
	}{
		{"~/x/../.ssh/" + sshKey, home, "~/.ssh/" + sshKey, true},
		{`~\x\..\` + asDir + `\audit.jsonl`, home, "~/" + asDir + "/audit.jsonl", true},
		{"~/./" + asDir, home, "~/" + asDir, true},
		{"~/../alice/.ssh/" + sshKey, home, "~/.ssh/" + sshKey, true},          // above ~ and back
		{"~/../bob/.ssh/" + sshKey, home, "C:/Users/bob/.ssh/" + sshKey, true}, // another profile
		{"~/../bob/x", "", "", false},                                          // above ~ with no home: as written
		{"~/a/../b", "", "~/b", true},                                          // within ~, no home needed
		{"/./Users/alice/" + asDir + "/" + asFile, "/Users/alice", "~/" + asDir + "/" + asFile, true},
		{"/Users/ALICE/./" + asDir, "/Users/alice", "~/" + asDir, true}, // home folded case-insensitively
		{`C:\x\..\Windows\System32`, home, "C:/Windows/System32", true},
		{`C:\..\Windows`, home, "C:/Windows", true}, // `..` at a root is dropped
		{`C:..\x`, home, "", false},                 // drive-relative: no root to clamp at
		{`\\srv\share\..\x`, home, "//srv/share/x", true},
		{`\\srv\share\a\..`, home, "//srv/share", true},
		{`.\audit.jsonl`, home, "audit.jsonl", true},
		{`..\x`, home, "", false}, // a relative `..` past the start stays: cwd decides it
		{`a\..\..\x`, home, "../x", true},
		{"~/.ssh/" + sshKey, home, "", false}, // no dot segment
		{"~/...", home, "", false},            // `...` is a name
		{"~/.x", home, "", false},
	}
	for _, tc := range cases {
		got, ok := lexicalPath(tc.in, tc.home)
		if got != tc.want || ok != tc.ok {
			t.Errorf("lexicalPath(%q, %q) = %q, %v; want %q, %v", tc.in, tc.home, got, ok, tc.want, tc.ok)
		}
	}
}

// The reading adds, never replaces, and leaves the as-written facts alone.
func TestFactsLexicalReading_AddsAndCopies(t *testing.T) {
	f := psFacts(`Remove-Item x.txt, ~\x\..\` + asDir + `\audit.jsonl`)
	before := deepCopyFacts(f)
	g, ok := factsLexicalReading(f, psHome, "")
	if !ok {
		t.Fatal("no lexical reading for a `..` path in an array")
	}
	if !reflect.DeepEqual(f, before) {
		t.Fatal("the as-written facts changed: the first reading must stay main's")
	}
	clean := "~/" + asDir + "/audit.jsonl"
	if !slices.Contains(g.Paths, clean) {
		t.Errorf("Paths %q lack the clean spelling %q", g.Paths, clean)
	}
	for _, p := range f.Paths {
		if !slices.Contains(g.Paths, p) {
			t.Errorf("the reading dropped %q", p)
		}
	}
	el := g.Commands[0].Elements[0]
	if !slices.Contains(el.Paths, "x.txt") || !slices.Contains(el.Paths, clean) {
		t.Errorf("element Paths %q, want the items and the clean spelling", el.Paths)
	}
	if _, ok := factsLexicalReading(psFacts(`Get-Content ~\.ssh\`+sshKey), psHome, "/tmp/x"); ok {
		t.Error("a text with no dot segment and no array has a second reading")
	}
}

// cmpHome is the home a row's reader folds: the lane's, else psHome.
func cmpHome(opt FactsOptions) string {
	if opt.Home != "" {
		return opt.Home
	}
	return psHome
}

func factsWithHome(text, home string) facts.Facts {
	return psreader.Read(text, psreader.Env{Home: home})
}

func deepCopyFacts(f facts.Facts) facts.Facts {
	g := f
	g.Paths = slices.Clone(f.Paths)
	g.Mentions = slices.Clone(f.Mentions)
	g.Commands = slices.Clone(f.Commands)
	for i, c := range g.Commands {
		els := slices.Clone(c.Elements)
		for j, el := range els {
			el.Paths = slices.Clone(el.Paths)
			el.ItemPaths = slices.Clone(el.ItemPaths)
			els[j] = el
		}
		g.Commands[i].Elements = els
	}
	return g
}

// The gaps #4830 lists, each against its clean spelling as the control: the
// control decides BLOCK naming the rule on main, and so does the spelling.
func TestEvaluateFacts_LexicalReading_ClosesTheGaps(t *testing.T) {
	engine := communityEngine(t)
	log := `~\` + asDir + `\audit.jsonl`
	rows := []struct {
		name, control, ps, rule string
		opt                     FactsOptions
		cwd                     string
	}{
		{"array item, log tamper", `Remove-Item ` + log, `Remove-Item x.txt, ` + log, "ps-block-agentshield-log-tamper", FactsOptions{}, ""},
		{"array item, -Path", `Remove-Item -Path ` + log + ` -Force`, `Remove-Item -Recurse -Force -Path x,` + log, "ps-block-agentshield-log-tamper", FactsOptions{}, ""},
		{"dot segment, log tamper", `Remove-Item ` + log, `Remove-Item ~\.\` + asDir + `\audit.jsonl`, "ps-block-agentshield-log-tamper", FactsOptions{}, ""},
		{"dot-dot segment, log tamper", `Clear-Content ` + log, `Clear-Content ~\x\..\` + asDir + `\audit.jsonl`, "ps-block-agentshield-log-tamper", FactsOptions{}, ""},
		{"dot-dot before the home, key read", `Get-Content ~\.ssh\` + sshKey, `Get-Content C:\Windows\..\Users\alice\.ssh\` + sshKey, ProtectedPathRuleID, FactsOptions{Home: psHome}, ""},
		{"slash-dot root, key read", `Get-Content ~/.ssh/` + sshKey, `Get-Content /./Users/alice/.ssh/` + sshKey, ProtectedPathRuleID, FactsOptions{Home: "/Users/alice"}, ""},
		{"slash-dot root, managed config", `Clear-Content ` + psCfg, `Clear-Content /./Users/alice/` + asDir + `/` + asFile, SelfProtectRuleID, FactsOptions{Managed: true, Home: "/Users/alice"}, ""},
		{"dot-dot before the home, managed config", `Set-Content ` + psCfg + ` x`, `Set-Content C:\x\..\Users\alice\` + asDir + `\` + asFile + ` x`, SelfProtectRuleID, FactsOptions{Managed: true, Home: psHome}, ""},
		// A pack rule's glob is written with `~`, which only the home fold
		// gives a path spelled from `/` (protected-path expands the pattern).
		{"slash-dot root, log tamper", `Remove-Item ` + log, `Remove-Item /./Users/alice/` + asDir + `/audit.jsonl`, "ps-block-agentshield-log-tamper", FactsOptions{Home: "/Users/alice"}, ""},
		// A bare item name is a path under cwd, as a lone bare argument is
		// (#4381); main kept the item out of Facts.Paths.
		{"bare array item in a key directory", `Get-Content ` + sshKey, `Get-Content notes.txt, ` + sshKey, ProtectedPathRuleID, FactsOptions{Home: absPath("/Users/alice")}, absPath("/Users/alice/.ssh")},
		// `$PWD` with cwd at home (#4830): the reader keeps the variable.
		{"PWD: managed config write", `Set-Content ` + psCfg + ` x`, `Set-Content "$PWD\` + asDir + `\notes.txt" x`, SelfProtectRuleID, FactsOptions{Managed: true, Home: "/Users/alice"}, "/Users/alice"},
		{"PWD: braced, redirect", `Set-Content ` + psCfg + ` x`, `'x' > "${PWD}\` + asDir + `\notes.txt"`, SelfProtectRuleID, FactsOptions{Managed: true, Home: "/Users/alice"}, "/Users/alice"},
		{"PWD: Path property, Out-File", `Set-Content ` + psCfg + ` x`, `'x' | Out-File "$($PWD.Path)\` + asDir + `\notes.txt"`, SelfProtectRuleID, FactsOptions{Managed: true, Home: "/Users/alice"}, "/Users/alice"},
		{"PWD: lower case, key read", `Get-Content ~/.ssh/` + sshKey, `Get-Content $pwd/.ssh/` + sshKey, ProtectedPathRuleID, FactsOptions{Home: "/Users/alice"}, "/Users/alice"},
		{"PWD: Windows cwd, log tamper", `Remove-Item ` + log, `Remove-Item $PWD\` + asDir + `\audit.jsonl`, "ps-block-agentshield-log-tamper", FactsOptions{Home: psHome}, `C:\Users\alice`},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			cwd := "/tmp/agentshield-ps-lexical"
			if r.cwd != "" {
				cwd = r.cwd
			}
			control := engine.EvaluateFacts(factsWithHome(r.control, cmpHome(r.opt)), cwd, r.opt)
			if control.Decision != DecisionBlock || !slices.Contains(control.TriggeredRules, r.rule) {
				t.Fatalf("control %q decides %s %v, want BLOCK naming %s", r.control, control.Decision, control.TriggeredRules, r.rule)
			}
			f := factsWithHome(r.ps, cmpHome(r.opt))
			asWritten := engine.evaluateFactsReading(f, cwd, r.opt, engine.factsHome(r.opt))
			if asWritten.Decision == DecisionBlock {
				t.Fatalf("%q already BLOCKs as written (%v): not a gap this reading closes", r.ps, asWritten.TriggeredRules)
			}
			got := engine.EvaluateFacts(f, cwd, r.opt)
			if got.Decision != DecisionBlock || !slices.Contains(got.TriggeredRules, r.rule) {
				t.Errorf("%q decides %s %v, want BLOCK naming %s", r.ps, got.Decision, got.TriggeredRules, r.rule)
			}
		})
	}
}

// The second reading never lowers: on every row it applies to, the result
// ranks at least as the as-written reading does, and an as-written BLOCK
// keeps its record.
func TestEvaluateFacts_LexicalReading_NeverLowers(t *testing.T) {
	engine := communityEngine(t)
	texts := []string{
		`Get-Content ~\x\..\.ssh\` + sshKey + `; Remove-Item ~\.ssh\` + sshKey2,
		`Remove-Item ~\.ssh\` + sshKey + `, .\x\..\y`,
		`Copy-Item ~\.aws\credentials, a.txt C:\tmp\.\out`,
		`Get-Content .\README.md, ..\notes.txt`,
		`Remove-Item .\build\..\dist -Recurse`,
		`Set-Content ~\` + asDir + `\..\x.txt y`,
	}
	for _, mode := range []FactsOptions{{}, {Managed: true}} {
		for _, text := range texts {
			f := psFacts(text)
			asWritten := engine.evaluateFactsReading(f, "/tmp/agentshield-ps-lexical", mode, engine.factsHome(mode))
			got := engine.EvaluateFacts(f, "/tmp/agentshield-ps-lexical", mode)
			if preDowngradeRank(got) < preDowngradeRank(asWritten) {
				t.Errorf("managed=%v %q: %s %v, as written %s %v: the reading lowered", mode.Managed, text, got.Decision, got.TriggeredRules, asWritten.Decision, asWritten.TriggeredRules)
			}
			if asWritten.Decision == DecisionBlock && !reflect.DeepEqual(record(got), record(asWritten)) {
				t.Errorf("managed=%v %q: a BLOCK's record moved: %+v, as written %+v", mode.Managed, text, record(got), record(asWritten))
			}
		}
	}
}

// The reading names only the file the call names: a `..` that climbs out
// of a protected directory, an array of harmless names, `$PWD` after a
// location change and `$PWD` naming an ordinary file decide exactly as
// written. The cwd is the home, so a `$PWD` reading would name the config.
func TestEvaluateFacts_LexicalReading_Negatives(t *testing.T) {
	engine := communityEngine(t)
	for _, text := range []string{
		`Get-Content C:\Users\alice\.ssh\..\notes.txt`,
		`Remove-Item /./tmp/` + asDir + `/../scratch.txt`,
		`Get-Content .\docs\..\README.md`,
		`Remove-Item x.txt, y.txt`,
		`Stop-Service WinDefend,WdNisSvc -WhatIf`,
		// $PWD after a location change is another directory: not read as cwd.
		`Set-Location C:\proj; Set-Content $PWD\` + asDir + `\notes.txt x`,
		`cd C:\proj; Remove-Item $PWD\` + asDir + `\audit.jsonl`,
		`Push-Location C:\proj; Set-Content "$PWD\` + asDir + `\notes.txt" x`,
		// $PWD naming an ordinary file, and a variable that only starts with PWD.
		`Get-Content $PWD\README.md`,
		`Set-Content $PWDX\` + asDir + `\notes.txt x`,
	} {
		f := psFacts(text)
		const cwd = `C:\Users\alice`
		asWritten := engine.evaluateFactsReading(f, cwd, FactsOptions{Home: psHome}, psHome)
		got := engine.EvaluateFacts(f, cwd, FactsOptions{Home: psHome})
		if !reflect.DeepEqual(record(got), record(asWritten)) {
			t.Errorf("%q: %+v, as written %+v: the reading named a file the call does not", text, record(got), record(asWritten))
		}
	}
}

func TestPWDPath(t *testing.T) {
	const home = "C:/Users/alice"
	cases := []struct {
		in, pwd, want string
		ok            bool
	}{
		{"$PWD/" + asDir + "/x", "C:/Users/alice", "~/" + asDir + "/x", true},
		{`$pwd\` + asDir, "C:/Users/alice", "~/" + asDir, true},
		{"${PWD}/a/../" + asDir, "C:/Users/alice", "~/" + asDir, true},
		{"$($PWD.Path)/x", "/srv/app", "/srv/app/x", true},
		{"$($pwd)/x", "/srv/app", "/srv/app/x", true},
		{"$PWD", "/srv/app", "/srv/app", true},
		{"$PWDX/x", "/srv/app", "", false},    // another variable
		{"x/$PWD/y", "/srv/app", "", false},   // not leading
		{"$PWD/x", "", "", false},             // no pwd: a location change, or no usable cwd
		{"$env:PWD/x", "/srv/app", "", false}, // an environment variable, resolved by the reader if set
	}
	for _, tc := range cases {
		got, ok := pwdPath(tc.in, tc.pwd, home)
		if got != tc.want || ok != tc.ok {
			t.Errorf("pwdPath(%q, %q) = %q, %v; want %q, %v", tc.in, tc.pwd, got, ok, tc.want, tc.ok)
		}
	}
}

func TestFactsPWD(t *testing.T) {
	for _, tc := range []struct{ text, cwd, want string }{
		{`Set-Content $PWD\x y`, `C:\Users\alice`, "C:/Users/alice"},
		{`Set-Content $PWD\x y`, "/Users/alice/", "/Users/alice"},
		{`Set-Content $PWD\x y`, "relative/dir", ""},
		{`sl C:\x; Set-Content $PWD\x y`, "/Users/alice", ""},
		{`pushd C:\x; Set-Content $PWD\x y; popd`, "/Users/alice", ""},
		{`& $c; Set-Content $PWD\x y`, "/Users/alice", ""}, // a computed command could be cd
	} {
		if got := factsPWD(psFacts(tc.text), tc.cwd); got != tc.want {
			t.Errorf("factsPWD(%q, %q) = %q, want %q", tc.text, tc.cwd, got, tc.want)
		}
	}
}
