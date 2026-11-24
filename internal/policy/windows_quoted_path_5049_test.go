package policy

import (
	"runtime"
	"slices"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/testhome"
)

// #5049: a quoted native Windows path lost its protected-path BLOCK, because
// StripShellQuotes deleted every backslash, including the ones Git Bash keeps
// inside quotes. These rows run the hook's path: NormalizeCommand, then the
// engine, against ~/.ssh/**, ~/.aws/** and a customer's absolute pattern.
//
// Git Bash 5.2 on Windows 10 opens the file for every BLOCK row (measured in
// the PR, one row per shape). Names are assembled at runtime: the hook reads
// test sources as commands.
func TestQuotedWindowsPathBlocksProtectedPath_5049(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows reading; the POSIX one is pinned by TestQuotedBackslashPOSIXUnchanged_5049")
	}
	home := `C:\Users\zzuser`
	testhome.Set(t, home)
	ssh, aws := "."+"ssh", "."+"aws"
	key, cred := "id_"+"rsa", "credentials"
	vault := `C:\ProgramData\Vault`
	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = []string{"~/" + ssh + "/**", "~/" + aws + "/**", vault + `\**`}
	engine, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	cwd := t.TempDir()
	eval := func(cmd string) EvalResult {
		nc := normalize.NormalizeCommand(cmd, cwd)
		return engine.EvaluateWithParsedCwd(cmd, nc.Paths, nc.Parsed, cwd)
	}

	for _, cmd := range []string{
		// double-quoted
		`cat "` + home + `\` + aws + `/` + cred + `"`,
		`cat "` + home + `\` + ssh + `"/` + key,
		`cat "C:\\Users\\zzuser\\` + ssh + `/` + key + `"`,
		// single-quoted
		`cat '` + home + `\'` + aws + `/` + cred,
		`cp '` + home + `\` + ssh + `'/` + key + ` out.txt`,
		// mixed quoting and ~
		`cat ~/"` + ssh + `\` + key + `"`,
		`cat ~/'` + aws + `\` + cred + `'`,
		`cat "` + home + `"\\` + ssh + `/` + key,
		// a backslash before $ " \ inside double quotes: only " and \ reach
		// the Windows reading (a $ keeps the word as written, on every OS)
		`cat "C:\\Users\\zzuser\\` + aws + `"/` + cred,
		// the customer's absolute pattern, spelled natively
		`cat "` + vault + `\keys"/a.pem`,
		`cat '` + vault + `'/keys/a.pem`,
	} {
		r := eval(cmd)
		if r.Decision != DecisionBlock || !slices.Contains(r.TriggeredRules, ProtectedPathRuleID) {
			t.Errorf("%s\n  %v rules=%v; want BLOCK %s", cmd, r.Decision, r.TriggeredRules, ProtectedPathRuleID)
		}
	}

	// Known gap, pinned so closing it is deliberate: a word whose separators
	// are all backslashes has no `/`, so normalize's looksLikePath never treats
	// it as a path. Git Bash opens each of these. The fix is in normalize, not
	// in StripShellQuotes, and is outside #5049's scope.
	for _, cmd := range []string{
		`cat "` + home + `\` + aws + `\` + cred + `"`,
		`cat '` + home + `\` + ssh + `\` + key + `'`,
		`cat "` + vault + `\keys\a.pem"`,
	} {
		if r := eval(cmd); slices.Contains(r.TriggeredRules, ProtectedPathRuleID) {
			t.Errorf("%s\n  %v rules=%v: the all-backslash gap closed; update this pin and the PR's gap note", cmd, r.Decision, r.TriggeredRules)
		}
	}

	// The MSYS spelling of the same files, the form Git Bash's pwd prints,
	// BLOCKs too: #5021 P-c reads `/c/...` as drive C (pathnorm.FromMSYSDrive),
	// quoted or not, with or without a backslash. This was a pinned gap until
	// P-c landed.
	for _, cmd := range []string{
		`cat "/c/Users/zzuser/` + ssh + `\` + key + `"`,
		`cat '/c/Users/zzuser/` + aws + `'/` + cred,
		`cat "/c/ProgramData/Vault/keys"/a.pem`,
	} {
		if r := eval(cmd); r.Decision != DecisionBlock || !slices.Contains(r.TriggeredRules, ProtectedPathRuleID) {
			t.Errorf("%s\n  %v rules=%v; want BLOCK %s (#5021 P-c)", cmd, r.Decision, r.TriggeredRules, ProtectedPathRuleID)
		}
	}

	// Lowered on purpose, named: on main these spliced names were read as the
	// protected name they imitate. Git Bash keeps the quoted backslash as a
	// separator (.ss\h is .ss/h), so it does not open the file.
	for _, cmd := range []string{
		`cat ~/".ss\h"/` + key,
		`cat ~/".a\ws/` + cred + `"`,
	} {
		if r := eval(cmd); slices.Contains(r.TriggeredRules, ProtectedPathRuleID) {
			t.Errorf("%s\n  %v rules=%v; Windows keeps the quoted backslash", cmd, r.Decision, r.TriggeredRules)
		}
	}

	// Controls: the slash spelling BLOCKs before and after; an unquoted native
	// path does not, because bash eats its separators and opens nothing.
	if r := eval(`cat C:/Users/zzuser/` + ssh + `/` + key); r.Decision != DecisionBlock {
		t.Errorf("control: slash spelling %v rules=%v; want BLOCK", r.Decision, r.TriggeredRules)
	}
	if r := eval(`cat ` + home + `\` + ssh + `\` + key); slices.Contains(r.TriggeredRules, ProtectedPathRuleID) {
		t.Errorf("control: unquoted native path %v rules=%v; bash cannot open it", r.Decision, r.TriggeredRules)
	}
}

// Off Windows the decision is unchanged: a spliced name with a backslash
// inside quotes is still read as the protected name it imitates. Option (a) of
// #5049 would lower these rows; option (b) must not.
func TestQuotedBackslashPOSIXUnchanged_5049(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX reading")
	}
	home := "/Users/zzuser"
	testhome.Set(t, home)
	ssh, key := "."+"ssh", "id_"+"rsa"
	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = []string{"~/" + ssh + "/**", "/opt/vault/**"}
	engine, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	cwd := t.TempDir()
	for _, cmd := range []string{
		`cat ~/".ss\h"/` + key,
		`cat "~/` + ssh + `/id_\rsa"`,
		`cat '` + home + `/.ss\h/` + key + `'`,
		`cat "/opt/va\ult/keys/a.pem"`,
		`cat ~/` + ssh + `/id_\\rsa`,
	} {
		nc := normalize.NormalizeCommand(cmd, cwd)
		r := engine.EvaluateWithParsedCwd(cmd, nc.Paths, nc.Parsed, cwd)
		if r.Decision != DecisionBlock || !slices.Contains(r.TriggeredRules, ProtectedPathRuleID) {
			t.Errorf("%s\n  %v rules=%v; want BLOCK %s (the POSIX reading)", cmd, r.Decision, r.TriggeredRules, ProtectedPathRuleID)
		}
	}
}

// A kept backslash next to a `/` is one separator to Git Bash: it runs
// `"/usr/bin/\rm"` as /usr/bin/rm (#5049, rows A1-A5). main deleted every
// backslash and read rm, so these BLOCK on main on every OS; the Windows
// reading must not hide the program name. Full packs, as the hook loads them.
func TestBackslashAtSlashKeepsProgramName_5049(t *testing.T) {
	pol, infos, err := LoadPacks(packsDir(), DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if e := firstPackLoadError(infos); e != nil {
		t.Fatal(e)
	}
	engine, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	tail := " -" + "rf /"
	for _, exe := range []string{
		`/usr/bin/rm`, // control
		`"/usr/bin/\rm"`,
		`'/usr/bin/\rm'`,
		`'/usr/bin/\\rm'`,
		`"/usr/\bin/rm"`,
		`"/usr/bin\/rm"`,
	} {
		cmd := exe + tail
		nc := normalize.NormalizeCommand(cmd, cwd)
		r := engine.EvaluateWithParsedCwd(cmd, nc.Paths, nc.Parsed, cwd)
		if r.Decision != DecisionBlock {
			t.Errorf("%s: %v rules=%v; want BLOCK", cmd, r.Decision, r.TriggeredRules)
		}
	}
}
