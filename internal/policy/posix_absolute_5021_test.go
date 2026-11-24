package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/testhome"
)

// #5021 P-c, option (c): on Windows Git Bash's `/c/...` is drive C and a
// rooted `/x` is on the cwd's drive, in normalize and in every consumer that
// re-reads a path: the designated-consumer table (isProtectedToken), the ssh
// receipt (sshReceiptHits), the cwd-relative match (relativeToCwd), the
// audit-only self-protection hits (resolvedProtectedHits) and the matcher's
// drive-less patterns (matchOnDrive). Expectations are computed
// for this OS, so a POSIX run pins main's behaviour and a Windows run pins
// the new reading. Credential paths are assembled at runtime: the hook reads
// test sources as commands.

// msysSpelling spells an OS path the way Git Bash's pwd does: C:\Users\u is
// /c/Users/u. A path with no drive (every POSIX path) comes back in slash form.
func msysSpelling(p string) string {
	p = filepath.ToSlash(p)
	if len(p) >= 2 && p[1] == ':' {
		return "/" + strings.ToLower(p[:1]) + p[2:]
	}
	return p
}

func evalAt(engine *Engine, cmd, cwd string) EvalResult {
	nc := normalize.NormalizeCommand(cmd, cwd)
	return engine.EvaluateWithParsedCwd(cmd, nc.Paths, nc.Parsed, cwd)
}

// Git Bash's spelling of the home, and on Windows the home with no drive
// (read on the cwd's drive, option (c)), decide exactly as `~` does from the
// same cwd: a reader BLOCKs, a designated consumer's credential slot is the
// flagged AUDIT, and a reader beside a consumer still BLOCKs. Built in
// normalize alone, the reading BLOCKed the consumer rows, because the
// consumer table did not recognise the word in the slot (the write-up's four
// over-blocks).
//
// From a protected cwd (~/.ssh, ~/.aws) main joined these spellings under the
// cwd and BLOCKed every one, the consumer rows included. They now decide as
// `~` does there, the consumer's AUDIT (the pass-1 review's 27 consumer rows).
func TestMSYSHomeDecidesAsTheHome_5021(t *testing.T) {
	home := t.TempDir()
	testhome.Set(t, home)
	engine, err := NewEngineWithAnalyzers(DefaultPolicy(), 2)
	if err != nil {
		t.Fatal(err)
	}
	ssh, aws, kube := "."+"ssh", "."+"aws", "."+"kube"
	key := "id_" + "ed25519"
	neutral := t.TempDir()
	cwds := []string{neutral, filepath.Join(home, ssh), filepath.Join(home, aws)}
	for _, d := range cwds[1:] {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	spellings := map[string]string{"msys": msysSpelling(home), "rooted": rootedSpelling(home)}
	rows := []struct {
		tmpl string // H is the home's spelling
		want Decision
		rule string
	}{
		{"cat H/" + ssh + "/" + key, DecisionBlock, ProtectedPathRuleID},
		{"cp H/" + aws + "/credentials /tmp/x", DecisionBlock, ProtectedPathRuleID},
		{"ssh -i H/" + ssh + "/" + key + " git@example.com", DecisionAudit, ProtectedPathConsumerRuleID},
		{"ssh-keygen -l -f H/" + ssh + "/" + key, DecisionAudit, ProtectedPathConsumerRuleID},
		{"helm --kubeconfig H/" + kube + "/config list", DecisionAudit, ProtectedPathConsumerRuleID},
		{"scp -i H/" + ssh + "/" + key + " notes.txt host:", DecisionAudit, ProtectedPathConsumerRuleID},
		{"ssh -i H/" + ssh + "/" + key + " host && cat H/" + ssh + "/id_" + "rsa", DecisionBlock, ProtectedPathRuleID},
		{"export KUBECONFIG=H/" + kube + "/config", DecisionAudit, ProtectedPathConsumerRuleID}, // the env slot (#3630)
	}
	for _, cwd := range cwds {
		for _, r := range rows {
			tilde := evalAt(engine, strings.ReplaceAll(r.tmpl, "H", "~"), cwd)
			if cwd == neutral && (tilde.Decision != r.want || !slices.Contains(tilde.TriggeredRules, r.rule)) {
				t.Fatalf("control %q with ~: %v %v; want %v by %s", r.tmpl, tilde.Decision, tilde.TriggeredRules, r.want, r.rule)
			}
			for name, h := range spellings {
				cmd := strings.ReplaceAll(r.tmpl, "H", h)
				got := evalAt(engine, cmd, cwd)
				if got.Decision != tilde.Decision || !slices.Equal(got.TriggeredRules, tilde.TriggeredRules) || !slices.Equal(got.TaxonomyRefs, tilde.TaxonomyRefs) {
					t.Errorf("%s %q cwd=%s: %v %v %q; want %v %v %q, as with ~", name, cmd, cwd, got.Decision, got.TriggeredRules, got.TaxonomyRefs, tilde.Decision, tilde.TriggeredRules, tilde.TaxonomyRefs)
				}
			}
		}
	}
	// A consumer's slot spelled with ~ must not hide a reader spelled the
	// Git Bash way (before #5021 P-c the consumer table could not see the
	// reader's word, so this decided AUDIT on Windows).
	for name, h := range spellings {
		mixed := "ssh -i ~/" + ssh + "/" + key + " host && cat " + h + "/" + ssh + "/id_" + "rsa"
		if got := evalAt(engine, mixed, neutral); got.Decision != DecisionBlock || !slices.Contains(got.TriggeredRules, ProtectedPathRuleID) {
			t.Errorf("%s %q: %v %v; want BLOCK by %s", name, mixed, got.Decision, got.TriggeredRules, ProtectedPathRuleID)
		}
	}
}

// rootedSpelling is p without its volume, in slash form: on Windows
// C:\Users\u is /Users/u, a rooted path on the current drive. On POSIX it is p.
func rootedSpelling(p string) string {
	return filepath.ToSlash(p[len(filepath.VolumeName(p)):])
}

// Off Windows `/c/...` is a directory named c, not the home's drive.
func TestMSYSSpellingIsNotTheHomeOffWindows_5021(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("on Windows /c/... is drive C; TestMSYSHomeDecidesAsTheHome_5021 pins that")
	}
	home := t.TempDir()
	testhome.Set(t, home)
	engine, err := NewEngine(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	cmd := "cat /c" + home + "/" + "." + "ssh/id_" + "rsa"
	if got := evalAt(engine, cmd, t.TempDir()); slices.Contains(got.TriggeredRules, ProtectedPathRuleID) {
		t.Errorf("%q: %v %v; protected-path fired on a directory named c", cmd, got.Decision, got.TriggeredRules)
	}
}

// The ssh receipt follows the file for Git Bash's spelling as for ~: config is
// ssh-config-access, not a key read. sshReceiptHits must key the word the way
// normalize resolved the hit, or it sees an operand that is no hit and falls
// back to citing a key read.
func TestMSYSHomeSSHReceiptFollowsTheFile_5021(t *testing.T) {
	home := t.TempDir()
	testhome.Set(t, home)
	engine, err := NewEngineWithAnalyzers(DefaultPolicy(), 2)
	if err != nil {
		t.Fatal(err)
	}
	dir := msysSpelling(home) + "/" + "." + "ssh/"
	for _, c := range []struct{ cmd, want string }{
		{"cat " + dir + "config", sshNode + "ssh-config-access"},
		{"cat " + dir + "authorized_keys", sshNode + "ssh-authorized-keys-access"},
		{"cat " + dir + "known_hosts", ""},
		{"cat " + dir + "id_" + "rsa", sshNode + "ssh-private-key-read"},
	} {
		checkSSHReceipt(t, engine, c.cmd, c.want)
	}
}

// A POSIX-shaped home (`/Users/zz`, a remote client's spelling) decides on
// Windows as it does on POSIX (#4717): with no drive in the home, a rooted
// cwd and a rooted operand stay rooted in normalize, in the consumer table and
// in the ssh receipt alike (pathnorm.Cwd: a rooted cwd is on the home's drive,
// and this home has none).
func TestPOSIXHomeDecidesAsOnPOSIX_5021(t *testing.T) {
	home := "/Users/" + "zz5021"
	testhome.Set(t, home)
	engine, err := NewEngineWithAnalyzers(DefaultPolicy(), 2)
	if err != nil {
		t.Fatal(err)
	}
	dir := home + "/" + "." + "ssh/"
	checkSSHReceipt(t, engine, "cat "+dir+"config", sshNode+"ssh-config-access")
	consumer := "ssh -i " + dir + "id_" + "ed25519 git@example.com"
	if got := evalAt(engine, consumer, "/srv/app"); got.Decision != DecisionAudit || !slices.Contains(got.TriggeredRules, ProtectedPathConsumerRuleID) {
		t.Errorf("%q: %v %v; want AUDIT by %s", consumer, got.Decision, got.TriggeredRules, ProtectedPathConsumerRuleID)
	}
}

// resolvedProtectedHits (the audit-only self-protection input) resolves a hit
// as normalize resolves an operand: on Windows a rooted path is on the cwd's
// drive, a relative hit is joined under a rooted cwd (itself on the home's
// drive), and Git Bash's /c/... is drive C.
func TestResolvedProtectedHits_5021(t *testing.T) {
	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = []string{"/srv/vault/**", "secrets/**"}
	engine, err := NewEngine(pol)
	if err != nil {
		t.Fatal(err)
	}
	native := t.TempDir()
	vol := filepath.VolumeName(native)
	type row struct {
		name       string
		paths      []string
		cwd        string
		want       []string
		onlyOnWins bool
	}
	rows := []row{
		{"rooted hit on the cwd's drive", []string{filepath.FromSlash("/srv/vault/db.env")}, native, []string{vol + filepath.FromSlash("/srv/vault/db.env")}, false},
		{"relative hit under a rooted cwd", []string{"secrets/token"}, "/srv/app", []string{filepath.VolumeName(engine.homeDir) + filepath.FromSlash("/srv/app/secrets/token")}, false},
		// From below the drive's root a rooted path is outside the cwd, so a
		// relative pattern does not claim it (main joined it under the cwd).
		{"rooted path outside the cwd", []string{"/secrets/token"}, native, nil, false},
		{"Git Bash hit under the cwd", []string{msysSpelling(native) + "/secrets/token"}, native, []string{filepath.Join(native, "secrets", "token")}, true},
		{"native hit under a Git Bash cwd", []string{filepath.Join(native, "secrets", "token")}, msysSpelling(native), []string{filepath.Join(native, "secrets", "token")}, true},
	}
	for _, r := range rows {
		if r.onlyOnWins && runtime.GOOS != "windows" {
			continue
		}
		if got := engine.resolvedProtectedHits(r.paths, r.cwd, false); !slices.Equal(got, r.want) {
			t.Errorf("%s: resolvedProtectedHits(%q, cwd=%q) = %q, want %q", r.name, r.paths, r.cwd, got, r.want)
		}
	}
}

// From a volume's root (`C:\`) a rooted operand is on that drive, C:\x, as
// main's join read it there: PowerShell opens `Get-Content
// /Users/u/.aws/credentials` from C:\. Git Bash's `/c/...` is drive C first,
// from any drive's root (the pass-1 finding: from C:\ or D:\ the volume-root
// join ran before the MSYS reading, and protected-path missed).
func TestRootedOperandFromAVolumeRoot_5021(t *testing.T) {
	home := t.TempDir()
	testhome.Set(t, home)
	engine, err := NewEngineWithAnalyzers(DefaultPolicy(), 2)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.VolumeName(home) + string(filepath.Separator)
	rooted := rootedSpelling(home) // the home with no drive
	for _, cmd := range []string{
		"cat " + rooted + "/" + "." + "aws/credentials",
		"cp " + rooted + "/" + "." + "aws/credentials /tmp/x",
		"tar czf /tmp/x.tgz " + rooted + "/" + "." + "gnupg",
	} {
		if got := evalAt(engine, cmd, root); got.Decision != DecisionBlock || !slices.Contains(got.TriggeredRules, ProtectedPathRuleID) {
			t.Errorf("%q cwd=%s: %v %v; want BLOCK by %s, as on main", cmd, root, got.Decision, got.TriggeredRules, ProtectedPathRuleID)
		}
	}
	// Git Bash's spelling, from this drive's root and from another drive's.
	roots := []string{root}
	if runtime.GOOS == "windows" {
		other := "Z:"
		if strings.EqualFold(filepath.VolumeName(home), other) {
			other = "Y:"
		}
		roots = append(roots, other+`\`)
	}
	for _, r := range roots {
		for _, cmd := range []string{
			"cat " + msysSpelling(home) + "/" + "." + "aws/credentials",
			"cp " + msysSpelling(home) + "/" + "." + "kube/config /tmp/x",
		} {
			if got := evalAt(engine, cmd, r); got.Decision != DecisionBlock || !slices.Contains(got.TriggeredRules, ProtectedPathRuleID) {
				t.Errorf("%q cwd=%s: %v %v; want BLOCK by %s", cmd, r, got.Decision, got.TriggeredRules, ProtectedPathRuleID)
			}
		}
	}
	// The ssh receipt keys the word as normalize resolved it, so a config read
	// from the root still attests config, not a key read.
	cmd := "cat " + rooted + "/" + "." + "ssh/config"
	if got := evalAt(engine, cmd, root); len(got.TaxonomyRefs) != 1 || got.TaxonomyRefs[0] != sshNode+"ssh-config-access" {
		t.Errorf("%q cwd=%s: taxonomy %q, want [%sssh-config-access]", cmd, root, got.TaxonomyRefs, sshNode)
	}
	// A relative pattern claims a rooted path under the root, as on main.
	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = []string{"secrets/**"}
	rel, err := NewEngine(pol)
	if err != nil {
		t.Fatal(err)
	}
	if got := rel.resolvedProtectedHits([]string{"/secrets/token"}, root, false); !slices.Equal(got, []string{filepath.Join(root, "secrets", "token")}) {
		t.Errorf("resolvedProtectedHits from %s = %q, want [%s]", root, got, filepath.Join(root, "secrets", "token"))
	}
}

// The pass-1 regression, closed by option (c): the home spelled with no drive,
// read from any cwd on its drive, is the home, as PowerShell opens it. From a
// protected cwd main BLOCKed these by joining the path under the cwd (so the
// receipt named the cwd's directory, not the file read); the reading that kept
// the path rooted lowered them to AUDIT or ALLOW. They now BLOCK by
// protected-path with the receipt the `~` spelling gets: the file actually
// read. The project dir was the pinned gap (main missed it too).
func TestRootedHomeReadFromAnyCwdOnItsDriveBlocks_5021(t *testing.T) {
	home := t.TempDir()
	testhome.Set(t, home)
	engine, err := NewEngineWithAnalyzers(DefaultPolicy(), 2)
	if err != nil {
		t.Fatal(err)
	}
	ssh, aws, kube := "."+"ssh", "."+"aws", "."+"kube"
	cwds := []string{filepath.Join(home, ssh), filepath.Join(home, aws), filepath.Join(home, kube), filepath.Join(home, "proj"), t.TempDir()}
	for _, d := range cwds {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if v := filepath.VolumeName(cwds[len(cwds)-1]); !strings.EqualFold(v, filepath.VolumeName(home)) {
		t.Skipf("the temp dir is on %s, not the home's drive; the rooted spelling names another drive's file there", v)
	}
	tmpls := []string{
		"Get-Content H/" + aws + "/credentials",
		"type H/" + aws + "/credentials",
		"cat H/" + aws + "/credentials",
		"Copy-Item H/" + aws + "/credentials $env:TEMP\\o",
		"Get-Content H/" + kube + "/config",
		"tar -czf $env:TEMP\\o.tgz -C H " + aws,
	}
	neutral := cwds[len(cwds)-1]
	for _, tmpl := range tmpls {
		tilde := evalAt(engine, strings.ReplaceAll(tmpl, "H", "~"), neutral)
		if tilde.Decision != DecisionBlock || !slices.Contains(tilde.TriggeredRules, ProtectedPathRuleID) {
			t.Fatalf("control %q with ~: %v %v; want BLOCK by %s", tmpl, tilde.Decision, tilde.TriggeredRules, ProtectedPathRuleID)
		}
		cmd := strings.ReplaceAll(tmpl, "H", rootedSpelling(home))
		for _, cwd := range cwds {
			got := evalAt(engine, cmd, cwd)
			if got.Decision != DecisionBlock || !slices.Contains(got.TriggeredRules, ProtectedPathRuleID) || !slices.Equal(got.TaxonomyRefs, tilde.TaxonomyRefs) {
				t.Errorf("%q cwd=%s: %v %v %q; want BLOCK by %s with the ~ spelling's receipt %q", cmd, cwd, got.Decision, got.TriggeredRules, got.TaxonomyRefs, ProtectedPathRuleID, tilde.TaxonomyRefs)
			}
		}
	}
}

// A protected_paths pattern with no drive (`/srv/vault/**`, a customer's, or
// /etc/** from configs/default_policy.yaml) is on the cwd's drive too, so it
// matches the operand normalize put there (matchOnDrive). The first match is
// main's: a drive-less path still matches a drive-less pattern from any cwd.
func TestDriveLessPatternIsOnTheCwdsDrive_5021(t *testing.T) {
	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = []string{"/srv/vault/**"}
	engine, err := NewEngine(pol)
	if err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	vol := filepath.VolumeName(cwd)
	if got := evalAt(engine, "cat /srv/vault/db.env", cwd); got.Decision != DecisionBlock || !slices.Contains(got.TriggeredRules, ProtectedPathRuleID) {
		t.Errorf("cat /srv/vault/db.env cwd=%s: %v %v; want BLOCK by %s", cwd, got.Decision, got.TriggeredRules, ProtectedPathRuleID)
	}
	// The consumer table compares the same way, so the credential slot is
	// still the consumer's AUDIT, as on POSIX.
	consumer := "ssh -i /srv/vault/" + "id_" + "ed25519 git@example.com"
	if got := evalAt(engine, consumer, cwd); got.Decision != DecisionAudit || !slices.Contains(got.TriggeredRules, ProtectedPathConsumerRuleID) {
		t.Errorf("%q cwd=%s: %v %v; want AUDIT by %s", consumer, cwd, got.Decision, got.TriggeredRules, ProtectedPathConsumerRuleID)
	}
	home := engine.homeDir
	pats := pol.Defaults.ProtectedPaths
	for _, c := range []struct {
		name, path, cwd string
		want            bool
	}{
		{"on the cwd's drive", vol + filepath.FromSlash("/srv/vault/x"), cwd, true},
		{"drive-less, as main matched it", filepath.FromSlash("/srv/vault/x"), cwd, true},
		{"drive-less, no cwd", filepath.FromSlash("/srv/vault/x"), "", true},
		{"elsewhere", vol + filepath.FromSlash("/srv/other/x"), cwd, false},
	} {
		if _, got := MatchProtectedPath(pats, home, c.path, c.cwd, false); got != c.want {
			t.Errorf("%s: MatchProtectedPath(%q, cwd %q) = %v, want %v", c.name, c.path, c.cwd, got, c.want)
		}
	}
	if runtime.GOOS != "windows" {
		return
	}
	// Another drive's file is not the pattern's, and with no cwd there is no
	// drive to read the pattern on.
	other := "Z:"
	if strings.EqualFold(vol, other) {
		other = "Y:"
	}
	for _, c := range []struct{ name, path, cwd string }{
		{"another drive", other + `\srv\vault\x`, cwd},
		{"a drive path, no cwd", vol + `\srv\vault\x`, ""},
	} {
		if _, got := MatchProtectedPath(pats, home, c.path, c.cwd, false); got {
			t.Errorf("%s: MatchProtectedPath(%q, cwd %q) matched; want no match", c.name, c.path, c.cwd)
		}
	}
	// The folded reading (#4194) folds the drive as it folds the rest, also
	// when the drive is the home's (a rooted cwd).
	if v := filepath.VolumeName(home); v != "" {
		if _, got := MatchProtectedPath(pats, home, v+`\SRV\vault\x`, "/work", true); !got {
			t.Errorf(`folded, cwd /work: no match for %s\SRV\vault\x`, v)
		}
	}
	if _, got := MatchProtectedPath(pats, home, strings.ToLower(vol)+`\SRV\vault\x`, cwd, true); !got {
		t.Errorf("folded: no match for %s\\SRV\\vault\\x", strings.ToLower(vol))
	}
}
