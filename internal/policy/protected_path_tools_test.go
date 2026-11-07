package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
	"gopkg.in/yaml.v3"
)

// shippedDeclarations reads every protected_paths pattern AgentShield ships
// from the files that declare them: DefaultPolicy, the policy template and
// every enabled shell pack under packs/community and packs/premium. premium is
// false in the OSS tree, where packs/premium is stripped.
func shippedDeclarations(t *testing.T) (decl map[string]string, premium bool) {
	t.Helper()
	decl = map[string]string{}
	for _, p := range DefaultPolicy().Defaults.ProtectedPaths {
		decl[p] = "DefaultPolicy"
	}
	tmpl, err := Load(filepath.Join("..", "..", "configs", "default_policy.yaml"))
	if err != nil {
		t.Fatalf("load policy template: %v", err)
	}
	for _, p := range tmpl.Defaults.ProtectedPaths {
		if _, ok := decl[p]; !ok {
			decl[p] = "configs/default_policy.yaml"
		}
	}
	read := func(dir string) int {
		files, _ := filepath.Glob(filepath.Join("..", "..", "packs", dir, "*.yaml"))
		for _, f := range files {
			if strings.HasPrefix(filepath.Base(f), "_") {
				continue
			}
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var doc protectedPathsDoc
			if err := yaml.Unmarshal(data, &doc); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			for _, p := range doc.Defaults.ProtectedPaths {
				if _, ok := decl[p]; !ok {
					decl[p] = f
				}
			}
		}
		return len(files)
	}
	if n := read("community"); n == 0 {
		t.Fatal("no community shell packs found: the ratchet would compare nothing")
	}
	premium = ossbuild.PremiumPacksPresent()
	if premium {
		if n := read("premium"); n == 0 {
			t.Fatal("packs/premium present but holds no shell packs")
		}
	}
	return decl, premium
}

// #4645: shippedProtectedPaths decides which protected_paths are the
// customer's, and so which ones newly BLOCK the agent's file tools. A shipped
// pattern missing from it would start BLOCKing every Read of that path; an
// entry nothing ships would hide a customer's identical pattern. Both
// directions fail here.
func TestShippedProtectedPaths_MatchEveryShippedDeclaration(t *testing.T) {
	decl, premium := shippedDeclarations(t)
	for p, from := range decl {
		if !IsShippedProtectedPath(p) {
			t.Errorf("%q is declared by %s but missing from shippedProtectedPaths: add it, or it BLOCKs file tools as a customer path", p, from)
		}
	}
	if !premium {
		t.Log("packs/premium absent (OSS tree): skipping the no-extra-entries direction")
		return
	}
	var extra []string
	for p := range shippedProtectedPaths {
		if _, ok := decl[p]; !ok && p != ManagedConfigProtectedPath {
			extra = append(extra, p)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("shippedProtectedPaths lists patterns nothing ships: %v", extra)
	}
	if len(decl) < 29 {
		t.Errorf("only %d shipped declarations found; the reader is missing files", len(decl))
	}
}

func TestCustomerProtectedPaths_DropsShippedKeepsOrder(t *testing.T) {
	in := []string{"~/.ssh/**", "/etc/acme/secrets/**", "~/.npmrc", "", "~/company/**", "/etc/acme/secrets/**", "/etc/**", ManagedConfigProtectedPath, "~/.pip/**"}
	got := CustomerProtectedPaths(in)
	want := []string{"/etc/acme/secrets/**", "~/company/**"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CustomerProtectedPaths = %v, want %v", got, want)
	}
	if CustomerProtectedPaths(nil) != nil {
		t.Error("nil in, want nil out")
	}
}

func TestMatchProtectedPath_SameMatcherAsTheShell(t *testing.T) {
	const home = "/home/u"
	pats := []string{"/etc/acme/secrets/**", "~/company/*", "~/.env"}
	for _, c := range []struct {
		path, cwd string
		fold      bool
		want      string
	}{
		{"/etc/acme/secrets/db.env", "", false, "/etc/acme/secrets/**"},
		{"/etc/acme/secrets", "", false, "/etc/acme/secrets/**"},
		{"/etc/acme/secrets/a/b/c", "", false, "/etc/acme/secrets/**"},
		{"/etc/acme/secrets-howto.md", "", false, ""},
		{"/etc/acme/secret", "", false, ""},
		{"/home/u/company/a", "", false, "~/company/*"},
		{"/home/u/company/a/b", "", false, ""},
		{"/home/u/.env", "", false, "~/.env"},
		{"/home/u/.envrc", "", false, ""},
		{"/ETC/ACME/SECRETS/DB.ENV", "", false, ""},
		{"/ETC/ACME/SECRETS/DB.ENV", "", true, "/etc/acme/secrets/**"},
	} {
		got, ok := MatchProtectedPath(pats, home, c.path, c.cwd, c.fold)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("MatchProtectedPath(%q, fold=%v) = %q %v, want %q", c.path, c.fold, got, ok, c.want)
		}
	}
	// The engine's own check agrees, case for case, on a relative pattern
	// under cwd (the #4020 reading).
	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = []string{"secrets/**"}
	engine, err := NewEngine(pol)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/work/secrets/k", "/work/other/k", "secrets/k"} {
		blocked, _ := engine.checkProtectedPaths([]string{p}, "/work", false)
		_, matched := MatchProtectedPath([]string{"secrets/**"}, engine.homeDir, p, "/work", false)
		if blocked != matched {
			t.Errorf("%s: engine %v, MatchProtectedPath %v", p, blocked, matched)
		}
	}
}

// fullDecode is what LoadPacks reads of a pack's protected_paths: a decode of
// the whole document.
func fullDecode(data []byte) ([]string, error) {
	var doc protectedPathsDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc.Defaults.ProtectedPaths, nil
}

// #4645: declaredProtectedPaths' fast path decodes only the defaults block.
// It must return what a whole-document decode returns, on every shipped pack
// and on the shapes that make the fast path stand aside.
func TestDeclaredProtectedPaths_FastPathMatchesFullDecode(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "packs", "*", "*.yaml"))
	fast := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(f, string(filepath.Separator)+"mcp"+string(filepath.Separator)) {
			continue
		}
		want, wantErr := fullDecode(data)
		got, err := declaredProtectedPaths(data)
		if (err != nil) != (wantErr != nil) || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: fast %v (%v), full %v (%v)", f, got, err, want, wantErr)
		}
		if _, ok := topLevelDefaultsBlock(data); ok && strings.Contains(string(data), "protected_paths") {
			fast++
		}
	}
	// Vacuity floor: the fast path really runs on the shipped packs.
	if fast < 3 {
		t.Errorf("fast path taken on %d shipped packs, want >= 3 (community secrets-pii, terminal-safety, ci-context)", fast)
	}

	for _, c := range []struct {
		name, doc string
		fastPath  bool
	}{
		{"block style", "name: x\ndefaults:\n  protected_paths:\n  - /a/**\n  - ~/b\nrules: []\n", true},
		{"indented list and comments", "defaults: # d\n  # c\n  protected_paths:\n    - /a/** # x\n# top comment\n    - /b\nrules:\n- id: r\n", true},
		{"crlf", "defaults:\r\n  protected_paths:\r\n  - /a/**\r\nrules: []\r\n", true},
		{"empty list", "defaults:\n  protected_paths: []\n", true},
		{"defaults last", "rules: []\ndefaults:\n  protected_paths: [/a, /b]\n", true},
		{"flow mapping", "defaults: {protected_paths: [/a/**]}\n", false},
		{"anchor and alias", "x: &p [/a/**]\ndefaults:\n  protected_paths: *p\n", true},
		{"quoted key", "\"defaults\":\n  protected_paths: [/a/**]\n", false},
		{"document marker", "---\ndefaults:\n  protected_paths: [/a/**]\n", false},
		{"second document ignored", "defaults:\n  protected_paths: [/a/**]\n---\ndefaults:\n  protected_paths: [/b/**]\n", false},
		{"no defaults", "rules: []\nprotected_paths: [/a]\n", false},
		{"protected_paths elsewhere", "defaults:\n  decision: AUDIT\nrules:\n- id: r\n  reason: protected_paths\n", true},
		{"rule body mentions defaults", "defaults:\n  protected_paths: [/a]\nrules:\n- id: r\n  reason: |\n    defaults:\n      protected_paths: [/evil]\n", true},
		{"broken yaml", "defaults:\n  protected_paths: [/a\n", false},
		{"named only in comments", "# protected_paths: [/x]\n  # see protected_paths\nrules: []\n", false},
		{"comment mention before the key", "# protected_paths below\ndefaults:\n  protected_paths: [/a] # protected_paths\n", true},
		{"comment and key on one line", "defaults: # protected_paths\n  protected_paths: [/a]\n", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			want, wantErr := fullDecode([]byte(c.doc))
			got, err := declaredProtectedPaths([]byte(c.doc))
			if (err != nil) != (wantErr != nil) || !reflect.DeepEqual(got, want) {
				t.Errorf("fast %v (%v), full %v (%v)", got, err, want, wantErr)
			}
		})
	}
	if got, err := declaredProtectedPaths([]byte("rules: []\n")); got != nil || err != nil {
		t.Errorf("a pack that never spells the key: %v %v, want nothing", got, err)
	}
}

// #4645: LoadDeclaredProtectedPaths reads the same files LoadPacks reads,
// and the same protected_paths from them.
func TestLoadDeclaredProtectedPaths_MatchesLoadPacks(t *testing.T) {
	dir := t.TempDir()
	packs := filepath.Join(dir, "packs")
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(packs, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pack := func(paths ...string) string {
		return "name: p\ndefaults:\n  protected_paths: [" + strings.Join(paths, ", ") + "]\nrules: []\n"
	}
	write("co-acme.yaml", pack("/etc/acme/secrets/**"))
	write("team.yml", pack("~/company/**", "~/.ssh/**"))
	write("_disabled.yaml", pack("/disabled/file/**"))
	write("mcp-flat.yaml", pack("/mcp/flat/**"))
	write("structural/sub.yaml", pack("/sub/dir/**"))
	write("_off/sub.yaml", pack("/disabled/dir/**"))
	write("mcp/inner.yaml", pack("/mcp/dir/**"))
	write("notes.txt", pack("/not/yaml/**"))
	write("broken.yaml", "defaults:\n  protected_paths: [/broken\n")
	policyFile := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyFile, []byte("defaults:\n  protected_paths: [\"/srv/vault/**\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, infos, err := LoadDeclaredProtectedPaths(policyFile, packs)
	if err != nil {
		t.Fatalf("LoadDeclaredProtectedPaths: %v", err)
	}
	base, err := Load(policyFile)
	if err != nil {
		t.Fatal(err)
	}
	full, fullInfos, err := LoadPacks(packs, base)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, full.Defaults.ProtectedPaths) {
		t.Errorf("declared %v\n  LoadPacks %v", got, full.Defaults.ProtectedPaths)
	}
	for _, want := range []string{"/srv/vault/**", "/etc/acme/secrets/**", "~/company/**", "/sub/dir/**"} {
		if !contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	failed := FailedPacks(infos)
	if len(failed) != 1 || !strings.HasSuffix(failed[0].Path, "broken.yaml") || len(FailedPacks(fullInfos)) != 1 {
		t.Errorf("failed packs %v (LoadPacks: %v), want broken.yaml in both", failed, FailedPacks(fullInfos))
	}

	// Missing files are not errors, and still yield the defaults.
	got, _, err = LoadDeclaredProtectedPaths(filepath.Join(dir, "absent.yaml"), filepath.Join(dir, "absent"))
	if err != nil || !reflect.DeepEqual(got, DefaultPolicy().Defaults.ProtectedPaths) {
		t.Errorf("absent files: %v %v", got, err)
	}
	// A broken policy file is an error, and the packs still load.
	if err := os.WriteFile(policyFile, []byte("defaults: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _, err = LoadDeclaredProtectedPaths(policyFile, packs)
	if err == nil || !contains(got, "/etc/acme/secrets/**") {
		t.Errorf("broken policy file: %v %v, want an error and the pack paths", got, err)
	}
}
