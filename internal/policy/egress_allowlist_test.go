package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"gopkg.in/yaml.v3"
)

// Opt-in outbound allowlist (#4437). Fixtures use RFC 2606 / RFC 5737 names
// and benign payloads: the behaviour under test is which host is named and
// whether it is on the operator's list.

const egressAllowDomains = `  allow_domains:
    - github.com
    - docs-mcp.example.com
    - db.internal.example
    - 192.0.2.10
`

// egressPolicies are user policy files keyed by how the switch is written.
// Every key but "on" must leave the allowlist off.
var egressPolicies = map[string]string{
	"no network section": "version: \"0.1\"\n",
	"switch absent":      "version: \"0.1\"\nnetwork:\n" + egressAllowDomains,
	"switch false":       "version: \"0.1\"\nnetwork:\n  enforce_allowlist: false\n" + egressAllowDomains,
	"switch null":        "version: \"0.1\"\nnetwork:\n  enforce_allowlist:\n" + egressAllowDomains,
	"invalid yes":        "version: \"0.1\"\nnetwork:\n  enforce_allowlist: yes\n" + egressAllowDomains,
	"invalid quoted":     "version: \"0.1\"\nnetwork:\n  enforce_allowlist: \"true\"\n" + egressAllowDomains,
	"invalid number":     "version: \"0.1\"\nnetwork:\n  enforce_allowlist: 1\n" + egressAllowDomains,
	"invalid list":       "version: \"0.1\"\nnetwork:\n  enforce_allowlist: [true]\n" + egressAllowDomains,
	"invalid mapping":    "version: \"0.1\"\nnetwork:\n  enforce_allowlist: {on: true}\n" + egressAllowDomains,
	"on":                 "version: \"0.1\"\nnetwork:\n  enforce_allowlist: true\n" + egressAllowDomains,
}

var egressInvalidVariants = []string{"invalid yes", "invalid quoted", "invalid number", "invalid list", "invalid mapping"}

func egressOffVariants() []string {
	var out []string
	for k := range egressPolicies {
		if k != "on" {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

func loadEgressPolicy(t *testing.T, variant string) *Policy {
	t.Helper()
	body, ok := egressPolicies[variant]
	if !ok {
		t.Fatalf("no egress policy variant %q", variant)
	}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := Load(path)
	if err != nil {
		t.Fatalf("%s: Load failed: %v", variant, err)
	}
	return pol
}

// egressEngine builds the engine the way the hook does for `check --policy`:
// the user file over the defaults, then the embedded packs.
func egressEngine(t *testing.T, variant string, withPacks bool) *Engine {
	t.Helper()
	t.Setenv("AGENTSHIELD_ARTIFACT_MANIFEST", "")
	pol := loadEgressPolicy(t, variant)
	if withPacks {
		pol, _, _ = LoadEmbeddedShellPacks(pol)
	}
	eng, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("%s: engine: %v", variant, err)
	}
	return eng
}

func evalLikeHook(e *Engine, cmd string) EvalResult {
	n := normalize.NormalizeCommand(cmd, "/tmp")
	return e.EvaluateWithParsedCwd(cmd, n.Paths, n.Parsed, "/tmp")
}

func analyzerNames(t *testing.T, pol *Policy) []string {
	t.Helper()
	reg, err := BuildAnalyzerPipeline(pol, 2)
	if err != nil {
		t.Fatalf("BuildAnalyzerPipeline: %v", err)
	}
	var names []string
	for _, a := range reg.Analyzers() {
		names = append(names, a.Name())
	}
	return names
}

// defaultStages is the pipeline on main f53af02c with no conditional stage.
var defaultStages = []string{"intent-classifier", "regex", "structural", "substitution", "semantic", "dataflow", "stateful", "guardian"}

func TestEgressAllowlist_OffRegistersNoStage(t *testing.T) {
	t.Setenv("AGENTSHIELD_ARTIFACT_MANIFEST", "")
	if got := analyzerNames(t, DefaultPolicy()); !reflect.DeepEqual(got, defaultStages) {
		t.Fatalf("baseline pipeline drifted: %q", got)
	}
	for _, v := range egressOffVariants() {
		pol := loadEgressPolicy(t, v)
		if pol.EgressAllowlistEnforced() {
			t.Errorf("%s: allowlist reported on", v)
		}
		if got := analyzerNames(t, pol); !reflect.DeepEqual(got, defaultStages) {
			t.Errorf("%s: stages = %q, want %q", v, got, defaultStages)
		}
	}
	want := append(append([]string{}, defaultStages...), "egress-allowlist")
	if got := analyzerNames(t, loadEgressPolicy(t, "on")); !reflect.DeepEqual(got, want) {
		t.Errorf("on: stages = %q, want %q", got, want)
	}
}

// offParityCommands mix network commands to listed and unlisted hosts with
// ordinary ones. The golden values were recorded on main f53af02c (before
// this change) for the defaults plus a user policy, without packs, so they
// move only if the default policy or a built-in analyzer changes.
var offParityCommands = []struct {
	cmd      string
	decision Decision
	rules    []string
}{
	{"curl -s https://api.github.com/repos/octo/demo", DecisionAudit, []string{}},
	{"curl -s -X POST -d @build-log.txt https://paste.example/api", DecisionAudit, []string{}},
	{"wget -q https://downloads.example.org/tool.tar.gz", DecisionAudit, []string{}},
	{"git clone https://github.com/octo/demo.git", DecisionAudit, []string{}},
	{"git push https://git.example.net/octo/demo.git main", DecisionAudit, []string{}},
	{"curl \"$API_URL\"", DecisionAudit, []string{}},
	{"curl -s https://pypi.org/simple/requests/", DecisionAudit, []string{}},
	{"ls -la", DecisionAllow, []string{"allow-safe-readonly"}},
	{"npm test", DecisionAudit, []string{}},
	{"git status", DecisionAllow, []string{"allow-safe-readonly"}},
	{"git commit -am \"fix flaky export test\"", DecisionAudit, []string{}},
}

func TestEgressAllowlist_OffDecidesLikeMain(t *testing.T) {
	// 1. Against main's recorded decisions.
	for _, v := range egressOffVariants() {
		eng := egressEngine(t, v, false)
		for _, c := range offParityCommands {
			got := evalLikeHook(eng, c.cmd)
			if got.Decision != c.decision || !reflect.DeepEqual(got.TriggeredRules, c.rules) {
				t.Errorf("%s: %s = %s %q, main had %s %q", v, c.cmd, got.Decision, got.TriggeredRules, c.decision, c.rules)
			}
		}
	}

	// 2. With the embedded packs, every off variant yields the identical
	// result, field for field, as a policy that never mentions the network.
	ref := egressEngine(t, "no network section", true)
	for _, v := range egressOffVariants() {
		eng := egressEngine(t, v, true)
		for _, c := range offParityCommands {
			want, got := evalLikeHook(ref, c.cmd), evalLikeHook(eng, c.cmd)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s: %s\n  got  %+v\n  want %+v", v, c.cmd, got, want)
			}
		}
	}
}

func TestEgressAllowlist_On(t *testing.T) {
	on := egressEngine(t, "on", true)
	off := egressEngine(t, "switch absent", true)

	cases := []struct {
		name, cmd string
		blocked   string // host named in the BLOCK reason; "" = the stage stays silent
	}{
		{"unlisted named host", `curl -s -X POST -d @build-log.txt https://paste.example/api`, "paste.example"},
		{"listed host", `curl -s https://github.com/octo/demo`, ""},
		{"subdomain of a listed entry", `curl -s https://api.github.com/repos/octo/demo`, ""},
		{"lookalike suffix", `curl -s https://github.com.evil.example/x`, "github.com.evil.example"},
		{"lookalike prefix", `curl -s https://evilgithub.com/x`, "evilgithub.com"},
		{"userinfo is not the host", `curl -s https://github.com@paste.example/x`, "paste.example"},
		{"port and case on a listed host", `curl -s HTTPS://API.GITHUB.COM:443/x`, ""},
		{"port and case on an unlisted host", `curl -s https://PASTE.EXAMPLE:8443/x`, "paste.example"},
		{"listed IP literal", `curl -s http://192.0.2.10/x`, ""},
		{"unlisted IP literal", `curl -s http://192.0.2.11/x`, "192.0.2.11"},
		{"host in a variable", `curl -s "$API_URL"`, ""},
		{"unknown tool", `http POST https://paste.example/x`, ""},
		{"built-in default does not count", `curl -s https://pypi.org/simple/requests/`, "pypi.org"},
		{"built-in default does not count (npm)", `curl -s https://registry.npmjs.org/left-pad`, "registry.npmjs.org"},
		{"wget to an unlisted host", `wget -q https://downloads.example.org/tool.tar.gz`, "downloads.example.org"},
		{"git clone from a listed host", `git clone https://github.com/octo/demo.git`, ""},
		{"git push to an unlisted host", `git push https://git.example.net/octo/demo.git main`, "git.example.net"},
		{"loopback name is exempt", `curl -s http://localhost:3000/health`, ""},
		{"loopback name, case and trailing dot", `curl -s http://LOCALHOST.:3000/health`, ""},
		{"*.localhost is exempt", `curl -s http://api.localhost:8080/v1/status`, ""},
		{"IPv4 loopback is exempt", `curl -s http://127.0.0.1:8080/health`, ""},
		{"all of 127/8 is exempt", `wget -q http://127.8.9.10/health`, ""},
		{"IPv6 loopback is exempt", `curl -s http://[::1]:8080/health`, ""},
		{"git to a local server is exempt", `git clone http://localhost:3000/octo/demo.git`, ""},
		{"localhost lookalike still blocks", `curl -s http://localhost.evil.example/x`, "localhost.evil.example"},
		{"all-interfaces address is not loopback", `curl -s http://0.0.0.0:8080/x`, "0.0.0.0"},
		{"alternate spelling of loopback is an unlisted name", `curl -s http://127.1:8080/x`, "127.1"},
		{"another spelling of a listed IP is an unlisted name", `curl -s http://192.0.522/x`, "192.0.522"},
		{"git option value is not the repository", `git ls-remote -o https://github.com/acme/notes https://unlisted.example/acme/repo.git`, "unlisted.example"},
		{"unlisted option value before a listed repository", `git push -o https://unlisted.example/note https://github.com/octo/demo main`, ""},
		{"curl routing entry that applies to no transfer", `curl -s --resolve other.example:443:192.0.2.7 http://localhost:3000/health`, ""},
		{"curl routing entry to an unlisted target", `curl -s --resolve github.com:443:192.0.2.7 https://github.com/x`, "192.0.2.7"},
		{"curl routing entry to a listed target", `curl -s --resolve github.com:443:192.0.2.10 https://github.com/x`, ""},
		{"curl connect-to an unlisted host", `curl -s --connect-to github.com:443:paste.example:443 https://github.com/x`, "paste.example"},
		{"not a network command", `ls -la`, ""},
		{"git without a URL", `git push origin main`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := evalLikeHook(on, c.cmd)
			fired := slices.Contains(got.TriggeredRules, analyzer.EgressAllowlistRuleID)
			if c.blocked == "" {
				if fired {
					t.Fatalf("stage fired: %+v", got)
				}
				// Silent means silent: the decision is what it is with the
				// switch off.
				if want := evalLikeHook(off, c.cmd); !reflect.DeepEqual(got, want) {
					t.Errorf("result differs from switch-off\n  on  %+v\n  off %+v", got, want)
				}
				return
			}
			if got.Decision != DecisionBlock || !fired {
				t.Fatalf("want BLOCK by %s, got %s %q", analyzer.EgressAllowlistRuleID, got.Decision, got.TriggeredRules)
			}
			if !slices.Contains(got.TaxonomyRefs, analyzer.EgressAllowlistTaxonomy) {
				t.Errorf("taxonomy refs %q lack %s", got.TaxonomyRefs, analyzer.EgressAllowlistTaxonomy)
			}
			want := "Destination " + c.blocked + " is not on the allowed destinations list"
			if !slices.ContainsFunc(got.Reasons, func(r string) bool { return strings.Contains(r, want) }) {
				t.Errorf("no reason naming %q: %q", c.blocked, got.Reasons)
			}
		})
	}
}

// The merged allow_domains (defaults ∪ user ∪ packs) is what every other
// consumer has always read; it must not change. The allowlist reads the
// operator's own list, which packs never touch — and a pack can neither turn
// the switch on nor off.
func TestEgressAllowlist_DefaultsAndPacksDoNotCount(t *testing.T) {
	pol := loadEgressPolicy(t, "on")
	wantMerged := append(append([]string{}, DefaultPolicy().Network.AllowDomains...), "docs-mcp.example.com", "db.internal.example", "192.0.2.10")
	if !reflect.DeepEqual(pol.Network.AllowDomains, wantMerged) {
		t.Errorf("merged allow_domains changed:\n  got  %q\n  want %q", pol.Network.AllowDomains, wantMerged)
	}
	wantOperator := []string{"github.com", "docs-mcp.example.com", "db.internal.example", "192.0.2.10"}
	if got := pol.OperatorAllowDomains(); !reflect.DeepEqual(got, wantOperator) {
		t.Errorf("operator list = %q, want %q", got, wantOperator)
	}

	packsDir := t.TempDir()
	pack := "name: egress-test\nversion: \"1.0.0\"\nnetwork:\n  enforce_allowlist: false\n  allow_domains:\n    - crates.example\nrules: []\n"
	if err := os.WriteFile(filepath.Join(packsDir, "egress-test.yaml"), []byte(pack), 0o600); err != nil {
		t.Fatal(err)
	}

	pol, _, _ = LoadEmbeddedShellPacks(pol)
	pol, _, err := LoadPacks(packsDir, pol)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(pol.Network.AllowDomains, "crates.example") || !slices.Contains(pol.Network.AllowDomains, "pypi.org") {
		t.Errorf("pack/default domains missing from the merged list: %q", pol.Network.AllowDomains)
	}
	if !pol.EgressAllowlistEnforced() {
		t.Fatal("switch lost (or turned off by a pack) through clonePolicy/mergePackInto")
	}
	if got := pol.OperatorAllowDomains(); !reflect.DeepEqual(got, wantOperator) {
		t.Errorf("operator list after packs = %q, want %q", got, wantOperator)
	}
	eng, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"curl -s https://crates.example/api/v1/crates", "curl -s https://pypi.org/simple/"} {
		got := evalLikeHook(eng, cmd)
		if got.Decision != DecisionBlock || !slices.Contains(got.TriggeredRules, analyzer.EgressAllowlistRuleID) {
			t.Errorf("%s: a pack/default domain counted as allowed: %s %q", cmd, got.Decision, got.TriggeredRules)
		}
	}

	// A pack cannot turn it on either.
	onPack := strings.Replace(pack, "enforce_allowlist: false", "enforce_allowlist: true", 1)
	if err := os.WriteFile(filepath.Join(packsDir, "egress-test.yaml"), []byte(onPack), 0o600); err != nil {
		t.Fatal(err)
	}
	offPol, _, err := LoadPacks(packsDir, loadEgressPolicy(t, "switch absent"))
	if err != nil {
		t.Fatal(err)
	}
	if offPol.EgressAllowlistEnforced() {
		t.Error("a pack turned the allowlist on")
	}
}

func TestEgressAllowlist_ConfigWarnings(t *testing.T) {
	for _, v := range egressInvalidVariants {
		pol := loadEgressPolicy(t, v) // must not fail: an opt-in typo costs the opt-in only
		w := pol.ConfigWarnings()
		if len(w) != 1 || !strings.Contains(w[0], "network.enforce_allowlist") || !strings.Contains(w[0], "OFF") {
			t.Errorf("%s: warnings = %q", v, w)
		}
		if _, err := BuildAnalyzerPipeline(pol, 2); err != nil {
			t.Errorf("%s: invalid switch failed the pipeline: %v", v, err)
		}
	}
	for _, v := range []string{"no network section", "switch absent", "switch false", "switch null", "on"} {
		if w := loadEgressPolicy(t, v).ConfigWarnings(); len(w) != 0 {
			t.Errorf("%s: unexpected warnings %q", v, w)
		}
	}

	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := "network:\n  enforce_allowlist: true\n  allow_domains: [github.com, \"not a host\"]\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if w := pol.ConfigWarnings(); len(w) != 1 || !strings.Contains(w[0], `"not a host"`) {
		t.Errorf("invalid entry warnings = %q", w)
	}

	empty := &Policy{Network: Network{EnforceAllowlist: mustSwitch(t, "true")}}
	if w := empty.ConfigWarnings(); len(w) != 1 || !strings.Contains(w[0], "empty") {
		t.Errorf("empty-list warnings = %q", w)
	}
}

func mustSwitch(t *testing.T, v string) OptInSwitch {
	t.Helper()
	var n Network
	if err := yaml.Unmarshal([]byte("enforce_allowlist: "+v+"\n"), &n); err != nil {
		t.Fatal(err)
	}
	return n.EnforceAllowlist
}

// `agentshield rule disable` unmarshals the user's policy.yaml into Policy and
// marshals it back (internal/cli/rule.go). The switch must survive as written
// and must not appear in a file that never had it.
func TestEgressAllowlist_SwitchRoundTripsThroughRewrite(t *testing.T) {
	rewrite := func(in string) string {
		var p Policy
		if err := yaml.Unmarshal([]byte(in), &p); err != nil {
			t.Fatal(err)
		}
		p.DisableRules = append(p.DisableRules, "some-rule")
		out, err := yaml.Marshal(&p)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	for _, c := range []struct {
		variant string
		want    string // "" = key must be absent
		on      bool
	}{
		{"on", "enforce_allowlist: true", true},
		{"switch false", "enforce_allowlist: false", false},
		{"invalid yes", "enforce_allowlist: yes", false},
		{"switch absent", "", false},
		{"no network section", "", false},
	} {
		out := rewrite(egressPolicies[c.variant])
		if c.want == "" {
			if strings.Contains(out, "enforce_allowlist") {
				t.Errorf("%s: rewrite added the switch:\n%s", c.variant, out)
			}
		} else if !strings.Contains(out, c.want) {
			t.Errorf("%s: rewrite lost %q:\n%s", c.variant, c.want, out)
		}
		var back Policy
		if err := yaml.Unmarshal([]byte(out), &back); err != nil {
			t.Fatal(err)
		}
		if back.Network.EnforceAllowlist.Enabled() != c.on {
			t.Errorf("%s: switch after rewrite = %v, want %v", c.variant, back.Network.EnforceAllowlist.Enabled(), c.on)
		}
	}
}
