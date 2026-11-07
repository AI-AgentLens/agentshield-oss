package policy

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// shippedProtectedPathEngine builds an engine over what an install enforces:
// the Go default policy, the embedded community packs and, when this tree has
// them, the premium packs. Its protected_paths are therefore every shipped
// pattern a production BLOCK can name.
func shippedProtectedPathEngine(t *testing.T, premium bool) (*Engine, *Policy) {
	t.Helper()
	pol, _, err := LoadEmbeddedShellPacks(DefaultPolicy())
	if err != nil {
		t.Fatalf("LoadEmbeddedShellPacks: %v", err)
	}
	if premium {
		pol, _, err = LoadPacks(filepath.Join("..", "..", "packs", "premium"), pol)
		if err != nil {
			t.Fatalf("LoadPacks(premium): %v", err)
		}
	}
	engine, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	return engine, pol
}

// #4560: the community and premium packs add protected paths beyond the five
// the Go default policy declares, and every one of them BLOCKed with no node.
// Measured on 2dd1527f: `cat ~/.config/gh/hosts.yml` BLOCKed as `protected-path`
// with no taxonomy, while an MCP read of the same file cited
// config-file-access/protected-path. A production BLOCK on 2026-10-27 had that
// shape. #4645 then gave every such BLOCK the generic protected-path node.
// Each row's node is the one a shipped rule cites for a read of the same file
// (for docker, netrc and gh that is the generic node itself), and both shell
// spellings must now carry it.
func TestProtectedPathPackPatternsCarryTaxonomy4560(t *testing.T) {
	const ce = "credential-exposure/"
	rows := []struct {
		file, want string
		premium    bool
	}{
		{".npmrc", ce + "package-registry/package-manager-credential-access", false},
		{".pypirc", ce + "package-registry/package-manager-credential-access", false},
		{".cargo/credentials.toml", ce + "package-registry/package-manager-credential-access", false},
		{".gem/credentials", ce + "package-registry/package-manager-credential-access", false},
		{".gradle/gradle.properties", ce + "build-tool-secrets/gradle-credential-access", false},
		{".git-credentials", ce + "version-control/git-credential-access", false},
		{".terraform.d/credentials.tfrc.json", ce + "cloud-credentials/terraform-credential-access", false},
		{".config/op/config", ce + "password-manager/1password-cli-credential-access", false},
		{".local/share/keyrings/login.keyring", ce + "password-manager/gnome-keyring-access", false},
		{".config/github-copilot/hosts.json", ce + "oauth-tokens/github-copilot-token-access", false},
		{".config/age/keys.txt", ce + "cryptographic-keys/age-identity-key-access", false},
		{".age/key.txt", ce + "cryptographic-keys/age-identity-key-access", false},
		{".docker/config.json", ce + "config-file-access/protected-path", false},
		{".netrc", ce + "config-file-access/protected-path", false},
		{".config/gh/hosts.yml", ce + "config-file-access/protected-path", false},
		{".yarnrc", ce + "package-registry/package-manager-credential-access", true},
	}
	community, _ := shippedProtectedPathEngine(t, false)
	var premium *Engine
	if ossbuild.PremiumPacksPresent() {
		premium, _ = shippedProtectedPathEngine(t, true)
	}
	for _, r := range rows {
		engine := community
		if r.premium {
			if premium == nil {
				continue // the OSS tree does not ship the premium pattern
			}
			engine = premium
		}
		// The canonical spelling takes the early protected-path exit, so the
		// table is the only source of evidence: the receipt is exactly its node.
		checkSSHReceipt(t, engine, "cat ~/"+r.file, r.want)

		// The $HOME spelling reaches the post-pass. Other rules may add their
		// own nodes; this one must be among them.
		cmd := "cat $HOME/" + r.file
		got := sshReceipt(t, engine, cmd)
		if got.Decision != DecisionBlock {
			t.Fatalf("%s: decision %s, want BLOCK", cmd, got.Decision)
		}
		if !containsTaxonomyRef(got.TaxonomyRefs, r.want) {
			t.Errorf("%s: taxonomy %q, want it to include %s", cmd, got.TaxonomyRefs, r.want)
		}
	}
}

// The shipped patterns whose specific node is a taxonomy call get no specific
// node until the call is made. They keep main's generic fallback (#4645): the
// receipt is exactly ProtectedPathNode, never nothing and never a guessed
// specific node. Pinned so that adding a row has to change this test too.
func TestProtectedPathCallsKeepGenericNode4560(t *testing.T) {
	community, _ := shippedProtectedPathEngine(t, false)
	for _, file := range []string{".m2/settings.xml", ".vault-token"} {
		checkSSHReceipt(t, community, "cat ~/"+file, ProtectedPathNode)
	}
	if !ossbuild.PremiumPacksPresent() {
		return
	}
	premium, _ := shippedProtectedPathEngine(t, true)
	for _, file := range []string{".pip/pip.conf", ".config/pip/pip.conf", ".cargo/config.toml"} {
		checkSSHReceipt(t, premium, "cat ~/"+file, ProtectedPathNode)
	}
}

// minShippedProtectedPaths is the floor on the patterns the ratchet below
// sees without premium packs: the Go defaults, the community packs and the
// shipped template (25 on introduction). A loader regression that drops the
// packs' protected_paths leaves 8, and the ratchet would pass over them.
const minShippedProtectedPaths = 20

// premiumOnlyProtectedPaths are the patterns only packs/premium declares. The
// OSS tree cannot see them, so the stale-row check skips them there.
var premiumOnlyProtectedPaths = map[string]bool{
	"~/.yarnrc": true, "~/.pip/**": true, "~/.config/pip/**": true, "~/.cargo/config.toml": true,
}

// TestEveryShippedProtectedPathIsAttributedOrListed4560 is the ratchet. Every
// protected_paths pattern a shipped policy or pack declares is in exactly one
// of: protectedPathTaxonomy (a specific node), protectedPathGenericOnly (a
// reason it keeps the generic #4645 fallback) or unattributedProtectedPaths
// (no node at all), and no list names a pattern nothing ships. Before #4560,
// 17 community patterns and 4 premium ones were in none; since #4645 a pattern
// in none still attests the generic node, so what this ratchet now enforces is
// that "generic" was chosen, not defaulted into.
func TestEveryShippedProtectedPathIsAttributedOrListed4560(t *testing.T) {
	shipped := map[string]string{}
	add := func(src string, pats []string) {
		for _, p := range pats {
			if _, seen := shipped[p]; !seen {
				shipped[p] = src
			}
		}
	}
	_, community := shippedProtectedPathEngine(t, false)
	add("community", community.Defaults.ProtectedPaths)
	tmpl, err := Load(filepath.Join("..", "..", "configs", "default_policy.yaml"))
	if err != nil {
		t.Fatalf("load configs/default_policy.yaml: %v", err)
	}
	add("configs/default_policy.yaml", tmpl.Defaults.ProtectedPaths)
	if len(shipped) < minShippedProtectedPaths {
		t.Fatalf("only %d shipped protected_paths patterns found (floor %d): the packs' protected_paths are not being loaded, so this ratchet would check nothing",
			len(shipped), minShippedProtectedPaths)
	}
	premiumPresent := ossbuild.PremiumPacksPresent()
	if premiumPresent {
		_, premium := shippedProtectedPathEngine(t, true)
		add("premium", premium.Defaults.ProtectedPaths)
	}

	rows := map[string]bool{}
	fallbackVisible := false
	for _, n := range protectedPathTaxonomy {
		if n.TaxonomyRef == "" {
			t.Errorf("%s: row with an empty TaxonomyRef; delete the row instead", n.Pattern)
		}
		if rows[n.Pattern] {
			t.Errorf("%s: two rows for one pattern", n.Pattern)
		}
		rows[n.Pattern] = true
		fallbackVisible = fallbackVisible || n.TaxonomyRef == ProtectedPathNode
		if _, listed := protectedPathGenericOnly[n.Pattern]; listed {
			t.Errorf("%s: has a node AND is listed in protectedPathGenericOnly; pick one", n.Pattern)
		}
		if unattributedProtectedPaths[n.Pattern] {
			t.Errorf("%s: has a node AND is listed in unattributedProtectedPaths; pick one", n.Pattern)
		}
	}
	for p := range protectedPathGenericOnly {
		if unattributedProtectedPaths[p] {
			t.Errorf("%s: listed in protectedPathGenericOnly AND unattributedProtectedPaths; pick one", p)
		}
	}
	// ProtectedPathNode is a const, which scripts/check-taxonomy-refs.sh cannot
	// see. It reaches CI's ref gate only as the TaxonomyRef literal of a row.
	if !fallbackVisible {
		t.Errorf("no protectedPathTaxonomy row has TaxonomyRef %q, so the CI ref gate no longer resolves the fallback node", ProtectedPathNode)
	}

	var missing []string
	for p, src := range shipped {
		if !rows[p] && protectedPathGenericOnly[p] == "" && !unattributedProtectedPaths[p] {
			missing = append(missing, p+" ("+src+")")
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("shipped protected path %s has no taxonomy row and is in neither protectedPathGenericOnly nor unattributedProtectedPaths: "+
			"a BLOCK on it attests the generic node by default. Add the node a shipped rule cites for a read of the same file, or list it with the reason", m)
	}

	// A row or reason for a pattern nothing ships is dead evidence. The
	// premium-only patterns can only be checked where the premium packs are.
	stale := func(p string) bool {
		if _, ok := shipped[p]; ok {
			return false
		}
		return premiumPresent || !premiumOnlyProtectedPaths[p]
	}
	if premiumPresent {
		for p := range premiumOnlyProtectedPaths {
			if shipped[p] != "premium" {
				t.Errorf("premiumOnlyProtectedPaths names %s, which the premium packs do not add (source: %q)", p, shipped[p])
			}
		}
	}
	for p := range rows {
		if stale(p) {
			t.Errorf("protectedPathTaxonomy has a row for %s, which no shipped policy or pack declares", p)
		}
	}
	for p := range protectedPathGenericOnly {
		if stale(p) {
			t.Errorf("protectedPathGenericOnly lists %s, which no shipped policy or pack declares", p)
		}
	}
	// The managed config directory is added by the CLI on a managed host, not
	// declared by a policy or pack, as in TestShippedProtectedPaths_MatchEveryShippedDeclaration.
	for p := range unattributedProtectedPaths {
		if p != ManagedConfigProtectedPath && stale(p) {
			t.Errorf("unattributedProtectedPaths lists %s, which no shipped policy or pack declares", p)
		}
	}
	t.Logf("shipped protected_paths patterns: %d (premium packs present: %v)", len(shipped), premiumPresent)
}
