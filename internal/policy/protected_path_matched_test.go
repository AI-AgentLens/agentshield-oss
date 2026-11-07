package policy

import (
	"strings"
	"testing"
)

// The node names, spelled once for the #4665 tests.
const (
	nodeSSHKey     = "credential-exposure/private-key-access/ssh-private-key-read"
	nodeCloud      = "credential-exposure/cloud-credentials/cloud-credential-access"
	nodeGPG        = "credential-exposure/cryptographic-keys/gpg-key-access"
	nodeKube       = "credential-exposure/container-config/kubernetes-config-access"
	nodePkgManager = "credential-exposure/package-registry/package-manager-credential-access"
	nodeGradle     = "credential-exposure/build-tool-secrets/gradle-credential-access"
	nodeOpCLI      = "credential-exposure/password-manager/1password-cli-credential-access"
	nodeKeyring    = "credential-exposure/password-manager/gnome-keyring-access"
	nodeCopilot    = "credential-exposure/oauth-tokens/github-copilot-token-access"
	nodeAge        = "credential-exposure/cryptographic-keys/age-identity-key-access"
)

// #4665: a rule that matched a credential path by value attests the node the
// protected-path table names for that path, wherever $HOME is, and the
// generic protected-path node for a path under no row.
func TestMatchedPathTaxonomyRef4665(t *testing.T) {
	cases := []struct{ name, path, want string }{
		// The row's node, whatever the home directory is spelled as.
		{"pypirc linux home", "/home/u/.pypirc", nodePkgManager},
		{"pypirc mac home", "/Users/u/.pypirc", nodePkgManager},
		{"pypirc tilde", "~/.pypirc", nodePkgManager},
		{"pypirc $HOME", "$HOME/.pypirc", nodePkgManager},
		{"pypirc relative", ".pypirc", nodePkgManager},
		{"pypirc root", "/root/.pypirc", nodePkgManager},

		// One path per row family the premium catch-alls reach.
		{"aws credentials", "/home/u/.aws/credentials", nodeCloud},
		{"aws dir", "/home/u/.aws", nodeCloud},
		{"gcloud", "/home/u/.config/gcloud/application_default_credentials.json", nodeCloud},
		{"gnupg", "/home/u/.gnupg/private-keys-v1.d/k.key", nodeGPG},
		{"kube", "/home/u/.kube/config", nodeKube},
		{"gradle", "/home/u/.gradle/gradle.properties", nodeGradle},
		{"cargo toml", "/home/u/.cargo/credentials.toml", nodePkgManager},
		{"op cli", "/home/u/.config/op/config", nodeOpCLI},
		{"op cli dir with slash", "/home/u/.config/op/", nodeOpCLI},
		{"keyrings", "/home/u/.local/share/keyrings/login.keyring", nodeKeyring},
		{"copilot", "/home/u/.config/github-copilot/hosts.json", nodeCopilot},
		{"age xdg", "/home/u/.config/age/keys.txt", nodeAge},
		{"age dotdir", "/home/u/.age/key.txt", nodeAge},
		{"docker config", "/home/u/.docker/config.json", ProtectedPathNode},

		// A relative directory row, bare and with a file under it (#4683 item 4).
		{"ssh relative dir", ".ssh", nodeSSHKey},
		{"ssh relative file", ".ssh/id_rsa", nodeSSHKey},
		{"aws relative dir", ".aws", nodeCloud},

		// A path that two rows name takes the earlier row in table order: the
		// ~/.aws/** row sits above ~/.pypirc (#4683 item 4).
		{"two rows, directory row first", "/home/u/.aws/backup/.pypirc", nodeCloud},

		// SSH keeps the key-read node for every path under it, with no #4364
		// per-file refinement (Gary, 2026-10-30).
		{"ssh key", "/home/u/.ssh/id_ed25519", nodeSSHKey},
		{"ssh config", "/home/u/.ssh/config", nodeSSHKey},
		{"ssh known_hosts", "/home/u/.ssh/known_hosts", nodeSSHKey},
		{"ssh dir", "/home/u/.ssh", nodeSSHKey},

		// No row: the generic node.
		{"azure dir", "/home/u/.azure", ProtectedPathNode},
		{"docker dir", "/home/u/.docker", ProtectedPathNode},
		{"helm", "/home/u/.config/helm/repositories.yaml", ProtectedPathNode},
		{"cargo legacy name", "/home/u/.cargo/credentials", ProtectedPathNode},
		{"poetry", "/home/u/.config/pypoetry/auth.toml", ProtectedPathNode},
		{"bitwarden", "/home/u/.config/bitwarden-cli/data.json", ProtectedPathNode},
		{"pass store", "/home/u/.password-store/email.gpg", ProtectedPathNode},
		{"xdg ssh dir", "/home/u/.config/ssh/id_rsa", ProtectedPathNode},
		{"empty", "", ProtectedPathNode},

		// Whole segments only: a file that merely ends in a row's name, or a
		// directory whose name ends in one, is not that file.
		{"suffix without boundary", "/home/u/release.pypirc", ProtectedPathNode},
		{"dir suffix without boundary", "/home/u/foo.ssh/id_rsa", ProtectedPathNode},
		{"backup of a file row", "/home/u/.gradle/gradle.properties.bak", ProtectedPathNode},

		// Cleaned first: the receipt names the file the path resolves to.
		{"dot-dot out of ssh", "/home/u/.ssh/../.pypirc", nodePkgManager},
		{"dot-dot to home", "/home/u/.ssh/..", ProtectedPathNode},
		{"dot segment", "/home/u/./.kube/config", nodeKube},

		// A relative directory row, with and without a file under it (#4683
		// item 4: the mutants that broke the dir-prefix arms survived).
		{"relative ssh dir", ".ssh", nodeSSHKey},
		{"relative ssh file", ".ssh/id_rsa", nodeSSHKey},
		{"relative kube file", ".kube/config", nodeKube},

		// A path under two rows takes the first row in table order: .aws
		// precedes .pypirc, so a .pypirc inside .aws is a cloud read.
		{"two rows, earlier wins", "/home/u/.aws/backup/.pypirc", nodeCloud},
		{"two rows, ssh before pypirc", "/home/u/.ssh/.pypirc", nodeSSHKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchedPathTaxonomyRef(tc.path); got != tc.want {
				t.Errorf("MatchedPathTaxonomyRef(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// Every row of the table reaches its own node through MatchedPathTaxonomyRef,
// under two home spellings. A new row is covered without a new case, and a
// row an earlier row shadows fails here.
func TestMatchedPathEveryRowReachesItsNode4665(t *testing.T) {
	for _, n := range protectedPathTaxonomy {
		rel := strings.TrimPrefix(n.Pattern, "~/")
		if dir, ok := strings.CutSuffix(rel, "/**"); ok {
			rel = dir + "/some-file"
		}
		for _, home := range []string{"/home/u/", "/Users/u/"} {
			if got := MatchedPathTaxonomyRef(home + rel); got != n.TaxonomyRef {
				t.Errorf("row %s: MatchedPathTaxonomyRef(%q) = %q, want the row's %q",
					n.Pattern, home+rel, got, n.TaxonomyRef)
			}
		}
	}
}

// rowNamesPathAnywhere understands two row shapes. A row of any other shape
// would match nothing there and silently attest the generic node, so the
// table may hold only those two.
func TestMatchedPathRowShapes4665(t *testing.T) {
	for _, n := range protectedPathTaxonomy {
		rel, ok := strings.CutPrefix(n.Pattern, "~/")
		if !ok {
			t.Errorf("row %s: does not start with ~/", n.Pattern)
			continue
		}
		rel = strings.TrimSuffix(rel, "/**")
		if rel == "" || strings.ContainsAny(rel, "*?[]{}\\") {
			t.Errorf("row %s: rowNamesPathAnywhere supports only ~/<literal> and ~/<literal>/**", n.Pattern)
		}
	}
}

// #4683 item 2, pinned as current behaviour: the path is cleaned with
// path.Clean, which does not read a backslash as a separator, so a Windows
// spelling matches no row and attests the generic node. Only the agentless
// Windows client reaches it. Closing it (replace `\` with `/` first) is a
// deliberate change that flips these rows; it moves a receipt's node, so it is
// a trust-surface change that waits for an adversarial pass.
func TestMatchedPathWindowsBackslashIsAPinnedResidual4683(t *testing.T) {
	for _, p := range []string{
		`C:\Users\u\.ssh`,
		`C:\Users\u\.pypirc`,
		`C:\Users\u\.aws`,
		`C:\Users\u\.kube`,
	} {
		if got := MatchedPathTaxonomyRef(p); got != ProtectedPathNode {
			t.Errorf("MatchedPathTaxonomyRef(%q) = %q; the residual was closed, so flip this row to its node (#4683 item 2)", p, got)
		}
	}
}
