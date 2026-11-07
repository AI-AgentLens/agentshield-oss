package policy

import (
	"path"
	"path/filepath"
	"strings"
)

// protectedPathNode pairs a protected_paths pattern with the taxonomy node its
// BLOCK attests to. TaxonomyRef is a field set to a string literal on purpose:
// scripts/check-taxonomy-refs.sh (CI's taxonomy-refs job) resolves exactly that
// spelling against Comply's taxonomy tree, so a renamed or retired node turns
// CI red. The map of bare strings this replaced was invisible to it (#4560).
type protectedPathNode struct {
	Pattern     string
	TaxonomyRef string
}

// protectedPathTaxonomy names the taxonomy node a protected-path BLOCK attests
// to, keyed by the pattern as a shipped policy or pack writes it (#4336). Without
// it the early protected-path exit recorded a BLOCK with no taxonomy, so a plain
// `cat` of an SSH key mapped to no control while the $HOME spelling (which
// reaches the sec-block-ssh-private rule) did.
//
// Each node is one a shipped rule already cites for a read of the same file,
// so the canonical spelling, the $HOME spelling and the MCP read render one
// control set. The first five are the Go default policy's patterns (#4336).
// The rest are the patterns the community and premium packs add (#4560): they
// refine the generic ProtectedPathNode those patterns fall back to (#4645), so
// `cat ~/.npmrc` attests the package-manager credential node the MCP read of
// the same file cites rather than "a protected path was touched".
//
// Every other pattern falls back to ProtectedPathNode (#4645), except the ones
// unattributedProtectedPaths names: /etc, /System, /Library (no shipped rule
// names a node for "any path under the system tree", and inventing one is a
// taxonomy call) and AgentShield's own config directory. Those BLOCKs stay
// unattributed and the gap is pinned by a test.
//
// Every shipped pattern without a row here is listed, with the reason, in
// protectedPathGenericOnly (it attests the generic node) or in
// unattributedProtectedPaths (it attests none). The ratchet
// TestEveryShippedProtectedPathIsAttributedOrListed4560 fails on a new shipped
// pattern that is in none of them, so the choice is made when it is added.
//
// Evidence only: this table never changes a decision.
var protectedPathTaxonomy = []protectedPathNode{
	// Go default policy (#4336).
	{Pattern: "~/.ssh/**", TaxonomyRef: "credential-exposure/private-key-access/ssh-private-key-read"},
	{Pattern: "~/.aws/**", TaxonomyRef: "credential-exposure/cloud-credentials/cloud-credential-access"},
	{Pattern: "~/.config/gcloud/**", TaxonomyRef: "credential-exposure/cloud-credentials/cloud-credential-access"},
	{Pattern: "~/.gnupg/**", TaxonomyRef: "credential-exposure/cryptographic-keys/gpg-key-access"},
	{Pattern: "~/.kube/**", TaxonomyRef: "credential-exposure/container-config/kubernetes-config-access"},

	// Community pack secrets-pii.yaml (#4560). The node in each row is the one
	// the named rule cites for a read of the same file.
	{Pattern: "~/.npmrc", TaxonomyRef: "credential-exposure/package-registry/package-manager-credential-access"},                  // mcp-sec-block-package-manager-creds
	{Pattern: "~/.pypirc", TaxonomyRef: "credential-exposure/package-registry/package-manager-credential-access"},                 // mcp-sec-block-pypirc
	{Pattern: "~/.cargo/credentials.toml", TaxonomyRef: "credential-exposure/package-registry/package-manager-credential-access"}, // sec-block-package-manager-credentials, mcp-sec-block-cargo-credentials
	{Pattern: "~/.gem/credentials", TaxonomyRef: "credential-exposure/package-registry/package-manager-credential-access"},        // sec-block-package-manager-credentials, mcp-sec-block-gem-credentials
	{Pattern: "~/.gradle/gradle.properties", TaxonomyRef: "credential-exposure/build-tool-secrets/gradle-credential-access"},      // sec-block-gradle-credential-access, mcp-sec-block-gradle-properties
	{Pattern: "~/.git-credentials", TaxonomyRef: "credential-exposure/version-control/git-credential-access"},                     // mcp-sec-block-git-credentials
	{Pattern: "~/.terraform.d/**", TaxonomyRef: "credential-exposure/cloud-credentials/terraform-credential-access"},              // sec-block-terraform-credentials
	{Pattern: "~/.config/op/**", TaxonomyRef: "credential-exposure/password-manager/1password-cli-credential-access"},             // mcp-sec-block-1password-cli-access
	{Pattern: "~/.local/share/keyrings/**", TaxonomyRef: "credential-exposure/password-manager/gnome-keyring-access"},             // mcp-sec-block-gnome-keyring-access
	{Pattern: "~/.config/github-copilot/**", TaxonomyRef: "credential-exposure/oauth-tokens/github-copilot-token-access"},         // mcp-sec-block-github-copilot-access
	{Pattern: "~/.config/age/**", TaxonomyRef: "credential-exposure/cryptographic-keys/age-identity-key-access"},                  // sec-block-age-identity-key, mcp-sec-block-age-identity-access
	{Pattern: "~/.age/**", TaxonomyRef: "credential-exposure/cryptographic-keys/age-identity-key-access"},                         // sec-block-age-identity-key, mcp-sec-block-sops-age-key-access
	// No specific node exists for these three; the generic node's own prose
	// names each file, and the MCP twin of the same pattern cites it.
	{Pattern: "~/.docker/config.json", TaxonomyRef: "credential-exposure/config-file-access/protected-path"}, // mcp-gen-protected-path-docker-configjson
	{Pattern: "~/.netrc", TaxonomyRef: "credential-exposure/config-file-access/protected-path"},              // mcp-gen-protected-path-netrc
	{Pattern: "~/.config/gh/**", TaxonomyRef: "credential-exposure/config-file-access/protected-path"},       // mcp-gen-protected-path-config-gh

	// Premium pack supply-chain.yaml (#4560). Attestation covers what the
	// install enforces, whatever tier the pattern ships in (2026-09-10).
	{Pattern: "~/.yarnrc", TaxonomyRef: "credential-exposure/package-registry/package-manager-credential-access"}, // mcp-sec-block-yarnrc-classic
}

// protectedPathGenericOnly lists the shipped patterns that deliberately have no
// row above, each with the reason no specific node was chosen. A BLOCK on one
// of them keeps its decision and attests the generic ProtectedPathNode, the
// #4645 fallback, and nothing more specific: a guessed specific node is worse
// than the generic one. Choosing one is a taxonomy call.
var protectedPathGenericOnly = map[string]string{
	"~/.m2/settings.xml": "three candidate nodes, a taxonomy call (#4560): package-manager-credential-access " +
		"(sec-block-package-manager-credentials), maven-credential-access (named for the file), protected-path (MCP twin)",
	"~/.vault-token": "three candidate nodes, a taxonomy call (#4560): protected-path (MCP twin), " +
		"secrets-manager-credential-access (names the file), infrastructure-session-token-theft (lists the read as its example)",
	"~/.pip/**":            "registry config, protected for the write (package-registry-redirect); no credential node fits a read (#4560)",
	"~/.config/pip/**":     "registry config, protected for the write (package-registry-redirect); no credential node fits a read (#4560)",
	"~/.cargo/config.toml": "registry config, protected for the write (package-registry-redirect); no credential node fits a read (#4560)",
}

// protectedPathRef is the node for one pattern, if the table has a row for it.
func protectedPathRef(pattern string) (string, bool) {
	for _, n := range protectedPathTaxonomy {
		if n.Pattern == pattern {
			return n.TaxonomyRef, true
		}
	}
	return "", false
}

// MatchedPathTaxonomyRef is the receipt node for a credential path that a rule
// matched by its value, not through protected_paths (#4665). An MCP structural
// rule that sets `taxonomy_from: matched_path` records it in place of its one
// static node. That is how the premium alternative-argument-key catch-alls,
// which match about 60 credential path families under one rule, stop
// attesting an SSH key read for a read of ~/.pypirc.
//
// It reads the same rows a protected-path BLOCK reads, so a read of one file
// attests one node on every surface. A path under no row gets
// ProtectedPathNode (Gary, 2026-10-30).
//
// It differs from addProtectedPathTaxonomy in two ways, both on purpose:
//   - It ignores where $HOME is. The rules that call it match `\.pypirc$`
//     under any directory, so the lookup does too. A row's pattern without
//     its `~/` is matched against whole path segments: at the end of the
//     path for a file row, anywhere in it for a `/**` row. So
//     /home/u/.pypirc and /Users/u/.pypirc attest the same node.
//   - It skips #4364's per-file ssh refinement. Any path under the ~/.ssh/**
//     row gets that row's node (Gary, 2026-10-30: ssh paths keep
//     ssh-private-key-read).
//
// The path is cleaned first, so `~/.ssh/../.pypirc` attests the file it
// names. Rows are tried in table order, and the first match wins.
func MatchedPathTaxonomyRef(p string) string {
	p = path.Clean(p)
	for _, n := range protectedPathTaxonomy {
		if rowNamesPathAnywhere(n.Pattern, p) {
			return n.TaxonomyRef
		}
	}
	return ProtectedPathNode
}

// rowNamesPathAnywhere reports whether p is the file a row names, or lies in
// the directory it names, under any home directory. It understands the two
// row shapes the table uses: `~/<literal>` and `~/<literal>/**`
// (TestMatchedPathRowShapes4665 fails on any other). A row of another shape
// matches nothing here, so its paths fall back to ProtectedPathNode.
func rowNamesPathAnywhere(pattern, p string) bool {
	rel, ok := strings.CutPrefix(pattern, "~/")
	if !ok {
		return false
	}
	if dir, isDir := strings.CutSuffix(rel, "/**"); isDir {
		return p == dir || strings.HasPrefix(p, dir+"/") ||
			strings.HasSuffix(p, "/"+dir) || strings.Contains(p, "/"+dir+"/")
	}
	return p == rel || strings.HasSuffix(p, "/"+rel)
}

// The files under ~/.ssh that refine below a key read (#4364). Written as
// protectedPathNode literals so the CI ref gate sees them too.
var (
	sshConfigNode         = protectedPathNode{Pattern: "~/.ssh/config", TaxonomyRef: "credential-exposure/private-key-access/ssh-config-access"}
	sshAuthorizedKeysNode = protectedPathNode{Pattern: "~/.ssh/authorized_keys*", TaxonomyRef: "credential-exposure/private-key-access/ssh-authorized-keys-access"}
)

// sshKeyRef is the ~/.ssh/** row: a key read.
func sshKeyRef() string {
	ref, _ := protectedPathRef("~/.ssh/**")
	return ref
}

// sshTaxonomy refines the `~/.ssh/**` pattern by the file that matched (#4364).
// The pattern covers the whole directory, but only key files are a private-key
// read: config and authorized_keys have their own nodes (the ones the MCP
// secrets pack cites, so both surfaces render one control set), and
// known_hosts and public keys have no shipped node, so they stay unattributed
// rather than claiming a key was read. Anything else is treated as a key:
// custom key names cannot be enumerated, the non-key files can.
//
// The directory itself is a key read (#4372 pass 1): `tar`, `cp -r`, `zip -r`
// or `grep -r` on it read every key inside, and MCP's catch-all
// mcp-sec-block-ssh-dir-read cites the same node.
func sshTaxonomy(hit string) string {
	base := strings.ToLower(filepath.Base(filepath.Clean(hit)))
	switch {
	case base == "config":
		return sshConfigNode.TaxonomyRef
	case strings.HasPrefix(base, "authorized_keys"):
		return sshAuthorizedKeysNode.TaxonomyRef
	case strings.HasPrefix(base, "known_hosts"), strings.HasSuffix(base, ".pub"),
		base == "allowed_signers", base == "environment", base == "rc":
		return ""
	}
	return sshKeyRef()
}

// sshSeverity orders the ssh nodes so a command that touches several files
// attests the worst one: a key read outranks authorized_keys, which outranks
// config, which outranks a file with no node.
func sshSeverity(ref string) int {
	switch ref {
	case sshKeyRef():
		return 3
	case sshAuthorizedKeysNode.TaxonomyRef:
		return 2
	case sshConfigNode.TaxonomyRef:
		return 1
	}
	return 0
}

// sshTaxonomyOf is the most severe node across every path under the ssh
// directory that the command touched (#4372 pass 1). Classifying only the
// first hit let a config read listed before a key attest config, and a listing
// of the directory before a key read attest nothing, while a key was read in
// both.
func sshTaxonomyOf(hits []string) string {
	best := ""
	for _, h := range hits {
		if ref := sshTaxonomy(h); sshSeverity(ref) > sshSeverity(best) {
			best = ref
		}
	}
	return best
}

// ProtectedPathNode is the node a protected-path BLOCK attests to when its
// pattern has no more specific node in protectedPathTaxonomy (#4645). It is
// the node the generated MCP twins of the shipped protected_paths already
// cite (cmd/mcp-gen, mcp-gen-protected-path-*), so a shell BLOCK and a
// file-tool BLOCK on one path render one control set. A customer's own
// protected_paths entry (a pack's or policy.yaml's) lands here too: "the
// policy declared this path off-limits" is what the node describes.
//
// A const is invisible to scripts/check-taxonomy-refs.sh, which reads
// TaxonomyRef literals. The same string is the TaxonomyRef of the
// ~/.docker/config.json, ~/.netrc and ~/.config/gh/** rows above, so the CI
// ref gate resolves it there; the #4560 ratchet fails if no row carries it.
const ProtectedPathNode = "credential-exposure/config-file-access/protected-path"

// ManagedConfigProtectedPath is the glob a managed host adds to
// protected_paths for AgentShield's own config directory (#3620, the CLI's
// protectManagedConfigDir).
const ManagedConfigProtectedPath = "~/.agentshield/**"

// unattributedProtectedPaths are the patterns whose BLOCK keeps recording no
// taxonomy, because which node they attest to is an open decision rather than
// a default:
//   - the system trees of configs/default_policy.yaml (#4336: no shipped rule
//     names a node for "any path under the system tree");
//   - AgentShield's own config directory on a managed host (#4431 item 2,
//     Gary's call: tampering with the guard is not a credential read).
//
// A pattern here is matched exactly as written, so a customer's narrower
// pattern under /etc (`/etc/acme/secrets/**`) still gets ProtectedPathNode.
var unattributedProtectedPaths = map[string]bool{
	"/etc/**":                  true,
	"/System/**":               true,
	"/Library/**":              true,
	ManagedConfigProtectedPath: true,
}

// ProtectedPathTaxonomyRefs is the taxonomy a protected-path BLOCK on pattern
// records, for the tool-call surfaces (#4645). hits are the paths that
// matched it; see addProtectedPathTaxonomy.
func ProtectedPathTaxonomyRefs(pattern string, hits []string) []string {
	return addProtectedPathTaxonomy(nil, pattern, hits)
}

// addProtectedPathTaxonomy appends the node for the matched pattern, once.
// hits are every path that matched it; only patterns that cover mixed content
// use them. A pattern with no entry in protectedPathTaxonomy attests to
// ProtectedPathNode unless unattributedProtectedPaths names it (#4645).
func addProtectedPathTaxonomy(refs []string, pattern string, hits []string) []string {
	ref, ok := protectedPathRef(pattern)
	if pattern == "~/.ssh/**" {
		ref, ok = sshTaxonomyOf(hits), true
	}
	if !ok && !unattributedProtectedPaths[pattern] {
		ref, ok = ProtectedPathNode, true
	}
	if !ok || ref == "" {
		return refs
	}
	for _, r := range refs {
		if r == ref {
			return refs
		}
	}
	return append(refs, ref)
}
