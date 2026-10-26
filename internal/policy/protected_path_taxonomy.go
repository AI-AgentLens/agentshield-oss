package policy

import (
	"path/filepath"
	"strings"
)

// protectedPathTaxonomy names the taxonomy node a protected-path BLOCK attests
// to, keyed by the default policy's pattern (#4336). Without it the early
// protected-path exit recorded a BLOCK with no taxonomy, so a plain `cat` of an
// SSH key mapped to no control while the $HOME spelling (which reaches the
// sec-block-ssh-private rule) did.
//
// Each node is the one the shipped community rule for the same credential
// already cites, so both spellings of one read render one control set. Not
// covered on purpose: /etc, /System, /Library. No shipped rule names a node
// for "any path under the system tree", and inventing one is a taxonomy call.
// Those BLOCKs stay unattributed and the gap is pinned by a test.
//
// Evidence only: this table never changes a decision.
var protectedPathTaxonomy = map[string]string{
	"~/.ssh/**":           "credential-exposure/private-key-access/ssh-private-key-read",
	"~/.aws/**":           "credential-exposure/cloud-credentials/cloud-credential-access",
	"~/.config/gcloud/**": "credential-exposure/cloud-credentials/cloud-credential-access",
	"~/.gnupg/**":         "credential-exposure/cryptographic-keys/gpg-key-access",
	"~/.kube/**":          "credential-exposure/container-config/kubernetes-config-access",
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
		return "credential-exposure/private-key-access/ssh-config-access"
	case strings.HasPrefix(base, "authorized_keys"):
		return "credential-exposure/private-key-access/ssh-authorized-keys-access"
	case strings.HasPrefix(base, "known_hosts"), strings.HasSuffix(base, ".pub"),
		base == "allowed_signers", base == "environment", base == "rc":
		return ""
	}
	return protectedPathTaxonomy["~/.ssh/**"]
}

// sshSeverity orders the ssh nodes so a command that touches several files
// attests the worst one: a key read outranks authorized_keys, which outranks
// config, which outranks a file with no node.
func sshSeverity(ref string) int {
	switch ref {
	case protectedPathTaxonomy["~/.ssh/**"]:
		return 3
	case "credential-exposure/private-key-access/ssh-authorized-keys-access":
		return 2
	case "credential-exposure/private-key-access/ssh-config-access":
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

// addProtectedPathTaxonomy appends the node for the matched pattern, once.
// hits are every path that matched it; only patterns that cover mixed content
// use them.
func addProtectedPathTaxonomy(refs []string, pattern string, hits []string) []string {
	ref, ok := protectedPathTaxonomy[pattern]
	if pattern == "~/.ssh/**" {
		ref, ok = sshTaxonomyOf(hits), true
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
