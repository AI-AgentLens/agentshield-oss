package policy

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

// addProtectedPathTaxonomy appends the node for the matched pattern, once.
func addProtectedPathTaxonomy(refs []string, pattern string) []string {
	ref, ok := protectedPathTaxonomy[pattern]
	if !ok {
		return refs
	}
	for _, r := range refs {
		if r == ref {
			return refs
		}
	}
	return append(refs, ref)
}
