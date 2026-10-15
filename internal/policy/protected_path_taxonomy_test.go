package policy

import (
	"os"
	"testing"
)

// #4336: the protected-path early exit used to BLOCK with no taxonomy, so a
// plain read of a credential attested no control. Each default pattern with a
// shipped community rule for the same credential now cites that rule's node.
func TestProtectedPathBlockCarriesTaxonomy4336(t *testing.T) {
	engine, err := NewEngine(DefaultPolicy())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	home, _ := os.UserHomeDir()
	cases := []struct{ path, want string }{
		{home + "/.ssh/id_rsa", "credential-exposure/private-key-access/ssh-private-key-read"},
		{home + "/.aws/credentials", "credential-exposure/cloud-credentials/cloud-credential-access"},
		{home + "/.config/gcloud/credentials.db", "credential-exposure/cloud-credentials/cloud-credential-access"},
		{home + "/.gnupg/private-keys-v1.d/k", "credential-exposure/cryptographic-keys/gpg-key-access"},
		{home + "/.kube/config", "credential-exposure/container-config/kubernetes-config-access"},
	}
	for _, c := range cases {
		r := engine.Evaluate("cat "+c.path, []string{c.path})
		if r.Decision != DecisionBlock {
			t.Fatalf("%s: decision %s, want BLOCK", c.path, r.Decision)
		}
		if len(r.TaxonomyRefs) != 1 || r.TaxonomyRefs[0] != c.want {
			t.Errorf("%s: taxonomy %v, want [%s]", c.path, r.TaxonomyRefs, c.want)
		}
	}
}

// The system trees have no shipped node. Pinned as an unattributed gap so that
// closing it is deliberate (#4336): the BLOCK must stay, the taxonomy stays empty.
func TestProtectedPathSystemTreeStaysUnattributed4336(t *testing.T) {
	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = []string{"/etc/**"} // as in configs/default_policy.yaml
	engine, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	r := engine.Evaluate("cat /etc/hosts", []string{"/etc/hosts"})
	if r.Decision != DecisionBlock || len(r.TaxonomyRefs) != 0 {
		t.Fatalf("got %s %v; want BLOCK with no taxonomy", r.Decision, r.TaxonomyRefs)
	}
}

// A user policy that names a path the table does not know keeps BLOCKing
// without a taxonomy: the table adds evidence, it is never a precondition.
func TestProtectedPathUnknownPatternStillBlocks4336(t *testing.T) {
	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = []string{"/srv/vault/**"}
	engine, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	r := engine.Evaluate("cat /srv/vault/k", []string{"/srv/vault/k"})
	if r.Decision != DecisionBlock || len(r.TaxonomyRefs) != 0 {
		t.Fatalf("got %s %v", r.Decision, r.TaxonomyRefs)
	}
}
