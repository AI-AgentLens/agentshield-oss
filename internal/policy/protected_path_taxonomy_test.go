package policy

import (
	"os"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
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

// sshReceipt evaluates cmd the way the hook does (normalize, then the parsed
// evaluation), so the receipt is judged on the same operands production sees.
// Synthetic command text would have no parse, and the completeness gate (#4372
// pass 2) correctly refuses to refine a receipt it cannot check.
func sshReceipt(t *testing.T, engine *Engine, cmd string) EvalResult {
	t.Helper()
	const cwd = "/tmp/agentshield-ssh-receipt-test"
	n := normalize.NormalizeCommand(cmd, cwd)
	return engine.EvaluateWithParsedCwd(cmd, n.Paths, n.Parsed, cwd)
}

// checkSSHReceipt asserts BLOCK and an exact receipt: want "" means no node at
// all, never an empty ref.
func checkSSHReceipt(t *testing.T, engine *Engine, cmd, want string) {
	t.Helper()
	r := sshReceipt(t, engine, cmd)
	if r.Decision != DecisionBlock {
		t.Fatalf("%s: decision %s, want BLOCK (the receipt change must never move a decision)", cmd, r.Decision)
	}
	if want == "" {
		if len(r.TaxonomyRefs) != 0 {
			t.Errorf("%s: taxonomy %q, want none", cmd, r.TaxonomyRefs)
		}
		return
	}
	if len(r.TaxonomyRefs) != 1 || r.TaxonomyRefs[0] != want {
		t.Errorf("%s: taxonomy %q, want [%s]", cmd, r.TaxonomyRefs, want)
	}
}

const sshNode = "credential-exposure/private-key-access/"

// #4364: ~/.ssh/** covers more than keys. A receipt must not claim a private
// key was read when only config, authorized_keys or known_hosts was.
func TestProtectedPathSSHReceiptFollowsTheFile4364(t *testing.T) {
	engine, err := NewEngineWithAnalyzers(DefaultPolicy(), 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	for _, c := range []struct{ cmd, want string }{
		{"cat ~/.ssh/id_ed25519", sshNode + "ssh-private-key-read"},
		{"cat ~/.ssh/deploy_key", sshNode + "ssh-private-key-read"},
		{"cat ~/.ssh/id_rsa.pem", sshNode + "ssh-private-key-read"},
		{"cat ~/.ssh/config", sshNode + "ssh-config-access"},
		{"cat ~/.ssh/authorized_keys", sshNode + "ssh-authorized-keys-access"},
		{"cat ~/.ssh/known_hosts", ""},
		{"cat ~/.ssh/known_hosts.old", ""},
		{"cat ~/.ssh/id_rsa.pub", ""},
	} {
		checkSSHReceipt(t, engine, c.cmd, c.want)
	}
}

// #4372: the receipt names the worst file the command touched, and refines
// below a key read only when it can see every operand.
//
// Pass 1: classifying only the first hit let a config read listed before a key
// attest config, and the directory listed before a key attest nothing. The
// directory itself is a key read: archiving or copying it reads every key.
//
// Pass 2: the early check sees only literal argv paths. A key operand spelled
// with $HOME, a case variant, a substitution, an interpreter body or a glob is
// invisible to it, so refining on the visible hits alone still under-attested
// a key read. Gary's call (2026-10-16): refine only when the parse shows every
// operand is a hit; otherwise cite the key read, as main does. The cost, which
// these rows pin on purpose, is main's over-attestation when a non-path operand
// is present (`grep Host ~/.ssh/config`).
func TestProtectedPathSSHReceiptIsTheWorstFileTouched4372(t *testing.T) {
	engine, err := NewEngineWithAnalyzers(DefaultPolicy(), 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	key := sshNode + "ssh-private-key-read"
	for _, c := range []struct{ cmd, want string }{
		// Pass 1: order and the directory.
		{"cat ~/.ssh/config ~/.ssh/id_rsa", key},
		{"cat ~/.ssh/id_rsa ~/.ssh/config", key},
		{"ls ~/.ssh && cat ~/.ssh/id_ed25519", key},
		{"cat ~/.ssh/id_rsa.pub ~/.ssh/github_deploy", key},
		{"tar czf /tmp/x.tgz ~/.ssh", key},
		{"rsync -a ~/.ssh/ host:", key},
		{"cat ~/.ssh/known_hosts ~/.ssh/config", sshNode + "ssh-config-access"},
		{"cat ~/.ssh/config ~/.ssh/authorized_keys", sshNode + "ssh-authorized-keys-access"},
		{"cat ~/.ssh/id_rsa.pub ~/.ssh/known_hosts", ""},
		// Pass 2: a key operand the literal check cannot see.
		{"cat ~/.ssh/known_hosts $HOME/.ssh/id_rsa", key},
		{"cat ~/.ssh/config ~/.SSH/id_rsa", key},
		{"cat ~/.ssh/config $(echo ~/.ssh/id_rsa)", key},
		{"cat ~/.ssh/known_hosts && sh -c 'cat ~/.ssh/id_rsa'", key},
		{"cat ~/.ssh/config ~/.ss*/id_rsa", key},
		{"cat ~/.SSH/ID_RSA", key},
		// Accepted cost: a non-path operand makes the evidence incomplete.
		{"grep Host ~/.ssh/config", key},
	} {
		checkSSHReceipt(t, engine, c.cmd, c.want)
	}
}
