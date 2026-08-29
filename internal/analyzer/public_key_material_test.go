package analyzer

import "testing"

// Public-by-design files under a credential directory are not credentials
// (follow-up to #3541 / #3286).
//
// The direction that matters most here is the NEGATIVE one: every entry that
// stops being a credential is a detection removed, so the private-key cases
// below are not padding — they are the reason this exemption is two rules wide
// instead of "anything under .ssh/ that isn't id_rsa".
func TestIsPublicKeyMaterial(t *testing.T) {
	public := []string{
		"~/.ssh/known_hosts",
		"~/.ssh/known_hosts2",
		"/home/deploy/.ssh/known_hosts.old",
		"~/.ssh/id_rsa.pub",
		"~/.ssh/id_ed25519.pub",
		"/etc/ssh/ssh_host_ecdsa_key.pub",
	}
	for _, p := range public {
		t.Run("public/"+p, func(t *testing.T) {
			if !isPublicKeyMaterial(p) {
				t.Errorf("isPublicKeyMaterial(%q) = false, want true", p)
			}
			if isCredentialPath(p) {
				t.Errorf("isCredentialPath(%q) = true — a public file must not be a credential source", p)
			}
		})
	}

	// Anything a leak would matter for must stay classified.
	private := []string{
		"~/.ssh/id_rsa",
		"~/.ssh/id_ed25519",
		"~/.ssh/config",
		"~/.ssh/authorized_keys",
		"~/.aws/credentials",
		"~/.kube/config",
		"~/.gnupg/secring.gpg",
		"~/.netrc",
		"~/.npmrc",
	}
	for _, p := range private {
		t.Run("private/"+p, func(t *testing.T) {
			if isPublicKeyMaterial(p) {
				t.Errorf("isPublicKeyMaterial(%q) = true — this would remove a real detection", p)
			}
			if !isCredentialPath(p) {
				t.Errorf("isCredentialPath(%q) = false — the exemption widened past public key material", p)
			}
		})
	}

	// The suffix check keys on the BASENAME, so a directory that merely
	// contains ".pub" must not exempt the private key inside it.
	t.Run("directory named .pub does not exempt its contents", func(t *testing.T) {
		p := "~/.ssh/backup.pub/id_rsa"
		if isPublicKeyMaterial(p) {
			t.Errorf("isPublicKeyMaterial(%q) = true, want false", p)
		}
		if !isCredentialPath(p) {
			t.Errorf("isCredentialPath(%q) = false, want true", p)
		}
	})
}
