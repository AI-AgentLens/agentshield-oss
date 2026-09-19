package analyzer

import (
	"slices"
	"testing"
)

// echo/printf arguments are text (adversarial review, 2026-09-02): the
// normalizer never treats them as paths, so the substitution analyzer must not
// either, or `echo $HOME/.kube/config` blocks while `echo ~/.kube/config` passes.
func TestSubstitution_EchoPrintfArgumentsAreText(t *testing.T) {
	for _, cmd := range []string{
		`echo $HOME/.kube/config`,
		`echo ${HOME}/.aws/credentials`,
		`printf '%s\n' $HOME/.ssh/id_ed25519`,
		`P=$HOME/.kube; echo $P/config`,
	} {
		got := runSubstitution(t, cmd)
		for _, p := range got {
			if p == "~/.kube/config" || p == "~/.aws/credentials" || p == "~/.ssh/id_ed25519" {
				t.Errorf("echo/printf argument materialized as a path (%q): %s", p, cmd)
			}
		}
	}
}

// A redirect on the same echo is a real file access and must still surface.
func TestSubstitution_EchoRedirectStillMaterializes(t *testing.T) {
	got := runSubstitution(t, `echo x >> $HOME/.ssh/authorized_keys`)
	if !slices.Contains(got, "~/.ssh/authorized_keys") {
		t.Fatalf("materialized = %v; want the redirect target ~/.ssh/authorized_keys", got)
	}
	// Piping echo's text into a reader keeps the reader's own argv visible to
	// the normalizer; nothing for this layer to add, nothing to lose.
	got = runSubstitution(t, `P=$HOME/.ssh; cat $P/id_rsa | base64`)
	if !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Fatalf("materialized = %v; want ~/.ssh/id_rsa from the cat argument", got)
	}
}
