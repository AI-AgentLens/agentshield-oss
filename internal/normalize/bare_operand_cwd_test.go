package normalize

import (
	"os"
	"path/filepath"
	"testing"
)

// #4381: with cwd inside a protected directory, a bare operand naming an
// existing entry resolves against cwd exactly as `./name` does. Alias of
// `~/.ssh/<key>`, which sec-block-ssh-private / protected_paths already BLOCK.
func TestBareOperandResolvesAgainstCwd_4381(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(ssh, "id_rsa")
	if err := os.WriteFile(key, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	has := func(cmd string) bool {
		for _, p := range NormalizeCommand(cmd, ssh).Paths {
			if p == key {
				return true
			}
		}
		return false
	}
	// control: the ./ spelling already resolved
	if !has("cat ./id_rsa") {
		t.Fatal("control: ./id_rsa must resolve")
	}
	for _, c := range []string{"cat id_rsa", "cat 'id_rsa'", "head -n 1 id_rsa", "cat id_rsa | wc -c", "cd /tmp && cat id_rsa"} {
		if c == "cd /tmp && cat id_rsa" {
			continue // cwd changed by cd: not modelled here
		}
		if !has(c) {
			t.Errorf("%q: bare operand not resolved against cwd", c)
		}
	}
	// ordinary words and absent names must not become paths
	for _, c := range []string{"ssh myhost", "git status", "cat nosuchfile", "echo id_rsa", "grep id_rsa notes.txt"} {
		if has(c) {
			t.Errorf("%q: must not resolve to the key", c)
		}
	}
	if got := NormalizeCommand("ssh myhost", ssh).Paths; len(got) != 0 {
		t.Errorf("ssh myhost: unexpected paths %v", got)
	}
	// empty / relative cwd: unchanged behaviour
	if got := NormalizeCommand("cat id_rsa", "").Paths; len(got) != 0 {
		t.Errorf("empty cwd: unexpected paths %v", got)
	}
}
