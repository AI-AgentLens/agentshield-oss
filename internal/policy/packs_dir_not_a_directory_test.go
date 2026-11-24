package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// #5021 (P-a): a regular file where the packs directory belongs, or where
// one of its parents belongs, is an error naming the packs path on every OS.
// It is never "no disk packs installed": that reading skips the hook's
// packs-load failure branch, and with it the managed fail_closed BLOCK. On
// Windows os.ReadDir reports both shapes as not-exist; on POSIX as ENOTDIR.
func TestLoadPacks_PacksPathNotADirectoryIsAnError_5021(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("not a directory\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	fileAtPacks := write("packs")
	fileAtParent := filepath.Join(write("config"), "packs")
	policyPath := filepath.Join(dir, "policy.yaml") // absent: the default policy
	base := DefaultPolicy()

	// Controls: a packs directory that does not exist, directly or under a
	// parent that does not exist, is no disk packs and no error.
	for _, absent := range []string{filepath.Join(dir, "absent"), filepath.Join(dir, "absent", "packs")} {
		if pol, infos, err := LoadPacks(absent, base); err != nil || pol != base || infos != nil {
			t.Fatalf("control LoadPacks(%s) = %p, %v, %v; want the base policy, no infos, no error", absent, pol, infos, err)
		}
		if _, _, err := LoadDeclaredToolCallInputs(policyPath, absent); err != nil {
			t.Fatalf("control LoadDeclaredToolCallInputs(_, %s): %v; want no error", absent, err)
		}
	}

	for _, p := range []string{fileAtPacks, fileAtParent} {
		pol, _, err := LoadPacks(p, base)
		if err == nil || os.IsNotExist(err) || pol != nil {
			t.Errorf("LoadPacks(%s) = %p, %v; want no policy and an error that is not not-exist", p, pol, err)
		} else if !strings.Contains(err.Error(), p) {
			t.Errorf("LoadPacks(%s): error %q does not name the packs path", p, err)
		}
		if _, _, err := LoadDeclaredToolCallInputs(policyPath, p); err == nil || os.IsNotExist(err) {
			t.Errorf("LoadDeclaredToolCallInputs(_, %s): error %v; want one that is not not-exist", p, err)
		}
	}
}

// existsAsNonDirectory's own truth table. It runs on every OS; only Windows
// calls it from readPacksDir.
func TestExistsAsNonDirectory_5021(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		want bool
	}{
		{file, true},
		{filepath.Join(file, "packs"), true},
		{filepath.Join(file, "a", "b"), true},
		{dir, false},
		{filepath.Join(dir, "absent"), false},
		{filepath.Join(dir, "absent", "packs"), false},
	} {
		if got := existsAsNonDirectory(tc.path); got != tc.want {
			t.Errorf("existsAsNonDirectory(%s) = %v, want %v", tc.path, got, tc.want)
		}
	}
	// No prefix can be stat'ed: reaching the root is false. Only Windows can
	// name a root that does not exist (an unmounted drive letter).
	if runtime.GOOS == "windows" {
		for c := 'Z'; c >= 'D'; c-- {
			root := string(c) + `:\`
			if _, err := os.Stat(root); err == nil {
				continue
			}
			if p := filepath.Join(root, "absent", "packs"); existsAsNonDirectory(p) {
				t.Errorf("existsAsNonDirectory(%s) = true on an absent volume, want false", p)
			}
			break
		}
	}
}
