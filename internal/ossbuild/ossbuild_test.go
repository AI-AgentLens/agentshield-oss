package ossbuild

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRepoRootResolves is the positive control for the path arithmetic, and it
// is tier-independent on purpose: both trees have a go.mod and a packs/ dir, so
// this fails loudly if the "..", ".." ever stops landing on the repo root —
// the failure mode that would make PremiumPacksPresent() report "OSS build"
// for every tree and silently disable every premium assertion in the suite.
func TestRepoRootResolves(t *testing.T) {
	root := repoRoot()
	if root == "" {
		t.Fatal("repoRoot() returned empty — runtime.Caller(0) failed")
	}
	for _, want := range []string{"go.mod", "packs"} {
		if _, err := os.Stat(filepath.Join(root, want)); err != nil {
			t.Errorf("repoRoot()=%q does not contain %s: %v", root, want, err)
		}
	}
}

// TestSentinelTracksTheDirectory is the drift guard. The sentinel is a stand-in
// for "packs/premium/ is present"; if it is renamed or deleted while the
// directory survives, this package would report OSS for a full tree and every
// premium-dependent assertion would skip or take the weaker budget without one
// test going red. Asserting the two agree is true in BOTH trees:
//
//	full tree: directory present, sentinel present -> true  == true
//	OSS tree:  directory absent,  sentinel absent  -> false == false
func TestSentinelTracksTheDirectory(t *testing.T) {
	root := repoRoot()
	dirInfo, dirErr := os.Stat(filepath.Join(root, "packs", "premium"))
	dirPresent := dirErr == nil && dirInfo.IsDir()

	if got := PremiumPacksPresent(); got != dirPresent {
		t.Errorf("PremiumPacksPresent()=%v but packs/premium/ present=%v.\n"+
			"The sentinel %q no longer tracks the directory — rename it here or restore the file.",
			got, dirPresent, premiumSentinel)
	}
	t.Logf("packs/premium/ present=%v (this is the %s build)", dirPresent,
		map[bool]string{true: "full", false: "OSS"}[dirPresent])
}
