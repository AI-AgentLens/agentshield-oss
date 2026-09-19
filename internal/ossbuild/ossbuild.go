// Package ossbuild answers exactly one question, for tests: does the tree this
// test binary was compiled from still contain packs/premium/?
//
// Two builds run the same test files against two different rule sets.
// scripts/publish-oss.sh strips packs/premium/ from the published tree but
// keeps every test file, and scripts/integration-test-oss.sh then runs
// `go test ./internal/policy/ ./internal/analyzer/` against that stripped tree.
// Any assertion whose answer depends on premium rules being loaded therefore
// has to know which tree it is running in.
//
// This package is that mechanism, and it is deliberately the ONLY one. It lives
// here rather than in a _test.go file because two packages need it —
// internal/analyzer (which had the original copy, see premium_pack_test.go) and
// internal/policy (which grew its first premium-dependent assertion in #3684).
// A second os.Stat somewhere else is how the two copies drift apart; do not add
// one, and do not invent a different signal (an env var, a build tag, a rule
// count). Nothing outside a test imports this.
//
// Two shapes are legitimate for callers:
//
//   - The assertion is ABOUT a premium rule (a rule ID, a taxonomy twin).
//     Meaningless without the pack — skip.
//   - The assertion holds in both trees but its measured CONSTANT differs,
//     because a smaller rule set genuinely enforces less. Keep the assertion,
//     pick the constant per build. Never widen the shared constant to cover the
//     weaker tree — that would let a real regression through on the build that
//     is actually shipped to customers.
package ossbuild

import (
	"os"
	"path/filepath"
	"runtime"
)

// premiumSentinel is a pack file that exists only in packs/premium/ and is
// removed by scripts/publish-oss.sh. Deleting or renaming it would make this
// package report "OSS build" for the full tree, which fails SAFE in the sense
// that matters: the premium-only assertions skip rather than the OSS-only
// budgets being applied to the full build. TestPremiumSentinelExists pins it.
const premiumSentinel = "terminal-safety-advanced.yaml"

// repoRoot resolves the root of the tree this package was COMPILED from, not
// the caller's working directory — the same runtime.Caller technique
// internal/policy's packsDir() already relies on, which is what makes it
// correct inside the OSS container (the tree is copied to /tmp/agentshield and
// built there, so the embedded path points at the stripped copy).
func repoRoot() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return filepath.Join(filepath.Dir(filename), "..", "..")
}

// PremiumPacksPresent reports whether packs/premium/ is part of this tree.
func PremiumPacksPresent() bool {
	root := repoRoot()
	if root == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(root, "packs", "premium", premiumSentinel))
	return err == nil
}
