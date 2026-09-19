package analyzer_test

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// Two builds run this test package against two different rule sets.
//
// scripts/publish-oss.sh strips packs/premium/ from the published tree but
// keeps every test file, and scripts/integration-test-oss.sh then runs
// `go test ./internal/policy/ ./internal/analyzer/` against that stripped tree
// — so any assertion whose answer depends on premium rules being loaded has to
// know which tree it is running in. There is exactly ONE mechanism for that;
// do not add a second way to detect it.
//
// That mechanism moved to internal/ossbuild when internal/policy grew its first
// premium-dependent assertion (#3684) and could not import a _test.go file. The
// two names below are the local adapters, kept so the ~10 call sites in this
// package read the same as before.
//
// Two shapes are legitimate:
//
//   - requirePremiumPack: the assertion is ABOUT a premium rule (a rule ID, a
//     taxonomy twin). Meaningless without the pack — skip.
//   - premiumPacksPresent: the assertion holds in both trees but its measured
//     CONSTANT differs, because a smaller rule set genuinely enforces less.
//     Keep the assertion, pick the constant. Never widen the shared constant to
//     cover the weaker tree — that would let a real regression through on the
//     build that is actually shipped to customers.

// premiumPacksPresent reports whether packs/premium/ is part of this tree.
func premiumPacksPresent() bool {
	return ossbuild.PremiumPacksPresent()
}

// requirePremiumPack skips the caller when packs/premium/ is absent, so a test
// asserting on a premium rule ID reports SKIP in the OSS tree rather than
// failing the OSS install gate.
func requirePremiumPack(t *testing.T) {
	t.Helper()
	if !premiumPacksPresent() {
		t.Skip("PREMIUM — packs/premium/terminal-safety-advanced.yaml not present (OSS build)")
	}
}
