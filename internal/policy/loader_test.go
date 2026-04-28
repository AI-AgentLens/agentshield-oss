package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoad_MissingFile_ReturnsDefaults — preserves the legacy contract: when
// no user policy.yaml exists, Load returns the hardcoded baseline.
func TestLoad_MissingFile_ReturnsDefaults(t *testing.T) {
	pol, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("Load returned error for missing file: %v", err)
	}
	if pol == nil {
		t.Fatal("Load returned nil policy")
	}
	if !ruleIDPresent(pol.Rules, "block-rm-root") {
		t.Errorf("expected baseline rule 'block-rm-root' in default policy, got %v", ruleIDs(pol.Rules))
	}
}

// TestLoad_MinimalUserFile_PreservesBaselineRules is the regression for #1641.
// A user policy file with only `disable_rules:` (or any other minimal content)
// must NOT cause the hardcoded baseline rules to disappear from the merged
// policy. Before the fix, `agentshield rule disable some-id` wrote a near-
// empty file, the loader returned just that, and rule IDs visibly drifted in
// the BLOCK output.
func TestLoad_MinimalUserFile_PreservesBaselineRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	must(t, os.WriteFile(path, []byte("version: \"0.1\"\ndisable_rules:\n  - some-test-rule\n"), 0o600))

	pol, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	for _, expected := range []string{
		"block-rm-root",
		"block-pipe-to-shell",
		"audit-package-installs",
		"audit-file-edits",
		"allow-safe-readonly",
	} {
		if !ruleIDPresent(pol.Rules, expected) {
			t.Errorf("baseline rule %q dropped after merging minimal user file — #1641 regression: %v", expected, ruleIDs(pol.Rules))
		}
	}

	if !pol.IsRuleDisabled("some-test-rule") {
		t.Error("user-supplied DisableRules entry not propagated through merge")
	}
}

// TestLoad_MinimalUserFile_PreservesProtectedPaths — same regression, scoped
// to the security-critical defaults block. A user file without a defaults:
// stanza must NOT silently wipe the hardcoded protected paths.
func TestLoad_MinimalUserFile_PreservesProtectedPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	must(t, os.WriteFile(path, []byte("version: \"0.1\"\n"), 0o600))

	pol, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	for _, expected := range []string{"~/.ssh/**", "~/.aws/**", "~/.gnupg/**", "~/.kube/**"} {
		if !contains(pol.Defaults.ProtectedPaths, expected) {
			t.Errorf("baseline protected path %q dropped after merging minimal user file: %v", expected, pol.Defaults.ProtectedPaths)
		}
	}
}

// TestLoad_MinimalUserFile_PreservesAllowDomains — same regression for the
// allow_domains list. Without this, a user file silently disables the curated
// allowlist (github.com, pypi.org, ...) and the network analyzer's allowlist
// behavior changes meaning.
func TestLoad_MinimalUserFile_PreservesAllowDomains(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	must(t, os.WriteFile(path, []byte("version: \"0.1\"\n"), 0o600))

	pol, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	for _, expected := range []string{"github.com", "pypi.org", "registry.npmjs.org"} {
		if !contains(pol.Network.AllowDomains, expected) {
			t.Errorf("baseline allow domain %q dropped after merging minimal user file: %v", expected, pol.Network.AllowDomains)
		}
	}
}

// TestLoad_UserRulesAppend — user-authored rules layer on top of baseline,
// they don't replace it. Order matters because the engine evaluates rules in
// declaration order; user rules running last lets them ALLOW-override a
// baseline AUDIT (or BLOCK-override a baseline ALLOW via most-restrictive).
func TestLoad_UserRulesAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := `version: "0.1"
rules:
  - id: user-custom-rule
    match:
      command_exact: "rm something-very-specific"
    decision: BLOCK
    reason: "user-defined block"
`
	must(t, os.WriteFile(path, []byte(body), 0o600))

	pol, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !ruleIDPresent(pol.Rules, "block-rm-root") {
		t.Errorf("baseline rule dropped: %v", ruleIDs(pol.Rules))
	}
	if !ruleIDPresent(pol.Rules, "user-custom-rule") {
		t.Errorf("user rule missing: %v", ruleIDs(pol.Rules))
	}

	baselineIdx, userIdx := -1, -1
	for i, r := range pol.Rules {
		if r.ID == "block-rm-root" {
			baselineIdx = i
		}
		if r.ID == "user-custom-rule" {
			userIdx = i
		}
	}
	if baselineIdx == -1 || userIdx == -1 || userIdx <= baselineIdx {
		t.Errorf("expected user rule to be appended AFTER baseline (baseline=%d, user=%d)", baselineIdx, userIdx)
	}
}

// TestLoad_UserDefaultsDecisionOverrides — when the user explicitly sets
// defaults.decision, their value wins. This is the one place where user
// content overrides rather than unions, because the default decision is a
// scalar. Allow domains and protected paths still union (defense-in-depth).
func TestLoad_UserDefaultsDecisionOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := `version: "0.1"
defaults:
  decision: BLOCK
`
	must(t, os.WriteFile(path, []byte(body), 0o600))

	pol, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if pol.Defaults.Decision != DecisionBlock {
		t.Errorf("user defaults.decision override ignored: got %s, want BLOCK", pol.Defaults.Decision)
	}
}

// TestLoad_UserProtectedPathsUnion — user can ADD protected paths but cannot
// silently remove baseline paths. Defense in depth: a misconfigured user file
// should never weaken the security floor.
func TestLoad_UserProtectedPathsUnion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := `version: "0.1"
defaults:
  protected_paths:
    - "~/.config/my-app/**"
`
	must(t, os.WriteFile(path, []byte(body), 0o600))

	pol, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !contains(pol.Defaults.ProtectedPaths, "~/.ssh/**") {
		t.Error("baseline ~/.ssh/** dropped when user added a custom path")
	}
	if !contains(pol.Defaults.ProtectedPaths, "~/.config/my-app/**") {
		t.Error("user-added protected path missing from merged policy")
	}
}

// TestLoad_LogRedactionCannotBeWeakened — once the baseline says "redact
// logs," a user file cannot silently flip it to false. This protects against
// a tampering vector where the operator's log gets useful redaction-disabled
// entries (PII, secrets) without a deliberate baseline change.
func TestLoad_LogRedactionCannotBeWeakened(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := `version: "0.1"
defaults:
  log_redaction: false
`
	must(t, os.WriteFile(path, []byte(body), 0o600))

	pol, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !pol.Defaults.LogRedaction {
		t.Error("user policy was able to turn off baseline LogRedaction")
	}
}

// helpers

func ruleIDs(rules []Rule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.ID)
	}
	return out
}

func ruleIDPresent(rules []Rule, id string) bool {
	for _, r := range rules {
		if r.ID == id {
			return true
		}
	}
	return false
}

// contains() is shared with schema_test.go.

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
