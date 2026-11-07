package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/enterprise"
)

// The #4670 tests that read definitions new in that change. The rows in
// self_protect_taxonomy_4670_test.go use only symbols main also has, so they
// run unchanged against main for the bite-check.

// TestAuditLogOverwriteSetComesFromCommunityPack: the log-path set is the
// community overwrite rule's own command_regex, read from the embedded packs
// with no second copy (#4670). If the rule is renamed, moved or loses its
// command_regex, this fails instead of every such receipt quietly going back
// to tampering.
func TestAuditLogOverwriteSetComesFromCommunityPack(t *testing.T) {
	re := auditLogOverwriteSet()
	if re == nil {
		t.Fatalf("%s not found in the embedded community packs, or it has no command_regex", auditLogOverwriteRule)
	}
	if rule := embeddedRule(t, auditLogOverwriteRule); re.String() != rule.Match.CommandRegex {
		t.Errorf("set %q is not the rule's pattern %q", re.String(), rule.Match.CommandRegex)
	}
}

// TestBinaryReplaceFallsBackWhenRuleAbsent pins the absent-rule fallback
// (#4670 pass 1, F2–F4): if the community overwrite rule is missing from the
// embedded packs (its log-path set is nil), both the shell receipt and the
// harness file-write receipt fall back to tampering — never the log node, and
// never a panic. The build-time TestAuditLogOverwriteSetComesFromCommunityPack
// guarantees the set is present; this guarantees the failure mode is safe.
func TestBinaryReplaceFallsBackWhenRuleAbsent(t *testing.T) {
	as := "agent" + "shield"
	tamper := []string{spNodeTampering}
	for _, cmd := range []string{
		"cp /tmp/x ~/." + as + "/audit.jsonl",
		"mv ~/." + as + "/audit.jsonl /tmp/x",
		"cp /tmp/x ~/." + as + "/audit.jsonl && cp /tmp/y ~/." + as + "/policy.yaml",
	} {
		if got := binaryReplaceTaxonomyRefsWith(cmd, nil); !reflect.DeepEqual(got, tamper) {
			t.Errorf("absent rule, %q: %v, want %v", cmd, got, tamper)
		}
	}
	// A real set still classifies the log, so the test is not vacuous.
	if got := binaryReplaceTaxonomyRefsWith("cp /tmp/x ~/."+as+"/audit.jsonl", auditLogOverwriteSet()); !reflect.DeepEqual(got, []string{spNodeAuditTrail}) {
		t.Errorf("present rule positive control: %v, want the audit-trail node", got)
	}
	if got := toolWriteTargetWith("audit.jsonl", nil); got != spTargetConfig {
		t.Errorf("absent rule, tool write onto the log: %v, want config (tampering)", got)
	}
	if got := toolWriteTargetWith("audit.jsonl", auditLogOverwriteSet()); got != spTargetLog {
		t.Errorf("present rule, tool write onto the log: %v, want log", got)
	}
}

// TestBinaryReplaceVerbsReachTheRule holds binaryReplaceVerbs to the rule's
// own verb list in internal/enterprise: each verb onto the binary reaches
// sp-block-binary-replace.
func TestBinaryReplaceVerbsReachTheRule(t *testing.T) {
	for _, verb := range binaryReplaceVerbs {
		cmd := verb + " /tmp/x /usr/local/bin/agent" + "shield"
		if id, ok := enterprise.MatchSelfProtectCommand(cmd); !ok || id != spBinaryReplaceRuleID {
			t.Errorf("%q reaches %q (%v), want %s", cmd, id, ok, spBinaryReplaceRuleID)
		}
	}
}

// TestManagedConfigDirRel: the relative path is read from the reading that
// found the directory, and ok is inManagedConfigDir's answer.
func TestManagedConfigDirRel(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".agent"+"shield")
	if err := os.MkdirAll(filepath.Join(dir, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	link := filepath.Join(outside, "cfg")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		p, wantRel string
		wantOK     bool
	}{
		{filepath.Join(dir, "audit.jsonl"), "audit.jsonl", true},
		{filepath.Join(dir, "logs", "a.log"), "logs/a.log", true},
		{dir, ".", true},
		{"~/.agent" + "shield/policy.yaml", "policy.yaml", true},
		{filepath.Join(link, "audit.jsonl"), "audit.jsonl", true},
		{filepath.Join(link, "logs", "x"), "logs/x", true},
		{filepath.Join(home, "proj", "audit.jsonl"), "", false},
		{filepath.Join(dir) + "/../outside.txt", "", false},
	} {
		rel, ok := managedConfigDirRel(c.p, home, home)
		if rel != c.wantRel || ok != c.wantOK {
			t.Errorf("%q: (%q, %v), want (%q, %v)", c.p, rel, ok, c.wantRel, c.wantOK)
		}
		if ok != inManagedConfigDir(c.p, home, home) {
			t.Errorf("%q: managedConfigDirRel ok=%v disagrees with inManagedConfigDir", c.p, ok)
		}
	}
}
