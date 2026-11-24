package policy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/testhome"
)

// A designated consumer's credential slot does not launder another read of a
// protected file in the same command (protectedPathConsumerOnly). A relative
// path is no candidate for the consumer table, so before this, from ~/.ssh,
// `ssh -i ~/.ssh/k host && cat id_rsa` decided the consumer's AUDIT while
// `cat id_rsa` alone BLOCKs, on every OS. #5021 P-c made Windows' Git Bash
// and drive-less spellings of the slot decide as `~` does, which carried them
// into the same gap (main had BLOCKed them, by accident). Every spelling of
// the slot now leaves the read BLOCKed; the slot alone is still the AUDIT.
// Credential paths are assembled at runtime: the hook reads test sources.
func TestConsumerSlotDoesNotLaunderARelativeRead_5021(t *testing.T) {
	home := t.TempDir()
	testhome.Set(t, home)
	ssh, kube := "."+"ssh", "."+"kube"
	key, other := "id_"+"ed25519", "id_"+"rsa"
	for _, d := range []string{ssh, kube, "proj"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(ssh, key), filepath.Join(ssh, other), filepath.Join("proj", "notes.txt")} {
		if err := os.WriteFile(filepath.Join(home, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	engine, err := NewEngineWithAnalyzers(DefaultPolicy(), 2)
	if err != nil {
		t.Fatal(err)
	}
	sshDir, proj := filepath.Join(home, ssh), filepath.Join(home, "proj")
	spellings := map[string]string{"tilde": "~", "msys": msysSpelling(home), "rooted": rootedSpelling(home)}
	for name, h := range spellings {
		slot := "ssh -i " + h + "/" + ssh + "/" + key + " host"
		for _, c := range []struct {
			cmd, cwd string
			want     Decision
			rule     string
		}{
			{slot + " && cat " + other, sshDir, DecisionBlock, ProtectedPathRuleID},
			{"cat " + other + "; " + slot, sshDir, DecisionBlock, ProtectedPathRuleID},
			{slot + " && cat ../" + ssh + "/" + other, proj, DecisionBlock, ProtectedPathRuleID},
			{"kubectl --kubeconfig " + h + "/" + kube + "/config get pods && cat ../" + ssh + "/" + other, proj, DecisionBlock, ProtectedPathRuleID},
			{"tar czf /tmp/x.tgz -C " + h + " " + ssh + " && " + slot, proj, DecisionBlock, ProtectedPathRuleID},
			// A second read of the slot's own file is a read too: one slot
			// occurrence accounts for one path normalize lists.
			{slot + " && cat " + key, sshDir, DecisionBlock, ProtectedPathRuleID},
			{slot + " && cat ../" + ssh + "/" + key, proj, DecisionBlock, ProtectedPathRuleID},
			// Controls: the slot alone, the same slot twice, two slots, and a
			// slot beside an unprotected relative operand stay the consumer's
			// AUDIT.
			{slot, sshDir, DecisionAudit, ProtectedPathConsumerRuleID},
			{"ssh -i " + h + "/" + ssh + "/" + key + " -i " + h + "/" + ssh + "/" + key + " host", proj, DecisionAudit, ProtectedPathConsumerRuleID},
			{slot, proj, DecisionAudit, ProtectedPathConsumerRuleID},
			{"ssh -i " + h + "/" + ssh + "/" + key + " -F " + h + "/" + ssh + "/config host", proj, DecisionAudit, ProtectedPathConsumerRuleID},
			{"scp -i " + h + "/" + ssh + "/" + key + " notes.txt host:", proj, DecisionAudit, ProtectedPathConsumerRuleID},
		} {
			got := evalAt(engine, c.cmd, c.cwd)
			shown := strings.ReplaceAll(c.cmd, home, "<home>")
			if got.Decision != c.want || !slices.Contains(got.TriggeredRules, c.rule) {
				t.Errorf("%s %q cwd=%s: %v %v; want %v by %s", name, shown, filepath.Base(c.cwd), got.Decision, got.TriggeredRules, c.want, c.rule)
			}
			if c.want == DecisionBlock && slices.Contains(got.TriggeredRules, ProtectedPathConsumerRuleID) {
				t.Errorf("%s %q: the BLOCK also records the consumer's AUDIT %v", name, shown, got.TriggeredRules)
			}
		}
	}
}

// A consumer slot accounts for its own word, and only that (#5021 P-c, pass
// 2). The count above compares normalize's paths with the slots, and neither
// list is one entry per read: normalize drops a `--name=value` reading of a
// path the segment already listed (F, the `--values=` and `-f` rows), so a slot
// written twice beside a read of its file left a credit free (T); a slot
// spelled `$HOME/...` is a credit normalize never lists; and the substitution
// analyzer's paths were not counted at all (M). Each row decided the
// consumer's AUDIT on a4ce3f4f; each second read alone BLOCKs.
func TestConsumerSlotAccountsForItsOwnWordOnly_5021(t *testing.T) {
	home := t.TempDir()
	testhome.Set(t, home)
	ssh, kube, aws := "."+"ssh", "."+"kube", "."+"aws"
	key, cred := "id_"+"ed25519", "creden"+"tials"
	for _, d := range []string{ssh, kube, aws, "proj"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(ssh, key), filepath.Join(kube, "config"), filepath.Join(aws, cred), filepath.Join("proj", "notes.txt")} {
		if err := os.WriteFile(filepath.Join(home, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	engine, err := NewEngineWithAnalyzers(DefaultPolicy(), 2)
	if err != nil {
		t.Fatal(err)
	}
	proj, kubeDir, sshDir := filepath.Join(home, "proj"), filepath.Join(home, kube), filepath.Join(home, ssh)
	const viaSubst = "protected-path-via-substitution"
	const awsNode = "credential-exposure/cloud-credentials/cloud-credential-access"
	type row struct {
		cmd, cwd string
		want     Decision
		rule     string
		names    string // a word the BLOCK's reason must name: the read, not the slot
	}
	check := func(name string, c row) {
		t.Helper()
		got := evalAt(engine, c.cmd, c.cwd)
		shown := strings.ReplaceAll(c.cmd, home, "<home>")
		if got.Decision != c.want || !slices.Contains(got.TriggeredRules, c.rule) {
			t.Errorf("%s %q cwd=%s: %v %v; want %v by %s", name, shown, filepath.Base(c.cwd), got.Decision, got.TriggeredRules, c.want, c.rule)
		}
		if c.want == DecisionBlock && slices.Contains(got.TriggeredRules, ProtectedPathConsumerRuleID) {
			t.Errorf("%s %q: the BLOCK also records the consumer's AUDIT %v", name, shown, got.TriggeredRules)
		}
		if c.names != "" && !strings.Contains(strings.Join(got.Reasons, " "), c.names) {
			t.Errorf("%s %q: reasons %q do not name %s", name, shown, got.Reasons, c.names)
		}
		if c.names == aws && !slices.Contains(got.TaxonomyRefs, awsNode) {
			t.Errorf("%s %q: taxonomy %v, want the AWS file's %s", name, shown, got.TaxonomyRefs, awsNode)
		}
	}
	spellings := map[string]string{"tilde": "~", "msys": msysSpelling(home), "rooted": rootedSpelling(home)}
	for name, h := range spellings {
		sshSlot := "ssh -i " + h + "/" + ssh + "/" + key + " host"
		kubeK := h + "/" + kube + "/config"
		for _, c := range []row{
			// M: a variable-built read beside the slot.
			{"D=$HOME; " + sshSlot + "; cp $D/" + aws + "/" + cred + " /tmp/o", proj, DecisionBlock, viaSubst, aws},
			{"D=$HOME; " + sshSlot + "; cat $D/" + ssh + "/" + key, proj, DecisionBlock, viaSubst, ""},
			// F: an option value naming the slot's file, deduped by normalize.
			{"kubectl --kubeconfig " + kubeK + " create secret generic x --from-file=../" + kube + "/config", proj, DecisionBlock, ProtectedPathRuleID, ""},
			{"helm --kubeconfig " + kubeK + " install x c --values=../" + kube + "/config", proj, DecisionBlock, ProtectedPathRuleID, ""},
			{"kubectl apply -f ../" + kube + "/config --kubeconfig=" + kubeK, proj, DecisionBlock, ProtectedPathRuleID, ""},
			// T: the slot written twice, then a read of its file.
			{"kubectl --kubeconfig=" + kubeK + " --kubeconfig=" + kubeK + " get pods; cat config", kubeDir, DecisionBlock, ProtectedPathRuleID, ""},
			// The receipt names the read the slots do not account for, not
			// the slot's file, which is the first protected path normalize
			// lists.
			{"kubectl --kubeconfig " + kubeK + " create secret generic x --from-file=../" + aws + "/" + cred, proj, DecisionBlock, ProtectedPathRuleID, aws},
			{sshSlot + " && cat ../" + aws + "/" + cred, proj, DecisionBlock, ProtectedPathRuleID, aws},
			{sshSlot + " && cat " + h + "/" + aws + "/" + cred, proj, DecisionBlock, ProtectedPathRuleID, aws},
			// Controls: the slot alone, the same slot twice, two different
			// slots, a slot beside an unprotected operand, and a
			// variable-built read of an unprotected file.
			{"kubectl --kubeconfig=" + kubeK + " get pods", kubeDir, DecisionAudit, ProtectedPathConsumerRuleID, ""},
			{"kubectl --kubeconfig=" + kubeK + " --kubeconfig=" + kubeK + " get pods", kubeDir, DecisionAudit, ProtectedPathConsumerRuleID, ""},
			{sshSlot + "; kubectl --kubeconfig " + kubeK + " get pods", proj, DecisionAudit, ProtectedPathConsumerRuleID, ""},
			{"kubectl --kubeconfig " + kubeK + " create secret generic x --from-file=notes.txt", proj, DecisionAudit, ProtectedPathConsumerRuleID, ""},
			{"D=$HOME; " + sshSlot + "; cp $D/proj/notes.txt /tmp/o", proj, DecisionAudit, ProtectedPathConsumerRuleID, ""},
		} {
			check(name, c)
		}
	}
	// A slot spelled `$HOME/...` is a credit normalize never lists, so a read
	// of its file was free; and the substitution analyzer lists that file once
	// for the slot and the read together.
	home1 := "ssh -i $HOME/" + ssh + "/" + key + " host"
	for _, c := range []row{
		{home1 + " && cat ../" + ssh + "/" + key, proj, DecisionBlock, ProtectedPathRuleID, ""},
		// From ~/.ssh normalize's cwd join of the unexpanded word is under the
		// protected directory, so this row BLOCKed already; kept as a control.
		{home1 + " && cat " + key, sshDir, DecisionBlock, ProtectedPathRuleID, ""},
		{home1 + "; D=$HOME; cat $D/" + ssh + "/" + key, proj, DecisionBlock, viaSubst, ""},
		{home1 + "; D=$HOME; cp $D/" + aws + "/" + cred + " /tmp/o", proj, DecisionBlock, viaSubst, aws},
		// Controls: the slot alone, twice, and beside the literal slot; a
		// quoted or wrapped consumer is still the consumer.
		{home1, proj, DecisionAudit, ProtectedPathConsumerRuleID, ""},
		{"'ssh' -i ~/" + ssh + "/" + key + " host", proj, DecisionAudit, ProtectedPathConsumerRuleID, ""},
		{"sudo ssh -i ~/" + ssh + "/" + key + " host", proj, DecisionAudit, ProtectedPathConsumerRuleID, ""},
		{"ssh -i $HOME/" + ssh + "/" + key + " -i ${HOME}/" + ssh + "/" + key + " host", proj, DecisionAudit, ProtectedPathConsumerRuleID, ""},
		{home1 + "; ssh -i ~/" + ssh + "/" + key + " host", proj, DecisionAudit, ProtectedPathConsumerRuleID, ""},
		// A slot inside another slot's word: one blank covers both. The
		// count decides this one (BLOCK, as on a4ce3f4f); the row pins that
		// the nested spans are read without a fault.
		{"ssh -i ~/" + ssh + "/\"$(ssh-add ~/" + ssh + "/" + key + "; echo " + key + ")\" host", proj, DecisionBlock, ProtectedPathRuleID, ""},
	} {
		check("home-var", c)
	}
}

// Finding Z (#5021 P-c, pass 2) is a pinned gap, not closed here: a read
// inside an executor whose text normalize does not read (`bash -c`) is no
// protected-path read on its own, so a slot beside it decides the consumer's
// AUDIT. `bash -c 'cat <key>'` alone from ~/.ssh is AUDIT too. Closing it is
// Gary's decision (the options are in the PR); this pins today's behaviour so
// a change to it is deliberate.
func TestConsumerSlotBesideAnOpaqueExecutorIsAGap_5021(t *testing.T) {
	home := t.TempDir()
	testhome.Set(t, home)
	ssh, key := "."+"ssh", "id_"+"rsa"
	if err := os.MkdirAll(filepath.Join(home, ssh), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ssh, key), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngineWithAnalyzers(DefaultPolicy(), 2)
	if err != nil {
		t.Fatal(err)
	}
	sshDir := filepath.Join(home, ssh)
	for _, c := range []struct {
		cmd  string
		want Decision
	}{
		{"ssh -i ~/" + ssh + "/" + key + " host; bash -c 'cat " + key + "'", DecisionAudit},
		{"bash -c 'cat " + key + "'", DecisionAudit},
		// Positive control: the same read outside the executor.
		{"ssh -i ~/" + ssh + "/" + key + " host; cat " + key, DecisionBlock},
	} {
		if got := evalAt(engine, c.cmd, sshDir); got.Decision != c.want {
			t.Errorf("%q from ~/.ssh: %v %v; want %v (the pinned gap; change it deliberately)", c.cmd, got.Decision, got.TriggeredRules, c.want)
		}
	}
}
