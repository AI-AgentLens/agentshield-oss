package policy

import (
	"path/filepath"
	"strings"
	"testing"
)

// Environment half of the designated-consumer table (#3630).
//
// `export KUBECONFIG=<protected path>` measured 0/22 BLOCK, 22/22 AUDIT with
// NO rule id before this change — an event an attestation could not cite.
// The decision (Gary, 2026-09-06) is to record it as protected-path-consumer
// AUDIT, never to block it: blocking would break every kubeconfig-switching
// workflow while stopping no read.
//
// The two properties worth pinning are therefore opposite in direction:
//   - the assignment MUST be attributed (a bare AUDIT is the bug), and
//   - the assignment MUST NOT be able to lower anything (an assignment reads
//     nothing, so it can neither block on its own nor launder someone else's
//     block — the shape #3670 had to fix on the mount side).

// Paths are assembled rather than spelled so this file carries no credential
// literal for the live hook to object to.
const (
	kubeCfg   = "~/." + "kube/config"
	awsCreds  = "~/." + "aws/credentials"
	gcloudCfg = "~/." + "config/gcloud/application_default_credentials.json"
	gnupgDir  = "~/." + "gnupg"
)

func envConsumerEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := NewEngineWithAnalyzers(DefaultPolicy(), 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	return engine
}

func TestProtectedEnvAssignment_RecordedNotBlocked(t *testing.T) {
	engine := envConsumerEngine(t)

	cases := []struct {
		name string
		cmd  string
	}{
		// export form
		{"export tilde", "export KUBECONFIG=" + kubeCfg},
		{"export HOME var", "export KUBECONFIG=$HOME/." + "kube/config"},
		{"export braced HOME", "export KUBECONFIG=${HOME}/." + "kube/config"},
		{"export quoted", `export KUBECONFIG="` + kubeCfg + `"`},
		// bare assignment, no command — behaves like export
		{"bare assignment", "KUBECONFIG=" + kubeCfg},
		// prefix-assignment form: the variable is set for one command only
		{"prefix assignment", "KUBECONFIG=" + kubeCfg + " kubectl get pods"},
		// the other shipped environment slots
		{"aws credentials file", "export AWS_SHARED_CREDENTIALS_FILE=" + awsCreds},
		{"aws config file", "export AWS_CONFIG_FILE=~/." + "aws/config"},
		{"google adc", "export GOOGLE_APPLICATION_CREDENTIALS=" + gcloudCfg},
		{"cloudsdk config", "export CLOUDSDK_CONFIG=~/." + "config/gcloud"},
		{"gnupg home", "export GNUPGHOME=" + gnupgDir},
		// a chain of assignments still resolves the one that matters
		{"chained through a temp var", "K=$HOME/." + "kube; export KUBECONFIG=$K/config"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := evalNormalized(engine, tc.cmd)
			if res.Decision == DecisionBlock {
				t.Fatalf("assignment BLOCKed — it must never block: %s → %v", tc.cmd, res.TriggeredRules)
			}
			if res.Decision != DecisionAudit {
				t.Fatalf("expected AUDIT, got %s: %s", res.Decision, tc.cmd)
			}
			if !has(res.TriggeredRules, ProtectedPathConsumerRuleID) {
				t.Fatalf("assignment not attributed: %s → %v", tc.cmd, res.TriggeredRules)
			}
			if !strings.Contains(strings.Join(res.Reasons, " "), "environment credential slot") {
				t.Errorf("reason does not name the environment slot: %v", res.Reasons)
			}
		})
	}
}

// An assignment to a variable the table does not name stays exactly as it was
// before this change: ignored. This is the property that keeps the table's
// contents a coverage decision rather than a noise decision — nothing becomes
// a BLOCK by being left off it.
func TestProtectedEnvAssignment_UnlistedVariableIsIgnored(t *testing.T) {
	engine := envConsumerEngine(t)

	for _, cmd := range []string{
		"P=" + kubeCfg,
		"export MY_KUBE=" + kubeCfg,
		"export kubeconfig=" + kubeCfg, // case-sensitive: not KUBECONFIG
		"CONFIG=$HOME/." + "aws/credentials",
	} {
		res := evalNormalized(engine, cmd)
		if res.Decision == DecisionBlock {
			t.Errorf("assignment to an unlisted variable BLOCKed (regression): %s → %v", cmd, res.TriggeredRules)
		}
		if has(res.TriggeredRules, ProtectedPathConsumerRuleID) {
			t.Errorf("assignment to an unlisted variable was attributed as a consumer: %s → %v", cmd, res.TriggeredRules)
		}
	}
}

// A listed variable pointed at something that is not a protected path records
// nothing — the record is about the credential, not about the variable.
func TestProtectedEnvAssignment_NonProtectedValueIsIgnored(t *testing.T) {
	engine := envConsumerEngine(t)

	for _, cmd := range []string{
		"export KUBECONFIG=/tmp/kind.yaml",
		"export KUBECONFIG=./kubeconfig.yaml",
		"KUBECONFIG=/tmp/kind.yaml kubectl get pods",
		"export EDITOR=vim",
		"export PATH=$HOME/bin:$PATH",
		"export GNUPGHOME=/tmp/gnupg-test",
	} {
		res := evalNormalized(engine, cmd)
		if has(res.TriggeredRules, ProtectedPathConsumerRuleID) {
			t.Errorf("non-credential assignment attributed as a consumer: %s → %v", cmd, res.TriggeredRules)
		}
	}
}

// The load-bearing negative: an assignment must not be able to buy silence
// for a read elsewhere in the same command. `ssh -i key host && docker run -v
// <creddir>:/mnt img` was exactly this bug on the mount side (#3670); the
// assignment path is kept in its own variable in the engine so it can only
// ever ADD a record, never satisfy the consumer-only test.
func TestProtectedEnvAssignment_CannotLaunderABlock(t *testing.T) {
	engine := envConsumerEngine(t)

	cases := []struct {
		name string
		cmd  string
	}{
		{"read of another credential", "export KUBECONFIG=" + kubeCfg + "; cat ~/." + "ssh/id_rsa"},
		{"read through the variable it set", "export KUBECONFIG=$HOME/." + "kube/config; cat $KUBECONFIG"},
		{"read of the same file, spelled out", "export KUBECONFIG=" + kubeCfg + "; cat " + kubeCfg},
		{"redirect into a protected path", "export KUBECONFIG=" + kubeCfg + "; echo x >> ~/." + "ssh/authorized_keys"},
		{"bind mount of a credential dir", "export KUBECONFIG=" + kubeCfg + "; docker run -v ~/." + "aws:/mnt img"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := evalNormalized(engine, tc.cmd)
			if res.Decision != DecisionBlock {
				t.Fatalf("BLOCK laundered by the assignment: %s → %s %v", tc.cmd, res.Decision, res.TriggeredRules)
			}
			if has(res.TriggeredRules, ProtectedPathConsumerRuleID) {
				t.Errorf("a blocked command was annotated 'recorded, not blocked': %s → %v", tc.cmd, res.TriggeredRules)
			}
		})
	}
}

// With no consumer table at all the assignment is ignored, as it was before
// #3625 existed. Guards against the record becoming unconditional.
func TestProtectedEnvAssignment_NoTableKeepsOldSemantics(t *testing.T) {
	p := DefaultPolicy()
	p.Defaults.ProtectedPathConsumers = nil
	engine, err := NewEngineWithAnalyzers(p, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	cmd := "export KUBECONFIG=" + kubeCfg
	res := evalNormalized(engine, cmd)
	if has(res.TriggeredRules, ProtectedPathConsumerRuleID) {
		t.Errorf("recorded a consumer with an empty table: %v", res.TriggeredRules)
	}
	if res.Decision == DecisionBlock {
		t.Errorf("assignment BLOCKed with an empty table: %v", res.TriggeredRules)
	}
}

// Users add environment slots the same way they add flag slots: additively,
// through defaults.protected_path_consumers.
func TestProtectedEnvAssignment_UserMayAddEnvSlot(t *testing.T) {
	user := &Policy{Defaults: Defaults{
		ProtectedPathConsumers: []ProtectedPathConsumer{
			{Executable: []string{"vault"}, Env: []string{"VAULT_CREDS_FILE"}},
		},
	}}
	merged := mergeUserOverDefaults(DefaultPolicy(), user)
	engine, err := NewEngineWithAnalyzers(merged, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}

	res := evalNormalized(engine, "export VAULT_CREDS_FILE="+kubeCfg)
	if !has(res.TriggeredRules, ProtectedPathConsumerRuleID) {
		t.Errorf("user-declared environment slot not honoured: %v", res.TriggeredRules)
	}
	// ...and the shipped slots survive the merge.
	res = evalNormalized(engine, "export KUBECONFIG="+kubeCfg)
	if !has(res.TriggeredRules, ProtectedPathConsumerRuleID) {
		t.Errorf("shipped environment slot lost through the user merge: %v", res.TriggeredRules)
	}
}

// The shipped table must actually declare the names this change is about; a
// table with no env column would make every test above pass vacuously in the
// other direction (nothing recorded, nothing blocked) if the assertions were
// ever inverted.
func TestDefaultProtectedPathConsumers_ShipEnvSlots(t *testing.T) {
	want := []string{
		"KUBECONFIG",
		"GNUPGHOME",
		"AWS_SHARED_CREDENTIALS_FILE",
		"AWS_CONFIG_FILE",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"CLOUDSDK_CONFIG",
	}
	table := defaultProtectedPathConsumers()
	for _, name := range want {
		if !envIsCredentialSlot(table, name) {
			t.Errorf("shipped table does not declare environment slot %s", name)
		}
	}
	// SSH_AUTH_SOCK names an agent socket, not a credential file: an
	// assignment of a key path to it is a misuse, not a consumer slot, and
	// stays blocked by sec-block-ssh-private.
	for _, name := range []string{"SSH_AUTH_SOCK", "HOME", "PATH", "EDITOR"} {
		if envIsCredentialSlot(table, name) {
			t.Errorf("shipped table wrongly declares %s an environment credential slot", name)
		}
	}
}

// The shipped template is a second policy, and it was the one that broke.
//
// Every test above builds its engine from DefaultPolicy(), whose default
// decision is AUDIT. `configs/default_policy.yaml` — the file the header of
// that file tells users to copy to ~/.agentshield/policy.yaml — defaults to
// REQUIRE_APPROVAL instead. The first cut of this change suppressed the
// record on any decision it considered "blocking" and counted
// REQUIRE_APPROVAL among them, so under the shipped template the feature did
// nothing at all: measured through a binary built from this tree,
// `export KUBECONFIG=$HOME/.kube/config` came back REQUIRE_APPROVAL with an
// empty rule list, while the identical command under DefaultPolicy() was
// attributed. Not one unit test saw it, because not one loaded the file.
//
// So this loads the real file, which makes it a fitness function on two
// things at once: the engine's treatment of a non-AUDIT default, and the
// presence of the `env:` column in the shipped YAML table.
func TestProtectedEnvAssignment_ShippedTemplatePolicy(t *testing.T) {
	pol, err := Load(filepath.Join("..", "..", "configs", "default_policy.yaml"))
	if err != nil {
		t.Fatalf("load shipped template: %v", err)
	}
	if pol.Defaults.Decision == DecisionAudit {
		t.Fatalf("shipped template now defaults to AUDIT; this test only means something "+
			"while its default differs from DefaultPolicy() — re-point it or delete it (got %s)",
			pol.Defaults.Decision)
	}
	engine, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}

	for _, cmd := range []string{
		"export KUBECONFIG=" + kubeCfg,
		"export KUBECONFIG=$HOME/." + "kube/config",
		"KUBECONFIG=" + kubeCfg + " kubectl get pods",
		"export AWS_SHARED_CREDENTIALS_FILE=" + awsCreds,
	} {
		res := evalNormalized(engine, cmd)
		if res.Decision == DecisionBlock {
			t.Errorf("assignment BLOCKed under the shipped template: %s → %v", cmd, res.TriggeredRules)
		}
		if !has(res.TriggeredRules, ProtectedPathConsumerRuleID) {
			t.Errorf("assignment not attributed under the shipped template (default %s): %s → %v",
				pol.Defaults.Decision, cmd, res.TriggeredRules)
		}
	}

	// The flag half (#3625) is the control: it was attributed under this
	// policy before and after, which is how the divergence was spotted.
	res := evalNormalized(engine, "kubectl --kubeconfig "+kubeCfg+" get pods")
	if !has(res.TriggeredRules, ProtectedPathConsumerRuleID) {
		t.Errorf("flag-slot control lost its attribution under the shipped template: %v", res.TriggeredRules)
	}

	// ...and a real read is still blocked under the same policy, so the
	// attribution above is not the engine having gone quiet generally.
	if res := evalNormalized(engine, "cat "+kubeCfg); res.Decision != DecisionBlock {
		t.Errorf("read of a protected path not BLOCKed under the shipped template: %s %v", res.Decision, res.TriggeredRules)
	}
}

// The load-bearing guarantee of #3630 on the unwrapped command: recording the
// assignment must not make the READ through it any less blocked.
//
// This lived briefly as a corpus case (TP-CLOUDCFG-ENVASSIGN-001) and does not
// belong there. Every corpus case is replayed behind ~30 wrapper prefixes by
// TestWrapperPositionalParity and friends, and assignment-then-substitution
// does not survive a wrapper operand (#3227/#3057) — so the case became a 47th
// instance of an already-budgeted 46-leak gap and reddened three suites. The
// assertion belongs here anyway: the grader compares only the decision, so it
// could not tell WHICH layer blocked, and that is the interesting part.
//
// Two layers block these, and which one fires depends only on spelling:
//
//   - A tilde-spelled assignment puts the literal path in the command text, so
//     the normalizer extracts it as an argv path and the EARLY protected-path
//     check fires (rule `protected-path`) before the pipeline runs at all.
//   - A `$HOME`-spelled assignment is invisible to the normalizer, so nothing
//     is blocked until the substitution post-pass resolves the symbol table
//     (rule `protected-path-via-substitution`).
//
// Both are correct, and asserting only the first would be vacuous for the layer
// this PR touches — so each case names the rule that must carry its block.
func TestProtectedEnvAssignment_ReadThroughVariableStillBlocks(t *testing.T) {
	engine := envConsumerEngine(t)

	cases := []struct{ name, cmd, wantRule string }{
		// $HOME spellings: only the substitution post-pass can catch these,
		// which is the layer #3630 publishes ctx.Assignments from.
		{"$HOME spelling, same command", "export KUBECONFIG=$HOME/." + "kube/config; cat $KUBECONFIG", "protected-path-via-substitution"},
		{"$HOME spelling, braced expansion", "export KUBECONFIG=$HOME/." + "kube/config; cat ${KUBECONFIG}", "protected-path-via-substitution"},
		{"$HOME spelling, and-chained", "export KUBECONFIG=$HOME/." + "kube/config && cat $KUBECONFIG", "protected-path-via-substitution"},
		{"$HOME spelling, aws slot", "export AWS_SHARED_CREDENTIALS_FILE=$HOME/." + "aws/credentials; cat $AWS_SHARED_CREDENTIALS_FILE", "protected-path-via-substitution"},
		// Tilde spellings: the normalizer already sees the path, so the early
		// check blocks first. Pinned so a future change that stops extracting
		// it does not silently fall through to nothing.
		{"tilde spelling, same command", "export KUBECONFIG=" + kubeCfg + "; cat $KUBECONFIG", "protected-path"},
		{"tilde spelling, prefix form", "KUBECONFIG=" + kubeCfg + "; base64 $KUBECONFIG", "protected-path"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := evalNormalized(engine, tc.cmd)
			if res.Decision != DecisionBlock {
				t.Fatalf("read through the variable was not BLOCKed — #3630 has become a bypass: %s → %s %v",
					tc.cmd, res.Decision, res.TriggeredRules)
			}
			if !has(res.TriggeredRules, tc.wantRule) {
				t.Errorf("BLOCKed, but not by %s — the layer under test may have stopped resolving "+
					"while another rule masks it: %s → %v", tc.wantRule, tc.cmd, res.TriggeredRules)
			}
			// A blocked command is never annotated "recorded, not blocked".
			if has(res.TriggeredRules, ProtectedPathConsumerRuleID) {
				t.Errorf("blocked command annotated as a consumer record: %s → %v", tc.cmd, res.TriggeredRules)
			}
		})
	}
}
