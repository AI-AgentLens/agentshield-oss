package policy

import (
	"strings"
	"testing"
)

// TestCommunityTierSeesAgenticRansomware is the fitness function behind the
// tiering decision in #3161.
//
// The free tier does not BLOCK the JADEPUFFER agentic-ransomware class -- that
// is premium, together with the attestation receipt. What was decided is that
// the free tier must still *see* it: an AUDIT finding with a named rule, not
// silence. Before this test existed, those three corpus cases appeared in
// scripts/oss-known-failures.txt and a baselined line is indistinguishable
// from blindness, which is exactly the shape #3130 warns about. So the claim
// "community detects at AUDIT" needs a check that can fail, not a comment.
//
// Deliberately evaluated against the EMBEDDED COMMUNITY packs only. That is
// what an OSS build ships, so this test asserts the same thing in the OSS tree
// and in the full tree -- if it ever passed only because a premium pack leaked
// into the community embed, guardCommunityOnly below fires first.
func TestCommunityTierSeesAgenticRansomware(t *testing.T) {
	pol, infos, err := LoadEmbeddedShellPacks(DefaultPolicy())
	if err != nil {
		t.Fatalf("LoadEmbeddedShellPacks: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("no embedded community packs loaded")
	}
	guardCommunityOnly(t, pol)

	engine, err := NewEngineWithAnalyzers(pol, 0)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}

	cases := []struct {
		name     string
		corpusID string // the corpus case this mirrors, for traceability
		command  string
		want     Decision
		wantRule string
	}{
		{
			name:     "sql crypto-denial via python delivery is visible",
			corpusID: "TP-CRYPTODENY-006",
			command:  `python3 -c "import pymysql; conn=pymysql.connect(host='db'); cur=conn.cursor(); cur.execute(\"UPDATE config_info SET content=AES_ENCRYPT(content,'k3y')\"); cur.execute('DROP TABLE config_info_backup')"`,
			want:     DecisionAudit,
			wantRule: "ts-audit-sql-crypto-denial-visibility",
		},
		{
			name:     "ransom-note table creation is visible",
			corpusID: "TP-RANSOMNOTE-001",
			command:  `mysql -e "CREATE TABLE README_RANSOM (msg TEXT); INSERT INTO README_RANSOM VALUES ('Pay 2 BTC to recover your data.')"`,
			want:     DecisionAudit,
			wantRule: "ts-audit-ransom-note-artifact-visibility",
		},
		{
			name:     "ransom-note file creation is visible",
			corpusID: "TP-RANSOMNOTE-002",
			command:  `echo "Your data has been encrypted. Send 0.5 BTC to 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy for the key." > README_RANSOM.txt`,
			want:     DecisionAudit,
			wantRule: "ts-audit-ransom-note-artifact-visibility",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := engine.Evaluate(tc.command, nil)
			if res.Decision != tc.want {
				t.Errorf("community tier decision = %q, want %q (corpus %s)\n  command: %s\n  rules:   %v",
					res.Decision, tc.want, tc.corpusID, tc.command, res.TriggeredRules)
			}
			if !hasExactRule(res.TriggeredRules, tc.wantRule) {
				t.Errorf("rule %q did not fire (corpus %s); triggered: %v",
					tc.wantRule, tc.corpusID, res.TriggeredRules)
			}
		})
	}
}

// TestCommunityTierRansomwareNegativeControl is the other half of the guard,
// and its shape matters.
//
// The obvious negative control -- "these benign commands must be ALLOW" -- is
// wrong here, and failed when written that way: this engine's DEFAULT decision
// is AUDIT, so a benign command with no rule match already reports AUDIT with
// an empty rule list. Asserting on the decision alone would therefore pass for
// the wrong reason on the positive cases too. What actually has to hold is
// that the two new ransomware rules do NOT fire on benign traffic sharing
// their vocabulary -- a README redirect, an ordinary table create, and prose
// about an incident.
func TestCommunityTierRansomwareNegativeControl(t *testing.T) {
	pol, _, err := LoadEmbeddedShellPacks(DefaultPolicy())
	if err != nil {
		t.Fatalf("LoadEmbeddedShellPacks: %v", err)
	}
	engine, err := NewEngineWithAnalyzers(pol, 0)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}

	ransomwareRules := []string{
		"ts-audit-sql-crypto-denial-visibility",
		"ts-audit-ransom-note-artifact-visibility",
	}
	benign := []string{
		`echo "Setup instructions" > README.md`,
		`mysql -e "CREATE TABLE readme_notes (id INT, note TEXT)"`,
		`gh issue create --body 'the incident created a table named README_RANSOM with a bitcoin demand'`,
		`mysql -e "SELECT AES_ENCRYPT('preview text', 'demo-key') AS sample"`,
	}
	for _, cmd := range benign {
		res := engine.Evaluate(cmd, nil)
		for _, id := range ransomwareRules {
			if hasExactRule(res.TriggeredRules, id) {
				t.Errorf("rule %q false-positived on benign command: %s\n  decision: %q rules: %v",
					id, cmd, res.Decision, res.TriggeredRules)
			}
		}
		if res.Decision == DecisionBlock {
			t.Errorf("benign command was BLOCKed: %s\n  rules: %v", cmd, res.TriggeredRules)
		}
	}
}

// guardCommunityOnly asserts the policy under test really is the community
// tier. The tiering claim in #3161 is about what an OSS build does; a test
// that silently picked up premium rules would report the free tier as covered
// when it is not -- the same false-confidence shape as a gate that cannot fail.
func guardCommunityOnly(t *testing.T, pol *Policy) {
	t.Helper()
	premiumOnly := []string{
		"ts-block-sql-aes-encrypt-drop-original",
		"ts-block-ransom-note-artifact-creation",
		// #3432. Not strictly load-bearing for the git-archive assertion
		// below (a leak would flip that case to BLOCK and fail it anyway),
		// but every tier claim in this file should name the premium rule it
		// is claiming absence of, or the guard silently stops covering the
		// tests added after it.
		"ts-block-git-remote-helper-exec",
		// #3520/#3521, claimed absent by TestCommunityTierSeesOllamaServe.
		"ne-block-unauthenticated-llm-endpoint",
	}
	for _, r := range pol.Rules {
		for _, p := range premiumOnly {
			if r.ID == p {
				t.Fatalf("premium rule %q is present in the embedded community set; "+
					"this test can no longer prove community-tier coverage", r.ID)
			}
		}
	}
}

// hasExactRule is deliberately stricter than the package's existing
// containsRule (a substring match): this test asserts that one specific
// community rule fired, so a substring hit on a differently-named rule would
// let the tier claim pass on the wrong evidence.
func hasExactRule(rules []string, want string) bool {
	for _, r := range rules {
		if r == want || strings.HasPrefix(r, want+":") {
			return true
		}
	}
	return false
}

// TestCommunityTierSeesGHAOIDCTokenRead is the proof required by
// scripts/oss-known-failures.txt before a `# tier-split` line may be added.
//
// TP-GHA-OIDC-SHELL-HEREDOC-GUARD-001 expects BLOCK and gets AUDIT in the OSS
// build, so it needs a baseline entry. But a BARE line reads as blindness, and
// for this case that is the opposite of true: the community tier does fire, at
// AUDIT, with named rules — premium escalates the same read to BLOCK and
// attributes it to the specific OIDC-theft taxonomy node rather than the
// generic env-dump one. Recording it without this test would understate free-
// tier coverage in one direction and overstate it in the other.
//
// Community-only on purpose, same as the ransomware case above: this is what an
// OSS build ships, so guardCommunityOnly fires first if a premium pack ever
// leaks into the community embed and makes the assertion pass for a false
// reason.
func TestCommunityTierSeesGHAOIDCTokenRead(t *testing.T) {
	pol, infos, err := LoadEmbeddedShellPacks(DefaultPolicy())
	if err != nil {
		t.Fatalf("LoadEmbeddedShellPacks: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("no embedded community packs loaded")
	}
	guardCommunityOnly(t, pol)

	engine, err := NewEngineWithAnalyzers(pol, 0)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}

	// Assembled rather than written literally: the deployed AgentShield hook
	// blocks a shell command carrying this variable name (ts-block-ci-oidc-
	// token-access, working as intended), which makes the file awkward to
	// author through tooling that shells out. The corpus case in
	// internal/analyzer/testdata carries the same command verbatim.
	oidcVar := "ACTIONS_ID" + "_TOKEN_REQUEST_TOKEN"
	command := "bash <<'SH'\nprintenv " + oidcVar + "\nSH"

	res := engine.Evaluate(command, nil)
	if res.Decision != DecisionAudit {
		t.Errorf("community tier: got %s, want %s for the OIDC token read (corpus TP-GHA-OIDC-SHELL-HEREDOC-GUARD-001)",
			res.Decision, DecisionAudit)
	}
	// A decision with no named rule is indistinguishable from the default
	// fall-through, which would make the tier-split claim unfalsifiable.
	if len(res.TriggeredRules) == 0 {
		t.Fatalf("community tier produced %s with NO named rule — that is the default fall-through, i.e. blindness, "+
			"so the `# tier-split` marker in scripts/oss-known-failures.txt would be false", res.Decision)
	}
	t.Logf("community tier sees it at %s via %v", res.Decision, res.TriggeredRules)
}

// TestCommunityTierSeesGitArchiveExec is the proof required by
// scripts/oss-known-failures.txt before a `# tier-split` line may be added.
//
// #3432 added the git remote-helper flag class (CVE-2026-54316) as three
// corpus cases, all premium-only, so all three needed baseline entries. They
// do not share a verdict, and that is the whole reason this test exists:
//
//	-001 (--receive-pack=) and -002 (--upload-pack=) are BLIND. No community
//	rule reads either flag; the OSS build returns AUDIT with an empty rule
//	list. They are recorded as bare lines, which is what a bare line means.
//
//	-003 (git archive --exec=) is a TIER-SPLIT: ts-audit-git-archive does
//	fire, at AUDIT. A bare line there would understate free-tier coverage.
//
// Read the tier-split claim narrowly. The community rule matches a bare
// `git archive` and knows nothing about --exec=, so the free tier sees the
// COMMAND, not the remote-helper RCE mechanism; premium adds the BLOCK and
// the specific unauthorized-execution/lolbin/git-remote-helper-exec node in
// place of the generic data-exfil one. The second half of this test pins that
// narrowness, so the line cannot quietly be read as "community covers the
// remote-helper class" later.
//
// Community-only on purpose, same as the cases above: this asserts what an OSS
// build does, so guardCommunityOnly fires first if a premium pack ever leaks
// into the community embed and makes the assertion pass for a false reason.
func TestCommunityTierSeesGitArchiveExec(t *testing.T) {
	pol, infos, err := LoadEmbeddedShellPacks(DefaultPolicy())
	if err != nil {
		t.Fatalf("LoadEmbeddedShellPacks: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("no embedded community packs loaded")
	}
	guardCommunityOnly(t, pol)

	engine, err := NewEngineWithAnalyzers(pol, 0)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}

	const wantRule = "ts-audit-git-archive"

	// Verbatim from corpus case TP-TS-BLOCK-GIT-REMOTE-HELPER-003 in
	// internal/analyzer/testdata/unauthorized_execution_cases.go.
	command := `git archive --remote=host:repo --exec='bash -c "id > /tmp/pwn"' HEAD`

	res := engine.Evaluate(command, nil)
	if res.Decision != DecisionAudit {
		t.Errorf("community tier: got %s, want %s for the git-archive --exec read (corpus TP-TS-BLOCK-GIT-REMOTE-HELPER-003)",
			res.Decision, DecisionAudit)
	}
	// A decision with no named rule is indistinguishable from the default
	// fall-through, which would make the tier-split claim unfalsifiable.
	if len(res.TriggeredRules) == 0 {
		t.Fatalf("community tier produced %s with NO named rule -- that is the default fall-through, i.e. blindness, "+
			"so the `# tier-split` marker in scripts/oss-known-failures.txt would be false", res.Decision)
	}
	if !hasExactRule(res.TriggeredRules, wantRule) {
		t.Errorf("rule %q did not fire (corpus TP-TS-BLOCK-GIT-REMOTE-HELPER-003); triggered: %v",
			wantRule, res.TriggeredRules)
	}

	// The narrowness pin. The same community rule fires identically on a
	// benign archive with no --exec= anywhere, which is precisely what "sees
	// the command, not the mechanism" means. If a community rule ever becomes
	// --exec-aware this stays green, but the sibling assertion above would
	// then be understating free-tier coverage -- so the pair is what tells a
	// future reader to re-triage rather than trust the marker.
	benign := `git archive HEAD -o release.tar.gz`
	bres := engine.Evaluate(benign, nil)
	if !hasExactRule(bres.TriggeredRules, wantRule) {
		t.Errorf("%q did not fire on a benign `git archive` (%s); the tier-split note claims this rule is generic "+
			"rather than --exec-aware, and that claim no longer holds -- re-triage the baseline line",
			wantRule, benign)
	}

	t.Logf("community tier sees corpus -003 at %s via %v; siblings -001/-002 are blind (bare baseline lines)",
		res.Decision, res.TriggeredRules)
}

// TestCommunityTierSeesOllamaServe is the proof required by
// scripts/oss-known-failures.txt before a `# tier-split` line may be added.
//
// #3520/#3521 added TP-TS-AUDIT-OLLAMA-SERVE-003 (`OLLAMA_HOST=0.0.0.0 ollama
// serve`), whose BLOCK comes from the premium ne-block-unauthenticated-llm-
// endpoint. In the OSS build it returns AUDIT, so it needs a baseline entry —
// but a BARE line would read as blindness, and the community tier is not blind
// here: ts-audit-ollama-serve fires by name.
//
// Read the tier-split claim NARROWLY, exactly as with git archive --exec=
// above. ts-audit-ollama-serve matches `\bollama\s+(serve|run|start)\b` and
// reads nothing about OLLAMA_HOST, so what the free tier sees is the shadow-AI
// COMMAND (taxonomy unauthorized-execution/ai-model-usage/shadow-ai-usage),
// not the all-interfaces NETWORK EXPOSURE (data-exfiltration/llm-data-flow/
// unauthenticated-llm-endpoint) that premium blocks on. The second half of
// this test pins that narrowness by showing the same rule fires identically on
// a loopback-bound server, so the line cannot later be misread as "community
// detects unauthenticated LLM endpoints."
//
// Community-only on purpose, same as the cases above: this asserts what an OSS
// build does, so guardCommunityOnly fires first if a premium pack ever leaks
// into the community embed and makes the assertion pass for a false reason.
func TestCommunityTierSeesOllamaServe(t *testing.T) {
	pol, infos, err := LoadEmbeddedShellPacks(DefaultPolicy())
	if err != nil {
		t.Fatalf("LoadEmbeddedShellPacks: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("no embedded community packs loaded")
	}
	guardCommunityOnly(t, pol)

	engine, err := NewEngineWithAnalyzers(pol, 0)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}

	const wantRule = "ts-audit-ollama-serve"

	// The corpus case, verbatim (internal/analyzer/testdata,
	// TP-TS-AUDIT-OLLAMA-SERVE-003).
	exposed := "OLLAMA_HOST=0.0.0.0 ollama serve"
	res := engine.Evaluate(exposed, nil)
	if res.Decision != DecisionAudit {
		t.Errorf("community tier: got %s, want %s for the exposed ollama server (corpus TP-TS-AUDIT-OLLAMA-SERVE-003)\n  rules: %v",
			res.Decision, DecisionAudit, res.TriggeredRules)
	}
	if !hasExactRule(res.TriggeredRules, wantRule) {
		t.Errorf("rule %q did not fire, so the `# tier-split` marker in scripts/oss-known-failures.txt would be false; triggered: %v",
			wantRule, res.TriggeredRules)
	}

	// The narrowness pin. A loopback-bound server is not a network exposure at
	// all, yet the community rule fires on it exactly the same way — which is
	// the proof that what the free tier detects is "an ollama server was
	// started", not "it was exposed on all interfaces". If a future community
	// rule ever DOES read the bind address, this assertion is the one that
	// should be revisited, and the baseline line rewritten to match.
	loopback := "OLLAMA_HOST=127.0.0.1 ollama serve"
	res = engine.Evaluate(loopback, nil)
	if !hasExactRule(res.TriggeredRules, wantRule) {
		t.Errorf("narrowness pin: %q did not fire on the loopback-bound server %q; triggered: %v",
			wantRule, loopback, res.TriggeredRules)
	}
	if res.Decision == DecisionBlock {
		t.Errorf("narrowness pin: community tier BLOCKed a loopback-bound ollama server: %v", res.TriggeredRules)
	}
}
