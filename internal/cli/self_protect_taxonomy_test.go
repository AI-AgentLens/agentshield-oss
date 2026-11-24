package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// The nodes a managed host's shell self-protection BLOCK may attest. They are
// spelled out here rather than taken from the table, so these rows also run
// unchanged against a tree that does not have the table (main, or the pass-1
// head of #4603).
const (
	spNodeTampering  = "persistence-evasion/defense-evasion/security-tool-tampering"
	spNodeAuditTrail = "persistence-evasion/anti-forensics/ai-audit-trail-circumvention"
)

// spReceiptRow is one command a managed host blocks in the self-protection
// middleware, the sp-* rule that must block it, and the nodes its receipt
// must carry.
type spReceiptRow struct {
	name, rule, cmd string
	want            []string
}

// spReceiptRows are assembled at runtime: this repo dogfoods AgentShield, and
// the literal spellings are what the rules block.
func spReceiptRows(home string) []spReceiptRow {
	as := "agent" + "shield"
	dir := "~/." + as
	both := []string{spNodeAuditTrail, spNodeTampering} // sorted
	return []spReceiptRow{
		// One node per rule (Gary, 2026-10-30).
		{"bypass variable", "sp-block-bypass-env", "export " + strings.ToUpper(as) + "_BYPASS=1", []string{spNodeTampering}},
		{"setup disable", "sp-block-setup-disable", as + " setup claude-code --dis" + "able", []string{spNodeTampering}},
		{"policy overwrite", "sp-block-policy-write", "echo x > " + home + "/." + as + "/policy.yaml", []string{spNodeTampering}},
		{"agent hook delete", "sp-block-delete-hooks", "r" + "m ~/.claude/settings.json", []string{spNodeTampering}},
		{"binary replace", "sp-block-binary-replace", "cp /tmp/x /usr/local/bin/" + as, []string{spNodeTampering}},

		// sp-block-delete-config, split by target. A log is exactly what the
		// community rule ts-block-agentshield-log-delete protects (#4603 pass 1,
		// finding 1: these cited tampering).
		{"delete the audit log", "sp-block-delete-config", "r" + "m " + dir + "/audit.jsonl", []string{spNodeAuditTrail}},
		{"delete the logs directory", "sp-block-delete-config", "r" + "m -rf " + dir + "/logs/", []string{spNodeAuditTrail}},
		{"delete a session log, quoted ;", "sp-block-delete-config", "r" + "m -f " + dir + "/'session;1.jsonl'", []string{spNodeAuditTrail}},
		{"delete the audit log, $HOME quoted", "sp-block-delete-config", `r` + `m -f "$HOME/.` + as + `"/audit.jsonl`, []string{spNodeAuditTrail}},
		{"delete the logs, unset-parameter splice", "sp-block-delete-config", "r" + "m -rf " + dir + "/lo${zqx}gs", []string{spNodeAuditTrail}},
		{"delete the policy", "sp-block-delete-config", "r" + "m " + dir + "/policy.yaml", []string{spNodeTampering}},
		{"delete the packs", "sp-block-delete-config", "r" + "m -rf " + dir + "/packs", []string{spNodeTampering}},
		{"delete the policy and the log", "sp-block-delete-config", "r" + "m " + dir + "/policy.yaml " + dir + "/audit.jsonl", both},
		{"delete the whole directory", "sp-block-delete-config", "r" + "m -rf " + dir, both},
		// $HOME, not the scratch HOME's absolute path: the whole directory is
		// spelled the way the community rule spells it (~, $HOME, ${HOME},
		// /Users/*, /home/*, /root), and a test HOME lives under a temp dir.
		{"delete the whole directory, trailing slash", "sp-block-delete-config", "r" + "m -rf $HOME/." + as + "/", both},
		{"empty the whole directory", "sp-block-delete-config", "r" + "m -rf " + dir + "/*", both},

		// The rule's text pattern also blocks these, and neither deletes an
		// AgentShield path: no node rather than a guessed one.
		{"delete a sibling backup directory", "sp-block-delete-config", "r" + "m -rf " + dir + "-backup", nil},
		{"echo of a delete", "sp-block-delete-config", "echo 'r" + "m -rf " + dir + "'", nil},
	}
}

// TestSelfProtectBlockCarriesRuleNode drives each row through the real
// evaluation a hook runs, on a managed scratch HOME, and checks the node on
// the result and on the audit event (the event is what is logged and sent to
// the SaaS).
func TestSelfProtectBlockCarriesRuleNode(t *testing.T) {
	home, _ := newFailSafeHome(t, true, failSafePolicyGood)
	for _, c := range spReceiptRows(home) {
		t.Run(c.name, func(t *testing.T) {
			res, event := evaluateCommand(c.cmd, home, "claude-code-hook", "")
			assertSPBlock(t, res, c.rule)
			if !reflect.DeepEqual(res.TaxonomyRefs, c.want) {
				t.Errorf("result taxonomy %v, want %v", res.TaxonomyRefs, c.want)
			}
			if event == nil {
				t.Fatal("no audit event")
			}
			if !reflect.DeepEqual(event.TaxonomyRefs, c.want) {
				t.Errorf("audit event taxonomy %v, want %v", event.TaxonomyRefs, c.want)
			}
		})
	}
}

// TestSelfProtectConfigTouch_WritesCiteTamperingReadsCiteNone_4666: an
// sp-block-config-touch BLOCK cites security-tool-tampering only on positive
// evidence that a statement writes a managed config file; a read that is not
// on the plain-read list cites no node (Gary, 2026-11-09). Both carry the
// generic message, which is true of a read and a write. The decision is
// BLOCK either way.
func TestSelfProtectConfigTouch_WritesCiteTamperingReadsCiteNone_4666(t *testing.T) {
	home, _ := newFailSafeHome(t, true, failSafePolicyGood)
	as := "agent" + "shield"
	policyFile := "~/." + as + "/policy.yaml"
	abs := home + "/." + as + "/policy.yaml"
	cfgDir := "~/." + as
	for _, tc := range []struct {
		cmd   string
		write bool
	}{
		// Reads and mentions: no node.
		{"less " + policyFile, false},
		{"sed -n '1,40p' " + policyFile, false},
		{"cat $(echo " + policyFile + ")", false},
		{"grep -n mode " + cfgDir + "/" + as + ".yaml | head -5", false},
		{"cat " + policyFile + " | tee /tmp/copy.yaml", false},
		{"cat " + policyFile + " > /tmp/copy.yaml", false},
		{"dd if=" + policyFile + " of=/tmp/copy.yaml", false},
		{`python3 -c "print(open('` + abs + `').read())"`, false},
		{`python3 -c "print(open('` + abs + `','r').read())"`, false},
		{`python3 -c "print(open('` + abs + `', mode='rb').read())"`, false},
		{"sed -i.bak s/x/y/ /tmp/other.txt; less " + policyFile, false},
		{`P=` + abs + `; python3 -c "open('$P','w')"`, false},
		// Opus pass 1, F1: perl options with an i that is not -i.
		{"perl -Mstrict -ne 'print if /mode/' " + cfgDir + "/" + as + ".yaml", false},
		{"perl -Ilib -ne 'print' " + policyFile, false},
		{"perl -MList::Util=sum -ne 'print' " + policyFile, false},
		// Opus pass 1, F2: the writer named in an argument, or the file as input.
		{`grep -rn "sed -i" ` + cfgDir + "/packs/ | head -20", false},
		{`grep -rn 'perl -pi' ` + cfgDir + "/packs/ | head", false},
		{"grep -rn truncate " + cfgDir + "/packs/ 2>/dev/null", false},
		{"grep -rn tee " + cfgDir + "/managed.json | head", false},
		{`git commit -m "fix: block sed -i s/x/y/ ` + policyFile + `"`, false},
		{`echo 'never: echo x >> ` + cfgDir + `/managed.json' | head`, false},
		{"tee /tmp/copy.yaml < " + cfgDir + "/managed.json", false},
		{`sed -i '/marker/r ` + policyFile + `' /tmp/notes.md`, false},
		{"sed -i -f " + policyFile + " /tmp/x.txt", false},
		{"truncate -r " + policyFile + " /tmp/x.bin", false},
		{`jq -r '.rules[] | select(.id|test("tee"))' ` + cfgDir + "/managed.json", false},
		{"jq . " + policyFile + " > " + cfgDir + "/managed.json.bak", false},
		{"jq . " + policyFile + " > /tmp/bak/." + as + "/managed.json", false},
		// Opus pass 2, F-A: a substitution naming a pack inside a writer's
		// operand is not a write to the pack.
		{"cat " + cfgDir + "/packs/a.yaml | tee /tmp/bk-$(basename " + cfgDir + "/packs/a.yaml)", false},
		{"truncate -s 0 /tmp/$(basename " + cfgDir + "/packs/a.yaml)", false},
		{"perl -pi -e 's/a/b/' /tmp/$(basename " + cfgDir + "/packs/a.yaml)", false},
		{"tee -a /tmp/log >(grep x " + cfgDir + "/packs/a.yaml)", false},
		{"cat " + cfgDir + "/managed.json | tee /tmp/bk-$(basename " + cfgDir + "/managed.json .json)", false},
		// Pass 2 follow-up 1: a sed read whose script holds an i.
		{"sed -n '/limit/p' " + policyFile, false},
		// Writes: tampering.
		// Opus pass 2, F-B: an interpreter's heredoc.
		{"python3 - <<'EOF'\nopen('" + abs + "','w').write('x')\nEOF", true},
		{"node - <<'EOF'\nrequire('fs').writeFileSync('" + abs + "','x')\nEOF", true},
		{`python3 -c "open('` + abs + `','w')"`, true},
		{`python3 -c "open('` + abs + `', mode='w')"`, true},
		{`python3 -c "open('` + abs + `','r+')"`, true},
		{`python3 -c "import pathlib; pathlib.Path('` + abs + `').write_text('x')"`, true},
		{`node -e "require('fs').writeFileSync('` + abs + `', 'x')"`, true},
		{"sed -i s/BLOCK/AUDIT/ " + policyFile, true},
		{"sed --in-place s/BLOCK/AUDIT/ " + policyFile, true},
		{"sudo sed -i.bak s/BLOCK/AUDIT/ " + policyFile, true},
		{"perl -pi -e s/BLOCK/AUDIT/ " + policyFile, true},
		{"perl -0pi -e s/BLOCK/AUDIT/ " + policyFile, true},
		{"dd if=/dev/null of=" + policyFile, true},
		{`dd if=/dev/null of="` + abs + `"`, true},
		{"truncate -s 0 " + cfgDir + "/managed.json", true},
		{"echo x | tee " + cfgDir + "/managed.json", true},
		{"echo mode: audit >> " + cfgDir + "/" + as + ".yaml", true},
		{"less " + policyFile + "; sed -i s/x/y/ " + policyFile, true},
		// Pass 2 follow-up 1: a write inside a substitution.
		{"echo $(sed -i s/x/y/ " + policyFile + ")", true},
	} {
		t.Run(tc.cmd, func(t *testing.T) {
			res, event := evaluateCommand(tc.cmd, home, "claude-code-hook", "")
			assertSPBlock(t, res, "sp-block-config-touch")
			want := []string(nil)
			if tc.write {
				want = []string{spNodeTampering}
			}
			if !equalStrings(res.TaxonomyRefs, want) {
				t.Errorf("result taxonomy %v, want %v", res.TaxonomyRefs, want)
			}
			if event == nil {
				t.Fatal("no audit event")
			}
			if !equalStrings(event.TaxonomyRefs, want) {
				t.Errorf("audit event taxonomy %v, want %v", event.TaxonomyRefs, want)
			}
			if len(res.Reasons) != 1 || res.Reasons[0] != enterprise.ConfigTouchBlockMsg {
				t.Errorf("reasons %q, want the generic statement %q", res.Reasons, enterprise.ConfigTouchBlockMsg)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestConfigTouchBlockMsg_SameOnBothLanes_4666: the shell middleware and the
// PowerShell lane write the same message for sp-block-config-touch.
func TestConfigTouchBlockMsg_SameOnBothLanes_4666(t *testing.T) {
	if policy.ConfigTouchBlockMsg != enterprise.ConfigTouchBlockMsg {
		t.Errorf("PowerShell lane %q, shell %q", policy.ConfigTouchBlockMsg, enterprise.ConfigTouchBlockMsg)
	}
	if got := enterprise.SelfProtectBlockMsg("sp-block-policy-write"); got != "Blocked: attempt to modify AgentShield configuration (rule: sp-block-policy-write)" {
		t.Errorf("other rules keep their message, got %q", got)
	}
}

// TestConfigTouchFileSetMatchesTheRule_4666: the write classifier's managed
// files are the files the rule's pattern names.
func TestConfigTouchFileSetMatchesTheRule_4666(t *testing.T) {
	as := "." + "agent" + "shield"
	for _, p := range []string{"policy.yaml", "managed.json", as[1:] + ".yaml", "credentials.json", "packs/x.yaml", "packs"} {
		path := "~/" + as + "/" + p
		id, ok := enterprise.MatchSelfProtectRawText("less " + path)
		if !ok || id != enterprise.ConfigTouchRuleID {
			t.Fatalf("%q: rule %q %v, want the config-touch rule", path, id, ok)
		}
		if !isManagedConfigFile(path) {
			t.Errorf("%q: the rule names it, the classifier does not", path)
		}
	}
	for _, p := range []string{"~/" + as + "/audit.jsonl", "~/" + as + "/managed.json.bak", "/tmp/x/" + as + "/policy.yaml"} {
		if isManagedConfigFile(p) {
			t.Errorf("%s is not a managed config file", p)
		}
	}
}

// TestConfigTouch_PastChainBoundIsNodelessWithTheMessage_4666: past the chain
// bound the raw-text middleware blocks with the generic message, and the
// receipt cites no node without parsing.
func TestConfigTouch_PastChainBoundIsNodelessWithTheMessage_4666(t *testing.T) {
	cmd := "less ~/." + "agent" + "shield/policy.yaml" + strings.Repeat(" && true", shellparse.MaxChainOperators+1)
	ctx := &enterprise.EvalContext{Command: cmd}
	enterprise.RunChain(ctx, []enterprise.EvalMiddleware{enterprise.SelfProtectRawText()})
	if !ctx.Blocked || ctx.BlockRule != enterprise.ConfigTouchRuleID || ctx.BlockMsg != enterprise.ConfigTouchBlockMsg {
		t.Fatalf("blocked=%v rule=%q msg=%q", ctx.Blocked, ctx.BlockRule, ctx.BlockMsg)
	}
	if refs := selfProtectTaxonomyRefsUnparsed(enterprise.ConfigTouchRuleID, cmd); refs != nil {
		t.Errorf("refs %v, want none past the chain bound", refs)
	}
}

// The control: on an unmanaged host the middleware does not run, so neither
// the result nor the audit event can carry a node from it. A test that passed
// here too would not be measuring the self-protection path.
func TestSelfProtectTamperingNodeOnlyFromManagedPath(t *testing.T) {
	home, _ := newFailSafeHome(t, false, failSafePolicyGood)
	cmd := "export " + strings.ToUpper("agent"+"shield") + "_BYPASS=1"
	res, event := evaluateCommand(cmd, home, "claude-code-hook", "")
	if containsStr(res.TriggeredRules, "enterprise-self-protect") {
		t.Fatalf("unmanaged host ran self-protection: %v", res.TriggeredRules)
	}
	if len(res.TaxonomyRefs) != 0 {
		t.Errorf("unmanaged result attests %v without a self-protection BLOCK: %v", res.TaxonomyRefs, res.TriggeredRules)
	}
	if event == nil {
		t.Fatal("no audit event")
	}
	if len(event.TaxonomyRefs) != 0 {
		t.Errorf("unmanaged audit event attests %v without a self-protection BLOCK: %v", event.TaxonomyRefs, event.TriggeredRules)
	}
}

// assertSPBlock fails the test unless res is a self-protection BLOCK whose
// reason names rule. A row whose command is blocked by another rule would
// not be measuring the mapping it names.
func assertSPBlock(t *testing.T, res *policy.EvalResult, rule string) {
	t.Helper()
	if res.Decision != policy.DecisionBlock || !containsStr(res.TriggeredRules, "enterprise-self-protect") {
		t.Fatalf("decision %s rules %v; want an enterprise-self-protect BLOCK (the node must never move a decision)", res.Decision, res.TriggeredRules)
	}
	if !strings.Contains(strings.Join(res.Reasons, " "), "(rule: "+rule+")") {
		t.Fatalf("reasons %v do not name %s; the row is not measuring it", res.Reasons, rule)
	}
}
