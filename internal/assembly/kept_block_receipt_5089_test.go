package assembly

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
	"github.com/AI-AgentLens/agentshield/internal/guardian"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/testhome"
)

// The receipt of a BLOCK audit-only mode keeps for self-protection (#5089),
// through the shell engine every surface builds, on the shipped packs. Paths
// are assembled: this repo dogfoods AgentShield.

func keptReceiptPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	pol, _, err := policy.LoadEmbeddedShellPacks(policy.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

func keptReceiptEval(t *testing.T, e *policy.Engine, cmd, cwd string) policy.EvalResult {
	t.Helper()
	n := normalize.NormalizeCommand(cmd, cwd)
	return e.EvaluateWithParsedCwd(cmd, n.Paths, n.Parsed, cwd)
}

func TestShellEngine_KeptBlockReceipt_5089(t *testing.T) {
	clearCIEnv(t)
	home := t.TempDir()
	testhome.Set(t, home)
	pol := keptReceiptPolicy(t)
	enf, err := ShellEngine(pol, 2, "enforce")
	if err != nil {
		t.Fatal(err)
	}
	aud, err := ShellEngine(pol, 2, "audit-only")
	if err != nil {
		t.Fatal(err)
	}
	mkfs := "mkfs." + "ext4 /dev/sda1"
	asPolicy := "~/." + "agent" + "shield/policy.yaml"
	sp := policy.SelfProtectRuleID
	for _, tc := range []struct {
		name string
		cmd  string
		// lead: audit-only BLOCKs, and its record is enforce mode's with the
		// keep's reason first under SelfProtectRuleID. Otherwise audit-only's
		// record is enforce mode's exactly, and decision says what it is.
		lead     bool
		decision policy.Decision
		// why, when set, is the keep's reason exactly.
		why string
	}{
		// The issue's shape on POSIX: on main the receipt was ts-block-mkfs
		// on the filesystem-format node, and nothing named why it stands.
		{"mkfs, then a change to AgentShield's policy", mkfs + "; r" + "m " + asPolicy, true, policy.DecisionBlock,
			policy.SelfProtectKeptReasonPrefix + "the command names ~/." + "agent" + "shield (AgentShield's own configuration) and is not a plain read"},
		{"mkfs, then an agent's MCP configuration", mkfs + "; r" + "m ~/.cursor/" + "mcp.json", true, policy.DecisionBlock, ""},
		{"a credential read decided first, then AgentShield's policy", "cat ~/.aws/" + "credentials; echo x > " + asPolicy, true, policy.DecisionBlock, ""},
		// The masked keep (#4429): the protected-path BLOCK returned before
		// the pipeline, and only the rest of the evaluation is self-protection.
		{"a credential read decided first, then AgentShield's disable variable", "cat ~/.aws/" + "credentials; export " + "AGENT" + "SHIELD_" + "DIS" + "ABLE=1", true, policy.DecisionBlock,
			policy.SelfProtectKeptReasonPrefix + "the command also matches the self-protection rule guardian-dis" + "able_security"},
		// Negative: case-fold ties. The folded reading's self-protection
		// rule (the directory delete) decides, so the record is enforce
		// mode's: the lead must not change which reading's record is kept.
		{"case-fold tie: a mixed-case AgentShield directory delete, then rm -rf /", "r" + "m -rf ~/.Agent" + "Shield; r" + "m -rf /", false, policy.DecisionBlock, ""},
		{"case-fold tie: a mixed-case AgentShield directory delete with /etc", "r" + "m -rf ~/.Agent" + "Shield /etc", false, policy.DecisionBlock, ""},
		// Negative: a self-protection rule decided, so the record names it.
		{"mkfs, then an agent hook write a self-protection rule blocks", mkfs + "; echo '{}' > ~/.claude/" + "settings.json", false, policy.DecisionBlock, ""},
		// Negative: nothing self-protected, so audit-only lowers it.
		{"mkfs alone", mkfs, false, policy.DecisionAudit, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := keptReceiptEval(t, enf, tc.cmd, home)
			if e.Decision != policy.DecisionBlock || containsID(e.TriggeredRules, sp) {
				t.Fatalf("enforce: %s %v; want BLOCK, never naming %s", e.Decision, e.TriggeredRules, sp)
			}
			a := keptReceiptEval(t, aud, tc.cmd, home)
			if a.Decision != tc.decision {
				t.Fatalf("audit-only: %s (original %q) %v; want %s", a.Decision, a.OriginalDecision, a.TriggeredRules, tc.decision)
			}
			wantRules, wantReasons := e.TriggeredRules, e.Reasons
			if tc.lead {
				if len(a.Reasons) == 0 || !strings.HasPrefix(a.Reasons[0], policy.SelfProtectKeptReasonPrefix) {
					t.Fatalf("audit-only reasons %q; want the keep's reason first", a.Reasons)
				}
				if tc.why != "" && a.Reasons[0] != tc.why {
					t.Errorf("keep's reason %q; want %q", a.Reasons[0], tc.why)
				}
				wantRules = append([]string{sp}, wantRules...)
				wantReasons = append([]string{a.Reasons[0]}, wantReasons...)
			}
			if !reflect.DeepEqual(a.TriggeredRules, wantRules) || !reflect.DeepEqual(a.Reasons, wantReasons) {
				t.Errorf("audit-only record %v %q; want %v %q", a.TriggeredRules, a.Reasons, wantRules, wantReasons)
			}
			if !reflect.DeepEqual(a.TaxonomyRefs, e.TaxonomyRefs) {
				t.Errorf("audit-only taxonomy %v; want enforce mode's %v", a.TaxonomyRefs, e.TaxonomyRefs)
			}
		})
	}
}

// The fitness function (#5089): over the accuracy corpus, every BLOCK
// audit-only mode keeps names why it stands, a self-protection rule (the
// keep's own reading of one) or SelfProtectRuleID; its record is enforce
// mode's exactly once the keep's lead is set aside (rules, reasons and
// taxonomy, so the lead never moves which reading's record is kept); and no
// enforce-mode record ever names SelfProtectRuleID. On main the BLOCKs kept for a reading named
// only their ordinary rules (rm -rf ~/*: ts-struct-block-rm-home-root).
func TestShellEngine_EveryKeptBlockNamesSelfProtection_5089(t *testing.T) {
	if testing.Short() {
		t.Skip("corpus sweep")
	}
	clearCIEnv(t)
	home := t.TempDir()
	testhome.Set(t, home)
	pol := keptReceiptPolicy(t)
	// A managed host's protected AgentShield directory, so the protected-path
	// hits reach the keep too.
	pol.Defaults.ProtectedPaths = append(pol.Defaults.ProtectedPaths, policy.ManagedConfigProtectedPath)
	enf, err := ShellEngine(pol, 2, "enforce")
	if err != nil {
		t.Fatal(err)
	}
	aud, err := ShellEngine(pol, 2, "audit-only")
	if err != nil {
		t.Fatal(err)
	}
	var cases []keptCase
	for _, tc := range testdata.AllTestCases() {
		cases = append(cases, keptCase{tc.ID, tc.Command})
	}
	kept, led := checkKeptBlocksNameWhy(t, pol, enf, aud, cases, home)
	// Positive controls: the sweep reached kept BLOCKs, and some of them only
	// the keep's reason explains.
	if kept == 0 || led == 0 {
		t.Fatalf("kept %d, led by %s %d; the sweep must reach both", kept, policy.SelfProtectRuleID, led)
	}
	t.Logf("%d kept BLOCKs, %d led by %s", kept, led, policy.SelfProtectRuleID)
}

type keptCase struct{ id, cmd string }

// checkKeptBlocksNameWhy is the fitness function's check, over cases: every
// BLOCK audit-only mode keeps names why it stands, its record is enforce
// mode's once the lead is set aside, and no enforce record names
// SelfProtectRuleID. It returns the kept BLOCKs and the led ones.
func checkKeptBlocksNameWhy(t *testing.T, pol *policy.Policy, enf, aud *policy.Engine, cases []keptCase, cwd string) (kept, led int) {
	t.Helper()
	isSP := mcp.ShellSelfProtectionRules(pol)
	namesWhy := func(rules []string, cmd string) bool {
		for _, id := range rules {
			if id == policy.SelfProtectRuleID || isSP(id) ||
				guardian.RuleTaxonomy(id) == "persistence-evasion/defense-evasion/security-tool-tampering" && guardian.TargetsAgentShield(id, cmd) {
				return true
			}
		}
		return false
	}
	for _, tc := range cases {
		if strings.TrimSpace(tc.cmd) == "" {
			continue
		}
		e := keptReceiptEval(t, enf, tc.cmd, cwd)
		if containsID(e.TriggeredRules, policy.SelfProtectRuleID) {
			t.Errorf("%s: enforce record %v names %s", tc.id, e.TriggeredRules, policy.SelfProtectRuleID)
		}
		a := keptReceiptEval(t, aud, tc.cmd, cwd)
		if a.Decision != policy.DecisionBlock || a.OriginalDecision != "" {
			continue
		}
		kept++
		rules, reasons := a.TriggeredRules, a.Reasons
		if len(rules) > 0 && rules[0] == policy.SelfProtectRuleID {
			led++
			if len(reasons) == 0 || !strings.HasPrefix(reasons[0], policy.SelfProtectKeptReasonPrefix) {
				t.Errorf("%s: led by %s without the keep's reason: %q", tc.id, policy.SelfProtectRuleID, reasons)
				continue
			}
			rules, reasons = rules[1:], reasons[1:]
		}
		if !reflect.DeepEqual(rules, e.TriggeredRules) || !reflect.DeepEqual(reasons, e.Reasons) || !reflect.DeepEqual(a.TaxonomyRefs, e.TaxonomyRefs) {
			t.Errorf("%s: audit-only record %v %v without the lead; want enforce mode's %v %v (%q)", tc.id, rules, a.TaxonomyRefs, e.TriggeredRules, e.TaxonomyRefs, tc.cmd)
		}
		if !namesWhy(a.TriggeredRules, tc.cmd) {
			t.Errorf("%s: audit-only BLOCK %v names no self-protection rule: %q", tc.id, a.TriggeredRules, tc.cmd)
		}
	}
	return kept, led
}

// The fitness function over the readings the corpus does not spell (#5091
// pass 1, F1): a reading layer's tie (keptOnTie) raises the as-written
// reading because another reading's BLOCK was kept by a self-protection rule
// only that reading sees. The home-tilde reading alone reads `~<login>/`
// (the corpus HOME is not the login's), and the case-fold and program-path
// readings alone read `/usr/bin/rm … ${HOME}/.AgentShield/…`. On 7c270ee1
// `mkfs.ext4 /dev/sda1; rm -rf ~<login>/.agentshield` recorded ts-block-mkfs
// alone, and the `${HOME}` row block-rm-root first, on both hosts.
func TestShellEngine_EveryKeptBlockNamesSelfProtection_Readings_5091(t *testing.T) {
	if testing.Short() {
		t.Skip("probe sweep")
	}
	clearCIEnv(t)
	home := filepath.Join(t.TempDir(), "zpme")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	testhome.Set(t, home)
	t.Cleanup(policy.SetTildeAccountLookupForTest(func() (string, string) { return "zpme", home }))
	cases := readingProbes()
	for _, managed := range []bool{false, true} {
		pol := keptReceiptPolicy(t)
		if managed {
			pol.Defaults.ProtectedPaths = append(pol.Defaults.ProtectedPaths, policy.ManagedConfigProtectedPath)
		}
		enf, err := ShellEngine(pol, 2, "enforce")
		if err != nil {
			t.Fatal(err)
		}
		aud, err := ShellEngine(pol, 2, "audit-only")
		if err != nil {
			t.Fatal(err)
		}
		kept, led := checkKeptBlocksNameWhy(t, pol, enf, aud, cases, home)
		// Positive controls: F1's two rows are kept, and led by the reason
		// that names what kept the other reading: its self-protection rule
		// only, never the ordinary rule beside it (the tilde row's expanded
		// reading also names the target, so the keep accepts ts-block-mkfs
		// alone there too). On a managed host the as-written tilde reading
		// is a protected-path hit of its own.
		tildeLead := policy.SelfProtectKeptReasonPrefix + "the command also matches the self-protection rule ts-struct-block-agentshield-dir-delete"
		if managed {
			tildeLead = policy.SelfProtectKeptReasonPrefix + "a protected path it matched, ~/." + "agent" + "shield, is AgentShield's own configuration"
		}
		// The case-fold row: on macOS and Linux only the folded reading names
		// the target, so the lead names the rule that kept it. Windows paths
		// fold case, so the keep reads `.AgentShield` as the target itself and
		// its own reason leads; both are true of the command.
		foldLead := policy.SelfProtectKeptReasonPrefix + "the command also matches the self-protection rule ts-block-agentshield-log-truncate"
		if runtime.GOOS == "windows" {
			foldLead = policy.SelfProtectKeptReasonPrefix + "the command names ~/." + "agent" + "shield (AgentShield's own configuration) and is not a plain read"
		}
		for _, c := range []struct{ cmd, lead string }{
			{readingF1Tilde, tildeLead},
			{readingF1Fold, foldLead},
		} {
			a := keptReceiptEval(t, aud, c.cmd, home)
			if a.Decision != policy.DecisionBlock || len(a.TriggeredRules) == 0 || a.TriggeredRules[0] != policy.SelfProtectRuleID {
				t.Errorf("managed=%v control %q: %s (original %q) %v; want a kept BLOCK led by %s", managed, c.cmd, a.Decision, a.OriginalDecision, a.TriggeredRules, policy.SelfProtectRuleID)
			} else if a.Reasons[0] != c.lead {
				t.Errorf("managed=%v control %q: lead %q; want %q", managed, c.cmd, a.Reasons[0], c.lead)
			}
		}
		if kept == 0 || led == 0 {
			t.Fatalf("managed=%v: kept %d, led %d; the sweep must reach both", managed, kept, led)
		}
		t.Logf("managed=%v: %d commands, %d kept BLOCKs, %d led by %s", managed, len(cases), kept, led, policy.SelfProtectRuleID)
	}
}

var (
	readingF1Tilde = "mkfs." + "ext4 /dev/sda1; r" + "m -rf ~zpme/." + "agent" + "shield"
	readingF1Fold  = "/usr/bin/r" + "m -rf / || truncate -s 0 ${HOME}/.Agent" + "Shield/agentshield.yaml"
)

// readingProbes are an ordinary BLOCK beside a change to a self-protection
// target, the target spelled the way only one reading layer reads it: the
// login's tilde, mixed case, the braced and bare HOME variable, and a program
// spelled as a path. Strings are assembled: this repo dogfoods AgentShield.
func readingProbes() []keptCase {
	as := []string{"." + "agent" + "shield", ".Agent" + "Shield"}
	files := []string{"", "/agentshield.yaml", "/audit.jsonl"}
	homes := []string{"~zpme/", "${HOME}/", "$HOME/", "~/"}
	others := []string{".Claude/" + "settings.json", ".cursor/" + "mcp.json"}
	var targets []string
	for _, h := range homes {
		for _, a := range as {
			for _, f := range files {
				targets = append(targets, h+a+f)
			}
		}
		for _, o := range others {
			targets = append(targets, h+o)
		}
	}
	rmw := "r" + "m"
	ops := []func(string) string{
		func(p string) string { return rmw + " " + p },
		func(p string) string { return rmw + " -rf " + p },
		func(p string) string { return "/bin/" + rmw + " -f " + p },
		func(p string) string { return "truncate -s 0 " + p },
		func(p string) string { return "echo x > " + p },
		func(p string) string { return "cp /tmp/x " + p },
		func(p string) string { return "cat " + p },
	}
	prefixes := []string{
		"mkfs." + "ext4 /dev/sda1",
		"/usr/bin/" + rmw + " -rf /",
		rmw + " -rf /",
		"cat ~/.ssh/id_" + "rsa",
		"git push --force origin main",
	}
	joiners := []string{"; ", " || ", " && "}
	var out []keptCase
	seen := map[string]bool{}
	add := func(c string) {
		if !seen[c] {
			seen[c] = true
			out = append(out, keptCase{"probe:" + c, c})
		}
	}
	add(readingF1Tilde)
	add(readingF1Fold)
	for _, p := range targets {
		for oi, op := range ops {
			tgt := op(p)
			add(tgt)
			for xi, x := range prefixes {
				add(x + joiners[(oi+xi)%len(joiners)] + tgt)
			}
		}
	}
	return out
}

func containsID(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}
