package enterprise

import (
	"sort"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// Self-protection past the chain bound (#4778 fix round, Kai 2026-11-04).
//
// A command past shellparse.MaxChainOperators is not parsed. On a managed host
// the self-protection rules still read its raw text (MatchSelfProtectRawText),
// so padding a tamper command with harmless `|a` stages cannot take it from
// main's BLOCK to AUDIT. What main's middleware found only through a reading
// that parses (a quote splice, an unset expansion, a zsh-only prefix, a
// reordered setup argv) is the residual, measured and pinned here.

// spPad makes cmd past the bound with harmless pipeline stages.
func spPad(cmd string) string {
	return cmd + strings.Repeat("|a", shellparse.MaxChainOperators+1)
}

// spBaseTPs are one plain TP per rule, as the rules' own tests spell them.
func spBaseTPs() []string {
	as := "agent" + "shield"
	return []string{
		"export AGENTSHIELD_" + "BYPASS=1",
		"AGENTSHIELD_" + "BYPASS=1 claude",
		as + " setup claude-code --disable",
		as + " setup mcp --disable",
		"rm -rf ~/." + as + "/",
		"rm ~/.claude/settings.json",
		"brew uninstall --cask " + as,
		"echo 'rules: []' > ~/." + as + "/policy.yaml",
		"cp /tmp/fake /opt/homebrew/bin/" + as,
		"python3 -c \"open('/Users/x/." + as + "/policy.yaml','w')\"",
	}
}

// spSplicedVariants are the spellings main's middleware finds only through a
// reading that parses: a quote splice, an unset-parameter splice, and a
// zsh-only statement in front.
func spSplicedVariants() []string {
	as := "agent" + "shield"
	return []string{
		"export AGENTSHIELD_BYPA'S'S=1",
		as + " setup claude-code --disa'b'le",
		as + " setup claude-code --disa${zqx}ble",
		"rm -rf ~/.agentshi'e'ld/",
		"rm -rf ~/.agentshi${zqx}eld",
		"rm ~/.cla'u'de/settings.json",
		"echo 'rules: []' > ~/." + as + "/poli'c'y.yaml",
		"cp /tmp/fake /opt/homebrew/bin/agentshi'e'ld",
		": ${(U)HOME}; rm -rf ~/." + as + "/",
		as + " --disable setup mcp",
	}
}

// spCorpus is every candidate command: the plain TPs, the spliced variants,
// and the self-protection tests' own tables. Only the ones main's middleware
// BLOCKs are measured.
func spCorpus() []string {
	out := append(spBaseTPs(), spSplicedVariants()...)
	for _, r := range setupDisableRows {
		out = append(out, r.cmd)
	}
	for _, r := range setupDisableDiscoveryRows {
		out = append(out, r.cmd())
	}
	out = append(out, brewUninstallTPs()...)
	for _, group := range []map[string][]string{brewFixRound1TPs(), brewFixRound2TPs()} {
		for _, cmds := range group {
			out = append(out, cmds...)
		}
	}
	return out
}

// TestSelfProtectPastChainBound_RawTextKeepsMainsBlock: every command main's
// middleware BLOCKs on its raw text is still matched, with the same rule id,
// when padded past the bound, so the hook keeps main's record
// (enterprise-self-protect). The commands main BLOCKed only through a parsing
// reading match no raw pattern; past the bound a managed host BLOCKs them
// all the same, as enterprise-chain-too-long (Gary, 2026-11-04; the hook's
// TestManagedPastTheBound_EveryCallBlocks), and MatchSelfProtectCommand, the
// MCP proxies' matcher, says so too (#4823 Opus pass 1). None is lowered: 487
// of 487 BLOCK, 421 with main's rule id. Those 66 are pinned by rule, so a change to
// which record a row gets is a deliberate diff. Main's decision is its
// matcher on the command without the padding: the padding is `|a` stages
// after the command, which no rule reads.
func TestSelfProtectPastChainBound_RawTextKeepsMainsBlock(t *testing.T) {
	seen := map[string]bool{}
	var mainBlocks, kept int
	residual := map[string]int{}
	var residualRows []string
	for _, cmd := range spCorpus() {
		if seen[cmd] {
			continue
		}
		seen[cmd] = true
		mainRule, ok := matchesSelfProtectRule(cmd)
		if !ok {
			continue
		}
		mainBlocks++
		padded := spPad(cmd)
		if shellparse.CheckChainBound(padded) == nil {
			t.Fatalf("control: the padded command is under the bound")
		}
		rule, ok := MatchSelfProtectCommand(padded)
		rawRule, rawOK := MatchSelfProtectRawText(cmd)
		switch {
		case ok && rule == mainRule:
			kept++
			if !rawOK || rawRule != mainRule {
				t.Errorf("%q: kept past the bound as %s, but its raw text alone does not match it", cmd, rule)
			}
		case ok && rule == ChainTooLongRuleID:
			if rawOK {
				t.Errorf("%q: its raw text matches %s, but past the bound it is recorded as %s", cmd, rawRule, rule)
			}
			residual[mainRule]++
			residualRows = append(residualRows, cmd)
		case ok:
			t.Errorf("%q: main's rule %s, past the bound %s", cmd, mainRule, rule)
		default:
			t.Errorf("%q: main BLOCKs it as %s; past the bound the managed matcher does not block it at all", cmd, mainRule)
		}
	}
	sort.Strings(residualRows)
	t.Logf("main BLOCKs %d corpus commands; past the bound %d keep main's rule, %d are recorded as enterprise-chain-too-long %v", mainBlocks, kept, len(residualRows), residual)
	for _, r := range residualRows {
		t.Logf("  residual: %q", r)
	}
	if mainBlocks < 50 {
		t.Fatalf("control: main BLOCKs only %d corpus commands; the corpus is not loading", mainBlocks)
	}
	// The rows the sentinel decides, exactly, per rule: the spellings only a
	// parsing reading finds. Measured 2026-11-04: 65 of 480; 66 of 487 since
	// main added the --remove-managed spellings (22dd2ed9), the new one
	// `setup --remove-managed claude-code`. Each is still a BLOCK on a
	// managed host, recorded as enterprise-chain-too-long. sp-block-setup-disable's 55 are
	// the setup argv walk's (another argument order, quoted or wrapped words,
	// a path to the binary), which CheckDisableAllowed refuses underneath on a
	// managed host anyway; the other 11 are quote and unset-parameter splices
	// (the dequoted and unset-folded readings). A change here is a decision
	// change, so these numbers move only by editing them.
	wantResidual := map[string]int{
		"sp-block-setup-disable":  55,
		"sp-block-brew-uninstall": 5,
		"sp-block-delete-config":  2,
		"sp-block-binary-replace": 1,
		"sp-block-bypass-env":     1,
		"sp-block-delete-hooks":   1,
		"sp-block-policy-write":   1,
	}
	for rule, n := range residual {
		if wantResidual[rule] != n {
			t.Errorf("%s: residual %d, pinned at %d", rule, n, wantResidual[rule])
		}
	}
	for rule, n := range wantResidual {
		if residual[rule] != n {
			t.Errorf("%s: residual %d, pinned at %d", rule, residual[rule], n)
		}
	}
}

// TestSelfProtectPastChainBound_EveryRuleKept: each rule's plain TP keeps its
// BLOCK and rule id past the bound.
func TestSelfProtectPastChainBound_EveryRuleKept(t *testing.T) {
	rules := map[string]bool{}
	for _, cmd := range spBaseTPs() {
		want, ok := matchesSelfProtectRule(cmd)
		if !ok {
			t.Fatalf("control: %q is not a TP on main", cmd)
		}
		got, ok := MatchSelfProtectCommand(spPad(cmd))
		if !ok || got != want {
			t.Errorf("%q past the bound: %q %v, want %s", cmd, got, ok, want)
		}
		rules[want] = true
	}
	for _, id := range SelfProtectRuleIDs() {
		if !rules[id] {
			t.Errorf("no plain TP for %s in spBaseTPs", id)
		}
	}
}

// TestSelfProtectRawText_SameAsMainsFirstReading: on the commands under the
// bound, the raw reading never matches what main's matcher does not, and
// names main's rule whenever it matches, so past the bound it can only keep a
// BLOCK main made, never invent one.
func TestSelfProtectRawText_SameAsMainsFirstReading(t *testing.T) {
	for _, cmd := range spCorpus() {
		raw, rawOK := MatchSelfProtectRawText(cmd)
		if !rawOK {
			continue
		}
		mainRule, ok := matchesSelfProtectRule(cmd)
		if !ok || mainRule != raw {
			t.Errorf("%q: raw reading %s, main %q %v", cmd, raw, mainRule, ok)
		}
	}
	// TNs the rules' tests keep clear stay clear on the raw reading too.
	for _, tn := range []string{"cat ~/.agentshield/policy.yaml", "agentshield status", "ls -la", "brew upgrade agentshield"} {
		if id, ok := MatchSelfProtectRawText(tn); ok {
			t.Errorf("TN %q matched %s", tn, id)
		}
	}
}

// TestMatchSelfProtectCommand_PastTheBoundBlocks_4823: the MCP proxies'
// matcher, which they consult on a managed host only, BLOCKs any command past
// the chain bound, as the hook does there (Gary, 2026-11-04): a benign one as
// enterprise-chain-too-long, since nothing parsed it. Under the bound the
// same benign text matches nothing (#4823 Opus pass 1: on the PR's first cut
// 63 of the 66 residual rows got through the proxies' guard).
func TestMatchSelfProtectCommand_PastTheBoundBlocks_4823(t *testing.T) {
	if _, ok := MatchSelfProtectCommand("ls -la" + strings.Repeat("|a", 100)); ok {
		t.Fatalf("control: a short benign pipeline matched")
	}
	padded := spPad("ls -la")
	if shellparse.CheckChainBound(padded) == nil {
		t.Fatalf("control: the padded command is under the bound")
	}
	if rule, ok := MatchSelfProtectCommand(padded); !ok || rule != ChainTooLongRuleID {
		t.Errorf("a benign command past the bound: %q %v, want %s", rule, ok, ChainTooLongRuleID)
	}
}

// TestChainTooLongRuleID_Spelling_4823: the sentinel is a receipt rule id
// the hook and the MCP proxies both record, so its spelling is pinned
// (#4823 Opus pass 2, M5).
func TestChainTooLongRuleID_Spelling_4823(t *testing.T) {
	if ChainTooLongRuleID != "enterprise-chain-too-long" {
		t.Errorf("ChainTooLongRuleID = %q, want enterprise-chain-too-long", ChainTooLongRuleID)
	}
}

// TestMatchSelfProtectCommand_DerivedTextPastTheBound_4823: a command under
// the bound whose derived text is past it (a nested shell's text after
// variable substitution reads four copies) is BLOCKed by the proxies'
// managed matcher as the sentinel, as the hook does (#4823 Opus pass 2, M8:
// nothing pinned this branch). Control: the command's own text is under the
// bound.
func TestMatchSelfProtectCommand_DerivedTextPastTheBound_4823(t *testing.T) {
	x := strings.Repeat("a|", 9000) + "a"
	cmd := "X='" + x + "'; bash -c \"$X|$X|$X|$X\""
	if shellparse.CheckChainBound(cmd) != nil {
		t.Fatalf("control: the command's own text is past the bound")
	}
	if rule, ok := MatchSelfProtectCommand(cmd); !ok || rule != ChainTooLongRuleID {
		t.Errorf("derived text past the bound: %q %v, want %s", rule, ok, ChainTooLongRuleID)
	}
}
