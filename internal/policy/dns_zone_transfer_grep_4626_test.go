package policy

import (
	"regexp"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// #4626: ne-block-dns-zone-transfer (premium) matches its regex over the whole
// command text, and `\b` splits on `-`, so a grep whose needles merely NAME the
// tool and the record type BLOCKed. The fix keeps main's command_regex byte for
// byte and adds a command_regex_exclude that recognises one benign statement:
// a single plain grep invocation with no separator, pipe, redirect, background
// `&`, substitution, expansion, escape, brace or bang.
//
// Attack text is assembled at runtime (the hook reads test sources as
// commands). Hosts are inert.

var (
	dzAx  = "ax" + "fr"
	dzAX  = "AX" + "FR"
	dzIx  = "ix" + "fr"
	dzDig = "di" + "g"
	dzNs  = "ns" + "lookup"
	// dzXfer is a real zone transfer.
	dzXfer = dzDig + " " + dzAx + " example.com"
	// dzWitness is the issue's blocked command.
	dzWitness = "grep -c -e " + dzDig + "-default-ok -e " + dzAx + "-type mutants.txt"
)

const dzRule = "ne-block-dns-zone-transfer"

func dzRuleAndEngine(t *testing.T) (Rule, *Engine) {
	t.Helper()
	ossbuild.SkipPremiumSized(t)
	pol, _, err := LoadPacks("../../packs", DefaultPolicy())
	if err != nil {
		t.Fatalf("LoadPacks: %v", err)
	}
	var rule Rule
	found := false
	for _, r := range pol.Rules {
		if r.ID == dzRule {
			rule, found = r, true
			break
		}
	}
	if !found {
		t.Fatalf("%s not loaded", dzRule)
	}
	engine, err := NewEngineWithAnalyzers(pol, 0)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	return rule, engine
}

// mainRegex is main's command_regex for the rule, pinned here so the TNs
// below can prove they are not vacuous: each one BLOCKed on main because this
// exact pattern matches it. If the pack's regex is ever edited, the first
// assertion in TestDNSZoneTransferGrepNeedles_4626 fails, and the reviewer
// has to re-derive what the exclusion is narrowing.
const mainRegex = `\b(dig|nslookup)\b.*\b(axfr|ixfr|AXFR|IXFR)\b`

// The FP class: grep needles that only name the tool and the record type.
// Each must (a) match main's regex, so main BLOCKed it, (b) be recognised by
// the exclusion, and (c) no longer name the rule end to end, on both
// evaluation paths.
func TestDNSZoneTransferGrepNeedles_4626(t *testing.T) {
	rule, engine := dzRuleAndEngine(t)
	if rule.Match.CommandRegex != mainRegex {
		t.Fatalf("command_regex changed:\n  got  %s\n  main %s\nthe exclusion was reviewed against main's pattern", rule.Match.CommandRegex, mainRegex)
	}
	re := regexp.MustCompile(mainRegex)
	excl := regexp.MustCompile(rule.Match.CommandRegexExclude)
	for _, cmd := range []string{
		dzWitness,
		"grep -e " + dzDig + " -e " + dzAx + " notes.txt",
		"grep -rn '" + dzDig + " " + dzAx + "' docs/",
		`grep -c "` + dzNs + " -type=" + dzAX + `" probes.txt`,
	} {
		if !re.MatchString(cmd) {
			t.Fatalf("vacuous TN: main's regex does not match %q", cmd)
		}
		if !excl.MatchString(cmd) {
			t.Errorf("exclusion does not recognise the benign grep %q", cmd)
		}
		for name, decide := range zshWitnessPaths(engine) {
			got := decide(cmd)
			if got.Decision == DecisionBlock || has(got.TriggeredRules, dzRule) {
				t.Errorf("%s: %q decides %s %v; grep needles resolve no name", name, cmd, got.Decision, got.TriggeredRules)
			}
		}
	}
}

// Every bypass class must keep main's BLOCK by this rule: wrappers, carriers,
// a chain or pipe after the benign-looking head, quoting, type flags, IXFR
// serials. Each row BLOCKed on main by this rule (measured through the
// binaries; see the PR).
func TestDNSZoneTransferBypassClassesStayBlocked_4626(t *testing.T) {
	_, engine := dzRuleAndEngine(t)
	g := dzWitness
	rows := []string{
		// TP-NE-BLOCK-DNS-AXFR-001..004, IXFR-001..002 shapes.
		dzXfer,
		dzDig + " " + dzAX + " @ns1.target.com target.com",
		dzDig + " " + dzIx + "=2023010101 example.com @ns1.example.com",
		dzDig + " _dmarc.example.com " + dzAx + " example.com",
		dzDig + " _dmarc.example.com " + dzAX + " @ns1.target.com target.com",
		dzDig + " _dmarc.example.com " + dzIx + "=2023010101 example.com @ns1.example.com",
		dzNs + " -type=" + dzAX + " example.com",
		// Wrappers, including the zsh command words.
		"sudo " + dzXfer, "env " + dzXfer, "nohup " + dzXfer, "command " + dzXfer,
		"noglob " + dzXfer, "nocorrect " + dzXfer, "=" + dzXfer,
		// Carriers.
		"bash -c '" + dzXfer + "'", "sh -c '" + dzXfer + "'", "bash -s <<< '" + dzXfer + "'",
		"eval '" + dzXfer + "'", "x=$(" + dzXfer + ")", `echo "$(` + dzXfer + `)"`,
		// A chain or pipe after a head the exclusion would recognise alone.
		g + "; " + dzXfer, g + " && " + dzXfer, g + " || " + dzXfer, g + " & " + dzXfer,
		g + "\n" + dzXfer,
		// A newline straight after the command word (#4635 Codex pass 1).
		"grep\n" + dzXfer, "grep\t\n" + dzXfer, "grep \n" + dzXfer,
		g + " | sh", g + " | bash",
		"grep -e " + dzDig + " -e " + dzAx + " notes.txt | sh",
		strings.TrimSuffix(g, "mutants.txt") + "$(" + dzXfer + ")",
		strings.TrimSuffix(g, "mutants.txt") + "`" + dzXfer + "`",
		strings.TrimSuffix(g, "mutants.txt") + "<(" + dzXfer + ")",
		// Quoting.
		dzDig + ` "` + dzAx + `" example.com`, dzDig + ` a""xfr example.com`, dzDig + " '" + dzAX + "' example.com",
		// Type flags and serials.
		dzDig + " -t " + dzAx + " example.com", dzDig + " -t " + dzAX + " example.com",
		dzDig + " -t IXFR=2023010101 example.com", dzDig + " example.com " + dzIx + "=2023010101",
		dzNs + " -type=" + dzAx + " example.com", dzNs + " -query=" + dzAX + " example.com",
		dzNs + " -q=" + dzAx + " example.com", dzNs + " -querytype=" + dzAX + " example.com",
	}
	for name, decide := range zshWitnessPaths(engine) {
		for _, cmd := range rows {
			if got := decide(cmd); got.Decision != DecisionBlock || !has(got.TriggeredRules, dzRule) {
				t.Errorf("%s: %q decides %s %v; want BLOCK by %s, as on main", name, cmd, got.Decision, got.TriggeredRules, dzRule)
			}
		}
	}
}

// The regex-only fallback engine (no analyzer registry) has no per-statement
// retry and no executed-text candidates, so on that path the exclusion's
// character class alone has to refuse a statement separator or a
// substitution. Each row must still fire there.
func TestDNSZoneTransferRegexOnlyPathKeepsChains_4626(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	pol, _, err := LoadPacks("../../packs", DefaultPolicy())
	if err != nil {
		t.Fatalf("LoadPacks: %v", err)
	}
	engine, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	g := dzWitness
	head := strings.TrimSuffix(g, "mutants.txt")
	for _, cmd := range []string{
		g + "; " + dzXfer, g + "\n" + dzXfer, g + "\r\n" + dzXfer, g + " && " + dzXfer, g + " & " + dzXfer,
		// The gap after `grep` must not take a newline: this engine never splits
		// statements, so the exclusion alone has to refuse it (#4635 Codex pass 1).
		"grep\n" + dzXfer, "grep\r\n" + dzXfer, "grep\t\n" + dzXfer,
		g + " | sh", head + "$(" + dzXfer + ")", head + "`" + dzXfer + "`", head + "<(" + dzXfer + ")",
	} {
		if got := engine.Evaluate(cmd, nil); got.Decision != DecisionBlock || !has(got.TriggeredRules, dzRule) {
			t.Errorf("regex-only: %q decides %s %v; want BLOCK by %s", cmd, got.Decision, got.TriggeredRules, dzRule)
		}
	}
	if got := engine.Evaluate(g, nil); has(got.TriggeredRules, dzRule) {
		t.Errorf("regex-only: the witness %q still names %s (%s)", g, dzRule, got.Decision)
	}
}

// Shapes the exclusion deliberately does not recognise, though none of them
// transfers a zone either. They keep main's BLOCK; widening the exclusion to
// any of them has to be a visible diff here.
func TestDNSZoneTransferExclusionResidue_4626(t *testing.T) {
	_, engine := dzRuleAndEngine(t)
	for _, cmd := range []string{
		"sudo " + dzWitness,
		"bash -c '" + dzWitness + "'",
		"grep -e '" + dzDig + "; " + dzAx + "' notes.txt",
		"grep -e " + dzDig + " -e " + dzAx + " notes.txt > hits.txt",
		"rg -e " + dzDig + " -e " + dzAx + " notes.txt",
	} {
		for name, decide := range zshWitnessPaths(engine) {
			if got := decide(cmd); got.Decision != DecisionBlock || !has(got.TriggeredRules, dzRule) {
				t.Errorf("%s: %q decides %s %v; pinned at main's BLOCK by %s", name, cmd, got.Decision, got.TriggeredRules, dzRule)
			}
		}
	}
}

// Pre-existing gaps, unchanged by #4626 and pinned so closing them is
// deliberate: an attached type flag (`-taxfr`, where `\b` cannot split t|a)
// and nslookup reading `set type=axfr` on stdin (the type precedes the tool).
// Both decided AUDIT on main and still do.
func TestDNSZoneTransferPreexistingGaps_4626(t *testing.T) {
	_, engine := dzRuleAndEngine(t)
	for _, cmd := range []string{
		dzDig + " -t" + dzAx + " example.com",
		"printf 'set type=" + dzAx + `\n' | ` + dzNs,
		"echo 'set type=" + dzAx + "' | " + dzNs,
	} {
		for name, decide := range zshWitnessPaths(engine) {
			if got := decide(cmd); got.Decision != DecisionAudit || has(got.TriggeredRules, dzRule) {
				t.Errorf("%s: %q decides %s %v; pinned at main's AUDIT without %s", name, cmd, got.Decision, got.TriggeredRules, dzRule)
			}
		}
	}
}

// An accepted residual (Codex pass 2 on #4635; Gary, 2026-10-28). When a
// grep the exclusion excuses is chained to doc text that names a transfer, the
// rule's statement attribution sees only the doc-text statement, so its
// existing command_intent_downgrade applies: BLOCK on main, AUDIT here, rule
// still named. That is main's own decision for the same remainder behind a
// grep that names nothing (the control row), so it reaches nothing new. Every
// variant whose remainder executes keeps main's BLOCK.
func TestDNSZoneTransferCompoundDocTextResidual_4626(t *testing.T) {
	_, engine := dzRuleAndEngine(t)
	g := "grep -e " + dzDig + " -e " + dzAx + " notes.txt"
	mention := "echo '" + dzDig + " " + dzAx + "'"
	attested := []string{
		g + " && " + mention,                // the residual
		"grep -c x notes.txt && " + mention, // control: main decides the same
	}
	executing := []string{
		g + " && echo '" + dzXfer + "' | sh",
		g + " && " + dzXfer,
		g + ` && echo "$(` + dzXfer + `)"`,
		g + " && bash -c 'echo " + dzXfer + "'",
	}
	for name, decide := range zshWitnessPaths(engine) {
		for _, cmd := range attested {
			if got := decide(cmd); got.Decision != DecisionAudit || !has(got.TriggeredRules, dzRule) {
				t.Errorf("%s: %q decides %s %v; pinned at AUDIT naming %s (attested downgrade)", name, cmd, got.Decision, got.TriggeredRules, dzRule)
			}
		}
		for _, cmd := range executing {
			if got := decide(cmd); got.Decision != DecisionBlock || !has(got.TriggeredRules, dzRule) {
				t.Errorf("%s: %q decides %s %v; want BLOCK by %s, as on main", name, cmd, got.Decision, got.TriggeredRules, dzRule)
			}
		}
	}
}
