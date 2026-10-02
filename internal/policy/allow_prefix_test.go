package policy

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// readOnlyPrefixes mirrors the shape of ts-allow-readonly's prefix list
// (packs/community/terminal-safety.yaml) without depending on the live pack.
//
// The isolation is deliberate and is the whole point of this file. Issue
// #3199's test plan warns that asserting on a suffix which has its own BLOCK
// rule passes for the wrong reason — the BLOCK rule wins on
// most-restrictive-wins and the ALLOW-side defect stays green. Every case
// here calls matchCommandPrefix directly against a synthetic rule, so a
// regression cannot be masked by the rest of the corpus.
var readOnlyPrefixes = []string{
	"ls", "pwd", "whoami", "id", "uname", "date", "df", "du",
	"ps ", "which ", "file ", "head ", "tail ", "wc ", "sort ", "uniq ",
	"grep ", "find ", "echo ", "printf ", "cat ",
	"git log", "git status", "git diff",
}

func allowRule() Rule {
	return Rule{
		ID:       "test-allow-readonly",
		Match:    Match{CommandPrefix: readOnlyPrefixes},
		Decision: DecisionAllow,
	}
}

func auditRule() Rule {
	return Rule{
		ID:       "test-audit-systemctl",
		Match:    Match{CommandPrefix: []string{"systemctl ", "launchctl "}},
		Decision: DecisionAudit,
	}
}

// TestAllowPrefixRejectsLaunderedCompounds is the regression test for #3199.
//
// Each "launders" case is a command whose bare suffix resolves to the AUDIT
// default, but which the pre-fix whole-command prefix match upgraded to ALLOW.
func TestAllowPrefixRejectsLaunderedCompounds(t *testing.T) {
	rule := allowRule()

	cases := []struct {
		name    string
		command string
		want    bool
		why     string
	}{
		// --- simple read-only commands keep ALLOW (no behaviour change) ---
		{"bare grep", "grep -rn foo .", true, "simple read-only command"},
		{"bare echo", "echo hello", true, "simple read-only command"},
		{"bare ls", "ls -la", true, "simple read-only command"},
		{"git status", "git status", true, "simple read-only subcommand"},

		// --- all-segments-read-only compounds keep ALLOW (variant B) ---
		{"grep into wc", "grep -rn foo . | wc -l", true, "every segment read-only"},
		{"cat into head", "cat /etc/hosts | head -20", true, "every segment read-only"},
		{"three read-only segments", "cat f.log | grep x | wc -l", true, "every segment read-only"},
		{"read-only and-chain", "echo hello && date", true, "every segment read-only"},

		// --- the three historical incident shapes: must NOT be ALLOW ---
		{
			"and-chain to non-readonly (#3199 probe)",
			"grep -rn foo . && touch /tmp/probe_marker",
			false,
			"touch is not read-only; bare form is AUDIT",
		},
		{
			"echo prefix launders xargs (#3188 shape)",
			"echo foo | xargs -I{} sh -c {}",
			false,
			"xargs->interpreter was the #3188 sink",
		},
		{
			"grep prefix launders xargs delete (#3197 shape)",
			"grep -rl foo . | xargs rm",
			false,
			"search->xargs delete was the #3197 sink",
		},
		// --- redirects: a file write is not read-only (#4082) ---
		// #3199 left redirects in scope for the ALLOW on the premise that a
		// redirect's danger is its target path and protected_paths plus
		// path-scoped BLOCK rules enumerate those. #4082 falsified the
		// premise: `echo '<payload>' >> ~/.zshenv` earned ALLOW because no
		// rule names that destination. The null device, the inherited
		// streams and fd dups onto them write no file and keep the ALLOW.
		{"append redirect loses allow", "echo hello >> /tmp/probe_out", false, "a file write (#4082)"},
		{"truncating redirect loses allow", "echo hello > /tmp/probe_out", false, "a file write (#4082)"},
		{"startup-file append loses allow", "echo 'export PATH=$PATH:/opt/bin' >> ~/.zshenv", false, "the #4082 carrier"},
		{"stderr to a file loses allow", "grep -rn foo . 2> /tmp/probe_err", false, "n> to a path is a file write"},
		{"fd merge stays allow", "ls /tmp 2>&1", true, "2>&1 is not a file write"},
		{"null device stays allow", "echo hello > /dev/null", true, "the null device is not a file"},
		{"stderr to null stays allow", "grep -rn foo . 2>/dev/null", true, "the null device is not a file"},

		// --- indirect execution ---
		{"command substitution", "echo $(date)", false, "substitution runs a command"},
		{"backtick substitution", "echo `date`", false, "substitution runs a command"},
		{"process substitution", "cat <(date)", false, "process substitution runs a command"},

		// --- separator coverage: every separator, same verdict ---
		{"semicolon launders", "echo hello; touch /tmp/probe_marker", false, "`;` launders too"},
		{"or-chain launders", "echo hello || touch /tmp/probe_marker", false, "`||` launders too"},
		{"pipe launders", "echo hello | tee /tmp/probe_out", false, "tee is not a read-only head"},

		// --- input redirects stay read-only ---
		{"input redirect", "wc -l < /etc/hosts", true, "reading is not a write effect"},
		{"here-string", "wc -c <<< hello", true, "here-string feeds data, does not write"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := matchCommandPrefix(tc.command, rule)
			if got != tc.want {
				t.Errorf("matchCommandPrefix(%q) = %v, want %v\n  rationale: %s",
					tc.command, got, tc.want, tc.why)
			}
		})
	}
}

// TestAllowPrefixNegativeControl is the control the #3199 issue asks for:
// prefixing an AUDIT-default command with a read-only segment must never
// *raise* it to ALLOW.
//
// Stated as a relation rather than as two independent assertions, because the
// defect was precisely that the compound scored MORE permissively than its own
// suffix. A test that only checked the compound in isolation would not
// distinguish "correctly not-ALLOW" from "the prefix list happens not to match".
func TestAllowPrefixNegativeControl(t *testing.T) {
	rule := allowRule()

	suffixes := []string{
		"touch /tmp/probe_marker",
		"systemctl restart nginx",
		"rm /tmp/probe_marker",
	}
	prefixes := []string{"grep -rn foo .", "echo hello", "ls -la"}
	separators := []string{" && ", "; ", " || ", " | "}

	for _, suffix := range suffixes {
		if matchCommandPrefix(suffix, rule) {
			t.Fatalf("precondition failed: bare %q already matches the ALLOW rule; "+
				"pick a suffix that is not itself read-only", suffix)
		}
		for _, prefix := range prefixes {
			for _, sep := range separators {
				compound := prefix + sep + suffix
				if matchCommandPrefix(compound, rule) {
					t.Errorf("laundering: %q is not ALLOW on its own, but %q matched the ALLOW rule",
						suffix, compound)
				}
			}
		}
	}
}

// TestNonAllowPrefixRulesKeepWholeCommandSemantics guards the other half of
// the change. A BLOCK/AUDIT prefix rule must still fire on a compound — a
// restrictive rule matching a chained command is correct, and narrowing it
// would turn this fix into a fail-open of its own.
func TestNonAllowPrefixRulesKeepWholeCommandSemantics(t *testing.T) {
	rule := auditRule()

	cases := []string{
		"systemctl restart nginx",
		"systemctl restart nginx && echo done",
		"systemctl restart nginx | tee /tmp/probe_out",
		"systemctl restart nginx; grep -rn foo .",
		"systemctl restart nginx > /tmp/probe_out",
		"systemctl restart $(cat /tmp/svc)",
	}
	for _, cmd := range cases {
		if !matchCommandPrefix(cmd, rule) {
			t.Errorf("AUDIT prefix rule stopped firing on %q — non-ALLOW rules must keep "+
				"whole-command semantics", cmd)
		}
	}

	// Control: the AUDIT rule must not fire when its prefix is genuinely absent,
	// otherwise the loop above would pass even if matchCommandPrefix returned
	// true unconditionally for non-ALLOW rules.
	if matchCommandPrefix("grep -rn foo .", rule) {
		t.Error("AUDIT prefix rule fired on a command with none of its prefixes")
	}
}

// TestAllowPrefixFailsClosedOnUnparseable checks the fail-safe direction:
// a command the shell parser cannot read must not earn an affirmative ALLOW.
func TestAllowPrefixFailsClosedOnUnparseable(t *testing.T) {
	rule := allowRule()

	unparseable := []string{
		"echo 'unterminated",
		"echo hello && (",
		"echo $(",
	}
	for _, cmd := range unparseable {
		if matchCommandPrefix(cmd, rule) {
			t.Errorf("unparseable command %q earned ALLOW; must fail closed to AUDIT", cmd)
		}
	}
}

// TestEmptyPrefixListNeverMatches guards against the degenerate case where a
// rule with no prefixes vacuously satisfies "every statement has a prefix".
func TestEmptyPrefixListNeverMatches(t *testing.T) {
	rule := Rule{ID: "empty", Match: Match{}, Decision: DecisionAllow}
	for _, cmd := range []string{"echo hello", "", "rm -rf /tmp/x"} {
		if matchCommandPrefix(cmd, rule) {
			t.Errorf("rule with no command_prefix matched %q", cmd)
		}
	}

	if shellparse.AllStatementsHavePrefix("echo hello", nil) {
		t.Error("AllStatementsHavePrefix vacuously true for an empty prefix list")
	}
}

// TestAllowPrefixEndToEnd exercises the engine rather than the helper, so the
// wiring is covered too — a correct helper that nothing calls is the "gate
// nobody runs" shape CLAUDE.md warns about.
func TestAllowPrefixEndToEnd(t *testing.T) {
	pol := &Policy{
		Version:  "0.1",
		Defaults: Defaults{Decision: DecisionAudit},
		Rules:    []Rule{allowRule()},
	}
	eng, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	if got := eng.Evaluate("grep -rn foo .", nil); got.Decision != DecisionAllow {
		t.Errorf("simple read-only command: got %v, want ALLOW", got.Decision)
	}
	if got := eng.Evaluate("grep -rn foo . | wc -l", nil); got.Decision != DecisionAllow {
		t.Errorf("all-read-only pipeline: got %v, want ALLOW", got.Decision)
	}

	laundered := eng.Evaluate("grep -rn foo . && touch /tmp/probe_marker", nil)
	if laundered.Decision == DecisionAllow {
		t.Errorf("laundered compound resolved to ALLOW through the engine: %+v", laundered)
	}
	if laundered.Decision != DecisionAudit {
		t.Errorf("laundered compound should fall through to the AUDIT default, got %v",
			laundered.Decision)
	}

	// #4082 through the engine: a redirect to a file falls to the AUDIT
	// default; one to the null device keeps ALLOW.
	if got := eng.Evaluate("echo 'export PATH=$PATH:/opt/bin' >> ~/.zshenv", nil); got.Decision != DecisionAudit {
		t.Errorf("echo redirected to a startup file: got %v, want the AUDIT default", got.Decision)
	}
	if got := eng.Evaluate("echo hello > /dev/null", nil); got.Decision != DecisionAllow {
		t.Errorf("echo redirected to /dev/null: got %v, want ALLOW", got.Decision)
	}
}

func TestHasIndirectExecution(t *testing.T) {
	indirect := []string{
		"echo $(date)", "echo `date`", "cat <(date)", "diff <(ls a) <(ls b)",
		"echo hi && echo $(whoami)", "echo \"x$(id)y\"",
	}
	for _, cmd := range indirect {
		if !shellparse.HasIndirectExecution(cmd) {
			t.Errorf("%q: want indirect execution detected, got none", cmd)
		}
	}

	direct := []string{
		"echo hi", "grep -rn foo .", "wc -l < /etc/hosts", "wc -c <<< hello",
		"cat a.txt | grep b | wc -l", "echo hi && date",
		// A redirect runs nothing, so it is NOT indirect execution. It is a
		// separate disqualifier (shellparse.HasFileWriteRedirect, #4082);
		// keeping the predicates apart keeps each name true.
		"echo hi > /tmp/x", "echo hi >> /tmp/x", "ls /tmp 2>&1",
	}
	for _, cmd := range direct {
		if shellparse.HasIndirectExecution(cmd) {
			t.Errorf("%q: no indirect execution expected, but one was detected", cmd)
		}
	}

	// Fails closed on unparseable input.
	if !shellparse.HasIndirectExecution("echo 'unterminated") {
		t.Error("unparseable command must report indirect execution (fail closed)")
	}
	// Empty input executes nothing.
	if shellparse.HasIndirectExecution("   ") {
		t.Error("blank command reported indirect execution")
	}
}

func TestAllStatementsHavePrefix(t *testing.T) {
	prefixes := []string{"echo ", "grep ", "wc "}

	all := []string{"echo hi", "echo hi && grep x .", "grep x . | wc -l"}
	for _, cmd := range all {
		if !shellparse.AllStatementsHavePrefix(cmd, prefixes) {
			t.Errorf("%q: every statement matches a prefix, want true", cmd)
		}
	}

	notAll := []string{"echo hi && touch /tmp/x", "touch /tmp/x && echo hi", "cat f | wc -l"}
	for _, cmd := range notAll {
		if shellparse.AllStatementsHavePrefix(cmd, prefixes) {
			t.Errorf("%q: at least one statement lacks a prefix, want false", cmd)
		}
	}

	// Guard against a vacuous pass: the helper must actually be splitting.
	// If it collapsed to a whole-string HasPrefix, this case would be true.
	if shellparse.AllStatementsHavePrefix("echo hi && touch /tmp/x", prefixes) {
		t.Error("helper appears to match on the whole string rather than per statement")
	}
	if strings.Count("echo hi && touch /tmp/x", "&&") != 1 {
		t.Fatal("test fixture lost its separator")
	}
}

// TestAllowPrefixRejectsCompoundConstructs guards the fail-open this fix
// briefly shipped. SplitTopLevelStatements descends into loop/function/if
// bodies, so a construct whose BODY is read-only would otherwise earn ALLOW
// even though the command being run is the construct, not the body.
//
// These three shapes are the accuracy-corpus cases that caught it
// (TN-FUNCSHADOW-001, TN-NE-PINGSWEEP-002, TN-SC-SKILL-CONCEAL-002), asserted
// here too so the regression is caught at the unit level rather than only by
// the full corpus.
func TestAllowPrefixRejectsCompoundConstructs(t *testing.T) {
	rule := allowRule()

	cases := []string{
		`for i in {1..100}; do echo "processing item $i"; done`,
		"for f in *.txt; do echo $f; done",
		`function my_helper() { echo "hello"; }`,
		"while true; do echo tick; done",
		`if true; then echo yes; fi`,
		"{ echo a; echo b; }",
		"(echo a; echo b)",
	}
	for _, cmd := range cases {
		if matchCommandPrefix(cmd, rule) {
			t.Errorf("compound construct %q earned ALLOW; the construct's own head "+
				"token is not in the read-only prefix list", cmd)
		}
	}

	// Control: the bodies in isolation DO match, which is precisely why the
	// whole-command check is load-bearing. If this fails, the test above is
	// passing for the wrong reason (e.g. the prefix list stopped matching echo).
	if !matchCommandPrefix("echo tick", rule) {
		t.Fatal("precondition failed: bare `echo tick` should match the ALLOW rule")
	}
}

// TestAllowPrefixRequiresTokenBoundary is the regression test for #3534: a
// bare (non-space-terminated) command_prefix entry like "ls" matched as a
// substring of an unrelated program's name, so an attacker only had to name
// a script `lsyncd-payload.sh`, `pwdx`, `idmapd`, etc. to launder it to
// ALLOW. #3199's fix (this file's other tests) never touched this — it
// addressed compound commands (`&&`, `|`, `;`), not simple ones.
//
// bareReadOnlyPrefixes mirrors the 19 bare entries in the live
// ts-allow-readonly rule (packs/community/terminal-safety.yaml) — the ones
// with no trailing space, which is exactly the half that had no boundary.
func TestAllowPrefixRequiresTokenBoundary(t *testing.T) {
	bareReadOnlyPrefixes := []string{
		"ls", "pwd", "whoami", "id", "uname", "date", "uptime", "df", "du", "free", "top -l",
		"git log", "git branch", "git show", "git remote", "git tag", "git stash list", "git diff", "git status",
	}
	if len(bareReadOnlyPrefixes) != 19 {
		t.Fatalf("fixture drift: expected 19 bare prefixes mirroring ts-allow-readonly, got %d", len(bareReadOnlyPrefixes))
	}
	rule := Rule{
		ID:       "test-allow-bare-readonly",
		Match:    Match{CommandPrefix: bareReadOnlyPrefixes},
		Decision: DecisionAllow,
	}

	// Empirical cases from #3534, verified against the deployed binary before
	// the fix — every one of these resolved ALLOW via a bare prefix substring.
	launderedByProgramName := []struct {
		command string
		prefix  string
	}{
		{"lsyncd /etc/lsyncd.conf", "ls"},
		{"lsyncd-with-a-payload.sh", "ls"},
		{"idevicebackup2 backup /tmp/dump", "id"},
		{"dumpe2fs /dev/disk1", "du"},
		{"freeradius -X", "free"},
		{"dateutils.dconv x", "date"},
		{"pwdx 1234", "pwd"},
		{"dfu-util -D firmware.bin", "df"},
		{"idmapd -f", "id"},
	}
	for _, tc := range launderedByProgramName {
		if matchCommandPrefix(tc.command, rule) {
			t.Errorf("%q earned ALLOW via bare prefix %q — attacker-controlled program name laundered past the token boundary", tc.command, tc.prefix)
		}
	}

	// Each bare prefix must still ALLOW its own genuine invocation, both bare
	// and with a following argument — the fix must not cost real coverage.
	genuine := []string{
		"ls", "ls -la", "pwd", "pwd -P", "whoami", "id", "id -u", "uname", "uname -a",
		"date", "date +%s", "uptime", "df", "df -h", "du", "du -sh .", "free", "free -m",
		"top -l", "top -l 1",
		"git log", "git log --oneline", "git branch", "git branch -a", "git show", "git show HEAD",
		"git remote", "git remote -v", "git tag", "git tag -l", "git stash list", "git stash list --oneline",
		"git diff", "git diff HEAD", "git status", "git status -s",
	}
	for _, cmd := range genuine {
		if !matchCommandPrefix(cmd, rule) {
			t.Errorf("%q: genuine invocation of a bare read-only prefix must keep ALLOW", cmd)
		}
	}

	// Negative control: a command with none of the bare prefixes must not be
	// affected by this change either way.
	if matchCommandPrefix("touch /tmp/probe_marker", rule) {
		t.Error("unrelated command matched the bare-prefix ALLOW rule")
	}
}

// TestNonAllowPrefixKeepsBareSubstringMatch guards the issue's explicit
// scoping decision: the token-boundary fix applies to the ALLOW path only.
// BLOCK/AUDIT prefix rules keep the historical bare-substring behaviour,
// because narrowing them risks false negatives and is a separate,
// separately-measured change (#3534's "Proposed fix" section).
func TestNonAllowPrefixKeepsBareSubstringMatch(t *testing.T) {
	rule := Rule{
		ID:       "test-audit-set",
		Match:    Match{CommandPrefix: []string{"set"}},
		Decision: DecisionAudit,
	}
	// setpriv is not "set" on a token boundary, but this rule is AUDIT, not
	// ALLOW — it must keep firing (this is the sec-audit-env-dump mis-fire
	// noted in the issue's Provenance section, and deliberately out of scope
	// here).
	if !matchCommandPrefix("setpriv --reuid 1000 bash", rule) {
		t.Error("AUDIT prefix rule must keep bare-substring semantics — boundary narrowing is ALLOW-only")
	}
}

// TestAllowPrefixRedirect_ShippedPolicies checks #4082 against the two
// policies Shield ships, each on its own (no packs), through the analyzer
// pipeline the binary uses. Both carry an ALLOW command_prefix rule of their
// own — DefaultPolicy()'s allow-safe-readonly and the YAML template's
// allow-readonly — with the same read-only-prefix shape as
// ts-allow-readonly, so the redirect condition in PrefixRuleMatches has to
// reach them too. The template matters separately because its default is
// REQUIRE_APPROVAL: there a withheld ALLOW becomes a prompt, not an AUDIT.
func TestAllowPrefixRedirect_ShippedPolicies(t *testing.T) {
	tmpl, err := Load(filepath.Join("..", "..", "configs", "default_policy.yaml"))
	if err != nil {
		t.Fatalf("load shipped template: %v", err)
	}
	cases := []struct {
		name         string
		pol          *Policy
		allowRuleID  string
		readOnly     string
		redirectOut  string
		wantWithheld Decision
	}{
		{"DefaultPolicy", DefaultPolicy(), "allow-safe-readonly", "ls -la", "ls -la > files.txt", DecisionAudit},
		{"configs/default_policy.yaml", tmpl, "allow-readonly", "echo hi", "echo 'export PATH=$PATH:/opt/bin' >> ~/.zshenv", DecisionRequireApproval},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			found := false
			for _, r := range tc.pol.Rules {
				if r.ID == tc.allowRuleID && r.Decision == DecisionAllow && len(r.Match.CommandPrefix) > 0 {
					found = true
				}
			}
			if !found {
				t.Fatalf("precondition: %s no longer ships ALLOW prefix rule %q; re-point this test", tc.name, tc.allowRuleID)
			}
			eng, err := NewEngineWithAnalyzers(tc.pol, 2)
			if err != nil {
				t.Fatalf("NewEngineWithAnalyzers: %v", err)
			}
			if got := eng.Evaluate(tc.readOnly, nil); got.Decision != DecisionAllow {
				t.Errorf("control %q: got %v %v, want ALLOW from %s", tc.readOnly, got.Decision, got.TriggeredRules, tc.allowRuleID)
			}
			if got := eng.Evaluate(tc.readOnly+" > /dev/null", nil); got.Decision != DecisionAllow {
				t.Errorf("%q > /dev/null: got %v, want ALLOW (the null device is not a file)", tc.readOnly, got.Decision)
			}
			got := eng.Evaluate(tc.redirectOut, nil)
			if got.Decision != tc.wantWithheld {
				t.Errorf("%q: got %v %v, want %v (the policy default: the redirect must withhold %s's ALLOW)",
					tc.redirectOut, got.Decision, got.TriggeredRules, tc.wantWithheld, tc.allowRuleID)
			}
		})
	}
}

// TestAllowPrefixRawVerdictSurvivesRewrites pins #4088 pass 1 (Opus review,
// finding F1). The write check ran on each rewritten form separately, and three
// rewrites lose a redirect bash still performs: a ${V:-/dev/null} fold (bash
// never uses the default when V is set by printf -v or is $_), a
// line-continuation join that treats an ESCAPED backslash as a continuation,
// and brace expansion offering a /dev/null alternative. Whichever form lost the
// write earned the ALLOW. Both match paths are exercised: the analyzer
// pipeline (the deployed one) and the regex-only engine fallback.
func TestAllowPrefixRawVerdictSurvivesRewrites(t *testing.T) {
	pol := DefaultPolicy()
	pol.Rules = append([]Rule{{
		ID:       "test-allow-readonly-4088",
		Match:    Match{CommandPrefix: []string{"echo", "printf", "ls"}},
		Decision: DecisionAllow,
		Reason:   "mirrors ts-allow-readonly's shape",
	}}, pol.Rules...)

	laundered := []struct{ cmd, why string }{
		{"echo x > ${X:-/dev/null}", "the PR body's own example: the fold picks the default"},
		{"printf -v zqout '%s' out.txt; echo m > ${zqout:-/dev/null}", "printf -v sets the variable; bash writes out.txt"},
		{"echo out.txt; echo m > ${_:-/dev/null}", "$_ is the last argument; bash writes out.txt"},
		{"echo \\\\\n> out.txt echo content", "an escaped backslash before a newline is not a continuation; bash writes out.txt"},
		{"echo m >> {out.txt,/dev/null}", "brace expansion in a redirect target (zsh MULTIOS writes out.txt)"},
	}
	controls := []string{"echo hi", "echo x > /dev/null", "ls -la >& /dev/null"}

	engines := map[string]func() (*Engine, error){
		"pipeline": func() (*Engine, error) { return NewEngineWithAnalyzers(pol, 2) },
		"fallback": func() (*Engine, error) { return NewEngine(pol) },
	}
	for name, mk := range engines {
		t.Run(name, func(t *testing.T) {
			eng, err := mk()
			if err != nil {
				t.Fatalf("engine: %v", err)
			}
			for _, c := range controls {
				if got := eng.Evaluate(c, nil); got.Decision != DecisionAllow {
					t.Errorf("control %q: got %v %v, want ALLOW", c, got.Decision, got.TriggeredRules)
				}
			}
			for _, tc := range laundered {
				if got := eng.Evaluate(tc.cmd, nil); got.Decision == DecisionAllow {
					t.Errorf("%q: got ALLOW %v — %s", tc.cmd, got.TriggeredRules, tc.why)
				}
			}
		})
	}
}
