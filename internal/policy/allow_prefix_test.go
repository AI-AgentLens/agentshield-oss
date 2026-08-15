package policy

import (
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
		// --- redirects: deliberately OUT of scope (see matchCommandPrefix) ---
		// These stay ALLOW. The sshd-config incident is this shape and is
		// stopped by its own BLOCK rule; excluding redirects here costs 61
		// accuracy-corpus TNs to close a *bounded* (target-path) risk that
		// protected_paths already covers. Asserted rather than omitted so the
		// scope decision is visible if someone changes it.
		{"append redirect stays allow", "echo hello >> /tmp/probe_out", true, "redirect scope: out"},
		{"truncating redirect stays allow", "echo hello > /tmp/probe_out", true, "redirect scope: out"},
		{"fd merge stays allow", "ls /tmp 2>&1", true, "2>&1 is not even a file write"},

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
		// Redirects are NOT indirect execution — deliberate scope, see
		// matchCommandPrefix. A regression here would silently re-expand the fix.
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
