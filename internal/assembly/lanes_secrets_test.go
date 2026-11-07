package assembly

import (
	"encoding/base64"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/psreader"
)

// The PowerShell lane runs the shell pipeline's inline-secrets heuristic over
// each text it reads (#4802), so a token in a cmdlet call, an assignment or a
// .NET call decides what the Bash tool decides: BLOCK
// guardian-secrets_in_command. These pin the lane's half; the hook and
// shield-server halves are in internal/cli and cmd/shield-server.
//
// Token-shaped strings are assembled at run time: the hook on a developer
// machine reads test sources it is asked to run as commands.

const (
	secretsRuleID = "guardian-secrets_in_command"
	secretsNode   = "credential-exposure/inline-credential/secret-in-command-line"
)

func laneToken() string { return "gh" + "p_" + strings.Repeat("a1B2", 9) }

func secretsLane(t *testing.T, e *policy.Engine) *PowerShellLane {
	t.Helper()
	return &PowerShellLane{Engine: e, Env: psreader.Env{Home: "/home/u"}, Opts: policy.FactsOptions{Home: "/home/u"},
		Cwd: "/home/u", MaxDepth: 2,
		POSIX: func(string) policy.EvalResult { return policy.EvalResult{Decision: policy.DecisionAudit} }}
}

// encodedCommand is text as PowerShell's -EncodedCommand takes it: base64 of
// its UTF-16LE bytes.
func encodedCommand(text string) string {
	u := utf16.Encode([]rune(text))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func hasDialectNote(ns []analyzer.Note) bool {
	return slices.ContainsFunc(ns, func(n analyzer.Note) bool { return n.Kind == analyzer.NoteDialect })
}

func TestPowerShellLane_InlineSecrets(t *testing.T) {
	l := secretsLane(t, testEngine(t))
	if r, err := l.Read("Get-ChildItem -Recurse | Select-Object -First 5"); err != nil || r.Decision != policy.DecisionAudit || len(r.TriggeredRules) != 0 {
		t.Fatalf("control: %s %v %v; want a rule-less AUDIT", r.Decision, r.TriggeredRules, err)
	}
	for _, text := range []string{
		"Write-Output " + laneToken(),
		"$env:GITHUB_TOKEN = '" + laneToken() + "'; gh repo list",
		"Invoke-RestMethod -Uri https://api.github.com/user -Headers @{Authorization='token " + laneToken() + "'}",
		"[Environment]::SetEnvironmentVariable('GITHUB_TOKEN', '" + laneToken() + "', 'User')",
	} {
		r, err := l.Read(text)
		if err != nil || r.Decision != policy.DecisionBlock || !slices.Equal(r.TriggeredRules, []string{secretsRuleID}) ||
			!slices.Equal(r.TaxonomyRefs, []string{secretsNode}) || len(r.Reasons) != 1 {
			t.Errorf("%q: %s %v %v %v (err %v); want BLOCK by %s with its node", text, r.Decision, r.TriggeredRules, r.TaxonomyRefs, r.Reasons, err, secretsRuleID)
		}
		if !hasDialectNote(r.Notes) {
			t.Errorf("%q: notes %v; the reading lost EvaluateFacts' dialect note", text, r.Notes)
		}
	}
}

// TestPowerShellLane_InlineSecrets_NameOnlyIsTheAuditTier: a credential-named
// assignment whose value has no credential shape is the heuristic's AUDIT
// tier (#3345). It does not raise the decision; the AUDIT tie rule (#4779)
// gives the rule-less AUDIT's record to it, so the receipt names the rule, as
// the Bash tool's does.
func TestPowerShellLane_InlineSecrets_NameOnlyIsTheAuditTier(t *testing.T) {
	r, err := secretsLane(t, testEngine(t)).Read("$env:API" + "_KEY = 'notarealvalue'")
	if err != nil || r.Decision != policy.DecisionAudit || !slices.Equal(r.TriggeredRules, []string{secretsRuleID}) {
		t.Errorf("%s %v (err %v); want AUDIT naming %s", r.Decision, r.TriggeredRules, err, secretsRuleID)
	}
}

// TestPowerShellLane_InlineSecrets_NestedText: a nested PowerShell text is
// read like the call's own, so a token only the decoded -EncodedCommand
// holds BLOCKs, as a protected path read there does. Control: the call's own
// text does not carry the token.
func TestPowerShellLane_InlineSecrets_NestedText(t *testing.T) {
	text := "powershell -NoProfile -EncodedCommand " + encodedCommand("Write-Output "+laneToken())
	if strings.Contains(text, laneToken()) || strings.Contains(text, "gh"+"p_") {
		t.Fatal("control: the outer text carries the token")
	}
	r, err := secretsLane(t, testEngine(t)).Read(text)
	if err != nil || r.Decision != policy.DecisionBlock || !slices.Contains(r.TriggeredRules, secretsRuleID) {
		t.Errorf("%s %v (err %v); want BLOCK by %s from the decoded text", r.Decision, r.TriggeredRules, err, secretsRuleID)
	}
}

// TestPowerShellLane_InlineSecrets_TieKeepsTheLanesRecord: a BLOCK the lane
// decides itself keeps its own record on the tie, as the shell's
// protected-path check, which runs before its pipeline, keeps its record.
func TestPowerShellLane_InlineSecrets_TieKeepsTheLanesRecord(t *testing.T) {
	r, err := secretsLane(t, testEngine(t)).Read("Get-Content ~/.ssh/id_rsa; Write-Output " + laneToken())
	if err != nil || r.Decision != policy.DecisionBlock || !slices.Equal(r.TriggeredRules, []string{policy.ProtectedPathRuleID}) {
		t.Errorf("%s %v (err %v); want the lane's own protected-path BLOCK record", r.Decision, r.TriggeredRules, err)
	}
}

// TestPowerShellLane_InlineSecrets_AuditOnly: in audit-only mode the lane
// decides AUDIT and records the BLOCK as the original decision, so the row
// combiner ranks it as the BLOCK it was.
func TestPowerShellLane_InlineSecrets_AuditOnly(t *testing.T) {
	e := testEngine(t)
	e.SetMode("audit-only")
	r, err := secretsLane(t, e).Read("Write-Output " + laneToken())
	if err != nil || r.Decision != policy.DecisionAudit || r.OriginalDecision != policy.DecisionBlock ||
		!slices.Equal(r.TriggeredRules, []string{secretsRuleID}) {
		t.Errorf("%s (was %s) %v (err %v); want AUDIT (was BLOCK) by %s", r.Decision, r.OriginalDecision, r.TriggeredRules, err, secretsRuleID)
	}
}

// TestPowerShellLane_InlineSecrets_Bound: with InlineSecretsBytes set (the
// server's), a text past it is not read by the heuristic, and a parse_error
// note says so (the AUDIT floor); a text at the bound is read. Control: with
// no bound (the hook's), the same long text BLOCKs.
func TestPowerShellLane_InlineSecrets_Bound(t *testing.T) {
	head := "Write-Output " + laneToken() + "; "
	long := head + strings.Repeat("Get-Date; ", (ServerInlineSecretsBytes-len(head))/10+1)
	if len(long) <= ServerInlineSecretsBytes {
		t.Fatalf("fixture of %d bytes is not past the bound", len(long))
	}
	l := secretsLane(t, testEngine(t))
	if r, err := l.Read(long); err != nil || r.Decision != policy.DecisionBlock || !slices.Contains(r.TriggeredRules, secretsRuleID) {
		t.Fatalf("control, no bound: %s %v (err %v); want BLOCK by %s", r.Decision, r.TriggeredRules, err, secretsRuleID)
	}

	l.InlineSecretsBytes = ServerInlineSecretsBytes
	r, err := l.Read(long)
	noted := slices.ContainsFunc(r.Notes, func(n analyzer.Note) bool {
		return n.Kind == "parse_error" && strings.Contains(n.Detail, "inline-secrets heuristic")
	})
	if err != nil || r.Decision != policy.DecisionAudit || slices.Contains(r.TriggeredRules, secretsRuleID) || !noted {
		t.Errorf("past the bound: %s %v, note %v (err %v); want AUDIT, no secrets rule, and the bound's note", r.Decision, r.TriggeredRules, noted, err)
	}

	atBound := head + strings.Repeat("x", ServerInlineSecretsBytes-len(head))
	if r, err := l.Read(atBound); err != nil || r.Decision != policy.DecisionBlock || !slices.Contains(r.TriggeredRules, secretsRuleID) {
		t.Errorf("at the bound (%d bytes): %s %v (err %v); want BLOCK by %s", len(atBound), r.Decision, r.TriggeredRules, err, secretsRuleID)
	}
}
