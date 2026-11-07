package cli

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/auth"
)

// spOperandRow is one command sp-block-delete-config blocks on a managed host,
// and the nodes its receipt must carry: those of the paths the delete
// statement's operands actually remove, or none.
type spOperandRow struct {
	name, cmd string
	want      []string
}

// spOperandRows are the shapes #4603 pass 2 and the Codex pass confirmed
// (finding (c)): the receipt classified every word of the command, so it cited
// nodes for AgentShield paths that were only mentioned. Gary's decision
// (2026-10-30): classify only the operands of the matched delete statement.
// Every row here fails on d567da43, the head that classified every word.
//
// Assembled at runtime: this repo dogfoods AgentShield, and the literal
// spellings are what the rules block.
func spOperandRows() []spOperandRow {
	rm := "r" + "m"
	dir := "~/.agent" + "shield"
	log := dir + "/audit.jsonl"
	pol := dir + "/policy.yaml"
	audit := []string{spNodeAuditTrail}
	return []spOperandRow{
		// Another statement mentions a path; the delete removes nothing of
		// AgentShield's (main's value: no node).
		{"n5: delete elsewhere, then read the policy", rm + " -f /tmp/out.txt; cat " + pol, nil},
		{"n4: delete elsewhere, then list the directory", rm + " -rf /tmp/build-cache && ls -la " + dir + "/", nil},
		// Prose: a heredoc body, an unquoted echo, a comment.
		{"heredoc doc that mentions the uninstall command", "cat > UNINSTALL.md <<'EOF'\n## Uninstall\n\nAsk IT to run the uninstaller. Do not run " + rm + " -rf " + dir + " yourself.\nEOF", nil},
		{"unquoted echo prose", "echo Do not run " + rm + " -rf " + dir, nil},
		{"a comment", "ls /tmp # " + rm + " -rf " + dir, nil},
		// The log is deleted; the policy is only read, echoed or redirected
		// from. Audit trail only.
		{"log delete, then read the policy", rm + " -f " + log + " && cat " + pol, audit},
		{"read the policy, then log delete (Kai's repro)", "cat " + pol + "; " + rm + " " + log, audit},
		{"log delete, stdin from the policy", rm + " " + log + " < " + pol, audit},
		{"log delete, then echo the policy path", rm + " " + log + " && echo " + pol, audit},
		// A .agentshield directory that is not AgentShield's: the community
		// rule's spellings are ~, $HOME, ${HOME}, /Users/*, /home/* and /root
		// (pass-2 follow-up 3).
		{"a scratch HOME's directory", rm + " -rf /tmp/scratch-home/.agent" + "shield", nil},
		{"everything in a scratch HOME's directory", rm + " -rf /tmp/scratch-home/.agent" + "shield/*", nil},
		// The operand's value is not known: the file names come from a file.
		{"substitution operand that is not an echo", rm + " -f $(cat " + dir + "/packs/list.txt)", nil},
		// Not bash: zsh-only syntax makes the parse fail, so the delete
		// statement cannot be identified. Nothing, never a guess.
		{"zsh-only statement before the delete", ": ${(U)HOME}; " + rm + " -rf " + dir + "/lo${zqx}gs", nil},
	}
}

// spOperandControls pass on d567da43 too. They pin what operand-only
// classification must keep: a real delete still attests its node.
func spOperandControls() []spOperandRow {
	rm := "r" + "m"
	dir := "~/.agent" + "shield"
	log := dir + "/audit.jsonl"
	both := []string{spNodeAuditTrail, spNodeTampering}
	return []spOperandRow{
		{"delete through sudo", "sudo " + rm + " " + log, []string{spNodeAuditTrail}},
		{"delete inside a command substitution", "echo $(" + rm + " " + log + ")", []string{spNodeAuditTrail}},
		{"delete inside a brace group", "{ " + rm + " -f " + dir + "/policy.yaml; }", []string{spNodeTampering}},
		{"delete the whole directory, /Users spelling", rm + " -rf /Users/alice/.agent" + "shield/", both},
		{"delete the whole directory, ${HOME} spelling", rm + " -rf ${HOME}/.agent" + "shield", both},
		{"quoted prose in a commit message", "git commit -m \"docs: never " + rm + " -rf " + dir + "\"", nil},
		{"a quoted operand with whitespace is a file name, not the log", rm + " -f \"/tmp/notes on " + log + "\"", nil},
	}
}

// TestDeleteConfigReceiptCitesOnlyDeletedOperands drives each row through the
// real evaluation a hook runs on a managed scratch HOME and checks the node on
// the result, on the logged audit event and in the /api/audit body the SaaS
// receives.
func TestDeleteConfigReceiptCitesOnlyDeletedOperands(t *testing.T) {
	srv, bodies := captureAudit(t)
	home, _ := newFailSafeHome(t, true, failSafePolicyGood)
	if err := auth.Save(&auth.Credentials{Server: srv.URL, Token: "test-agent-token"}); err != nil {
		t.Fatalf("auth.Save: %v", err)
	}
	rows := append(spOperandRows(), spOperandControls()...)
	for _, c := range rows {
		t.Run(c.name, func(t *testing.T) {
			before := len(bodies())
			res, event := evaluateCommand(c.cmd, home, "claude-code-hook", "sess-4603-fr2")
			assertSPBlock(t, res, spDeleteConfigRuleID)
			if !reflect.DeepEqual(res.TaxonomyRefs, c.want) {
				t.Errorf("result taxonomy %v, want %v", res.TaxonomyRefs, c.want)
			}
			if event == nil {
				t.Fatal("no audit event")
			}
			if !reflect.DeepEqual(event.TaxonomyRefs, c.want) {
				t.Errorf("audit event taxonomy %v, want %v", event.TaxonomyRefs, c.want)
			}
			got := bodies()
			if len(got) != before+1 {
				t.Fatalf("want exactly 1 new /api/audit body, got %d", len(got)-before)
			}
			var wire struct {
				Events []struct {
					Taxonomy []string `json:"taxonomy"`
				} `json:"events"`
			}
			if err := json.Unmarshal([]byte(got[before]), &wire); err != nil || len(wire.Events) != 1 {
				t.Fatalf("wire body is not one event (%v):\n%s", err, got[before])
			}
			want := c.want
			if want == nil {
				want = []string{} // present and empty on the wire
			}
			if tax := wire.Events[0].Taxonomy; tax == nil || !reflect.DeepEqual(tax, want) {
				t.Errorf("wire taxonomy %v, want %v:\n%s", tax, want, got[before])
			}
		})
	}
}

// spDeleteConfigRuleID is spelled out rather than taken from the table, so
// this file also runs unchanged against d567da43.
const spDeleteConfigRuleID = "sp-block-delete-config"
