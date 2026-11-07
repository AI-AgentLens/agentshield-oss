package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/auth"
	"github.com/AI-AgentLens/agentshield/internal/enterprise"
)

// #4670 (Gary, 2026-10-30): sp-block-binary-replace and the harness
// file-write path sp-block-config-tool-write are split by target, like
// sp-block-delete-config since #4603. A destination on a log path cites
// ai-audit-trail-circumvention; every other target keeps
// security-tool-tampering. The receipt changes; no decision does.
//
// Every command here is assembled at runtime: this repo dogfoods AgentShield,
// and the literal spellings are what the rules block.

// spBinaryReplaceRuleID is spelled out rather than taken from the table, so
// this file also runs unchanged against main d6edfc98 for the bite-check.
const spBinaryReplaceRuleID = "sp-block-binary-replace"

// binaryReplaceReceiptRows are commands sp-block-binary-replace blocks on a
// managed host, and the nodes the receipt must carry.
func binaryReplaceReceiptRows() []spOperandRow {
	as := "agent" + "shield"
	dir := "~/." + as
	log := dir + "/audit.jsonl"
	pol := dir + "/policy.yaml"
	bin := "/usr/local/bin/" + as
	audit := []string{spNodeAuditTrail}
	tamper := []string{spNodeTampering}
	both := []string{spNodeAuditTrail, spNodeTampering}
	return []spOperandRow{
		// Each verb onto the audit log: the audit-trail node, not tampering
		// (main: tampering).
		{"cp onto the log (the issue's repro)", "cp /tmp/x " + log, audit},
		{"mv onto the log", "mv /tmp/x " + log, audit},
		{"ln onto the log", "ln -sf /dev/null " + log, audit},
		{"install onto the log", "install -m 600 /dev/null " + log, audit},
		{"cp through sudo, then echo", "sudo cp -f /tmp/x " + log + " && echo done", audit},
		{"cp by path", "/bin/cp /tmp/x " + log, audit},
		{"cp onto the log, $HOME quoted", `cp /tmp/x "$HOME/.` + as + `/audit.jsonl"`, audit},
		{"cp onto the log, /Users spelling", "cp -f /tmp/x /Users/alice/." + as + "/audit.jsonl", audit},
		{"cp onto the log, redirect after", "cp /tmp/x " + log + " 2>/dev/null", audit},
		{"cp inside a command substitution", "echo $(cp /tmp/x " + log + ")", audit},
		{"cp with a quote-spliced log name", "cp /tmp/x " + dir + "/au'd'it.jsonl", audit},
		{"quote-spliced verb", "c'p' /tmp/x " + log, audit},
		{"cp with an unset-parameter splice", "cp /tmp/x ~/.agent${zqx}shield/audit.jsonl", audit},
		{"cp of a quoted ; source onto the log", "cp 'a;b' " + log, audit},
		// The other log files the community rule covers.
		{"cp onto a rotated generation", "cp /tmp/x " + log + ".1", audit},
		{"cp into the logs directory", "cp /tmp/x " + dir + "/logs/audit.jsonl", audit},
		{"cp onto the upload queue", "cp /dev/null " + dir + "/audit-queue/queue.jsonl", audit},
		{"ln onto another .jsonl", "ln -sf /dev/null " + dir + "/session-1.jsonl", audit},
		{"cp a log-named file into the directory itself", "cp /tmp/backup/audit.jsonl " + dir + "/", audit},
		// The shape choice: mv with the log as a SOURCE. Moving the log away
		// removes the trail; on an unmanaged host ts-block-agentshield-log-move
		// cites the audit-trail node.
		{"mv the log away", "mv " + log + " /tmp/x", audit},
		{"mv the logs directory away", "mv " + dir + "/logs /tmp/old-logs", audit},
		{"mv the log onto its own generation", "mv " + log + " " + log + ".1", audit},
		{"mv the log away to a variable", "mv " + log + ` "$DEST"`, audit},

		// Binary and config targets: tampering, unchanged.
		{"cp onto the binary", "cp /tmp/x " + bin, tamper},
		{"install onto the binary", "install -m 755 /tmp/x /opt/homebrew/bin/" + as, tamper},
		{"ln onto the binary", "ln -sf /tmp/x /opt/homebrew/bin/" + as, tamper},
		{"mv onto the binary", "mv /tmp/x " + bin, tamper},
		{"cp onto the policy", "cp /tmp/x " + pol, tamper},
		{"cp the policy into the directory", "cp /tmp/policy.yaml " + dir + "/", tamper},
		{"mv the policy away", "mv " + pol + " /tmp/x", tamper},
		// Not the log by the community rule's path set: tampering, unchanged.
		{"cp onto a .jsonl.txt", "cp /tmp/x " + dir + "/notes.jsonl.txt", tamper},
		{"cp onto logsheet.txt", "cp /tmp/x " + dir + "/logsheet.txt", tamper},
		{"cp onto a scratch HOME's log", "cp /tmp/x /tmp/scratch-home/." + as + "/audit.jsonl", tamper},
		// The log is only read: no target is the log, main's node.
		{"cp the log out", "cp " + log + " /tmp/x", tamper},
		{"ln to the log from elsewhere", "ln -s " + log + " /tmp/x", tamper},

		// Pass-1 finding 1: -t/--target-directory names the destination, so a
		// positional log is a SOURCE copied or linked out. These stay tampering
		// (main: tampering), except mv (the log is moved away) and a target dir
		// that IS the log location.
		{"-t: cp the log out to a dir", "cp -t /tmp " + log, tamper},
		{"--target-directory=: cp the log out", "cp --target-directory=/tmp " + log, tamper},
		{"--target-directory : cp the log out", "cp --target-directory /tmp " + log, tamper},
		{"-t: ln the log out to a dir", "ln -s -t /tmp " + log, tamper},
		{"-t: install the log out to a dir", "install -t /tmp " + log, tamper},
		{"-rt: cp the logs dir out", "cp -rt /tmp/backup " + dir + "/logs", tamper},
		{"-t: mv the log away to a dir", "mv -t /tmp " + log, audit},
		{"-t: the target dir is the logs dir", "cp -t " + dir + "/logs /tmp/x", audit},

		// Pass-2 finding 1 (Gary's 2026-10-31 conservative fallback): a
		// `-t`-family option this parse cannot place keeps tampering, never the
		// log node. A short cluster that jammed the dir on, a value-taking
		// option whose value carries the letter, a quoted option left in Args,
		// and a long-option variant of --target-directory are all uncertain.
		{"p2: short cluster -t with jammed dir", "cp -t/tmp " + log, tamper},
		{"p2: short cluster -rt with jammed dir", "cp -rt/tmp/backup " + dir + "/logs", tamper},
		{"p2: short cluster -at", "cp -at/tmp " + log, tamper},
		{"p2: -t with quoted jammed dir", `cp -t"/tmp" ` + log, tamper},
		{"p2: ln short cluster -st", "ln -st/tmp " + log, tamper},
		{"p2: ln short cluster -sft", "ln -sft/tmp " + log, tamper},
		{"p2: install short cluster -t", "install -t/tmp " + log, tamper},
		{"p2: quoted -t single", "cp '-t' /tmp " + log, tamper},
		{"p2: quoted -t double", `cp "-t" /tmp ` + log, tamper},
		{"p2: quoted --target-directory=", `cp "--target-directory=/tmp" ` + log, tamper},
		{"p2: long --target abbreviation", "cp --target /tmp " + log, tamper},
		{"p2: long --target-dir abbreviation", "cp --target-dir /tmp " + log, tamper},
		{"p2: install value-option carrying t", "install -gstaff " + log + " /tmp/out", tamper},
		{"p2: short cluster -t with two operands", "cp -t/tmp " + log + " " + pol, tamper},
		{"p2: -rT uppercase cluster (tampering not dropped)", "cp -rT /tmp/backup/logs " + dir, tamper},

		// Pass-2 finding 2: a quoted directory destination is read the way the
		// shell passes it, over every form pair, so these cite audit-trail like
		// their unquoted twins.
		{"p2: quoted $HOME dir destination", `cp /tmp/backup/audit.jsonl "$HOME/.` + as + `/"`, audit},
		{"p2: quoted braced HOME dir destination", `cp /tmp/backup/audit.jsonl "${HOME}/.` + as + `"`, audit},
		{"p2: -t with quoted $HOME dir", `cp -t "$HOME/.` + as + `" /tmp/backup/audit.jsonl`, audit},
		{"p2: --target-directory= quoted $HOME dir", `cp --target-directory="$HOME/.` + as + `" /tmp/backup/audit.jsonl`, audit},
		{"p2: ln into a quoted $HOME dir", `ln -s /tmp/backup/audit.jsonl "$HOME/.` + as + `"`, audit},
		{"p2: cp -r logs into a quoted $HOME dir", `cp -r /tmp/backup/logs "$HOME/.` + as + `/"`, audit},
		// A single-quoted leading ~ is a literal in bash, not the home dir, so
		// this stays tampering even though the community overwrite rule's own
		// `["']?~` would read it as home (the one deliberate managed/unmanaged
		// divergence, #4670 pass 2).
		{"p2: single-quoted literal tilde dir", "install /tmp/backup/audit.jsonl '~/." + as + "/'", tamper},

		// Pass-2 suspected item (Gary: "lands on the log"): mv INTO the
		// directory lands the moved file on the log, so audit-trail.
		{"p2: mv a log file into the dir", "mv /tmp/backup/audit.jsonl " + dir + "/", audit},
		{"p2: mv the logs dir into the dir", "mv /tmp/backup/logs " + dir + "/", audit},
		{"p2: mv a log file into the dir, no slash", "mv /tmp/backup/audit.jsonl " + dir, audit},
		{"p2: mv -t the dir, a log source", "mv -t " + dir + " /tmp/backup/audit.jsonl", audit},

		// Pass-2 T5: --target-directory= the dir, a policy and a log source, so
		// both nodes.
		{"p2: target-dir the dir, policy and log sources", "cp --target-directory=" + dir + " /tmp/policy.yaml /tmp/audit.jsonl", both},

		// Pass-1 finding 2: a one-operand ln links into the cwd and leaves the
		// log untouched. Tampering (main: tampering).
		{"one-operand ln of the log", "ln -s " + log, tamper},
		{"one-operand ln of the logs dir", "ln -s " + dir + "/logs", tamper},

		// Pass-1 finding 3: a `..` operand is cleaned before the log set is
		// consulted, so the real destination decides the node.
		{"dotdot through logs to the policy", "cp /tmp/x " + dir + "/logs/../policy.yaml", tamper},
		{"dotdot out to the binary", "cp /tmp/x " + dir + "/logs/../../../../usr/local/bin/" + as, tamper},
		{"dotdot mv to agentshield.yaml", "mv /tmp/x " + dir + "/logs/../" + as + ".yaml", tamper},
		{"dotdot install into packs", "install -m 755 /tmp/x " + dir + "/logs/../packs/community/x.yaml", tamper},
		{"dotdot that cleans to the log", "cp /tmp/x " + dir + "/packs/../audit.jsonl", audit},

		// A log and a config target: each node once.
		{"cp onto the log, then onto the policy", "cp /tmp/x " + log + " && cp /tmp/y " + pol, both},
		{"mv the log onto the policy", "mv " + log + " " + pol, both},
		{"cp onto the log; ln onto the binary", "cp /tmp/x " + log + "; ln -sf /tmp/y " + bin, both},
		{"cp the log out, then cp onto the log", "cp " + log + " /tmp/bak && cp /tmp/x " + log, audit},
		// Follow-up #4: several sources into the directory root, one log-named,
		// one not. Each lands as ~/.agentshield/<basename>, so both nodes.
		{"log and packs sources into the directory", "cp -r /tmp/backup/logs /tmp/backup/packs " + dir + "/", both},
		// Mutant D4 pin: a config copy-OUT is a read, not a modification, so it
		// adds no node; only the log write counts. (All-operands-modified would
		// make this `both`.)
		{"policy copied out, then cp onto the log", "cp " + pol + " /tmp/p && cp /tmp/x " + log, audit},

		// No statement of the rule's verbs writes the log: main's node.
		// Prose that quotes the copy is not a copy (#4603's principle: the
		// receipt names what the matched statement does).
		{"echo of the copy", `echo "cp /tmp/x ` + log + `"`, tamper},
		{"commit message quoting the copy", `git commit -m "fix: block cp /tmp/x ` + log + `"`, tamper},
		// Residuals, pinned so that closing them is deliberate: a bash -c body
		// is not parsed, and a command that does not parse as bash names no
		// statement. Both keep main's node.
		{"residual: copy inside bash -c", "bash -c 'cp /tmp/x " + log + "'", tamper},
		{"residual: zsh-only statement before the copy", ": ${(U)HOME}; cp /tmp/x " + log, tamper},
		// #4637's kept-BLOCK shapes: no verb statement writes the log.
		{"#4637 kept: echo mcp redirected onto the binary", "echo mcp " + as + " > " + bin, tamper},
		{"#4637 kept: setup mcp then cp onto the binary", as + " setup mcp && cp /tmp/x " + bin, tamper},
	}
}

// TestBinaryReplaceReceiptSplitByTarget drives each row through the real
// evaluation a hook runs on a managed scratch HOME and checks the node on the
// result, the logged audit event and the /api/audit body. assertSPBlock first
// pins that the decision and the rule are main's.
func TestBinaryReplaceReceiptSplitByTarget(t *testing.T) {
	srv, bodies := captureAudit(t)
	home, _ := newFailSafeHome(t, true, failSafePolicyGood)
	if err := auth.Save(&auth.Credentials{Server: srv.URL, Token: "test-agent-token"}); err != nil {
		t.Fatalf("auth.Save: %v", err)
	}
	for _, c := range binaryReplaceReceiptRows() {
		t.Run(c.name, func(t *testing.T) {
			before := len(bodies())
			res, event := evaluateCommand(c.cmd, home, "claude-code-hook", "sess-4670")
			assertSPBlock(t, res, spBinaryReplaceRuleID)
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
			if tax := wire.Events[0].Taxonomy; !reflect.DeepEqual(tax, c.want) {
				t.Errorf("wire taxonomy %v, want %v", tax, c.want)
			}
		})
	}
}

// The #4637 shape #4642 excluded is not a self-protection BLOCK, so it has no
// receipt from this path at all. Unchanged by #4670.
func TestBinaryReplaceExcludedMCPShapeStillUnmatched(t *testing.T) {
	as := "agent" + "shield"
	for _, cmd := range []string{
		as + " setup mcp && " + as + " status",
		"echo mcp " + as,
	} {
		if id, ok := enterprise.MatchSelfProtectCommand(cmd); ok {
			t.Errorf("%q now reaches %s; #4642 excluded it", cmd, id)
		}
	}
}

// binaryReplaceNotLogTPs lists the community log TPs that reach
// sp-block-binary-replace whose receipt is NOT the audit-trail node, each
// with the reason. Empty today: every one agrees.
var binaryReplaceNotLogTPs = map[string]string{}

// binaryReplaceLogTNs lists the community log TNs that reach
// sp-block-binary-replace whose receipt IS the audit-trail node, each with the
// reason. They are TNs of the move rule because the log is the destination,
// not a source. They are not inline TPs of the overwrite rule only because its
// raw pattern stops at the trailing redirect or comment; on an unmanaged host
// the engine reads the statement without it, and the overwrite rule BLOCKs
// both and cites the audit-trail node (real-hook probes, #4670 PR body).
var binaryReplaceLogTNs = map[string]string{
	"mv -f /tmp/x ~/.agent" + "shield/audit.jsonl 2>/dev/null": "a move onto the log; the trailing redirect is not an operand",
	"mv /tmp/x ~/.agent" + "shield/audit.jsonl # restore":      "a move onto the log; the trailing comment is not an operand",
}

// TestBinaryReplaceNodesAgreeWithCommunityRules is the parity check behind
// the receipt (Gary's principle from #4603: a managed host and an unmanaged
// host agree on what an action does to the log). Every inline TP of the two
// community rules that define a copy onto the log and a move off it, when
// sp-block-binary-replace blocks it first on a managed host, carries the
// audit-trail node and not tampering. Every inline TN that the managed rule
// still blocks, and that is no TP of either rule, keeps tampering.
func TestBinaryReplaceNodesAgreeWithCommunityRules(t *testing.T) {
	overwrite := embeddedRule(t, "ts-block-agentshield-log-overwrite")
	move := embeddedRule(t, "ts-block-agentshield-log-move")
	if overwrite.Tests == nil || move.Tests == nil {
		t.Fatal("a community log rule has no inline tests")
	}
	isTP := map[string]bool{}
	for _, c := range append(append([]string{}, overwrite.Tests.TP...), move.Tests.TP...) {
		isTP[c] = true
	}
	audit := []string{spNodeAuditTrail}
	tamper := []string{spNodeTampering}
	for _, set := range []struct {
		name string
		cmds []string
		tp   bool
	}{
		{"overwrite tp", overwrite.Tests.TP, true},
		{"move tp", move.Tests.TP, true},
		{"overwrite tn", overwrite.Tests.TN, false},
		{"move tn", move.Tests.TN, false},
	} {
		reached := 0
		for _, cmd := range set.cmds {
			if !set.tp && isTP[cmd] {
				continue // a TN of one rule that is a TP of the other
			}
			if id, ok := enterprise.MatchSelfProtectCommand(cmd); !ok || id != spBinaryReplaceRuleID {
				continue
			}
			reached++
			want := tamper
			if _, ok := binaryReplaceLogTNs[cmd]; ok && !set.tp {
				want = audit
			}
			if set.tp {
				want = audit
				if _, ok := binaryReplaceNotLogTPs[cmd]; ok {
					want = tamper
				}
			}
			if got := selfProtectTaxonomyRefs(spBinaryReplaceRuleID, cmd); !reflect.DeepEqual(got, want) {
				t.Errorf("%s %q: %v, want %v", set.name, cmd, got, want)
			}
		}
		// A denominator, so a pack edit that stops these commands reaching the
		// managed rule cannot turn this test vacuous.
		t.Logf("%s: %d of %d inline cases reach %s", set.name, reached, len(set.cmds), spBinaryReplaceRuleID)
		if reached == 0 {
			t.Errorf("%s: no inline case reaches %s; the parity check measured nothing", set.name, spBinaryReplaceRuleID)
		}
	}
	for cmd, why := range binaryReplaceNotLogTPs {
		if strings.TrimSpace(why) == "" || !isTP[cmd] {
			t.Errorf("binaryReplaceNotLogTPs: %q has no reason or is no longer a TP", cmd)
		}
	}
	// The exception list cannot go stale: each entry is still an inline TN.
	tn := map[string]bool{}
	for _, c := range append(append([]string{}, overwrite.Tests.TN...), move.Tests.TN...) {
		tn[c] = true
	}
	for cmd, why := range binaryReplaceLogTNs {
		if strings.TrimSpace(why) == "" || !tn[cmd] || isTP[cmd] {
			t.Errorf("binaryReplaceLogTNs: %q has no reason, is no longer a TN, or is now a TP", cmd)
		}
	}
}

// TestToolWriteReceiptSplitByTarget: sp-block-config-tool-write cites the
// audit-trail node for a write onto a log file and tampering for every other
// file in the directory, each once. The decision and the reason are main's:
// a BLOCK naming the first target in the directory.
func TestToolWriteReceiptSplitByTarget(t *testing.T) {
	home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
	f := func(rel string) string { return filepath.Join(configDir, filepath.FromSlash(rel)) }
	// A link from outside into the directory, and a link to the log itself.
	outside := t.TempDir()
	dirLink := filepath.Join(outside, "cfg")
	if err := os.Symlink(configDir, dirLink); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f("audit.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	logLink := filepath.Join(outside, "l.jsonl")
	if err := os.Symlink(f("audit.jsonl"), logLink); err != nil {
		t.Fatal(err)
	}
	audit := []string{spNodeAuditTrail}
	tamper := []string{spNodeTampering}
	both := []string{spNodeAuditTrail, spNodeTampering}
	patch := func(headers ...string) string {
		return "*** Begin Patch\n" + strings.Join(headers, "\n") + "\n*** End Patch\n"
	}
	cases := []struct {
		name, tool string
		args       map[string]interface{}
		fromText   bool
		want       []string
	}{
		{"Write the log", "Write", map[string]interface{}{"file_path": f("audit.jsonl"), "content": ""}, false, audit},
		{"Edit the log", "Edit", map[string]interface{}{"file_path": f("audit.jsonl"), "old_string": "BLOCK", "new_string": "ALLOW"}, false, audit},
		{"MultiEdit the log", "MultiEdit", map[string]interface{}{"file_path": f("audit.jsonl"), "edits": []interface{}{}}, false, audit},
		{"Write a rotated generation", "Write", map[string]interface{}{"file_path": f("audit.jsonl.1"), "content": ""}, false, audit},
		{"Write into the logs directory", "Write", map[string]interface{}{"file_path": f("logs/debug.log"), "content": ""}, false, audit},
		{"Write the upload queue", "Write", map[string]interface{}{"file_path": f("audit-queue/queue.jsonl"), "content": ""}, false, audit},
		{"Write another .jsonl", "Write", map[string]interface{}{"file_path": f("session-1.jsonl"), "content": ""}, false, audit},
		{"Write the log by ~", "Write", map[string]interface{}{"file_path": "~/.agent" + "shield/audit.jsonl", "content": ""}, false, audit},
		{"Write the log through a linked directory", "Write", map[string]interface{}{"file_path": filepath.Join(dirLink, "audit.jsonl"), "content": ""}, false, audit},
		{"Edit the log through a file link", "Edit", map[string]interface{}{"file_path": logLink, "old_string": "a", "new_string": "b"}, false, audit},
		{"copilot create the log", "create", map[string]interface{}{"path": f("audit.jsonl"), "file_text": ""}, false, audit},
		{"apply_patch delete the log", "apply_patch", map[string]interface{}{"input": patch("*** Delete File: " + f("audit.jsonl"))}, false, audit},
		{"apply_patch move the log away", "apply_patch", map[string]interface{}{"input": patch("*** Update File: "+f("audit.jsonl"), "*** Move to: /tmp/x.jsonl", "@@", "-a", "+b")}, false, audit},

		{"Write the policy", "Write", map[string]interface{}{"file_path": f("policy.yaml"), "content": "x"}, false, tamper},
		{"Edit managed.json", "Edit", map[string]interface{}{"file_path": f("managed.json"), "old_string": "true", "new_string": "false"}, false, tamper},
		{"Write a pack", "Write", map[string]interface{}{"file_path": f("packs/x.yaml"), "content": "x"}, false, tamper},
		{"Write a .jsonl.txt", "Write", map[string]interface{}{"file_path": f("notes.jsonl.txt"), "content": "x"}, false, tamper},
		{"Write logsheet.txt", "Write", map[string]interface{}{"file_path": f("logsheet.txt"), "content": "x"}, false, tamper},
		{"Write the policy through a linked directory", "Write", map[string]interface{}{"file_path": filepath.Join(dirLink, "policy.yaml"), "content": "x"}, false, tamper},

		{"apply_patch the log and the policy", "apply_patch", map[string]interface{}{"input": patch("*** Delete File: "+f("audit.jsonl"), "*** Delete File: "+f("policy.yaml"))}, false, both},
		{"apply_patch the policy and an outside file", "apply_patch", map[string]interface{}{"input": patch("*** Delete File: "+f("policy.yaml"), "*** Add File: /tmp/a.txt", "+x")}, false, tamper},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, blocked := managedConfigToolWrite(c.tool, c.args, c.fromText, home)
			if !blocked {
				t.Fatalf("not blocked: the receipt must never move a decision")
			}
			if !containsStr(res.TriggeredRules, "enterprise-self-protect") || !strings.Contains(res.Reasons[0], "(rule: "+selfProtectToolWriteRule+")") {
				t.Fatalf("rules %v reasons %v; want sp-block-config-tool-write", res.TriggeredRules, res.Reasons)
			}
			if !reflect.DeepEqual(res.TaxonomyRefs, c.want) {
				t.Errorf("taxonomy %v, want %v", res.TaxonomyRefs, c.want)
			}
		})
	}
	// The reason still names the first target in the directory.
	res, _ := managedConfigToolWrite("apply_patch", map[string]interface{}{"input": patch("*** Add File: /tmp/a.txt", "+x", "*** Delete File: "+f("policy.yaml"), "*** Delete File: "+f("audit.jsonl"))}, false, home)
	if !strings.Contains(res.Reasons[0], f("policy.yaml")) {
		t.Errorf("reason %q does not name the first target in the directory", res.Reasons[0])
	}
}

// TestHook_ManagedToolWriteToLog_ReceiptCitesAuditTrail: the logged receipt
// of a real hook run, for a Write onto the log and onto the policy.
func TestHook_ManagedToolWriteToLog_ReceiptCitesAuditTrail(t *testing.T) {
	home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
	want := map[string][]string{
		"l1": {spNodeAuditTrail},
		"l2": {spNodeTampering},
	}
	for session, file := range map[string]string{"l1": "audit.jsonl", "l2": "policy.yaml"} {
		p := claudeToolPayload(t, session, "Write", map[string]interface{}{"file_path": asConfigFile(home, file), "content": ""})
		if code, _, stderr := runHookChild(t, home, p); code != 2 {
			t.Fatalf("%s: exit %d, want 2. stderr:\n%s", file, code, stderr)
		}
	}
	seen := map[string]bool{}
	for _, l := range strings.Split(readFailSafeAuditLog(t, configDir), "\n") {
		var e struct {
			SessionID string   `json:"session_id"`
			Decision  string   `json:"decision"`
			Taxonomy  []string `json:"taxonomy"`
		}
		if json.Unmarshal([]byte(l), &e) != nil || want[e.SessionID] == nil {
			continue
		}
		seen[e.SessionID] = true
		if e.Decision != "BLOCK" || !reflect.DeepEqual(e.Taxonomy, want[e.SessionID]) {
			t.Errorf("session %s: decision %s taxonomy %v, want BLOCK %v", e.SessionID, e.Decision, e.Taxonomy, want[e.SessionID])
		}
	}
	if len(seen) != len(want) {
		t.Errorf("found receipts for %v, want %d sessions", seen, len(want))
	}
}
