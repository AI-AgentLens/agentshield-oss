package analyzer

import "testing"

// #4455: interp_heredoc_literal now excuses the audit-log rules for an inert
// interpreter heredoc, so "inert" must not admit a body that opens
// AgentShield's own state. Otherwise a decoy literal that main BLOCKs on, plus
// a real truncation main never sees, decides AUDIT (Codex pass 1 on #4455).
func TestInterpInertRefusesAgentShieldDestination(t *testing.T) {
	refused := []struct{ name, lang, body string }{
		{"open-write", "python3", "open('/Users/x/.agentshield/audit.jsonl', 'w').write('')"},
		{"decoy-then-open-write", "python3", "note = '<span>~/.agentshield/audit.jsonl</span>'\nopen('/Users/x/.agentshield/audit.jsonl', 'w').write('')"},
		{"open-append-relative", "python3", "open('.agentshield/audit.jsonl', 'a').write('x')"},
		{"case-folded-dir", "python3", "open('/Users/x/.AgentShield/audit.jsonl', 'w').write('')"},
		{"through-variable", "python3", "p = '/Users/x/.agentshield/audit.jsonl'\nopen(p, 'w').write('')"},
		{"path-write-text", "python3", "from pathlib import Path\nPath('/Users/x/.agentshield/audit.jsonl').write_text('')"},
		{"node-write", "node", "const fs = require('fs');\nfs.writeFileSync('/Users/x/.agentshield/audit.jsonl', '');"},
	}
	for _, tc := range refused {
		t.Run("refused/"+tc.name, func(t *testing.T) {
			if closedInertBody(tc.lang, tc.body) {
				t.Fatal("a body that opens AgentShield's state directory was accepted as inert")
			}
		})
	}

	// Controls: the issue's own body, and a path that only resembles the
	// directory, stay inert, so the check is not a blanket refusal.
	accepted := []struct{ name, body string }{
		{"issue-4455-repro", "p = 'index.html'\ns = open(p).read()\ns = s.replace('x', '<span>~/.agentshield/audit.jsonl</span>')\nopen(p, 'w').write(s)"},
		{"lookalike-dir", "open('/Users/x/agentshield-notes/audit.jsonl', 'w').write('')"},
	}
	for _, tc := range accepted {
		t.Run("accepted/"+tc.name, func(t *testing.T) {
			if !closedInertBody("python3", tc.body) {
				t.Fatal("control body rejected; the check is broader than AgentShield's state directory")
			}
		})
	}
}
