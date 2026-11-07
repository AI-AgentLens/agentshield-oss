package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
	"github.com/AI-AgentLens/agentshield/internal/datalabel"
)

// #4781: the hook redacts an event once (RedactOnce) and writes the result
// with LogLinkedRedacted. These tests hold that to the line main wrote, with
// a frozen copy of main's LogLinked as the reference.

// legacyLogLinked is LogLinked as it was on main before #4781 (6d6ba507),
// frozen: the degraded note appended, then the event redacted under the
// lock, then hashed and written. Only the comments are dropped.
func legacyLogLinked(l *AuditLogger, event AuditEvent) (*ChainLink, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	release := lockFile(l.lockFd)
	defer release()
	note, degraded := l.LockUnavailableNote()
	if degraded {
		event.Notes = appendNote(event.Notes, note)
		if _, _, err := l.followRotation(); err != nil {
			fmt.Fprintf(os.Stderr, "[AgentShield] warning: audit log reopen failed: %v\n", err)
		}
		if afterDegradedFollow != nil {
			afterDegradedFollow()
		}
	} else if err := l.rotateIfNeeded(); err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: log rotation failed: %v\n", err)
	}
	l.resyncHead()
	event = event.Redacted()
	entry := ChainedEvent{AuditEvent: event, PrevHash: l.prevHash}
	entry.EntryHash = ComputeEntryHash(entry)
	data, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	n, err := l.file.Write(data)
	if err != nil {
		l.knownSize = -1
		return nil, err
	}
	l.knownSize += int64(n)
	link := writtenLink(entry, data)
	l.prevHash = link.LineHash
	if !degraded {
		return link, nil
	}
	return l.reappendIfUnlinked(entry, link)
}

// redactionSecrets are secret-shaped texts, one per redaction pattern
// family, assembled at runtime so the source is not itself a secret.
func redactionSecrets() []string {
	jwt := "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NSJ9" + "." + "dGhpc2lzdGhlc2ln"
	pw := "pw" + "Secret99xyz"
	return []string{
		"export AWS_SECRET_ACCESS_KEY=" + strings.Repeat("Ab1/", 10),
		"echo AKIA" + strings.Repeat("Q7", 8),
		"git push https://x:" + "ghp_" + strings.Repeat("a1", 18) + "@github.com/o/r",
		"curl -H 'Authorization: Bea" + "rer " + jwt + "' https://api.example.com",
		"ps" + "ql postgres://app:" + pw + "@db.internal/stage",
		"my" + "sql --password " + pw + " -h db",
		"curl -u admin:" + pw + " https://x",
		"TOKEN=" + strings.Repeat("t0k", 6) + " ./deploy.sh",
		"export OPENAI_KEY=sk-" + "proj-" + strings.Repeat("Z9", 12),
		"slack xox" + "b-1234567890-1234567890123-abc",
		"cat <<'EOF' > k.pem\n-----BEGIN " + "RSA PRIVATE KEY-----\nMIIabc\n-----END " + "RSA PRIVATE KEY-----\nEOF",
		"echo pass" + "word=" + pw + " >> .env",
		"api_key: " + strings.Repeat("k", 24),
		"PHOENIX launch codes " + pw,
	}
}

// redactionCorpus is real-shaped events for the equivalence tests: every
// command in the analyzer corpus as a shell event (command, args, reasons and
// an error that quote it, notes), the secret-shaped texts in every redacted
// field, MCP events with nested arguments, and events with a data-label
// scrubber.
func redactionCorpus() []AuditEvent {
	shell := func(cmd string) AuditEvent {
		return AuditEvent{
			Timestamp: "2026-11-05T00:00:00Z", Command: cmd, Args: strings.Fields(cmd), Cwd: "/repo",
			Decision: "BLOCK", Flagged: true, TriggeredRules: []string{"rule-a", "content:x"},
			Reasons:      []string{"matched in " + cmd, "AgentShield: analysis failed — blocking (fail_closed enabled): " + cmd},
			TaxonomyRefs: []string{"a/b/c"}, Mode: "managed", Source: "codex-hook", SessionID: "s1", Principal: "u",
			Error: "analysis_budget_exceeded: " + cmd,
			Notes: []Note{{Kind: "analysis_budget_exceeded", Detail: "budget=8.951s; harness=codex"}},
		}
	}
	var out []AuditEvent
	for _, s := range redactionSecrets() {
		out = append(out, shell(s))
		out = append(out, shell(s).WithScrubber(codenameScrub))
		out = append(out, AuditEvent{
			Timestamp: "2026-11-05T00:00:00Z", ToolName: "mcp__fs__write_file", Decision: "AUDIT", Source: "claude-code-mcp-hook",
			MCPArguments: map[string]interface{}{"path": "/repo/x", "content": s, "nested": map[string]interface{}{"list": []interface{}{s, 3.0, true}}},
			Reasons:      []string{"argument scan: " + s},
		})
	}
	for _, tc := range testdata.AllTestCases() {
		out = append(out, shell(tc.Command))
	}
	return out
}

// TestRedactOnce_WritesMainsLine: for every corpus event, LogLinked and
// LogLinkedRedacted(RedactOnce) write byte for byte the line main's LogLinked
// wrote, and return the same chain links, on a healthy logger and on one
// whose lock file cannot be opened (the degraded note is appended after the
// redaction now, before it on main).
func TestRedactOnce_WritesMainsLine(t *testing.T) {
	corpus := redactionCorpus()
	if len(corpus) < 5000 {
		t.Fatalf("corpus has %d events; the analyzer corpus did not load", len(corpus))
	}
	for _, degraded := range []bool{false, true} {
		t.Run(fmt.Sprintf("degraded=%v", degraded), func(t *testing.T) {
			open := func(name string) (*AuditLogger, string) {
				dir := t.TempDir()
				path := filepath.Join(dir, name+".jsonl")
				if degraded {
					if err := os.Mkdir(path+lockSuffix, 0o755); err != nil {
						t.Fatal(err)
					}
				}
				l, err := New(path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = l.Close() })
				if _, d := l.LockUnavailableNote(); d != degraded {
					t.Fatalf("control: lock unavailable %v, want %v", d, degraded)
				}
				return l, path
			}
			legacy, legacyPath := open("legacy")
			linked, linkedPath := open("linked")
			once, oncePath := open("once")
			changed := 0
			for i, e := range corpus {
				if r := e.Redacted(); r.Command != e.Command || r.Error != e.Error {
					changed++
				}
				l1, err1 := legacyLogLinked(legacy, e)
				l2, err2 := linked.LogLinked(e)
				l3, err3 := once.LogLinkedRedacted(e.RedactOnce())
				if err1 != nil || err2 != nil || err3 != nil {
					t.Fatalf("event %d: errors %v / %v / %v", i, err1, err2, err3)
				}
				if *l1 != *l2 || *l1 != *l3 {
					t.Fatalf("event %d: links differ: main %+v, LogLinked %+v, LogLinkedRedacted %+v", i, *l1, *l2, *l3)
				}
			}
			want, _ := os.ReadFile(legacyPath)
			for name, p := range map[string]string{"LogLinked": linkedPath, "LogLinkedRedacted": oncePath} {
				got, _ := os.ReadFile(p)
				if !bytes.Equal(got, want) {
					t.Errorf("%s wrote %d bytes that differ from main's %d", name, len(got), len(want))
				}
			}
			// Positive control: the corpus exercises redaction, so a writer
			// that skipped it, or redacted a field main did not, would differ.
			if changed < 20 {
				t.Fatalf("only %d events had text the redactor changes", changed)
			}
			t.Logf("%d events, %d with redacted text, %d bytes identical", len(corpus), changed, len(want))
		})
	}
}

// TestRedactOnce_NoteAddedAfterRedactionMatchesBefore is the property
// LogLinked's new order relies on. Note details are redacted (#4801), so a
// note added after Redacted() goes through redactNotes. It must then end up
// exactly as it would have if the event had carried it when Redacted() ran,
// with and without a data-label scrubber.
func TestRedactOnce_NoteAddedAfterRedactionMatchesBefore(t *testing.T) {
	secret := "pass" + "word=" + "pw" + "Secret99xyz"
	note := Note{Kind: "k", Rule: "rule-id", Detail: "lock at /x/CUST-104233 near " + secret}
	for _, scrub := range []func(string) []datalabel.Span{nil, fakeScrub} {
		base := AuditEvent{Command: "echo " + secret}
		if scrub != nil {
			base = base.WithScrubber(scrub)
		}
		withNote := base
		withNote.Notes = []Note{note}
		before, _ := json.Marshal(withNote.Redacted())

		r := base.Redacted()
		r.Notes = appendNote(r.Notes, r.redactNotes([]Note{note})[0])
		after, _ := json.Marshal(r)

		if string(before) != string(after) {
			t.Errorf("scrub=%v: note added after redaction differs:\nbefore %s\nafter  %s", scrub != nil, before, after)
		}
		if strings.Contains(string(after), secret) {
			t.Errorf("scrub=%v: the secret survived: %s", scrub != nil, after)
		}
		if scrub != nil && strings.Contains(string(after), "CUST-104233") {
			t.Errorf("the label value survived the scrubber: %s", after)
		}
		if !strings.Contains(string(after), `"rule":"rule-id"`) {
			t.Errorf("scrub=%v: the note's rule changed: %s", scrub != nil, after)
		}
	}
}

// TestRedactOnce_WithNotesStaysRedacted: a RedactedEvent's notes can be
// replaced (the budget's late mark, #4785) and the result is what Redacted()
// gives for the event carrying those notes.
func TestRedactOnce_WithNotesStaysRedacted(t *testing.T) {
	secret := "pass" + "word=" + "pw" + "Secret99xyz"
	e := AuditEvent{Command: "echo " + secret, Args: []string{"echo", secret}, Notes: []Note{{Kind: "a"}}}
	// The replaced note carries the secret too, so a WithNotes that skipped
	// redaction would leave it in the record (#4803's Opus pass, L5).
	r := e.RedactOnce().WithNotes([]Note{{Kind: "a", Detail: "late; " + secret}})
	want := e
	want.Notes = []Note{{Kind: "a", Detail: "late; " + secret}}
	got, _ := json.Marshal(r.Event())
	ref, _ := json.Marshal(want.Redacted())
	if !bytes.Equal(got, ref) {
		t.Fatalf("WithNotes after RedactOnce:\n got %s\nwant %s", got, ref)
	}
	if strings.Contains(string(got), secret) {
		t.Fatal("the secret survived")
	}
}
