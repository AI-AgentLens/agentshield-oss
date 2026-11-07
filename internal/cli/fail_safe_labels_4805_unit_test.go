package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/facts"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Unit tests of #4805's own symbols, kept out of fail_safe_labels_4805_test.go
// so that file still compiles, and runs, on main.

// TestLabelSourceFailures_NeverQuotesTheParseError_4805: the withheld note names
// the source and how it failed, never the YAML error, which quotes the text
// it choked on: in a data_labels block, a label's keyword.
func TestLabelSourceFailures_NeverQuotesTheParseError_4805(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte("data_labels:\n- id: x\n  patterns:\n  - keywords: "+shortKeyword4805()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := policy.LoadDeclaredDataLabels(p, filepath.Join(dir, "packs"))
	if err == nil || !strings.Contains(err.Error(), shortKeyword4805()) {
		t.Fatalf("control: error %v; want a parse error that quotes the keyword", err)
	}
	if got := labelSourceFailures(err); strings.Contains(got, shortKeyword4805()) || !strings.Contains(got, "policy.yaml: data_labels does not parse") {
		t.Errorf("detail %q: want the source and \"data_labels does not parse\", never the keyword", got)
	}
}

// TestWithheldCause_4805: the cause a withheld event records is the file a
// read failed on, in the file system's words; any other failure is
// "(cause withheld)", never its own text and never the labels' failure,
// which is a different read (#4814 item 2).
func TestWithheldCause_4805(t *testing.T) {
	logErr := &fs.PathError{Op: "open", Path: "/h/.agentshield/audit.jsonl", Err: syscall.EACCES}
	packsErr := fmt.Errorf("disk packs directory unreadable: %w", &fs.PathError{Op: "open", Path: "/h/.agentshield/packs", Err: syscall.ENOTDIR})
	for _, c := range []struct {
		err  error
		want string
	}{
		{logErr, "open /h/.agentshield/audit.jsonl: permission denied"},
		{packsErr, "open /h/.agentshield/packs: not a directory"},
		{errors.New("yaml: cannot unmarshal !!str `" + shortKeyword4805() + "` into []string"), "(cause withheld)"},
		{errors.New("data label engine init failed: invalid regex `" + shortKeyword4805() + "(`"), "(cause withheld)"},
	} {
		if got := withheldCause(c.err); got != c.want {
			t.Errorf("withheldCause(%v)\n got %q\nwant %q", c.err, got, c.want)
		}
	}
}

// TestOwnTextNoteKinds_4805: the note kinds a withheld event keeps the detail
// of are the analyzer's and logger's own-text kinds by name, and every other
// kind this binary writes (analyzer, facts) is withheld (#4805 Codex F2).
func TestOwnTextNoteKinds_4805(t *testing.T) {
	own := []string{logger.NoteAgentTextWithheld, logger.NoteAuditLockUnavailable,
		analyzer.NoteAnalysisBudgetExceeded, analyzer.NotePolicyDegraded, analyzer.NoteLaneReadings, analyzer.NoteLateAnswer}
	withheld := []string{analyzer.NoteExcused, analyzer.NoteDowngraded, analyzer.NoteParseFallback,
		analyzer.NoteScopeAlternatesCapped, analyzer.NoteExecutedTextUnresolved, analyzer.NotePayloadCwdUnusable,
		analyzer.NoteRoutingGap, analyzer.NoteDialect, analyzer.NoteNestedDepthExceeded, analyzer.NotePathMention,
		string(facts.NoteParseError), string(facts.NoteDynamicName), string(facts.NoteDynamicNested), string(facts.NoteDecodeFailed)}
	for _, k := range own {
		if !logger.OwnTextNoteKind(k) {
			t.Errorf("%s: its detail is AgentShield's own text, want it kept", k)
		}
	}
	for _, k := range withheld {
		if logger.OwnTextNoteKind(k) {
			t.Errorf("%s: its detail can quote the agent's text, want it withheld", k)
		}
	}
}

// TestRecordLabelsApply_WithheldTextIsTheCause_4805: a withheld event's error
// is withheldCause and its reason states the stage and the decision with
// that cause, never the failure's own text. Only the line carries the error,
// and the stages whose failure names a file the labels do not (audit log
// init) write no line, so this is checked on the redaction itself.
func TestRecordLabelsApply_WithheldTextIsTheCause_4805(t *testing.T) {
	why := "data labels unreadable: /h/.agentshield/packs: not a directory"
	f := evalFailure{stage: "audit log init", err: &fs.PathError{Op: "open", Path: "/h/.agentshield/audit.jsonl", Err: syscall.EACCES}}
	want := "open /h/.agentshield/audit.jsonl: permission denied"
	for _, block := range []bool{true, false} {
		e := logger.AuditEvent{Command: "echo x", Error: f.err.Error(), Reasons: []string{failSafeReason(block, f.stage, f.err.Error())}}
		r := (&recordLabels{withheld: why}).apply(e, f, block).Redacted()
		if r.Error != want || len(r.Reasons) != 1 || r.Reasons[0] != failSafeReason(block, f.stage, want) {
			t.Errorf("block=%v: error %q reasons %q, want %q and its reason", block, r.Error, r.Reasons, want)
		}
	}
}
