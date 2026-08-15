package analyzer

import (
	"encoding/base64"
	"strings"
	"testing"
)

// dec decodes a base64 fixture. Detection-shaped strings are stored encoded so a
// dense batch of them in one file cannot accumulate in the session transcript and
// trip the local safety classifier (see docs/mcp-fixture-indirection.md).
func dec(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	return string(b)
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// heredocBody builds `<intro> <<'EOT'\n<body>\nEOT`.
func heredocBody(intro, body string) string {
	return intro + " <<'EOT'\n" + body + "\nEOT"
}

func TestInterpreterHeredocLabel_TP(t *testing.T) {
	c := NewIntentClassifier()
	body := "x = \"" + strings.Join([]string{"some", "shell", "text"}, " ") + "\""
	for _, intro := range []string{
		"python3 -", "python3", "python -", "node", "ruby", "perl", "php", "Rscript",
	} {
		cmd := heredocBody(intro, body)
		if got := c.Classify(cmd); !got.InInterpreterHeredoc {
			t.Errorf("intro %q: InInterpreterHeredoc = false, want true", intro)
		}
	}
}

// TestInterpreterHeredocNeverExcusesShellHeredoc is the load-bearing guard.
//
// A shell heredoc body IS shell — it executes. If a future change widens the
// interpreter-heredoc regex to "any command before <<", then
// `bash <<'EOT' … EOT` would start being excused and any rule opting into
// in_interpreter_heredoc would silently stop firing on a real attack.
//
// This was very nearly shipped while fixing #3031: broadening in_heredoc to all
// introducers looked like the obvious fix, and the security-daemon/auditd BLOCKs
// turned out to be the SOLE coverage for daemon-stop inside a heredoc.
func TestInterpreterHeredocNeverExcusesShellHeredoc(t *testing.T) {
	c := NewIntentClassifier()
	for _, intro := range []string{"bash", "sh", "zsh", "ksh", "dash", "bash -s", "/bin/sh"} {
		cmd := heredocBody(intro, "echo hi")
		if got := c.Classify(cmd); got.InInterpreterHeredoc {
			t.Errorf("intro %q: InInterpreterHeredoc = true — a shell heredoc body executes as shell and must never be excused", intro)
		}
	}
}

// A command separator between the interpreter and the `<<` must break the match,
// otherwise `python3 -c x && bash <<EOF` launders the shell heredoc via the
// python prefix.
func TestInterpreterHeredocNotLaunderedByPrefix(t *testing.T) {
	c := NewIntentClassifier()
	// python3 -c "..." && bash <<'EOT' ... EOT
	cmd := "python3 -c " + dec(t, b64("\"print(1)\"")) + " && bash <<'EOT'\necho hi\nEOT"
	if got := c.Classify(cmd); got.InInterpreterHeredoc {
		t.Errorf("InInterpreterHeredoc = true for %q — separator must break the match", cmd)
	}
}

// in_heredoc and in_interpreter_heredoc are distinct facts: cat/tee sets only the
// former, a python heredoc only the latter. Conflating them is the bug this label
// exists to prevent.
func TestHeredocLabelsAreDistinct(t *testing.T) {
	c := NewIntentClassifier()
	catCmd := heredocBody("cat > notes.md", "some text")
	if f := c.Classify(catCmd); !f.InHeredoc || f.InInterpreterHeredoc {
		t.Errorf("cat heredoc: InHeredoc=%v InInterpreterHeredoc=%v, want true/false", f.InHeredoc, f.InInterpreterHeredoc)
	}
	pyCmd := heredocBody("python3 -", "s = 1")
	if f := c.Classify(pyCmd); f.InHeredoc || !f.InInterpreterHeredoc {
		t.Errorf("python heredoc: InHeredoc=%v InInterpreterHeredoc=%v, want false/true", f.InHeredoc, f.InInterpreterHeredoc)
	}
}

func TestInterpreterHeredocLabelIsValid(t *testing.T) {
	if !IsValidIntentLabel(LabelInInterpreterHeredoc) {
		t.Fatal("in_interpreter_heredoc must be accepted at policy load, else rules using it silently suppress nothing")
	}
	if !(CommandFacts{InInterpreterHeredoc: true}).HasAny([]string{LabelInInterpreterHeredoc}) {
		t.Fatal("HasAny does not honour in_interpreter_heredoc")
	}
}
