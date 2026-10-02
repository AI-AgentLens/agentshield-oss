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

// #3970: an interpreter given a script-file operand, or the value of a
// code-carrying flag (-c/-e/-m/...), never reads a trailing HERE-STRING as
// its program — the label must be withdrawn for that shape, same reasoning
// as #3964's cat fix.
func TestInterpreterHeredocLabel_WithdrawnWithOperand(t *testing.T) {
	c := NewIntentClassifier()
	for _, intro := range []string{
		"python3 backup.py", "python3 -u backup.py", "node app.js", "ruby backup.rb",
		"perl backup.pl", "php backup.php", "Rscript backup.R", "osascript backup.scpt",
	} {
		cmd := intro + " <<< x"
		if got := c.Classify(cmd); got.InInterpreterHeredoc {
			t.Errorf("intro %q: InInterpreterHeredoc = true, want false — a script-file operand means the interpreter never reads the here-string", intro)
		}
	}
	// Live regression for #3970's own reproduction: the whole statement,
	// including sensitive text in the interpreter's own argv, must not be
	// excused just because a trailing here-string sits after it.
	herestring := "python3 backup.py -c ~/.ssh/id_rsa <<< x"
	if got := c.Classify(herestring); got.InInterpreterHeredoc {
		t.Errorf("InInterpreterHeredoc = true for %q, want false", herestring)
	}
}

// A multi-line HEREDOC body (not a here-string) is deliberately left alone
// even with the identical operand present — ts-block-authorized-keys-
// write's FP-fix (#3540) relies on the body being treated as source-code
// text regardless of whether the interpreter actually reads it from stdin.
// This is the regression guard for the narrower #3970 fix.
func TestInterpreterHeredocLabel_NotWithdrawnForRealHeredocBody(t *testing.T) {
	c := NewIntentClassifier()
	body := "x = \"" + strings.Join([]string{"some", "shell", "text"}, " ") + "\""
	for _, intro := range []string{
		"python3 backup.py", "python3 -u backup.py", "node app.js", "ruby backup.rb",
		"perl backup.pl", "php backup.php", "Rscript backup.R", "osascript backup.scpt",
	} {
		cmd := heredocBody(intro, body)
		if got := c.Classify(cmd); !got.InInterpreterHeredoc {
			t.Errorf("intro %q: InInterpreterHeredoc = false, want true — a real heredoc BODY stays excused regardless of the interpreter's operand", intro)
		}
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
