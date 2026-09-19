package shellparse

import (
	"strings"
	"testing"
)

// TestDequoteCompoundWordPositionParity is the fitness function for the walker
// gap: every obfuscation DequoteCommand repairs in ordinary argument position
// must also be repaired when the same word sits in a compound node's word list.
//
// The matrix is (obfuscation form) x (word position). Each row asserts its
// CallExpr CONTROL first — a position row whose control does not fold is NOT
// MEASURED rather than clean, which is how a previous parity sweep in this repo
// reported false coverage.
func TestDequoteCompoundWordPositionParity(t *testing.T) {
	forms := []struct {
		name    string
		spliced string // the obfuscated word
		want    string // what it must fold to
	}{
		{"quote-splice", `/et'c'/shadow`, "/etc/shadow"},
		{"dquote-splice", `/et"c"/shadow`, "/etc/shadow"},
		{"ansic-hex-single", `$'\x2f'etc/shadow`, "/etc/shadow"},
		{"backslash-splice", `/et\c/shadow`, "/etc/shadow"},
	}

	positions := []struct {
		name string
		tmpl string // %s is the word
	}{
		{"CONTROL-callexpr", `cat %s`},
		{"for-wordlist", `for p in %s; do cat "$p"; done`},
		{"select-wordlist", `select p in %s; do cat "$p"; done`},
		{"array-literal", `zf=(%s); cat "${zf[0]}"`},
		{"declare-array", `declare -a zf=(%s); cat "${zf[0]}"`},
	}

	for _, f := range forms {
		f := f
		t.Run(f.name, func(t *testing.T) {
			control := DequoteCommand(strings.Replace(positions[0].tmpl, "%s", f.spliced, 1))
			if !strings.Contains(control, f.want) {
				t.Fatalf("CONTROL did not fold %s in argument position: got %q, want it to contain %q\n"+
					"a matrix whose control is silent measures nothing", f.name, control, f.want)
			}
			for _, p := range positions[1:] {
				got := DequoteCommand(strings.Replace(p.tmpl, "%s", f.spliced, 1))
				if !strings.Contains(got, f.want) {
					t.Errorf("%s: DequoteCommand(%q) = %q, want it to contain %q",
						p.name, strings.Replace(p.tmpl, "%s", f.spliced, 1), got, f.want)
				}
			}
		})
	}
}

// TestDequoteCompoundWordPositionFPBoundary pins the shapes the 2+-parts splice
// guard must keep leaving alone now that the walk reaches more positions. A
// whole-argument quote is ordinary bash, and stripping it would defeat the
// command_regex_exclude heuristics that key on "a quote follows this flag".
func TestDequoteCompoundWordPositionFPBoundary(t *testing.T) {
	untouched := []string{
		`for f in *.log; do gzip "$f"; done`,
		`for m in "fix: don't panic" "chore: bump deps"; do git commit -m "$m"; done`,
		`opts=(--color=auto -lh); ls "${opts[@]}" /tmp`,
		`files=("$SRC_DIR"/*.go); gofmt -l "${files[@]}"`,
		`for d in "$HOME/build" "$HOME/dist"; do rm -rf "$d"; done`,
	}
	for _, cmd := range untouched {
		if got := DequoteCommand(cmd); got != "" {
			t.Errorf("DequoteCommand(%q) rewrote to %q, want the \"\" no-op sentinel", cmd, got)
		}
	}
}

// TestDequoteLeavesCasePatternsAlone pins the deliberate exclusion. A case
// pattern is a glob matched against a subject, not a value handed to a command,
// and quoting is semantically load-bearing there ('*' quoted is a literal
// asterisk) — so folding it would invent a match form no shell produces.
func TestDequoteLeavesCasePatternsAlone(t *testing.T) {
	cmd := `case "$f" in /et'c'/shadow) echo hit;; esac`
	if got := DequoteCommand(cmd); got != "" {
		t.Errorf("DequoteCommand(%q) = %q, want case patterns left untouched", cmd, got)
	}
}
