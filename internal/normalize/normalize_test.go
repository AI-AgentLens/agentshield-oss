package normalize

import (
	"os"
	"path/filepath"
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
