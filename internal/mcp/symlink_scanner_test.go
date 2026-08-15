package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shortSymlinkTestDir creates a short-named temp directory (fully symlink-
// resolved, e.g. macOS's /tmp -> /private/tmp) for symlink-scanner tests.
// Two things matter here that t.TempDir() doesn't give us:
//  1. A short path — t.TempDir() embeds the full test name plus a counter,
//     easily exceeding 100 characters, which trips the unrelated
//     high-entropy content scanner (isHighEntropy fires on any single
//     "word" >= 100 chars) when the path is used as a live tool-call
//     argument in an end-to-end test.
//  2. A fully symlink-resolved root — so a path built from it already
//     equals what filepath.EvalSymlinks(declaredSymlink) will report,
//     letting tests assert exact resolved-path equality.
func shortSymlinkTestDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "as-ga")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	return resolved
}

// TestHandleToolCall_SymlinkEscape_BlocksEndToEnd drives the full live proxy
// entry point (HandleToolCall) to prove a GhostApproval-class symlink escape
// is blocked on the real tools/call path an IDE hook exercises. The declared
// path looks like an ordinary in-workspace config file; it is actually a
// symlink resolving to a credential file.
func TestHandleToolCall_SymlinkEscape_BlocksEndToEnd(t *testing.T) {
	dir := shortSymlinkTestDir(t)
	sshDir := filepath.Join(dir, ".ssh")
	if err := os.Mkdir(sshDir, 0o755); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	privateKey := filepath.Join(sshDir, "id_rsa")
	if err := os.WriteFile(privateKey, []byte("fake-private-key"), 0o600); err != nil {
		t.Fatalf("write id_rsa: %v", err)
	}
	declaredPath := filepath.Join(dir, "config", "settings.json")
	if err := os.MkdirAll(filepath.Dir(declaredPath), 0o755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	if err := os.Symlink(privateKey, declaredPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	h, buf := newHintTestHandler() // default-AUDIT policy; write_file is not pre-blocked

	msg := &Message{
		JSONRPC: "2.0",
		ID:      mustRequestID(t),
		Method:  MethodToolsCall,
		Params: mustMarshal(t, CallToolParams{
			Name: "write_file",
			Arguments: map[string]interface{}{
				"path":    declaredPath,
				"content": "{}",
			},
		}),
	}

	blocked, _ := h.HandleToolCall(msg)
	if !blocked {
		t.Fatal("write_file whose declared path is a symlink to ~/.ssh/id_rsa must be BLOCKED on the live HandleToolCall path")
	}
	out := buf.String()
	if !strings.Contains(out, "symlink escape") {
		t.Errorf("expected symlink escape block reason in stderr, got:\n%s", out)
	}
	if !strings.Contains(out, privateKey) {
		t.Errorf("expected resolved target %q in stderr, got:\n%s", privateKey, out)
	}
}

// ScanFilesystemSymlinkEscape — a declared path that is an existing symlink
// resolving to a credential file or system directory must be flagged even
// though the declared string looks benign. Non-symlinks, non-existent
// paths, and in-workspace symlink targets must never be flagged.

func TestSymlinkEscape_BlocksSymlinkToSSHKey(t *testing.T) {
	dir := shortSymlinkTestDir(t)
	sshDir := filepath.Join(dir, ".ssh")
	_ = os.Mkdir(sshDir, 0o755)
	target := filepath.Join(sshDir, "id_rsa")
	_ = os.WriteFile(target, []byte("key"), 0o600)

	declared := filepath.Join(dir, "notes.txt")
	if err := os.Symlink(target, declared); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	res := ScanFilesystemSymlinkEscape("read_file", map[string]interface{}{"path": declared})
	if !res.Blocked {
		t.Fatalf("read_file(path=%q) symlinked to an SSH key must block: %+v", declared, res.Findings)
	}
	if res.Findings[0].ResolvedPath != target {
		t.Errorf("expected resolved path %q, got %q", target, res.Findings[0].ResolvedPath)
	}
}

func TestSymlinkEscape_BlocksSymlinkToAWSCredentials(t *testing.T) {
	dir := shortSymlinkTestDir(t)
	awsDir := filepath.Join(dir, ".aws")
	_ = os.Mkdir(awsDir, 0o755)
	target := filepath.Join(awsDir, "credentials")
	_ = os.WriteFile(target, []byte("[default]\naws_access_key_id=AKIA"), 0o600)

	declared := filepath.Join(dir, "docs", "readme_link.md")
	_ = os.MkdirAll(filepath.Dir(declared), 0o755)
	if err := os.Symlink(target, declared); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	res := ScanFilesystemSymlinkEscape("read_file", map[string]interface{}{"path": declared})
	if !res.Blocked {
		t.Fatalf("read_file(path=%q) symlinked to AWS credentials must block: %+v", declared, res.Findings)
	}
}

func TestSymlinkEscape_TN_RegularFileNotSymlink(t *testing.T) {
	dir := shortSymlinkTestDir(t)
	// A file literally named id_rsa but NOT a symlink — GhostApproval requires
	// declared/resolved divergence via a symlink; a plain credential-named
	// file is a different (already-covered) threat class.
	declared := filepath.Join(dir, "id_rsa")
	_ = os.WriteFile(declared, []byte("not a symlink"), 0o600)

	res := ScanFilesystemSymlinkEscape("write_file", map[string]interface{}{"path": declared})
	if res.Blocked || res.Audited {
		t.Fatalf("a regular file (not a symlink) must never be flagged: %+v", res.Findings)
	}
}

func TestSymlinkEscape_TN_SymlinkWithinWorkspace(t *testing.T) {
	dir := shortSymlinkTestDir(t)
	target := filepath.Join(dir, "src", "utils.js")
	_ = os.MkdirAll(filepath.Dir(target), 0o755)
	_ = os.WriteFile(target, []byte("export const x = 1;"), 0o644)

	declared := filepath.Join(dir, "src", "utils-link.js")
	if err := os.Symlink(target, declared); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	res := ScanFilesystemSymlinkEscape("read_file", map[string]interface{}{"path": declared})
	if res.Blocked || res.Audited {
		t.Fatalf("a symlink resolving to another in-workspace file must not be flagged: %+v", res.Findings)
	}
}

func TestSymlinkEscape_TN_NonExistentPath(t *testing.T) {
	dir := shortSymlinkTestDir(t)
	declared := filepath.Join(dir, "brand-new-file.txt")

	res := ScanFilesystemSymlinkEscape("write_file", map[string]interface{}{"path": declared})
	if res.Blocked || res.Audited {
		t.Fatalf("write_file creating a brand-new file must not be flagged: %+v", res.Findings)
	}
}

func TestSymlinkEscape_TN_BrokenSymlink(t *testing.T) {
	dir := shortSymlinkTestDir(t)
	declared := filepath.Join(dir, "dangling-link")
	if err := os.Symlink(filepath.Join(dir, "does-not-exist"), declared); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	res := ScanFilesystemSymlinkEscape("read_file", map[string]interface{}{"path": declared})
	if res.Blocked || res.Audited {
		t.Fatalf("a broken symlink (unresolvable target) must fail safe, not block: %+v", res.Findings)
	}
}

func TestSymlinkEscape_TN_NonFilesystemToolNotScanned(t *testing.T) {
	dir := shortSymlinkTestDir(t)
	sshDir := filepath.Join(dir, ".ssh")
	_ = os.Mkdir(sshDir, 0o755)
	target := filepath.Join(sshDir, "id_rsa")
	_ = os.WriteFile(target, []byte("key"), 0o600)

	declared := filepath.Join(dir, "notes.txt")
	_ = os.Symlink(target, declared)

	// execute_code is not a filesystem tool — out of scope for this scanner
	// (its own rule families govern code execution).
	res := ScanFilesystemSymlinkEscape("execute_code", map[string]interface{}{"path": declared})
	if res.Blocked || res.Audited {
		t.Fatalf("non-filesystem tool must not be scanned: %+v", res.Findings)
	}
}

func TestSymlinkEscape_TN_NonPathArgIgnored(t *testing.T) {
	dir := shortSymlinkTestDir(t)
	sshDir := filepath.Join(dir, ".ssh")
	_ = os.Mkdir(sshDir, 0o755)
	target := filepath.Join(sshDir, "id_rsa")
	_ = os.WriteFile(target, []byte("key"), 0o600)

	declared := filepath.Join(dir, "notes.txt")
	_ = os.Symlink(target, declared)

	// The symlink lives in a non-path argument key — out of scope.
	res := ScanFilesystemSymlinkEscape("read_file", map[string]interface{}{
		"path":         filepath.Join(dir, "safe.txt"),
		"related_note": declared,
	})
	if res.Blocked || res.Audited {
		t.Fatalf("symlink in a non-path argument key must not be flagged: %+v", res.Findings)
	}
}

// matchesAnyGlob / symlinkSystemTargetPatterns coverage — validated against
// representative resolved absolute paths directly rather than via real
// filesystem symlinks into system roots, since /etc, /var, and /tmp are
// themselves symlinks on macOS (e.g. /etc -> /private/etc), which would make
// filesystem-backed assertions of the literal anchored prefix flaky across
// platforms. The glob engine itself (matchGlob) already has its own tests;
// this only confirms the pattern *lists* used by this scanner are correct.
func TestSymlinkEscape_SystemTargetPatterns(t *testing.T) {
	blocked := []string{
		"/etc/nginx/nginx.conf",
		"/etc/shadow",
		"/usr/local/bin/backdoor",
		"/var/log/auth.log",
		"/root/.bashrc",
		"/sys/kernel/debug/x",
		"/proc/1/environ",
	}
	for _, p := range blocked {
		if !matchesAnyGlob(p, symlinkSystemTargetPatterns) {
			t.Errorf("expected %q to match a system target pattern", p)
		}
	}

	safe := []string{
		"/opt/homebrew/bin/node", // deliberately excluded — legitimate package inspection
		"/workspace/project/src/main.go",
		"/home/dev/repo/README.md",
	}
	for _, p := range safe {
		if matchesAnyGlob(p, symlinkSystemTargetPatterns) {
			t.Errorf("expected %q to NOT match a system target pattern", p)
		}
	}
}

func TestSymlinkEscape_CredentialTargetPatterns(t *testing.T) {
	blocked := []string{
		"/home/dev/.ssh/id_rsa",
		"/Users/dev/.aws/credentials",
		"/home/dev/.gnupg/private-keys-v1.d/ABCD.key",
		"/home/dev/.kube/config",
		"/home/dev/.docker/config.json",
		"/home/dev/.npmrc",
		"/home/dev/.pypirc",
		"/home/dev/.netrc",
		"/etc/shadow",
		"/etc/passwd",
		"/home/dev/.ssh/id_ed25519",
		"/home/dev/certs/server.pem",
	}
	for _, p := range blocked {
		if !matchesAnyGlob(p, symlinkCredentialTargetPatterns) {
			t.Errorf("expected %q to match a credential target pattern", p)
		}
	}

	safe := []string{
		// Note: .ssh/id_rsa.pub (a public key) DOES match **/.ssh/** here —
		// consistent with this codebase's existing protected_paths convention
		// (~/.ssh/** as a whole is treated as sensitive, not just private
		// key files), so it is intentionally not listed as a safe case.
		"/workspace/project/src/main.go",
		"/home/dev/.config/app/settings.json",
	}
	for _, p := range safe {
		if matchesAnyGlob(p, symlinkCredentialTargetPatterns) {
			t.Errorf("expected %q to NOT match a credential target pattern", p)
		}
	}
}
