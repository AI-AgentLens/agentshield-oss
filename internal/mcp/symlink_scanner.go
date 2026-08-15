package mcp

import (
	"os"
	"path/filepath"
)

// SymlinkEscapeFinding records one filesystem tool call whose declared path
// argument is a symlink resolving to a location that diverges from what the
// declared string implies.
type SymlinkEscapeFinding struct {
	// ArgName is the argument key containing the symlink (e.g., "path", "source").
	ArgName string
	// DeclaredPath is the raw path argument value the caller supplied — the
	// string an approval dialog would display.
	DeclaredPath string
	// ResolvedPath is the real target after following the full symlink chain.
	ResolvedPath string
	// Detail is a human-readable description of why the resolved target matters.
	Detail string
}

// SymlinkEscapeResult is the result of a GhostApproval-class symlink scan.
type SymlinkEscapeResult struct {
	// Blocked is true when a declared path resolves (through symlinks) to a
	// credential/secrets file.
	Blocked bool
	// Audited is true when a declared path resolves to a system directory
	// outside the workspace, without any finding matching the Blocked tier.
	Audited  bool
	Findings []SymlinkEscapeFinding
}

// symlinkCredentialTargetPatterns are glob patterns (matched against the
// fully resolved, symlink-followed target — never the declared string)
// naming credential/secrets files. A symlink resolving to one of these is
// blocked regardless of how benign the declared path argument looks.
var symlinkCredentialTargetPatterns = []string{
	"**/.ssh/**",
	"**/.aws/**",
	"**/.gnupg/**",
	"**/.kube/**",
	"**/.docker/config.json",
	"**/.npmrc",
	"**/.pypirc",
	"**/.netrc",
	"/etc/shadow",
	"/etc/passwd",
	"**/id_rsa",
	"**/id_ed25519",
	"**/id_ecdsa",
	"**/*.pem",
}

// symlinkSystemTargetPatterns are broader system-directory glob patterns.
// Audited rather than blocked — some legitimate tooling reads system paths
// (e.g. inspecting an installed package under /usr or /opt), and this list
// deliberately excludes /opt for that reason.
var symlinkSystemTargetPatterns = []string{
	"/etc/**",
	"/usr/**",
	"/var/**",
	"/root/**",
	"/sys/**",
	"/proc/**",
}

// ScanFilesystemSymlinkEscape resolves symlinks in the declared path
// arguments of MCP filesystem tool calls and flags cases where the resolved
// target diverges from the declared, benign-looking path into a credential
// file or system directory.
//
// This is the GhostApproval trust-boundary gap (CVE-2026-12958, Wiz Research,
// disclosed July 2026, reproduced across six coding agents including Claude
// Code, Cursor, and Windsurf): a repository plants a symlink so an approval
// dialog displays a benign in-workspace-looking path (e.g. config/settings.json)
// while the underlying read_file/write_file call actually resolves to a
// different target (/etc/passwd, ~/.ssh/id_rsa). The dialog shows the
// declared string, never the resolved target.
//
// Scoped to the same tool set and argument keys as ScanFilesystemPathTraversal
// and ScanFilesystemSchemeHijack (read_file, write_file, create_directory,
// list_directory, move_file, copy_file, create_symlink, and camelCase
// aliases; path/source/destination/target/src/dst argument keys).
//
// Non-existent declared paths (e.g. write_file creating a brand-new file)
// and regular files/directories are not findings — there is nothing to
// escape through yet. Only an EXISTING symlink at the declared path, whose
// resolved target lands in a credential file or system directory, triggers
// a finding.
//
// Known limitation: this check runs once, at evaluation time, against the
// filesystem AgentShield itself can see. It cannot close a TOCTOU window
// where the symlink is swapped after evaluation but before the downstream
// MCP server performs the actual I/O — AgentShield mediates the call, it
// does not perform the file operation itself.
func ScanFilesystemSymlinkEscape(toolName string, arguments map[string]interface{}) SymlinkEscapeResult {
	var result SymlinkEscapeResult

	if !filesystemToolNames[toolName] {
		return result
	}

	for argName, argValue := range arguments {
		if !filesystemPathArgNames[argName] {
			continue
		}
		declared, ok := argValue.(string)
		if !ok || declared == "" {
			continue
		}

		resolved, isSymlink := resolveSymlinkTarget(declared)
		if !isSymlink {
			continue
		}

		if matchesAnyGlob(resolved, symlinkCredentialTargetPatterns) {
			result.Blocked = true
			result.Findings = append(result.Findings, SymlinkEscapeFinding{
				ArgName:      argName,
				DeclaredPath: declared,
				ResolvedPath: resolved,
				Detail:       "symlink target is a credential/secrets file",
			})
			continue
		}

		if matchesAnyGlob(resolved, symlinkSystemTargetPatterns) {
			if !result.Blocked {
				result.Audited = true
			}
			result.Findings = append(result.Findings, SymlinkEscapeFinding{
				ArgName:      argName,
				DeclaredPath: declared,
				ResolvedPath: resolved,
				Detail:       "symlink target is a system directory outside the workspace",
			})
		}
	}

	return result
}

// resolveSymlinkTarget Lstat's the declared path (after ~ expansion); if it
// is a symlink, it resolves the full chain via filepath.EvalSymlinks.
// Returns ("", false) for non-existent paths (nothing to write yet — not a
// symlink attack) and for regular files/directories (the declared path IS
// the real path, so there is no divergence to flag).
func resolveSymlinkTarget(declared string) (string, bool) {
	expanded := expandHome(declared)
	info, err := os.Lstat(expanded)
	if err != nil {
		return "", false
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(expanded)
	if err != nil {
		return "", false
	}
	return resolved, true
}

// matchesAnyGlob reports whether value matches any of the given glob
// patterns, reusing the same matchGlob engine (filepath.Match + "**"
// doublestar support) that argument_patterns rules use in policy.go.
func matchesAnyGlob(value string, patterns []string) bool {
	for _, p := range patterns {
		if matchGlob(value, p) {
			return true
		}
	}
	return false
}
