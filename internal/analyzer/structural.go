package analyzer

import (
	"fmt"
	"strings"

	"github.com/security-researcher-ca/agentshield/internal/shellparse"
)

// StructuralAnalyzer parses shell commands into an AST using mvdan.cc/sh/v3
// and performs structural checks that regex cannot: flag normalization, pipe
// target analysis, string-literal detection, path classification.
type StructuralAnalyzer struct {
	maxParseDepth int
	checks        []StructuralCheck
	userRules     []StructuralRule // user-defined YAML structural rules
}

// StructuralCheck is a single structural detection rule implemented in Go.
// Each check receives the parsed command and returns zero or more findings.
type StructuralCheck interface {
	Name() string
	Check(parsed *ParsedCommand, raw string) []Finding
}

// NewStructuralAnalyzer creates a structural analyzer with built-in checks.
func NewStructuralAnalyzer(maxParseDepth int) *StructuralAnalyzer {
	if maxParseDepth <= 0 {
		maxParseDepth = 2
	}
	a := &StructuralAnalyzer{
		maxParseDepth: maxParseDepth,
	}
	a.checks = []StructuralCheck{
		&rmRecursiveRootCheck{},
		&rmSystemDirCheck{},
		&ddOutputTargetCheck{},
		&chmodSymbolicCheck{},
		&pipeToShellCheck{},
		&pipeToDangerousTargetCheck{},
	}
	return a
}

func (a *StructuralAnalyzer) Name() string { return "structural" }

// Analyze parses the command into an AST and runs structural checks.
// It enriches ctx.Parsed for downstream analyzers to consume.
// If ctx.Parsed is already set (e.g., by the normalizer), it reuses it.
// SetUserRules attaches user-defined structural rules from YAML packs.
// These are evaluated after built-in Go checks, using the same ParsedCommand.
func (a *StructuralAnalyzer) SetUserRules(rules []StructuralRule) {
	a.userRules = rules
}

func (a *StructuralAnalyzer) Analyze(ctx *AnalysisContext) []Finding {
	if ctx.Parsed == nil {
		ctx.Parsed = a.Parse(ctx.RawCommand)
	}
	parsed := ctx.Parsed

	var findings []Finding

	// 1. Run built-in Go checks (hardcoded detection rules)
	for _, check := range a.checks {
		findings = append(findings, check.Check(parsed, ctx.RawCommand)...)
	}

	// 2. Run user-defined YAML structural rules against the parsed AST
	for _, rule := range a.userRules {
		if MatchStructuralRule(parsed, rule) {
			f := Finding{
				AnalyzerName: "structural",
				RuleID:       rule.ID,
				Decision:     rule.Decision,
				Confidence:   rule.Confidence,
				Reason:       rule.Reason,
				TaxonomyRef:  rule.Taxonomy,
			}
			if f.Confidence == 0 {
				f.Confidence = 0.85 // structural rules are more precise than regex
			}
			findings = append(findings, f)
		}
	}

	return findings
}

// Parse converts a raw command string into a ParsedCommand AST.
// This delegates to shellparse.Parse for the actual parsing.
func (a *StructuralAnalyzer) Parse(command string) *ParsedCommand {
	return shellparse.Parse(command, a.maxParseDepth)
}

// ---------------------------------------------------------------------------
// Built-in structural checks
// ---------------------------------------------------------------------------

// rmRecursiveRootCheck detects rm with recursive+force flags targeting root.
// Fixes: FN-FSDESTR-002 (--recursive --force), FN-FSDESTR-003 (-r -f),
//
//	FN-FSDESTR-004 (rm -rf /*)
type rmRecursiveRootCheck struct{}

func (c *rmRecursiveRootCheck) Name() string { return "rm-recursive-root" }

func (c *rmRecursiveRootCheck) Check(parsed *ParsedCommand, raw string) []Finding {
	if parsed == nil {
		return nil
	}
	var findings []Finding
	for _, seg := range allSegments(parsed) {
		if seg.Executable != "rm" && seg.Executable != "sudo" {
			continue
		}
		exec := seg.Executable
		args := seg.Args
		flags := seg.Flags
		if exec == "sudo" && len(args) > 0 && args[0] == "rm" {
			exec = "rm"
			flags, args = reparseArgsAsFlags(args[1:])
		}
		if exec != "rm" {
			continue
		}

		hasRecursive := hasFlag(flags, "r") || hasFlag(flags, "R") || hasFlag(flags, "recursive")
		hasForce := hasFlag(flags, "f") || hasFlag(flags, "force")

		if !hasRecursive || !hasForce {
			continue
		}

		for _, arg := range args {
			if isRootTarget(arg) {
				findings = append(findings, Finding{
					AnalyzerName: "structural",
					RuleID:       "st-block-rm-recursive-root",
					Decision:     "BLOCK",
					Confidence:   0.95,
					Reason:       fmt.Sprintf("rm with recursive+force flags targeting root path: %s", arg),
					TaxonomyRef:  "destructive-ops/fs-destruction/recursive-root-delete",
					Tags:         []string{"destructive", "critical"},
				})
			}
		}
	}
	return findings
}

// rmSystemDirCheck detects rm with recursive+force targeting system directories.
// Fixes: FN-SYSDIR-004 (--recursive --force /boot)
type rmSystemDirCheck struct{}

func (c *rmSystemDirCheck) Name() string { return "rm-system-dir" }

func (c *rmSystemDirCheck) Check(parsed *ParsedCommand, raw string) []Finding {
	if parsed == nil {
		return nil
	}
	var findings []Finding
	for _, seg := range allSegments(parsed) {
		exec := seg.Executable
		args := seg.Args
		flags := seg.Flags
		if exec == "sudo" && len(args) > 0 && args[0] == "rm" {
			exec = "rm"
			flags, args = reparseArgsAsFlags(args[1:])
		}
		if exec != "rm" {
			continue
		}

		hasRecursive := hasFlag(flags, "r") || hasFlag(flags, "R") || hasFlag(flags, "recursive")
		hasForce := hasFlag(flags, "f") || hasFlag(flags, "force")
		if !hasRecursive || !hasForce {
			continue
		}

		for _, arg := range args {
			if isSystemDir(arg) {
				findings = append(findings, Finding{
					AnalyzerName: "structural",
					RuleID:       "st-block-rm-system-dir",
					Decision:     "BLOCK",
					Confidence:   0.95,
					Reason:       fmt.Sprintf("rm with recursive+force targeting system directory: %s", arg),
					TaxonomyRef:  "destructive-ops/fs-destruction/system-directory-delete",
					Tags:         []string{"destructive", "critical"},
				})
			}
		}
	}
	return findings
}

// ddOutputTargetCheck distinguishes dd writing to block devices (dangerous)
// from dd writing to regular files (benign).
// Fixes: FP-DISKWR-002 (dd if=/dev/zero of=./test.img)
type ddOutputTargetCheck struct{}

func (c *ddOutputTargetCheck) Name() string { return "dd-output-target" }

func (c *ddOutputTargetCheck) Check(parsed *ParsedCommand, raw string) []Finding {
	if parsed == nil {
		return nil
	}
	var findings []Finding
	for _, seg := range allSegments(parsed) {
		exec := seg.Executable
		if exec == "sudo" && len(seg.Args) > 0 && seg.Args[0] == "dd" {
			exec = "dd"
		}
		if exec != "dd" {
			continue
		}

		var ifPath, ofPath string
		allWords := append([]string{}, seg.Args...)
		for k, v := range seg.Flags {
			if v != "" {
				allWords = append(allWords, k+"="+v)
			}
		}
		for _, w := range allWords {
			if strings.HasPrefix(w, "if=") {
				ifPath = w[3:]
			} else if strings.HasPrefix(w, "of=") {
				ofPath = w[3:]
			}
		}

		hasDangerousInput := strings.HasPrefix(ifPath, "/dev/zero") ||
			strings.HasPrefix(ifPath, "/dev/urandom") ||
			strings.HasPrefix(ifPath, "/dev/random")

		if hasDangerousInput && ofPath != "" && !isBlockDevice(ofPath) {
			findings = append(findings, Finding{
				AnalyzerName: "structural",
				RuleID:       "st-allow-dd-to-file",
				Decision:     "ALLOW",
				Confidence:   0.90,
				Reason:       fmt.Sprintf("dd from %s to regular file %s (not a block device)", ifPath, ofPath),
				TaxonomyRef:  "destructive-ops/disk-ops/disk-overwrite",
				Tags:         []string{"structural-override"},
			})
		}
	}
	return findings
}

// chmodSymbolicCheck detects chmod a+rwx (equivalent to 777) on system paths.
// Fixes: FN-CHMOD-001 (chmod a+rwx /etc/passwd)
type chmodSymbolicCheck struct{}

func (c *chmodSymbolicCheck) Name() string { return "chmod-symbolic" }

func (c *chmodSymbolicCheck) Check(parsed *ParsedCommand, raw string) []Finding {
	if parsed == nil {
		return nil
	}
	var findings []Finding
	for _, seg := range allSegments(parsed) {
		exec := seg.Executable
		args := seg.Args
		if exec == "sudo" && len(args) > 0 && args[0] == "chmod" {
			exec = "chmod"
			args = args[1:]
		}
		if exec != "chmod" {
			continue
		}

		for i, arg := range args {
			if isWorldWritableSymbolic(arg) {
				for _, pathArg := range args[i+1:] {
					if isSystemPath(pathArg) {
						findings = append(findings, Finding{
							AnalyzerName: "structural",
							RuleID:       "st-block-chmod-world-writable",
							Decision:     "BLOCK",
							Confidence:   0.90,
							Reason:       fmt.Sprintf("chmod %s on system path %s (equivalent to 777)", arg, pathArg),
							TaxonomyRef:  "destructive-ops/permission-weakening/chmod-world-writable",
							Tags:         []string{"permission-weakening", "critical"},
						})
					}
				}
			}
		}
	}
	return findings
}

// pipeToShellCheck detects download-pipe-to-interpreter patterns.
// Catches python3, node, ruby, perl as pipe targets (regex only catches sh/bash/zsh).
// Fixes: FN-PIPESH-005 (curl ... | python3 -)
type pipeToShellCheck struct{}

func (c *pipeToShellCheck) Name() string { return "pipe-to-shell" }

func (c *pipeToShellCheck) Check(parsed *ParsedCommand, raw string) []Finding {
	if parsed == nil || len(parsed.Segments) < 2 {
		return nil
	}
	var findings []Finding
	for i := 0; i < len(parsed.Segments)-1; i++ {
		left := parsed.Segments[i]
		right := parsed.Segments[i+1]

		isDownload := isDownloadCommand(left.Executable)
		isPipe := i < len(parsed.Operators) && parsed.Operators[i] == "|"
		isInterpreter := isShellOrInterpreter(right.Executable)

		if isDownload && isPipe && isInterpreter {
			findings = append(findings, Finding{
				AnalyzerName: "structural",
				RuleID:       "st-block-pipe-to-interpreter",
				Decision:     "BLOCK",
				Confidence:   0.95,
				Reason: fmt.Sprintf("Download (%s) piped to interpreter (%s). "+
					"Download and inspect first.", left.Executable, right.Executable),
				TaxonomyRef: "unauthorized-execution/remote-code-exec/pipe-to-shell",
				Tags:        []string{"code-execution", "critical"},
			})
		}
	}
	return findings
}

// pipeToDangerousTargetCheck detects piping into dangerous commands (crontab, etc.)
// Fixes: FP-CRON-002 (echo "..." | crontab -)
type pipeToDangerousTargetCheck struct{}

func (c *pipeToDangerousTargetCheck) Name() string { return "pipe-to-dangerous-target" }

func (c *pipeToDangerousTargetCheck) Check(parsed *ParsedCommand, raw string) []Finding {
	if parsed == nil || len(parsed.Segments) < 2 {
		return nil
	}
	var findings []Finding
	for i := 0; i < len(parsed.Segments)-1; i++ {
		right := parsed.Segments[i+1]
		isPipe := i < len(parsed.Operators) && parsed.Operators[i] == "|"
		if !isPipe {
			continue
		}
		if isDangerousPipeTarget(right.Executable) {
			findings = append(findings, Finding{
				AnalyzerName: "structural",
				RuleID:       "st-audit-pipe-to-dangerous",
				Decision:     "AUDIT",
				Confidence:   0.85,
				Reason:       fmt.Sprintf("Pipe to %s — may modify system state via stdin", right.Executable),
				Tags:         []string{"pipe-target"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Helper functions (analyzer-specific, not shared with shellparse)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Thin wrappers for shellparse functions — keeps existing analyzer code
// (semantic.go, stateful.go, structural_rule.go) compiling without changes.
// ---------------------------------------------------------------------------

func allSegments(parsed *ParsedCommand) []CommandSegment {
	return shellparse.AllSegments(parsed)
}

func reparseArgsAsFlags(words []string) (map[string]string, []string) {
	return shellparse.ReparseArgsAsFlags(words)
}

func isShellOrInterpreter(exe string) bool { return shellparse.IsShellOrInterpreter(exe) }
func isDownloadCommand(exe string) bool    { return shellparse.IsDownloadCommand(exe) }
func isDangerousPipeTarget(exe string) bool { return shellparse.IsDangerousPipeTarget(exe) }

// hasFlag checks if a flag key exists in the flags map.
func hasFlag(flags map[string]string, key string) bool {
	_, ok := flags[key]
	return ok
}

func isRootTarget(path string) bool {
	cleaned := strings.TrimRight(path, "/")
	return cleaned == "" || cleaned == "/" || path == "/*"
}

var systemDirs = map[string]bool{
	"/etc": true, "/usr": true, "/usr/local": true, "/var": true,
	"/boot": true, "/sys": true, "/proc": true, "/lib": true,
	"/lib64": true, "/sbin": true, "/bin": true, "/opt": true,
	"/var/log": true, "/usr/bin": true, "/usr/lib": true,
}

func isSystemDir(path string) bool {
	cleaned := strings.TrimRight(path, "/")
	return systemDirs[cleaned]
}

func isSystemPath(path string) bool {
	if isSystemDir(path) {
		return true
	}
	for dir := range systemDirs {
		if strings.HasPrefix(path, dir+"/") {
			return true
		}
	}
	return path == "/" || path == "/*"
}

func isBlockDevice(path string) bool {
	return strings.HasPrefix(path, "/dev/sd") ||
		strings.HasPrefix(path, "/dev/hd") ||
		strings.HasPrefix(path, "/dev/nvme") ||
		strings.HasPrefix(path, "/dev/vd") ||
		strings.HasPrefix(path, "/dev/xvd") ||
		strings.HasPrefix(path, "/dev/md") ||
		strings.HasPrefix(path, "/dev/dm-") ||
		strings.HasPrefix(path, "/dev/loop")
}

func isWorldWritableSymbolic(mode string) bool {
	mode = strings.ToLower(mode)
	if mode == "777" || mode == "0777" {
		return true
	}
	if strings.Contains(mode, "a+") && strings.Contains(mode, "w") {
		return true
	}
	if strings.Contains(mode, "o+") && strings.Contains(mode, "w") {
		return true
	}
	if strings.HasPrefix(mode, "+") && strings.Contains(mode, "w") {
		return true
	}
	return false
}
