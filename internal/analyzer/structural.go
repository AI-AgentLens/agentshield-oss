package analyzer

import (
	"fmt"
	"path"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
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
		if cc, ok := check.(cwdAwareCheck); ok {
			findings = append(findings, cc.CheckInCwd(parsed, ctx.RawCommand, ctx.Cwd)...)
			continue
		}
		findings = append(findings, check.Check(parsed, ctx.RawCommand)...)
	}
	// A command word spelled as a path (#3991): re-run the checks against the
	// program-name view and keep only RESTRICTING findings that are new.
	// Filtering on the finding's decision, not on a list of checks, is what
	// keeps a check that can also allow (st-allow-dd-to-file) from ever
	// allowing a planted /tmp/x/dd.
	pv := ctx.restrictView()
	if pv != nil {
		have := map[string]bool{}
		for _, f := range findings {
			have[f.RuleID] = true
		}
		for _, check := range a.checks {
			for _, f := range check.Check(pv, ctx.RawCommand) {
				if restrictingDecision(f.Decision) && !have[f.RuleID] {
					have[f.RuleID] = true
					findings = append(findings, f)
				}
			}
		}
	}

	// 2. Run user-defined YAML structural rules against the parsed AST.
	// A restricting, non-negated rule also gets the program-name view, as a
	// union (#3991); an ALLOW rule — whose finding carries the
	// structural-override tag that can suppress a regex BLOCK — never does.
	for _, rule := range a.userRules {
		if MatchStructuralRule(parsed, rule) ||
			(pv != nil && restrictingDecision(rule.Decision) && !rule.Negate && MatchStructuralRule(pv, rule)) {
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
			// ALLOW rules from structural YAML get the override tag so the
			// combiner can suppress less-precise regex BLOCKs on the same taxonomy.
			if f.Decision == "ALLOW" {
				f.Tags = []string{"structural-override"}
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

// cwdAwareCheck is a built-in check whose verdict depends on the directory
// the command runs in. The analyzer hands such checks ctx.Cwd.
type cwdAwareCheck interface {
	CheckInCwd(parsed *ParsedCommand, raw, cwd string) []Finding
}

func (c *ddOutputTargetCheck) Check(parsed *ParsedCommand, raw string) []Finding {
	return c.CheckInCwd(parsed, raw, "")
}

// CheckInCwd resolves relative dd targets against cwd. Claude Code's Bash
// tool keeps the working directory between calls, so `cd /dev` in one call
// and `dd … of=sda` in the next is a real two-step (Codex pass 5 on #3997).
// With cwd unknown ("") relative targets are classified as written.
func (c *ddOutputTargetCheck) CheckInCwd(parsed *ParsedCommand, raw, cwd string) []Finding {
	if parsed == nil {
		return nil
	}
	// #3994. This ALLOW is a structural override: the combiner uses it to
	// suppress ts-block-dd-zero and every other disk-overwrite finding in the
	// WHOLE command. So it may be granted only for a command we can vouch for
	// completely. Three Codex passes each found a new way round a deny-list
	// version of this check (unlisted devices, quoted operands, streams routed
	// outside the statement, xargs/find -exec, carriers, groups). Every one of
	// those holes came from enumerating what is dangerous. The gate below
	// enumerates what is SAFE instead.
	if !ddCommandProvablySafe(raw, cwd) {
		return nil
	}

	// From here on this is main's original check, unchanged. Because the
	// gate above can only withhold, the ALLOW this function emits is a subset
	// of the ALLOW main emitted, by construction. So no command can move from
	// a BLOCK on main to an ALLOW here. TestDdAllowIsSubsetOfMain enforces
	// that over the corpus.
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

		normIfPath := normalizeTargetPath(ifPath)
		hasDangerousInput := strings.HasPrefix(normIfPath, "/dev/zero") ||
			strings.HasPrefix(normIfPath, "/dev/urandom") ||
			strings.HasPrefix(normIfPath, "/dev/random")

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

		// Exclude inline-code variants: python3 -c "...", ruby -e "...", perl -e "..."
		// In these cases the piped data is stdin INPUT to the inline script, not
		// remote code being executed. The true threat is when stdin IS the script
		// (no -c/-e/-m flag, or explicit '-' stdin marker).
		// Also exclude -m (module invocations): python3 -m json.tool reads stdin
		// as data (JSON, not Python code) — same safety property as -c for this check.
		_, hasInlineFlag := right.Flags["c"]
		if !hasInlineFlag {
			_, hasInlineFlag = right.Flags["e"]
		}
		if !hasInlineFlag {
			_, hasInlineFlag = right.Flags["m"]
		}

		if isDownload && isPipe && isInterpreter && !hasInlineFlag {
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

// normalizeTargetPath collapses the shell quoting/escaping and path syntax that
// a real shell resolves before a destructive command ever sees the target, so
// path-equivalence evasions can't slip a root/system delete past the check:
//
//	"/"  '/'  \/        → /        (quote/escape stripping)
//	/.   /./  //        → /        (path.Clean)
//	/home/../  /tmp/..  → /        (.. traversal back to root)
//	"/etc"  /etc/       → /etc
//
// Words carrying a dynamic expansion ($VAR, $(...), backticks) are left
// untouched — their value can't be resolved statically.
func normalizeTargetPath(p string) string {
	if p == "" {
		return p
	}
	// Shared shell quote/escape stripping (single source of truth in pathnorm) so
	// this destructive-target check, protected_paths and argument-glob matching
	// all collapse quotes identically (issue #2813).
	p = pathnorm.StripShellQuotes(p)
	if p == "" {
		return p
	}
	// A '?'/'*' wildcard masking one interior byte of a well-known sensitive
	// path segment (`/?ev/sda`, `/?tc/passwd`) resolves to the exact target
	// at runtime the same way a brace group or quote-splice does — this is
	// the single source-of-truth path check, so resolving it here covers
	// every caller (isBlockDevice, isSystemDir/isSystemPath, isRootTarget)
	// without each needing its own deglob call (issue #3103, structural
	// residual of #3102/RegexAnalyzer's candidate-list-only fix).
	p = shellparse.DeglobPath(p)
	// Preserve a trailing "/*" glob marker across cleaning ("/*" → "/*", not "/").
	glob := strings.HasSuffix(p, "/*")
	cleaned := path.Clean(p)
	if glob && cleaned != "/*" {
		if cleaned == "/" {
			cleaned = "/*"
		} else {
			cleaned += "/*"
		}
	}
	return cleaned
}

func isRootTarget(p string) bool {
	cleaned := normalizeTargetPath(p)
	return cleaned == "" || cleaned == "/" || cleaned == "/*"
}

var systemDirs = map[string]bool{
	"/etc": true, "/usr": true, "/usr/local": true, "/var": true,
	"/boot": true, "/sys": true, "/proc": true, "/lib": true,
	"/lib64": true, "/sbin": true, "/bin": true, "/opt": true,
	"/var/log": true, "/usr/bin": true, "/usr/lib": true,
}

func isSystemDir(p string) bool {
	cleaned := strings.TrimRight(normalizeTargetPath(p), "/")
	return systemDirs[cleaned]
}

func isSystemPath(p string) bool {
	cleaned := normalizeTargetPath(p)
	if isSystemDir(cleaned) {
		return true
	}
	for dir := range systemDirs {
		if strings.HasPrefix(cleaned, dir+"/") {
			return true
		}
	}
	return cleaned == "/" || cleaned == "/*"
}

// isBlockDevice reports whether p names a block device the list below knows.
//
// The list names the DANGEROUS set, and that set is open-ended: every platform
// names its disks differently, so the list can never be complete. That is fine
// for its restricting callers (shred/wipefs BLOCK when it says yes; a miss
// leaves them where they would have been anyway). It is NOT fine negated: "not
// on the list" is not evidence of "not a device". Granting an ALLOW on that
// basis let `dd if=/dev/zero of=/dev/disk0`, the macOS boot disk, through with
// no record at all (#3994). Use ddTargetMayBeDevice for anything that relaxes.
//
// The list itself is unchanged by #3994. Adding macOS and Linux names here
// would also widen sem-block-wipefs-device, which BLOCKs read-only listing,
// and doing that honestly needs wipefs's real option grammar. shred's wider
// list lives in isShredTargetDevice (#4006) for exactly that reason.
func isBlockDevice(p string) bool {
	p = normalizeTargetPath(p)
	return strings.HasPrefix(p, "/dev/sd") ||
		strings.HasPrefix(p, "/dev/hd") ||
		strings.HasPrefix(p, "/dev/nvme") ||
		strings.HasPrefix(p, "/dev/vd") ||
		strings.HasPrefix(p, "/dev/xvd") ||
		strings.HasPrefix(p, "/dev/md") ||
		strings.HasPrefix(p, "/dev/dm-") ||
		strings.HasPrefix(p, "/dev/loop")
}

// isShredTargetDevice widens device-name recognition for sem-block-shred-device
// only (#4006). shred destroys the target regardless of flags, so unlike
// wipefs (which has a read-only listing mode #3997 had to stop widening for)
// there is no option grammar to get wrong here — any of these names being the
// operand of shred is destructive. Kept separate from isBlockDevice, which
// also gates sem-block-wipefs-device and structural.go's dd-target check, so
// this widening cannot leak into wipefs's narrower, flag-sensitive rule.
func isShredTargetDevice(p string) bool {
	if isBlockDevice(p) {
		return true
	}
	p = normalizeTargetPath(p)
	return strings.HasPrefix(p, "/dev/disk") || // macOS whole disk
		strings.HasPrefix(p, "/dev/rdisk") || // macOS raw disk
		strings.HasPrefix(p, "/dev/mmcblk") || // SD/eMMC
		strings.HasPrefix(p, "/dev/mapper/") || // device-mapper (LVM, LUKS, ...)
		strings.HasPrefix(p, "/dev/nbd") || // network block device
		strings.HasPrefix(p, "/dev/zd") || // ZFS zvol
		strings.HasPrefix(p, "/dev/bcache") || // bcache
		strings.HasPrefix(p, "/dev/rbd") // Ceph RBD
}

// ddTargetMayBeDevice reports whether dd's of= target is, or may resolve to, a
// device node other than a harmless sink. st-allow-dd-to-file withholds its
// ALLOW whenever this says yes.
//
// It inverts isBlockDevice's question on purpose. The dangerous set cannot be
// enumerated; the safe set can: any path outside /dev/, plus the few device
// nodes that writing to destroys nothing. So the ALLOW needs the target's
// SPELLING to be known safe. Withholding it adds no BLOCK rule of its own; the
// decision falls back to whatever else matched, which for dd if=/dev/zero is
// ts-block-dd-zero.
//
// The evidence is lexical, not filesystem identity. That is why the ALLOW
// also needs ddCommandProvablySafe: every statement a literal dd, so a cd, ln
// or $OUT in the command withholds it. The residual is a target that is
// ALREADY a symlink to a device before the command runs, which no static
// check can see.
func ddTargetMayBeDevice(p string) bool {
	// Detect /dev case-folded: macOS's root volume is case-insensitive, so an
	// upper-case spelling of /dev reaches the same device nodes (#3997
	// post-merge review). But match the harmless sinks on the path AS
	// WRITTEN. Folding it too turned /dev/NULL and /dev/SHM/<x> into sinks
	// and granted an ALLOW that main withholds (Codex on #4019). This way the
	// fold can only ever withhold.
	n := normalizeTargetPath(p)
	low := strings.ToLower(n)
	if low == "/dev" || strings.HasPrefix(low, "/dev/") {
		return !isHarmlessDeviceSink(n)
	}
	// A brace group or a glob the shell still expands at runtime is not a
	// target we can vouch for: of={/tmp/out,/dev/disk0} expands to several
	// operands, and GNU dd writes the last (#3994 review).
	if strings.ContainsAny(n, "{*?[") {
		return true
	}
	// A relative path that climbs out of the working directory can land in
	// /dev (../../dev/sda). The cwd is unknown here, so a relative ".." path
	// passing through a "dev" segment is not known to be safe.
	if strings.HasPrefix(n, "../") && strings.Contains("/"+low+"/", "/dev/") {
		return true
	}
	return false
}

// isHarmlessDeviceSink reports whether n (already normalized) is a device node
// that dd can write to without destroying anything: the bit bucket, and files
// on the /dev/shm tmpfs.
//
// The standard streams and /dev/fd/N are deliberately NOT here. Where they
// lead is decided outside the dd statement: by a redirect on an enclosing
// group or subshell (`{ dd … of=/dev/stdout; } > /dev/sda`), by a later pipeline
// stage (`… | cat > /dev/sda`), or by an earlier `exec 3>`. The per-statement
// redirect check cannot see any of these. It also matches dd with no of= at
// all, which writes to stdout and never earned the ALLOW (#3994 review).
func isHarmlessDeviceSink(n string) bool {
	switch n {
	case "/dev/null", "/dev/zero":
		return true
	}
	return strings.HasPrefix(n, "/dev/shm/")
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
