package analyzer

import (
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// StatefulAnalyzer detects multi-step attack chains within a single compound
// command connected by &&, ||, ;, or | — e.g. download→execute sequences like
// "curl -o x.sh && bash x.sh" that no single-segment analyzer can detect.
type StatefulAnalyzer struct {
	userRules []StatefulRule // user-defined YAML stateful rules
}

// NewStatefulAnalyzer creates a stateful analyzer.
func NewStatefulAnalyzer() *StatefulAnalyzer {
	return &StatefulAnalyzer{}
}

// SetUserRules attaches user-defined stateful rules from YAML packs.
func (s *StatefulAnalyzer) SetUserRules(rules []StatefulRule) {
	s.userRules = rules
}

func (s *StatefulAnalyzer) Name() string { return "stateful" }

// Analyze checks for multi-step attack patterns.
//
// Runs every check against ctx.Parsed AND, independently, against each
// subcommand reachable from it (shellparse.AllParsedCommands) — a chain like
// "curl x | bash" can sit entirely inside a single command substitution
// ("export y=$(curl x | bash)"), self-contained in its own Subcommand entry
// with its own Operators. Checking only ctx.Parsed's top-level
// Segments/Operators would never see that chain (#3076).
func (s *StatefulAnalyzer) Analyze(ctx *AnalysisContext) []Finding {
	var findings []Finding

	if ctx.Parsed == nil {
		return findings
	}

	for _, pc := range shellparse.AllParsedCommands(ctx.Parsed) {
		// 1. Run built-in Go checks
		// Check compound commands within this single evaluation
		// (e.g., "curl -o x.sh && bash x.sh")
		findings = append(findings, s.checkCompoundDownloadExecute(pc)...)

		// 2. Run user-defined YAML stateful rules
		for _, rule := range s.userRules {
			if MatchStatefulRule(pc, rule) {
				f := Finding{
					AnalyzerName: "stateful",
					RuleID:       rule.ID,
					Decision:     rule.Decision,
					Confidence:   rule.Confidence,
					Reason:       rule.Reason,
					TaxonomyRef:  rule.Taxonomy,
				}
				if f.Confidence == 0 {
					f.Confidence = 0.85
				}
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// checkCompoundDownloadExecute detects download→execute chains within a single
// compound command connected by && or ;
//
// Patterns:
//   - curl/wget -o <file> && bash/sh/chmod <file>
//   - curl/wget -O <file> && chmod +x <file> && ./<file>
func (s *StatefulAnalyzer) checkCompoundDownloadExecute(parsed *ParsedCommand) []Finding {
	if parsed == nil {
		return nil
	}

	if len(parsed.Segments) < 2 {
		return nil
	}

	// Look for download segments
	var downloadedFiles []string
	var downloadSegIdx = -1

	for i, seg := range parsed.Segments {
		if !isDownloadCommand(seg.Executable) {
			continue
		}

		// Extract output file from flags/args. Strip inline shell quotes
		// (issue #2945) — "/tmp/x'.'sh" resolves to /tmp/x.sh at exec time,
		// so raw-text comparison against the execute-side filename misses
		// the spliced form while the same file still gets executed.
		outFile := pathnorm.StripShellQuotes(extractDownloadOutputFile(seg))
		if outFile != "" {
			downloadedFiles = append(downloadedFiles, outFile)
			downloadSegIdx = i
		}
	}

	if len(downloadedFiles) == 0 {
		return nil
	}

	// Look for execute segments that reference the downloaded file
	var findings []Finding
	for i, seg := range parsed.Segments {
		if i <= downloadSegIdx {
			continue
		}

		for _, dlFile := range downloadedFiles {
			if isExecuteOfFile(seg, dlFile) {
				findings = append(findings, Finding{
					AnalyzerName: "stateful",
					RuleID:       "sf-block-download-execute",
					Decision:     "BLOCK",
					Confidence:   0.90,
					Reason: "Download-then-execute chain detected: " +
						parsed.Segments[downloadSegIdx].Executable + " → " + seg.Executable + " " + dlFile,
					TaxonomyRef: "unauthorized-execution/remote-code-exec/pipe-to-shell",
					Tags:        []string{"stateful", "download-execute"},
				})
				break
			}
		}
	}

	// Also check for chmod +x followed by execution of same file
	for i, seg := range parsed.Segments {
		if seg.Executable != "chmod" {
			continue
		}
		chmodFile := pathnorm.StripShellQuotes(extractChmodTarget(seg))
		if chmodFile == "" {
			continue
		}

		for j := i + 1; j < len(parsed.Segments); j++ {
			nextSeg := parsed.Segments[j]
			nextExec := pathnorm.StripShellQuotes(nextSeg.Executable)
			if isExecuteOfFile(nextSeg, chmodFile) || nextExec == chmodFile || nextExec == "./"+chmodFile {
				// Already covered by the download-execute finding above, skip if duplicate
				alreadyFound := false
				for _, f := range findings {
					if f.RuleID == "sf-block-download-execute" {
						alreadyFound = true
						break
					}
				}
				if !alreadyFound {
					findings = append(findings, Finding{
						AnalyzerName: "stateful",
						RuleID:       "sf-block-download-execute",
						Decision:     "BLOCK",
						Confidence:   0.85,
						Reason:       "chmod +x followed by execution of same file: " + chmodFile,
						TaxonomyRef:  "unauthorized-execution/remote-code-exec/pipe-to-shell",
						Tags:         []string{"stateful", "download-execute"},
					})
				}
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// extractDownloadOutputFile extracts the output filename from a curl/wget segment.
// The structural parser may put the flag value in the Flags map OR as a separate arg.
func extractDownloadOutputFile(seg CommandSegment) string {
	// Check Flags map first (flag value might be attached: -o/tmp/x.sh)
	for _, flag := range []string{"o", "output", "O", "output-document"} {
		if v, ok := seg.Flags[flag]; ok && v != "" {
			return v
		}
	}

	// The parser often puts -o with empty value and the file as the next arg.
	// Look for flag presence with empty value, then grab the corresponding arg.
	hasOutputFlag := false
	for _, flag := range []string{"o", "output", "O", "output-document"} {
		if _, ok := seg.Flags[flag]; ok {
			hasOutputFlag = true
			break
		}
	}

	if hasOutputFlag && len(seg.Args) > 0 {
		// The output file is typically a path-like arg (starts with / or ./ or contains /)
		for _, arg := range seg.Args {
			if isFilePath(arg) {
				return arg
			}
		}
		// Fallback: last arg that's not a URL
		for i := len(seg.Args) - 1; i >= 0; i-- {
			if !isURL(seg.Args[i]) {
				return seg.Args[i]
			}
		}
	}

	return ""
}

func isFilePath(s string) bool {
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../")
}

func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "ftp://")
}

// isSafeModuleInvocation returns true when a Python interpreter is called with
// a stdlib module that treats its argument as data, not as code to execute.
// e.g. "python3 -m json.tool /tmp/packs.json" reads the file as JSON, not Python.
//
// Note: the shell parser stores "-m" as an empty-valued flag and puts the
// module name as the first positional arg, so we look at seg.Args[0].
func isSafeModuleInvocation(seg CommandSegment) bool {
	if _, hasM := seg.Flags["m"]; !hasM {
		return false
	}
	// Module name lands in Args[0] because the parser treats short flag values as args.
	if len(seg.Args) == 0 {
		return false
	}
	switch seg.Args[0] {
	case "json.tool", "http.server", "pydoc", "venv", "ensurepip":
		return true
	}
	return false
}

// hasInlineCodeFlag returns true when the segment carries an interpreter's
// "-c" flag (bash/sh/zsh/python/python3 "run this string as code"). Mirrors
// the flags_none: [c, m] exclusion on the YAML sibling rule
// ts-sf-block-download-execute (#3277) — an interpreter invoked with -c
// executes the inline string, not a file, so any file-shaped argument
// alongside it (e.g. "python3 -c '...' \"$f\"") is a positional data
// argument (sys.argv), not code being executed.
func hasInlineCodeFlag(seg CommandSegment) bool {
	_, ok := seg.Flags["c"]
	return ok
}

// isExecuteOfFile checks if a segment executes a specific file.
func isExecuteOfFile(seg CommandSegment, file string) bool {
	// Strip inline shell quotes from both sides (issue #2945) — the caller
	// may pass an already-spliced filename (e.g. from extractDownloadOutputFile
	// before normalization landed here too), and the execute-side arg/
	// executable can independently be spliced (e.g. "bash /tmp/x'.'sh").
	file = pathnorm.StripShellQuotes(file)
	execName := pathnorm.StripShellQuotes(seg.Executable)

	// Direct execution: bash <file>, sh <file>, python3 <file>, node <file>, etc.
	// Use isShellOrInterpreter to cover both shell (bash/sh/zsh) and code
	// interpreters (python3/node/ruby/perl) — the latter were previously missed.
	if isShellOrInterpreter(execName) {
		// -c invocations run inline code, not the downloaded file (#3277).
		if hasInlineCodeFlag(seg) {
			return false
		}
		// Safe stdlib module invocations consume the file as data, not as code.
		if isSafeModuleInvocation(seg) {
			return false
		}
		for _, arg := range seg.Args {
			a := pathnorm.StripShellQuotes(arg)
			if a == file || strings.HasSuffix(a, "/"+file) {
				return true
			}
		}
	}

	// chmod +x <file> (not execution, but part of the chain)
	if execName == "chmod" {
		for _, arg := range seg.Args {
			a := pathnorm.StripShellQuotes(arg)
			if a == file || strings.HasSuffix(a, "/"+file) {
				return true
			}
		}
	}

	// Direct path execution: ./<file> or /tmp/<file>
	if execName == file || execName == "./"+file || strings.HasSuffix(execName, "/"+file) {
		return true
	}

	return false
}

func extractChmodTarget(seg CommandSegment) string {
	// chmod +x <file> — the file is the last non-flag argument
	for _, arg := range seg.Args {
		if !strings.HasPrefix(arg, "+") && !strings.HasPrefix(arg, "-") && arg != "chmod" {
			return arg
		}
	}
	return ""
}
