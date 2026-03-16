package analyzer

import (
	"strings"
)

// StatefulAnalyzer (Layer 4) detects multi-step attack chains by analyzing
// the current command in the context of session history. It catches patterns
// like download→execute sequences that no single-command analyzer can detect.
//
// For single-command evaluation (no session store), the stateful analyzer
// falls back to detecting multi-step patterns within a single compound
// command (e.g., "curl -o x.sh && bash x.sh").
type StatefulAnalyzer struct {
	store     SessionStore   // optional: nil means compound-command-only mode
	userRules []StatefulRule // user-defined YAML stateful rules
}

// NewStatefulAnalyzer creates a stateful analyzer.
// If store is nil, only compound-command detection is active.
func NewStatefulAnalyzer(store SessionStore) *StatefulAnalyzer {
	return &StatefulAnalyzer{store: store}
}

// SetUserRules attaches user-defined stateful rules from YAML packs.
func (s *StatefulAnalyzer) SetUserRules(rules []StatefulRule) {
	s.userRules = rules
}

func (s *StatefulAnalyzer) Name() string { return "stateful" }

// Analyze checks for multi-step attack patterns.
func (s *StatefulAnalyzer) Analyze(ctx *AnalysisContext) []Finding {
	var findings []Finding

	// 1. Run built-in Go checks
	// Check compound commands within this single evaluation
	// (e.g., "curl -o x.sh && bash x.sh")
	findings = append(findings, s.checkCompoundDownloadExecute(ctx)...)

	// If a session store is available, check cross-command patterns
	if s.store != nil {
		findings = append(findings, s.checkSessionPatterns(ctx)...)
	}

	// 2. Run user-defined YAML stateful rules
	if ctx.Parsed != nil {
		for _, rule := range s.userRules {
			if MatchStatefulRule(ctx.Parsed, rule) {
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
func (s *StatefulAnalyzer) checkCompoundDownloadExecute(ctx *AnalysisContext) []Finding {
	if ctx.Parsed == nil {
		return nil
	}

	parsed := ctx.Parsed
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

		// Extract output file from flags/args
		outFile := extractDownloadOutputFile(seg)
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
		chmodFile := extractChmodTarget(seg)
		if chmodFile == "" {
			continue
		}

		for j := i + 1; j < len(parsed.Segments); j++ {
			nextSeg := parsed.Segments[j]
			if isExecuteOfFile(nextSeg, chmodFile) || nextSeg.Executable == chmodFile || nextSeg.Executable == "./"+chmodFile {
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

// checkSessionPatterns checks the session history for multi-command attack chains.
func (s *StatefulAnalyzer) checkSessionPatterns(ctx *AnalysisContext) []Finding {
	history, err := s.store.GetHistory(10)
	if err != nil || len(history) == 0 {
		return nil
	}

	var findings []Finding

	// Check if a recent download is now being executed
	for _, prev := range history {
		if !isRawDownloadCommand(prev.Command) {
			continue
		}

		outFile := extractOutputFileFromRaw(prev.Command)
		if outFile == "" {
			continue
		}

		// Check if current command executes this file
		if ctx.Parsed != nil {
			for _, seg := range ctx.Parsed.Segments {
				if isExecuteOfFile(seg, outFile) {
					findings = append(findings, Finding{
						AnalyzerName: "stateful",
						RuleID:       "sf-block-session-download-execute",
						Decision:     "BLOCK",
						Confidence:   0.85,
						Reason:       "Executing file downloaded in a previous command: " + outFile,
						TaxonomyRef:  "unauthorized-execution/remote-code-exec/pipe-to-shell",
						Tags:         []string{"stateful", "session", "download-execute"},
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

func isRawDownloadCommand(raw string) bool {
	return strings.HasPrefix(raw, "curl ") || strings.HasPrefix(raw, "wget ")
}

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

// extractOutputFileFromRaw extracts output file from raw command string (for session history).
func extractOutputFileFromRaw(raw string) string {
	parts := strings.Fields(raw)
	for i, p := range parts {
		if (p == "-o" || p == "-O" || p == "--output" || p == "--output-document") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// isExecuteOfFile checks if a segment executes a specific file.
func isExecuteOfFile(seg CommandSegment, file string) bool {
	// Direct execution: bash <file>, sh <file>, python3 <file>, node <file>, etc.
	// Use isShellOrInterpreter to cover both shell (bash/sh/zsh) and code
	// interpreters (python3/node/ruby/perl) — the latter were previously missed.
	if isShellOrInterpreter(seg.Executable) {
		for _, arg := range seg.Args {
			if arg == file || strings.HasSuffix(arg, "/"+file) {
				return true
			}
		}
	}

	// chmod +x <file> (not execution, but part of the chain)
	if seg.Executable == "chmod" {
		for _, arg := range seg.Args {
			if arg == file || strings.HasSuffix(arg, "/"+file) {
				return true
			}
		}
	}

	// Direct path execution: ./<file> or /tmp/<file>
	if seg.Executable == file || seg.Executable == "./"+file || strings.HasSuffix(seg.Executable, "/"+file) {
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
