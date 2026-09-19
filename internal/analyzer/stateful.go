package analyzer

import (
	"net/url"
	"path"
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

		// Check for the agentic-pentest decoy-payload pattern: a recon/exploit
		// tool run against a target, followed by fetching an executable
		// artifact FROM THAT SAME HOST, followed by running it (#3654).
		findings = append(findings, s.checkPentestDecoyPayloadExecution(pc)...)

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

// pentestReconTools are offensive-security scanning/exploitation tools whose
// invocation names an explicit network target — the "recon step" of the
// agentic-pentest decoy-payload chain (taxonomy:
// unauthorized-execution/agentic-attacks/agentic-pentest-tool-decoy-payload-execution,
// #3654). Source: "Red-Teaming the Agentic Red-Team" (arXiv:2606.24496) —
// an autonomous offensive-security agent recons a target, discovers a
// fully-functional but self-vulnerable "tool" staged on that same target,
// downloads it, and runs it. No prompt injection or malicious code is
// present anywhere in the chain — the paper's own framing is that this is
// the point: model-based code inspection finds nothing to object to.
var pentestReconTools = map[string]bool{
	"nmap": true, "masscan": true, "rustscan": true,
	"gobuster": true, "dirb": true, "dirsearch": true, "ffuf": true, "wfuzz": true,
	"nikto": true, "sqlmap": true, "nuclei": true,
	"whatweb": true, "wpscan": true,
	"amass": true, "subfinder": true,
	"hydra": true, "medusa": true,
}

// pentestReconTargetFlags are the flag names these tools use to carry an
// explicit target host/URL, checked before falling back to positional args.
var pentestReconTargetFlags = []string{"u", "url", "host", "h", "target", "rhost", "rhosts", "d"}

// checkPentestDecoyPayloadExecution detects: [recon/exploit tool against a
// target] -> [download of an executable artifact FROM THAT SAME HOST] ->
// [local execution of the downloaded artifact]. The differentiator from the
// generic download-execute chain above is host correlation — downloading and
// running a tool discovered on the very host under test is the behavioral
// signature the taxonomy entry names; downloading a tool from a DIFFERENT
// host (the operator's own tooling infra) is ordinary pentest workflow and
// must not match. Exact-host-match only (no subdomain/base-domain fuzzing) —
// deliberately conservative for a BLOCK-tier finding; see #3654 PR notes for
// the scope decision.
func (s *StatefulAnalyzer) checkPentestDecoyPayloadExecution(parsed *ParsedCommand) []Finding {
	if parsed == nil || len(parsed.Segments) < 3 {
		return nil
	}

	// 1. Find the recon/exploit step and its target host.
	reconHost := ""
	reconTool := ""
	reconIdx := -1
	for i, seg := range parsed.Segments {
		if !pentestReconTools[seg.Executable] {
			continue
		}
		if h := extractReconTargetHost(seg); h != "" {
			reconHost = h
			reconTool = seg.Executable
			reconIdx = i
			break
		}
	}
	if reconIdx == -1 {
		return nil
	}

	// 2. Find a later download step whose URL host matches the recon target.
	downloadedFiles := map[string]bool{}
	downloadIdx := -1
	for i := reconIdx + 1; i < len(parsed.Segments); i++ {
		seg := parsed.Segments[i]
		if !isDownloadCommand(seg.Executable) {
			continue
		}
		if extractDownloadURLHost(seg) != reconHost {
			continue
		}
		outFile := pathnorm.StripShellQuotes(extractDownloadOutputFile(seg))
		if outFile == "" {
			outFile = extractDownloadURLBasename(seg)
		}
		if outFile != "" {
			downloadedFiles[outFile] = true
			downloadIdx = i
		}
	}
	if downloadIdx == -1 || len(downloadedFiles) == 0 {
		return nil
	}

	// 3. Find local execution (or chmod +x prep) of the downloaded artifact.
	for i := downloadIdx + 1; i < len(parsed.Segments); i++ {
		seg := parsed.Segments[i]
		for f := range downloadedFiles {
			if isExecuteOfFile(seg, f) {
				return []Finding{{
					AnalyzerName: "stateful",
					RuleID:       "sf-block-pentest-decoy-payload-execution",
					Decision:     "BLOCK",
					Confidence:   0.90,
					Reason: reconTool + " recon against " + reconHost + " followed by fetching and " +
						"executing an artifact from that SAME host — treat any tool discovered on a " +
						"scanned target as an untrusted, potentially self-compromising supply-chain " +
						"artifact, never as a required deliverable. No prompt injection is required " +
						"for this attack; the artifact's code is honestly-behaving with a self-planted " +
						"vulnerability triggered by ordinary execution (arXiv:2606.24496).",
					TaxonomyRef: "unauthorized-execution/agentic-attacks/agentic-pentest-tool-decoy-payload-execution",
					Tags:        []string{"stateful", "agentic-attack", "pentest-decoy-payload"},
				}}
			}
		}
	}

	return nil
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

// nonHostFileSuffixes are common non-URL file extensions that would
// otherwise look host-like to hostFromToken (they contain a dot) — wordlist
// and output-file arguments sitting alongside a recon tool's target, e.g.
// "-w wordlist.txt". Filtering them out only costs recall: a missed host
// extraction just means the chain fails to correlate, never a false BLOCK,
// since correlation requires an exact match against a SECOND independently
// extracted host.
var nonHostFileSuffixes = []string{
	".txt", ".lst", ".dic", ".csv", ".json", ".xml", ".yaml", ".yml", ".db", ".sqlite", ".log",
}

// hostFromToken extracts a lowercase hostname/IP from a single shell
// argument: a full URL ("http://host/path"), a scheme-less "host/path" or
// "host:port" (curl/wget/nmap all accept this shape), or a bare
// hostname/IP/CIDR target ("10.0.0.5", "10.0.0.0/24"). Requires a '.' in the
// extracted head so it doesn't match bare flag-like tokens. Deliberately
// loose in the safe direction only: a wrong extraction can only weaken
// correlation (both call sites require the SAME extracted host to appear on
// two independent segments), it can never manufacture a match between two
// genuinely different hosts.
func hostFromToken(raw string) string {
	tok := pathnorm.StripShellQuotes(strings.TrimSpace(raw))
	if tok == "" {
		return ""
	}

	if strings.Contains(tok, "://") {
		u, err := url.Parse(tok)
		if err != nil || u.Hostname() == "" {
			return ""
		}
		return strings.ToLower(u.Hostname())
	}

	lower := strings.ToLower(tok)
	for _, suffix := range nonHostFileSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return ""
		}
	}

	head := tok
	if idx := strings.IndexByte(head, '/'); idx >= 0 {
		head = head[:idx]
	}
	if idx := strings.IndexByte(head, ':'); idx >= 0 {
		head = head[:idx]
	}
	if head == "" || !strings.Contains(head, ".") || !hostLikeToken(head) {
		return ""
	}
	return strings.ToLower(head)
}

// hostLikeToken reports whether s is composed only of characters valid in a
// hostname or IPv4 literal.
func hostLikeToken(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
		default:
			return false
		}
	}
	return true
}

// extractReconTargetHost pulls the scan/exploit target host out of a recon
// tool's segment: known target-carrying flags first (-u/-url/-host/-target/
// -rhost(s)/-d), then the first host-like positional argument.
func extractReconTargetHost(seg CommandSegment) string {
	for _, flag := range pentestReconTargetFlags {
		if v, ok := seg.Flags[flag]; ok && v != "" {
			if h := hostFromToken(v); h != "" {
				return h
			}
		}
	}
	for _, arg := range seg.Args {
		if h := hostFromToken(arg); h != "" {
			return h
		}
	}
	return ""
}

// extractDownloadURLHost pulls the source host out of a curl/wget segment's
// URL argument. Requires an explicit "://" scheme, unlike hostFromToken's
// bare-host fallback used for recon targets — a download segment's Args can
// also contain the OUTPUT filename (e.g. "curl -o decrypt.py https://...",
// where the parser leaves an empty Flags["o"] and puts both "decrypt.py" and
// the URL in Args, see extractDownloadOutputFile's comment). A bare filename
// like "decrypt.py" satisfies hostFromToken's dotted-hostname shape, so
// scanning Args with the bare-host-tolerant matcher would grab the filename
// and never reach the real URL. curl/wget invocations in practice always
// carry an explicit scheme, so requiring one here costs no real recall.
func extractDownloadURLHost(seg CommandSegment) string {
	for _, arg := range seg.Args {
		if h := urlSchemeHost(arg); h != "" {
			return h
		}
	}
	for _, v := range seg.Flags {
		if h := urlSchemeHost(v); h != "" {
			return h
		}
	}
	return ""
}

// urlSchemeHost extracts the lowercase hostname from a token that carries an
// explicit "scheme://" prefix; returns "" for anything else (including bare
// hostnames — see extractDownloadURLHost).
func urlSchemeHost(raw string) string {
	tok := pathnorm.StripShellQuotes(strings.TrimSpace(raw))
	if !strings.Contains(tok, "://") {
		return ""
	}
	u, err := url.Parse(tok)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// extractDownloadURLBasename infers the local filename curl -O / wget's
// default naming produces when no explicit -o/-O <name> is given — the
// URL's path basename. Only called after extractDownloadOutputFile finds no
// explicit output filename.
func extractDownloadURLBasename(seg CommandSegment) string {
	for _, arg := range seg.Args {
		a := pathnorm.StripShellQuotes(arg)
		raw := a
		if !strings.Contains(raw, "://") {
			if !strings.Contains(raw, ".") {
				continue
			}
			raw = "http://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil || u.Path == "" || u.Path == "/" {
			continue
		}
		base := path.Base(u.Path)
		if base != "" && base != "." && base != "/" {
			return base
		}
	}
	return ""
}
