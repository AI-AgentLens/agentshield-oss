package analyzer

import (
	"strings"
)

// SemanticAnalyzer classifies commands by intent rather than pattern.
// It operates on the ParsedCommand produced by the structural analyzer,
// identifying dangerous command families that regex cannot cover (e.g.,
// shred ≈ dd, find -delete ≈ rm -rf, wipefs ≈ mkfs).
type SemanticAnalyzer struct {
	rules     []SemanticRule
	userRules []UserSemanticRule // user-defined YAML semantic rules
}

// SemanticRule maps a command intent to a security classification.
type SemanticRule struct {
	ID          string
	Match       func(parsed *ParsedCommand, raw string) bool
	Decision    string
	Confidence  float64
	Reason      string
	TaxonomyRef string
	Intent      CommandIntent
	Tags        []string
}

// NewSemanticAnalyzer creates a semantic analyzer with built-in intent rules.
func NewSemanticAnalyzer() *SemanticAnalyzer {
	a := &SemanticAnalyzer{}
	a.rules = a.buildRules()
	return a
}

// SetUserRules attaches user-defined semantic rules from YAML packs.
// These match against intents classified by the built-in rules.
func (a *SemanticAnalyzer) SetUserRules(rules []UserSemanticRule) {
	a.userRules = rules
}

func (a *SemanticAnalyzer) Name() string { return "semantic" }

// Analyze runs semantic intent classification on the parsed command.
// Requires ctx.Parsed to be set (by the structural analyzer).
func (a *SemanticAnalyzer) Analyze(ctx *AnalysisContext) []Finding {
	if ctx.Parsed == nil {
		return nil
	}

	var findings []Finding

	// 1. Run built-in Go semantic rules (classifies intents into ctx.Intents)
	for _, rule := range a.rules {
		if rule.Match(ctx.Parsed, ctx.RawCommand) {
			findings = append(findings, Finding{
				AnalyzerName: "semantic",
				RuleID:       rule.ID,
				Decision:     rule.Decision,
				Confidence:   rule.Confidence,
				Reason:       rule.Reason,
				TaxonomyRef:  rule.TaxonomyRef,
				Tags:         rule.Tags,
			})
			ctx.Intents = append(ctx.Intents, rule.Intent)
		}
	}

	// 2. Run user-defined YAML semantic rules against accumulated intents
	for _, rule := range a.userRules {
		if MatchSemanticRule(ctx.Intents, rule) {
			f := Finding{
				AnalyzerName: "semantic",
				RuleID:       rule.ID,
				Decision:     rule.Decision,
				Confidence:   rule.Confidence,
				Reason:       rule.Reason,
				TaxonomyRef:  rule.Taxonomy,
			}
			if f.Confidence == 0 {
				f.Confidence = 0.80
			}
			findings = append(findings, f)
		}
	}

	return findings
}

func (a *SemanticAnalyzer) buildRules() []SemanticRule {
	return []SemanticRule{
		// --- Destructive file operations (alternatives to rm) ---
		{
			ID: "sem-block-find-delete",
			Match: func(parsed *ParsedCommand, raw string) bool {
				// The shell parser splits -delete into short flags (d,e,l,t).
				// Use raw string matching for find commands with -delete/-exec on system paths.
				if !strings.Contains(raw, "find") {
					return false
				}
				hasDangerousAction := strings.Contains(raw, "-delete") ||
					strings.Contains(raw, "-exec")
				if !hasDangerousAction {
					return false
				}
				// Check if any arg to find is a system path
				for _, seg := range allSegments(parsed) {
					if seg.Executable == "find" {
						for _, a := range seg.Args {
							if isSystemPath(a) {
								return true
							}
						}
					}
				}
				return false
			},
			Decision:    "BLOCK",
			Confidence:  0.90,
			Reason:      "find with -delete on system path is destructive (equivalent to rm -rf)",
			TaxonomyRef: "destructive-ops/fs-destruction/system-directory-delete",
			Intent: CommandIntent{
				Category:   "file-delete",
				Risk:       "critical",
				Confidence: 0.90,
				Segment:    -1,
				Detail:     "find -delete on system path",
			},
			Tags: []string{"destructive", "evasion"},
		},

		// --- Disk destruction alternatives ---
		{
			ID: "sem-block-shred-device",
			Match: func(parsed *ParsedCommand, raw string) bool {
				for _, seg := range allSegments(parsed) {
					if seg.Executable == "shred" {
						for _, arg := range seg.Args {
							if isBlockDevice(arg) {
								return true
							}
						}
					}
				}
				return false
			},
			Decision:    "BLOCK",
			Confidence:  0.95,
			Reason:      "shred on block device is destructive (secure erase)",
			TaxonomyRef: "destructive-ops/disk-ops/disk-overwrite",
			Intent: CommandIntent{
				Category:   "disk-destroy",
				Risk:       "critical",
				Confidence: 0.95,
				Segment:    -1,
				Detail:     "shred on block device",
			},
			Tags: []string{"destructive", "critical"},
		},
		{
			ID: "sem-block-wipefs-device",
			Match: func(parsed *ParsedCommand, raw string) bool {
				for _, seg := range allSegments(parsed) {
					if seg.Executable == "wipefs" {
						for _, arg := range seg.Args {
							if isBlockDevice(arg) {
								return true
							}
						}
					}
				}
				return false
			},
			Decision:    "BLOCK",
			Confidence:  0.90,
			Reason:      "wipefs on block device erases filesystem signatures",
			TaxonomyRef: "destructive-ops/disk-ops/filesystem-format",
			Intent: CommandIntent{
				Category:   "disk-destroy",
				Risk:       "critical",
				Confidence: 0.90,
				Segment:    -1,
				Detail:     "wipefs erases filesystem signatures",
			},
			Tags: []string{"destructive"},
		},

		// --- Network scanning ---
		{
			ID: "sem-audit-nmap",
			Match: func(parsed *ParsedCommand, raw string) bool {
				for _, seg := range allSegments(parsed) {
					if seg.Executable == "nmap" || seg.Executable == "masscan" ||
						seg.Executable == "zmap" {
						return true
					}
				}
				return false
			},
			Decision:    "AUDIT",
			Confidence:  0.85,
			Reason:      "Network scanning tool detected",
			TaxonomyRef: "reconnaissance/system-enum/network-scanning",
			Intent: CommandIntent{
				Category:   "network-scan",
				Risk:       "medium",
				Confidence: 0.85,
				Segment:    -1,
				Detail:     "network scanning tool",
			},
			Tags: []string{"reconnaissance"},
		},

		// --- Indirect code execution detection (depth 2) ---
		{
			ID: "sem-block-python-rmtree",
			Match: func(parsed *ParsedCommand, raw string) bool {
				// Check both raw command and subcommand content
				return matchesIndirectPattern(parsed, raw,
					[]string{"python", "python3", "python2"},
					[]string{"shutil.rmtree", "os.remove", "os.unlink"})
			},
			Decision:    "BLOCK",
			Confidence:  0.85,
			Reason:      "Python code executing destructive file operations (shutil.rmtree or os.remove)",
			TaxonomyRef: "destructive-ops/fs-destruction/recursive-root-delete",
			Intent: CommandIntent{
				Category:   "file-delete",
				Risk:       "critical",
				Confidence: 0.85,
				Segment:    -1,
				Detail:     "python indirect destructive operation",
			},
			Tags: []string{"indirect-execution", "depth-2"},
		},
		{
			ID: "sem-block-python-fork-bomb",
			Match: func(parsed *ParsedCommand, raw string) bool {
				return matchesIndirectPattern(parsed, raw,
					[]string{"python", "python3", "python2"},
					[]string{"os.fork()"})
			},
			Decision:    "BLOCK",
			Confidence:  0.85,
			Reason:      "Python code executing fork bomb (os.fork in loop)",
			TaxonomyRef: "destructive-ops/resource-exhaustion/fork-bomb",
			Intent: CommandIntent{
				Category:   "resource-exhaust",
				Risk:       "critical",
				Confidence: 0.85,
				Segment:    -1,
				Detail:     "python fork bomb via os.fork()",
			},
			Tags: []string{"indirect-execution", "depth-2"},
		},

		// --- Safe DNS pattern detection (FP override) ---
		{
			ID: "sem-allow-dns-safe",
			Match: func(parsed *ParsedCommand, raw string) bool {
				for _, seg := range allSegments(parsed) {
					if seg.Executable == "dig" || seg.Executable == "nslookup" || seg.Executable == "host" {
						for _, arg := range seg.Args {
							lower := strings.ToLower(arg)
							if strings.HasPrefix(lower, "_dmarc.") ||
								strings.HasPrefix(lower, "_spf.") ||
								strings.HasPrefix(lower, "_dkim.") ||
								strings.HasPrefix(lower, "_domainkey.") ||
								strings.HasPrefix(lower, "_acme-challenge.") ||
								strings.HasPrefix(lower, "_mta-sts.") {
								return true
							}
						}
					}
				}
				return false
			},
			Decision:    "ALLOW",
			Confidence:  0.90,
			Reason:      "DNS query for DMARC/SPF/DKIM/ACME is a legitimate security operation",
			TaxonomyRef: "data-exfiltration/network-egress/dns-tunneling",
			Intent: CommandIntent{
				Category:   "dns-query-safe",
				Risk:       "none",
				Confidence: 0.90,
				Segment:    -1,
				Detail:     "legitimate DNS security record lookup",
			},
			Tags: []string{"safe-override", "semantic-override"},
		},

		// --- Safe DNS pattern detection — reconnaissance override ---
		// Companion to sem-allow-dns-safe: suppresses ne-audit-dns AUDIT for the
		// same DMARC/SPF/DKIM patterns (ne-audit-dns uses reconnaissance taxonomy).
		{
			ID: "sem-allow-dns-safe-recon",
			Match: func(parsed *ParsedCommand, raw string) bool {
				for _, seg := range allSegments(parsed) {
					if seg.Executable == "dig" || seg.Executable == "nslookup" || seg.Executable == "host" {
						for _, arg := range seg.Args {
							lower := strings.ToLower(arg)
							if strings.HasPrefix(lower, "_dmarc.") ||
								strings.HasPrefix(lower, "_spf.") ||
								strings.HasPrefix(lower, "_dkim.") ||
								strings.HasPrefix(lower, "_domainkey.") ||
								strings.HasPrefix(lower, "_acme-challenge.") ||
								strings.HasPrefix(lower, "_mta-sts.") {
								return true
							}
						}
					}
				}
				return false
			},
			Decision:    "ALLOW",
			Confidence:  0.90,
			Reason:      "DNS query for DMARC/SPF/DKIM/ACME is a legitimate security operation",
			TaxonomyRef: "reconnaissance/network-discovery/dns-lookup",
			Intent: CommandIntent{
				Category:   "dns-query-safe",
				Risk:       "none",
				Confidence: 0.90,
				Segment:    -1,
				Detail:     "legitimate DNS security record lookup",
			},
			Tags: []string{"safe-override", "semantic-override"},
		},

		// --- Pipe to crontab stdin = persistence (BLOCK) ---
		{
			ID: "sem-block-pipe-to-crontab",
			Match: func(parsed *ParsedCommand, raw string) bool {
				// Detect: <anything> | crontab -
				if len(parsed.Segments) < 2 {
					return false
				}
				for i := 1; i < len(parsed.Segments); i++ {
					seg := parsed.Segments[i]
					if seg.Executable == "crontab" {
						for _, a := range seg.Args {
							if a == "-" {
								return true
							}
						}
					}
				}
				return false
			},
			Decision:    "BLOCK",
			Confidence:  0.90,
			Reason:      "Piping content to crontab stdin installs persistent scheduled tasks",
			TaxonomyRef: "persistence-evasion/scheduled-tasks/crontab-modification",
			Intent: CommandIntent{
				Category:   "persistence",
				Risk:       "critical",
				Confidence: 0.90,
				Segment:    -1,
				Detail:     "pipe to crontab stdin",
			},
			Tags: []string{"persistence", "evasion"},
		},

		// --- Supply chain: pip config manipulation ---
		{
			ID: "sem-block-pip-config-index",
			Match: func(parsed *ParsedCommand, raw string) bool {
				return strings.Contains(raw, "pip config set") &&
					(strings.Contains(raw, "index-url") || strings.Contains(raw, "extra-index-url"))
			},
			Decision:    "BLOCK",
			Confidence:  0.85,
			Reason:      "pip config set changing package index URL is a supply chain risk",
			TaxonomyRef: "supply-chain/dependency-confusion/non-standard-registry",
			Intent: CommandIntent{
				Category:   "supply-chain",
				Risk:       "high",
				Confidence: 0.85,
				Segment:    -1,
				Detail:     "pip config changing package index",
			},
			Tags: []string{"supply-chain", "evasion"},
		},

		// --- Persistence detection ---
		{
			ID: "sem-audit-crontab-modify",
			Match: func(parsed *ParsedCommand, raw string) bool {
				for _, seg := range allSegments(parsed) {
					if seg.Executable == "crontab" {
						// crontab -e or crontab - (reading from stdin) is modification
						if _, hasE := seg.Flags["e"]; hasE {
							return true
						}
						// crontab with file argument (crontab mycronfile)
						if len(seg.Args) > 0 && seg.Args[0] != "-l" {
							return true
						}
						// crontab - (read from stdin, typically via pipe)
						for _, a := range seg.Args {
							if a == "-" {
								return true
							}
						}
					}
				}
				return false
			},
			Decision:    "AUDIT",
			Confidence:  0.85,
			Reason:      "crontab modification detected — may establish persistence",
			TaxonomyRef: "persistence-evasion/scheduled-tasks/crontab-modification",
			Intent: CommandIntent{
				Category:   "persistence",
				Risk:       "high",
				Confidence: 0.85,
				Segment:    -1,
				Detail:     "crontab modification",
			},
			Tags: []string{"persistence"},
		},
	}
}

// matchesIndirectPattern checks if a command uses an interpreter to execute
// code containing dangerous patterns. Works at depth 0 (raw string check)
// and depth 1+ (parsed subcommand check).
func matchesIndirectPattern(parsed *ParsedCommand, raw string, interpreters []string, patterns []string) bool {
	// Check raw command for simple cases like: python3 -c "shutil.rmtree('/')"
	for _, interp := range interpreters {
		if strings.Contains(raw, interp) {
			for _, pat := range patterns {
				if strings.Contains(raw, pat) {
					return true
				}
			}
		}
	}

	// Check subcommands (parsed at depth > 0)
	if parsed != nil {
		for _, sub := range parsed.Subcommands {
			for _, seg := range allSegments(sub) {
				raw := seg.Raw
				for _, pat := range patterns {
					if strings.Contains(raw, pat) {
						return true
					}
				}
			}
		}
	}
	return false
}
