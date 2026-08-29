package analyzer

import (
	"regexp"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
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

	// IntentExclude lists CommandFacts labels (see intent.go) that suppress
	// this rule — the built-in-Go-rule equivalent of YAML's
	// command_intent_exclude. Unlike YAML rules, these hardcoded rules match
	// via raw substring search (matchesIndirectPattern), which cannot tell a
	// live command from a heredoc body being written to a file, so rules
	// prone to that FP opt in explicitly.
	IntentExclude []string
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

	// A handful of built-in rules below match via strings.Contains(raw, ...)
	// on the literal command text rather than through ctx.Parsed, so they
	// don't automatically benefit from shellparse.Parse's internal ${IFS}
	// canonicalization the way AST-driven rules do (#3044 — "pip${IFS}config
	// set ... extra-index-url" defeated sem-block-pip-config-index, whose
	// Match func does strings.Contains(raw, "pip config set")). Computed
	// once per command, "" (no-op) when nothing needs collapsing.
	ifsNormalizedRaw := shellparse.NormalizeIFS(ctx.RawCommand)

	// Those same strings.Contains(raw, ...) rules need the unset-parameter
	// splice folded for exactly the same reason — "pip con${zqx}fig set ...
	// extra-index-url" runs `pip config set` but contains no such substring.
	unsetFoldedRaw := shellparse.NormalizeUnsetParamExp(ctx.RawCommand)

	// And the same again for a whole-word brace group — "{pip,config,set,
	// global.extra-index-url,https://evil.example/simple/}" runs exactly
	// `pip config set global.extra-index-url ...`, but contains no literal
	// "pip config set" substring until expanded (issue #3217).
	braceFoldedRaw := shellparse.NormalizeBraceWordList(ctx.RawCommand)

	// 1. Run built-in Go semantic rules (classifies intents into ctx.Intents)
	for _, rule := range a.rules {
		if len(rule.IntentExclude) > 0 && ctx.CommandFacts.HasAny(rule.IntentExclude) {
			continue
		}
		matched := rule.Match(ctx.Parsed, ctx.RawCommand)
		if !matched && ifsNormalizedRaw != "" {
			matched = rule.Match(ctx.Parsed, ifsNormalizedRaw)
		}
		if !matched && unsetFoldedRaw != "" {
			matched = rule.Match(ctx.Parsed, unsetFoldedRaw)
		}
		if !matched && braceFoldedRaw != "" {
			matched = rule.Match(ctx.Parsed, braceFoldedRaw)
		}
		if matched {
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
						seg.Executable == "rustscan" || seg.Executable == "zmap" {
						return true
					}
				}
				return false
			},
			Decision:    "AUDIT",
			Confidence:  0.85,
			Reason:      "Network scanning tool detected",
			TaxonomyRef: "reconnaissance/network-discovery/port-scan",
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
			// matchesIndirectPattern is a raw substring search, so it cannot
			// distinguish `python3 -c "shutil.rmtree(...)"` (executes) from a
			// `cat >> fixture.py <<'EOF'` heredoc body that merely CONTAINS
			// that text as data being written to disk (issue #3054).
			// in_interpreter_heredoc is deliberately NOT excluded — a heredoc
			// fed directly to python (`python3 <<EOF`) really does execute.
			IntentExclude: []string{LabelIsBashComment, LabelIsDocText, LabelInHeredoc, LabelIsSelfMgmt},
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
			// Same raw-substring-search FP class as sem-block-python-rmtree above.
			IntentExclude: []string{LabelIsBashComment, LabelIsDocText, LabelInHeredoc, LabelIsSelfMgmt},
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
// code containing dangerous patterns.
//
// Before issue #3466, this matched via a bare raw-substring search: "does the
// command text contain an interpreter name AND a dangerous pattern, anywhere,
// in any context." That cannot distinguish a live call from the same text
// appearing as inert data — a Python string literal being searched for and
// replaced, a grep pattern, or (measured live during this fix) a rule-ID
// substring like "sem-block-python-rmtree" combined with a search string
// containing "shutil.rmtree". Both false-positived a BLOCK.
//
// The fix inspects the actual code the interpreter runs, extracted from its
// two known carriers — a `-c` payload (via shellparse.ExtractInlineCode,
// which already dequotes it correctly) and a heredoc body fed directly to it
// — and checks whether the pattern appears there as live code rather than
// inside a Python string literal or "#" comment (pythonCodeContainsAny).
// `parsed.Subcommands` is never populated for these interpreters in the first
// place: shellparse.CarriesShellSource deliberately excludes CodeInterpreters
// (python/node/...) so their inline code is never re-parsed as shell source —
// the old subcommand-scanning branch here was dead code.
//
// No interpreter invocation at all (no matching segment, no heredoc) now
// means no match — never falling back to the bare substring scan, which is
// exactly the mechanism that produced the false positives above.
func matchesIndirectPattern(parsed *ParsedCommand, raw string, interpreters []string, patterns []string) bool {
	interpSet := make(map[string]bool, len(interpreters))
	for _, in := range interpreters {
		interpSet[in] = true
	}

	for _, seg := range allSegments(parsed) {
		if !interpSet[seg.Executable] {
			continue
		}
		if code := shellparse.ExtractInlineCode(seg); code != "" && pythonCodeContainsAny(code, patterns) {
			return true
		}
	}

	// A heredoc fed directly to the interpreter runs its body exactly like a
	// `-c` payload, but shellparse's AST-based seg.HeredocBody is populated
	// only for shell interpreters (bash/sh/zsh) — deliberately, so a
	// python/node heredoc body is never mistaken for shell source (see
	// shellparse.CarriesShellSource's doc comment). Scan the raw text for the
	// same shape instead, cheaply gated on "<<" being present at all so the
	// common (heredoc-free) command pays nothing extra.
	if strings.Contains(raw, "<<") {
		for _, body := range interpreterHeredocBodies(raw, interpreters) {
			if pythonCodeContainsAny(body, patterns) {
				return true
			}
		}
	}

	return false
}

// interpreterHeredocIntroPattern builds a regex matching one of interpreters
// introducing a heredoc: "python3 - <<'PY'". Anchored on both sides with \b
// so "ipython3 <<EOF" does not count as a "python3" invocation. Compiled
// fresh per call, but only reached when raw already contains "<<" — see the
// gate in matchesIndirectPattern.
func interpreterHeredocIntroPattern(interpreters []string) *regexp.Regexp {
	quoted := make([]string, len(interpreters))
	for i, in := range interpreters {
		quoted[i] = regexp.QuoteMeta(in)
	}
	return regexp.MustCompile(`\b(?:` + strings.Join(quoted, "|") + `)\b[^\n<]*<<-?\s*(['"]?)(\w+)`)
}

// interpreterHeredocBodies extracts the literal body text of every heredoc
// fed directly to one of interpreters in raw (e.g. "python3 - <<'PY'\n...\nPY").
// Best-effort regex extraction scoped to this rule family; RE2 (Go's regexp)
// has no backreferences, so the closing delimiter is located with a second,
// separately-compiled pattern rather than in one expression.
func interpreterHeredocBodies(raw string, interpreters []string) []string {
	intro := interpreterHeredocIntroPattern(interpreters)
	var bodies []string
	for _, m := range intro.FindAllStringSubmatchIndex(raw, -1) {
		delim := raw[m[4]:m[5]]
		if delim == "" {
			continue
		}
		matchEnd := m[1]
		nl := strings.IndexByte(raw[matchEnd:], '\n')
		if nl < 0 {
			continue
		}
		bodyStart := matchEnd + nl + 1
		rest := raw[bodyStart:]
		closeRe := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(delim) + `\s*$`)
		loc := closeRe.FindStringIndex(rest)
		if loc == nil {
			continue
		}
		bodies = append(bodies, rest[:loc[0]])
	}
	return bodies
}

// pythonCodeContainsAny reports whether any of patterns appears in source as
// live Python code — outside a string literal (single/double/triple-quoted)
// or a "#" comment. A best-effort character scan, not a full tokenizer: it
// tracks Python's quoting rules (including triple-quoted strings and
// backslash escapes) well enough to tell "shutil.rmtree(" as code apart from
// the identical text sitting inside `old = "...shutil.rmtree(...)..."`
// (issue #3466's reported false positive).
func pythonCodeContainsAny(source string, patterns []string) bool {
	const (
		stateNone = iota
		stateSingle
		stateDouble
		stateTripleSingle
		stateTripleDouble
	)
	state := stateNone
	n := len(source)
	for i := 0; i < n; i++ {
		c := source[i]
		switch state {
		case stateNone:
			switch {
			case c == '#':
				nl := strings.IndexByte(source[i:], '\n')
				if nl < 0 {
					return false
				}
				i += nl
				continue
			case strings.HasPrefix(source[i:], `'''`):
				state = stateTripleSingle
				i += 2
				continue
			case strings.HasPrefix(source[i:], `"""`):
				state = stateTripleDouble
				i += 2
				continue
			case c == '\'':
				state = stateSingle
				continue
			case c == '"':
				state = stateDouble
				continue
			}
			for _, pat := range patterns {
				if strings.HasPrefix(source[i:], pat) {
					return true
				}
			}
		case stateSingle, stateDouble:
			if c == '\\' && i+1 < n {
				i++
				continue
			}
			quote := byte('\'')
			if state == stateDouble {
				quote = '"'
			}
			if c == quote {
				state = stateNone
			}
		case stateTripleSingle, stateTripleDouble:
			delim := `'''`
			if state == stateTripleDouble {
				delim = `"""`
			}
			if c == '\\' && i+1 < n {
				i++
				continue
			}
			if strings.HasPrefix(source[i:], delim) {
				state = stateNone
				i += 2
			}
		}
	}
	return false
}
