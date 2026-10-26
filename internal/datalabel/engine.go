package datalabel

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Engine is the core data label detection engine. It holds pre-compiled
// patterns and a shared Aho-Corasick automaton for keyword matching.
// A nil Engine is safe to call — ScanText returns nil.
type Engine struct {
	labels           []compiledLabel
	keywordAutomaton *ACAutomaton   // nil if no keywords across all labels
	keywordIndex     []keywordOwner // maps AC pattern ID → (labelIdx, patternIdx)
}

type compiledLabel struct {
	config         DataLabelConfig
	regexes        []*regexp.Regexp // one per pattern (nil if pattern has no regex)
	contextRegexes []*regexp.Regexp // one per pattern (nil if no context)
}

// keywordOwner maps an Aho-Corasick pattern ID back to its owning label and pattern.
type keywordOwner struct {
	labelIdx   int
	patternIdx int
}

// NewEngine creates a detection engine from the given configs.
// Returns (nil, nil) if configs is empty — caller should skip registration.
// Returns an error if any regex pattern fails to compile, or if a pattern
// references an unknown validator name (fail at startup per BUG-DL-005).
func NewEngine(configs []DataLabelConfig) (*Engine, error) {
	if len(configs) == 0 {
		return nil, nil
	}

	e := &Engine{
		labels: make([]compiledLabel, len(configs)),
	}

	var acPatterns []ACPattern
	acID := 0

	for i, cfg := range configs {
		cl := compiledLabel{
			config:         cfg,
			regexes:        make([]*regexp.Regexp, len(cfg.Patterns)),
			contextRegexes: make([]*regexp.Regexp, len(cfg.Patterns)),
		}

		for j, pat := range cfg.Patterns {
			// Compile regex
			if pat.Regex != "" {
				re, err := regexp.Compile(pat.Regex)
				if err != nil {
					return nil, fmt.Errorf("data label %q pattern %d: invalid regex: %w", cfg.ID, j, err)
				}
				cl.regexes[j] = re
			}

			// Compile context regex
			if pat.Context != "" {
				re, err := regexp.Compile("(?i)" + pat.Context)
				if err != nil {
					return nil, fmt.Errorf("data label %q pattern %d: invalid context regex: %w", cfg.ID, j, err)
				}
				cl.contextRegexes[j] = re
			}

			// Validator name check — fail fast on typos so bad config can't
			// silently fail-open at scan time (BUG-DL-005).
			if !IsKnownValidator(pat.Validator) {
				return nil, fmt.Errorf("data label %q pattern %d: unknown validator %q (supported: luhn)", cfg.ID, j, pat.Validator)
			}

			// Collect keywords for Aho-Corasick
			for _, kw := range pat.Keywords {
				acPatterns = append(acPatterns, ACPattern{
					Text:          kw,
					ID:            acID,
					CaseSensitive: pat.CaseSensitive,
				})
				e.keywordIndex = append(e.keywordIndex, keywordOwner{
					labelIdx:   i,
					patternIdx: j,
				})
				acID++
			}
		}

		e.labels[i] = cl
	}

	// Build single AC automaton for all keywords
	e.keywordAutomaton = NewACAutomaton(acPatterns)

	return e, nil
}

// ScanText scans text for all configured data labels and returns matches.
// toolName and direction are used for scope filtering (MCP context).
// For shell commands, pass toolName="" and direction="".
//
// BLOCK semantics (BUG-DL-002): as soon as any tier produces a BLOCK match,
// ScanText returns a slice containing only that single BLOCK finding — prior
// AUDIT findings are discarded. This prevents corrupted finding sets where
// keyword-tier AUDITs leak into a regex-tier BLOCK return.
func (e *Engine) ScanText(text, toolName, direction string) []DataLabelMatch {
	if e == nil || len(e.labels) == 0 {
		return nil
	}

	// Apply max scan bytes truncation
	maxBytes := defaultMaxScanBytes
	// Use the smallest non-zero MaxScanBytes across all labels
	for _, cl := range e.labels {
		if cl.config.ScanScope.MaxScanBytes > 0 && cl.config.ScanScope.MaxScanBytes < maxBytes {
			maxBytes = cl.config.ScanScope.MaxScanBytes
		}
	}
	if len(text) > maxBytes {
		text = text[:maxBytes]
	}

	var matches []DataLabelMatch

	// Tier 1: Keyword scan (single pass for all labels)
	keywordHits := e.keywordAutomaton.Search(text) // nil automaton returns nil

	// Process keyword matches
	for _, hit := range keywordHits {
		owner := e.keywordIndex[hit.PatternID]
		cl := e.labels[owner.labelIdx]

		// Tier 0: Scope check
		if !matchesScope(cl.config.ScanScope, toolName, direction) {
			continue
		}

		matchText := text[hit.Start:hit.End]
		m := DataLabelMatch{
			LabelID:    cl.config.ID,
			LabelName:  cl.config.Name,
			Decision:   cl.config.Decision,
			Confidence: cl.config.Confidence,
			Reason:     cl.config.Reason,
			PatternIdx: owner.patternIdx,
			MatchText:  truncateMatch(matchText),
		}

		// Early termination on BLOCK — return only the BLOCK finding.
		if cl.config.Decision == "BLOCK" {
			return []DataLabelMatch{m}
		}

		matches = append(matches, m)
	}

	// Tier 2: Regex scan (per-label, only if scope matches)
	for i := range e.labels {
		cl := &e.labels[i]

		// Tier 0: Scope check
		if !matchesScope(cl.config.ScanScope, toolName, direction) {
			continue
		}

		for j, re := range cl.regexes {
			if re == nil {
				continue
			}

			loc := re.FindStringIndex(text)
			if loc == nil {
				continue
			}

			matchText := text[loc[0]:loc[1]]

			// Context check: if a context regex is defined, match it against
			// a window around the primary match (BUG-DL-001). Matching against
			// the full text turns any context regex into a global "word is
			// present anywhere" check, providing no FP discrimination.
			if cl.contextRegexes[j] != nil {
				window := contextWindow(text, loc[0], loc[1])
				if !cl.contextRegexes[j].MatchString(window) {
					continue
				}
			}

			// Tier 3: Validator check
			pat := cl.config.Patterns[j]
			if pat.Validator != "" {
				if !Validate(pat.Validator, matchText) {
					continue
				}
			}

			m := DataLabelMatch{
				LabelID:    cl.config.ID,
				LabelName:  cl.config.Name,
				Decision:   cl.config.Decision,
				Confidence: cl.config.Confidence,
				Reason:     cl.config.Reason,
				PatternIdx: j,
				MatchText:  truncateMatch(matchText),
			}

			// Early termination on BLOCK — return only the BLOCK finding,
			// pruning any prior AUDIT findings accumulated from tier 1.
			if cl.config.Decision == "BLOCK" {
				return []DataLabelMatch{m}
			}

			matches = append(matches, m)

			// One match per label is sufficient — move to next label
			break
		}
	}

	return matches
}

// Scrub returns text with every span a configured label matches replaced by
// "[LABEL:<id>]" (#4448). It is the audit-record counterpart of ScanText: a
// label BLOCK must not deliver the value it stopped to the audit log or the
// SaaS, so the record keeps the label id and drops the bytes.
//
// Differences from ScanText, each deliberate:
//   - every match is replaced, not the first per label (a command carrying two
//     customer ids leaks the second if only one is removed);
//   - scope is ignored: scope decides what is DETECTED, and over-redacting a
//     tool outside a label's scope costs a placeholder, while under-redacting
//     costs the value;
//   - no max-scan-bytes cap: a cap here would leave the tail unredacted.
//
// Overlapping spans merge; the earliest label's id names the merged span.
// A nil Engine returns text unchanged.
func (e *Engine) Scrub(text string) string {
	if e == nil || len(e.labels) == 0 || text == "" {
		return text
	}

	type span struct {
		start, end int
		label      string
	}
	var spans []span

	if e.keywordAutomaton != nil {
		for _, hit := range e.keywordAutomaton.Search(text) {
			owner := e.keywordIndex[hit.PatternID]
			spans = append(spans, span{hit.Start, hit.End, e.labels[owner.labelIdx].config.ID})
		}
	}

	for i := range e.labels {
		cl := &e.labels[i]
		for j, re := range cl.regexes {
			if re == nil {
				continue
			}
			for _, loc := range re.FindAllStringIndex(text, -1) {
				if loc[1] <= loc[0] {
					continue
				}
				if cl.contextRegexes[j] != nil &&
					!cl.contextRegexes[j].MatchString(contextWindow(text, loc[0], loc[1])) {
					continue
				}
				if v := cl.config.Patterns[j].Validator; v != "" && !Validate(v, text[loc[0]:loc[1]]) {
					continue
				}
				spans = append(spans, span{loc[0], loc[1], cl.config.ID})
			}
		}
	}

	if len(spans) == 0 {
		return text
	}

	sort.SliceStable(spans, func(a, b int) bool { return spans[a].start < spans[b].start })

	var out strings.Builder
	pos := 0
	for i := 0; i < len(spans); {
		s := spans[i]
		end := s.end
		i++
		for i < len(spans) && spans[i].start < end {
			if spans[i].end > end {
				end = spans[i].end
			}
			i++
		}
		if s.start > pos {
			out.WriteString(text[pos:s.start])
		}
		out.WriteString("[LABEL:" + s.label + "]")
		pos = end
	}
	out.WriteString(text[pos:])
	return out.String()
}

// contextWindow returns a slice of text covering ±contextWindowBytes around
// the given match range. Used by BUG-DL-001 fix so context regexes are
// evaluated against the vicinity of a match, not the full document.
func contextWindow(text string, start, end int) string {
	s := start - contextWindowBytes
	if s < 0 {
		s = 0
	}
	e := end + contextWindowBytes
	if e > len(text) {
		e = len(text)
	}
	return text[s:e]
}

// matchesScope checks whether the given toolName and direction fall within
// the label's scan scope. Semantics (BUG-DL-004):
//
//   - Shell context = toolName == "" AND direction == "" (the convention
//     established by the shell-command analyzer).
//   - In shell context, scope.Shell is consulted: nil defaults to matching
//     only when no MCP filters (Tools/Directions) are set; true always
//     matches; false never matches.
//   - In MCP context, Tools and Directions filters apply. If Tools is set
//     but toolName is empty (e.g., response path with no correlation), the
//     label does not match — use scope.Directions for inbound-only labels
//     that don't depend on tool correlation.
func matchesScope(scope ScanScopeConfig, toolName, direction string) bool {
	isShell := toolName == "" && direction == ""

	if isShell {
		if scope.Shell != nil {
			return *scope.Shell
		}
		// Legacy default: a label with any Tools/Directions filter is
		// considered MCP-scoped; shell commands do not match unless
		// scope.Shell=true is explicitly set.
		if len(scope.Tools) > 0 || len(scope.Directions) > 0 {
			return false
		}
		return true
	}

	// MCP context — apply direction filter
	if len(scope.Directions) > 0 {
		found := false
		for _, d := range scope.Directions {
			if d == direction {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// MCP context — apply tool name filter
	if len(scope.Tools) > 0 {
		if toolName == "" {
			// Response path without tool correlation — can't match a tools filter.
			// Customers that want to scan responses should rely on Directions.
			return false
		}
		found := false
		for _, pattern := range scope.Tools {
			if matched, _ := filepath.Match(pattern, toolName); matched {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// truncateMatch truncates match text for audit log readability.
func truncateMatch(s string) string {
	if len(s) <= maxMatchTextLen {
		return s
	}
	return s[:maxMatchTextLen-3] + "..."
}
