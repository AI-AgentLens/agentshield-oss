package datalabel

import (
	"fmt"
	"path/filepath"
	"regexp"
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
// Returns an error if any regex pattern fails to compile (fail at startup).
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
		matches = append(matches, DataLabelMatch{
			LabelID:    cl.config.ID,
			LabelName:  cl.config.Name,
			Decision:   cl.config.Decision,
			Confidence: cl.config.Confidence,
			Reason:     cl.config.Reason,
			PatternIdx: owner.patternIdx,
			MatchText:  truncateMatch(matchText),
		})

		// Early termination: if we found a BLOCK, stop scanning
		if cl.config.Decision == "BLOCK" {
			return matches
		}
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

			// Context check: if a context regex is defined, it must also match
			if cl.contextRegexes[j] != nil {
				if !cl.contextRegexes[j].MatchString(text) {
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

			matches = append(matches, DataLabelMatch{
				LabelID:    cl.config.ID,
				LabelName:  cl.config.Name,
				Decision:   cl.config.Decision,
				Confidence: cl.config.Confidence,
				Reason:     cl.config.Reason,
				PatternIdx: j,
				MatchText:  truncateMatch(matchText),
			})

			// Early termination on BLOCK
			if cl.config.Decision == "BLOCK" {
				return matches
			}

			// One match per label is sufficient — move to next label
			break
		}
	}

	return matches
}

// matchesScope checks whether the given toolName and direction fall within
// the label's scan scope. Empty scope fields mean "match everything".
func matchesScope(scope ScanScopeConfig, toolName, direction string) bool {
	// Direction check
	if len(scope.Directions) > 0 && direction != "" {
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

	// Tool name glob check
	if len(scope.Tools) > 0 && toolName != "" {
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
