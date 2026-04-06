package datalabel

import "strings"

// ACPattern is an input pattern for the Aho-Corasick automaton.
type ACPattern struct {
	Text          string
	ID            int  // back-reference to (labelIdx, patternIdx)
	CaseSensitive bool
}

// ACMatch is a search result from the automaton.
type ACMatch struct {
	PatternID int // matches ACPattern.ID
	Start     int // byte offset in the searched text
	End       int // byte offset (exclusive)
}

// ACAutomaton is a simple Aho-Corasick multi-pattern string matcher.
// It builds two tries: one for case-sensitive patterns and one for
// case-insensitive patterns (lowered at build and search time).
type ACAutomaton struct {
	sensitive   *acTrie // nil if no case-sensitive patterns
	insensitive *acTrie // nil if no case-insensitive patterns
}

type acNode struct {
	children map[byte]*acNode
	fail     *acNode
	output   []int // pattern IDs that end at this node
}

type acTrie struct {
	root     *acNode
	patterns []acStoredPattern
}

type acStoredPattern struct {
	text string // stored as-is for sensitive, lowered for insensitive
	id   int
}

// NewACAutomaton builds an Aho-Corasick automaton from the given patterns.
// Returns nil if patterns is empty.
func NewACAutomaton(patterns []ACPattern) *ACAutomaton {
	if len(patterns) == 0 {
		return nil
	}

	var sensPatterns, insensPatterns []acStoredPattern
	for _, p := range patterns {
		if p.Text == "" {
			continue
		}
		sp := acStoredPattern{id: p.ID}
		if p.CaseSensitive {
			sp.text = p.Text
			sensPatterns = append(sensPatterns, sp)
		} else {
			sp.text = strings.ToLower(p.Text)
			insensPatterns = append(insensPatterns, sp)
		}
	}

	a := &ACAutomaton{}
	if len(sensPatterns) > 0 {
		a.sensitive = buildTrie(sensPatterns)
	}
	if len(insensPatterns) > 0 {
		a.insensitive = buildTrie(insensPatterns)
	}

	if a.sensitive == nil && a.insensitive == nil {
		return nil
	}
	return a
}

// Search returns all matches of the automaton's patterns in text.
func (a *ACAutomaton) Search(text string) []ACMatch {
	if a == nil {
		return nil
	}

	var matches []ACMatch
	if a.sensitive != nil {
		matches = a.sensitive.search(text, matches)
	}
	if a.insensitive != nil {
		matches = a.insensitive.search(strings.ToLower(text), matches)
	}
	return matches
}

func buildTrie(patterns []acStoredPattern) *acTrie {
	root := &acNode{children: make(map[byte]*acNode)}
	t := &acTrie{root: root, patterns: patterns}

	// Build goto function
	for i, p := range patterns {
		cur := root
		for j := 0; j < len(p.text); j++ {
			ch := p.text[j]
			if cur.children[ch] == nil {
				cur.children[ch] = &acNode{children: make(map[byte]*acNode)}
			}
			cur = cur.children[ch]
		}
		cur.output = append(cur.output, i)
	}

	// Build failure links via BFS
	queue := make([]*acNode, 0)
	for _, child := range root.children {
		child.fail = root
		queue = append(queue, child)
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		for ch, child := range cur.children {
			queue = append(queue, child)

			fail := cur.fail
			for fail != nil && fail.children[ch] == nil {
				fail = fail.fail
			}
			if fail == nil {
				child.fail = root
			} else {
				child.fail = fail.children[ch]
			}
			// Merge output from fail chain
			if child.fail != nil {
				child.output = append(child.output, child.fail.output...)
			}
		}
	}

	return t
}

func (t *acTrie) search(text string, matches []ACMatch) []ACMatch {
	cur := t.root

	for i := 0; i < len(text); i++ {
		ch := text[i]

		for cur != t.root && cur.children[ch] == nil {
			cur = cur.fail
		}
		if next := cur.children[ch]; next != nil {
			cur = next
		}

		for _, pidx := range cur.output {
			p := t.patterns[pidx]
			start := i - len(p.text) + 1
			matches = append(matches, ACMatch{
				PatternID: p.id,
				Start:     start,
				End:       i + 1,
			})
		}
	}

	return matches
}
