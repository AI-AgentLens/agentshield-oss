// Package main implements check-regex-anchors, a ratcheting shape lint for
// the `command_regex` of every pack rule (#3846).
//
// # The shape it flags, and why (#3842)
//
// ts-block-cicd-cp-mv shipped for months with
//
//	(cp|mv)(\s+-\S+)*\s+\S+\s+(\./)?(.*\.github/workflows/|Jenkinsfile|...)
//
// and BLOCKed a read-only command whose text contained the word "mcp" in one
// statement and a workflow path in a *later* statement. Two properties of the
// regex conspired: the leading verb alternation `(cp|mv)` is not anchored to
// a word start, so the `cp` inside `mcp` satisfies it; and the `.*` that
// reaches the target path spans `;`, `&&`, `|` and any other statement
// boundary, so the two halves of the "attack" may come from two unrelated
// statements. #3845 fixed that ONE rule (`\b(cp|mv)` + `[^;&|\n]*`); #3846
// measured that the shape is an authoring convention shared by dozens of
// rules, i.e. a generator, not an output. This gate is the fitness function
// on the generator: today's instances are baselined debt, a NEW one fails
// CI, and a baselined one that gets fixed must be removed from the baseline
// so the list can only shrink.
//
// # The predicate, stated so a reader can apply it by eye
//
// A `command_regex` is flagged when BOTH hold:
//
//  1. Unanchored leading verb alternation. After stripping any leading inline
//     flag groups such as `(?i)`, the regex begins with a plain group — `(`,
//     `(?:` or a flag-scoped `(?i:` — and at least one of that group's
//     top-level alternatives is a bare word matching `[a-z][a-z0-9_-]*`.
//     Nothing precedes the group, so nothing anchors it: `\b(cp|mv)`,
//     `^(cp|mv)` and `(?:^|\s)(cp|mv)` are NOT flagged (they begin with an
//     anchor, or with a group whose alternatives are anchors, not words);
//     `(cp|mv)` and `(curl|wget)\b` ARE (a trailing `\b` anchors the END of
//     the word — `xcurl\b` still matches).
//  2. Unbounded span. Somewhere AFTER that group's closing paren the regex
//     contains an unescaped `.*` or `.+` outside a character class. `\.\*`
//     is a literal, `[.*]` is a class, `[^;&|\n]*` is the bounded
//     replacement #3845 used — none of those count.
//
// A regex with only one of the two halves is not flagged: `(cat|less)\s+x`
// has no span and cannot reach a later statement; `\b(cp|mv)\s+.*x` still
// spans but at least cannot be satisfied from inside another word. Both are
// weaker than the #3842 shape and are not this gate's question.
//
// # A decision this gate makes that the issue left open
//
// A non-word alternative does NOT disqualify the group: `(cp|mv|/usr/bin/cp)`
// is flagged because its `cp` branch carries exactly the #3842 hazard
// regardless of what the other branches look like. The alternative —
// require ALL alternatives to be bare words — was rejected because
// `(python3?|node|ruby)`-style groups, where one branch has a quantifier,
// would silently exempt the bare `node` and `ruby` branches, and a new rule
// could slip past the ratchet by adding any decorated alternative.
//
// # Deliberately NOT covered
//
//   - Only the FIRST group is inspected. `(sudo\s+)?(rm|shred)\s+.*` has the
//     hazard on its second group but its first has no bare-word alternative,
//     so it is not flagged.
//   - A leading literal with no group, `cp\s+.*x`, has the same hazard and
//     is not flagged: the issue scoped the class to the alternation shape.
//   - Named groups `(?P<n>...)` / `(?<n>...)` are not treated as plain
//     groups (0 in the corpus at the leading position on introduction).
//   - Only `.*` and `.+` count as a span; `[\s\S]*` and `.{n,}` do not.
//   - `command_regex_exclude` is not examined: an over-broad exclude
//     suppresses a rule, which is a different (fail-open) hazard.
//
// Each of these is a measured gap, not an oversight; widen the predicate
// deliberately and re-seed the baseline in the same PR.
//
// # Contract, shared with the sibling gates
//
// Reads packs/ and nothing else — no taxonomy tree, no AI_risk_compliance
// coupling (workspace CLAUDE.md, invariant 3). Every id-bearing section is
// walked, not just `rules:` (cmd/check-duplicate-rule-ids found 356 of 3520
// ids outside `rules:`); a section that carries ids but is not in
// idBearingSections is a hard error, so the gate cannot widen its own scope
// silently. Examining 0 regexes is exit 2, not a pass (#3130).
//
// Exit codes: 0 no delta against the baseline; 1 a NEW flagged rule or a
// STALE baseline row (a listed id that no longer flags — delete the row);
// 2 unusable input.
//
// Usage:
//
//	go run ./cmd/check-regex-anchors -v
//	go run ./cmd/check-regex-anchors -write-baseline   # re-seed (review the diff)
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// idBearingSections mirrors cmd/check-duplicate-rule-ids: every top-level pack
// key whose entries carry an `id`. Kept as a local list on purpose — an
// unknown id-bearing section is refused rather than scanned or skipped.
var idBearingSections = map[string]bool{
	"rules":            true,
	"structural_rules": true,
	"resource_rules":   true,
	"semantic_rules":   true,
	"value_limits":     true,
}

// site is one `match.command_regex` value and where it lives.
type site struct {
	ID    string
	File  string
	Line  int
	Regex string
}

// key is what the baseline records. Rule ids are the stable handle; a rule
// without one (the loader would reject it anyway) falls back to file:line so
// it is at least reported.
func (s site) key() string {
	if s.ID != "" {
		return s.ID
	}
	return fmt.Sprintf("%s:%d", s.File, s.Line)
}

// shape is the two halves of the predicate, kept separate so a report (and a
// test) can say WHICH half a regex has.
type shape struct {
	LeadingVerbAlternation bool // half 1: unanchored leading group with a bare-word alternative
	UnboundedSpan          bool // half 2: an unescaped .* or .+ after that group
}

func (s shape) flagged() bool { return s.LeadingVerbAlternation && s.UnboundedSpan }

var (
	leadingFlags = regexp.MustCompile(`^\(\?[a-zA-Z-]+\)`)
	bareWord     = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
)

// classify applies the predicate documented in the package comment.
func classify(re string) shape {
	s := strings.TrimSpace(re)
	for {
		loc := leadingFlags.FindStringIndex(s)
		if loc == nil {
			break
		}
		s = s[loc[1]:]
	}
	start, end, ok := leadingPlainGroup(s)
	if !ok {
		// No leading plain group: half 1 cannot hold. Half 2 is still
		// reported over the whole regex so a report can say "span only".
		return shape{UnboundedSpan: hasUnboundedSpan(s)}
	}
	var out shape
	for _, alt := range splitTopLevel(s[start:end]) {
		if bareWord.MatchString(alt) {
			out.LeadingVerbAlternation = true
			break
		}
	}
	// end is the index of the closing paren; the span must come after it.
	out.UnboundedSpan = hasUnboundedSpan(s[end+1:])
	return out
}

// leadingPlainGroup reports whether s begins with a plain group — `(`, `(?:`
// or `(?flags:` — and returns the [start, end) of its content, where end is
// the index of the matching close paren. Lookaround and named-group openers
// are not plain groups. An unclosed paren is not a group either (RE2 would
// refuse to compile it, and the loader surfaces that).
func leadingPlainGroup(s string) (start, end int, ok bool) {
	if !strings.HasPrefix(s, "(") {
		return 0, 0, false
	}
	start = 1
	if strings.HasPrefix(s, "(?") {
		i := 2
		for i < len(s) && (s[i] == '-' || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z')) {
			i++
		}
		if i >= len(s) || s[i] != ':' {
			return 0, 0, false // (?<name>, (?P<name>, (?=, (?! ...
		}
		start = i + 1
	}
	depth := 1
	inClass := false
	for i := start; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			i++ // skip the escaped char
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
			// A ']' immediately after '[' or '[^' is a literal, not a close.
			if i+1 < len(s) && s[i+1] == '^' {
				i++
			}
			if i+1 < len(s) && s[i+1] == ']' {
				i++
			}
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return start, i, true
			}
		}
	}
	return 0, 0, false
}

// splitTopLevel splits group content on '|' at nesting depth 0 and outside
// character classes.
func splitTopLevel(content string) []string {
	var alts []string
	depth := 0
	inClass := false
	last := 0
	for i := 0; i < len(content); i++ {
		c := content[i]
		switch {
		case c == '\\':
			i++
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
			if i+1 < len(content) && content[i+1] == '^' {
				i++
			}
			if i+1 < len(content) && content[i+1] == ']' {
				i++
			}
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == '|' && depth == 0:
			alts = append(alts, content[last:i])
			last = i + 1
		}
	}
	return append(alts, content[last:])
}

// hasUnboundedSpan reports whether s contains an unescaped `.` immediately
// followed by `*` or `+`, outside a character class.
func hasUnboundedSpan(s string) bool {
	inClass := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			i++
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
			if i+1 < len(s) && s[i+1] == '^' {
				i++
			}
			if i+1 < len(s) && s[i+1] == ']' {
				i++
			}
		case c == '.':
			if i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '+') {
				return true
			}
		}
	}
	return false
}

// collect walks packsDir and returns every match.command_regex it finds, in
// file order. Disabled `_`-prefixed packs are skipped, as everywhere else.
func collect(packsDir string) ([]site, error) {
	var sites []site
	err := filepath.WalkDir(packsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if strings.HasPrefix(name, "_") {
			return nil
		}
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var doc map[string]yaml.Node
		if err := yaml.Unmarshal(b, &doc); err != nil {
			return nil // malformed packs are the loader's to report (#2188)
		}
		for key, node := range doc {
			if node.Kind != yaml.SequenceNode {
				continue
			}
			carriesID := false
			for _, item := range node.Content {
				if item.Kind == yaml.MappingNode && mappingValue(item, "id") != nil {
					carriesID = true
					break
				}
			}
			if !carriesID {
				continue
			}
			if !idBearingSections[key] {
				return fmt.Errorf("%s: unknown id-bearing section %q — add it to idBearingSections "+
					"in cmd/check-regex-anchors/main.go, deliberately", path, key)
			}
			for _, item := range node.Content {
				if item.Kind != yaml.MappingNode {
					continue
				}
				match := mappingValue(item, "match")
				if match == nil || match.Kind != yaml.MappingNode {
					continue
				}
				re := mappingValue(match, "command_regex")
				if re == nil || re.Kind != yaml.ScalarNode {
					continue
				}
				id := ""
				if n := mappingValue(item, "id"); n != nil {
					id = n.Value
				}
				sites = append(sites, site{ID: id, File: path, Line: re.Line, Regex: re.Value})
			}
		}
		return nil
	})
	return sites, err
}

// mappingValue returns the value node for key in a mapping node, or nil.
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// loadBaseline reads one rule id per line, ignoring blanks and '#' comments.
// A duplicate line is refused: the file is a set.
func loadBaseline(path string) (map[string]bool, error) {
	out := map[string]bool{}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil // absent means "expect zero"
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	ln := 0
	for sc.Scan() {
		ln++
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if out[line] {
			return nil, fmt.Errorf("%s:%d: %s listed twice in the baseline", path, ln, line)
		}
		out[line] = true
	}
	return out, sc.Err()
}

const baselineHeader = `# baseline.txt — pack rules whose command_regex has the #3842 shape:
# an unanchored leading verb alternation, e.g. (cat|less|cp|mv), AND an
# unescaped .* / .+ later in the regex. See cmd/check-regex-anchors for
# the exact predicate. Seeded from the corpus on introduction (#3846).
#
# Contract: a line here is recorded debt, not an endorsement. The gate
# fails on a NEW flagged rule that is not listed, and on a STALE row —
# a listed id that no longer flags — so this list can only shrink.
# Fix a rule as #3845 did: prefix \b (or (?:^|\s)) to the verb group and
# replace the spanning .* with [^;&|\n]*, then delete its row here.
#
# Format: <rule id>, one per line, sorted. Comments after '#'.
# Re-seed (and review the diff): go run ./cmd/check-regex-anchors -write-baseline
#
`

func main() {
	packsDir := flag.String("packs", "packs", "Root directory to walk for pack YAML")
	baselinePath := flag.String("baseline", "cmd/check-regex-anchors/baseline.txt",
		"Baseline listing already-flagged rule ids, one per line")
	writeBaseline := flag.Bool("write-baseline", false, "Rewrite the baseline from the current corpus")
	verbose := flag.Bool("v", false, "Also list baselined findings")
	flag.Parse()
	os.Exit(run(*packsDir, *baselinePath, *writeBaseline, *verbose, os.Stdout, os.Stderr))
}

// run is main() with the exit code returned instead of taken, so the ratchet
// can be tested in both directions. 0 = no delta, 1 = delta, 2 = unusable.
func run(packsDir, baselinePath string, writeBaseline, verbose bool, out, errw io.Writer) int {
	sites, err := collect(packsDir)
	if err != nil {
		_, _ = fmt.Fprintf(errw, "error: %v\n", err)
		return 2
	}
	if len(sites) == 0 {
		_, _ = fmt.Fprintf(errw, "error: examined 0 command_regex values under %s — refusing to report a vacuous pass\n", packsDir)
		return 2
	}

	flaggedBy := map[string]site{}
	for _, s := range sites {
		if classify(s.Regex).flagged() {
			if _, dup := flaggedBy[s.key()]; !dup {
				flaggedBy[s.key()] = s
			}
		}
	}
	flaggedKeys := make([]string, 0, len(flaggedBy))
	for k := range flaggedBy {
		flaggedKeys = append(flaggedKeys, k)
	}
	sort.Strings(flaggedKeys)

	if writeBaseline {
		var sb strings.Builder
		sb.WriteString(baselineHeader)
		for _, k := range flaggedKeys {
			sb.WriteString(k)
			sb.WriteString("\n")
		}
		if err := os.WriteFile(baselinePath, []byte(sb.String()), 0o644); err != nil {
			_, _ = fmt.Fprintf(errw, "error: write baseline: %v\n", err)
			return 2
		}
		_, _ = fmt.Fprintf(out, "wrote %d flagged rule(s) to %s (%d command_regex examined)\n",
			len(flaggedKeys), baselinePath, len(sites))
		return 0
	}

	baseline, err := loadBaseline(baselinePath)
	if err != nil {
		_, _ = fmt.Fprintf(errw, "error: %v\n", err)
		return 2
	}

	var fresh, stale []string
	for _, k := range flaggedKeys {
		if !baseline[k] {
			fresh = append(fresh, k)
		}
	}
	for k := range baseline {
		if _, ok := flaggedBy[k]; !ok {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)

	if verbose {
		for _, k := range flaggedKeys {
			if baseline[k] {
				s := flaggedBy[k]
				_, _ = fmt.Fprintf(out, "BASELINED  %s  [%s:%d]\n    command_regex: %s\n", k, s.File, s.Line, s.Regex)
			}
		}
	}
	for _, k := range fresh {
		s := flaggedBy[k]
		_, _ = fmt.Fprintf(out, "NEW  %s  [%s:%d]\n", k, s.File, s.Line)
		_, _ = fmt.Fprintf(out, "    command_regex: %s\n", s.Regex)
		_, _ = fmt.Fprintln(out, "    The leading verb alternation is not anchored to a word start, and a later")
		_, _ = fmt.Fprintln(out, "    .* / .+ spans statement boundaries — the #3842 shape (\"cp\" inside \"mcp\" in")
		_, _ = fmt.Fprintln(out, "    one statement plus a target path in a later one satisfied it). Prefix \\b")
		_, _ = fmt.Fprintln(out, "    (or (?:^|\\s)) and replace the span with [^;&|\\n]* as #3845 did. If the span")
		_, _ = fmt.Fprintf(out, "    is deliberate, add the id to %s and say why in the PR.\n\n", baselinePath)
	}
	for _, k := range stale {
		_, _ = fmt.Fprintf(out, "STALE  %s\n", k)
		_, _ = fmt.Fprintln(out, "    No longer flagged (fixed, renamed or removed). Delete this baseline row;")
		_, _ = fmt.Fprintln(out, "    the list may only shrink.")
		_, _ = fmt.Fprintln(out)
	}

	summary := fmt.Sprintf("%d command_regex examined, %d baselined, %d new, %d stale",
		len(sites), len(baseline), len(fresh), len(stale))
	if len(fresh) > 0 || len(stale) > 0 {
		_, _ = fmt.Fprintf(errw, "FAIL: %s\n", summary)
		return 1
	}
	_, _ = fmt.Fprintf(out, "OK: %s\n", summary)
	return 0
}
