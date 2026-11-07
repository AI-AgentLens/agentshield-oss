package policy

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/facts"
)

// PowerShell pack rules (ADR-001 step 5, #4245): a `powershell:` match
// block in the pack YAML, evaluated by EvaluateFacts on what the PowerShell
// lane read. The vocabulary is what the shipped rules need and no more (the
// rule language grows case by case, never as Go per rule): command names,
// parameters by prefix (decision 1), argument words, whole-value paths, the
// commands that feed a command, and -EncodedCommand. See PowerShellMatch.
// The Windows rules of round 2 added three (Match.PowerShellStrings, a
// sibling key for .NET text with no command; PowerShellMatch.ValuesAny and
// OutputRuns); each type comment says which older binaries can read a rule
// that uses it.
//
// Three properties keep these rules out of everything else:
//
//   - A rule with a powershell block may carry no other matcher
//     (validatePowerShellRule), so BuildAnalyzerPipeline routes it to no
//     analyzer and the regex fallback never matches it.
//   - A binary that predates the field reads such a rule with an empty
//     match, and an empty match fires on neither path, on main or v0.2.2619
//     (TestPowerShellRule_InertInThePOSIXLane pins today's half; the PR
//     records the old binary's).
//   - A matcher must name a command at every level, so no rule can match
//     every command.
//
// A rule decides BLOCK, AUDIT or REQUIRE_APPROVAL. ALLOW is refused for now:
// the lane has no ALLOW rule (step 4), and an ALLOW pack rule would be the
// first way to lower its decision, which is a decision for its own review.

// factsRule is a compiled powershell rule: a powershell block (match) or a
// powershell_strings list (strings), never both.
type factsRule struct {
	rule    Rule
	match   *psMatcher
	strings map[string]bool
}

// matches reports whether the rule fires on f.
func (fr factsRule) matches(f facts.Facts, cwd string) bool {
	if fr.match != nil {
		return fr.match.matches(f, cwd)
	}
	for _, s := range f.Strings {
		if fr.strings[asciiFold(s)] {
			return true
		}
	}
	return false
}

// isFactsRule reports whether m is read by EvaluateFacts: a powershell block,
// a powershell_strings list or a powershell_calls block.
func (m Match) isFactsRule() bool {
	return m.PowerShell != nil || len(m.PowerShellStrings) > 0 || m.PowerShellCalls != nil
}

// compileFactsRule compiles a rule isFactsRule accepts.
func compileFactsRule(r Rule) factsRule {
	if r.Match.PowerShell != nil {
		return factsRule{rule: r, match: compilePowerShellMatch(r.Match.PowerShell)}
	}
	if r.Match.PowerShellCalls != nil {
		return factsRule{rule: r, match: compilePowerShellMatch(r.Match.PowerShellCalls)}
	}
	set := map[string]bool{}
	for _, s := range r.Match.PowerShellStrings {
		set[asciiFold(s)] = true
	}
	return factsRule{rule: r, strings: set}
}

// psMatcher is a compiled PowerShellMatch: a command node, or a call node
// (isCall) that matches facts.Facts.Calls.
type psMatcher struct {
	names        map[string]bool
	isCall       bool
	params       []PowerShellParam
	args         map[string]bool
	argsWildcard bool
	paths        []string
	values       []string
	runs         *psOutputRuns
	fedBy        []*psMatcher
	fedAll       []*psMatcher
	encoded      bool
	stdin        bool
	positions    []string
}

// psOutputRuns is a compiled PowerShellOutputRuns.
type psOutputRuns struct {
	params []string
	by     map[string]bool
}

// validatePowerShellRule reports why a rule with a powershell block or a
// powershell_strings list cannot load, or nil.
func validatePowerShellRule(r Rule) error {
	m := r.Match
	if !m.isFactsRule() {
		return nil
	}
	kinds := 0
	for _, set := range []bool{m.PowerShell != nil, len(m.PowerShellStrings) > 0, m.PowerShellCalls != nil} {
		if set {
			kinds++
		}
	}
	if kinds > 1 {
		return fmt.Errorf("rule %q: a rule carries one of a powershell block, powershell_strings or powershell_calls", r.ID)
	}
	if m.CommandExact != "" || len(m.CommandPrefix) > 0 || m.CommandRegex != "" || m.CommandRegexExclude != "" ||
		len(m.CommandIntentExclude) > 0 || len(m.CommandIntentDowngrade) > 0 || len(m.CommandPositionExclude) > 0 ||
		m.CommandFoldSeparators || m.Structural != nil || m.Dataflow != nil || m.Semantic != nil || m.Stateful != nil || m.Context != nil {
		return fmt.Errorf("rule %q: a powershell match cannot be combined with another matcher: the shell pipeline would read the rest of it against bash text", r.ID)
	}
	switch r.Decision {
	case DecisionBlock, DecisionAudit, DecisionRequireApproval:
	default:
		return fmt.Errorf("rule %q: a powershell rule decides BLOCK, AUDIT or REQUIRE_APPROVAL, not %q", r.ID, r.Decision)
	}
	switch {
	case m.PowerShell != nil:
		return validatePowerShellMatch(r.ID, m.PowerShell, "powershell", false)
	case m.PowerShellCalls != nil:
		return validatePowerShellMatch(r.ID, m.PowerShellCalls, "powershell_calls", true)
	}
	for _, s := range m.PowerShellStrings {
		if s == "" {
			return fmt.Errorf("rule %q: powershell_strings has an empty entry", r.ID)
		}
	}
	return nil
}

// validatePowerShellMatch checks one node and its fed_by_any entries. calls
// reports whether call nodes are allowed (under powershell_calls only).
func validatePowerShellMatch(id string, m *PowerShellMatch, where string, calls bool) error {
	if len(m.Call) > 0 {
		if !calls {
			return fmt.Errorf("rule %q: %s names a call: a call node belongs under powershell_calls, which older binaries ignore", id, where)
		}
		if len(m.Command) > 0 {
			return fmt.Errorf("rule %q: %s names both a command and a call", id, where)
		}
		if len(m.ParamsAny) > 0 || len(m.ArgsAny) > 0 || m.ArgsWildcard || len(m.PathsAny) > 0 || m.OutputRuns != nil || m.EncodedCommand || m.StdinScript || len(m.Positions) > 0 {
			return fmt.Errorf("rule %q: %s is a call node: it carries only call, values_any and fed_by_any", id, where)
		}
		for _, n := range m.Call {
			c := normalizeCallName(n)
			if !strings.HasPrefix(c, ".") && !strings.Contains(c, "::") ||
				strings.HasPrefix(c, "::") || strings.HasSuffix(c, "::") || c == "." {
				return fmt.Errorf("rule %q: %s call %q is neither Type::Method nor .Method", id, where, n)
			}
		}
	} else if len(m.Command) == 0 {
		return fmt.Errorf("rule %q: %s names no command: a matcher must name one, so no rule can match every command", id, where)
	}
	for _, n := range m.Command {
		if normalizePSName(n) == "" {
			return fmt.Errorf("rule %q: %s has an empty command name", id, where)
		}
	}
	for _, p := range m.ParamsAny {
		name := strings.TrimSuffix(p.Name, "*")
		if len(name) < 2 || name[0] != '-' || name[1] == '-' {
			return fmt.Errorf("rule %q: %s parameter %q must be a dash and a name", id, where, p.Name)
		}
	}
	for _, a := range m.ArgsAny {
		if a == "" {
			return fmt.Errorf("rule %q: %s has an empty args_any entry", id, where)
		}
	}
	if m.ArgsWildcard && len(m.ArgsAny) == 0 {
		return fmt.Errorf("rule %q: %s sets args_wildcard with no args_any", id, where)
	}
	if len(m.Positions) > 0 && len(m.ParamsAny) == 0 {
		return fmt.Errorf("rule %q: %s sets positions with no params_any", id, where)
	}
	for _, p := range m.Positions {
		if len(p) < 2 || p[0] != '-' || p[1] == '-' || strings.HasSuffix(p, "*") {
			return fmt.Errorf("rule %q: %s position %q must be a dash and a parameter name", id, where, p)
		}
	}
	for _, g := range m.PathsAny {
		if _, err := path.Match(strings.TrimPrefix(g, "**/"), ""); err != nil || g == "" {
			return fmt.Errorf("rule %q: %s paths_any %q is not a glob", id, where, g)
		}
	}
	for _, g := range m.ValuesAny {
		if _, err := path.Match(strings.TrimPrefix(g, "**/"), ""); err != nil || g == "" {
			return fmt.Errorf("rule %q: %s values_any %q is not a glob", id, where, g)
		}
	}
	if r := m.OutputRuns; r != nil {
		if len(r.Params) == 0 {
			return fmt.Errorf("rule %q: %s output_runs names no parameter", id, where)
		}
		for _, p := range r.Params {
			if len(p) < 2 || p[0] != '-' {
				return fmt.Errorf("rule %q: %s output_runs parameter %q must be a dash and a name", id, where, p)
			}
		}
	}
	for i := range m.FedByAny {
		if err := validatePowerShellMatch(id, &m.FedByAny[i], where+".fed_by_any", calls); err != nil {
			return err
		}
	}
	if len(m.FedByAll) > 0 && !calls {
		return fmt.Errorf("rule %q: %s uses fed_by_all, which belongs under powershell_calls: an older binary would drop it and read a broader rule", id, where)
	}
	if m.StdinScript && !calls {
		return fmt.Errorf("rule %q: %s uses stdin_script, which belongs under powershell_calls: an older binary would drop it and read a broader rule", id, where)
	}
	for i := range m.FedByAll {
		if err := validatePowerShellMatch(id, &m.FedByAll[i], where+".fed_by_all", calls); err != nil {
			return err
		}
	}
	return nil
}

func compilePowerShellMatch(m *PowerShellMatch) *psMatcher {
	c := &psMatcher{names: map[string]bool{}, args: map[string]bool{}, params: m.ParamsAny, encoded: m.EncodedCommand, argsWildcard: m.ArgsWildcard, stdin: m.StdinScript, positions: m.Positions}
	for _, n := range m.Command {
		c.names[normalizePSName(n)] = true
	}
	if len(m.Call) > 0 {
		c.isCall = true
		for _, n := range m.Call {
			c.names[normalizeCallName(n)] = true
		}
	}
	for _, a := range m.ArgsAny {
		c.args[asciiFold(a)] = true
	}
	for _, g := range m.PathsAny {
		c.paths = append(c.paths, asciiFold(g))
	}
	for _, g := range m.ValuesAny {
		c.values = append(c.values, asciiFold(g))
	}
	if r := m.OutputRuns; r != nil {
		c.runs = &psOutputRuns{params: r.Params, by: map[string]bool{}}
		for _, n := range r.By {
			c.runs.by[normalizePSName(n)] = true
		}
	}
	for i := range m.FedByAny {
		c.fedBy = append(c.fedBy, compilePowerShellMatch(&m.FedByAny[i]))
	}
	for i := range m.FedByAll {
		c.fedAll = append(c.fedAll, compilePowerShellMatch(&m.FedByAll[i]))
	}
	return c
}

// compilePowerShellRules compiles every enabled rule that carries a
// powershell block or a powershell_strings list.
func compilePowerShellRules(p *Policy) ([]factsRule, error) {
	var out []factsRule
	for _, r := range p.Rules {
		if !r.Match.isFactsRule() || p.IsRuleDisabled(r.ID) {
			continue
		}
		if err := validatePowerShellRule(r); err != nil {
			return nil, err
		}
		out = append(out, compileFactsRule(r))
	}
	return out, nil
}

// factsRuleResult applies the powershell rules to f, as the shell combiner
// applies findings: with no match r is unchanged; otherwise the most
// restrictive matching decision replaces r's, with the rules of that
// decision (rule order), their reasons and their taxonomy.
func (e *Engine) factsRuleResult(r EvalResult, f facts.Facts, cwd string) EvalResult {
	best := 0
	var dec Decision
	var ids, reasons, tax []string
	for _, fr := range e.psRules {
		if !fr.matches(f, cwd) {
			continue
		}
		sev := decisionSeverity(fr.rule.Decision)
		if sev > best {
			best, dec = sev, fr.rule.Decision
			ids, reasons, tax = nil, nil, nil
		}
		// A pack on disk and its embedded twin load the same rule twice (the
		// loader appends); the receipt names it once.
		if sev == best && !hasString(ids, fr.rule.ID) {
			ids = append(ids, fr.rule.ID)
			reasons = append(reasons, fr.rule.Reason)
			if fr.rule.Taxonomy != "" && !hasString(tax, fr.rule.Taxonomy) {
				tax = append(tax, fr.rule.Taxonomy)
			}
		}
	}
	if best == 0 {
		return r
	}
	r.Decision, r.TriggeredRules, r.Reasons = dec, ids, reasons
	r.TaxonomyRefs = append([]string{}, tax...)
	return r
}

// matches reports whether some command of f matches.
func (m *psMatcher) matches(f facts.Facts, cwd string) bool {
	for _, hit := range m.hits(f, cwd) {
		if hit {
			return true
		}
	}
	return false
}

// fedSum is a fed_by_any entry's hits as prefix sums, over f.Commands or,
// for a call node, f.Calls.
type fedSum struct {
	sum  []int
	call bool
}

// hits reports, per command of f (per call, for a call node), whether it
// matches. Linear in the commands and calls for each matcher in the tree: a
// fed_by_any entry's hits are counted once into a prefix sum, and an input
// range is then one subtraction, whatever the text's pipeline length.
func (m *psMatcher) hits(f facts.Facts, cwd string) []bool {
	fed, all := fedSums(m.fedBy, f, cwd), fedSums(m.fedAll, f, cwd)
	if m.isCall {
		out := make([]bool, len(f.Calls))
		for i, c := range f.Calls {
			out[i] = m.names[c.Name] && m.callValuesOK(c, f.Strings) && m.fedOK(fed, f, i) && m.fedAllOK(all, f, i)
		}
		return out
	}
	var runLater func(i int) bool
	if m.runs != nil {
		runLater = m.runs.laterRun(f.Commands)
	}
	out := make([]bool, len(f.Commands))
	for i, c := range f.Commands {
		out[i] = m.matchesCommand(c, cwd) && m.fedOK(fed, f, i) && m.fedAllOK(all, f, i) && (runLater == nil || runLater(i))
	}
	return out
}

// inputRange is the range of f.Commands (or of f.Calls, when calls) whose
// output can reach this node's i-th command or call.
func (m *psMatcher) inputRange(f facts.Facts, i int, calls bool) (int, int) {
	if m.isCall {
		c := f.Calls[i]
		if calls {
			return c.CallsFrom, c.CallsTo
		}
		return c.InputFrom, c.InputTo
	}
	c := f.Commands[i]
	if calls {
		return c.CallsFrom, c.CallsTo
	}
	return c.InputFrom, c.InputTo
}

// callValuesOK applies values_any to a call: some string literal inside its
// arguments matches, read as anyValue reads an argument value.
func (m *psMatcher) callValuesOK(c facts.Call, strs []string) bool {
	if len(m.values) == 0 {
		return true
	}
	from, to := max(c.StringsFrom, 0), min(c.StringsTo, len(strs))
	for _, s := range strs[min(from, to):to] {
		v := strings.TrimRight(strings.ReplaceAll(s, `\`, "/"), "/")
		for _, g := range m.values {
			if psGlobMatches(g, v) {
				return true
			}
		}
	}
	return false
}

// laterRun returns whether a file command i writes (through one of r's
// parameters) is run by a later command. One pass records, for every path
// a command runs, the last command that runs it, so the whole text costs
// one walk however many downloads it holds.
func (r *psOutputRuns) laterRun(cmds []facts.Command) func(i int) bool {
	last := map[string]int{}
	for j, c := range cmds {
		if c.Written != facts.Dynamic && strings.ContainsAny(c.Written, `/\`) {
			last[psRunPath(c.Written)] = j
		}
		if !r.runsArguments(c) {
			continue
		}
		for _, el := range c.Elements {
			for _, p := range el.Paths {
				last[psRunPath(p)] = j
			}
		}
	}
	return func(i int) bool {
		for _, p := range r.outputs(cmds[i].Elements) {
			if j, ok := last[psRunPath(p)]; ok && j > i {
				return true
			}
		}
		return false
	}
}

// runsArguments reports whether c is one of the By commands, in any reading.
func (r *psOutputRuns) runsArguments(c facts.Command) bool {
	for _, n := range c.Names() {
		if r.by[normalizePSName(n)] {
			return true
		}
	}
	return false
}

// outputs are the paths els names through one of r's parameters: the value
// attached with a colon, else the argument right after the parameter.
func (r *psOutputRuns) outputs(els []facts.Element) []string {
	var out []string
	for k, el := range els {
		if el.Param == "" {
			// A native long option is an argument word to PowerShell:
			// `--output a.exe` or `--output=a.exe`.
			name, val, joined := strings.Cut(el.Value, "=")
			if !strings.HasPrefix(name, "--") || !r.isOutputParam(name) {
				continue
			}
			if joined {
				out = append(out, val)
			} else if k+1 < len(els) && els[k+1].Param == "" {
				out = append(out, els[k+1].Paths...)
			}
			continue
		}
		if !r.isOutputParam(psDash(el.Param)) {
			continue
		}
		if strings.Contains(el.Raw, ":") {
			out = append(out, el.Paths...)
		} else if k+1 < len(els) && els[k+1].Param == "" {
			out = append(out, els[k+1].Paths...)
		}
	}
	return out
}

func (r *psOutputRuns) isOutputParam(written string) bool {
	for _, p := range r.params {
		if asciiFold(written) == asciiFold(p) || psParamMatches(written, p) {
			return true
		}
	}
	return false
}

// psRunPath is a path as laterRun compares it: `\` read as `/`, ASCII
// lower case, without a leading `./`.
func psRunPath(p string) string {
	p = asciiFold(strings.ReplaceAll(p, `\`, "/"))
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	return p
}

// fedSums counts each entry's hits into prefix sums.
func fedSums(subs []*psMatcher, f facts.Facts, cwd string) []fedSum {
	var out []fedSum
	for _, sub := range subs {
		h := sub.hits(f, cwd)
		sum := make([]int, len(h)+1)
		for j, ok := range h {
			sum[j+1] = sum[j]
			if ok {
				sum[j+1]++
			}
		}
		out = append(out, fedSum{sum: sum, call: sub.isCall})
	}
	return out
}

// inputs is how many of an entry's hits are inputs of this node's i-th
// command or call.
func (m *psMatcher) inputs(s fedSum, f facts.Facts, i int) int {
	from, to := m.inputRange(f, i, s.call)
	from, to = max(from, 0), min(to, len(s.sum)-1)
	if from >= to {
		return 0
	}
	count := s.sum[to] - s.sum[from]
	if s.call == m.isCall && i >= from && i < to {
		count -= s.sum[i+1] - s.sum[i] // a command or call is no input of its own
	}
	return count
}

func (m *psMatcher) fedOK(fed []fedSum, f facts.Facts, i int) bool {
	if len(m.fedBy) == 0 {
		return true
	}
	for _, s := range fed {
		if m.inputs(s, f, i) > 0 {
			return true
		}
	}
	return false
}

// fedAllOK applies fed_by_all: every entry has an input.
func (m *psMatcher) fedAllOK(all []fedSum, f facts.Facts, i int) bool {
	for _, s := range all {
		if m.inputs(s, f, i) == 0 {
			return false
		}
	}
	return true
}

func (m *psMatcher) matchesCommand(c facts.Command, cwd string) bool {
	named := false
	for _, n := range c.Names() {
		if m.names[normalizePSName(n)] {
			named = true
			break
		}
	}
	if !named {
		return false
	}
	if m.encoded && !c.EncodedCommand {
		return false
	}
	if m.stdin && !c.StdinScript {
		return false
	}
	if len(m.params) > 0 && !m.anyParam(c.Elements) {
		return false
	}
	if len(m.args) > 0 && !m.anyArg(c.Elements) {
		return false
	}
	if len(m.paths) > 0 && !m.anyPath(c.Elements, cwd) {
		return false
	}
	if len(m.values) > 0 && !m.anyValue(c.Elements) {
		return false
	}
	return true
}

func (m *psMatcher) anyParam(els []facts.Element) bool {
	for k, el := range els {
		if el.Param == "" {
			continue
		}
		written := psDash(el.Param)
		for _, p := range m.params {
			if psParamMatches(written, p.Name) && psValueHolds(els, k, p.ValueNot) {
				return true
			}
		}
	}
	for _, b := range psPositional(els, m.positions) {
		for _, p := range m.params {
			if psParamMatches(b.param, p.Name) && psValueNotIn(b.raw, p.ValueNot) {
				return true
			}
		}
	}
	return false
}

// psBinding is a parameter bound by position and the argument's source text.
type psBinding struct{ param, raw string }

// psPositional binds the positional arguments of els to positions, in
// order, skipping a parameter the text names: a positional argument is one
// that does not follow a parameter written without an attached value. The
// reader does not know which parameters are switches, so an argument after
// a switch is read as the switch's value: fewer positional arguments, never
// more, so a later parameter is bound to nothing rather than to the wrong
// argument.
func psPositional(els []facts.Element, positions []string) []psBinding {
	if len(positions) == 0 {
		return nil
	}
	named := make([]bool, len(positions))
	var args []string
	for k, el := range els {
		if el.Param != "" {
			for i, p := range positions {
				if psParamMatches(psDash(el.Param), p) {
					named[i] = true
				}
			}
			continue
		}
		if k > 0 && els[k-1].Param != "" && !strings.Contains(els[k-1].Raw, ":") {
			continue // the value of the parameter before it
		}
		args = append(args, el.Raw)
	}
	var out []psBinding
	for i, p := range positions {
		if named[i] {
			continue
		}
		if len(args) == 0 {
			break
		}
		out = append(out, psBinding{param: p, raw: args[0]})
		args = args[1:]
	}
	return out
}

// psValueNotIn reports whether a value's source text is none of not
// (PowerShellParam.ValueNot): true for an empty list.
func psValueNotIn(raw string, not []string) bool {
	v := asciiFold(strings.TrimSpace(raw))
	for _, n := range not {
		if v == asciiFold(n) {
			return false
		}
	}
	return true
}

func (m *psMatcher) anyArg(els []facts.Element) bool {
	for _, el := range els {
		for _, w := range psWords(el) {
			fw := asciiFold(w)
			if m.args[fw] {
				return true
			}
			if m.argsWildcard && psIsWildcard(w) {
				for entry := range m.args {
					if psWildcardMatches(fw, entry) {
						return true
					}
				}
			}
		}
	}
	return false
}

// psIsWildcard reports whether w holds a PowerShell wildcard character
// (`*`, `?`, `[`) that a backtick does not escape.
func psIsWildcard(w string) bool {
	for i := 0; i < len(w); i++ {
		switch w[i] {
		case '`':
			i++
		case '*', '?', '[':
			return true
		}
	}
	return false
}

// psWildcardMatches reports whether the PowerShell wildcard pattern (ASCII
// lower case) matches s: `*` any run, `?` one character, `[abc]` and `[a-c]`
// a set, a backtick escaping the next character. A malformed pattern matches
// nothing.
func psWildcardMatches(pattern, s string) bool {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '`':
			if i+1 < len(pattern) {
				i++
				b.WriteByte('\\')
				b.WriteByte(pattern[i])
			}
		case '\\':
			b.WriteString(`\\`)
		default:
			b.WriteByte(c)
		}
	}
	ok, err := path.Match(b.String(), s)
	return err == nil && ok
}

func (m *psMatcher) anyPath(els []facts.Element, cwd string) bool {
	for _, el := range els {
		for _, p := range el.Paths {
			if psStartsWithProse(p) {
				continue
			}
			for _, cand := range psPathCandidates(p, cwd) {
				for _, g := range m.paths {
					if psGlobMatches(g, cand) {
						return true
					}
				}
			}
		}
	}
	return false
}

// anyValue reports whether some argument value of els, `\` read as `/` and
// trailing separators dropped, matches a values_any glob. A parameter
// without an attached value has none, and a computed value matches nothing.
func (m *psMatcher) anyValue(els []facts.Element) bool {
	for _, el := range els {
		if el.Value == "" || el.Value == facts.Expr {
			continue
		}
		v := strings.TrimRight(strings.ReplaceAll(el.Value, `\`, "/"), "/")
		for _, g := range m.values {
			if psGlobMatches(g, v) {
				return true
			}
		}
	}
	return false
}

// psParamMatches applies decision 1's prefix rule, with a trailing `*` in
// the rule's name for a family of parameters.
func psParamMatches(written, ruleName string) bool {
	if stem, family := strings.CutSuffix(ruleName, "*"); family {
		return strings.HasPrefix(asciiFold(written), asciiFold(stem)) || facts.ParamMatches(written, stem)
	}
	return facts.ParamMatches(written, ruleName)
}

// psValueHolds reports whether the parameter at els[k] has a value that is
// none of not (PowerShellParam.ValueNot).
func psValueHolds(els []facts.Element, k int, not []string) bool {
	if len(not) == 0 {
		return true
	}
	var v string
	if _, attached, ok := strings.Cut(els[k].Raw, ":"); ok {
		v = attached
	} else if k+1 < len(els) && els[k+1].Param == "" {
		v = els[k+1].Raw
	} else {
		return true // a bare switch
	}
	v = asciiFold(strings.TrimSpace(v))
	for _, n := range not {
		if v == asciiFold(n) {
			return false
		}
	}
	return true
}

// psWords are the words of an element args_any reads: a parameter's name as
// written, or an argument's value (its source text when the value is an
// expression). Round 3 adds the value a cmdlet binds where step 5 read none:
// a parameter's attached value (`-Name:WinDefend`) and each item of an array
// value (`WinDefend,WdNisSvc`), so a rule naming one service reads a list
// that holds it. Each only adds words: a binary that predates them reads
// fewer, never other ones.
func psWords(el facts.Element) []string {
	var out []string
	switch {
	case el.Param != "":
		_, attached, ok := strings.Cut(el.Raw, ":")
		if !ok {
			return []string{psDash(el.Param)}
		}
		if el.Value != "" && el.Value != facts.Expr {
			out = append(out, el.Value)
		} else if attached != "" {
			out = append(out, attached)
		}
	case el.Value == facts.Expr:
		if el.Raw != "" {
			out = append(out, el.Raw)
		}
	case el.Value != "":
		out = append(out, el.Value)
	}
	for _, item := range el.Items {
		if item != "" && item != facts.Expr {
			out = append(out, item)
		}
	}
	return out
}

// psDash writes a parameter's leading dash as `-`: PowerShell accepts the
// en dash, em dash and horizontal bar there too.
func psDash(p string) string {
	for _, d := range []string{"–", "—", "―"} {
		if rest, ok := strings.CutPrefix(p, d); ok {
			return "-" + rest
		}
	}
	return p
}

// normalizeCallName is a call name as a rule compares it with
// facts.Call.Name: ASCII lower case, the type without brackets, surrounding
// space or a leading `System.`.
func normalizeCallName(n string) string {
	n = asciiFold(strings.TrimSpace(n))
	typ, method, static := strings.Cut(n, "::")
	if !static {
		return n
	}
	typ = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(typ, "["), "]"))
	return strings.TrimPrefix(typ, "system.") + "::" + strings.TrimSpace(method)
}

// normalizePSName is a command name as a rule compares it: ASCII lower
// case, without a directory or a `.exe`.
func normalizePSName(n string) string {
	n = asciiFold(n)
	if i := strings.LastIndexAny(n, `/\`); i >= 0 {
		n = n[i+1:]
	}
	return strings.TrimSuffix(n, ".exe")
}

// psStartsWithProse reports a whole value whose first component holds
// whitespace, or a colon other than a drive letter's: text such as
// `cleared PSReadLine\ConsoleHost_history.txt` given to Set-Content to
// write, or `key=C:\x`. The lane keeps such a value as a path (it is one
// value, and it holds a separator), and a protected pattern, anchored at its
// start, never matches it; a `**/` glob matches any trailing run of
// components and would. No file a Windows program opens starts that way:
// `C:\Users\John Smith\…` has its space in a later component, and a colon
// is no file-name character.
func psStartsWithProse(p string) bool {
	first, _, _ := strings.Cut(strings.ReplaceAll(p, `\`, "/"), "/")
	if strings.ContainsAny(first, " \t") {
		return true
	}
	colon := strings.IndexByte(first, ':')
	return colon >= 0 && !(colon == 1 && len(first) == 2)
}

// psPathCandidates is p with `\` read as `/`, and under cwd when relative.
func psPathCandidates(p, cwd string) []string {
	p = strings.ReplaceAll(p, `\`, "/")
	out := []string{p}
	if filepath.IsAbs(cwd) && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "~") && !(len(p) > 1 && p[1] == ':') {
		out = append(out, filepath.ToSlash(filepath.Join(cwd, p)))
	}
	return out
}

// psGlobMatches matches a folded glob against p, folded. `**/` at the start
// matches any run of leading components, so it reads as "ends with". `/**` at
// the end (Windows round 4) matches the directory the rest names and anything
// under it: the glob before it matched against p or one of p's ancestors. A
// binary that predates it reads `**` there as `*`, one level only: fewer
// matches, never other ones.
func psGlobMatches(glob, p string) bool {
	if base, ok := strings.CutSuffix(glob, "/**"); ok && base != "" && base != "**" {
		p = asciiFold(p)
		for {
			if psGlobMatches(base, p) {
				return true
			}
			i := strings.LastIndexByte(p, '/')
			if i <= 0 {
				return false
			}
			p = p[:i]
		}
	}
	p = asciiFold(p)
	rest, anyPrefix := strings.CutPrefix(glob, "**/")
	if !anyPrefix {
		ok, _ := path.Match(glob, p)
		return ok
	}
	for {
		if ok, _ := path.Match(rest, p); ok {
			return true
		}
		i := strings.IndexByte(p, '/')
		if i < 0 {
			return false
		}
		p = p[i+1:]
	}
}

// asciiFold lowers ASCII letters only, as PowerShell compares names: a full
// Unicode fold maps U+212A KELVIN SIGN to k, which PowerShell does not.
func asciiFold(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func hasString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
