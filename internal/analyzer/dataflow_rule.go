package analyzer

// DataflowRule is the analyzer-side representation of a user-defined dataflow
// rule from YAML. It matches source→sink data flows through pipes, redirects,
// and command substitutions.
//
// Inspired by classical taint tracking analysis:
//   - Source: where data originates (credential files, /dev/zero, sensitive paths)
//   - Sink: where data ends up (network commands, devices, cron)
//   - Via: optional transform/encoding commands in between (base64, gzip)
//
// The matcher inspects the ParsedCommand's pipe chain and redirect structure
// to detect dangerous flows that individual command analysis would miss.
type DataflowRule struct {
	// Rule metadata
	ID         string
	Decision   string
	Confidence float64
	Reason     string
	Taxonomy   string

	// Flow pattern
	Source DataflowRuleEndpoint
	Sink   DataflowRuleEndpoint
	Via    []string // optional: encoding/transform commands in the chain

	// Modifiers
	Negate bool
}

// DataflowRuleEndpoint describes one end of a flow (source or sink).
type DataflowRuleEndpoint struct {
	Type     string   // pre-classified: "credential", "sensitive", "zero", "network", "device", "cron"
	Paths    []string // glob patterns on file paths
	Commands []string // command names
}

// MatchDataflowRule evaluates a dataflow rule against the parsed command.
// It checks pipe chains and redirects for source→sink flows.
//
// On Windows the flow is matched under main's reading of the words its
// endpoints read and under Git Bash's (#5049, see quoteReading), and the two
// results, after negation, are joined by the rule's decision: a restricting
// rule fires if either fires, an ALLOW only if both do. The join is on whole
// evaluations because the pipe flow takes the FIRST source and the first sink
// after it: a source that matches one segment earlier can move the sink and
// lose a flow main matched.
func MatchDataflowRule(parsed *ParsedCommand, rule DataflowRule) bool {
	if parsed == nil || len(parsed.Segments) == 0 {
		return rule.Negate
	}

	return matchDataflowRuleGated(parsed, rule, readsTwoWays(parsed))
}

// matchDataflowRuleGated is MatchDataflowRule for a command whose
// readsTwoWays is already known.
func matchDataflowRuleGated(parsed *ParsedCommand, rule DataflowRule, twoWays bool) bool {
	if parsed == nil || len(parsed.Segments) == 0 {
		return rule.Negate
	}
	twoWays = twoWays || globsHaveBackslash(rule.Source.Paths, rule.Sink.Paths)
	return combineReadingsIf(twoWays, restrictingDecision(rule.Decision), func(r quoteReading) bool {
		return applyNegate(matchDataflowAs(parsed, rule, r), rule.Negate)
	})
}

// matchDataflowAs is MatchDataflowRule's flow match, before negation, under
// one reading.
func matchDataflowAs(parsed *ParsedCommand, rule DataflowRule, r quoteReading) bool {
	matched := false

	// Check pipe-based flows: source segment → [via] → sink segment
	if len(parsed.Segments) >= 2 {
		matched = matched || matchPipeFlow(parsed, rule, r)
	}

	// Check redirect-based flows: source command → redirect to sink path
	matched = matched || matchRedirectFlow(parsed, rule, r)

	return matched
}

// matchPipeFlow checks if the pipe chain matches source → [via] → sink.
func matchPipeFlow(parsed *ParsedCommand, rule DataflowRule, r quoteReading) bool {
	segments := parsed.Segments

	// Find source segments (leftmost matching segment)
	sourceIdx := -1
	for i, seg := range segments {
		if matchesFlowEndpointAsSource(seg, rule.Source, r) {
			sourceIdx = i
			break
		}
	}
	if sourceIdx < 0 {
		return false
	}

	// Find sink segments (any segment after source)
	sinkIdx := -1
	for i := sourceIdx + 1; i < len(segments); i++ {
		if matchesFlowEndpointAsSink(segments[i], rule.Sink, r) {
			sinkIdx = i
			break
		}
	}
	if sinkIdx < 0 {
		return false
	}

	// Check via: if specified, at least one intermediate segment must match
	if len(rule.Via) > 0 {
		foundVia := false
		for i := sourceIdx + 1; i < sinkIdx; i++ {
			if stringInList(segments[i].Executable, rule.Via) {
				foundVia = true
				break
			}
		}
		if !foundVia {
			return false
		}
	}

	return true
}

// matchRedirectFlow checks if a command reads from a source and redirects to a sink path.
func matchRedirectFlow(parsed *ParsedCommand, rule DataflowRule, r quoteReading) bool {
	// Collect all redirects (top-level + per-segment)
	for i, seg := range parsed.Segments {
		if !matchesFlowEndpointAsSource(seg, rule.Source, r) {
			continue
		}

		// Check segment-level redirects
		for _, redir := range seg.Redirects {
			if redir.Op == ">" || redir.Op == ">>" {
				if matchesSinkPath(redir.Path, rule.Sink, r) {
					return true
				}
			}
		}

		// Check top-level redirects (apply to first/last segment)
		if i == 0 || i == len(parsed.Segments)-1 {
			for _, redir := range parsed.Redirects {
				if redir.Op == ">" || redir.Op == ">>" {
					if matchesSinkPath(redir.Path, rule.Sink, r) {
						return true
					}
				}
			}
		}
	}
	return false
}

// matchesFlowEndpointAsSource checks if a command segment acts as a data source.
func matchesFlowEndpointAsSource(seg CommandSegment, ep DataflowRuleEndpoint, r quoteReading) bool {
	// Match by pre-classified type
	if ep.Type != "" {
		sourceType := classifySourceAs(seg.Executable, seg.Args, r)
		switch ep.Type {
		case "credential":
			if sourceType != "credential-source" {
				return false
			}
		case "sensitive":
			if sourceType != "sensitive-source" && sourceType != "credential-source" {
				return false
			}
		case "zero":
			if sourceType != "zero-source" {
				return false
			}
		default:
			return false
		}
	}

	// Match by explicit command names
	if len(ep.Commands) > 0 {
		if !stringInList(seg.Executable, ep.Commands) {
			return false
		}
	}

	// Match by explicit path patterns on args
	if len(ep.Paths) > 0 {
		foundPath := false
		for _, arg := range seg.Args {
			for _, pattern := range ep.Paths {
				if matchArgGlobAs(arg, pattern, r) {
					foundPath = true
					break
				}
			}
			if foundPath {
				break
			}
		}
		if !foundPath {
			return false
		}
	}

	// At least one criterion must be specified
	if ep.Type == "" && len(ep.Commands) == 0 && len(ep.Paths) == 0 {
		return false
	}

	return true
}

// matchesFlowEndpointAsSink checks if a command segment acts as a data sink.
func matchesFlowEndpointAsSink(seg CommandSegment, ep DataflowRuleEndpoint, r quoteReading) bool {
	// Match by pre-classified type
	if ep.Type != "" {
		switch ep.Type {
		case "network":
			if !isNetworkCommand(seg.Executable) && !isDNSCommand(seg.Executable) {
				return false
			}
		case "device":
			// For device sinks, check args for device paths
			hasDevice := false
			for _, arg := range seg.Args {
				if isDevicePathAs(arg, r) {
					hasDevice = true
					break
				}
			}
			if !hasDevice {
				return false
			}
		case "cron":
			if seg.Executable != "crontab" {
				return false
			}
		default:
			return false
		}
	}

	// Match by explicit command names
	if len(ep.Commands) > 0 {
		if !stringInList(seg.Executable, ep.Commands) {
			return false
		}
	}

	// Match by path patterns on args (for device paths etc.)
	if len(ep.Paths) > 0 {
		foundPath := false
		for _, arg := range seg.Args {
			for _, pattern := range ep.Paths {
				if matchArgGlobAs(arg, pattern, r) {
					foundPath = true
					break
				}
			}
			if foundPath {
				break
			}
		}
		if !foundPath {
			return false
		}
	}

	// At least one criterion must be specified
	if ep.Type == "" && len(ep.Commands) == 0 && len(ep.Paths) == 0 {
		return false
	}

	return true
}

// matchesSinkPath checks if a redirect target path matches sink criteria.
func matchesSinkPath(path string, ep DataflowRuleEndpoint, r quoteReading) bool {
	// Match by type
	if ep.Type != "" {
		switch ep.Type {
		case "device":
			if !isDevicePathAs(path, r) {
				return false
			}
		case "cron":
			if !isCronSpoolPath(path) {
				return false
			}
		default:
			return false
		}
	}

	// Match by explicit path patterns
	if len(ep.Paths) > 0 {
		foundPath := false
		for _, pattern := range ep.Paths {
			if matchArgGlobAs(path, pattern, r) {
				foundPath = true
				break
			}
		}
		if !foundPath {
			return false
		}
	}

	if ep.Type == "" && len(ep.Paths) == 0 {
		return false
	}

	return true
}
