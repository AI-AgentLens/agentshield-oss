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
func MatchDataflowRule(parsed *ParsedCommand, rule DataflowRule) bool {
	if parsed == nil || len(parsed.Segments) == 0 {
		return rule.Negate
	}

	matched := false

	// Check pipe-based flows: source segment → [via] → sink segment
	if len(parsed.Segments) >= 2 {
		matched = matched || matchPipeFlow(parsed, rule)
	}

	// Check redirect-based flows: source command → redirect to sink path
	matched = matched || matchRedirectFlow(parsed, rule)

	return applyNegate(matched, rule.Negate)
}

// matchPipeFlow checks if the pipe chain matches source → [via] → sink.
func matchPipeFlow(parsed *ParsedCommand, rule DataflowRule) bool {
	segments := parsed.Segments

	// Find source segments (leftmost matching segment)
	sourceIdx := -1
	for i, seg := range segments {
		if matchesFlowEndpointAsSource(seg, rule.Source) {
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
		if matchesFlowEndpointAsSink(segments[i], rule.Sink) {
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
func matchRedirectFlow(parsed *ParsedCommand, rule DataflowRule) bool {
	// Collect all redirects (top-level + per-segment)
	for i, seg := range parsed.Segments {
		if !matchesFlowEndpointAsSource(seg, rule.Source) {
			continue
		}

		// Check segment-level redirects
		for _, redir := range seg.Redirects {
			if redir.Op == ">" || redir.Op == ">>" {
				if matchesSinkPath(redir.Path, rule.Sink) {
					return true
				}
			}
		}

		// Check top-level redirects (apply to first/last segment)
		if i == 0 || i == len(parsed.Segments)-1 {
			for _, redir := range parsed.Redirects {
				if redir.Op == ">" || redir.Op == ">>" {
					if matchesSinkPath(redir.Path, rule.Sink) {
						return true
					}
				}
			}
		}
	}
	return false
}

// matchesFlowEndpointAsSource checks if a command segment acts as a data source.
func matchesFlowEndpointAsSource(seg CommandSegment, ep DataflowRuleEndpoint) bool {
	// Match by pre-classified type
	if ep.Type != "" {
		sourceType := classifySource(seg.Executable, seg.Args)
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
				if matchArgGlob(arg, pattern) {
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
func matchesFlowEndpointAsSink(seg CommandSegment, ep DataflowRuleEndpoint) bool {
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
				if isDevicePath(arg) {
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
				if matchArgGlob(arg, pattern) {
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
func matchesSinkPath(path string, ep DataflowRuleEndpoint) bool {
	// Match by type
	if ep.Type != "" {
		switch ep.Type {
		case "device":
			if !isDevicePath(path) {
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
			if matchArgGlob(path, pattern) {
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
