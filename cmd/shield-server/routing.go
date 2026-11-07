package main

import (
	"errors"
	"fmt"
	"slices"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/assembly"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/psreader"
	"github.com/AI-AgentLens/agentshield/internal/route"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// Routing a request through the table (ADR-001 step 2, #4245).
//
// A thin client sends the routing key the local hook routes on: the harness,
// the tool it names and the host OS. The server reads such a request with
// the lane its request shape always took on this server (a command: the
// shell pipeline; a tool_name: MCP policy), FIRST, then every other lane the
// table's row names, and combines them with the hook's runner and combiner
// (assembly.ReadRow, route.Combine). That is D2's union across the entry
// points that route through the table, per request: the row is the local
// hook's lanes, the legacy lane is this client's. So a keyed call decides at
// least as strictly as before (the legacy lane is always one of the
// readings), and on a tie it keeps exactly the record it had (the earlier
// lane wins, D4), except that a legacy AUDIT naming no rule gives the record
// to a tied AUDIT that names one (the AUDIT tie rule, #4779: evidence only,
// the decision is the same).
//
// The legacy lane is not optional. PowerShell runs cross-platform CLIs
// verbatim (`git push --force origin main`, `terraform destroy`, `kubectl
// delete namespace …`), and the POSIX pipeline's rules for them are the only
// rules that read them: the PowerShell lane has protected paths,
// self-protection and PowerShell pack rules, not CLI rules. Dropping the
// POSIX reading of Claude Code's PowerShell tool lowered 245 of 270 such
// BLOCKs in the bash corpus (Opus pass 1 on #4766). Taking a lane away from
// an entry point is ADR step 6, after a replay shows it adds nothing.
//
// A request with no key, from a client that predates step 2, decides exactly
// as before (the version-skew fitness function, TestVersionSkew_*). The
// clients keep sending the shape they always did, so a server that predates
// step 2 decides as before for an updated client too.

// routeKey is a request's routing key (route.ToolCall).
type routeKey struct {
	// Harness is the harness the client speaks for, as internal/route names
	// it: claude-code, codex, copilot-cli (Copilot's Claude-compatible
	// format), copilot-cli-native.
	Harness string `json:"harness"`
	// Tool is the tool the harness named, exactly as it named it.
	Tool string `json:"tool"`
	// OS is the host OS the call runs on, as Go's runtime.GOOS spells it:
	// windows, darwin, linux.
	OS string `json:"os"`
}

// routedCall is a keyed request the table routes.
type routedCall struct {
	call  route.ToolCall
	lanes []route.Lane
	// command is the text the shell lanes read: the request's command, or
	// its arguments' command string. "" when there is none.
	command string
	// arguments are what the Structured lane reads: the tool's input, with
	// the command in it when the request carried one.
	arguments map[string]interface{}
}

// routeRequest decides whether req goes through the routing table. nil and
// no error keeps it on today's path; an error is a malformed key (400).
func routeRequest(req evaluateRequest) (*routedCall, error) {
	k := req.Route
	if k == nil {
		return nil, nil
	}
	if k.Harness == "" || k.Tool == "" || k.OS == "" {
		return nil, errors.New("route needs all of harness, tool and os")
	}
	// One call, one reading: two names for the tool, or two texts for the
	// command, would let the lanes read different calls.
	if req.ToolName != "" && req.ToolName != k.Tool {
		return nil, fmt.Errorf("tool_name %q and route.tool %q differ", req.ToolName, k.Tool)
	}
	args := req.Arguments
	if v, has := args["command"]; has && req.Command != "" {
		if s, ok := v.(string); !ok || s != req.Command {
			return nil, errors.New("command and arguments.command differ")
		}
	}

	command := req.Command
	if command == "" {
		command, _ = args["command"].(string)
	} else if _, has := args["command"]; !has {
		// The Structured lane reads the command among the tool's input, as
		// the hook's reads tool_input.
		withCommand := make(map[string]interface{}, len(args)+1)
		for key, v := range args {
			withCommand[key] = v
		}
		withCommand["command"] = command
		args = withCommand
	}

	call := route.ToolCall{Harness: route.Harness(k.Harness), Tool: k.Tool, OS: k.OS, HasCommand: command != ""}
	return &routedCall{call: call, lanes: legacyFirst(req, route.Route(call)), command: command, arguments: args}, nil
}

// legacyFirst is the lanes a keyed request is read by: the lane its request
// shape took without the key (a command: POSIX; a tool_name: Structured),
// then the row's other lanes in the row's order.
func legacyFirst(req evaluateRequest, row []route.Lane) []route.Lane {
	legacy := route.Structured
	if req.Command != "" {
		legacy = route.POSIX
	}
	lanes := []route.Lane{legacy}
	for _, l := range row {
		if l != legacy {
			lanes = append(lanes, l)
		}
	}
	return lanes
}

// serverReading is one lane's reading of a routed request, held until its
// row's lanes are combined.
type serverReading struct {
	verdict route.Verdict
	resp    evaluateResponse
	// rec is the request as this reading's record names it: the command for
	// a shell lane, the tool name and arguments for the Structured lane, as
	// the hook records each. A receipt kept from a shell lane is
	// shell-shaped; its lane_readings note names the tool.
	rec evaluateRequest
}

func (r serverReading) Verdict() route.Verdict { return r.verdict }

// evaluateRouted reads a routed request with each of its lanes and combines
// them (assembly.ReadRow). It returns the kept reading's verdict, with the
// combined decision, and the request shape its record takes. ok is false
// only when no lane had anything to read, which the legacy lane rules out
// (a command is read by POSIX, a tool call by MCP policy); the handler then
// takes today's path.
func (s *Server) evaluateRouted(req evaluateRequest, rc *routedCall) (resp evaluateResponse, rec evaluateRequest, ok bool) {
	row, ok := assembly.ReadRow(rc.call.Tool, rc.lanes, func(l route.Lane) (serverReading, bool) {
		return s.readLane(l, req, rc)
	})
	if !ok {
		return evaluateResponse{}, req, false
	}
	kept := row.Kept()
	resp = kept.resp
	resp.Decision, resp.OriginalDecision = row.Combined.Decision, row.Combined.OriginalDecision
	if len(rc.lanes) > 1 {
		// As the hook: a row of more than one lane records what every lane
		// decided, on the one receipt, after the other readings' notes the
		// kept one carries (assembly.Row.Extra, #4779).
		resp.Notes = append(append([]analyzer.Note(nil), resp.Notes...), row.Extra()...)
	}
	return resp, kept.rec, true
}

// readLane is one lane's reading of a routed request. A shell lane with no
// command text has nothing to read.
func (s *Server) readLane(l route.Lane, req evaluateRequest, rc *routedCall) (serverReading, bool) {
	shellRec := req
	shellRec.Command, shellRec.ToolName, shellRec.Arguments = rc.command, "", nil

	switch l {
	case route.Structured:
		rec := req
		rec.Command, rec.ToolName, rec.Arguments = "", rc.call.Tool, rc.arguments
		// A gap is command text no shell lane reads (D5); here the legacy
		// POSIX lane reads a command its client sent as one.
		var notes []analyzer.Note
		if route.Gap(rc.call) && !slices.Contains(rc.lanes, route.POSIX) && !slices.Contains(rc.lanes, route.PowerShell) {
			notes = append(notes, assembly.RoutingGapNote(rc.call))
		}
		result := s.readMCP(rec)
		resp := mcpResponse(result)
		resp.Notes = notes
		return serverReading{verdict: assembly.ToolCallVerdict(result, assembly.RouteNotes(notes)), resp: resp, rec: rec}, true
	case route.POSIX:
		if rc.command == "" {
			return serverReading{}, false
		}
		result := s.readShell(rc.command, req.Cwd)
		return serverReading{
			verdict: assembly.ShellVerdict(l, &result, assembly.RouteNotes(result.Notes)),
			resp:    shellResponse(result, rc.command),
			rec:     shellRec,
		}, true
	case route.PowerShell:
		if rc.command == "" {
			return serverReading{}, false
		}
		lane := s.powerShellLane(req.Cwd)
		// The native-command bridge (#4768) only where no POSIX lane reads
		// the command: the Python client's Claude Code PowerShell call. A
		// PowerShell-client call keeps its legacy POSIX reading (first) and
		// no bridge: the hook bridges on every row, but here a second POSIX
		// pass would add cost under the thin clients' 5 s timeout, already
		// tight (the accepted C1 residual, #4771; Kai, 2026-11-04).
		lane.NativeBridge = !slices.Contains(rc.lanes, route.POSIX)
		result, err := lane.Read(rc.command)
		if err != nil {
			result = laneFailure(l, err)
		}
		return serverReading{
			verdict: assembly.FactsVerdict(l, &result, nil),
			resp:    shellResponse(result, rc.command),
			rec:     shellRec,
		}, true
	}
	// A lane the server cannot run is a lane failure (ADR-001 D9). No row
	// names one (internal/route's table tests); this keeps a future row from
	// being silently ignored.
	result := laneFailure(l, fmt.Errorf("shield-server has no implementation of the %s lane", l))
	return serverReading{
		verdict: assembly.ShellVerdict(l, &result, nil),
		resp:    shellResponse(result, rc.command),
		rec:     shellRec,
	}, true
}

// evalErrorRuleID is the rule id of the AUDIT a lane failure decides, the
// one the hook's fail-safe boundary writes outside managed fail_closed
// (internal/cli/fail_safe.go). shield-server has no managed fail_closed
// (docs/shield-server.md, "Fail-safe, not fail-closed").
const evalErrorRuleID = "agentshield-eval-error"

// laneFailure is the reading of a lane that could not decide (ADR-001 D9):
// AUDIT, never a crash and never a silent pass.
func laneFailure(l route.Lane, err error) policy.EvalResult {
	return policy.EvalResult{
		Decision:       policy.DecisionAudit,
		TriggeredRules: []string{evalErrorRuleID},
		Reasons:        []string{fmt.Sprintf("the %s lane failed, so the call was not fully evaluated: %v", l, err)},
	}
}

// pastChainBound is the reading of a shell text past the chain bound
// (#4778): a lane failure's AUDIT, with the chain_too_long note. The text was
// not parsed, so nothing was matched.
func pastChainBound(e *shellparse.ChainTooLongError) policy.EvalResult {
	return policy.EvalResult{
		Decision:       policy.DecisionAudit,
		TriggeredRules: []string{evalErrorRuleID},
		Reasons:        []string{fmt.Sprintf("the call was not fully evaluated: %v", e)},
		Notes:          []analyzer.Note{{Kind: analyzer.NoteChainTooLong, Detail: e.NoteDetail()}},
	}
}

// psRead is the PowerShell reader. A variable only so a test can make the
// lane fail; nothing in shield-server changes it.
var psRead = psreader.Read

// powerShellLane is the PowerShell lane (assembly.PowerShellLane, the one the
// hook runs) for a request.
//
// Two inputs differ from the hook's, because the server does not run on the
// client's host:
//
//   - The environment is the reader's Windows defaults, not this process's:
//     `$env:USERPROFILE`, `$HOME` and `~` resolve to `~`, matched against
//     protected paths as the hook matches them. A path the client spelled
//     from its home directory (`C:\Users\alice\.ssh\…`) is read as written,
//     because the client sends no home directory.
//   - The host is not managed: whether the client's host is managed is not
//     known here, and the server's POSIX lane runs no managed
//     self-protection either (no enterprise middleware).
//
// A nested bash or sh text is decided as the server's POSIX lane decides a
// command.
func (s *Server) powerShellLane(cwd string) *assembly.PowerShellLane {
	return &assembly.PowerShellLane{
		Engine:   s.engine,
		Env:      psreader.Env{},
		Opts:     policy.FactsOptions{},
		Cwd:      cwd,
		MaxDepth: assembly.NestedDepthBound(s.maxParseDepth),
		POSIX:    func(text string) policy.EvalResult { return s.readShell(text, cwd) },
		Reader:   psRead,
		// The thin clients wait 5 s; past this bound a nested sh text is not
		// read, and the call floors at AUDIT (assembly.ServerNestedPOSIXBound).
		NestedPOSIXBound: assembly.ServerNestedPOSIXBound,
		// The same for the native-command bridge's one reading, where the
		// call's route runs it (assembly.ServerNativeBridgeBytes).
		NativeBridgeBytes: assembly.ServerNativeBridgeBytes,
		// And for the inline-secrets heuristic, per text
		// (assembly.ServerInlineSecretsBytes, #4802).
		InlineSecretsBytes: assembly.ServerInlineSecretsBytes,
	}
}
