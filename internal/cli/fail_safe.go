package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/datalabel"
	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// The error-to-decision boundary (#3619).
//
// evaluateCommand can fail before it reaches a verdict: config unreadable,
// audit log unwritable, policy unparseable, a pack dropped, the engine
// refusing to build (an unknown intent label, say). Each of those used to be
// handled at its own site — three became a BLOCK under managed fail_closed,
// two returned a plain error, and every harness handler turned an error into
// `return nil // fail open`. Reproduced on 2026-09-01: with managed.json
// {"managed":true,"fail_closed":true} and one typo'd command_intent_exclude
// label in policy.yaml, `rm -rf /` exited 0 with a warning and no audit event.
//
// failSafeDecision is the single place a failure becomes a decision, so there
// is exactly one answer to "what happens when evaluation cannot run" and every
// dialect inherits it:
//
//   - managed fail_closed → BLOCK, rule id enterprise-fail-closed, the error
//     in the reason and on the event;
//   - a command past the chain bound (#4778) on a managed host without
//     fail_closed → BLOCK, rule id enterprise-chain-too-long (Gary,
//     2026-11-04: past the bound every managed host BLOCKs);
//   - otherwise → the fail-safe default, AUDIT (the command runs), with a
//     flagged event carrying the error so the failure is visible in the audit
//     log and on the SaaS — never a silent allow.
//
// The event is written when a logger exists (it does not for config-load and
// audit-log-init failures) and always forwarded to the SaaS.

const (
	// failClosedRuleID is the sentinel rule id on a BLOCK produced by the
	// boundary under managed fail_closed.
	failClosedRuleID = "enterprise-fail-closed"
	// evalErrorRuleID is the sentinel rule id on the AUDIT produced by the
	// boundary outside managed fail_closed.
	evalErrorRuleID = "agentshield-eval-error"
	// chainTooLongManagedRuleID is the sentinel rule id on the BLOCK a managed
	// host without fail_closed makes for a command past the chain bound
	// (#4778, Gary 2026-11-04: "past the chain bound, every managed host
	// BLOCKs"). No rule matched: the command was not evaluated, so it names
	// no taxonomy node. A call the self-protection rules match on its raw
	// text keeps their record instead (enterprise-self-protect). The MCP
	// proxies' config guard blocks with the same id (#4823 Opus pass 1).
	chainTooLongManagedRuleID = enterprise.ChainTooLongRuleID
)

// eventLogger is the slice of the audit logger the boundary needs:
// LogLinkedRedacted for the disk line and its chain link (sent with the
// event, #4208), and the lock note so the wire payload matches it.
type eventLogger interface {
	LogLinkedRedacted(event logger.RedactedEvent) (*logger.ChainLink, error)
	lockNoteSource
}

// evalFailure describes where evaluation stopped. cfg is nil when config
// itself failed to load; log is nil when no audit logger could be opened.
type evalFailure struct {
	stage string
	err   error
	cfg   *config.Config
	log   eventLogger
	// notes are the caller's notes about this evaluation (#4452), carried
	// onto the fail-safe event like any other.
	notes []logger.Note
	// labels is the data-label set the evaluation had loaded when it
	// stopped (#4805), nil when it stopped before the shell policy was
	// complete; failSafeReading then reads the labels itself.
	labels *recordLabels
	// chainTooLong marks a failure that is the chain bound (#4778): on a
	// managed host without fail_closed it BLOCKs (chainTooLongManagedRuleID)
	// where any other failure is AUDIT.
	chainTooLong bool
}

// The record never carries the value it stopped (#4448), on the fail-safe
// path too (#4805).
//
// The normal path scrubs its event with the data labels the policy declares.
// A fail-safe reading scrubs its own the same way, with the same scrubber:
// the evaluation's label set when it had loaded one (engine init, a lane's
// failure or panic, and the decision budget's answer once the policy is
// loaded). When it stopped before that (the config, the audit log, the policy
// or a pack failed, or the budget answered first), it reads the data_labels
// declarations on their own (policy.LoadDeclaredDataLabels), from the files the
// evaluation would have loaded. When those cannot be read, or the labels do
// not compile, nothing can find a label value in the text, so the event
// withholds the agent's text instead (logger.WithAgentTextWithheld): the
// command, its args, the MCP arguments, the cwd, every note detail
// AgentShield did not write from its own text, and the failure's own error
// and reason, which can quote what it choked on (apply). The decision is never
// involved: it is failSafeVerdict's, computed before any of this, and the
// harness's verdict text is the decision's, unchanged.

// recordLabels is what keeps one record from carrying a data-label value.
type recordLabels struct {
	// scrub is the labels' Engine.Spans, the scrubber an event's Redacted()
	// masks them with (#4813); nil when none are declared.
	scrub func(string) []datalabel.Span
	// withheld is set when the labels could not be read or compiled: the
	// agent_text_withheld note's detail, saying why.
	withheld string
}

// labelsFor compiles labels into a record's scrubber. A set that does not
// compile scrubs nothing, so its record withholds.
func labelsFor(labels []policy.DataLabel) *recordLabels {
	scrub, err := policy.DataLabelScrubber(labels)
	if err != nil {
		// The compile error quotes the label's pattern: not for the record.
		return &recordLabels{withheld: "data labels unusable: they do not compile, so nothing can find a label value in the text"}
	}
	return &recordLabels{scrub: scrub}
}

// declaredLabels reads the data labels a call's shell policy declares, alone,
// for a fail-safe reading that stopped before the policy was complete. The
// files are cfg's, or with no cfg the ones config.Load would have read.
func declaredLabels(cfg *config.Config) *recordLabels {
	var configDir, policyFile string
	if cfg != nil {
		configDir, policyFile = cfg.ConfigDir, cfg.PolicyPath
	} else {
		var err error
		if configDir, policyFile, err = config.PolicyLocation(policyPath); err != nil {
			return &recordLabels{withheld: "data labels unreadable: the home directory is unknown"}
		}
	}
	labels, err := policy.LoadDeclaredDataLabels(policyFile, filepath.Join(configDir, "packs"))
	if err != nil {
		return &recordLabels{withheld: "data labels unreadable: " + labelSourceFailures(err)}
	}
	return labelsFor(labels)
}

// labelSourceFailures names each source of labels that could not be read and
// how: the file system's own words for a read, "does not parse" for a parse.
// Never the parse error itself: a YAML error quotes the text it choked on,
// which in a data_labels block is a label's keyword or pattern.
func labelSourceFailures(err error) string {
	var parts []string
	var walk func(error)
	walk = func(e error) {
		if joined, ok := e.(interface{ Unwrap() []error }); ok {
			for _, x := range joined.Unwrap() {
				walk(x)
			}
			return
		}
		var de *policy.DeclaredLabelsError
		if !errors.As(e, &de) {
			parts = append(parts, "a source could not be read")
			return
		}
		how := "data_labels does not parse"
		var pe *fs.PathError
		if errors.As(de.Err, &pe) {
			how = pe.Err.Error()
		}
		parts = append(parts, de.Source+": "+how)
	}
	walk(err)
	return strings.Join(parts, "; ")
}

// apply gives e, the event of fail-safe reading f, the scrubber, or marks
// its agent text withheld. A withheld event's error and reason become
// withheldCause's (Gary, 2026-11-06): the failure's own text can quote what
// it choked on, a label's keyword or pattern among them. block is the
// reading's decision, which the reason states as before. A nil set, or one
// with no labels, leaves e exactly as it was.
func (l *recordLabels) apply(e logger.AuditEvent, f evalFailure, block bool) logger.AuditEvent {
	switch {
	case l == nil:
		return e
	case l.withheld != "":
		cause := withheldCause(f.err)
		return e.WithAgentTextWithheld(logger.Withheld{
			Detail:  l.withheld,
			Error:   cause,
			Reasons: []string{failSafeReason(block, f.stage, cause)},
		})
	case l.scrub != nil:
		return e.WithScrubber(l.scrub)
	}
	return e
}

// withheldCause is what a withheld fail-safe event records in place of its
// failure's text: the file the failure could not read, in the file system's
// words, when the failure was a read, and otherwise "(cause withheld)". Never
// a parse or compile error, which quotes the text it choked on, and never the
// labels' own failure, a different read the agent_text_withheld note names:
// "policy load failed — …: …/packs: not a directory" read as the policy's
// cause when the policy had failed on its YAML (#4814 item 2).
func withheldCause(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Op + " " + pe.Path + ": " + pe.Err.Error()
	}
	return "(cause withheld)"
}

// failClosedEnabled reports whether managed fail-closed mode is on. It
// prefers the loaded config (one definition of "managed" — see
// internal/policy/remediation) and falls back to reading managed.json
// directly when config itself could not be loaded, so a config-load failure
// cannot switch the guarantee off.
func failClosedEnabled(cfg *config.Config) bool {
	if cfg != nil && cfg.Managed != nil {
		return cfg.Managed.FailClosed
	}
	if m := enterprise.LoadManagedConfig(); m != nil {
		return m.FailClosed
	}
	return false
}

// managedEnabled reports whether this is a managed host, read the way
// failClosedEnabled reads fail_closed: the loaded config, else managed.json.
func managedEnabled(cfg *config.Config) bool {
	if cfg != nil && cfg.Managed != nil {
		return cfg.Managed.Managed
	}
	if m := enterprise.LoadManagedConfig(); m != nil {
		return m.Managed
	}
	return false
}

// mcpRulesetDegraded describes why the MCP ruleset about to be evaluated is
// not the one configured, or "" when it is. Every source is a real failure:
// config unreadable, an MCP policy file that exists but does not parse, a
// packs directory that exists but cannot be read, a pack that failed to parse.
// An ABSENT policy file or packs directory is not degraded — the loaders
// return the embedded defaults for those without a warning.
func mcpRulesetDegraded(cfgErr error, loaded *loadedMCPPolicy) string {
	var parts []string
	if cfgErr != nil {
		parts = append(parts, "config load: "+cfgErr.Error())
	}
	if loaded != nil {
		parts = append(parts, loaded.Warnings...)
		for _, infos := range [][]mcp.MCPPackInfo{loaded.Embedded, loaded.Disk, loaded.LegacyDisk} {
			for _, fp := range mcp.FailedMCPPacks(infos) {
				parts = append(parts, fmt.Sprintf("pack %s failed to parse: %v", fp.Path, fp.LoadError))
			}
		}
	}
	return strings.Join(parts, "; ")
}

// hookInputFailure is the boundary for failures that happen before there is a
// command to evaluate: stdin unreadable, or not the JSON a harness sends. The
// dialect is unknown at that point, so a BLOCK is signalled the one way every
// harness understands — a message on stderr and exit code 2 — and an allow is
// a plain return with the warning. No audit logger exists yet either; the
// event still goes to the SaaS through sendRemoteAudit.
func hookInputFailure(stage string, err error) error {
	// The dialect is unknown, but a harness that names itself through
	// AGENTSHIELD_AGENT_ID still gets its own verdict format (#4251).
	return hookInputFailureFor(hookSourceFor(hookInput{}, "hook"), stage, err)
}

// hookInputFailureFor is hookInputFailure for a caller that already knows
// which harness sent the payload — Copilot CLI's native dialect is
// recognisable before its toolArgs fail to decode.
func hookInputFailureFor(source, stage string, err error) error {
	res, _ := failSafeDecision(evalFailure{stage: stage, err: err}, "<unparseable hook input>", "", "hook", "")
	if res.Decision == policy.DecisionBlock {
		fmt.Fprintf(os.Stderr, "🛡️ AgentShield BLOCKED this command\n   Reason: %s\n", res.Explanation)
		emitCopilotDeny(source, "this command", res.TriggeredRules, []string{res.Explanation})
		os.Exit(2)
	}
	return nil
}

// failSafeDecision converts an evaluation failure into the decision every
// harness handler acts on. See the package comment above for the contract.
// It claims the call before it writes (hook_budget.go), as every other
// writer on the hook's path does.
func failSafeDecision(f evalFailure, cmdStr, cwd, source, sessionID string) (*policy.EvalResult, *logger.AuditEvent) {
	activeBudget.claimForEvaluation()
	result, event, write := failSafeReading(f, cmdStr, cwd, source, sessionID)
	write(event)
	return result, event
}

// failSafeReading is failSafeDecision up to the point it writes: the decision,
// the event, and write, which records the event (the local line when a logger
// exists, and the SaaS queue). It writes nothing itself, so a lane the
// combiner does not keep leaves no record (ADR-001 D4, D9).
func failSafeReading(f evalFailure, cmdStr, cwd, source, sessionID string) (*policy.EvalResult, *logger.AuditEvent, func(*logger.AuditEvent)) {
	result, modeStr := failSafeVerdict(f)
	event := logger.AuditEvent{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Command:        cmdStr,
		Args:           strings.Fields(cmdStr),
		Cwd:            cwd,
		Decision:       string(result.Decision),
		Flagged:        true,
		TriggeredRules: result.TriggeredRules,
		Reasons:        result.Reasons,
		Mode:           modeStr,
		Source:         source,
		SessionID:      sessionID,
		Principal:      osPrincipal(),
		Error:          f.err.Error(),
		Notes:          append([]logger.Note(nil), f.notes...),
	}
	// #4805: scrubbed like the normal path's event, or withheld.
	labels := f.labels
	if labels == nil {
		labels = declaredLabels(f.cfg)
	}
	event = labels.apply(event, f, result.Decision == policy.DecisionBlock)
	write := func(event *logger.AuditEvent) {
		noteLockUnavailable(event, f.log)
		// One redaction for the line and the wire entry (#4781).
		red := redactForRecord(event)
		var link *logger.ChainLink
		if f.log != nil {
			var err error
			if link, err = f.log.LogLinkedRedacted(red); err != nil {
				fmt.Fprintf(os.Stderr, "[AgentShield] warning: audit log failed: %v\n", err)
			}
		}
		sendRemoteAuditRedacted(red, link)
	}
	return &result, &event, write
}

// failSafeToolCallReading is failSafeReading for a call only MCP policy
// reads (the hook's decision budget is its one caller): the same decision,
// recorded as the tool-call event auditMCPCall writes for that call, with the
// error on it, and emitted as the MCP path emits a decision. Like that event
// it is not scrubbed of data labels: the hook's MCP path reads none (#4448's
// "not covered"), and #4805 left that path as it is.
func failSafeToolCallReading(f evalFailure, toolName string, rawToolInput json.RawMessage, source, sessionID, cwd string) *toolCallReading {
	result, modeStr := failSafeVerdict(f)
	arguments, _ := toolCallArguments(rawToolInput)
	return &toolCallReading{
		toolName:  toolName,
		arguments: arguments,
		result: mcp.MCPEvalResult{
			Decision:       result.Decision,
			TriggeredRules: result.TriggeredRules,
			Reasons:        result.Reasons,
		},
		source:    source,
		mode:      modeStr,
		sessionID: sessionID,
		auditCwd:  cwd,
		notes:     append([]logger.Note(nil), f.notes...),
		errText:   f.err.Error(),
		emitFor:   emitFailSafeToolCall,
	}
}

// emitFailSafeToolCall is the verdict of a tool call's fail-safe reading:
// the degraded-ruleset BLOCK's output under fail_closed, the MCP policy
// verdict's AUDIT line otherwise.
func emitFailSafeToolCall(r *toolCallReading) {
	if r.result.Decision == policy.DecisionBlock {
		emitMCPFailClosedBlock(r)
		return
	}
	emitMCPPolicyVerdict(r)
}

// failSafeReason is the reason of a fail-safe decision: BLOCK under managed
// fail_closed (block), AUDIT otherwise, for a failure at stage whose cause
// is cause.
func failSafeReason(block bool, stage, cause string) string {
	if block {
		return fmt.Sprintf("AgentShield: %s failed — blocking (fail_closed enabled): %s", stage, cause)
	}
	return fmt.Sprintf("AgentShield: %s failed — evaluated as AUDIT (fail-safe default, not enforced): %s", stage, cause)
}

// failSafeVerdict is the fail-safe decision for f and the mode its event
// records, with the warning every fail-safe reading prints on stderr.
func failSafeVerdict(f evalFailure) (policy.EvalResult, string) {
	failClosed := failClosedEnabled(f.cfg)
	// Past the chain bound a managed host BLOCKs even without fail_closed
	// (#4778, Gary 2026-11-04). Under fail_closed the record stays
	// enterprise-fail-closed.
	managedChainBlock := !failClosed && f.chainTooLong && managedEnabled(f.cfg)

	var result policy.EvalResult
	reason := failSafeReason(failClosed, f.stage, fmt.Sprint(f.err))
	if failClosed {
		result = policy.EvalResult{
			Decision:       policy.DecisionBlock,
			TriggeredRules: []string{failClosedRuleID},
			Reasons:        []string{reason},
			Explanation:    reason,
		}
	} else if managedChainBlock {
		reason := fmt.Sprintf("AgentShield: %s failed — blocking on a managed host, which does not run a command it could not evaluate: %v", f.stage, f.err)
		result = policy.EvalResult{
			Decision:       policy.DecisionBlock,
			TriggeredRules: []string{chainTooLongManagedRuleID},
			Reasons:        []string{reason},
			Explanation:    reason,
		}
	} else {
		result = policy.EvalResult{
			Decision:       policy.DecisionAudit,
			TriggeredRules: []string{evalErrorRuleID},
			Reasons:        []string{reason},
			Explanation:    reason,
		}
	}
	fmt.Fprintf(os.Stderr, "[AgentShield] warning: %s\n", result.Explanation)

	modeStr := ""
	if f.cfg != nil {
		modeStr = f.cfg.Mode
	}
	if failClosed || managedChainBlock {
		modeStr = "managed"
	}
	return result, modeStr
}
