package cli

import (
	"os"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/assembly"
	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/homedir"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/psreader"
	"github.com/AI-AgentLens/agentshield/internal/route"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// The PowerShell lane in the hook (ADR-001 step 4 part 2, #4245).
//
// The lane reads a call's command text with internal/psreader and decides on
// what it read with policy.Engine.EvaluateFacts: protected paths with every
// pattern the shell enforces, and on a managed host self-protection of
// AgentShield's config directory ("only known reads pass"), and the
// PowerShell pack rules (`powershell:` match blocks, packs/community/
// powershell.yaml, step 5); and it runs the shell pipeline's inline-secrets
// heuristic over the text (#4802), so a token in a cmdlet call BLOCKs as
// guardian-secrets_in_command, as through the Bash tool. It runs only beside
// a lane its row already had (internal/route), so the combiner can only raise
// a call. The lane itself,
// nested routing included, is assembly.PowerShellLane, which shield-server
// runs too (ADR-001 step 2); this file supplies the hook's engine, its
// environment and its POSIX reading of nested text.
//
// Its reading is shell-shaped, like the POSIX lane's: the same load sequence,
// fail-safe boundary and writer (readShellShaped), with the PowerShell text as
// the event's command and the harness's shell source. The event carries
// EvaluateFacts' dialect note and the reader's notes. The lane does not run
// the enterprise middleware over its own text: on the Copilot rows POSIX runs
// the sp-* text rules over the same text, and Claude Code's row has no POSIX
// lane (as on main, nothing reads its PowerShell text with them). A nested
// bash or sh text does get them, through readPOSIX, and so do the native
// programs' argv the native-command bridge reads on every row (#4768), so
// on Claude Code's row too `agentshield setup … --disable` BLOCKs as through
// the Bash tool.
//
// Reading is side-effect free: the reader reads characters and never runs or
// evaluates them, and nothing is written until the combiner keeps the
// reading. A panic anywhere in the lane is a lane failure (ADR-001 D9): the
// reading becomes failSafeDecision's, BLOCK under managed fail_closed and
// AUDIT otherwise.

// psRead is the PowerShell reader. A variable only so a test can make the
// lane fail; nothing in the agentshield binary changes it.
var psRead = psreader.Read

// readPowerShell is the PowerShell lane's reading of cmdStr.
func readPowerShell(cmdStr, cwd, source, sessionID string, notes []logger.Note) *commandReading {
	return readShellShaped(cmdStr, cwd, source, sessionID, notes, powershellEvaluation(source))
}

// powershellEvaluation is the PowerShell lane's evaluate step. source is the
// call's shell source, which a nested POSIX reading's middleware sees. A panic
// anywhere in the lane comes back as an error (assembly.PowerShellLane.Read),
// which readShellShaped turns into failSafeDecision's reading.
func powershellEvaluation(source string) shellShapedEvaluation {
	return shellShapedEvaluation{
		stage: "lane " + string(route.PowerShell),
		evaluate: func(engine *policy.Engine, cfg *config.Config, cmdStr, cwd string) (policy.EvalResult, error) {
			home, _ := homedir.Dir()
			l := &psLane{
				engine:   engine,
				cfg:      cfg,
				env:      psreader.Env{Home: home, Vars: processEnvVars(os.Environ())},
				opts:     policy.FactsOptions{Managed: enterprise.ManagedHost(), Home: home},
				cwd:      cwd,
				source:   source,
				maxDepth: nestedDepthBound(cfg),
			}
			return l.lane().Read(cmdStr)
		},
	}
}

// nestedDepthBound is how deep the lane follows nested interpreters
// (assembly.NestedDepthBound): the analyzer's max_parse_depth, default 2.
func nestedDepthBound(cfg *config.Config) int {
	if cfg == nil {
		return assembly.NestedDepthBound(0)
	}
	return assembly.NestedDepthBound(cfg.Analyzer.MaxParseDepth)
}

// processEnvVars are the environment variables the reader resolves
// `$env:NAME` and `%NAME%` with: this process's, which the harness started
// alongside the shell it runs the call in. Windows matches names without
// regard to case, so names are keyed in upper case; when two names fold to
// one key, an upper-case spelling wins, and otherwise the first. A variable
// that is absent takes the reader's Windows default (psreader.Env).
func processEnvVars(environ []string) map[string]string {
	vars := make(map[string]string, len(environ))
	exact := map[string]bool{}
	for _, kv := range environ {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || name == "" {
			continue // Windows' per-drive "=C:=C:\…" entries have no name
		}
		key := strings.ToUpper(name)
		isExact := name == key
		if _, seen := vars[key]; seen && (exact[key] || !isExact) {
			continue
		}
		vars[key] = value
		exact[key] = isExact
	}
	return vars
}

// psLane is one call's PowerShell lane in the hook: the shared lane
// (assembly.PowerShellLane) on the call's engine, with the hook's POSIX
// reading of a nested bash or sh text.
type psLane struct {
	engine   *policy.Engine
	cfg      *config.Config // decides a nested text past the chain bound (#4778)
	env      psreader.Env
	opts     policy.FactsOptions
	cwd      string
	source   string
	maxDepth int
}

// lane is the shared lane this call reads with.
func (l *psLane) lane() *assembly.PowerShellLane {
	return &assembly.PowerShellLane{
		Engine:   l.engine,
		Env:      l.env,
		Opts:     l.opts,
		Cwd:      l.cwd,
		MaxDepth: l.maxDepth,
		POSIX:    l.readPOSIX,
		Reader:   psRead,
		// The native-command bridge (#4768) on every row the lane is on
		// (Kai, 2026-11-04). On the Copilot rows POSIX also reads the raw
		// text, but it misses a native program written the Windows way:
		// `git.exe push --force origin main` let 297 of 483 CLI BLOCKs
		// through on Copilot's native powershell row, and 4 with the bridge,
		// for +0.6% hook time. The bridge's lines are read like a nested bash
		// text: on this call's engine, the enterprise middleware first
		// (readPOSIX).
		NativeBridge: true,
	}
}

// readPOSIX is the POSIX lane's decision on a nested bash or sh text, on this
// call's engine: the enterprise middleware, then the analyzer pipeline, as
// readCommand decides a call. The engine is the outer call's, so on a managed
// host its config directory is protected for every text, the strict side of
// the plain-read exception protectManagedConfigDir grants a whole command.
//
// A text past the chain bound, or one a reading derived from it, is not
// parsed (#4778): its reading is failSafeDecision's decision with the
// chain_too_long note (AUDIT, BLOCK under managed fail_closed), which the
// lane combines like any nested reading and whose note floors the call at
// AUDIT (assembly.UncertainNote).
func (l *psLane) readPOSIX(text string) policy.EvalResult {
	hookSlowPoint("nested-posix")
	var blocked *policy.EvalResult
	var ok bool
	if chain := shellparse.GuardChainBound(text, func() { blocked, ok = middlewareBlock(text, l.cwd, l.source) }); chain != nil {
		// Past the bound, a managed host still reads the raw text with the
		// self-protection rules (middlewareBlockPastChainBound).
		if blocked, ok := middlewareBlockPastChainBound(text, l.cwd, l.source); ok {
			r := *blocked
			r.Notes = append(r.Notes, chainTooLongNote(chain))
			return r
		}
		return pastChainBoundResult(chain, l.cfg)
	}
	if ok {
		return *blocked
	}
	r, chain := readPOSIXText(l.engine, text, l.cwd)
	if chain != nil {
		return pastChainBoundResult(chain, l.cfg)
	}
	return r
}

// factsLaneVerdict adapts the PowerShell lane's reading
// (assembly.FactsVerdict) with the notes its event carries, which hold the
// result's and the hook's own; nil takes the result's.
func factsLaneVerdict(lane route.Lane, r *policy.EvalResult, notes []logger.Note) route.Verdict {
	var ns []route.Note
	if notes != nil {
		ns = make([]route.Note, 0, len(notes))
		for _, n := range notes {
			ns = append(ns, route.Note{Kind: n.Kind, Rule: n.Rule, Detail: n.Detail})
		}
	}
	return assembly.FactsVerdict(lane, r, ns)
}
