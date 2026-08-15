package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/execenv"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/policy/remediation"
)

// Options configures a Server. Zero values resolve to the same defaults the
// IDE hook uses (~/.agentshield/*), so a bare `shield-server` evaluates with
// exactly the ruleset a local install would.
type Options struct {
	PolicyPath    string // shell policy override; skips disk packs like `check --policy` (#3030)
	MCPPolicyPath string // MCP policy override
	LogPath       string // audit log path override
	Mode          string // enforce | audit-only
	Token         string // static bearer token for /v1/*; empty means loopback-only (enforced in main)
	Version       string
}

// Server holds everything loaded once at startup. config.Load re-reads
// ~/.agentshield/agentshield.yaml + policy.yaml from disk and mkdirs the
// config dir on every call, so it must run exactly once here — not
// per-request the way the one-shot CLI surfaces do.
//
// Concurrency: one *policy.Engine built via NewEngineWithAnalyzers is shared
// across requests. That path is read-only after construction (regex caches
// are fully precompiled in the constructors; IntentClassifier memoization is
// per-evaluation). The regex-FALLBACK engine path (nil registry) is NOT
// goroutine-safe — never construct this server around it.
type Server struct {
	engine      *policy.Engine
	mcpEval     *mcp.PolicyEvaluator
	sessions    *sessionStore
	audit       logger.Logger // nil when the audit log could not be opened
	token       string
	mode        string
	version     string
	degraded    bool
	failedPacks []string
	warnings    []string
}

// NewServer loads config, shell policy, MCP policy, and the audit logger —
// mirroring the IDE hook's load order so a remote verdict matches what the
// same command would get from a local install (the same faithful-predictor
// contract `agentshield check` keeps, #1952/#3030).
func NewServer(opts Options) (*Server, error) {
	cfg, err := config.Load(opts.PolicyPath, opts.LogPath, opts.Mode)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	if opts.Mode != "" {
		cfg.Mode = opts.Mode
	}

	s := &Server{
		sessions: newSessionStore(),
		token:    opts.Token,
		mode:     cfg.Mode,
		version:  opts.Version,
	}

	if err := s.loadShellEngine(cfg, opts.PolicyPath); err != nil {
		return nil, err
	}
	s.loadMCPEvaluator(cfg, opts.MCPPolicyPath)

	// Audit logging is best-effort: an unwritable log degrades evidence, not
	// enforcement (fail-safe defaults). The handler reports degradation via
	// /healthz instead of refusing verdicts.
	if audit, err := logger.New(cfg.LogPath); err != nil {
		s.warnings = append(s.warnings, fmt.Sprintf("audit log %s unavailable (%v); evaluations will NOT be recorded", cfg.LogPath, err))
	} else {
		s.audit = audit
	}

	s.degraded = len(s.failedPacks) > 0
	return s, nil
}

// loadShellEngine mirrors internal/cli/check.go loadCheckPolicy — kept in
// lock-step by hand because those helpers are deliberately unexported and
// importing internal/cli would drag the whole cobra CLI in via its init()s.
func (s *Server) loadShellEngine(cfg *config.Config, policyOverride string) error {
	basePath := policyOverride
	if basePath == "" {
		basePath = cfg.PolicyPath
	} else if _, err := os.Stat(basePath); err != nil {
		// The operator named the file; a typo must surface, not fall back.
		return fmt.Errorf("policy file %s not found: %w", basePath, err)
	}

	pol, err := policy.Load(basePath)
	if err != nil {
		return fmt.Errorf("load policy %s: %w", basePath, err)
	}

	pol, embeddedInfos, _ := policy.LoadEmbeddedShellPacks(pol)

	// #3030: an explicit --policy skips machine-local disk packs so the named
	// file cannot be shadowed by a stale deployed copy of the same rule.
	var diskInfos []policy.PackInfo
	if policyOverride == "" {
		packsDir := filepath.Join(cfg.ConfigDir, "packs")
		if merged, infos, err := policy.LoadPacks(packsDir, pol); err == nil && merged != nil {
			pol = merged
			diskInfos = infos
		}
	}
	for _, fp := range append(policy.FailedPacks(embeddedInfos), policy.FailedPacks(diskInfos)...) {
		s.failedPacks = append(s.failedPacks, fp.Path)
		s.warnings = append(s.warnings, fmt.Sprintf("pack %q failed to parse — its rules are NOT loaded: %v", fp.Path, fp.LoadError))
	}

	engine, err := policy.NewEngineWithAnalyzers(pol, cfg.Analyzer.MaxParseDepth)
	if err != nil {
		return fmt.Errorf("create policy engine: %w", err)
	}
	engine.SetMode(cfg.Mode)
	engine.SetExecContext(execenv.Detect(os.Getenv))
	s.engine = engine
	return nil
}

// loadMCPEvaluator mirrors internal/cli/mcp_policy.go loadDeployedMCPPolicy:
// user policy → embedded community packs → ~/.agentshield/mcp-packs → legacy
// packs/mcp (only when the disk layer is empty), deduped by pack name so a
// pre-2026-04 on-disk copy of a community pack cannot double-fire (#1628).
// Fail-safe: soft errors become warnings, embedded rules always enforce.
func (s *Server) loadMCPEvaluator(cfg *config.Config, policyOverride string) {
	policyFile := policyOverride
	if policyFile == "" {
		policyFile = filepath.Join(cfg.ConfigDir, mcp.DefaultMCPPolicyFile)
	}

	mcpPolicy := mcp.DefaultMCPPolicy()
	if loadedPolicy, err := mcp.LoadMCPPolicy(policyFile); err != nil {
		if !os.IsNotExist(err) {
			s.warnings = append(s.warnings, fmt.Sprintf("MCP policy %s could not be parsed (%v); using embedded community rules", policyFile, err))
		}
	} else {
		mcpPolicy = loadedPolicy
	}

	mcpPolicy, embedded, _ := mcp.LoadEmbeddedMCPPacks(mcpPolicy)
	loadedNames := map[string]bool{}
	for _, p := range embedded {
		loadedNames[p.Name] = true
	}
	for _, fp := range mcp.FailedMCPPacks(embedded) {
		s.failedPacks = append(s.failedPacks, fp.Path)
	}

	packsDir := filepath.Join(cfg.ConfigDir, mcp.DefaultMCPPacksDir)
	legacyDir := filepath.Join(cfg.ConfigDir, "packs", "mcp")
	var disk []mcp.MCPPackInfo
	if merged, infos, err := mcp.LoadMCPPacksExcluding(packsDir, mcpPolicy, loadedNames); err != nil {
		s.warnings = append(s.warnings, fmt.Sprintf("MCP packs dir %s could not be read (%v); skipping disk packs", packsDir, err))
	} else if merged != nil {
		mcpPolicy = merged
		disk = infos
		for _, p := range infos {
			loadedNames[p.Name] = true
		}
	}
	if len(disk) == 0 && legacyDir != packsDir {
		if merged, _, err := mcp.LoadMCPPacksExcluding(legacyDir, mcpPolicy, loadedNames); err == nil && merged != nil {
			mcpPolicy = merged
		}
	}

	s.mcpEval = mcp.NewPolicyEvaluator(mcpPolicy)
	s.mcpEval.SetMode(cfg.Mode)
}

// Close releases the audit logger. Safe on a nil logger.
func (s *Server) Close() {
	if s.audit != nil {
		_ = s.audit.Close()
	}
}

// --- HTTP surface -----------------------------------------------------------

// evaluateRequest is the /v1/evaluate wire format, v1. Additive changes only:
// this schema is the seam every thin client (curl hook, CI wrapper, gateway
// callout) builds against. Exactly one of Command / ToolName must be set —
// mirroring how the IDE hook branches shell vs MCP on tool name.
//
// AgentID / SessionID / Principal are carried from day one (identity plane,
// issue #3111): the server side is exactly where identity data appears, and
// retrofitting it onto an evidence schema later is brutal.
type evaluateRequest struct {
	Command         string                 `json:"command,omitempty"`
	Cwd             string                 `json:"cwd,omitempty"`
	ToolName        string                 `json:"tool_name,omitempty"`
	Arguments       map[string]interface{} `json:"arguments,omitempty"`
	ToolDescription string                 `json:"tool_description,omitempty"`
	SessionID       string                 `json:"session_id,omitempty"`
	AgentID         string                 `json:"agent_id,omitempty"`
	Principal       string                 `json:"principal,omitempty"`
	Source          string                 `json:"source,omitempty"`
}

type evaluateResponse struct {
	Decision         string   `json:"decision"`
	Rules            []string `json:"rules,omitempty"`
	Reasons          []string `json:"reasons,omitempty"`
	Taxonomy         []string `json:"taxonomy,omitempty"`
	Explanation      string   `json:"explanation,omitempty"`
	OriginalDecision string   `json:"original_decision,omitempty"`
	Remediation      string   `json:"remediation,omitempty"`
	Mode             string   `json:"mode"`
	Degraded         bool     `json:"degraded"`
	SessionID        string   `json:"session_id,omitempty"`
}

type healthResponse struct {
	Status      string   `json:"status"`
	Version     string   `json:"version"`
	Mode        string   `json:"mode"`
	Degraded    bool     `json:"degraded"`
	FailedPacks []string `json:"failed_packs,omitempty"`
}

// Handler returns the routed HTTP handler. /healthz is unauthenticated (it
// leaks only load state, and probes need it); everything under /v1/ requires
// the bearer token when one is configured.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.Handle("/v1/evaluate", s.requireAuth(http.HandlerFunc(s.handleEvaluate)))
	return mux
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	if s.token == "" {
		return next // loopback-only operation, enforced at startup
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, prefix) ||
			subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(h, prefix)), []byte(s.token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or missing bearer token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	writeJSON(w, http.StatusOK, healthResponse{
		Status:      "ok",
		Version:     s.version,
		Mode:        s.mode,
		Degraded:    s.degraded,
		FailedPacks: s.failedPacks,
	})
}

func (s *Server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)

	var req evaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	if (req.Command == "") == (req.ToolName == "") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "exactly one of command or tool_name must be set"})
		return
	}

	var resp evaluateResponse
	if req.Command != "" {
		resp = s.evaluateShell(req)
	} else {
		resp = s.evaluateMCP(req)
	}
	resp.Mode = s.mode
	resp.Degraded = s.degraded
	resp.SessionID = req.SessionID

	s.logAudit(req, resp)
	writeJSON(w, http.StatusOK, resp)
}

// evaluateShell mirrors the IDE hook's evaluation path (see the lock-step
// note in internal/cli/check.go): NormalizeCommand tokenizes for the
// path-extraction state machine but parses the AST from the original string
// (#2831), and the parsed AST feeds the structural + downstream analyzers.
func (s *Server) evaluateShell(req evaluateRequest) evaluateResponse {
	normalized := normalize.NormalizeCommand(req.Command, req.Cwd)
	result := s.engine.EvaluateWithParsedCwd(req.Command, normalized.Paths, normalized.Parsed, req.Cwd)
	return evaluateResponse{
		Decision:         string(result.Decision),
		Rules:            result.TriggeredRules,
		Reasons:          result.Reasons,
		Taxonomy:         result.TaxonomyRefs,
		Explanation:      result.Explanation,
		OriginalDecision: string(result.OriginalDecision),
		Remediation:      remediation.SuggestForShell(result.TriggeredRules, req.Command),
	}
}

func (s *Server) evaluateMCP(req evaluateRequest) evaluateResponse {
	args := req.Arguments
	if args == nil {
		args = map[string]interface{}{}
	}

	// Per-session call history feeds sequence rules. The in-process MCP proxy
	// shares one history across all clients (documented caveat in
	// call_history.go); keying by the caller-supplied session_id here is
	// strictly better. No session_id → no history, honestly, rather than a
	// synthesized one correlating unrelated calls.
	var history []mcp.RecordedCall
	var tracker *mcp.MCPCallHistoryTracker
	if req.SessionID != "" {
		tracker = s.sessions.get(req.SessionID)
		history = tracker.History()
	}

	result := s.mcpEval.EvaluateToolCallWithHistory(req.ToolName, args, req.ToolDescription, history)

	// value_limits rules are a separate numeric-threshold pass merged after
	// the rule matcher, gated on not-already-BLOCKed — kept in lock-step with
	// internal/cli/mcp_eval.go and mcp/handler.go, or this surface silently
	// mis-simulates every value_limits rule in the corpus (#3169).
	if result.Decision != policy.DecisionBlock {
		vlResult := s.mcpEval.CheckValueLimits(req.ToolName, args)
		if vlResult.Blocked {
			result.Decision = policy.DecisionBlock
			result.TriggeredRules = append(result.TriggeredRules, "value-limit")
			for _, f := range vlResult.Findings {
				if f.RuleID != "" {
					result.TriggeredRules = append(result.TriggeredRules, f.RuleID)
				}
				result.Reasons = append(result.Reasons, fmt.Sprintf("value_limit: %s (arg: %s, value: %.2f, %s)", f.Reason, f.ArgName, f.Value, f.Limit))
			}
		} else if len(vlResult.Findings) > 0 {
			result.TriggeredRules = append(result.TriggeredRules, "value-limit-audit")
			for _, f := range vlResult.Findings {
				if f.RuleID != "" {
					result.TriggeredRules = append(result.TriggeredRules, f.RuleID)
				}
				result.Reasons = append(result.Reasons, fmt.Sprintf("value_limit_audit: %s (arg: %s, value: %.2f, %s)", f.Reason, f.ArgName, f.Value, f.Limit))
			}
		}
	}

	if tracker != nil {
		// Record after evaluation so history holds prior calls only — a rule
		// matching "call X after call Y" must not see the current call as
		// its own predecessor.
		tracker.Record(req.ToolName, args)
	}

	return evaluateResponse{
		Decision:         string(result.Decision),
		Rules:            result.TriggeredRules,
		Reasons:          result.Reasons,
		Taxonomy:         result.AllTaxonomyRefs(), // both Go-intercept and YAML-rule refs (#3111)
		OriginalDecision: string(result.OriginalDecision),
		Remediation:      remediation.SuggestForMCP(result.TriggeredRules),
	}
}

func (s *Server) logAudit(req evaluateRequest, resp evaluateResponse) {
	if s.audit == nil {
		return
	}
	source := req.Source
	if source == "" {
		source = "shield-server"
	}
	_ = s.audit.Log(logger.AuditEvent{
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Command:          req.Command,
		Cwd:              req.Cwd,
		Decision:         resp.Decision,
		Flagged:          len(resp.Rules) > 0,
		TriggeredRules:   resp.Rules,
		Reasons:          resp.Reasons,
		TaxonomyRefs:     resp.Taxonomy,
		Mode:             resp.Mode,
		OriginalDecision: resp.OriginalDecision,
		Source:           source,
		SessionID:        req.SessionID,
		Principal:        req.Principal,
		ToolName:         req.ToolName,
		MCPArguments:     req.Arguments,
	})
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil && !errors.Is(err, http.ErrHandlerTimeout) {
		// Nothing useful to do: headers are gone. Encoding of our own structs
		// cannot fail; this guards broken client connections only.
		_ = err
	}
}
