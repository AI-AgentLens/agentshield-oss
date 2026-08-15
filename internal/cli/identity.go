package cli

import (
	"os"
	"os/user"
	"sync"
)

// Identity plane for the audit wire (issue #3111).
//
// Scope note, deliberately narrow: AgentShield reports only identity it can
// observe first-hand at hook time. It does not invent a session concept, and
// it does not attempt to name the *agent* as a principal — the agent runs
// in-process with the developer's shell under the developer's OS credentials,
// so the OS user is the honest answer to "who acted." Richer identity
// (workload identity, agent credentials) belongs to whichever plane actually
// issues them; the evidence plane ingests it, it does not fabricate it.

var (
	principalOnce sync.Once
	principalVal  string
)

// osPrincipal returns the OS user the AgentShield hook is running as, or ""
// if it cannot be determined. Resolved once per process — the hook runs on
// every tool call, and user.Current() can hit the name-service on some
// systems.
func osPrincipal() string {
	principalOnce.Do(func() {
		if u, err := user.Current(); err == nil && u.Username != "" {
			principalVal = u.Username
			return
		}
		// Fallback for environments where the name-service lookup fails
		// (static builds, minimal containers) but the environment is set.
		for _, key := range []string{"USER", "LOGNAME", "USERNAME"} {
			if v := os.Getenv(key); v != "" {
				principalVal = v
				return
			}
		}
	})
	return principalVal
}

// sessionIDFor extracts the harness-provided session identifier from a hook
// payload. Claude Code and Codex send `session_id`; Windsurf's per-agent-run
// identifier is `trajectory_id`. Cursor sends neither, so its events carry an
// empty session — see the AuditEvent.SessionID comment for why we leave it
// empty rather than minting one.
func sessionIDFor(input hookInput) string {
	if input.SessionID != "" {
		return input.SessionID
	}
	return input.TrajectoryID
}
