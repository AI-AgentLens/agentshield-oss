package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/logger"
)

// payloadEvalCwd returns the directory a Claude-shaped PreToolUse payload's
// command is evaluated against: Claude Code, Codex CLI and both Copilot CLI
// dialects (#4452).
//
// Before #4452 that path passed "" to evaluateCommand, which then used
// os.Getwd() of the hook PROCESS. Every cwd-relative step ran against that
// directory: relative-path resolution in normalize and the protected-path
// checks, the bare-operand existence check, and the artifact-hash stage, which
// skipped silently when the script was not found there. The payload's cwd is
// where the agent's shell actually runs the command, so it is the right base
// whenever it can be used.
//
// It is used when it is an absolute path to an existing directory. Otherwise
// the result is "" (evaluateCommand's os.Getwd() fallback, i.e. exactly what
// main did for every payload) plus a note saying why:
//
//   - empty: no note. Payloads without a cwd evaluated against the process
//     directory before #4452 too, and a note on each would be noise.
//   - relative: there is no base to resolve it against that the harness
//     meant. Joining it onto the process directory would be a guess combining
//     two sources; no supported harness sends one.
//   - missing, unreadable, or not a directory: the hook cannot see the
//     directory the payload names, so a relative path in the command cannot
//     be checked there (the bare-operand and artifact-hash steps read the
//     filesystem). Using the string lexically would let an unverifiable value
//     move resolution away from where main resolved it; falling back keeps
//     main's decision for that payload.
//
// The fallback never errors out of the hook: a bad cwd is a fact about the
// payload, recorded on the event, not an evaluation failure.
//
// A usable payload cwd that is the same directory as the process's (by file
// identity) yields the process's own spelling of it, so those invocations
// evaluate exactly as on main. Claude Code spawns the hook in the directory
// it reports, so that is its ordinary case. A different directory is used as sent: not cleaned,
// not symlink-resolved. Resolving it would trade one lexical miss for
// another (a protected pattern under a symlinked HOME stops matching), and
// the engine's macOS /private reading (#4387) already covers that alias.
func payloadEvalCwd(payloadCwd string) (string, []logger.Note) {
	if payloadCwd == "" {
		return "", nil
	}
	if !filepath.IsAbs(payloadCwd) {
		return "", unusableCwdNote(payloadCwd, "is not an absolute path")
	}
	fi, err := os.Stat(payloadCwd)
	switch {
	case os.IsNotExist(err):
		return "", unusableCwdNote(payloadCwd, "does not exist")
	case err != nil:
		return "", unusableCwdNote(payloadCwd, "cannot be read ("+err.Error()+")")
	case !fi.IsDir():
		return "", unusableCwdNote(payloadCwd, "is not a directory")
	}
	// The same directory as the process's own (Claude Code spawns the hook in
	// the directory it reports): keep the process's spelling, which is
	// exactly what main evaluated against. A logical spelling of the same
	// directory (a symlinked path, /tmp for /private/tmp) would otherwise
	// change lexical matching on invocations this fix is not about.
	if wd, err := os.Getwd(); err == nil {
		if wfi, err := os.Stat(wd); err == nil && os.SameFile(fi, wfi) {
			return wd, nil
		}
	}
	return payloadCwd, nil
}

func unusableCwdNote(payloadCwd, why string) []logger.Note {
	return []logger.Note{{
		Kind:   analyzer.NotePayloadCwdUnusable,
		Detail: fmt.Sprintf("payload cwd %q %s; evaluated against the hook process's working directory", truncateForNote(payloadCwd), why),
	}}
}

// maxNoteValueLen bounds a payload value quoted in a note's detail.
const maxNoteValueLen = 256

func truncateForNote(s string) string {
	if len(s) <= maxNoteValueLen {
		return s
	}
	return s[:maxNoteValueLen] + "…"
}
