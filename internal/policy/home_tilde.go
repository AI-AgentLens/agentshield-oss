package policy

import (
	"os/user"
	"path/filepath"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// HomeTildeMode selects how an evaluation treats the `~<login>/` and `~+/`
// spellings of a path (#4596).
type HomeTildeMode int

const (
	// HomeTildeStricter is production: evaluate as written and, for a
	// command carrying `~<login>` (this account's login) or `~+`, again with
	// them written the way the shell expands them
	// (shellparse.HomeTildeReading); keep the expanded reading only when
	// strictly more restrictive (stricterResult).
	HomeTildeStricter HomeTildeMode = iota
	// HomeTildeOff evaluates as written only, byte for byte pre-#4596.
	HomeTildeOff
	// HomeTildeOn is the expanded reading alone. Diagnostics and tests only.
	HomeTildeOn
)

// EvaluateHomeTilde sits between EvaluateANSICNUL and EvaluatePrivateAlias.
//
// # The bypass
//
// bash and zsh expand `~<login>` to that account's home and `~+` to $PWD.
// Packs and protected_paths are written against `~/`, and expandPath maps
// any other `~...` word to $HOME itself, so `cat ~<you>/.npmrc` and
// `cat ~+/.npmrc` (run from home) decided ALLOW (ts-allow-readonly) where
// `cat ~/.npmrc` BLOCKs. The issue measured 70 of 345 `~/` corpus BLOCKs
// lowered by the `~<login>/` spelling, 15 to ALLOW.
//
// # The guarantee
//
// The construction of #3991, #4194, #4289, #4387 and #4540: the as-written
// evaluation is untouched, the expanded reading is a second evaluation of the
// rewritten text with its own argv paths and tree, and it replaces the
// as-written result only when strictly more restrictive. No tie rule.
//
// `~<login>` is read for the account running the process only, written `~`
// when that account's home is $HOME (the packs' spelling) and as the absolute
// home otherwise. Other logins are not looked up: protected_paths and the
// packs describe this account's home.
//
// # What it does not reach
//
// `~-` ($OLDPWD), a tilde inside a carrier's quoted payload (`bash -c '...'`),
// and a home spelling inside a heredoc body (the shell does not expand it).
func (e *Engine) EvaluateHomeTilde(command string, paths []string, parsed *analyzer.ParsedCommand, cwd string, mode HomeTildeMode) EvalResult {
	if mode == HomeTildeOff {
		return e.EvaluatePrivateAlias(command, paths, parsed, cwd, PrivateAliasStricter)
	}
	login, loginHome := e.tildeAccount()
	reading := shellparse.HomeTildeReading(command, login, loginHome, cwd)
	if reading == "" {
		return e.EvaluatePrivateAlias(command, paths, parsed, cwd, PrivateAliasStricter)
	}
	n := normalize.NormalizeCommand(reading, cwd)
	// A caller that supplied no paths (Evaluate(cmd, nil): the accuracy
	// corpus) gets none for the expanded reading either, so the two readings
	// are judged on the same evidence.
	expandedPaths := n.Paths
	if paths == nil {
		expandedPaths = nil
	}
	expanded := e.EvaluatePrivateAlias(reading, expandedPaths, n.Parsed, cwd, PrivateAliasStricter)
	if mode == HomeTildeOn {
		return expanded
	}
	asWritten := e.EvaluatePrivateAlias(command, paths, parsed, cwd, PrivateAliasStricter)
	return stricterResult(asWritten, expanded)
}

// tildeAccountLookup returns the login and home of the account running the
// process (os/user caches it after the first call). Tests replace it so they
// never depend on the developer's account.
var tildeAccountLookup = func() (string, string) {
	u, err := user.Current()
	if err != nil || u == nil {
		return "", ""
	}
	return u.Username, u.HomeDir
}

// SetTildeAccountLookupForTest replaces tildeAccountLookup and returns a
// function that restores the previous one. It exists for tests in other
// packages (the cli hook tests re-exec their own binary with a scratch HOME,
// and a darwin build reads the real account's home from the user database,
// whatever HOME says), the twin of homedir.SetAccountLookupForTest.
func SetTildeAccountLookupForTest(f func() (login, home string)) (restore func()) {
	prev := tildeAccountLookup
	tildeAccountLookup = f
	return func() { tildeAccountLookup = prev }
}

// tildeAccount is the (login, replacement) pair HomeTildeReading needs: the
// replacement is "~" when the account's home is the engine's $HOME, the
// absolute account home otherwise, and "" when the account is unknown.
func (e *Engine) tildeAccount() (string, string) {
	login, home := tildeAccountLookup()
	if login == "" || home == "" {
		return "", ""
	}
	if e.homeDir != "" && filepath.Clean(home) == filepath.Clean(e.homeDir) {
		return login, "~"
	}
	return login, filepath.Clean(home)
}
