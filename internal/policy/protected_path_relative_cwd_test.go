package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// TestRelativeProtectedPathMatchesInHook pins #4020: a relative protected_paths
// pattern (e.g. "secrets/**") never matched in the hook, the path that actually
// enforces, because the hook normalizes with the real process cwd
// (normalize.NormalizeCommand(cmd, cwd)), turning "secrets/token" into an
// absolute path before checkProtectedPaths ever sees it — and an absolute path
// has no "secrets/" prefix left for a relative pattern to match. `agentshield
// check` (cwd "") kept the token relative and matched, so the two disagreed:
// check reported a protection the hook silently never applied. No error, no
// AUDIT note — the pattern just never fires.
//
// The fix also matches a relative pattern against the path made relative to
// that cwd (relativeToCwd), so hook and check now agree either way.
func TestRelativeProtectedPathMatchesInHook(t *testing.T) {
	cwd := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cwd, "secrets", "nested"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	policy := DefaultPolicy()
	policy.Defaults.ProtectedPaths = []string{"secrets/**"}
	engine, err := NewEngine(policy)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	hookEval := func(command string) EvalResult {
		normalized := normalize.NormalizeCommand(command, cwd)
		return engine.EvaluateWithParsedCwd(command, normalized.Paths, normalized.Parsed, cwd)
	}
	checkEval := func(command string) EvalResult {
		normalized := normalize.NormalizeCommand(command, "")
		return engine.EvaluateWithParsed(command, normalized.Paths, normalized.Parsed)
	}

	tests := []struct {
		name    string
		command string
	}{
		{"bare relative path", "cat secrets/token"},
		{"dot-relative path", "cat ./secrets/token"},
		{"nested relative path", "cat secrets/nested/token"},
		{"different sink", "cp secrets/token /tmp/x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hookEval(tt.command)
			if result.Decision != DecisionBlock {
				t.Errorf("hook: command %q decided %s, want BLOCK (rules=%v)", tt.command, result.Decision, result.TriggeredRules)
			}
			found := false
			for _, r := range result.TriggeredRules {
				if r == "protected-path" {
					found = true
				}
			}
			if !found {
				t.Errorf("hook: command %q did not trigger protected-path, rules=%v", tt.command, result.TriggeredRules)
			}

			// Regression pin: `check` (cwd "") already matched this pattern
			// before the fix and must keep matching it now.
			checkResult := checkEval(tt.command)
			if checkResult.Decision != DecisionBlock {
				t.Errorf("check: command %q decided %s, want BLOCK (rules=%v)", tt.command, checkResult.Decision, checkResult.TriggeredRules)
			}
		})
	}
}

// TestRelativeProtectedPathDoesNotOvermatch is the negative control for the
// #4020 fix: resolving a relative pattern against cwd must not start matching
// paths that were never under it. A sibling directory sharing a prefix with
// the pattern name, and a bare filename with no path separator, must both stay
// unmatched.
func TestRelativeProtectedPathDoesNotOvermatch(t *testing.T) {
	cwd := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cwd, "secrets-archive"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, "notes"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	policy := DefaultPolicy()
	policy.Defaults.ProtectedPaths = []string{"secrets/**"}
	engine, err := NewEngine(policy)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	tests := []struct {
		name    string
		command string
	}{
		{"sibling directory sharing a prefix", "cat secrets-archive/token"},
		{"unrelated relative path", "cat notes/readme.md"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := normalize.NormalizeCommand(tt.command, cwd)
			result := engine.EvaluateWithParsedCwd(tt.command, normalized.Paths, normalized.Parsed, cwd)
			for _, r := range result.TriggeredRules {
				if r == "protected-path" {
					t.Errorf("command %q unexpectedly triggered protected-path (overmatch), rules=%v", tt.command, result.TriggeredRules)
				}
			}
		})
	}
}

// TestAbsoluteProtectedPathUnaffectedByCwd is the regression control: the
// shipped default_policy.yaml and every current pack use only ~-anchored or
// absolute protected_paths patterns (#4020's own blast-radius note — none of
// the 37 shipped entries is relative). The cwd-relative match must not apply to those
// regardless of cwd, so this pins that the fix cannot change behavior for the
// patterns actually in production today.
func TestAbsoluteProtectedPathUnaffectedByCwd(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	if err != nil || homeDir == "" {
		t.Skip("no home directory available")
	}
	// An arbitrary cwd, unrelated to the pattern or the target path, so any
	// accidental cwd-joining of an already-absolute/tilde pattern would show
	// up as a spurious mismatch.
	cwd := t.TempDir()

	engine, err := NewEngine(DefaultPolicy())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	command := "cat ~/.ssh/id_rsa"
	normalized := normalize.NormalizeCommand(command, cwd)
	result := engine.EvaluateWithParsedCwd(command, normalized.Paths, normalized.Parsed, cwd)
	if result.Decision != DecisionBlock {
		t.Errorf("command %q decided %s, want BLOCK (rules=%v)", command, result.Decision, result.TriggeredRules)
	}
}

// hookEvalWith evaluates command the way the hook does: paths normalized
// against cwd, and cwd passed to the engine.
func hookEvalWith(t *testing.T, patterns []string, cwd, command string) EvalResult {
	t.Helper()
	policy := DefaultPolicy()
	policy.Defaults.ProtectedPaths = patterns
	engine, err := NewEngine(policy)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	normalized := normalize.NormalizeCommand(command, cwd)
	return engine.EvaluateWithParsedCwd(command, normalized.Paths, normalized.Parsed, cwd)
}

// TestRelativeProtectedPathKeepsLegacyMatches pins #4025 Codex pass 1: the
// first version anchored every relative pattern to cwd, which REPLACED the
// match main already made. A leading wildcard matches the empty string, so on
// main `*/var/tmp/org-token` matched /var/tmp/org-token from any cwd; anchored
// under cwd it stopped matching (measured: hook BLOCK -> pass). The fix keeps
// main's match and only adds the cwd-relative one.
func TestRelativeProtectedPathKeepsLegacyMatches(t *testing.T) {
	cwd := t.TempDir()
	for _, pattern := range []string{"*/var/tmp/org-token", "**/var/tmp/org-token"} {
		t.Run(pattern, func(t *testing.T) {
			r := hookEvalWith(t, []string{pattern}, cwd, "cat /var/tmp/org-token")
			if r.Decision != DecisionBlock {
				t.Errorf("pattern %q: decided %s, want BLOCK as on main (rules=%v)", pattern, r.Decision, r.TriggeredRules)
			}
		})
	}
}

// TestRelativeProtectedPathCwdIsNotGlobSyntax: cwd is compared as a literal
// prefix, never spliced into the pattern. Joined into a glob, a cwd such as
// .../project[1] became a character class, which missed ./org-token and
// matched the unrelated sibling .../project1/org-token (#4025 Codex pass 1).
func TestRelativeProtectedPathCwdIsNotGlobSyntax(t *testing.T) {
	root := t.TempDir()
	cwd := filepath.Join(root, "project[1]")
	sibling := filepath.Join(root, "project1")
	for _, d := range []string{cwd, sibling} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	if r := hookEvalWith(t, []string{"org-token"}, cwd, "cat ./org-token"); r.Decision != DecisionBlock {
		t.Errorf("cwd with brackets: decided %s, want BLOCK (rules=%v)", r.Decision, r.TriggeredRules)
	}
	r := hookEvalWith(t, []string{"org-token"}, cwd, "cat "+filepath.Join(sibling, "org-token"))
	for _, rule := range r.TriggeredRules {
		if rule == "protected-path" {
			t.Errorf("sibling %s matched the bracketed cwd's pattern (decision %s)", sibling, r.Decision)
		}
	}
}

// TestRelativeProtectedPathDoesNotClaimPathsOutsideCwd: a relative pattern
// describes paths under cwd. The first rework matched "../**" against the
// cwd-relative form of EVERY path outside cwd ("../../usr/..."), so it blocked
// arbitrary reads (#4025 Opus review). Paths outside cwd keep main's
// as-written match only.
func TestRelativeProtectedPathDoesNotClaimPathsOutsideCwd(t *testing.T) {
	root := t.TempDir()
	cwd := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, tc := range []struct{ pattern, command string }{
		{"../**", "cat /usr/share/dict/words"},
		{"../**", "cat ../../org-token"},
		{"*/org-token", "cat ../org-token"},
	} {
		r := hookEvalWith(t, []string{tc.pattern}, cwd, tc.command)
		for _, rule := range r.TriggeredRules {
			if rule == "protected-path" || rule == "protected-path-via-substitution" {
				t.Errorf("pattern %q claimed %q, a path outside cwd (decision %s)", tc.pattern, tc.command, r.Decision)
			}
		}
	}
}

// TestRelativeProtectedPathDotSlashPattern: a "./"-prefixed relative pattern
// matches like its clean form.
func TestRelativeProtectedPathDotSlashPattern(t *testing.T) {
	cwd := t.TempDir()
	if r := hookEvalWith(t, []string{"./secrets/**"}, cwd, "cat secrets/token"); r.Decision != DecisionBlock {
		t.Errorf("./secrets/**: decided %s, want BLOCK (rules=%v)", r.Decision, r.TriggeredRules)
	}
}

// TestRelativeProtectedPathViaSubstitution: a path the substitution analyzer
// materializes can be relative, including "./". It must be matched against
// cwd too (#4025 Opus review: "P=./secrets/token; python3 -c ..." passed).
func TestRelativeProtectedPathViaSubstitution(t *testing.T) {
	cwd := t.TempDir()
	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = []string{"secrets/**"}
	engine, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	for _, cmd := range []string{
		`P=./secrets/token; python3 -c "open('$P').read()"`,
		`P=secrets/token; python3 -c "open('$P').read()"`,
		`python3 -c "open('` + filepath.Join(cwd, "secrets", "token") + `').read()"`,
	} {
		n := normalize.NormalizeCommand(cmd, cwd)
		if r := engine.EvaluateWithParsedCwd(cmd, n.Paths, n.Parsed, cwd); r.Decision != DecisionBlock {
			t.Errorf("%s: decided %s, want BLOCK (rules=%v)", cmd, r.Decision, r.TriggeredRules)
		}
	}
}
