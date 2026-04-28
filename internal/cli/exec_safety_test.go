package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

// TestNoShellExecutionInEvalSurfaces asserts that AgentShield's evaluation-only
// CLI surfaces never gain a path to actually execute the user input they
// evaluate. Issue #1639 captured the rationale: the deleted `agentshield run`
// command had `exec.Command(args[0], args[1:]...)` and `exec.Command("sh", "-c", ...)`
// — patterns that, if reintroduced into any evaluator surface, recreate the
// 2026-04 incident where `agentshield run -- rm -rf /` actually wiped data.
//
// Scope:
//
//	check.go     — shell-command evaluator (issue/PR #1632)
//	rule.go      — rule disable/allow CLI (writes config, never executes)
//	hook.go      — Claude Code PreToolUse hook (evaluates, returns)
//	mcp_eval.go  — MCP tool-call evaluator (no spawn)
//	scan.go      — diagnostic / self-test
//
// Out of scope (legitimate system-tool wrappers, not user-command execution):
//
//	login.go        — pbcopy / xclip / open / xdg-open / rundll32
//	setup.go        — agentshield self-LookPath, openclaw hook (de)installer
//	setup_mcp.go    — agentshield self-LookPath
//	daemon.go       — launchctl load/unload, agentshield connect
//	mcp_http_proxy.go — syscall for SO_REUSEPORT-class options
//
// Detection: AST-based — we scan each guarded file for SelectorExpr nodes
// matching the forbidden (package, function) pairs. AST parsing avoids the
// false positives of a naive string scan (e.g., a doc comment that mentions
// `exec.Command` would trip a grep but not the AST walk).
func TestNoShellExecutionInEvalSurfaces(t *testing.T) {
	guarded := []string{
		"check.go",
		"rule.go",
		"hook.go",
		"mcp_eval.go",
		"scan.go",
	}

	// (package, function) pairs that, on these surfaces, would mean we are
	// spawning a process — recreating the run.go failure mode.
	forbidden := map[string]map[string]bool{
		"exec": {
			"Command":    true,
			"CommandContext": true,
			"LookPath":   true,
		},
		"syscall": {
			"Exec":     true,
			"ForkExec": true,
			"StartProcess": true,
		},
	}

	fset := token.NewFileSet()
	for _, name := range guarded {
		path := filepath.Join(".", name)
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", path, err)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			fns, watched := forbidden[pkg.Name]
			if !watched {
				return true
			}
			if fns[sel.Sel.Name] {
				pos := fset.Position(call.Pos())
				t.Errorf(
					"%s: forbidden process-spawn call %s.%s — eval surfaces must never execute user input. "+
						"If this is a legitimate system-tool wrapper, refactor it into login/setup/daemon and "+
						"narrow the public API; see internal/cli/exec_safety_test.go for the scope rationale.",
					pos, pkg.Name, sel.Sel.Name,
				)
			}
			return true
		})
	}
}

// TestNoShellExecutionInEvalSurfaces_GuardedFilesExist guards against the
// fitness function silently shrinking. If someone renames or deletes one of
// the guarded files (e.g. moving check.go → check_command.go), this test fails
// and forces an explicit update to the allowlist — preventing a stealth scope
// reduction that would weaken the fitness function.
func TestNoShellExecutionInEvalSurfaces_GuardedFilesExist(t *testing.T) {
	guarded := []string{"check.go", "rule.go", "hook.go", "mcp_eval.go", "scan.go"}
	for _, name := range guarded {
		path := filepath.Join(".", name)
		if _, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution); err != nil {
			t.Errorf("guarded file %s missing or unparseable (%v) — update the guarded list in TestNoShellExecutionInEvalSurfaces or restore the file", path, err)
		}
	}
}
