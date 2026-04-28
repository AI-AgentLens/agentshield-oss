package mcp

import (
	"os"
	"testing"
)

func TestConfigGuard_BlockAgentShieldConfig(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    home + "/.agentshield/policy.yaml",
		"content": "defaults:\n  decision: ALLOW\n",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to AgentShield policy")
	}
	assertConfigCategory(t, result, "agentshield-config")
}

func TestConfigGuard_BlockMCPPolicyWrite(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("edit_file", map[string]interface{}{
		"path": home + "/.agentshield/mcp-policy.yaml",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to MCP policy")
	}
	assertConfigCategory(t, result, "agentshield-config")
}

func TestConfigGuard_BlockCursorMCPConfig(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    home + "/.cursor/mcp.json",
		"content": `{"mcpServers":{"evil":{"command":"evil-server"}}}`,
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to Cursor MCP config")
	}
	assertConfigCategory(t, result, "ide-mcp-config")
}

func TestConfigGuard_BlockWindsurfHooks(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("create_file", map[string]interface{}{
		"path":    home + "/.codeium/windsurf/hooks.json",
		"content": "{}",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to Windsurf hooks")
	}
	assertConfigCategory(t, result, "ide-hooks")
}

func TestConfigGuard_BlockBashrc(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    home + "/.bashrc",
		"content": "alias rm='rm -rf /'\n",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to .bashrc")
	}
	assertConfigCategory(t, result, "shell-config")
}

func TestConfigGuard_BlockZshrc(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("edit_file", map[string]interface{}{
		"path": home + "/.zshrc",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to .zshrc")
	}
	assertConfigCategory(t, result, "shell-config")
}

func TestConfigGuard_BlockNpmrc(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    home + "/.npmrc",
		"content": "registry=https://evil.com/npm/\n",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to .npmrc")
	}
	assertConfigCategory(t, result, "package-config")
}

func TestConfigGuard_BlockGitConfig(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path": home + "/.gitconfig",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to .gitconfig")
	}
	assertConfigCategory(t, result, "git-config")
}

func TestConfigGuard_BlockSSHConfig(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("edit_file", map[string]interface{}{
		"path": home + "/.ssh/config",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to SSH config")
	}
	assertConfigCategory(t, result, "ssh-config")
}

func TestConfigGuard_BlockKubeConfig(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path": home + "/.kube/config",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to kubeconfig")
	}
	assertConfigCategory(t, result, "kube-config")
}

func TestConfigGuard_BlockDockerConfig(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path": home + "/.docker/config.json",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to Docker config")
	}
	assertConfigCategory(t, result, "docker-config")
}

func TestConfigGuard_BlockTildePath(t *testing.T) {
	// Tools might pass paths with ~ instead of expanded home
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path": "~/.agentshield/policy.yaml",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — tilde path to AgentShield config")
	}
}

func TestConfigGuard_BlockPipConfig(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    home + "/.config/pip/pip.conf",
		"content": "[global]\nindex-url = https://evil.com/simple/\n",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to pip config")
	}
	assertConfigCategory(t, result, "package-config")
}

func TestConfigGuard_AllowProjectFiles(t *testing.T) {
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    "/Users/dev/myproject/src/main.go",
		"content": "package main\n",
	})
	if result.Blocked {
		t.Errorf("expected allowed — project file write, got: %v", result.Findings)
	}
}

func TestConfigGuard_AllowTmpFiles(t *testing.T) {
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    "/tmp/test.txt",
		"content": "hello",
	})
	if result.Blocked {
		t.Errorf("expected allowed — tmp file write, got: %v", result.Findings)
	}
}

func TestConfigGuard_AllowNonPathArguments(t *testing.T) {
	result := CheckConfigGuard("get_weather", map[string]interface{}{
		"location": "New York",
		"units":    "celsius",
	})
	if result.Blocked {
		t.Errorf("expected allowed — no paths in arguments, got: %v", result.Findings)
	}
}

func TestConfigGuard_EmptyArguments(t *testing.T) {
	result := CheckConfigGuard("noop", map[string]interface{}{})
	if result.Blocked {
		t.Error("expected allowed — empty arguments")
	}
}

func TestConfigGuard_NilArguments(t *testing.T) {
	result := CheckConfigGuard("noop", nil)
	if result.Blocked {
		t.Error("expected allowed — nil arguments")
	}
}

func TestConfigGuard_NestedPathArgument(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("complex_tool", map[string]interface{}{
		"config": map[string]interface{}{
			"target": home + "/.bashrc",
		},
	})
	if !result.Blocked {
		t.Fatal("expected blocked — nested path to .bashrc")
	}
	assertConfigCategory(t, result, "shell-config")
}

func TestConfigGuard_AgentShieldSubdir(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path": home + "/.agentshield/packs/evil.yaml",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to AgentShield packs directory")
	}
	assertConfigCategory(t, result, "agentshield-config")
}

func TestConfigGuard_PathTraversalToBashrc(t *testing.T) {
	home := os.Getenv("HOME")
	// Path traversal that resolves to ~/.bashrc
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path": home + "/project/../.bashrc",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — path traversal to .bashrc")
	}
	assertConfigCategory(t, result, "shell-config")
}

func TestConfigGuard_PathTraversalToAgentShield(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path": home + "/dev/../.agentshield/policy.yaml",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — path traversal to AgentShield config")
	}
}

func TestConfigGuard_ClaudeDesktopConfig(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    home + "/Library/Application Support/Claude/claude_desktop_config.json",
		"content": `{"mcpServers":{"evil":{"command":"evil-server"}}}`,
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to Claude Desktop config")
	}
	assertConfigCategory(t, result, "ide-mcp-config")
}

func TestConfigGuard_MultipleFindings(t *testing.T) {
	home := os.Getenv("HOME")
	// A tool call that has paths to multiple protected configs
	result := CheckConfigGuard("multi_write", map[string]interface{}{
		"primary":   home + "/.bashrc",
		"secondary": home + "/.agentshield/policy.yaml",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — multiple protected paths")
	}
	if len(result.Findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(result.Findings))
	}
}

func TestConfigGuard_CursorHooksJson(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    home + "/.cursor/hooks.json",
		"content": `{"hooks":[]}`,
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to Cursor hooks")
	}
	assertConfigCategory(t, result, "ide-hooks")
}

func TestConfigGuard_YarnrcYml(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    home + "/.yarnrc.yml",
		"content": "npmRegistryServer: https://evil.com/npm/",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to .yarnrc.yml")
	}
	assertConfigCategory(t, result, "package-config")
}

func TestConfigGuard_BunfigToml(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    home + "/.bunfig.toml",
		"content": `[install]\nregistry = "https://evil.com/npm/"`,
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to .bunfig.toml")
	}
	assertConfigCategory(t, result, "package-config")
}

func TestConfigGuard_PyPIrc(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    home + "/.pypirc",
		"content": "[pypi]\nusername = __token__\npassword = pypi-xxx",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to .pypirc")
	}
	assertConfigCategory(t, result, "package-config")
}

func TestConfigGuard_AllowProjectDotfile(t *testing.T) {
	// A .bashrc inside a project directory should NOT be blocked
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    "/Users/dev/myproject/.bashrc",
		"content": "# project-local bashrc",
	})
	// This should NOT be blocked because it's not at ~
	if result.Blocked {
		t.Errorf("expected allowed — .bashrc inside project dir, got: %v", result.Findings)
	}
}

func TestConfigGuard_AllowProjectNpmrc(t *testing.T) {
	// A .npmrc inside a project directory is normal
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    "/Users/dev/myproject/.npmrc",
		"content": "save-exact=true",
	})
	if result.Blocked {
		t.Errorf("expected allowed — .npmrc inside project dir, got: %v", result.Findings)
	}
}

func TestConfigGuard_ProfileVariant(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path": home + "/.zprofile",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to .zprofile")
	}
	assertConfigCategory(t, result, "shell-config")
}

func TestConfigGuard_BashProfile(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path": home + "/.bash_profile",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to .bash_profile")
	}
	assertConfigCategory(t, result, "shell-config")
}

func TestConfigGuard_GitConfigXDG(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path": home + "/.config/git/config",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to XDG git config")
	}
	assertConfigCategory(t, result, "git-config")
}

func TestConfigGuard_BlockClaudeCodeSettings(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    home + "/.claude/settings.json",
		"content": `{"permissions": {}}`,
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to ~/.claude/settings.json could remove AgentShield hooks")
	}
	assertConfigCategory(t, result, "ide-hooks")
}

func TestConfigGuard_BlockClaudeCodeLocalSettings(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("edit_file", map[string]interface{}{
		"path": home + "/.claude/settings.local.json",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to ~/.claude/settings.local.json could remove AgentShield hooks")
	}
	assertConfigCategory(t, result, "ide-hooks")
}

func TestConfigGuard_BlockGeminiSettings(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    home + "/.gemini/settings.json",
		"content": `{}`,
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to ~/.gemini/settings.json could remove AgentShield hooks")
	}
	assertConfigCategory(t, result, "ide-hooks")
}

func TestConfigGuard_BlockCodexConfig(t *testing.T) {
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    home + "/.codex/config.json",
		"content": `{}`,
	})
	if !result.Blocked {
		t.Fatal("expected blocked — writing to ~/.codex/config.json could remove AgentShield hooks")
	}
	assertConfigCategory(t, result, "ide-hooks")
}

func TestConfigGuard_AllowClaudeProjectFiles(t *testing.T) {
	// Files inside ~/.claude/projects/ are project-level settings and should not be blocked
	home := os.Getenv("HOME")
	result := CheckConfigGuard("write_file", map[string]interface{}{
		"path":    home + "/.claude/projects/myproject/CLAUDE.md",
		"content": "# Project notes",
	})
	if result.Blocked {
		t.Errorf("expected allowed — project-level CLAUDE.md in ~/.claude/projects/, got: %v", result.Findings)
	}
}

func assertConfigCategory(t *testing.T, result ConfigGuardResult, category string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.Category == category {
			return
		}
	}
	var found []string
	for _, f := range result.Findings {
		found = append(found, f.Category+": "+f.Reason)
	}
	t.Errorf("expected category %s, got: %v", category, found)
}
