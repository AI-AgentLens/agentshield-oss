package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/packs"
)

// TestPackInstallDir is the routing gate for #2219: `agentshield update` must
// send MCP packs (mcp-*) to mcp-packs/ — where the MCP loader reads them — and
// everything else to packs/. An MCP pack misrouted into packs/ both breaks the
// terminal loader (schema it can't parse) and goes unenforced (the MCP loader
// never looks in packs/).
func TestPackInstallDir(t *testing.T) {
	packsDir := filepath.Join("home", "packs")
	mcpPacksDir := filepath.Join("home", "mcp-packs")

	cases := []struct {
		filename string
		want     string
	}{
		{"mcp-agent-platform-creds.yaml", mcpPacksDir},
		{"mcp-safety.yaml", mcpPacksDir},
		{"MCP-Upper.yaml", mcpPacksDir}, // case-insensitive
		{"terminal-safety.yaml", packsDir},
		{"secrets-pii.yaml", packsDir},
		{"supply-chain.yaml", packsDir},
		{"premium-mcp-helper.yaml", packsDir}, // mcp not at the start → terminal
	}
	for _, c := range cases {
		if got := packInstallDir(c.filename, packsDir, mcpPacksDir); got != c.want {
			t.Errorf("packInstallDir(%q) = %q, want %q", c.filename, got, c.want)
		}
	}
}

// TestValidateDownloadedPack is the delivery-time gate for issue #2204: a
// premium pack downloaded via `agentshield update` must be rejected before it
// touches disk if it does not parse or contains no rules at all.
func TestValidateDownloadedPack(t *testing.T) {
	tests := []struct {
		name          string
		yaml          string
		wantErr       bool
		wantTopLevel  int
		wantTotalover int // total() must be > this
	}{
		{
			name: "valid shell pack",
			yaml: `
name: "Shell Pack"
rules:
  - id: "a"
    match: {command_exact: "x"}
    decision: "BLOCK"
    reason: "ok"
  - id: "b"
    match: {command_exact: "y"}
    decision: "AUDIT"
    reason: "ok"
`,
			wantErr:       false,
			wantTopLevel:  2,
			wantTotalover: 1,
		},
		{
			name: "valid MCP pack (non-rules rule types count)",
			yaml: `
name: "MCP Pack"
resource_rules:
  - id: "r1"
value_limits:
  - id: "v1"
`,
			wantErr:       false,
			wantTopLevel:  0,
			wantTotalover: 1,
		},
		{
			name: "valid pack with only blocked_tools",
			yaml: `
name: "Block Pack"
blocked_tools: ["execute_command", "run_shell"]
`,
			wantErr:       false,
			wantTopLevel:  0,
			wantTotalover: 1,
		},
		{
			name:    "malformed YAML — #2188 incident shape (unquoted colon)",
			yaml:    "name: Bad\nrules:\n  - id: x\n    reason: docs: explain git+https:// risks\n",
			wantErr: true,
		},
		{
			name:    "malformed YAML — tab indentation",
			yaml:    "name: Bad\nrules:\n\t- id: x\n",
			wantErr: true,
		},
		{
			name: "parses but zero rules — empty/corrupt pack",
			yaml: `
name: "Empty Pack"
description: "no rules at all"
version: "1.0.0"
`,
			wantErr: true,
		},
		{
			name:    "empty payload",
			yaml:    "",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			counts, err := validateDownloadedPack([]byte(tc.yaml))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected rejection, got nil error (counts.total=%d)", counts.total())
				}
				return
			}
			if err != nil {
				t.Fatalf("expected pack to validate, got error: %v", err)
			}
			if len(counts.Rules) != tc.wantTopLevel {
				t.Errorf("top-level rules: got %d, want %d", len(counts.Rules), tc.wantTopLevel)
			}
			if counts.total() <= tc.wantTotalover {
				t.Errorf("total(): got %d, want > %d", counts.total(), tc.wantTotalover)
			}
		})
	}
}

// TestSweepStaleCommunityPacks verifies `agentshield update` keeps disk =
// premium/user only: a community-named disk pack the SaaS does not serve is a
// stale duplicate (community rules are embedded) and gets swept, while a
// premium pack — even one reusing a community name in the manifest — is kept.
func TestSweepStaleCommunityPacks(t *testing.T) {
	// Guard: the names we test must actually be embedded community packs, so the
	// test fails loudly if community packs are ever renamed.
	embedded := packs.ShellFiles()
	for _, n := range []string{"terminal-safety.yaml", "secrets-pii.yaml"} {
		if _, ok := embedded[n]; !ok {
			t.Fatalf("precondition: %q is no longer an embedded community pack — update this test", n)
		}
	}

	dir := t.TempDir()
	write := func(name string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("version: \"1\"\nrules: []\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("terminal-safety.yaml")          // stale community copy → must be swept
	write("secrets-pii.yaml")              // community name BUT served by manifest → keep
	write("terminal-safety-advanced.yaml") // premium (not a community name) → keep

	manifest := &packManifest{Packs: []packEntry{
		{Filename: "secrets-pii.yaml"},
		{Filename: "terminal-safety-advanced.yaml"},
	}}

	removed := sweepStaleCommunityPacks(dir, manifest)

	if len(removed) != 1 || removed[0] != "terminal-safety.yaml" {
		t.Errorf("removed = %v, want [terminal-safety.yaml]", removed)
	}
	if _, err := os.Stat(filepath.Join(dir, "terminal-safety.yaml")); !os.IsNotExist(err) {
		t.Error("terminal-safety.yaml should have been swept")
	}
	for _, keep := range []string{"secrets-pii.yaml", "terminal-safety-advanced.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
			t.Errorf("%s should have been kept: %v", keep, err)
		}
	}
}
