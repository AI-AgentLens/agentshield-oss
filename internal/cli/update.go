package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/packs"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// mcpPackPrefix marks MCP-protocol packs by filename convention. Every MCP pack
// shipped — community and premium, embedded and SaaS-delivered — is named
// mcp-*; no terminal pack uses this prefix. We route by name because the
// /api/packs manifest carries no pack-type field (packEntry is just filename /
// version / rule_count).
const mcpPackPrefix = "mcp-"

// packInstallDir returns the on-disk directory a downloaded pack belongs in.
// MCP packs go to ~/.agentshield/mcp-packs/ (mcp.DefaultMCPPacksDir, where
// mcp.LoadMCPPacks reads); terminal packs go to ~/.agentshield/packs/. Keeping
// MCP packs out of packs/ matters twice over (#2219): the terminal loader
// (policy.LoadPacks) cannot parse the MCP schema and would surface a spurious
// "0 rules loaded (enforcement degraded)" failure, AND — more importantly — an
// MCP pack left in packs/ is never read by the MCP loader, so its rules go
// unenforced. Routing fixes both.
func packInstallDir(filename, packsDir, mcpPacksDir string) string {
	if strings.HasPrefix(strings.ToLower(filepath.Base(filename)), mcpPackPrefix) {
		return mcpPacksDir
	}
	return packsDir
}

// credentials mirrors the structure of ~/.agentshield/credentials.json
// written by `agentshield login`.
type credentials struct {
	Server string `json:"server"`
	Token  string `json:"token"`
}

const defaultUpdateEndpoint = "https://app.aiagentlens.com/api/packs"

func init() {
	var endpoint string
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Download premium rule packs from AI Agent Lens",
		Long: `Pull the latest premium rule packs from the AI Agent Lens SaaS API.

Requires authentication — run 'agentshield login' first.

The endpoint can be overridden with --endpoint for on-prem deployments.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(endpoint)
		},
	}
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "Override the packs API endpoint")
	rootCmd.AddCommand(cmd)
}

func runUpdate(endpointOverride string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}

	configDir := filepath.Join(home, ".agentshield")
	packsDir := filepath.Join(configDir, "packs")
	mcpPacksDir := filepath.Join(configDir, mcp.DefaultMCPPacksDir)

	// Load credentials
	creds, err := loadCredentials(filepath.Join(configDir, "credentials.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Not logged in. Run 'agentshield login' first.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Premium rules require an AI Agent Lens account.")
		fmt.Fprintln(os.Stderr, "Sign up at https://aiagentlens.com")
		return fmt.Errorf("not authenticated")
	}

	// Determine endpoint: credentials.json server > default, --endpoint overrides all
	endpoint := defaultUpdateEndpoint
	if creds.Server != "" {
		endpoint = creds.Server + "/api/packs"
	}
	if endpointOverride != "" {
		endpoint = endpointOverride
	}

	fmt.Printf("Checking for premium packs...\n")

	// Fetch pack manifest
	manifest, err := fetchManifest(endpoint, creds.Token)
	if err != nil {
		return fmt.Errorf("failed to fetch packs: %w", err)
	}

	// Keep disk = premium/user packs only. Community rule packs are EMBEDDED in
	// the binary (authoritative); a copy in packs/ is a stale duplicate from an
	// older install, and because the loader is additive its old rules SHADOW the
	// embedded (current) ones. Sweep any community-named disk pack the SaaS does
	// not actively serve. Runs every update, so environments self-heal.
	for _, name := range sweepStaleCommunityPacks(packsDir, manifest) {
		fmt.Printf("  swept stale community pack %s (superseded by embedded rules)\n", name)
	}

	if len(manifest.Packs) == 0 {
		fmt.Println("No premium packs available.")
		return nil
	}

	// Download and install packs
	if err := os.MkdirAll(packsDir, 0755); err != nil {
		return fmt.Errorf("cannot create packs directory: %w", err)
	}
	if err := os.MkdirAll(mcpPacksDir, 0755); err != nil {
		return fmt.Errorf("cannot create mcp-packs directory: %w", err)
	}

	installed := 0
	updated := 0
	for _, pack := range manifest.Packs {
		// MCP packs (mcp-*) belong in mcp-packs/, not packs/ — see packInstallDir.
		destDir := packInstallDir(pack.Filename, packsDir, mcpPacksDir)
		destPath := filepath.Join(destDir, pack.Filename)

		// Check if update needed
		if !needsUpdate(destPath, pack.Version) {
			continue
		}

		isNew := true
		if _, err := os.Stat(destPath); err == nil {
			isNew = false
		}

		data, err := downloadPack(endpoint, creds.Token, pack.Filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: failed to download %s: %v\n", pack.Filename, err)
			continue
		}

		// Issue #2204: validate the payload BEFORE it touches disk. A corrupt
		// download must never overwrite a working pack or install as a silent
		// no-op. The runtime loader (post-#2188) surfaces parse failures, but
		// catching them here keeps the bad bytes off disk entirely.
		counts, verr := validateDownloadedPack(data)
		if verr != nil {
			fmt.Fprintf(os.Stderr, "  ❌ rejected %s: %v (existing pack left untouched)\n", pack.Filename, verr)
			continue
		}
		// Soft regression signal: the manifest's declared rule_count is
		// len(rules:) at the source (see SaaS handler). Compare apples-to-apples
		// against the downloaded top-level rule count. Warn but still install —
		// count semantics can drift, so this is a heads-up, not a hard gate.
		if pack.RuleCount > 0 && len(counts.Rules) < pack.RuleCount {
			fmt.Fprintf(os.Stderr, "  ⚠️  %s: manifest declares %d rules but download has %d top-level — possible regression\n",
				pack.Filename, pack.RuleCount, len(counts.Rules))
		}

		if err := os.WriteFile(destPath, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: failed to write %s: %v\n", pack.Filename, err)
			continue
		}

		// Migration cleanup (#2219): older clients wrote MCP packs flat into
		// packs/, where the terminal loader chokes on them. Now that this pack
		// lives in mcp-packs/, remove any stale flat copy so it stops surfacing
		// a spurious parse failure. Only touches a path we just superseded.
		if destDir != packsDir {
			stale := filepath.Join(packsDir, pack.Filename)
			if _, statErr := os.Stat(stale); statErr == nil {
				if rmErr := os.Remove(stale); rmErr == nil {
					fmt.Printf("  migrated %s → %s/ (removed stale copy in packs/)\n", pack.Filename, mcp.DefaultMCPPacksDir)
				}
			}
		}

		if isNew {
			installed++
		} else {
			updated++
		}
		fmt.Printf("  %s (%s) — %d rules\n", pack.Filename, pack.Version, pack.RuleCount)
	}

	if installed+updated == 0 {
		fmt.Println("All premium packs are up to date.")
	} else {
		fmt.Printf("Done: %d installed, %d updated.\n", installed, updated)
	}

	return nil
}

// sweepStaleCommunityPacks removes disk packs in packsDir whose filename matches
// an embedded community pack (packs.ShellFiles) but which the SaaS manifest does
// NOT serve. Such a file is a stale duplicate of a now-embedded community pack;
// left in place, its (older) rules shadow the embedded ones because the loader
// is additive (most_restrictive_wins). The manifest-served check means a premium
// pack that legitimately reuses a community name is never swept (it gets
// (re)installed by the download loop instead). Returns the names removed.
func sweepStaleCommunityPacks(packsDir string, manifest *packManifest) []string {
	served := map[string]bool{}
	if manifest != nil {
		for _, p := range manifest.Packs {
			served[p.Filename] = true
		}
	}
	var removed []string
	for name := range packs.ShellFiles() {
		if served[name] {
			continue // SaaS actively serves this name — not a stale community copy
		}
		path := filepath.Join(packsDir, name)
		if _, err := os.Stat(path); err != nil {
			continue // not on disk — nothing to sweep
		}
		if err := os.Remove(path); err == nil {
			removed = append(removed, name)
		}
	}
	return removed
}

// packManifest is the API response listing available packs.
type packManifest struct {
	Packs []packEntry `json:"packs"`
}

type packEntry struct {
	Filename  string `json:"filename"`
	Version   string `json:"version"`
	RuleCount int    `json:"rule_count"`
}

// packRuleCounts is a permissive view over a downloaded pack used only to count
// rule entries across both shell and MCP pack shapes. yaml.Node lets us count
// without depending on the full Rule/MCPRule schemas (or importing the
// policy/mcp packages, which would risk an import cycle).
type packRuleCounts struct {
	Rules           []yaml.Node `yaml:"rules,omitempty"`
	ResourceRules   []yaml.Node `yaml:"resource_rules,omitempty"`
	ValueLimits     []yaml.Node `yaml:"value_limits,omitempty"`
	StructuralRules []yaml.Node `yaml:"structural_rules,omitempty"`
	SemanticRules   []yaml.Node `yaml:"semantic_rules,omitempty"`
	DataLabels      []yaml.Node `yaml:"data_labels,omitempty"`
	BlockedTools    []string    `yaml:"blocked_tools,omitempty"`
}

func (c packRuleCounts) total() int {
	return len(c.Rules) + len(c.ResourceRules) + len(c.ValueLimits) +
		len(c.StructuralRules) + len(c.SemanticRules) + len(c.DataLabels) +
		len(c.BlockedTools)
}

// validateDownloadedPack parses a freshly-downloaded pack payload and decides
// whether it is safe to install (issue #2204). It returns the parsed counts and
// a non-nil error when the pack must be REJECTED (not written to disk):
//   - the YAML does not parse, or
//   - the pack contains zero rules of any kind — an empty/corrupt pack (a real
//     premium pack always ships at least one rule).
//
// This is the delivery-time gate: a corrupt download must never overwrite a
// working pack or install as a silent no-op.
func validateDownloadedPack(data []byte) (packRuleCounts, error) {
	var counts packRuleCounts
	if err := yaml.Unmarshal(data, &counts); err != nil {
		return counts, fmt.Errorf("does not parse as YAML: %w", err)
	}
	if counts.total() == 0 {
		return counts, fmt.Errorf("parsed to 0 rules — empty or corrupt pack")
	}
	return counts, nil
}

func loadCredentials(path string) (*credentials, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var creds credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, err
	}
	if creds.Token == "" {
		return nil, fmt.Errorf("no token in credentials")
	}
	return &creds, nil
}

func fetchManifest(endpoint, token string) (*packManifest, error) {
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "agentshield-update/1.0")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("authentication failed (HTTP %d) — try 'agentshield login' again", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %s", resp.Status)
	}

	var manifest packManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("invalid response: %w", err)
	}
	return &manifest, nil
}

func downloadPack(endpoint, token, filename string) ([]byte, error) {
	url := endpoint + "/" + filename
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "agentshield-update/1.0")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}

	return io.ReadAll(resp.Body)
}

func needsUpdate(path, newVersion string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return true // file doesn't exist
	}
	var pack struct {
		Version string `yaml:"version"`
	}
	if err := yaml.Unmarshal(data, &pack); err != nil {
		return true
	}
	return pack.Version != newVersion
}
