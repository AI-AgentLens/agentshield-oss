package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// updateConfig holds the user's update configuration from ~/.agentshield/config.yaml.
type updateConfig struct {
	LicenseKey string `yaml:"license_key"`
	Endpoint   string `yaml:"endpoint"`
}

const defaultUpdateEndpoint = "https://app.aiagentlens.com/api/packs"

func init() {
	var endpoint string
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Download premium rule packs from AI Agent Lens",
		Long: `Pull the latest premium rule packs from the AI Agent Lens SaaS API.

Requires a license key configured in ~/.agentshield/config.yaml:

  license_key: "your-license-key"
  endpoint: "https://app.aiagentlens.com/api/packs"  # optional, this is the default

The endpoint can also be overridden with --endpoint for on-prem deployments.`,
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

	// Load config
	cfg := loadUpdateConfig(filepath.Join(configDir, "config.yaml"))

	// Determine endpoint
	endpoint := defaultUpdateEndpoint
	if cfg.Endpoint != "" {
		endpoint = cfg.Endpoint
	}
	if endpointOverride != "" {
		endpoint = endpointOverride
	}

	// Check license key
	if cfg.LicenseKey == "" {
		fmt.Fprintln(os.Stderr, "No license key configured.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Add your license key to ~/.agentshield/config.yaml:")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  license_key: \"your-license-key\"")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Get a license key at https://aiagentlens.com")
		return fmt.Errorf("missing license key")
	}

	fmt.Printf("Checking for premium packs from %s...\n", endpoint)

	// Fetch pack manifest
	manifest, err := fetchManifest(endpoint, cfg.LicenseKey)
	if err != nil {
		return fmt.Errorf("failed to fetch packs: %w", err)
	}

	if len(manifest.Packs) == 0 {
		fmt.Println("No premium packs available for your license.")
		return nil
	}

	// Download and install packs
	if err := os.MkdirAll(packsDir, 0755); err != nil {
		return fmt.Errorf("cannot create packs directory: %w", err)
	}

	installed := 0
	updated := 0
	for _, pack := range manifest.Packs {
		destPath := filepath.Join(packsDir, pack.Filename)

		// Check if update needed (compare etag/version)
		if !needsUpdate(destPath, pack.Version) {
			continue
		}

		data, err := downloadPack(endpoint, cfg.LicenseKey, pack.Filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: failed to download %s: %v\n", pack.Filename, err)
			continue
		}

		if err := os.WriteFile(destPath, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: failed to write %s: %v\n", pack.Filename, err)
			continue
		}

		if _, err := os.Stat(destPath); err == nil {
			updated++
		} else {
			installed++
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

// packManifest is the API response listing available packs.
type packManifest struct {
	Packs []packEntry `json:"packs"`
}

type packEntry struct {
	Filename  string `json:"filename"`
	Version   string `json:"version"`
	RuleCount int    `json:"rule_count"`
}

func loadUpdateConfig(path string) updateConfig {
	var cfg updateConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	_ = yaml.Unmarshal(data, &cfg)
	return cfg
}

func fetchManifest(endpoint, licenseKey string) (*packManifest, error) {
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+licenseKey)
	req.Header.Set("User-Agent", "agentshield-update/1.0")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("invalid license key (HTTP 401)")
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

func downloadPack(endpoint, licenseKey, filename string) ([]byte, error) {
	url := endpoint + "/" + filename
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+licenseKey)
	req.Header.Set("User-Agent", "agentshield-update/1.0")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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
	// Quick check: parse version from existing pack
	var pack struct {
		Version string `yaml:"version"`
	}
	if err := yaml.Unmarshal(data, &pack); err != nil {
		return true
	}
	return pack.Version != newVersion
}
