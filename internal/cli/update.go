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

	if len(manifest.Packs) == 0 {
		fmt.Println("No premium packs available.")
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

		if err := os.WriteFile(destPath, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: failed to write %s: %v\n", pack.Filename, err)
			continue
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

// packManifest is the API response listing available packs.
type packManifest struct {
	Packs []packEntry `json:"packs"`
}

type packEntry struct {
	Filename  string `json:"filename"`
	Version   string `json:"version"`
	RuleCount int    `json:"rule_count"`
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
	defer resp.Body.Close()

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
	var pack struct {
		Version string `yaml:"version"`
	}
	if err := yaml.Unmarshal(data, &pack); err != nil {
		return true
	}
	return pack.Version != newVersion
}
