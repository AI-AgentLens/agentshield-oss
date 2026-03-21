package enterprise

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// policyCheckResponse matches the server's /api/policy/check response.
type policyCheckResponse struct {
	NeedsUpdate bool   `json:"needs_update"`
	Checksum    string `json:"checksum"`
}

// RunPolicySync starts the background policy sync loop. It blocks forever.
func RunPolicySync(cfg *PolicySyncConf, configDir string) {
	if cfg == nil || cfg.URL == "" || cfg.Token == "" {
		fmt.Fprintf(os.Stderr, "[AgentShield] policy-sync: missing url or token, skipping\n")
		return
	}

	interval := 300
	if cfg.IntervalSeconds > 0 {
		interval = cfg.IntervalSeconds
	}

	client := &http.Client{Timeout: 15 * time.Second}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	// Track the last known checksum to avoid unnecessary downloads
	var lastChecksum string

	fmt.Fprintf(os.Stderr, "[AgentShield] policy-sync: started (interval: %ds, url: %s)\n", interval, cfg.URL)

	// Sync immediately on start, then on tick
	lastChecksum = syncPolicy(client, cfg, configDir, lastChecksum)
	for range ticker.C {
		lastChecksum = syncPolicy(client, cfg, configDir, lastChecksum)
	}
}

// syncPolicy checks for policy updates and downloads new YAML if changed.
// Returns the current checksum.
func syncPolicy(client *http.Client, cfg *PolicySyncConf, configDir, lastChecksum string) string {
	// Step 1: Check if update is needed
	checkURL := strings.TrimSuffix(cfg.URL, "/") + "/check"
	if lastChecksum != "" {
		checkURL += "?checksum=" + lastChecksum
	}

	checkResp, err := doGet(client, checkURL, cfg.Token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] policy-sync: check failed: %v\n", err)
		return lastChecksum
	}

	var check policyCheckResponse
	if err := json.Unmarshal(checkResp, &check); err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] policy-sync: invalid check response: %v\n", err)
		return lastChecksum
	}

	if !check.NeedsUpdate && lastChecksum != "" {
		return check.Checksum
	}

	// Step 2: Download the YAML policy
	yamlURL := strings.TrimSuffix(cfg.URL, "/") + "/yaml"
	yamlData, err := doGet(client, yamlURL, cfg.Token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] policy-sync: download failed: %v\n", err)
		return lastChecksum
	}

	if len(yamlData) == 0 {
		return check.Checksum
	}

	// Step 3: Atomic write to policy.yaml
	policyPath := filepath.Join(configDir, "policy.yaml")
	tmpPath := policyPath + ".tmp"

	if err := os.WriteFile(tmpPath, yamlData, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] policy-sync: write tmp failed: %v\n", err)
		return lastChecksum
	}

	if err := os.Rename(tmpPath, policyPath); err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] policy-sync: rename failed: %v\n", err)
		os.Remove(tmpPath)
		return lastChecksum
	}

	fmt.Fprintf(os.Stderr, "[AgentShield] policy-sync: updated policy (checksum: %s)\n", check.Checksum)
	return check.Checksum
}

// doGet performs an authenticated GET request and returns the response body.
func doGet(client *http.Client, url, token string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, err
	}
	return body, nil
}
