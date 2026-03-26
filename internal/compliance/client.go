package compliance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"time"

	"github.com/security-researcher-ca/agentshield/internal/auth"
)

// Mode represents where compliance processing happens.
type Mode string

const (
	ModeLocal  Mode = "local"
	ModeRemote Mode = "remote"
)

// AgentConfig is the response from GET /api/agent/config.
type AgentConfig struct {
	ComplianceMode    string `json:"compliance_mode"`
	ComplianceEnabled bool   `json:"compliance_enabled"`
	OrgID             *int64 `json:"org_id,omitempty"`
	Tier              string `json:"tier,omitempty"`
}

// DetectMode queries the SaaS to determine if the org uses remote or local compliance.
// Returns ModeLocal if not logged in or on error.
func DetectMode(creds *auth.Credentials) Mode {
	if creds == nil || creds.Token == "" {
		return ModeLocal
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", creds.Server+"/api/agent/config", nil)
	if err != nil {
		return ModeLocal
	}
	req.Header.Set("Authorization", "Bearer "+creds.Token)

	resp, err := client.Do(req)
	if err != nil {
		return ModeLocal
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ModeLocal
	}

	var config AgentConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return ModeLocal
	}

	if config.ComplianceMode == "remote" {
		return ModeRemote
	}
	return ModeLocal
}

// ScanResult holds compliance scan output.
type ScanResult struct {
	Findings []json.RawMessage `json:"findings"`
	Error    string            `json:"error,omitempty"`
}

// RunLocal executes agentcompliance as a subprocess.
func RunLocal(args []string) (*ScanResult, error) {
	binPath, err := exec.LookPath("agentcompliance")
	if err != nil {
		return nil, fmt.Errorf("agentcompliance not found in PATH — reinstall with: brew reinstall agentshield")
	}

	fullArgs := append([]string{"scan", "--json"}, args...)
	cmd := exec.Command(binPath, fullArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return &ScanResult{Error: stderr.String()}, fmt.Errorf("agentcompliance failed: %w", err)
	}

	var result ScanResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return &ScanResult{Error: "failed to parse agentcompliance output"}, err
	}
	return &result, nil
}

// RunRemote calls the SaaS compliance API for scanning.
func RunRemote(creds *auth.Credentials, path string) (*ScanResult, error) {
	if creds == nil || creds.Token == "" {
		return nil, fmt.Errorf("not logged in — run 'agentshield login' first")
	}

	client := &http.Client{Timeout: 60 * time.Second}
	body, _ := json.Marshal(map[string]string{"path": path})

	req, err := http.NewRequest("POST", creds.Server+"/api/compliance/scan", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+creds.Token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("remote compliance scan failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("remote compliance scan returned %d", resp.StatusCode)
	}

	var result ScanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}
