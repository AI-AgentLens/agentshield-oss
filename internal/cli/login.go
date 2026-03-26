package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/security-researcher-ca/agentshield/internal/auth"
	"github.com/spf13/cobra"
)

var loginServer string

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with AI Agent Lens",
	Long: `Log in to AI Agent Lens using the device authorization flow.

This will open your browser to complete authentication. If the browser
does not open, a URL and code will be printed for manual login.

After login, this agent will appear as active in your AI Agent Lens dashboard.

  agentshield login
  agentshield login --server https://aiagentlens.com`,
	RunE: loginCommand,
}

func init() {
	loginCmd.Flags().StringVar(&loginServer, "server", "https://aiagentlens.com", "AI Agent Lens server URL")
	rootCmd.AddCommand(loginCmd)
}

// deviceCodeResponse from POST /api/auth/device-code
type deviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// deviceTokenResponse from POST /api/auth/device-token
type deviceTokenResponse struct {
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	Error       string `json:"error,omitempty"`
	User        *struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
		OrgID *int64 `json:"org_id,omitempty"`
	} `json:"user,omitempty"`
}

func loginCommand(cmd *cobra.Command, args []string) error {
	// Check if already logged in
	existing, _ := auth.Load()
	if existing != nil && existing.Token != "" {
		fmt.Fprintf(os.Stderr, "Already logged in as %s. Run 'agentshield logout' first to re-authenticate.\n", existing.User.Email)
		return nil
	}

	// Step 1: Request device code
	resp, err := http.Post(loginServer+"/api/auth/device-code", "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		return fmt.Errorf("failed to contact server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d — is the server URL correct?", resp.StatusCode)
	}

	var dcResp deviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&dcResp); err != nil {
		return fmt.Errorf("invalid server response: %w", err)
	}

	// Step 2: Try to open browser
	verifyURL := dcResp.VerificationURL
	if verifyURL == "" {
		verifyURL = loginServer + "/app/verify"
	}
	// Ensure URL points to the SPA route
	if verifyURL == loginServer+"/verify" {
		verifyURL = loginServer + "/app/verify"
	}

	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════════════╗")
	fmt.Printf("  ║  Your code: %-37s║\n", dcResp.UserCode)
	fmt.Println("  ╚══════════════════════════════════════════════════╝")
	fmt.Println()

	browserOpened := openBrowser(verifyURL)
	if browserOpened {
		fmt.Printf("  Browser opened. Enter the code above at:\n  %s\n\n", verifyURL)
	} else {
		fmt.Printf("  Could not open browser. Visit this URL and enter the code:\n  %s\n\n", verifyURL)
	}

	fmt.Println("  Waiting for authentication...")

	// Step 3: Poll for token
	interval := dcResp.Interval
	if interval <= 0 {
		interval = 5
	}
	expiresAt := time.Now().Add(time.Duration(dcResp.ExpiresIn) * time.Second)

	client := &http.Client{Timeout: 10 * time.Second}

	for time.Now().Before(expiresAt) {
		time.Sleep(time.Duration(interval) * time.Second)

		tokenResp, err := pollDeviceToken(client, loginServer, dcResp.DeviceCode)
		if err != nil {
			continue // network error, retry
		}

		if tokenResp.Error == "authorization_pending" {
			continue
		}
		if tokenResp.Error == "slow_down" {
			interval += 2
			continue
		}
		if tokenResp.Error == "expired_token" {
			return fmt.Errorf("device code expired — please try again")
		}
		if tokenResp.Error != "" {
			return fmt.Errorf("authentication failed: %s", tokenResp.Error)
		}

		// Success — save credentials
		creds := &auth.Credentials{
			Server: loginServer,
			Token:  tokenResp.AccessToken,
		}
		if tokenResp.User != nil {
			creds.User.ID = tokenResp.User.ID
			creds.User.Email = tokenResp.User.Email
			creds.User.OrgID = tokenResp.User.OrgID
		}

		if err := auth.Save(creds); err != nil {
			return fmt.Errorf("failed to save credentials: %w", err)
		}

		// Send initial heartbeat to register agent
		sendInitialHeartbeat(client, creds)

		fmt.Println()
		fmt.Printf("  ✅ Logged in as %s\n", creds.User.Email)
		fmt.Println("  Agent registered — visible in your AI Agent Lens dashboard.")
		fmt.Println()
		return nil
	}

	return fmt.Errorf("authentication timed out — please try again")
}

func pollDeviceToken(client *http.Client, server, deviceCode string) (*deviceTokenResponse, error) {
	body, _ := json.Marshal(map[string]string{"device_code": deviceCode})
	resp, err := client.Post(server+"/api/auth/device-token", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenResp deviceTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}
	return &tokenResp, nil
}

func sendInitialHeartbeat(client *http.Client, creds *auth.Credentials) {
	hostname, _ := os.Hostname()
	payload, _ := json.Marshal(map[string]any{
		"hostname":      hostname,
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"agent_version": Version,
		"mode":          "standalone",
	})

	req, err := http.NewRequest("POST", creds.Server+"/api/heartbeat", bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+creds.Token)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

func openBrowser(url string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return false
	}
	return cmd.Start() == nil
}
