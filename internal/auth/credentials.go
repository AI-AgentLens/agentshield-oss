package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const credentialsFile = "credentials.json"

// Credentials stores the authentication state from `agentshield login`.
type Credentials struct {
	Server string `json:"server"`
	Token  string `json:"token"`
	User   struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
		OrgID *int64 `json:"org_id,omitempty"`
	} `json:"user"`
}

// CredentialsPath returns the full path to the credentials file.
func CredentialsPath() string {
	return filepath.Join(configDir(), credentialsFile)
}

// Load reads credentials from ~/.agentshield/credentials.json.
// Returns nil, nil if the file does not exist.
func Load() (*Credentials, error) {
	data, err := os.ReadFile(CredentialsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read credentials: %w", err)
	}

	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("parse credentials: %w", err)
	}
	return &creds, nil
}

// Save writes credentials to ~/.agentshield/credentials.json with 0600 permissions.
func Save(creds *Credentials) error {
	dir := configDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}

	if err := os.WriteFile(CredentialsPath(), data, 0600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}
	return nil
}

// Remove deletes the credentials file.
func Remove() error {
	err := os.Remove(CredentialsPath())
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove credentials: %w", err)
	}
	return nil
}

func configDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".agentshield")
}
