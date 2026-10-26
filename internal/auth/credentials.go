package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AI-AgentLens/agentshield/internal/logger"
)

const credentialsFile = "credentials.json"

// credentialsMaxBytes caps the credentials read (#4474). Save writes a
// server URL, one bearer token and a three-field user object, indented: a
// real file is around a kilobyte. 64 KiB is about fifty times that, and a
// file anywhere near it could not authenticate anyway: the token is sent in
// an Authorization header, and common front ends refuse a single header
// line far smaller (nginx's default is 8 KiB). Over the cap reads as no
// credentials, so a too-small cap would only stop the SaaS send, never
// change a verdict.
const credentialsMaxBytes = 64 << 10

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
// Returns nil, nil if the file does not exist, and equally when it is
// anything but a readable regular file of at most credentialsMaxBytes: a
// FIFO, a device, a directory, an oversized file, or one this user cannot
// read. A symlink is followed, and its target must pass the same check.
// Only a file that was read but does not parse is an error.
//
// The hook calls Load before it returns its verdict (sendRemoteAudit), so
// the read must never block: with a plain os.ReadFile, a FIFO at the path
// blocked open(2) with no writer and the hook gave no verdict at all
// (#4474; the #4057 FIFO class). Any process running as this user can
// plant one (#4393). "No credentials" means no SaaS send, which leaves the
// verdict untouched; that is why every such case folds into it.
func Load() (*Credentials, error) {
	data, ok := logger.ReadRegularFileCapped(CredentialsPath(), credentialsMaxBytes)
	if !ok {
		return nil, nil
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
