package redact

import (
	"strings"
	"testing"
)

func TestRedact_AWSKeys(t *testing.T) {
	tests := []struct {
		input    string
		contains string
	}{
		{"AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwxyz123456", "[REDACTED]"},
		{"export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "[REDACTED]"},
		{"AKIAIOSFODNN7EXAMPLE", "[REDACTED]"},
	}

	for _, tt := range tests {
		result := Redact(tt.input)
		if !strings.Contains(result, tt.contains) {
			t.Errorf("Redact(%q) = %q, expected to contain %q", tt.input, result, tt.contains)
		}
		if strings.Contains(result, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("Redact(%q) should not contain original key", tt.input)
		}
	}
}

func TestRedact_GitHubTokens(t *testing.T) {
	tests := []string{
		"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"export GH_TOKEN=some_long_token_value_here_1234567890",
	}

	for _, input := range tests {
		result := Redact(input)
		if !strings.Contains(result, "[REDACTED]") {
			t.Errorf("Redact(%q) = %q, expected to contain [REDACTED]", input, result)
		}
	}
}

func TestRedact_PrivateKeys(t *testing.T) {
	input := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`

	result := Redact(input)
	if !strings.Contains(result, "[REDACTED]") {
		t.Errorf("Private key should be redacted")
	}
}

func TestRedact_Passwords(t *testing.T) {
	tests := []string{
		"password=mysecretpassword",
		"PASSWORD: supersecret123",
		"secret=verysecretvalue",
	}

	for _, input := range tests {
		result := Redact(input)
		if !strings.Contains(result, "[REDACTED]") {
			t.Errorf("Redact(%q) = %q, expected to contain [REDACTED]", input, result)
		}
	}
}

func TestRedact_PreservesNonSensitive(t *testing.T) {
	input := "echo hello world"
	result := Redact(input)
	if result != input {
		t.Errorf("Non-sensitive input should not be modified: got %q", result)
	}
}

func TestRedactEnvVars(t *testing.T) {
	envVars := []string{
		"PATH=/usr/bin",
		"AWS_SECRET_ACCESS_KEY=verysecret",
		"HOME=/Users/test",
		"GITHUB_TOKEN=ghp_token123",
	}

	result := RedactEnvVars(envVars)

	for _, env := range result {
		if strings.HasPrefix(env, "AWS_SECRET_ACCESS_KEY=") && !strings.Contains(env, "[REDACTED]") {
			t.Errorf("AWS_SECRET_ACCESS_KEY should be redacted: %s", env)
		}
		if strings.HasPrefix(env, "GITHUB_TOKEN=") && !strings.Contains(env, "[REDACTED]") {
			t.Errorf("GITHUB_TOKEN should be redacted: %s", env)
		}
		if strings.HasPrefix(env, "PATH=") && strings.Contains(env, "[REDACTED]") {
			t.Errorf("PATH should not be redacted: %s", env)
		}
	}
}
