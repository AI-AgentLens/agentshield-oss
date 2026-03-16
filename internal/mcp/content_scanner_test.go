package mcp

import (
	"strings"
	"testing"
)

func TestContentScan_CleanArguments(t *testing.T) {
	result := ScanToolCallContent("get_weather", map[string]interface{}{
		"location": "New York City",
		"units":    "celsius",
	})
	if result.Blocked {
		t.Errorf("expected clean args, got blocked with findings: %v", result.Findings)
	}
}

func TestContentScan_SSHPrivateKey(t *testing.T) {
	result := ScanToolCallContent("send_message", map[string]interface{}{
		"to":      "user@example.com",
		"subject": "Hello",
		"body":    "Here is the key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — SSH private key in argument")
	}
	assertContentSignal(t, result, SignalPrivateKey)
}

func TestContentScan_AWSAccessKey(t *testing.T) {
	result := ScanToolCallContent("add", map[string]interface{}{
		"a":        1,
		"b":        2,
		"sidenote": "AKIAIOSFODNN7EXAMPLE",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — AWS access key in sidenote")
	}
	assertContentSignal(t, result, SignalAWSCredential)
}

func TestContentScan_AWSSecretAssignment(t *testing.T) {
	result := ScanToolCallContent("calculator", map[string]interface{}{
		"context": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — AWS secret in argument")
	}
	assertContentSignal(t, result, SignalAWSCredential)
}

func TestContentScan_GitHubToken(t *testing.T) {
	result := ScanToolCallContent("search", map[string]interface{}{
		"query":   "test",
		"context": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — GitHub token")
	}
	assertContentSignal(t, result, SignalGitHubToken)
}

func TestContentScan_BearerToken(t *testing.T) {
	result := ScanToolCallContent("fetch", map[string]interface{}{
		"url":     "https://api.example.com/data",
		"headers": "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — bearer token")
	}
	assertContentSignal(t, result, SignalBearerToken)
}

func TestContentScan_BasicAuthURL(t *testing.T) {
	result := ScanToolCallContent("fetch", map[string]interface{}{
		"url": "https://admin:s3cret_p4ss@internal-api.company.com/data",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — basic auth in URL")
	}
	assertContentSignal(t, result, SignalBasicAuth)
}

func TestContentScan_StripeKey(t *testing.T) {
	stripeKey := "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
	result := ScanToolCallContent("payment", map[string]interface{}{
		"key": stripeKey,
	})
	if !result.Blocked {
		t.Fatal("expected blocked — Stripe secret key")
	}
	assertContentSignal(t, result, SignalStripeKey)
}

func TestContentScan_GenericAPIKey(t *testing.T) {
	result := ScanToolCallContent("config", map[string]interface{}{
		"data": "api_key=sk-proj-abcdefghijklmnopqrstuvwxyz123456",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — generic API key")
	}
	assertContentSignal(t, result, SignalGenericSecret)
}

func TestContentScan_EnvFileContent(t *testing.T) {
	envContent := `DATABASE_URL=postgres://user:pass@host:5432/db
API_KEY=sk-1234567890abcdef
SECRET_KEY=mysupersecretvalue
REDIS_URL=redis://localhost:6379`

	result := ScanToolCallContent("write_file", map[string]interface{}{
		"path":    "/tmp/test.env",
		"content": envContent,
	})
	if !result.Blocked {
		t.Fatal("expected blocked — .env file content with secrets")
	}
	assertContentSignal(t, result, SignalEnvFileContent)
}

func TestContentScan_LargeBase64Blob(t *testing.T) {
	// Generate a large base64-looking string (simulating exfiltrated file content)
	blob := strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 5)

	result := ScanToolCallContent("add", map[string]interface{}{
		"a":        1,
		"b":        2,
		"sidenote": blob,
	})
	if !result.Blocked {
		t.Fatal("expected blocked — large base64 blob in sidenote")
	}
	assertContentSignal(t, result, SignalBase64Blob)
}

func TestContentScan_NestedArguments(t *testing.T) {
	result := ScanToolCallContent("complex_tool", map[string]interface{}{
		"config": map[string]interface{}{
			"auth": "-----BEGIN OPENSSH PRIVATE KEY-----\nbase64data\n-----END OPENSSH PRIVATE KEY-----",
		},
	})
	if !result.Blocked {
		t.Fatal("expected blocked — private key in nested argument")
	}
	assertContentSignal(t, result, SignalPrivateKey)
}

func TestContentScan_WhatsAppExfiltration(t *testing.T) {
	// Real-world attack pattern: WhatsApp MCP exfiltration
	// The agent reads SSH keys and passes them as a "sidenote" parameter
	result := ScanToolCallContent("add", map[string]interface{}{
		"a":        42,
		"b":        13,
		"sidenote": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWep4PAtGoRBh2vHKSl0tkjyPFOExrr\nnG5ka15mMNHMdF+E0k0XavSmGvh97PmYbvfJNY5tCl8JjF8T7LMbGMXQ\n-----END RSA PRIVATE KEY-----",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — WhatsApp-style SSH key exfiltration via sidenote")
	}
	assertContentSignal(t, result, SignalPrivateKey)
}

func TestContentScan_SlackToken(t *testing.T) {
	slackToken := "xoxb-" + "1234567890123-" + "1234567890123-" + "ABCdefGHIjklMNOpqrSTUvwx"
	result := ScanToolCallContent("notify", map[string]interface{}{
		"token": slackToken,
	})
	if !result.Blocked {
		t.Fatal("expected blocked — Slack token")
	}
	assertContentSignal(t, result, SignalSlackToken)
}

func TestContentScan_SafeBase64(t *testing.T) {
	// Short base64 should NOT trigger (could be a legitimate small payload)
	result := ScanToolCallContent("encode", map[string]interface{}{
		"data": "SGVsbG8gV29ybGQ=", // "Hello World"
	})
	if result.Blocked {
		t.Errorf("short base64 should not trigger, got: %v", result.Findings)
	}
}

func TestContentScan_NormalTextNotBlocked(t *testing.T) {
	result := ScanToolCallContent("write_file", map[string]interface{}{
		"path":    "/tmp/readme.md",
		"content": "# My Project\n\nThis is a normal README file with regular text content.\nIt has multiple lines but no secrets.\n\n## Installation\n\nnpm install my-package",
	})
	if result.Blocked {
		t.Errorf("normal text should not be blocked, got: %v", result.Findings)
	}
}

func TestContentScan_EmptyArguments(t *testing.T) {
	result := ScanToolCallContent("noop", map[string]interface{}{})
	if result.Blocked {
		t.Error("empty arguments should not be blocked")
	}
}

func TestContentScan_NilArguments(t *testing.T) {
	result := ScanToolCallContent("noop", nil)
	if result.Blocked {
		t.Error("nil arguments should not be blocked")
	}
}

func TestContentScan_PGPPrivateKey(t *testing.T) {
	result := ScanToolCallContent("send_data", map[string]interface{}{
		"payload": "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\nlQOYBF...\n-----END PGP PRIVATE KEY BLOCK-----",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — PGP private key")
	}
	assertContentSignal(t, result, SignalPrivateKey)
}

func TestContentScan_OpenSSHKey(t *testing.T) {
	result := ScanToolCallContent("upload", map[string]interface{}{
		"file_content": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA...\n-----END OPENSSH PRIVATE KEY-----",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — OpenSSH private key")
	}
	assertContentSignal(t, result, SignalPrivateKey)
}

func TestContentScan_HighEntropyString(t *testing.T) {
	// Generate a string with high entropy (random-looking chars, >100 chars)
	highEntropy := "aK9xZm3qR7wL2nY8pJ4vT6bF1hD5gS0cE3iU9oA7mW2lX8jN4kQ6rV1tB5yH0fG3dP9sI7uO2eC8aM4nR6wJ1xL5kT3bF9hY0gQ7vD2pS8cE4iU6oA3mW1lX7jN9kQ5rV0tB4yH2fG6dP8sI1uO3eC7aM9n"
	result := ScanToolCallContent("process", map[string]interface{}{
		"data": highEntropy,
	})
	if !result.Blocked {
		t.Fatal("expected blocked — high entropy string")
	}
	assertContentSignal(t, result, SignalHighEntropy)
}

func TestContentScan_MultipleSecretsInOneCall(t *testing.T) {
	stripeKey := "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
	result := ScanToolCallContent("exfil", map[string]interface{}{
		"aws_key":  "AKIAIOSFODNN7EXAMPLE",
		"gh_token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
		"stripe":   stripeKey,
	})
	if !result.Blocked {
		t.Fatal("expected blocked — multiple secrets")
	}
	if len(result.Findings) < 3 {
		t.Errorf("expected at least 3 findings, got %d", len(result.Findings))
	}
}

func TestContentScan_ArrayArgWithSecret(t *testing.T) {
	result := ScanToolCallContent("batch", map[string]interface{}{
		"items": []interface{}{
			"normal text",
			"AKIAIOSFODNN7EXAMPLE",
			"more normal text",
		},
	})
	if !result.Blocked {
		t.Fatal("expected blocked — AWS key in array argument")
	}
	assertContentSignal(t, result, SignalAWSCredential)
}

func TestContentScan_NumericArgsNotBlocked(t *testing.T) {
	result := ScanToolCallContent("calc", map[string]interface{}{
		"a":      42,
		"b":      3.14,
		"negate": true,
	})
	if result.Blocked {
		t.Errorf("numeric/boolean args should not be blocked, got: %v", result.Findings)
	}
}

func TestContentScan_GCPServiceAccountKey(t *testing.T) {
	// Google Cloud service account JSON typically contains private_key field
	gcpKey := `{
  "type": "service_account",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n",
  "client_email": "test@project.iam.gserviceaccount.com"
}`
	result := ScanToolCallContent("upload_config", map[string]interface{}{
		"content": gcpKey,
	})
	if !result.Blocked {
		t.Fatal("expected blocked — GCP service account key contains private key")
	}
	assertContentSignal(t, result, SignalPrivateKey)
}

func TestContentScan_SafeURLNotBlocked(t *testing.T) {
	// URLs without credentials should not trigger basic_auth
	result := ScanToolCallContent("fetch", map[string]interface{}{
		"url": "https://api.example.com/v2/data?page=1&limit=50",
	})
	if result.Blocked {
		t.Errorf("safe URL should not be blocked, got: %v", result.Findings)
	}
}

func TestContentScan_SafeJSONNotBlocked(t *testing.T) {
	// Normal JSON config should not trigger
	result := ScanToolCallContent("write_file", map[string]interface{}{
		"path":    "/tmp/config.json",
		"content": `{"database": {"host": "localhost", "port": 5432, "name": "mydb"}, "debug": true}`,
	})
	if result.Blocked {
		t.Errorf("normal JSON should not be blocked, got: %v", result.Findings)
	}
}

func TestContentScan_SafeCodeNotBlocked(t *testing.T) {
	// Source code with the word "key" should not trigger
	result := ScanToolCallContent("write_file", map[string]interface{}{
		"path":    "/tmp/main.go",
		"content": "package main\n\nfunc main() {\n\tkey := \"user-input\"\n\tfmt.Println(key)\n}",
	})
	if result.Blocked {
		t.Errorf("normal source code should not be blocked, got: %v", result.Findings)
	}
}

func TestContentScan_DeeplyNestedSecret(t *testing.T) {
	result := ScanToolCallContent("complex", map[string]interface{}{
		"level1": map[string]interface{}{
			"level2": map[string]interface{}{
				"level3": "AKIAIOSFODNN7EXAMPLE",
			},
		},
	})
	if !result.Blocked {
		t.Fatal("expected blocked — AWS key in deeply nested argument")
	}
	assertContentSignal(t, result, SignalAWSCredential)
}

// ── Database URI tests ─────────────────────────────────────────────────────

// TestContentScan_DatabaseURIMySQL verifies that a MySQL connection string with
// embedded credentials in a tool argument is detected and blocked.
// Taxonomy: credential-exposure/database-access/database-credential-access
func TestContentScan_DatabaseURIMySQL(t *testing.T) {
	result := ScanToolCallContent("execute_query", map[string]interface{}{
		"connection_string": "mysql://admin:s3cr3t@prod-db.internal:3306/customers",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — MySQL URI with credentials")
	}
	assertContentSignal(t, result, SignalDatabaseURI)
}

func TestContentScan_DatabaseURIPostgres(t *testing.T) {
	result := ScanToolCallContent("run_sql", map[string]interface{}{
		"dsn": "postgresql://dbuser:password123@db.example.com:5432/production",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — PostgreSQL URI with credentials")
	}
	assertContentSignal(t, result, SignalDatabaseURI)
}

func TestContentScan_DatabaseURIMongoDB(t *testing.T) {
	result := ScanToolCallContent("query_collection", map[string]interface{}{
		"uri": "mongodb://root:mongopass@cluster0.example.mongodb.net:27017/mydb",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — MongoDB URI with credentials")
	}
	assertContentSignal(t, result, SignalDatabaseURI)
}

func TestContentScan_DatabaseURIMongoSRV(t *testing.T) {
	result := ScanToolCallContent("aggregate", map[string]interface{}{
		"connection": "mongodb+srv://admin:atlas_pass@cluster.mongodb.net/prod",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — MongoDB+srv URI with credentials")
	}
	assertContentSignal(t, result, SignalDatabaseURI)
}

func TestContentScan_DatabaseURIRedis(t *testing.T) {
	result := ScanToolCallContent("cache_set", map[string]interface{}{
		"url": "redis://:redispassword@redis.internal:6379/0",
	})
	if !result.Blocked {
		t.Fatal("expected blocked — Redis URI with credentials")
	}
	assertContentSignal(t, result, SignalDatabaseURI)
}

// TestContentScan_DatabaseURINoCredentials verifies that a database URI
// without embedded credentials (no user:pass@) does NOT trigger the signal,
// avoiding FPs on bare connection strings used for development.
func TestContentScan_DatabaseURINoCredentials(t *testing.T) {
	result := ScanToolCallContent("connect", map[string]interface{}{
		"host":     "localhost",
		"database": "myapp_dev",
		"port":     5432,
	})
	if result.Blocked {
		t.Errorf("plain connection args without URI should not be blocked, got: %v", result.Findings)
	}
}

func assertContentSignal(t *testing.T, result ContentScanResult, signal ContentSignal) {
	t.Helper()
	for _, f := range result.Findings {
		if f.Signal == signal {
			return
		}
	}
	var found []string
	for _, f := range result.Findings {
		found = append(found, string(f.Signal)+": "+f.Detail)
	}
	t.Errorf("expected signal %s, got: %v", signal, found)
}
