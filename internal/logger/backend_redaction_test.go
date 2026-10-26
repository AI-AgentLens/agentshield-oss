package logger

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The syslog and webhook backends marshal the event themselves, so they have
// to apply the same Redacted as the file line and the SaaS wire copy (#4332).
// Secret is assembled at runtime: the hook reads test sources as commands.
func backendSecretCommand() (cmd, secret string) {
	secret = "hunter2" + "-correct-horse-9912"
	return "curl -H 'Authorization: Bearer " + secret + "' https://example.test/x", secret
}

func TestWebhookLogger_RedactsEvent(t *testing.T) {
	cmd, secret := backendSecretCommand()
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
	}))
	defer srv.Close()

	w := NewWebhookLogger(srv.URL, "")
	if err := w.SendSync(AuditEvent{Command: cmd, Args: strings.Fields(cmd), Decision: "AUDIT"}); err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Fatal("webhook received nothing: the control did not run")
	}
	if strings.Contains(got, secret) {
		t.Fatalf("webhook payload carries the secret: %s", got)
	}
	if !strings.Contains(got, "example.test") {
		t.Fatalf("redaction ate the command shape: %s", got)
	}
}

func TestSyslogLogger_RedactsEvent(t *testing.T) {
	cmd, secret := backendSecretCommand()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no udp listener: %v", err)
	}
	defer pc.Close()

	s, err := NewSyslogLogger("udp", pc.LocalAddr().String())
	if err != nil {
		t.Skipf("syslog dial: %v", err)
	}
	defer s.Close()
	if err := s.Log(AuditEvent{Command: cmd, Args: strings.Fields(cmd), Decision: "AUDIT"}); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 65536)
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("syslog datagram not received: %v", err)
	}
	msg := string(buf[:n])
	if strings.Contains(msg, secret) {
		t.Fatalf("syslog message carries the secret: %s", msg)
	}
	if !strings.Contains(msg, "example.test") {
		t.Fatalf("redaction ate the command shape: %s", msg)
	}
}
