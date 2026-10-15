package redact

import (
	"strings"
	"testing"
)

// TestRedact_Slice3From4340 covers the third slice of #4340: the key body of a
// PEM block, and a credential passed as the NEXT argument (--password <v>,
// curl -u user:pass). Secrets are assembled at runtime.
func TestRedact_Slice3From4340(t *testing.T) {
	body := "MIIEowIBAAKCAQEA" + "x9Zq1LmNoPqRsTuVwXyZ"
	pw := "hunter" + "2Secret"
	rows := []struct{ name, in, secret string }{
		{"pem block multi-line", "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----", body},
		{"pem block bare PRIVATE KEY", "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----", body},
		{"pem block, JSON-escaped newlines", `{"key":"-----BEGIN OPENSSH PRIVATE KEY-----\n` + body + `\n-----END OPENSSH PRIVATE KEY-----\n"}`, body},
		{"--password space value", "mysql --password " + pw + " -h db", pw},
		{"--passwd space value", "tool --passwd " + pw, pw},
		{"--token space value", "cli login --token " + pw, pw},
		{"curl -u user:pass", "curl -u admin:" + pw + " https://api.example.com/", pw},
		{"curl --user user:pass", "curl --user admin:" + pw + " https://api.example.com/", pw},
	}
	for _, r := range rows {
		if got := Redact(r.in); strings.Contains(got, r.secret) {
			t.Errorf("%s: secret survived: %q", r.name, got)
		}
	}
}

func TestRedact_Slice3KeepsOrdinaryTextReadable(t *testing.T) {
	for _, in := range []string{
		"mysql --password-file /etc/db.pw -h db",
		"cli --token-url https://auth.example.com",
		"curl -u admin https://api.example.com/",
		"git log --user alice",
		"curl --user-agent foo https://example.com",
		"echo -----BEGIN PUBLIC KEY-----",
	} {
		if got := Redact(in); got != in {
			t.Errorf("benign text changed:\n in: %q\nout: %q", in, got)
		}
	}
}
