package redact

import (
	"strings"
	"testing"
)

// TestRedact_ShapesFrom4340 covers the shapes #4340 measured as leaking. Each
// row's secret is assembled at runtime so the source is not itself a secret.
func TestRedact_ShapesFrom4340(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NSJ9" + "." + "dGhpc2lzdGhlc2ln"
	pw := "pw" + "Secret99"
	rows := []struct{ name, in, secret string }{
		{"jwt bearer", "Authorization: Bea" + "rer " + jwt, jwt},
		{"jwt bearer, no header", "curl -H 'Bea" + "rer " + jwt + "'", jwt},
		{"short bearer under Authorization", "Authorization: Bea" + "rer abc123def", "abc123def"},
		{"short bearer, JSON header map", `{"Authorization": "Bea` + `rer abc123def"}`, "abc123def"},
		{"postgres userinfo", "psql postgres://app:" + pw + "@db.internal/prod", pw},
		{"mongodb+srv userinfo", "mongosh mongodb+srv://app:" + pw + "@cl.example.net/x", pw},
		{"amqp userinfo", "amqp://guest:" + pw + "@mq:5672/", pw},
	}
	for _, r := range rows {
		if got := Redact(r.in); strings.Contains(got, r.secret) {
			t.Errorf("%s: secret survived: %q", r.name, got)
		}
	}
}

// TestRedact_NoFalseRedactionFrom4340Patterns keeps ordinary text readable.
func TestRedact_NoFalseRedactionFrom4340Patterns(t *testing.T) {
	for _, in := range []string{
		"git commit -m 'document bearer authentication flow'",
		"the bearer of bad news",
		"ssh://git@github.com/org/repo.git",
		"git clone https://github.com/org/repo.git",
		"psql postgres://db.internal:5432/prod",
		"curl http://localhost:8080/path",
		"echo 'authorization: required'",
	} {
		if got := Redact(in); got != in {
			t.Errorf("benign text changed:\n in: %q\nout: %q", in, got)
		}
	}
}
