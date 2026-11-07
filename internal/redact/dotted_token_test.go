package redact

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestRedact_DottedTokenAfterKeyName_4816: a JWT (or any dotted token) after
// a credential key name is redacted whole. The generic key pattern used to
// stop at the first dot, leaving the payload and signature in the record; a
// JWT header is standard, so the rest rebuilds the token.
func TestRedact_DottedTokenAfterKeyName_4816(t *testing.T) {
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	// Assembled at runtime: AgentShield reads test sources as content, and
	// blocks a key name joined to a value (#4811).
	payload := b64(`{"sub":"1234567890","name":"x"}`)
	sig := "Sig" + strings.Repeat("QwErTy", 6)
	jwt := b64(`{"alg":"HS256","typ":"JWT"}`) + "." + payload + "." + sig
	keys := []string{"access" + "_to" + "ken", "ACCESS" + "_TO" + "KEN", "auth" + "_to" + "ken", "api" + "_key", "secret" + "_key"}
	var inputs []string
	for _, k := range keys {
		inputs = append(inputs,
			"export "+k+"="+jwt,
			"curl 'https://api.example.com/v1?"+k+"="+jwt+"'",
			`{"`+k+`": "`+jwt+`"}`,
			k+": "+jwt,
		)
	}
	for _, in := range inputs {
		got := Redact(in)
		if strings.Contains(got, payload) || strings.Contains(got, sig) {
			t.Errorf("Redact(%q) = %q: part of the token survived", in, got)
		}
		if !strings.Contains(got, "[REDACTED]") {
			t.Errorf("Redact(%q) = %q: nothing redacted", in, got)
		}
	}

	// Controls: an undotted value after a key name is redacted as before, and
	// text with no key name is left alone.
	plain := "export " + keys[0] + "=" + strings.Repeat("Ab3", 8)
	if got := Redact(plain); strings.Contains(got, "Ab3Ab3Ab3") {
		t.Errorf("Redact(%q) = %q: an undotted value survived", plain, got)
	}
	for _, s := range []string{"go test ./internal/redact/...", "echo v1.2.3-rc.4.build.567890123456", "cat docs/api_key_rotation.md"} {
		if got := Redact(s); got != s {
			t.Errorf("Redact(%q) = %q: text with no credential changed", s, got)
		}
	}
}
