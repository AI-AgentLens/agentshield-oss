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

// Secret-shaped values are assembled at runtime so no literal key-shaped
// string sits in this file (AgentShield guards the machine it is written on).
func spanTestToken() string { return "tok_" + "live_" + "A1b2" + "C3d4" + "E5f6" + "Lk4332" }

// TestRedactArgs_SecretSpanningArguments is the #4332 local-log case: the
// bearer token is its own whitespace-split argument, so redacting argument by
// argument kept it. Both quote styles split the same way.
func TestRedactArgs_SecretSpanningArguments(t *testing.T) {
	for _, q := range []string{`"`, `'`} {
		cmd := `curl -sS -H ` + q + `Authorization: Bearer ` + spanTestToken() + q + ` https://api.example.com/v1/me`
		got := RedactArgs(strings.Fields(cmd))
		joined := strings.Join(got, " ")
		if strings.Contains(joined, spanTestToken()) {
			t.Errorf("quote %s: token survived in args: %q", q, got)
		}
		// Same result as redacting the command line itself.
		if want := strings.Fields(Redact(cmd)); strings.Join(want, " ") != joined {
			t.Errorf("quote %s: args %q disagree with the redacted command %q", q, got, want)
		}
		for _, keep := range []string{"curl", "-sS", "-H", "https://api.example.com/v1/me"} {
			if !strings.Contains(joined, keep) {
				t.Errorf("quote %s: args %q lost %q", q, got, keep)
			}
		}
	}
}

// TestRedactArgs_ElementForElementWhenNothingSpans pins that the line pass
// only reshapes the list when it found something the per-argument pass missed.
func TestRedactArgs_ElementForElementWhenNothingSpans(t *testing.T) {
	args := []string{"env", "API_KEY=" + spanTestToken(), "./run.sh", "--verbose"}
	got := RedactArgs(args)
	if len(got) != len(args) {
		t.Fatalf("len = %d, want %d: %q", len(got), len(args), got)
	}
	want := []string{"env", "[REDACTED]", "./run.sh", "--verbose"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("arg %d = %q, want %q", i, got[i], want[i])
		}
	}
	if args[1] != "API_KEY="+spanTestToken() {
		t.Errorf("input modified: %q", args)
	}
}

// TestRedactArgs_NilBecomesEmpty pins the audit line's "args":[] for events
// without args, which RedactArgs has always produced.
func TestRedactArgs_NilBecomesEmpty(t *testing.T) {
	if got := RedactArgs(nil); got == nil || len(got) != 0 {
		t.Errorf("RedactArgs(nil) = %#v, want an empty non-nil slice", got)
	}
}

func TestRedactArguments(t *testing.T) {
	pw := "Pw-" + "Sx9" + "-q7" + "Lk4332"
	tok := spanTestToken()
	in := map[string]interface{}{
		"host":     "db.internal",
		"password": pw,
		"auth": map[string]interface{}{
			"access_token": tok,
			"scopes":       []interface{}{"read", "write"},
		},
		"api_key": []interface{}{tok},
		"headers": map[string]interface{}{"Authorization": "Bearer " + tok},
		"retries": 3.0,
		"verbose": true,
		"empty":   nil,
		"pin":     "1234", // shorter than the password pattern's 8 characters
	}
	got := RedactArguments(in)

	checks := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"password (key names the secret)", got["password"], "[REDACTED]"},
		{"nested access_token", got["auth"].(map[string]interface{})["access_token"], "[REDACTED]"},
		{"bearer value under a neutral key", got["headers"].(map[string]interface{})["Authorization"], "[REDACTED]"},
		{"host kept", got["host"], "db.internal"},
		{"number kept", got["retries"], 3.0},
		{"bool kept", got["verbose"], true},
		{"null kept", got["empty"], nil},
		{"short value kept", got["pin"], "1234"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %#v, want %#v", c.name, c.got, c.want)
		}
	}
	if s := got["auth"].(map[string]interface{})["scopes"].([]interface{}); s[0] != "read" || s[1] != "write" {
		t.Errorf("scopes changed: %#v", s)
	}
	// An array's strings are judged under the array's key.
	if s := got["api_key"].([]interface{}); s[0] != "[REDACTED]" {
		t.Errorf("api_key element kept the token: %#v", s)
	}
	// Input untouched, nested levels included.
	if in["password"] != pw || in["auth"].(map[string]interface{})["access_token"] != tok {
		t.Errorf("input map was modified: %#v", in)
	}
	if RedactArguments(nil) != nil {
		t.Error("RedactArguments(nil) should be nil")
	}
}

// TestRedactArguments_BareTokenKey: a key called just "token" is redacted
// like access_token and auth_token (#4340; this was a pinned gap until then).
func TestRedactArguments_BareTokenKey(t *testing.T) {
	v := "opaque" + "Value" + "Lk4332" + "abcdef"
	got := RedactArguments(map[string]interface{}{"token": v})
	if got["token"] != "[REDACTED]" {
		t.Errorf("bare token key kept its value: %#v", got["token"])
	}
}

// #4340: a JSON-quoted key puts a quote between the name and the colon, so
// `password\s*[=:]` never matched the most common real-world shape.
func TestRedact_JSONQuotedKeys(t *testing.T) {
	secrets := []struct{ input, secret string }{
		{`curl -d '{"user":"app","password":"hunter2hunter2"}' https://x.example`, "hunter2hunter2"},
		{`{"api_key": "abcdefghijklmnop1234"}`, "abcdefghijklmnop1234"},
		{`{'secret': 'abcdefgh1234'}`, "abcdefgh1234"},
		{`{"AWS_SECRET_ACCESS_KEY":"abcdefghijklmnopqrstuvwxyz123456"}`, "abcdefghijklmnopqrstuvwxyz123456"},
		{`{"github_token":"some_long_token_value_here_1234567890"}`, "some_long_token_value_here_1234567890"},
	}
	for _, tt := range secrets {
		got := Redact(tt.input)
		if strings.Contains(got, tt.secret) {
			t.Errorf("Redact(%q) = %q, still contains the secret", tt.input, got)
		}
	}
}

func TestRedact_JSONQuotedKeys_BenignUnchanged(t *testing.T) {
	for _, in := range []string{
		`{"user":"app","name":"build"}`,
		`{"password_policy":"strict"}`,
		`git commit -m "document the password rotation process"`,
		`{"password":"short"}`,
	} {
		if got := Redact(in); got != in {
			t.Errorf("Redact(%q) = %q, expected unchanged", in, got)
		}
	}
}

// TestRedactArguments_ArrayIsADeepCopy pins that redacting an array never
// writes through to the caller's slice (#4340 follow-up): the input is
// documented as unmodified, and an `out := t` shortcut would alias it.
func TestRedactArguments_ArrayIsADeepCopy(t *testing.T) {
	pw := "hunter2" + "hunter2"
	in := map[string]interface{}{
		"password": []interface{}{pw, map[string]interface{}{"password": pw}},
	}
	got := RedactArguments(in)

	arr := in["password"].([]interface{})
	if arr[0] != pw || arr[1].(map[string]interface{})["password"] != pw {
		t.Fatalf("input array was modified: %#v", arr)
	}
	out := got["password"].([]interface{})
	if out[0] != "[REDACTED]" || out[1].(map[string]interface{})["password"] != "[REDACTED]" {
		t.Fatalf("array elements not redacted: %#v", out)
	}
	out[0] = "changed"
	if arr[0] != pw {
		t.Fatalf("output shares storage with input")
	}
}
