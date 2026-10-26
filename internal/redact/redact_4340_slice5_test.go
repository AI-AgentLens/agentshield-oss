package redact

import (
	"strings"
	"testing"
)

// #4340: a secret under the bare name "token" was the last shape in the issue's
// table that leaked on every surface.
func TestRedact_BareTokenName_4340(t *testing.T) {
	v := "Zk3" + "Qw9xLm2" + "Rt7Yp"
	for name, in := range map[string]string{
		"env assignment": "export TOKEN=" + v,
		"inline env":     "TOKEN=" + v + " make deploy",
		"json key":       `curl -d '{"token":"` + v + `"}'`,
		"header":         "curl -H 'X-Token: " + v + "' https://api.example.com",
		"prefixed":       "DEPLOY_TOKEN=" + v,
	} {
		if got := Redact(in); strings.Contains(got, v) {
			t.Errorf("%s: value survived: %q", name, got)
		}
	}
}

func TestRedact_BareTokenName_LeavesProseAlone_4340(t *testing.T) {
	for _, in := range []string{
		`git commit -m "token: refresh on expiry"`,
		"echo max token=42",
		"cli --token-url https://auth.example.com/oauth",
		`{"tokens": 4096, "max_tokens": 1024}`,
		"grep -rn 'token' internal/",
		"export TOKENIZERS_PARALLELISM=false",
	} {
		if got := Redact(in); got != in {
			t.Errorf("over-redacted %q -> %q", in, got)
		}
	}
}
