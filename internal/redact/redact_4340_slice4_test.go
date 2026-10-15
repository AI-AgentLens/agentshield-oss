package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

// Slice 4 of #4340: a secret whose name is a parent key or a sibling, and bare
// provider keys. Secrets are assembled at runtime.
func TestRedactArguments_NestedUnderSecretKey_4340(t *testing.T) {
	pw := "pw" + "Secret99"
	rows := []struct{ name, in string }{
		{"object under password", `{"password":{"value":"` + pw + `"}}`},
		{"two levels down", `{"db":{"password":{"inner":{"v":"` + pw + `"}}}}`},
		{"array under password", `{"password":["` + pw + `"]}`},
		{"k8s env pair", `{"env":[{"name":"DB_PASSWORD","value":"` + pw + `"}]}`},
	}
	for _, r := range rows {
		var args map[string]interface{}
		if err := json.Unmarshal([]byte(r.in), &args); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(RedactArguments(args))
		if strings.Contains(string(b), pw) {
			t.Errorf("%s: secret survived: %s", r.name, b)
		}
	}
}

func TestRedactArguments_NestedBenignKept_4340(t *testing.T) {
	in := `{"headers":{"accept":"application/json"},"env":[{"name":"LOG_LEVEL","value":"debug-verbose"}],"n":{"path":"/tmp/some/file.txt"}}`
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(in), &args); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(RedactArguments(args))
	var want, got interface{}
	_ = json.Unmarshal([]byte(in), &want)
	_ = json.Unmarshal(b, &got)
	if a, _ := json.Marshal(want); string(a) != string(b) {
		t.Errorf("benign object changed:\n in: %s\nout: %s", a, b)
	}
	_ = got
}

func TestRedact_BareProviderKeys_4340(t *testing.T) {
	for _, secret := range []string{
		"sk-ant-" + "api03-abcdefghijklmnopqrstuv",
		"sk-proj-" + "abcdefghijklmnopqrstuvwxyz0123",
	} {
		if got := Redact("export X=" + secret); strings.Contains(got, secret) {
			t.Errorf("provider key survived: %q", got)
		}
	}
	for _, in := range []string{"git checkout task-ant-colony", "echo sk-ant"} {
		if got := Redact(in); got != in {
			t.Errorf("benign changed: %q -> %q", in, got)
		}
	}
}

func TestRedactArguments_DoesNotAliasInput_4340(t *testing.T) {
	in := map[string]interface{}{"l": []interface{}{"a", map[string]interface{}{"password": "pw" + "Secret99"}}}
	out := RedactArguments(in)
	out["l"].([]interface{})[0] = "changed"
	if in["l"].([]interface{})[0] != "a" {
		t.Error("output aliases input array")
	}
	if in["l"].([]interface{})[1].(map[string]interface{})["password"] != "pw"+"Secret99" {
		t.Error("input modified")
	}
}
