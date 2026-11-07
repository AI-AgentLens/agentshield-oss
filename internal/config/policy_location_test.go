package config

import (
	"os"
	"path/filepath"
	"testing"
)

// #4805: PolicyLocation names the files Load would, so the hook's fail-safe
// record reads its data_labels from the policy file evaluation would have
// read, and creates nothing doing so.
func TestPolicyLocation_MatchesLoad(t *testing.T) {
	for _, c := range []struct {
		name       string
		managed    string // managed.json content; "" for none
		policyPath string
	}{
		{"default path", "", ""},
		{"custom path", "", "/custom/policy.yaml"},
		{"managed host ignores a custom path", `{"managed": true, "fail_closed": true}`, "/custom/policy.yaml"},
		{"corrupt managed.json is managed", `not json`, "/custom/policy.yaml"},
		{"unmanaged managed.json keeps a custom path", `{"managed": false}`, "/custom/policy.yaml"},
	} {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			configDir := filepath.Join(home, DefaultConfigDir)
			if c.managed != "" {
				if err := os.MkdirAll(configDir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(configDir, "managed.json"), []byte(c.managed), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			gotDir, gotPolicy, err := PolicyLocation(c.policyPath)
			if err != nil {
				t.Fatal(err)
			}
			if c.managed == "" {
				if _, err := os.Stat(configDir); !os.IsNotExist(err) {
					t.Fatalf("PolicyLocation created %s (stat: %v)", configDir, err)
				}
			}
			cfg, err := Load(c.policyPath, "", "enforce")
			if err != nil {
				t.Fatal(err)
			}
			if gotDir != cfg.ConfigDir || gotPolicy != cfg.PolicyPath {
				t.Errorf("PolicyLocation = %s, %s; Load = %s, %s", gotDir, gotPolicy, cfg.ConfigDir, cfg.PolicyPath)
			}
		})
	}
}

func TestPolicyLocation_NoHomeIsAnError(t *testing.T) {
	t.Setenv("HOME", "")
	if _, _, err := PolicyLocation(""); err == nil {
		t.Fatal("PolicyLocation with no home: no error")
	}
	if _, err := Load("", "", ""); err == nil {
		t.Fatal("control: Load with no home succeeded")
	}
}
