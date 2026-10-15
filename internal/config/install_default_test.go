package config

import (
	"os"
	"path/filepath"
	"testing"
)

// The new-install default (#4337) is rung 4 of the mode resolution: below the
// --mode flag, a local `mode:` line and the SaaS-pushed policy.yaml, above the
// built-in enforce default, and ignored on a managed host. Each row writes the
// files a machine can hold and checks the mode and the rung it came from.
func TestLoad_NewInstallDefaultRung(t *testing.T) {
	const installDefault = "default_mode: audit-only\n"
	cases := []struct {
		name       string
		yaml       string // agentshield.yaml; "" = absent
		policy     string // policy.yaml; "" = absent
		managed    string // managed.json; "" = absent
		flag       string // --mode
		wantMode   string
		wantSource string
	}{
		{
			name:       "install default alone: audit-only",
			yaml:       installDefault,
			wantMode:   ModeAuditOnly,
			wantSource: ModeSourceInstallDefault,
		},
		{
			name:       "no file at all: built-in enforce (every upgraded install)",
			wantMode:   ModeEnforce,
			wantSource: ModeSourceBuiltIn,
		},
		{
			name:       "agentshield.yaml without either key: built-in enforce",
			yaml:       "# nothing set\n",
			wantMode:   ModeEnforce,
			wantSource: ModeSourceBuiltIn,
		},
		{
			name:       "local mode: enforce wins over the install default",
			yaml:       "mode: enforce\n" + installDefault,
			wantMode:   ModeEnforce,
			wantSource: ModeSourceConfigFile,
		},
		{
			name:       "--mode enforce wins over the install default",
			yaml:       installDefault,
			flag:       ModeEnforce,
			wantMode:   ModeEnforce,
			wantSource: ModeSourceFlag,
		},
		{
			name:       "organisation push enforce wins over the install default",
			yaml:       installDefault,
			policy:     "enforcement_mode: \"enforce\"\nrules: []\n",
			wantMode:   ModeEnforce,
			wantSource: ModeSourcePolicyFile,
		},
		{
			name:       "organisation push audit-only is the organisation's, not the install default",
			yaml:       installDefault,
			policy:     "enforcement_mode: \"audit-only\"\nrules: []\n",
			wantMode:   ModeAuditOnly,
			wantSource: ModeSourcePolicyFile,
		},
		{
			name:       "managed host ignores the install default",
			yaml:       installDefault,
			managed:    `{"managed": true, "fail_closed": true}`,
			wantMode:   ModeEnforce,
			wantSource: ModeSourceBuiltIn,
		},
		{
			// No fail_closed: "managed" alone decides, not fail_closed
			// (#4337 review: every managed row set fail_closed, so a check
			// on FailClosed instead of Managed survived).
			name:       "plain managed host (no fail_closed) ignores the install default",
			yaml:       installDefault,
			managed:    `{"managed": true}`,
			wantMode:   ModeEnforce,
			wantSource: ModeSourceBuiltIn,
		},
		{
			name:       "plain managed host follows the organisation push",
			yaml:       installDefault,
			policy:     "enforcement_mode: \"audit-only\"\nrules: []\n",
			managed:    `{"managed": true}`,
			wantMode:   ModeAuditOnly,
			wantSource: ModeSourcePolicyFile,
		},
		{
			name:       "corrupt managed.json reads as managed and ignores the install default",
			yaml:       installDefault,
			managed:    `{not json`,
			wantMode:   ModeEnforce,
			wantSource: ModeSourceBuiltIn,
		},
		{
			name:       "managed.json with managed false is not managed: install default applies",
			yaml:       installDefault,
			managed:    `{"managed": false}`,
			wantMode:   ModeAuditOnly,
			wantSource: ModeSourceInstallDefault,
		},
		{
			name:       "a typo in the install default coerces to enforce",
			yaml:       "default_mode: audit_only\n",
			wantMode:   ModeEnforce,
			wantSource: ModeSourceInstallDefault,
		},
		{
			name:       "unparseable agentshield.yaml: built-in enforce",
			yaml:       "default_mode: [audit-only\n",
			wantMode:   ModeEnforce,
			wantSource: ModeSourceBuiltIn,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			dir := filepath.Join(home, DefaultConfigDir)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{
				DefaultConfigFile: tc.yaml,
				DefaultPolicyFile: tc.policy,
				"managed.json":    tc.managed,
			} {
				if body == "" {
					continue
				}
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := Load("", "", tc.flag)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Mode != tc.wantMode || cfg.ModeSource != tc.wantSource {
				t.Errorf("Load = (%q, %q); want (%q, %q)", cfg.Mode, cfg.ModeSource, tc.wantMode, tc.wantSource)
			}
		})
	}
}
