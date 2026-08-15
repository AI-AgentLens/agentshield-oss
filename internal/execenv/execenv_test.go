package execenv

import "testing"

// fakeEnv returns a getenv closure backed by a map — deterministic, no reliance
// on (or mutation of) the real process environment.
func fakeEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDetect(t *testing.T) {
	cases := []struct {
		name     string
		env      map[string]string
		wantCI   bool
		wantProv string
	}{
		{"empty", map[string]string{}, false, ""},
		{"github-actions", map[string]string{"GITHUB_ACTIONS": "true", "CI": "true"}, true, "github-actions"},
		{"gitlab", map[string]string{"GITLAB_CI": "true", "CI": "true"}, true, "gitlab-ci"},
		{"circleci", map[string]string{"CIRCLECI": "true", "CI": "true"}, true, "circleci"},
		{"buildkite", map[string]string{"BUILDKITE": "true"}, true, "buildkite"},
		{"jenkins", map[string]string{"JENKINS_URL": "https://ci.example/"}, true, "jenkins"},
		{"azure", map[string]string{"TF_BUILD": "True"}, true, "azure-pipelines"},
		{"generic-ci-true", map[string]string{"CI": "true"}, true, "generic"},
		{"generic-ci-1", map[string]string{"CI": "1"}, true, "generic"},
		{"ci-false", map[string]string{"CI": "false"}, false, ""},
		{"ci-empty-string", map[string]string{"CI": ""}, false, ""},
		// A GITHUB_ACTIONS set to a non-truthy value must not report CI.
		{"github-actions-false", map[string]string{"GITHUB_ACTIONS": "false"}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Detect(fakeEnv(tc.env))
			if got.CI != tc.wantCI || got.Provider != tc.wantProv {
				t.Errorf("Detect(%v) = {CI:%v Provider:%q}, want {CI:%v Provider:%q}",
					tc.env, got.CI, got.Provider, tc.wantCI, tc.wantProv)
			}
		})
	}
}

// TestDetect_SpecificProviderWinsOverGeneric pins the ordering guarantee: a
// runner that sets both its own marker and the generic CI flag is reported with
// the specific provider, not "generic".
func TestDetect_SpecificProviderWinsOverGeneric(t *testing.T) {
	got := Detect(fakeEnv(map[string]string{"GITHUB_ACTIONS": "true", "CI": "true"}))
	if got.Provider != "github-actions" {
		t.Errorf("provider = %q, want github-actions", got.Provider)
	}
}
