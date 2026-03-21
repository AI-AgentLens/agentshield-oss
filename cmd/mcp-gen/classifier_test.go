package main

import (
	"testing"
)

func TestIsShellOnly(t *testing.T) {
	tests := []struct {
		name  string
		regex string
		want  bool
	}{
		// These use regex patterns as they appear AFTER yaml.Unmarshal
		// (YAML `\\s` becomes Go string `\s`).
		{"pipe_in_regex", "(cat|less)\\s+.*\\|.*grep", true},
		{"command_sub_in_regex", "\\$\\(cat /etc/passwd\\)", true},
		{"compound_prefix", "(^|&&|;|\\|\\s*)keyctl\\s+read", true},
		{"keyctl", "keyctl\\s+read", true},
		{"secret-tool", "secret-tool\\s+lookup", true},
		{"ssh-add", "ssh-add\\s+-L", true},
		{"gpg_export", "gpg2?\\s.*--export-secret-keys", true},
		{"vault_read", "vault\\s+read\\s+", true},
		{"gh_auth", "gh\\s+auth\\s+token", true},
		{"gcloud_auth", "gcloud\\s+auth\\s+print-access-token", true},
		{"python_oneliner", "python3\\s+-c", true},
		// These should NOT be flagged as shell-only.
		{"simple_path", "(/etc/shadow|/etc/master\\.passwd)", false},
		{"dotfile_path", ".ssh/id_rsa", false},
		{"metadata_url", "https?://169\\.254\\.169\\.254", false},
		{"chrome_path", "(Google/Chrome|chromium).*/Login", false},
		{"firefox_path", "\\.mozilla/firefox.*key4\\.db", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isShellOnly(tt.regex)
			if got != tt.want {
				t.Errorf("isShellOnly(%q) = %v, want %v", tt.regex, got, tt.want)
			}
		})
	}
}

func TestExtractPaths(t *testing.T) {
	tests := []struct {
		name  string
		regex string
		want  int // minimum number of paths expected
	}{
		{"etc_shadow", `/etc/shadow`, 1},
		{"etc_wireguard", `/etc/wireguard/wg0.conf`, 1},
		{"dot_ssh", `.ssh/id_rsa`, 1},
		{"dot_aws", `.aws/credentials`, 1},
		{"dot_npmrc", `.npmrc`, 1},
		{"no_paths", `^rm -rf`, 0},
		{"metadata_ip", `169.254.169.254`, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := extractPaths(tt.regex)
			if len(paths) < tt.want {
				t.Errorf("extractPaths(%q) got %d paths %v, want >= %d", tt.regex, len(paths), paths, tt.want)
			}
		})
	}
}

func TestCleanRegexPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`/etc/shadow`, "/etc/shadow"},
		{`/etc/master\.passwd`, "/etc/master.passwd"},
		{`/etc/wireguard/wg0\.conf`, "/etc/wireguard/wg0.conf"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := cleanRegexPath(tt.input)
			if got != tt.want {
				t.Errorf("cleanRegexPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsSensitiveDotPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{".ssh/id_rsa", true},
		{".aws/credentials", true},
		{".npmrc", true},
		{".git-credentials", true},
		{".env", true},
		{".config/gcloud/credentials.db", true},
		{".random_dir", false},
		{".gitignore", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isSensitiveDotPath(tt.path)
			if got != tt.want {
				t.Errorf("isSensitiveDotPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestPathSlug(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"~/.ssh/**", "ssh"},
		{"~/.aws/credentials", "aws-credentials"},
		{"/etc/wireguard/wg0.conf", "etc-wireguard-wg0conf"},
		{"~/.npmrc", "npmrc"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := pathSlug(tt.input)
			if got != tt.want {
				t.Errorf("pathSlug(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestTildeToGlob(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"~/.ssh/**", "**/.ssh/**"},
		{"~/.npmrc", "**/.npmrc"},
		{"/etc/shadow", "/etc/shadow"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := tildeToGlob(tt.input)
			if got != tt.want {
				t.Errorf("tildeToGlob(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestClassifyRuleSkipsShellOnly(t *testing.T) {
	// Rules that depend on pipes, shell tools, etc. should not convert.
	shellOnlyRules := []ShellRule{
		{ID: "test-pipe", Match: MatchSpec{CommandRegex: `cat file | grep secret`}},
		{ID: "test-gpg", Match: MatchSpec{CommandRegex: `gpg --export-secret-keys`}},
		{ID: "test-vault", Match: MatchSpec{CommandRegex: `vault read secret/data`}},
	}

	for _, rule := range shellOnlyRules {
		_, ok := classifyRule(rule)
		if ok {
			t.Errorf("expected rule %q to be skipped (shell-only), but it was classified", rule.ID)
		}
	}
}

func TestClassifyRuleConvertsPathRules(t *testing.T) {
	rule := ShellRule{
		ID:       "sec-block-etc-shadow",
		Taxonomy: "credential-exposure/password-db-access/system-shadow-read",
		Match:    MatchSpec{CommandRegex: `(/etc/shadow|/etc/master\.passwd)`},
		Decision: "BLOCK",
		Reason:   "Access to system password database is blocked.",
	}

	c, ok := classifyRule(rule)
	if !ok {
		t.Fatal("expected rule to be classified as convertible")
	}
	if len(c.Paths) == 0 {
		t.Fatal("expected at least one path extracted")
	}
	if c.Decision != "BLOCK" {
		t.Errorf("expected BLOCK decision, got %s", c.Decision)
	}
}
