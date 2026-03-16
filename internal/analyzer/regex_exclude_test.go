package analyzer

import (
	"testing"
)

// TestRegexExcludeSSHPrivate verifies that command_regex_exclude suppresses
// sec-block-ssh-private false positives when SSH paths appear in flag values.
func TestRegexExcludeSSHPrivate(t *testing.T) {
	mainRegex := `\.(ssh|gnupg)/(id_[^.\s"']+([\s"']|$)|private|secret)`
	excludeRegex := `^(echo|printf)\s|--(?:body|message|notes|description|title|annotation|comment)\s+["']?[^"'\n;|&]*\.(?:ssh|gnupg)/|-[mb]\s+["']?[^"'\n;|&]*\.(?:ssh|gnupg)/`

	rule := RegexRule{
		ID:           "sec-block-ssh-private",
		Decision:     "BLOCK",
		Regex:        mainRegex,
		RegexExclude: excludeRegex,
	}

	tests := []struct {
		name    string
		command string
		want    bool // true = should match (BLOCK), false = should be excluded (ALLOW)
	}{
		// True positives — must still fire
		{"cat id_rsa", "cat ~/.ssh/id_rsa", true},
		{"base64 id_rsa", "base64 ~/.ssh/id_rsa", true},
		{"cp id_rsa", "cp ~/.ssh/id_rsa /tmp/", true},
		// False positives — must be suppressed
		{"echo with ssh path", "echo Use ~/.ssh/id_rsa for connections", false},
		{"printf with ssh path", "printf Use ~/.ssh/id_rsa", false},
		{"git commit -m with ssh path", `git commit -m "docs: show ~/.ssh/id_rsa path in README"`, false},
		{"git tag -m with ssh path", `git tag -m "see ~/.ssh/id_rsa"`, false},
		{"gh --body with ssh path", `gh issue create --title "SSH setup" --body "Copy ~/.ssh/id_rsa.pub to the server"`, false},
		{"gh --message with ssh path", `gh pr create --message "uses ~/.ssh/id_rsa"`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchRegexRule(tt.command, rule)
			if got != tt.want {
				t.Errorf("matchRegexRule(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}
