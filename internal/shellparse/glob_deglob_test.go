package shellparse

import "testing"

// TestDeglobSensitivePaths_Resolves is the core issue-3102 behavior: a
// single unquoted '?'/'*' hiding one interior byte of a well-known sensitive
// path segment must resolve to the literal path, mirroring what a real
// shell's pathname expansion does before the command ever runs.
func TestDeglobSensitivePaths_Resolves(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"etc-shadow-question", "cat /?tc/shadow", "cat /etc/shadow"},
		{"etc-sudoers-question", "echo x > /?tc/sudoers", "echo x > /etc/sudoers"},
		{"ssh-id-rsa-question", "cat ~/.ssh/i?_rsa", "cat ~/.ssh/id_rsa"},
		{"ssh-dir-question", "b64 ~/.?sh/id_rsa", "b64 ~/.ssh/id_rsa"},
		{"aws-credentials-star", "cat ~/.aws/cred*tials", "cat ~/.aws/credentials"},
		{"gnupg-secring-question", "cat ~/.gnupg/secring.?pg", "cat ~/.gnupg/secring.gpg"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeglobSensitivePaths(tc.in)
			found := false
			for _, alt := range got {
				if alt == tc.want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("DeglobSensitivePaths(%q) = %v, want to contain %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestDeglobSensitivePaths_NoFalsePositive guards the "tightly anchored, no
// new false positives" claim from issue #3102: a loose, everyday wildcard
// that doesn't shape-match any known sensitive-path segment must never
// resolve to anything.
func TestDeglobSensitivePaths_NoFalsePositive(t *testing.T) {
	cases := []string{
		"rm -rf build/*",
		"dd if=/dev/zero of=/dev/sd* bs=1M",
		"ls /dev/*",
		"echo *.log",
		"cat notes-2024-??.txt",
		"find . -name '*.tmp' -delete",
		"cp *.go /tmp/",
		"echo no wildcard here at all",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if got := DeglobSensitivePaths(c); got != nil {
				t.Errorf("DeglobSensitivePaths(%q) = %v, want nil (no known sensitive-path shape)", c, got)
			}
		})
	}
}

// TestDeglobSensitivePaths_QuotedIgnored mirrors ExpandBraces/NormalizeIFS:
// pathname expansion never occurs inside quotes, so a quoted wildcard must
// never resolve.
func TestDeglobSensitivePaths_QuotedIgnored(t *testing.T) {
	cases := []string{
		`echo "cat /?tc/shadow is just a string"`,
		`echo 'cat ~/.ssh/i?_rsa is just a string'`,
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if got := DeglobSensitivePaths(c); got != nil {
				t.Errorf("DeglobSensitivePaths(%q) = %v, want nil (quoted wildcard)", c, got)
			}
		})
	}
}

// TestDeglobPath_Resolves is the core issue-3103 behavior: the single-path
// counterpart to DeglobSensitivePaths, for callers (structural/dataflow)
// that already hold an isolated argument string rather than a whole raw
// command — a wildcard masking a block-device directory, a system path, or
// a credential directory must resolve identically.
func TestDeglobPath_Resolves(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"block-device-dev", "/?ev/sda", "/dev/sda"},
		{"etc-passwd-chmod-target", "/?tc/passwd", "/etc/passwd"},
		{"gnupg-secring", "~/.?nupg/secring.gpg", "~/.gnupg/secring.gpg"},
		{"ssh-dir-only", "~/.?sh/", "~/.ssh/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DeglobPath(tc.in); got != tc.want {
				t.Errorf("DeglobPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestDeglobPath_NoFalsePositive mirrors
// TestDeglobSensitivePaths_NoFalsePositive for the single-path form: a
// legitimate wildcard on a device-name SUFFIX (not the "dev" segment
// itself) or any other everyday glob must pass through unchanged.
func TestDeglobPath_NoFalsePositive(t *testing.T) {
	cases := []string{
		"/dev/sd*",
		"build/*",
		"*.log",
		"/dev/*",
		"notes-2024-??.txt",
		"no wildcard here",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if got := DeglobPath(c); got != c {
				t.Errorf("DeglobPath(%q) = %q, want unchanged", c, got)
			}
		})
	}
}
