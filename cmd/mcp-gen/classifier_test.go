package main

import (
	"reflect"
	"strings"
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
		// #3465: env-var-assignment rules ("ENVVAR=<path>") have no MCP
		// tool-call equivalent — the threat requires a LATER command (the
		// dynamic linker, a cloud CLI) to consume the env var. Left
		// unexcluded, these silently defaulted to "path-read" and would emit
		// an MCP BLOCK on *reading* /var/tmp or /var/folders.
		{"ld_preload_export", `export\s+LD_(PRELOAD|LIBRARY_PATH)=(/tmp|/dev/shm|/var/tmp|/proc|/run/user)`, true},
		{"ld_audit_export", `export\s+LD_AUDIT=(/tmp|/dev/shm|/var/tmp|/proc|/run/user)`, true},
		{"cloud_config_env_redirect", `(?:^|[\s;&|])(AWS_CONFIG_FILE|AWS_SHARED_CREDENTIALS_FILE|KUBECONFIG|GOOGLE_APPLICATION_CREDENTIALS|AZURE_CONFIG_DIR|GCLOUD_CONFIG_PATH|CLOUDSDK_CONFIG)\s*=\s*['"]?(?:/tmp/|/var/tmp/|/dev/shm/|/dev/fd/|/proc/self/fd/|\./|\.\./|~/?\.cache/|\$HOME/\.cache/|/var/folders/)\S*\s+\S`, true},
		// #3566: `ln` (symlink/hardlink creation) has no MCP tool
		// equivalent — every MCP tool operates on file content, not
		// filesystem links, so a conversion produces a rule that matches
		// the wrong thing (a read_file call against the bare credential
		// directory) instead of detecting the link-creation threat.
		{"symlink_credential_files", `ln\s+(-[a-zA-Z]*s[a-zA-Z]*\s+|--symbolic\s+)(~|\$HOME|/home/|/root/|/etc/)\S*(\.ssh|\.aws|\.gnupg|\.kube|shadow|passwd|credentials|id_rsa|id_ed25519|known_hosts|authorized_keys|token|secret)`, true},
		{"hardlink_credential_files", `\bln\s+(-[^s\s]*\s+)?(~|\$HOME|/home/|/root/|/etc/)\S*(\.ssh|\.aws|\.gnupg|\.kube|shadow|passwd|credentials|id_rsa|id_ed25519|id_ecdsa|known_hosts|authorized_keys|\.pem|\.key|token|secret|\.vault-token|\.netrc|\.npmrc|\.pypirc)`, true},
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

func TestExtractPathsPreservesEscapedExtension(t *testing.T) {
	// #3375 Group C: the segment matcher's character class excluded `\`, so
	// an escaped-dot extension like `\.m2/settings\.xml` truncated at the
	// backslash and dropped ".xml" — extracting the directory-shaped
	// "/home/*/.m2/settings" instead of the actual file.
	regex := `(cat|less|more|head|tail|bat|vi?|nano|cp|mv)\s+.*(cargo/credentials|\.gem/credentials|\.m2/settings\.xml|gradle\.properties)`
	paths := extractPaths(regex)

	want := "/home/*/.m2/settings.xml"
	found := false
	for _, p := range paths {
		if p == want {
			found = true
		}
		if strings.HasSuffix(p, "/.m2/settings") {
			t.Errorf("extractPaths(%q) produced truncated path %q — missing .xml extension", regex, p)
		}
	}
	if !found {
		t.Errorf("extractPaths(%q) = %v, want it to include %q", regex, paths, want)
	}
}

// TestExtractPathsRecoversMultiAlternationBranches is #3817 finding #1: a
// shared prefix wrapping a parenthesized "(a|b|c)" alternation broke the
// char-class-based extraction patterns at the first "(", so only branches
// that happened to carry zero embedded regex syntax survived — an accident
// of which words were chosen, not a real distinction. All three regexes here
// are the exact source text of real, cited shell rules (see the
// hazardousConversion comment above); before expandAlternations, extraction
// on find-fwrite kept only "/var/root" and "/usr/lib" out of ~9 named
// targets, and on pkgmgr kept only ".m2/settings.xml" out of 4.
func TestExtractPathsRecoversMultiAlternationBranches(t *testing.T) {
	tests := []struct {
		name  string
		regex string
		want  []string
	}{
		{
			name:  "find_fwrite_etc_alternation",
			regex: `\bfind\b.*\s-f(print[f0]?|ls)\s+(/etc/(cron|sudoers|profile|ld\.so)|/root/|/var/root/|/home/[^/\s]+/\.(ssh|aws|gnupg|kube)|~/\.(ssh|aws|gnupg|kube)|/Library/Launch(Daemons|Agents)|/usr/lib/|/proc/sys/)`,
			want: []string{
				"/etc/cron", "/etc/sudoers", "/etc/profile", "/etc/ld.so",
				"/Library/LaunchDaemons", "/Library/LaunchAgents",
				"/proc/sys",
				"/home/*/.ssh", "/home/*/.aws", "/home/*/.gnupg", "/home/*/.kube",
			},
		},
		{
			name:  "pkgmgr_no_leading_dot_branches",
			regex: `(cat|less|more|head|tail|bat|vi?|nano|cp|mv)\s+.*(cargo/credentials|\.gem/credentials|\.m2/settings\.xml|gradle\.properties)`,
			want: []string{
				"/home/*/.cargo/credentials",
				"/home/*/.gem/credentials",
				"/home/*/.m2/settings.xml",
				"/home/*/.gradle/gradle.properties",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := extractPaths(tt.regex)
			for _, w := range tt.want {
				found := false
				for _, p := range paths {
					if p == w {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("extractPaths(%q) = %v, missing branch %q", tt.regex, paths, w)
				}
			}
		})
	}
}

// TestExtractPathsDoesNotEmitGroupTruncatedMatch pins matchTruncatedByGroup:
// expandAlternations always retries the fully-unexpanded original regex
// alongside its flattened variants, so a match can still land right next to
// an unexpanded "(" (e.g. "/Library/Launch" stopping dead at
// "(Daemons|Agents)"). That fragment is not a real path — it must not appear
// in the output — while the two REAL targets the group expands to must still
// be present.
func TestExtractPathsDoesNotEmitGroupTruncatedMatch(t *testing.T) {
	regex := `/Library/Launch(Daemons|Agents)`
	paths := extractPaths(regex)

	for _, p := range paths {
		if p == "/Library/Launch" {
			t.Errorf("extractPaths(%q) = %v, contains truncated fragment %q", regex, paths, p)
		}
	}
	for _, want := range []string{"/Library/LaunchDaemons", "/Library/LaunchAgents"} {
		found := false
		for _, p := range paths {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("extractPaths(%q) = %v, missing %q", regex, paths, want)
		}
	}
}

func TestExpandAlternations(t *testing.T) {
	tests := []struct {
		name  string
		regex string
		want  []string // exact set, order-independent
	}{
		{
			name:  "no_groups_returns_original_only",
			regex: `/etc/shadow`,
			want:  []string{`/etc/shadow`},
		},
		{
			name:  "single_group_expands_to_one_variant_per_branch",
			regex: `/etc/(cron|sudoers)`,
			want:  []string{`/etc/(cron|sudoers)`, `/etc/cron`, `/etc/sudoers`},
		},
		{
			name:  "non_capturing_prefix_stripped",
			regex: `/etc/(?:cron|sudoers)`,
			want:  []string{`/etc/(?:cron|sudoers)`, `/etc/cron`, `/etc/sudoers`},
		},
		{
			name: "sibling_groups_expand_independently_not_cartesian",
			// Two 2-branch groups: a full cartesian product would be 4
			// combined variants; one-group-at-a-time produces 2+2=4 partial
			// variants plus the original — 5 total, each with only ONE
			// group flattened.
			regex: `(a|b)-(c|d)`,
			want:  []string{`(a|b)-(c|d)`, `a-(c|d)`, `b-(c|d)`, `(a|b)-c`, `(a|b)-d`},
		},
		{
			name:  "bracket_class_pipe_not_a_group_split",
			regex: `(?:^|[;&|])cmd`,
			want:  []string{`(?:^|[;&|])cmd`, `^cmd`, `[;&|]cmd`},
		},
		{
			name:  "group_with_no_pipe_is_left_untouched",
			regex: `/etc/(shadow)`,
			want:  []string{`/etc/(shadow)`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandAlternations(tt.regex)
			gotSet := map[string]bool{}
			for _, g := range got {
				gotSet[g] = true
			}
			wantSet := map[string]bool{}
			for _, w := range tt.want {
				wantSet[w] = true
			}
			if !reflect.DeepEqual(gotSet, wantSet) {
				t.Errorf("expandAlternations(%q) = %v, want set %v", tt.regex, got, tt.want)
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
		// A bare optional character must widen to a glob wildcard, not
		// vanish and leave the character mandatory — dropping just the `?`
		// from "authorized_keys2?" left "authorized_keys2" as the ONLY
		// match, narrowing coverage to the rarely-used spelling (#3375).
		{`\.ssh/authorized_keys2?`, ".ssh/authorized_keys2*"},
		// A `?` left behind after an entire alternation group is removed
		// (no group content survives to widen) is still dropped cleanly.
		{`\.terraform(\.d)?`, ".terraform*"},
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
		{".env.local", true},
		{".envrc", true},
		{".config/gcloud/credentials.db", true},
		{".random_dir", false},
		{".gitignore", false},
		// ".env" is a prefix of ".environ" (Python's os.environ, matched
		// incidentally by an unrelated code-pattern rule's `os\.environ\.get\(`
		// text), but ".environ" is not a file — a bare prefix match with no
		// segment/extension boundary false-extracted it as a candidate MCP
		// path (#3375 Group C).
		{".environ", false},
		{".environment", false},
		// Same shape: ".docker" must not swallow ".dockerignore".
		{".dockerignore", false},
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
		want  []string
	}{
		{"~/.ssh/**", []string{"/home/*/.ssh/**", "/root/.ssh/**", "/var/root/.ssh/**", "/Users/*/.ssh/**", "C:/Users/*/.ssh/**"}},
		{"~/.npmrc", []string{"/home/*/.npmrc", "/root/.npmrc", "/var/root/.npmrc", "/Users/*/.npmrc", "C:/Users/*/.npmrc"}},
		{"/etc/shadow", []string{"/etc/shadow"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := tildeToGlob(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("tildeToGlob(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestTildeToGlobNeverUnanchored guards the #3354 fix class-wide: every
// tilde-prefixed protected path must expand to real home-directory roots,
// never a bare **/<path> glob that also matches project-relative dotfiles.
func TestTildeToGlobNeverUnanchored(t *testing.T) {
	samples := []string{
		"~/.ssh/**", "~/.aws/**", "~/.docker/config.json", "~/.netrc",
		"~/.config/gh/**", "~/.vault-token", "~/.terraform.d/**",
		"~/.pip/**", "~/.config/pip/**", "~/.cargo/config.toml", "~/.m2/settings.xml",
	}
	for _, s := range samples {
		for _, g := range tildeToGlob(s) {
			if strings.HasPrefix(g, "**/") {
				t.Errorf("tildeToGlob(%q) produced unanchored glob %q — matches any project directory, not just a real home dir", s, g)
			}
		}
	}
}

func TestClassifyPathCategory(t *testing.T) {
	tests := []struct {
		name  string
		regex string
		want  string
	}{
		{
			// #3375 Group C: `cat` here is the redirect's data SOURCE, not
			// an operation on /etc/hosts — the rule's own TN (`cat /etc/hosts`)
			// proves reading must stay outside this rule's scope.
			name:  "redirect_source_read_verb_is_not_a_read",
			regex: `(echo|printf|cat)\b.*(>>|>)\s*/etc/hosts\b|\btee\b.*\s/etc/hosts\b`,
			want:  "config-write",
		},
		{
			// No redirect operator at all — every verb (read or ambiguous
			// write-word) applies directly to the credential path, so this
			// must still resolve to the broader readwrite category exactly
			// as before the fix (no regression for non-redirect rules).
			name:  "no_redirect_operator_keeps_readwrite",
			regex: `(cat|less|more|head|tail|bat|vi?|nano|cp|mv)\s+.*(cargo/credentials|\.gem/credentials|\.m2/settings\.xml|gradle\.properties)`,
			want:  "path-readwrite",
		},
		{
			// A genuine two-branch read-OR-write rule (distinct branches,
			// one pure read, one redirect write) must keep classifying as
			// readwrite — the fix must not collapse this into write-only.
			name:  "distinct_read_and_write_branches_stay_readwrite",
			regex: `(cat|less)\s+/etc/example\b|echo\b.*>\s*/etc/example\b`,
			want:  "path-readwrite",
		},
		{
			name:  "pure_read_no_write_signal",
			regex: `\bcat\b\s+/etc/shadow\b`,
			want:  "path-read",
		},
		{
			// #3465: chflags clearing an immutable flag is a file-attribute
			// WRITE, but contains no redirect operator, write-word, or read
			// verb — it silently defaulted to "path-read" (an MCP BLOCK on
			// *reading* /var/log, /var/root, a busy path with no read risk).
			name:  "chflags_clear_immutable_is_write",
			regex: `(?:^|[\s|;&])(?:sudo\s+)?chflags\s+(?:-[a-zA-Z]+\s+)*(?:noschg|nouchg|nosappnd|nouappnd|nosimmutable|nouimmutable)\b\s+(?:-[a-zA-Z]+\s+)*(?:/etc/|/usr/|/bin/|/sbin/|/System/|/private/etc/|/private/var/db/|/var/log/|/var/db/|/var/root/|/Library/LaunchDaemons/|/Library/LaunchAgents/|/Library/Preferences/|/Library/StartupItems/|/Library/PrivilegedHelperTools/)`,
			want:  "config-write",
		},
		{
			// #3465: find -fprintf/-fprint/-fprint0/-fls write directly to
			// the operand path with no shell redirect operator — the whole
			// point of the source rule's reason text. Same silent
			// path-read default as chflags above.
			name:  "find_fwrite_flags_are_write",
			regex: `\bfind\b.*\s-f(print[f0]?|ls)\s+(/etc/(cron|sudoers|profile|ld\.so)|/root/|/var/root/|/home/[^/\s]+/\.(ssh|aws|gnupg|kube)|~/\.(ssh|aws|gnupg|kube)|/Library/Launch(Daemons|Agents)|/usr/lib/|/proc/sys/)`,
			want:  "config-write",
		},
		{
			// #3589: the live regex from sec-audit-ai-cred-files. An
			// interactive editor opens the path for BOTH directions, but
			// `vi?`/`nano` were in neither verb list, so this defaulted to
			// "path-read" and shipped an MCP rule with read tools only.
			name:  "editor_verb_is_read_and_write",
			regex: `(cat|less|more|head|tail|bat|vi?|nano)\s+.*(\.config/(openai|anthropic|google|gemini|cohere|mistral)|\.openai|\.anthropic)`,
			want:  "path-readwrite",
		},
		{
			// An editor alone, with no read verb anywhere, must still reach
			// readwrite — the write half is the point.
			name:  "editor_alone_is_read_and_write",
			regex: `\b(vim|nvim|nano|emacs)\b\s+.*/home/[^/\s]+/\.aws/credentials`,
			want:  "path-readwrite",
		},
		{
			// NEGATIVE CONTROL. `view` is vim's read-only mode and is
			// deliberately absent from editVerbRe: treating it as a write
			// would hand write-family tools to a rule whose source regex
			// cannot write. If editVerbRe is ever loosened to `vi\w*`, this
			// is the test that catches it.
			name:  "vim_readonly_view_mode_is_not_a_write",
			regex: `\b(view|rview)\b\s+/etc/shadow\b`,
			want:  "path-read",
		},
		{
			// NEGATIVE CONTROL. A read verb that merely CONTAINS an editor
			// name as a substring must not trip the word-boundary match.
			name:  "editor_name_as_substring_is_not_an_editor",
			regex: `\b(cat|editor_log|nanosecond_dump|vimrc_dump)\b\s+/etc/shadow\b`,
			want:  "path-read",
		},
		{
			// An editor inside a redirect branch is the redirect's data
			// source, exactly like a read verb — the branch is still a
			// write to the path and nothing more. Pins that the editor
			// check sits AFTER the redirect short-circuit.
			name:  "editor_in_redirect_branch_stays_write_only",
			regex: `(echo|vi)\b.*(>>|>)\s*/etc/hosts\b`,
			want:  "config-write",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyPathCategory(tt.regex)
			if got != tt.want {
				t.Errorf("classifyPathCategory(%q) = %q, want %q", tt.regex, got, tt.want)
			}
		})
	}
}

func TestSplitTopLevelAlternation(t *testing.T) {
	tests := []struct {
		name  string
		regex string
		want  []string
	}{
		{
			name:  "group_internal_alternation_not_split",
			regex: `(echo|printf|cat)\b.*/etc/hosts\b`,
			want:  []string{`(echo|printf|cat)\b.*/etc/hosts\b`},
		},
		{
			name:  "top_level_alternation_splits",
			regex: `\bcat\b\s+/etc/example\b|\btee\b.*\s/etc/example\b`,
			want:  []string{`\bcat\b\s+/etc/example\b`, `\btee\b.*\s/etc/example\b`},
		},
		{
			name:  "mixed_nested_and_top_level",
			regex: `(echo|printf|cat)\b.*(>>|>)\s*/etc/hosts\b|\btee\b.*\s/etc/hosts\b`,
			want:  []string{`(echo|printf|cat)\b.*(>>|>)\s*/etc/hosts\b`, `\btee\b.*\s/etc/hosts\b`},
		},
		{
			name:  "escaped_paren_is_literal_not_a_group",
			regex: `foo\(bar\)|baz`,
			want:  []string{`foo\(bar\)`, `baz`},
		},
		{
			// A `|` inside a bracket character class is a literal
			// alternative character, not a split point — sc-block-pypirc-edit
			// (#3375) has exactly this shape: `[^;&|\n\r]*` after the real
			// alternation group closes, at nominal paren-depth 0.
			name:  "pipe_inside_bracket_class_is_not_a_split_point",
			regex: `(?:^|[;&|])(echo|cat)[^;&|\n\r]*\.pypirc`,
			want:  []string{`(?:^|[;&|])(echo|cat)[^;&|\n\r]*\.pypirc`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitTopLevelAlternation(tt.regex)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitTopLevelAlternation(%q) = %#v, want %#v", tt.regex, got, tt.want)
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

// TestClassifyProtectedPathsExcludesWriteWhenCoveredElsewhere pins #3735's
// fix: a protected_paths entry listed in writeCoveredElsewhere must be
// classified with ReadDeleteTools (no write-family tools), because a
// dedicated write-taxonomy rule already covers writes to that path
// elsewhere. An ordinary protected path not in the map must still get the
// full AllFileTools set — this must not become a blanket narrowing.
func TestClassifyProtectedPathsExcludesWriteWhenCoveredElsewhere(t *testing.T) {
	pack := &ShellPack{
		Defaults: Defaults{
			ProtectedPaths: []string{
				"~/.m2/settings.xml",  // covered elsewhere — must exclude write
				"~/.some-other-thing", // not covered — must keep full coverage
			},
		},
	}

	candidates := classifyProtectedPaths(pack)
	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(candidates))
	}

	byPath := map[string]Candidate{}
	for _, c := range candidates {
		byPath[c.SourceRule.ID] = c
	}

	m2, ok := byPath["protected-path-m2-settingsxml"]
	if !ok {
		t.Fatalf("expected a candidate for ~/.m2/settings.xml, got IDs: %v", keysOf(byPath))
	}
	for _, wt := range WriteTools {
		if containsStr(m2.ToolNames, wt) {
			t.Errorf("~/.m2/settings.xml candidate must not include write tool %q (write is covered by mcp-sc-block-pkgmgr-config-write), got %v", wt, m2.ToolNames)
		}
	}
	for _, rt := range append(append([]string{}, ReadTools...), DeleteTools...) {
		if !containsStr(m2.ToolNames, rt) {
			t.Errorf("~/.m2/settings.xml candidate must still include %q, got %v", rt, m2.ToolNames)
		}
	}

	var other Candidate
	found := false
	for _, c := range candidates {
		if len(c.Paths) > 0 && strings.Contains(c.Paths[0], "some-other-thing") {
			other = c
			found = true
		}
	}
	if !found {
		t.Fatal("expected a candidate for ~/.some-other-thing")
	}
	for _, wt := range WriteTools {
		if !containsStr(other.ToolNames, wt) {
			t.Errorf("an ordinary protected path not in writeCoveredElsewhere must keep write tool %q, got %v", wt, other.ToolNames)
		}
	}
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func keysOf(m map[string]Candidate) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
