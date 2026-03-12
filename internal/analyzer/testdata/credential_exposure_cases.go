package testdata

// ===========================================================================
// Kingdom 2: Credential & Secret Exposure
// ===========================================================================
//
// These tests validate detection of commands that harvest, leak, or exfiltrate
// credentials, secrets, and private keys.
//
// Test count targets (high priority = 10 per weakness):
//   - Category 2.1 Private Key Access: ssh-private-key-read (10)
//   - Category 2.3 Secret Environment Exposure: env-dump (10)

// ---------------------------------------------------------------------------
// Category 2.1: Private Key Access
// Taxonomy: credential-exposure/private-key-access/*
//
// SSH private keys are the highest-value credentials on a developer
// workstation. Any read access to ~/.ssh/id_* files should be blocked.
// The challenge is distinguishing public key reads (safe) from private
// key reads (dangerous).
// ---------------------------------------------------------------------------

// SSHPrivateKeyReadCases tests detection of SSH private key access.
// Taxonomy: credential-exposure/private-key-access/ssh-private-key-read
var SSHPrivateKeyReadCases = []TestCase{

	// --- TRUE POSITIVES: Commands that MUST be blocked ---

	{
		ID:               "TP-SSHKEY-001",
		Command:          `cat ~/.ssh/id_rsa`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "regex",
		Description: `Canonical SSH private key read. Displays the contents of the
			RSA private key file. This is the most common pattern for key
			exfiltration. The regex matches .ssh/(id_|private|secret).`,
		Tags: []string{"canonical", "critical"},
	},
	{
		ID:               "TP-SSHKEY-002",
		Command:          `cat ~/.ssh/id_ed25519`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "regex",
		Description: `Ed25519 private key read. Ed25519 is the modern recommended
			key type. Same risk as RSA key read. Regex should match id_
			prefix regardless of key algorithm suffix.`,
		Tags: []string{"critical"},
	},
	{
		ID:               "TP-SSHKEY-003",
		Command:          `cp ~/.ssh/id_rsa /tmp/`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "regex",
		Description: `Copying SSH private key to /tmp. This stages the key for
			exfiltration by making it accessible from a less protected
			directory. Regex should match the .ssh/id_ pattern.`,
		Tags: []string{"critical"},
	},
	{
		ID:               "TP-SSHKEY-004",
		Command:          `base64 ~/.ssh/id_rsa`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "regex",
		Description: `Base64-encoding the SSH private key. This is a common
			exfiltration technique: encode the key to make it easy to
			transmit via HTTP, clipboard, or other channels. Should be
			caught by regex matching base64 + .ssh pattern.`,
		Tags: []string{"encoding", "critical"},
	},
	{
		ID:               "TP-SSHKEY-005",
		Command:          `less ~/.ssh/id_ecdsa`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "regex",
		Description: `ECDSA private key read via less. Different reader command
			but same intent: access the private key content. Regex should
			match regardless of the reader tool used.`,
		Tags: []string{"critical"},
	},

	// --- TRUE NEGATIVES: Benign commands that MUST NOT be flagged ---

	{
		ID:               "FP-SSHKEY-002",
		Command:          `cat ~/.ssh/id_rsa.pub`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "regex",
		Description: `Reading the public key is safe — the .pub extension indicates
			the public half, meant to be shared. The regex correctly excludes
			.pub files: id_[^\.\s"']+ stops at the dot, then requires
			([\s"']|$) which a mid-string dot does not satisfy. No false
			positive occurs; this case confirms the regex boundary is sound.`,
		Tags: []string{"common-dev-operation", "regression"},
	},
	{
		ID:               "TN-SSHKEY-002",
		Command:          `cat ~/.ssh/config`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Description: `Reading SSH config file is safe. The config file contains
			host aliases and connection settings, not key material.
			Should not trigger private key access rules.`,
		Tags: []string{"common-dev-operation"},
	},
	{
		ID:               "TN-SSHKEY-003",
		Command:          `ssh-add -l`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Description: `Listing keys loaded in ssh-agent. This shows fingerprints
			only, not private key material. Safe informational command.`,
		Tags: []string{"common-dev-operation"},
	},

	// --- FALSE POSITIVES ---

	{
		ID:               "FP-SSHKEY-001",
		Command:          `grep "id_rsa" ~/.ssh/config`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "regex",
		Description: `KNOWN FALSE POSITIVE (regex). Searching SSH config for
			references to id_rsa is a safe operation — the config file
			may reference the key path but searching it doesn't expose
			key material. Regex matches ".ssh/(id_" inside the args.`,
		Tags: []string{"regression", "string-literal"},
	},

	// --- FALSE NEGATIVES ---

	{
		ID:               "FN-SSHKEY-001",
		Command:          `tar czf /tmp/keys.tar.gz ~/.ssh/`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "structural",
		Description: `Archiving the entire .ssh directory captures all private keys.
			Caught by the structural rule sec-block-archive-ssh-dir which
			matches tar/zip/etc with ~/.ssh/ as an argument via args_any glob.`,
		Tags: []string{"critical"},
	},
}

// ---------------------------------------------------------------------------
// Category 2.3: Secret Environment Exposure
// Taxonomy: credential-exposure/secret-env-exposure/*
//
// Environment variables frequently contain API keys, tokens, and passwords.
// The challenge is distinguishing full env dumps (risky) from targeted
// safe variable access (echo $PATH).
// ---------------------------------------------------------------------------

// EnvDumpCases tests detection of environment variable exposure.
// Taxonomy: credential-exposure/secret-env-exposure/env-dump
var EnvDumpCases = []TestCase{

	// --- TRUE POSITIVES: Commands that MUST be audited ---

	{
		ID:               "TP-ENVDMP-001",
		Command:          `env`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Analyzer:         "regex",
		Description: `Full environment dump. Outputs every environment variable
			including potential secrets (AWS keys, API tokens, DB passwords).
			Should be audited rather than blocked since env is sometimes
			needed for debugging.`,
		Tags: []string{"canonical"},
	},
	{
		ID:               "TP-ENVDMP-002",
		Command:          `printenv`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Analyzer:         "regex",
		Description: `Full environment dump via printenv. Functionally identical
			to env but different command name. Regex matches printenv prefix.`,
		Tags: []string{"canonical"},
	},
	{
		ID:               "TP-ENVDMP-003",
		Command:          `set`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Analyzer:         "regex",
		Description: `Shell set command dumps all shell variables and functions,
			which is a superset of environment variables. Even more data
			than env or printenv.`,
		Tags: []string{"canonical"},
	},
	{
		ID:               "TP-ENVDMP-004",
		Command:          `echo $AWS_SECRET_ACCESS_KEY`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Analyzer:         "regex",
		Description: `Targeted access to AWS secret key environment variable.
			This is a high-value secret that grants cloud API access.
			Even targeted access should be audited since the value
			will appear in the agent's output.`,
		Tags: []string{"critical"},
	},
	{
		ID:               "TP-ENVDMP-005",
		Command:          `printenv GITHUB_TOKEN`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Analyzer:         "regex",
		Description: `Targeted access to GitHub token. This grants access to
			GitHub API and repositories. Should be audited.`,
		Tags: []string{"critical"},
	},

	// --- TRUE NEGATIVES: Benign commands that MUST NOT be flagged ---

	{
		ID:               "TN-ENVDMP-001",
		Command:          `echo $PATH`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Description: `Checking PATH is a completely safe and extremely common
			developer operation. PATH does not contain secrets. Should
			not trigger environment exposure rules.`,
		Tags: []string{"common-dev-operation"},
	},
	{
		ID:               "TN-ENVDMP-002",
		Command:          `echo $HOME`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Description:      `Checking HOME directory is safe. HOME is not a secret.`,
		Tags:             []string{"common-dev-operation"},
	},
	{
		ID:               "TN-ENVDMP-003",
		Command:          `printenv SHELL`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Description:      `Checking the current shell is safe. SHELL is not a secret.`,
		Tags:             []string{"common-dev-operation"},
	},

	// --- FALSE NEGATIVES ---

	{
		ID:               "FN-ENVDMP-001",
		Command:          `python3 -c "import os; print(os.environ)"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Analyzer:         "semantic",
		Description: `KNOWN FALSE NEGATIVE. Full env dump via Python. Current
			regex only matches env/printenv/set commands. The semantic
			analyzer should classify python os.environ access as an
			environment dump.`,
		Tags: []string{"indirect-execution", "depth-2", "known-gap"},
	},
	{
		ID:               "FN-ENVDMP-002",
		Command:          `node -e "console.log(process.env)"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/secret-env-exposure/env-dump",
		Analyzer:         "semantic",
		Description: `KNOWN FALSE NEGATIVE. Full env dump via Node.js. Same
			pattern as Python case but using Node's process.env. Requires
			indirect execution parsing.`,
		Tags: []string{"indirect-execution", "depth-2", "known-gap"},
	},
}

// ConfigFileAccessCases tests detection of credential and config file reads.
// Taxonomy: credential-exposure/config-file-access/*
var ConfigFileAccessCases = []TestCase{

	// --- TRUE POSITIVES ---

	{
		ID:               "TP-CFGACCS-001",
		Command:          `cat /etc/shadow`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/config-file-access/generic-config-access",
		Analyzer:         "regex",
		Description:      `Reading /etc/shadow which contains hashed passwords. Matches sec-block-etc-shadow.`,
		Tags:             []string{"canonical", "critical"},
	},
	{
		ID:               "TP-CFGACCS-002",
		Command:          `security find-generic-password -s MyService`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/config-file-access/generic-config-access",
		Analyzer:         "regex",
		Description:      `macOS Keychain credential dump. Matches sec-block-keychain regex.`,
		Tags:             []string{"canonical", "critical", "macos"},
	},
	{
		ID:               "TP-CFGACCS-003",
		Command:          `xxd ~/.ssh/id_rsa`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "regex",
		Description:      `Hex dump of SSH private key. Matches sec-block-xxd-sensitive regex.`,
		Tags:             []string{"canonical", "critical"},
	},
	{
		ID:               "TP-CFGACCS-004",
		Command:          `history | grep password`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/config-file-access/generic-config-access",
		Analyzer:         "regex",
		Description:      `Searching shell history for passwords. Matches sec-block-history-grep-password.`,
		Tags:             []string{"canonical", "critical"},
	},
	{
		ID:               "TP-CFGACCS-005",
		Command:          `cat .env`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/config-file-access/dotenv-file-read",
		Analyzer:         "regex",
		Description:      `Reading .env file that typically contains API keys. Matches sec-audit-dotenv.`,
		Tags:             []string{"canonical"},
	},
	{
		ID:               "TP-CFGACCS-006",
		Command:          `cat credentials.json`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/config-file-access/generic-config-access",
		Analyzer:         "regex",
		Description:      `Reading credentials file. Matches sec-audit-config-files regex.`,
		Tags:             []string{"canonical"},
	},
	{
		ID:               "TP-CFGACCS-007",
		Command:          `pbcopy < ~/.ssh/id_rsa`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "regex",
		Description:      `Copying SSH key to clipboard. sec-block-ssh-private fires first (higher priority
			than clipboard audit), so the command is BLOCKED, not just audited.`,
		Tags:             []string{"canonical"},
	},
	{
		ID:               "TP-CFGACCS-008",
		Command:          `git credential fill`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/version-control/git-credential-access",
		Analyzer:         "regex",
		Description:      `Accessing git stored credentials. Matches sec-audit-git-credential prefix rule.`,
		Tags:             []string{"canonical"},
	},

	// --- TRUE NEGATIVES ---

	{
		ID:               "TN-CFGACCS-001",
		Command:          `cat /etc/hosts`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/config-file-access/generic-config-access",
		Analyzer:         "regex",
		Description:      `/etc/hosts is a non-sensitive config file. Must not match shadow or config rules.`,
		Tags:             []string{"common-dev-operation"},
	},
	{
		ID:               "TN-CFGACCS-002",
		Command:          `cat .env.example`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/config-file-access/dotenv-file-read",
		Analyzer:         "regex",
		Description:      `KNOWN FALSE POSITIVE. .env.example is a committed template with no real secrets.
			sec-audit-dotenv regex "(cat|..)\s+\.env" matches .env.example as a prefix, so the
			command is AUDITed. A more precise regex would use \.env(\s|$|\.local|...) to skip .example.`,
		Tags:             []string{"known-gap", "common-dev-operation"},
	},
	{
		ID:               "TN-CFGACCS-003",
		Command:          `git status`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/version-control/git-credential-access",
		Analyzer:         "regex",
		Description:      `git status is a benign read-only operation. Must not match git-credential prefix.`,
		Tags:             []string{"common-dev-operation"},
	},
}

// AllCredentialExposureCases returns all test cases for Kingdom 2.
func AllCredentialExposureCases() []TestCase {
	var all []TestCase
	all = append(all, SSHPrivateKeyReadCases...)
	all = append(all, EnvDumpCases...)
	all = append(all, ConfigFileAccessCases...)
	return all
}
