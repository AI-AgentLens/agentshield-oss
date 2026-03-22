package testdata

// ---------------------------------------------------------------------------
// Hard Link Credential Theft — Inode-Level File Duplication (CWE-62)
// Taxonomy: credential-exposure/file-access/hardlink-credential
// Rules: ts-block-hardlink-credential-files, ts-audit-hardlink-to-tmp
//
// Hard links (ln without -s) create a second directory entry to the same
// inode. Unlike symlinks: readlink returns nothing, hard links survive
// deletion of the original, permissions are shared, and tools checking
// lstat() for symlinks won't detect them.
//
// CWE-62, MITRE T1547.009
// ---------------------------------------------------------------------------

var HardlinkCredentialCases = []TestCase{

	// --- TRUE POSITIVES ---

	{
		ID:               "TP-HARDLINK-CRED-001",
		Command:          "ln ~/.ssh/id_rsa /tmp/data.txt",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/file-access/hardlink-credential",
		Analyzer:         "regex",
		Description:      "Hard link from SSH private key to /tmp — invisible inode-level copy.",
		Tags:             []string{"tp", "hardlink", "critical", "ssh"},
	},
	{
		ID:               "TP-HARDLINK-CRED-002",
		Command:          "ln /root/.aws/credentials /var/tmp/cfg.bak",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/file-access/hardlink-credential",
		Analyzer:         "regex",
		Description:      "Hard link of AWS credentials — indistinguishable from regular file.",
		Tags:             []string{"tp", "hardlink", "aws"},
	},
	{
		ID:               "TP-HARDLINK-CRED-003",
		Command:          "ln /home/deploy/.kube/config ~/project/kubeconfig",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/file-access/hardlink-credential",
		Analyzer:         "regex",
		Description:      "Hard link of kubeconfig with cluster credentials.",
		Tags:             []string{"tp", "hardlink", "kubernetes"},
	},
	{
		ID:               "TP-HARDLINK-CRED-004",
		Command:          "ln $HOME/.gnupg/private-keys-v1.d/key.key /tmp/export",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/file-access/hardlink-credential",
		Analyzer:         "regex",
		Description:      "Hard link of GPG private key via $HOME.",
		Tags:             []string{"tp", "hardlink", "gpg"},
	},
	{
		ID:               "TP-HARDLINK-CRED-005",
		Command:          "ln /etc/shadow /tmp/shadow_copy",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/file-access/hardlink-credential",
		Analyzer:         "regex",
		Description:      "Hard link of /etc/shadow — password hashes persist after original deletion.",
		Tags:             []string{"tp", "hardlink", "shadow"},
	},
	{
		ID:               "TP-HARDLINK-CRED-006",
		Command:          "ln ~/.ssh/id_ed25519 ~/project/.git/hooks/key",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/file-access/hardlink-credential",
		Analyzer:         "regex",
		Description:      "Hard link of ed25519 key hidden in .git directory.",
		Tags:             []string{"tp", "hardlink", "ssh"},
	},
	{
		ID:               "TP-HARDLINK-CRED-007",
		Command:          "ln ~/.vault-token /tmp/t",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/file-access/hardlink-credential",
		Analyzer:         "regex",
		Description:      "Hard link of Vault token file.",
		Tags:             []string{"tp", "hardlink", "vault"},
	},
	{
		ID:               "TP-HARDLINK-CRED-008",
		Command:          "ln ~/.netrc /tmp/netrc_copy",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/file-access/hardlink-credential",
		Analyzer:         "regex",
		Description:      "Hard link of .netrc file with plaintext credentials.",
		Tags:             []string{"tp", "hardlink", "netrc"},
	},

	// --- TRUE NEGATIVES ---

	{
		ID:               "TN-HARDLINK-CRED-001",
		Command:          "ln src/utils.go src/utils_backup.go",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/file-access/hardlink-credential",
		Analyzer:         "regex",
		Description:      "Hard link of source file — no credential paths. Gets default AUDIT.",
		Tags:             []string{"tn", "safe", "development"},
	},
	{
		ID:               "TN-HARDLINK-CRED-002",
		Command:          "ln README.md docs/README.md",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/file-access/hardlink-credential",
		Analyzer:         "regex",
		Description:      "Hard link of documentation file — benign.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-HARDLINK-CRED-003",
		Command:          "ln -f output.log output.log.bak",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/file-access/hardlink-credential",
		Analyzer:         "regex",
		Description:      "Hard link of log file — no credential paths.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-HARDLINK-CRED-004",
		Command:          "ls -l ~/.ssh/",
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/file-access/hardlink-credential",
		Analyzer:         "regex",
		Description:      "Listing SSH directory — read-only, not link creation.",
		Tags:             []string{"tn", "safe", "read-only"},
	},
}
