package testdata

// EvalAndFlagBeforeCCases cover issue #3059 — two carriers of shell source
// that the analyzer never reached, measured at 34%+ leak rates over the
// corpus of commands that BLOCK today (on main at 0c64518c, i.e. AFTER
// #3050/#3052 already fixed the plain `bash -c`/`sh -c` case):
//
//  1. `eval` was not treated as an inline-code carrier at all — absent from
//     ExtractInlineCode, InlineCodeFragments, and walkStmt's recursion — even
//     though it is the most direct inline-code carrier there is: unlike an
//     interpreter, it takes no options, so every argument IS the source.
//  2. A value-taking flag before `-c` (`bash -O expand_aliases -c '...'`,
//     `bash --rcfile /tmp/x -c '...'`) defeated #3052's fix, because
//     ExtractInlineCode read the payload from seg.Args[0] — the first
//     POSITIONAL argument — rather than the argument that follows the token
//     carrying "c". Bucketing into Flags/Args loses position, so an earlier
//     value-taking flag shifts Args[0] onto that flag's value instead of the
//     real payload.
//
// Both TP groups below use ts-block-mkfs and ts-block-dd-zero — the same
// pair the issue itself measured with (`mkfs.ext4`, `dd if=/dev/zero`) —
// wrapped in the two previously-uncovered carrier shapes. The TN group covers
// eval's extremely common legitimate use wrapping a command substitution
// (`eval "$(ssh-agent -s)"` and friends), which must not escalate.
var EvalAndFlagBeforeCCases = []TestCase{
	// --- TP: eval as a direct inline-code carrier -------------------------
	{
		ID:               "TP-EVALCARRIER-001",
		Command:          "eval 'mkfs.ext4 /dev/sda1'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/filesystem-format",
		Analyzer:         "pipeline",
		Description:      "eval wrapping a single-quoted destructive command — eval takes no options, so the argument IS the shell source.",
		Tags:             []string{"tp", "destructive", "eval", "inline-code"},
	},
	{
		ID:               "TP-EVALCARRIER-002",
		Command:          `eval "dd if=/dev/zero of=/dev/sda bs=1M"`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/disk-overwrite",
		Analyzer:         "pipeline",
		Description:      "eval wrapping a double-quoted destructive command.",
		Tags:             []string{"tp", "destructive", "eval", "inline-code"},
	},
	{
		ID:               "TP-EVALCARRIER-003",
		Command:          "eval mkfs.ext4 /dev/sda1",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/filesystem-format",
		Analyzer:         "pipeline",
		Description:      "eval with NO quoting at all — bash concatenates eval's argv with a space before re-parsing, so the unquoted form must resolve identically to the quoted one.",
		Tags:             []string{"tp", "destructive", "eval", "inline-code"},
	},
	{
		ID:               "TP-EVALCARRIER-004",
		Command:          "eval 'mkfs' '.ext4' '/dev/sda1'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/filesystem-format",
		Analyzer:         "pipeline",
		Description:      "eval given several separately-quoted words — each is a complete shell word individually, joined with a space before re-parsing, exactly like eval itself does with argv.",
		Tags:             []string{"tp", "destructive", "eval", "inline-code"},
	},
	{
		ID:               "TP-EVALCARRIER-005",
		Command:          "cd /tmp && eval 'dd if=/dev/zero of=/dev/sda bs=1M'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/disk-overwrite",
		Analyzer:         "pipeline",
		Description:      "eval-carrier form chained after a benign cd — the eval-compound shape the issue measured at 34.3%.",
		Tags:             []string{"tp", "destructive", "eval", "inline-code"},
	},

	// --- TP: value-taking flag before -c -----------------------------------
	{
		ID:               "TP-CFLAGPOS-001",
		Command:          "bash -O expand_aliases -c 'mkfs.ext4 /dev/sda1'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/filesystem-format",
		Analyzer:         "pipeline",
		Description:      "A shopt-style flag with a value sits before -c. The payload must be read positionally (the word after the c-bearing token), not from Args[0].",
		Tags:             []string{"tp", "destructive", "inline-code"},
	},
	{
		ID:               "TP-CFLAGPOS-002",
		Command:          "bash --rcfile /tmp/x -c 'dd if=/dev/zero of=/dev/sda bs=1M'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/disk-overwrite",
		Analyzer:         "pipeline",
		Description:      "A long flag with a separate value token (--rcfile /tmp/x) sits before -c, same failure mode with a long-flag shape.",
		Tags:             []string{"tp", "destructive", "inline-code"},
	},
	{
		ID:               "TP-CFLAGPOS-003",
		Command:          "sh -o pipefail -c 'mkfs.ext4 /dev/sda1'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/filesystem-format",
		Analyzer:         "pipeline",
		Description:      "sh -o pipefail (a value-taking flag) before -c.",
		Tags:             []string{"tp", "destructive", "inline-code"},
	},
	{
		ID:               "TP-CFLAGPOS-004",
		Command:          "sh -ec 'mkfs.ext4 /dev/sda1'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/filesystem-format",
		Analyzer:         "pipeline",
		Description:      "Combined short-flag cluster '-ec' (errexit + inline-code) — must still resolve the payload, this shape was already correct and must not regress.",
		Tags:             []string{"tp", "destructive", "inline-code"},
	},

	// --- TN: eval's extremely common legitimate use -------------------------
	{
		ID:               "TN-EVALCARRIER-001",
		Command:          `eval "$(ssh-agent -s)"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/disk-ops/filesystem-format",
		Analyzer:         "pipeline",
		Description:      "Standard ssh-agent shell setup — a command substitution, not a literal destructive command; must not escalate now that eval is analyzed.",
		Tags:             []string{"tn", "safe", "eval"},
	},
	{
		ID:               "TN-EVALCARRIER-002",
		Command:          `eval "$(direnv hook bash)"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/disk-ops/filesystem-format",
		Analyzer:         "pipeline",
		Description:      "Standard direnv shell hook — same shape, different tool.",
		Tags:             []string{"tn", "safe", "eval"},
	},
	{
		ID:               "TN-EVALCARRIER-003",
		Command:          `eval "$(rbenv init -)"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/disk-ops/filesystem-format",
		Analyzer:         "pipeline",
		Description:      "Standard rbenv shell init.",
		Tags:             []string{"tn", "safe", "eval"},
	},
	{
		ID:               "TN-EVALCARRIER-004",
		Command:          `eval "$(minikube docker-env)"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/disk-ops/filesystem-format",
		Analyzer:         "pipeline",
		Description:      "Standard minikube docker-env wiring.",
		Tags:             []string{"tn", "safe", "eval"},
	},
	{
		ID:               "TN-CFLAGPOS-001",
		Command:          "bash -O expand_aliases -c 'go test ./...'",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/disk-ops/filesystem-format",
		Analyzer:         "pipeline",
		Description:      "Same wrapper shape running an ordinary benign test command — the fix must not escalate benign -c payloads just because a flag preceded -c.",
		Tags:             []string{"tn", "safe", "inline-code"},
	},
}
