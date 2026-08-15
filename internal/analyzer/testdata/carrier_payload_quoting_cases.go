package testdata

// CarrierPayloadQuotingCases cover issue #3241 — a carrier's payload was
// reconstructed by stripping ONE outer quote pair rather than by performing
// quote removal.
//
// Bash performs quote removal on a carrier's argv word before the carrier ever
// sees it, so the payload is that word's runtime VALUE. Outer-pair stripping
// equals quote removal only when the word happens to be a single whole quoted
// span — the shape #3050 measured and fixed. When the payload's WORD BOUNDARIES
// are hidden inside the word instead, the old reconstruction handed back the
// text verbatim and it re-parsed as one word: an executable literally named
// "mkfs.ext4 /dev/sda1".
//
// Three spellings hide a boundary, and they are the three TP groups below:
//
//	bash -c mkfs.ext4\ /dev/sda1        escaped space — the payload is one Lit
//	bash -c mkfs.ext4' '/dev/sda1       interior quote splice — Lit+SglQuoted+Lit
//	bash -c 'mkfs.ext4'\ '/dev/sda1'    alternating — first and last chars are
//	                                    quotes of DIFFERENT spans, so the old
//	                                    "matched pair" test corrupted the payload
//
// Measured at 75.4% of the BLOCKing corpus against a 1.0% control, on all eight
// carrier surfaces at once — the largest single leak recorded in this repo.
// Every spelling was verified to execute against a real bash, not inferred from
// the parse.
//
// The taxonomy refs reuse ts-block-mkfs / ts-block-dd-zero / ts-block-rm-root,
// the same rules #3059's cases measured with, so these exercise the carrier
// mechanism rather than introducing new rule coverage.
//
// TNs are the developer-workflow shapes that must not escalate: a payload whose
// interior quoting is meaningful to the INNER shell (which must survive
// reconstruction untouched — those quotes are the inner shell's to remove, not
// ours), and a payload that legitimately escapes a space because the path
// really does contain one.
var CarrierPayloadQuotingCases = []TestCase{
	// --- TP: escaped-space splice ----------------------------------------
	{
		ID:               "TP-CARRIERQUOTE-001",
		Command:          `bash -c mkfs.ext4\ /dev/sda1`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/filesystem-format",
		Analyzer:         "pipeline",
		Description:      "bash -c payload whose word boundary is an escaped space — bash removes the escape before -c sees it, so this formats the disk.",
		Tags:             []string{"tp", "destructive", "carrier", "quote-removal"},
	},
	{
		ID:               "TP-CARRIERQUOTE-002",
		Command:          `eval dd\ if=/dev/zero\ of=/dev/sda\ bs=1M`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/disk-overwrite",
		Analyzer:         "pipeline",
		Description:      "eval joining argv words whose boundaries are escaped spaces — eval takes no options, so the resolved word is shell source.",
		Tags:             []string{"tp", "destructive", "carrier", "quote-removal"},
	},
	{
		ID:               "TP-CARRIERQUOTE-003",
		Command:          `trap mkfs.ext4\ /dev/sda1 EXIT`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/filesystem-format",
		Analyzer:         "pipeline",
		Description:      "trap action carrying an escaped-space payload — deferred execution plus a hidden word boundary, neither visible to a reviewer reading the command stream.",
		Tags:             []string{"tp", "destructive", "carrier", "quote-removal", "trap"},
	},

	// --- TP: interior quote splice ---------------------------------------
	{
		ID:               "TP-CARRIERQUOTE-004",
		Command:          `bash -c mkfs.ext4' '/dev/sda1`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/filesystem-format",
		Analyzer:         "pipeline",
		Description:      "Interior single-quote splice supplies the space — the word has no outer quote pair at all, so outer-pair stripping was a no-op.",
		Tags:             []string{"tp", "destructive", "carrier", "quote-removal"},
	},
	{
		ID:               "TP-CARRIERQUOTE-005",
		Command:          `eval dd" "if=/dev/zero" "of=/dev/sda" "bs=1M`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/disk-overwrite",
		Analyzer:         "pipeline",
		Description:      "Same splice with double quotes — the quoting style does not change that the runtime value is one destructive command.",
		Tags:             []string{"tp", "destructive", "carrier", "quote-removal"},
	},

	// --- TP: alternating splice, the shape that CORRUPTED the old parse ---
	{
		ID:               "TP-CARRIERQUOTE-006",
		Command:          `bash -c 'rm'\ '-rf'\ '/'`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "pipeline",
		Description:      "First and last characters are quotes of DIFFERENT spans — the old outer-pair test stripped one from each and emitted corrupted text, so nothing downstream could match.",
		Tags:             []string{"tp", "destructive", "carrier", "quote-removal"},
	},
	{
		ID:               "TP-CARRIERQUOTE-007",
		Command:          `su -c rm\ -rf\ / root`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "pipeline",
		Description:      "The privilege-carrier surface (#3223) shares the one reconstruction primitive, so it leaked identically — root-privileged recursive delete.",
		Tags:             []string{"tp", "destructive", "carrier", "quote-removal", "privesc"},
	},

	// --- TN: interior quoting that is the INNER shell's to remove ---------
	{
		ID:               "TN-CARRIERQUOTE-001",
		Command:          `bash -c 'echo "build complete"'`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/disk-ops/filesystem-format",
		Analyzer:         "pipeline",
		Description:      "Whole-word quoted payload with meaningful inner quotes — reconstruction must hand `echo \"build complete\"` to the inner parse, not flatten it.",
		Tags:             []string{"tn", "safe", "carrier"},
	},
	{
		ID:               "TN-CARRIERQUOTE-002",
		Command:          `bash -c 'ls "/Users/dev/My Documents"'`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/disk-ops/filesystem-format",
		Analyzer:         "pipeline",
		Description:      "A path that genuinely contains a space — quoting the boundary here is correct usage, not concealment.",
		Tags:             []string{"tn", "safe", "carrier"},
	},
	{
		ID:               "TN-CARRIERQUOTE-003",
		Command:          `bash -c ls\ /tmp`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/disk-ops/disk-overwrite",
		Analyzer:         "pipeline",
		Description:      "The escaped-space shape itself is not the threat — the resolved payload is `ls /tmp`, which the baseline allow-safe-readonly/ts-allow-readonly command_prefix rules recognize as a read-only listing once it resolves cleanly.",
		Tags:             []string{"tn", "safe", "carrier"},
	},
	{
		ID:               "TN-CARRIERQUOTE-004",
		Command:          `sh -c 'cd /srv/app && git pull --ff-only'`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/disk-ops/disk-overwrite",
		Analyzer:         "pipeline",
		Description:      "Routine deploy step — a multi-statement payload that parseLoneWord declines, falling back to the previous reconstruction unchanged.",
		Tags:             []string{"tn", "safe", "carrier"},
	},
	{
		ID:               "TN-CARRIERQUOTE-005",
		Command:          `trap 'rm -f "$tmpdir"/*.lock' EXIT`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "pipeline",
		Description:      "trap cleaning up its own lock files — the canonical legitimate trap, and a payload carrying a ParamExp the resolver must decline rather than partially resolve.",
		Tags:             []string{"tn", "safe", "carrier", "trap"},
	},
	{
		ID:               "TN-CARRIERQUOTE-006",
		Command:          `flock /tmp/deploy.lock -c 'make deploy'`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "pipeline",
		Description:      "Serialised deploy through flock — a shell-source carrier (#3232) on the benign side of the same reconstruction path.",
		Tags:             []string{"tn", "safe", "carrier"},
	},
}
