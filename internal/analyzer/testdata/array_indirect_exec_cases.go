package testdata

// ArrayIndirectExecCases validate that delivering an executable name — or the
// whole command — through a bash array element does not weaken its decision
// (issue #3091), the array-based sibling of the scalar/cmdsubst indirection
// cases (#3089/#3090, see CmdSubstEvasionCases).
//
// Attack vector: shellparse's constant-scalar symbol table (#3089) skipped
// array assignments and its executable-word resolver bailed on any indexed
// expansion, so an executable routed through "${a[@]}" / "${a[*]}" / "${a[0]}"
// stayed an unresolved token — no structural/semantic/dataflow/stateful rule
// keyed on the real executable matched, and the regex layer missed it too:
//
//	rm -rf /                          -> BLOCK
//	a=(rm -rf /); "${a[@]}"           -> AUDIT   (should BLOCK — whole command
//	                                              hidden in an array splat)
//	a=(rm); ${a[0]} -rf /             -> AUDIT   (should BLOCK — exec name only)
//
// The fix (internal/shellparse/parse.go) registers constant, fully-literal,
// positionally-defined array literals in the exec symbol table and resolves
// [@]/[*]/[<n>] expansions in executable position, splitting a multi-word
// expansion back into argv so every downstream analyzer sees the real command.
// Resolution is conservative — a single dynamic or explicitly-indexed element
// bails the whole array — so a resolved array genuinely IS the command it runs,
// keeping precision at 100% (the negative controls below stay un-escalated).
var ArrayIndirectExecCases = []TestCase{
	// --- True Positives: array indirection must not weaken the decision ---
	{
		ID:               "TP-ARRAY-EXEC-001",
		Command:          `a=(rm -rf /); "${a[@]}"`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      `rm -rf / smuggled through an array splat "${a[@]}" — the whole command lives in the array literal and expands back to argv.`,
		Tags:             []string{"tp", "destructive", "array-indirection"},
	},
	{
		ID:               "TP-ARRAY-EXEC-002",
		Command:          `a=(rm); ${a[0]} -rf /`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      "Executable name delivered via a single-element array index ${a[0]}; flags/target stay literal.",
		Tags:             []string{"tp", "destructive", "array-indirection"},
	},
	{
		ID:               "TP-ARRAY-EXEC-003",
		Command:          `cmd=(dd if=/dev/zero of=/dev/sda); "${cmd[*]}"`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/disk-overwrite",
		Analyzer:         "structural",
		Description:      `dd disk-overwrite hidden in an array expanded with "${cmd[*]}".`,
		Tags:             []string{"tp", "destructive", "array-indirection"},
	},
	// --- Negative controls: benign array use must NOT be over-escalated ---
	// These prove the resolver only ever reveals what the array actually runs;
	// it never manufactures a block. (AUDIT, the default decision, not BLOCK.)
	{
		ID:               "TN-ARRAY-EXEC-001",
		Command:          `a=(ls -la /tmp); "${a[@]}"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      "Benign command via array splat resolves to `ls -la /tmp` — must not trip the rm destructive rule.",
		Tags:             []string{"tn", "safe", "array-indirection"},
	},
	{
		ID:               "TN-ARRAY-EXEC-002",
		Command:          `a=("$USER" whoami); "${a[@]}"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      "A dynamic ($USER) element makes the array non-constant, so the resolver bails the whole array — no spurious resolution or block.",
		Tags:             []string{"tn", "safe", "array-indirection"},
	},
}
