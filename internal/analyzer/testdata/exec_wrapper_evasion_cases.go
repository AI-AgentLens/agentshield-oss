package testdata

// ExecWrapperEvasionCases validate that execution-wrapper prefixes do not let a
// dangerous command slip past the structural analyzer.
//
// Attack vector: every structural/regex rule keys on the *first* word of a
// command. An attacker prefixes a destructive command with a transparent
// execution wrapper — env, nice, nohup, setsid, timeout, ionice, stdbuf,
// taskset, chrt, command, doas, proxychains, or the `time` reserved word — so
// the parsed executable becomes the wrapper, not "rm"/"chmod"/"dd". Before the
// parser learned to peel wrappers (StripExecWrappers), "nice rm -rf /" parsed
// with Executable=="nice" and dodged st-block-rm-recursive-root entirely while
// "rm -rf /" was blocked. These wrappers are ubiquitous on every Linux box, so
// the bypass needs no extra tooling.
//
// The fix is surgical: a wrapper escalates the decision ONLY when the wrapped
// command is itself dangerous. "nice rm -rf node_modules" stays benign because
// the target is not a root/system path — see the TN cases.
var ExecWrapperEvasionCases = []TestCase{
	// --- True Positives: wrapper-prefixed destructive commands must BLOCK ---
	{
		ID:               "TP-WRAPEVASION-001",
		Command:          "env rm -rf /",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      "env(1) runs rm -rf / with a (possibly empty) modified environment. The wrapper must be transparent so the structural rm-recursive-root check still fires.",
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-WRAPEVASION-002",
		Command:          "nice rm -rf /",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      "nice(1) only adjusts scheduling priority; the wrapped rm -rf / is fully destructive and must be blocked.",
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-WRAPEVASION-003",
		Command:          "timeout 5 rm -rf /",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      "timeout(1) takes a positional DURATION ('5') before the command. The duration token must be skipped so 'rm' is recognized as the executable.",
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-WRAPEVASION-004",
		Command:          "command rm -rf /",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      "The `command` builtin bypasses shell functions/aliases to run the real rm — a common way to evade defensive aliases. Must remain blocked.",
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-WRAPEVASION-005",
		Command:          "setsid rm -rf /",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      "setsid(1) detaches rm into a new session; the destructive payload is unchanged and must be blocked.",
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-WRAPEVASION-006",
		Command:          "sudo nice rm -rf /",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      "Nested wrappers (sudo + nice) must both be peeled to reach the rm executable.",
		Tags:             []string{"tp", "destructive", "critical", "evasion", "sudo"},
	},
	{
		ID:               "TP-WRAPEVASION-007",
		Command:          "env FOO=bar nice -n 5 rm -rf /",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      "Mixed wrapper chain: env with a KEY=VALUE assignment, then nice with a flag+value, then rm. All wrapper operands must be skipped.",
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-WRAPEVASION-008",
		Command:          "time rm -rf /",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      "`time` is a bash reserved word parsed as a TimeClause, not a CallExpr. Without TimeClause handling the command vanished from the parse tree entirely (no segments → AUDIT). Must be seen through and blocked.",
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-WRAPEVASION-009",
		Command:          "ionice -c3 rm -rf /boot",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/system-directory-delete",
		Analyzer:         "structural",
		Description:      "ionice(1) with a class flag wrapping rm -rf of a system directory (/boot). Wrapper flag must be skipped and the system-dir delete blocked.",
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-WRAPEVASION-010",
		Command:          "nohup chmod -R 777 /etc",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/permission-weakening/chmod-world-writable",
		Analyzer:         "structural",
		Description:      "nohup wrapping a recursive world-writable chmod on /etc. The wrapper must not hide the chmod from permission-weakening detection.",
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-WRAPEVASION-011",
		Command:          "taskset -c 0 chmod -R 777 /usr",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/permission-weakening/chmod-world-writable",
		Analyzer:         "structural",
		Description:      "taskset(1) pins CPU affinity then runs chmod -R 777 on /usr. Wrapper flag+value skipped; world-writable system path must block.",
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},

	// --- True Negatives: wrappers around benign commands must NOT block ---
	// These prove the unwrap is surgical: escalation depends on the INNER
	// command being dangerous, not on a wrapper merely being present.
	{
		ID:               "TN-WRAPEVASION-001",
		Command:          "nice rm -rf node_modules",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      "Everyday cleanup: rm -rf node_modules is benign because the target is a relative project dir, not root. The nice wrapper must not turn it into a block.",
		Tags:             []string{"tn", "safe", "common-dev-operation"},
	},
	{
		ID:               "TN-WRAPEVASION-002",
		Command:          "timeout 5 rm -rf ./build",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      "Common CI/dev pattern: clear a local build dir under a timeout. Relative path, not root — must not block.",
		Tags:             []string{"tn", "safe", "common-dev-operation"},
	},
	{
		ID:               "TN-WRAPEVASION-003",
		Command:          "env node app.js",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      "Running a Node app under env(1) is routine. Unwrapping must yield 'node', which triggers no destructive rule.",
		Tags:             []string{"tn", "safe", "common-dev-operation"},
	},
	{
		ID:               "TN-WRAPEVASION-004",
		Command:          "timeout 30 npm test",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      "Bounding a test run with timeout is standard. Unwraps to 'npm test' — benign.",
		Tags:             []string{"tn", "safe", "common-dev-operation"},
	},
	{
		ID:               "TN-WRAPEVASION-005",
		Command:          "nice -n 19 make build",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/permission-weakening/chmod-world-writable",
		Analyzer:         "structural",
		Description:      "Lowering build priority with nice is common on shared machines. Unwraps to 'make build' — benign.",
		Tags:             []string{"tn", "safe", "common-dev-operation"},
	},
	{
		ID:               "TN-WRAPEVASION-006",
		Command:          "env",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/system-directory-delete",
		Analyzer:         "structural",
		Description:      "Bare env(1) just prints the environment — there is no wrapped command, so the wrapper must be left in place and nothing should block.",
		Tags:             []string{"tn", "safe", "common-dev-operation"},
	},
	{
		ID:               "TN-WRAPEVASION-007",
		Command:          "nohup rm -rf dist",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/system-directory-delete",
		Analyzer:         "structural",
		Description:      "Removing a local dist/ output directory under nohup is benign — relative path, not a system directory.",
		Tags:             []string{"tn", "safe", "common-dev-operation"},
	},
	{
		ID:               "TN-WRAPEVASION-008",
		Command:          "taskset -c 0 ./benchmark",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/permission-weakening/chmod-world-writable",
		Analyzer:         "structural",
		Description:      "Pinning a benchmark binary to a CPU core with taskset is a normal performance workflow. Unwraps to './benchmark' — benign.",
		Tags:             []string{"tn", "safe", "common-dev-operation"},
	},
}

// ExecNameObfuscationCases validate that shell quoting/escaping of the
// executable name does not let a dangerous command slip past detection.
//
// Attack vector: `\rm`, `"rm"`, `'rm'`, `r""m`, `rm''`, `r\m` all execute rm in
// a real shell — the quotes and backslashes are shell syntax that collapses
// before the command name is resolved. The canonical purpose of `\rm` is to
// bypass a defensive shell alias (`alias rm='rm -i'`); the same trick bypasses
// a naive analyzer that keeps the quoting in the parsed executable. Before
// NormalizeExecName, "\rm -rf /" parsed with Executable=="\rm" and sailed past
// every rule keyed on "rm". Combines with wrappers ("env \rm -rf /").
var ExecNameObfuscationCases = []TestCase{
	// --- True Positives: obfuscated executable names must still BLOCK ---
	{
		ID:               "TP-EXECOBF-001",
		Command:          `\rm -rf /`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      `Backslash-escaped rm (\rm) is the classic alias-bypass form. The shell runs plain rm; the analyzer must normalize the name and block.`,
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-EXECOBF-002",
		Command:          `"rm" -rf /`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      `Double-quoting the command name ("rm") collapses to rm at runtime. Must be normalized and blocked.`,
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-EXECOBF-003",
		Command:          `r""m -rf /`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      `Empty double quotes embedded mid-token (r""m) is a stealthy concatenation evasion that still runs rm. Must be normalized and blocked.`,
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-EXECOBF-004",
		Command:          `'rm' -rf /`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      `Single-quoting the command name ('rm') resolves to rm at runtime. Must be normalized and blocked.`,
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-EXECOBF-005",
		Command:          `r\m -rf /`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      `Internal backslash (r\m) is another no-op escape that resolves to rm. Must be normalized and blocked.`,
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-EXECOBF-006",
		Command:          `env \rm -rf /`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      `Obfuscation combined with an exec wrapper: env runs \rm. Both the wrapper and the escaped name must be seen through.`,
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-EXECOBF-007",
		Command:          `\nice rm -rf /`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      `The wrapper name itself is escaped (\nice). Wrapper detection must normalize the name to still recognize and peel the nice wrapper.`,
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-EXECOBF-008",
		Command:          `"chmod" -R 777 /etc`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/permission-weakening/chmod-world-writable",
		Analyzer:         "structural",
		Description:      `Quoted chmod ("chmod") still weakens permissions on /etc. Must be normalized and blocked.`,
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},

	// --- True Negatives: quoting in ARGUMENTS is normal and must stay clean ---
	// Critical: normalization is scoped to the executable position. These prove
	// that quoted/escaped *arguments* (extremely common) are left untouched.
	{
		ID:               "TN-EXECOBF-001",
		Command:          `echo "hello world"`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      `A quoted string argument to echo is ubiquitous. Executable-name normalization must not touch arguments — this stays benign.`,
		Tags:             []string{"tn", "safe", "common-dev-operation"},
	},
	{
		ID:               "TN-EXECOBF-002",
		Command:          `git commit -m "fix: handle rm -rf edge case"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      `A commit message that literally contains "rm -rf" is a realistic developer workflow. The quoted text is an argument, not a command, and must not block.`,
		Tags:             []string{"tn", "safe", "common-dev-operation"},
	},
	{
		ID:               "TN-EXECOBF-003",
		Command:          `grep -r "rm -rf" .`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/system-directory-delete",
		Analyzer:         "structural",
		Description:      `Searching a codebase for the literal string "rm -rf" is a normal audit task. The quoted pattern is an argument and must stay benign.`,
		Tags:             []string{"tn", "safe", "common-dev-operation"},
	},
	{
		ID:               "TN-EXECOBF-004",
		Command:          `printf '%s\n' "backup complete"`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/permission-weakening/chmod-world-writable",
		Analyzer:         "structural",
		Description:      `printf with an escaped format string and quoted argument is routine; backslashes in arguments must be preserved and not trigger any rule.`,
		Tags:             []string{"tn", "safe", "common-dev-operation"},
	},
}

// RootTargetPathEvasionCases validate that quoting / escaping / path-traversal
// of the TARGET path cannot sneak a root or system-directory delete past the
// structural check.
//
// Attack vector: the root/system-dir check compared the raw argument string, so
// any path that is *equivalent* to "/" or "/etc" but spelled differently
// evaded it — "/" quoted as "/" or '/', the escaped \/, the path-identical /.
// and /./ and //, or a traversal like /home/../ and /tmp/.. that resolves back
// to root. All of these delete the same files a bare "rm -rf /" would. Closed
// by normalizeTargetPath (shell-unquote + path.Clean) inside isRootTarget /
// isSystemDir / isSystemPath. Chains with the wrapper and exec-name fixes:
// `nice rm -rf "/"` and `\rm -rf '/etc'` are blocked too.
var RootTargetPathEvasionCases = []TestCase{
	// --- True Positives: path-equivalent root/system targets must BLOCK ---
	{
		ID:               "TP-PATHEVASION-001",
		Command:          `rm -rf "/"`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      `Double-quoting the root target ("/") is the simplest path evasion; the shell still passes /. Must normalize and block.`,
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-PATHEVASION-002",
		Command:          `rm -rf '/'`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      `Single-quoted root target ('/'). Must normalize and block.`,
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-PATHEVASION-003",
		Command:          `rm -rf /.`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      `"/." is path-identical to "/" — path.Clean collapses it. Must block.`,
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-PATHEVASION-004",
		Command:          `rm -rf /./`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      `"/./" collapses to "/". Must block.`,
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-PATHEVASION-005",
		Command:          `rm -rf /home/../`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      `"/home/.." traverses back to root. The destructive payload is identical to "rm -rf /". Must resolve traversal and block.`,
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-PATHEVASION-006",
		Command:          `rm -rf \/`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      `Backslash-escaped slash (\/) still resolves to / at runtime. Must strip the escape and block.`,
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-PATHEVASION-007",
		Command:          `rm -rf "/etc"`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/system-directory-delete",
		Analyzer:         "structural",
		Description:      `Quoted system directory ("/etc"). Must normalize and block.`,
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},
	{
		ID:               "TP-PATHEVASION-008",
		Command:          `nice rm -rf "/"`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      `Layered evasion: nice wrapper + quoted root target. All three normalizations (wrapper, exec name, path) must compose.`,
		Tags:             []string{"tp", "destructive", "critical", "evasion"},
	},

	// --- True Negatives: benign relative/traversal paths must NOT block ---
	{
		ID:               "TN-PATHEVASION-001",
		Command:          `rm -rf ./dist/../out`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      `Traversal that stays inside the project (resolves to "out"). path.Clean must not mistake it for root.`,
		Tags:             []string{"tn", "safe", "common-dev-operation"},
	},
	{
		ID:               "TN-PATHEVASION-002",
		Command:          `rm -rf ../sibling-project`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/recursive-root-delete",
		Analyzer:         "structural",
		Description:      `Cleaning to "../sibling-project" — a relative path, not root. Must not block a routine sibling-dir cleanup.`,
		Tags:             []string{"tn", "safe", "common-dev-operation"},
	},
	{
		ID:               "TN-PATHEVASION-003",
		Command:          `rm -rf "$BUILD_DIR"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/system-directory-delete",
		Analyzer:         "structural",
		Description:      `A variable target ("$BUILD_DIR") can't be resolved statically and must be left untouched — not assumed to be root.`,
		Tags:             []string{"tn", "safe", "common-dev-operation"},
	},
	{
		ID:               "TN-PATHEVASION-004",
		Command:          `rm -rf /home/user/project/build`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/fs-destruction/system-directory-delete",
		Analyzer:         "structural",
		Description:      `Deleting a deep project build dir under /home is benign — not a system directory. Must not block.`,
		Tags:             []string{"tn", "safe", "common-dev-operation"},
	},

	// --- dd output-target path-equivalence evasion (issue #2575) ---
	// isBlockDevice must normalize paths so traversal or device-path tricks
	// don't bypass the dd safety check.
	{
		ID:               "TP-PATHEVASION-DD-001",
		Command:          `dd if=/dev/zero of=/dev/../dev/sda`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/disk-overwrite",
		Analyzer:         "structural",
		Description:      `Traversal in of= path resolves to /dev/sda — isBlockDevice must normalize before prefix check or this overwrites the disk silently.`,
		Tags:             []string{"tp", "evasion", "path-equivalence"},
	},
	{
		ID:               "TP-PATHEVASION-DD-002",
		Command:          `dd if=/dev/./zero of=/dev/sda bs=512`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "destructive-ops/disk-ops/disk-overwrite",
		Analyzer:         "regex",
		Description:      `Superfluous dot in if= path (/dev/./zero) — path-equivalence evasion of ts-block-dd-zero. Closed by premium rule ts-block-dd-dev-path-equivalence which matches /dev/[./]+ variants.`,
		Tags:             []string{"tp", "evasion", "path-equivalence"},
	},
	{
		ID:               "FP-PATHEVASION-DD-001",
		Command:          `dd if=/dev/zero of=/tmp/../tmp/disk.img bs=1M count=1`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "destructive-ops/disk-ops/disk-overwrite",
		Analyzer:         "structural",
		Description:      `Traversal in of= path resolves to /tmp/disk.img — a regular file, not a block device. Must ALLOW (FP guard).`,
		Tags:             []string{"tn", "fp-guard", "path-equivalence"},
	},
}
