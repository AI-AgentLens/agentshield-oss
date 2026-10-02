package testdata

// ReadOnlyAllowRedirectCases grade #4082 end to end through the analyzer
// pipeline (TestPipeline_AllKingdoms): ts-allow-readonly's `echo`/`printf`/
// `cat` prefixes used to ALLOW a command whose output was redirected into a
// file, below the AUDIT default, whenever no other rule named the
// destination. The rows below pin both halves: a redirect to a file falls to
// the default AUDIT (it is recorded, not vouched for), and a redirect to the
// null device, an inherited stream or an fd dup keeps the ALLOW.
//
// None of these expects BLOCK. The fix removes an ALLOW; it adds no denial.
var ReadOnlyAllowRedirectCases = []TestCase{
	{
		ID:               "TP-ROALLOW-REDIR-001",
		Command:          `echo 'avml /tmp/memory.lime ' >> ~/.zshenv`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "persistence-evasion/shell-startup/shell-profile-backdoor",
		Analyzer:         "regex",
		Description: "Supervisor carrier from #4082: a BLOCK rule's own TP text echoed into " +
			"~/.zshenv, which every zsh sources on start. The memory-acquisition rule is " +
			"anchored to a statement start, so it does not fire on the echo argument, and no " +
			"rule names ~/.zshenv as a destination. Before #4082 ts-allow-readonly's 'echo ' " +
			"prefix ALLOWed it — an affirmative 'read-only' vouch for a startup-file write. " +
			"Now the redirect withholds that ALLOW and the command is recorded at the default " +
			"AUDIT. What this row asserts is 'not ALLOW'; it is not a BLOCK.",
		Tags: []string{"regression", "allow-narrowing", "redirect-write", "startup-file"},
	},
	{
		ID:               "TP-ROALLOW-REDIR-002",
		Command:          `printf 'msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf > /tmp/shell.elf\n' >> ~/.zshenv`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "persistence-evasion/shell-startup/shell-profile-backdoor",
		Analyzer:         "regex",
		Description: "Supervisor carrier from #4082, printf form: a payload-generation line " +
			"written into ~/.zshenv so the next shell runs it. The '>' inside the quoted " +
			"format string is text, not a redirect; the '>>' after it is the write. Was ALLOW " +
			"via ts-allow-readonly's 'printf ' prefix; now the default AUDIT.",
		Tags: []string{"regression", "allow-narrowing", "redirect-write", "startup-file"},
	},
	{
		ID:               "TN-ROALLOW-REDIR-003",
		Command:          `echo 'export PATH=$PATH:/opt/bin' >> ~/.zshenv`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "persistence-evasion/shell-startup/shell-profile-backdoor",
		Analyzer:         "regex",
		Description: "An ordinary PATH line appended to ~/.zshenv. Benign, and not blocked, but " +
			"it is a startup-file write, so it is recorded at the default AUDIT rather than " +
			"vouched for as read-only (ALLOW before #4082).",
		Tags: []string{"allow-narrowing", "redirect-write", "common-dev-operation"},
	},
	{
		ID:               "TN-ROALLOW-REDIR-004",
		Command:          `echo a; { echo b; } > out.txt`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "persistence-evasion/shell-startup/shell-profile-backdoor",
		Analyzer:         "regex",
		Description: "The redirect sits on a brace group, which the statement splitter " +
			"descends into and drops. On main every split statement started with 'echo ' and " +
			"the command earned ALLOW; the #4082 check walks every statement's redirects in " +
			"the AST, the group's included, so the write falls to the default AUDIT.",
		Tags: []string{"allow-narrowing", "redirect-write", "compound"},
	},
	{
		ID:               "TN-ROALLOW-REDIR-005",
		Command:          `echo x > /dev/null`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "persistence-evasion/shell-startup/shell-profile-backdoor",
		Analyzer:         "regex",
		Description:      "Output to the null device writes no file: ts-allow-readonly keeps its ALLOW (#4082 exemption).",
		Tags:             []string{"allow-narrowing", "redirect-exempt"},
	},
	{
		ID:               "TN-ROALLOW-REDIR-006",
		Command:          `printf '%s\n' foo 2>&1`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "persistence-evasion/shell-startup/shell-profile-backdoor",
		Analyzer:         "regex",
		Description:      "An fd dup onto stdout writes no file: ts-allow-readonly keeps its ALLOW (#4082 exemption).",
		Tags:             []string{"allow-narrowing", "redirect-exempt"},
	},
	{
		ID:               "TN-ROALLOW-REDIR-007",
		Command:          `grep -rn TODO . 2>/dev/null`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "persistence-evasion/shell-startup/shell-profile-backdoor",
		Analyzer:         "regex",
		Description:      "stderr to the null device writes no file: ts-allow-readonly keeps its ALLOW (#4082 exemption).",
		Tags:             []string{"allow-narrowing", "redirect-exempt", "common-dev-operation"},
	},
	{
		ID:               "TN-ROALLOW-REDIR-008",
		Command:          `echo 'a > b' "c >> d"`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "persistence-evasion/shell-startup/shell-profile-backdoor",
		Analyzer:         "regex",
		Description: "A quoted '>' is text, not a redirect. This is the row a regex-based " +
			"exclusion would get wrong, and the reason the #4082 check reads the shell AST.",
		Tags: []string{"allow-narrowing", "redirect-exempt", "string-literal"},
	},
}
