package testdata

// AllTestCases returns every test case across all kingdoms.
// Used by the accuracy metrics test to compute aggregate TP/FP/FN/TN counts.
func AllTestCases() []TestCase {
	var all []TestCase
	all = append(all, AllDestructiveOpsCases()...)
	all = append(all, AllCredentialExposureCases()...)
	all = append(all, AllDataExfiltrationCases()...)
	all = append(all, AllUnauthorizedExecutionCases()...)
	all = append(all, AllPrivilegeEscalationCases()...)
	all = append(all, AllPersistenceEvasionCases()...)
	all = append(all, AllSupplyChainCases()...)
	all = append(all, AllReconnaissanceCases()...)
	all = append(all, AllGovernanceRiskCases()...)
	// Edge Case Deep Dive — hard link cases (history/alias cases in AllPersistenceEvasionCases)
	all = append(all, HardlinkCredentialCases...)
	// Opus deep-dive (2026-04-22): macOS Keychain file-level exfil, Python chr() obfuscation,
	// getattr(__import__) indirect dispatch, OSC 52 terminal clipboard hijack.
	all = append(all, KeychainFileExfilCases...)
	all = append(all, PythonChrObfuscationCases...)
	all = append(all, PythonGetattrImportCases...)
	all = append(all, OSC52ClipboardHijackCases...)
	// Agent-generated credential commit cases (issue #471)
	all = append(all, AgentGeneratedCredentialCommitCases...)
	// Build diagnostic prompt injection cases (issue #467)
	all = append(all, BuildDiagnosticPromptInjectionCases...)
	// Opus deep-dive (2026-04-25): bash hash -p PATH-bypass, getent NSS-bypass
	// (shadow read + DNS exfil), shell rcfile / ZDOTDIR override.
	all = append(all, BashHashRebindCases...)
	all = append(all, GetentCredentialDBCases...)
	all = append(all, GetentDNSExfilCases...)
	all = append(all, ShellRcfileOverrideCases...)
	// Opus deep-dive (2026-04-26): cloud SDK config redirection / poisoning —
	// AWS_CONFIG_FILE/KUBECONFIG/GAC env hijack, credential_process directive,
	// kubeconfig users.exec plugin poison, AKIA static-key replacement.
	all = append(all, CloudConfigRedirectCases...)
	all = append(all, AwsCredentialProcessPoisonCases...)
	all = append(all, KubeconfigExecPluginPoisonCases...)
	all = append(all, AwsCredentialsStaticKeyPoisonCases...)
	return all
}
