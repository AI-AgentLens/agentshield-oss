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
	return all
}
