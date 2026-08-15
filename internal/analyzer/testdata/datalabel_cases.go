package testdata

// DataLabelFixtureCases exercise the conditional data-label stage (Layer 7).
// BuildAnalyzerPipeline only registers the DataLabelAnalyzer when the policy
// carries a `data_labels` block — before these cases existed, no test policy
// ever did, so the registration branch and the shell scan path were invisible
// to the accuracy corpus.
//
// The fixture label (case-sensitive keyword "AALFIXTURE-CODENAME-ZUNIQ7",
// decision BLOCK) is appended by the accuracy harness in loadTestPolicy
// (accuracy_test.go) — it is NOT part of any shipped pack, and the keyword is
// synthetic so no other corpus command can collide with it.
//
// TaxonomyRef is the taxonomy DataLabelAnalyzer synthesizes for the fixture
// label ("data-protection/pii/" + label ID). No pack rule declares it —
// customer data_labels are configuration, not rules — so the ref is baselined
// in cmd/check-rule-coverage/baseline.txt as an intentional orphan.
var DataLabelFixtureCases = []TestCase{
	{
		ID:               "TP-DATALABEL-FIXTURE-001",
		Command:          "cat /docs/AALFIXTURE-CODENAME-ZUNIQ7-roadmap.md",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "data-protection/pii/test-fixture-codename",
		Analyzer:         "datalabel",
		Description:      "Customer-defined codename in a shell command — the Layer 7 data-label stage must fire (keyword tier, case-sensitive).",
		Tags:             []string{"tp", "datalabel", "fixture"},
	},
	{
		ID:               "TN-DATALABEL-FIXTURE-001",
		Command:          "cat /docs/project-roadmap.md",
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "data-protection/pii/test-fixture-codename",
		Analyzer:         "datalabel",
		Description:      "Benign near-miss (lowercase, no codename) — the data-label stage must not fire and no other rule flags a plain doc read.",
		Tags:             []string{"tn", "datalabel", "fixture"},
	},
}
