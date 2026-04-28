package testdata

// TestCase represents a single test scenario for rule accuracy validation.
// Every field is documented to make maintenance straightforward.
//
// Naming convention for IDs:
//
//	TP-<CATEGORY>-<NNN>  True Positive: malicious command correctly detected
//	TN-<CATEGORY>-<NNN>  True Negative: benign command correctly allowed
//	FP-<CATEGORY>-<NNN>  False Positive: benign command incorrectly flagged
//	FN-<CATEGORY>-<NNN>  False Negative: malicious command missed
//
// Example: TP-FSDESTR-001, FP-FSDESTR-001, FN-FSDESTR-002
type TestCase struct {
	// ID is a unique identifier for this test case (e.g., "TP-FSDESTR-001").
	// Convention: <Classification>-<CategoryAbbrev>-<NNN>
	ID string

	// Command is the shell command string to evaluate.
	Command string

	// ExpectedDecision is the expected policy decision: "BLOCK", "AUDIT", "ALLOW".
	ExpectedDecision string

	// Classification indicates what this test validates:
	//   "TP" — True Positive: malicious command correctly detected
	//   "TN" — True Negative: benign command correctly allowed
	//   "FP" — False Positive: benign command incorrectly flagged (regression test)
	//   "FN" — False Negative: malicious command missed (known limitation or regression)
	Classification string

	// TaxonomyRef links to the taxonomy entry this test validates.
	// Format: "kingdom/category/weakness"
	// Example: "destructive-ops/fs-destruction/recursive-root-delete"
	TaxonomyRef string

	// Analyzer specifies which analyzer is expected to catch (or miss) this.
	// Empty means "any analyzer". Used to validate analyzer-specific behavior.
	// Values: "regex", "structural", "semantic", "dataflow", "stateful", "ai"
	Analyzer string

	// Description explains WHY this test exists and what behavior it validates.
	// This is the most important field for maintenance — be verbose.
	// Include what the command does, why the expected decision is correct,
	// and what analysis technique is needed to reach that decision.
	Description string

	// Tags for filtering tests. Common tags:
	//   "canonical"            — the most basic/obvious case for a weakness
	//   "critical"             — tests critical security boundaries
	//   "regression"           — regression test for a known FP or FN
	//   "flag-normalization"   — tests flag variant handling
	//   "structural-required"  — only structural analyzer can catch this
	//   "string-literal"       — pattern appears inside a string argument
	//   "indirect-execution"   — command executes code via python -c, etc.
	//   "depth-N"              — requires parse depth N to detect
	//   "known-gap"            — documents a known detection limitation
	//   "common-dev-operation" — common benign developer workflow
	//   "evasion"              — deliberately crafted to evade detection
	//   "encoding"             — uses encoding to hide intent
	//   "glob-evasion"         — uses glob patterns to bypass checks
	//   "sudo"                 — involves privilege escalation
	Tags []string
}

// AllClassifications is the set of valid Classification values.
var AllClassifications = []string{"TP", "TN", "FP", "FN"}
