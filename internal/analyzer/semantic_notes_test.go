package analyzer

import "testing"

// #3995: the semantic stage's label exclusion writes the same excused note
// as the regex stage — and only when the rule's own predicate fires. Pinned
// with a synthetic rule because the shipped Go rules' predicates require an
// interpreter invocation, which no excused shape (comment, doc text, heredoc
// body) carries, so real traffic exercises the skip branch but never the
// note. The three cases: fires and excused → note, no finding; fires and not
// excused → finding, no note; excused but does not fire → nothing.
func TestSemanticAnalyzer_ExcusedProbeNotesOnlyAFiringRule(t *testing.T) {
	fires := func(*ParsedCommand, string) bool { return true }
	never := func(*ParsedCommand, string) bool { return false }
	a := &SemanticAnalyzer{rules: []SemanticRule{
		{ID: "syn-fires", Match: fires, Decision: "BLOCK", Confidence: 0.9, Reason: "r", IntentExclude: []string{LabelIsBashComment}},
		{ID: "syn-never", Match: never, Decision: "BLOCK", Confidence: 0.9, Reason: "r", IntentExclude: []string{LabelIsBashComment}},
		{ID: "syn-audit", Match: fires, Decision: "AUDIT", Confidence: 0.5, Reason: "r", IntentExclude: []string{LabelIsBashComment}},
	}}

	// Analyze returns early without a parsed command; give it one.
	excused := &AnalysisContext{RawCommand: "# anything", Parsed: &ParsedCommand{}, CommandFacts: CommandFacts{IsBashComment: true}}
	findings := a.Analyze(excused)
	if len(findings) != 0 {
		t.Fatalf("excused rules must produce no finding, got %+v", findings)
	}
	if len(excused.Notes) != 1 || excused.Notes[0] != (Note{Kind: NoteExcused, Rule: "syn-fires", Detail: "intent:" + LabelIsBashComment}) {
		t.Fatalf("want exactly one excused note for the firing BLOCK rule, got %+v", excused.Notes)
	}

	live := &AnalysisContext{RawCommand: "anything", Parsed: &ParsedCommand{}}
	findings = a.Analyze(live)
	if len(findings) != 2 || findings[0].RuleID != "syn-fires" || findings[1].RuleID != "syn-audit" {
		t.Fatalf("unexcused: want findings for the two firing rules, got %+v", findings)
	}
	if len(live.Notes) != 0 {
		t.Fatalf("a firing, unexcused rule must not be noted: %+v", live.Notes)
	}
}
