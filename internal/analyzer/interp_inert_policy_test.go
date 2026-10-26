package analyzer_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"gopkg.in/yaml.v3"
)

// Apply the exclusions from p4418.diff/p4422.diff to real loaded rules. Keep
// their regexes and the rest of the policy intact; the simplified unit-test
// predicate cannot exercise rule-specific candidates in the full pipeline.
func interpReviewPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	// ts-block-adb-am-start-shell-injection ships in packs/premium/, so the
	// OSS tree finds 2 of the 3 rules and publish-oss.sh refuses the publish.
	ossbuild.SkipPremiumSized(t)
	pol := loadTestPolicy(t)
	patched := policy.Pack{Name: "interp-inert-review", PackVersion: "0.1"}
	var remaining []policy.Rule
	for i := range pol.Rules {
		switch pol.Rules[i].ID {
		case "ts-block-home-redirect", "ts-block-home-redirect-inline", "ts-block-adb-am-start-shell-injection":
			pol.Rules[i].Match.CommandPositionExclude = append(pol.Rules[i].Match.CommandPositionExclude, analyzer.LabelPosInterpHeredocLiteral)
			patched.Rules = append(patched.Rules, pol.Rules[i])
		default:
			remaining = append(remaining, pol.Rules[i])
		}
	}
	if len(patched.Rules) != 3 {
		t.Fatalf("found %d patched rules, want 3", len(patched.Rules))
	}
	// Load an actual temporary pack with the exclusions. Replace the original
	// copies instead of appending duplicates: an unpatched embedded community
	// copy would correctly keep BLOCK under most-restrictive-wins, regardless
	// of whether the patched copy excused the literal.
	pol.Rules = remaining
	dir := t.TempDir()
	data, err := yaml.Marshal(patched)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(dir,"interp-review.yaml"), data, 0600); err != nil { t.Fatal(err) }
	pol, infos, err := policy.LoadPacks(dir, pol)
	if err != nil { t.Fatal(err) }
	if len(infos)!=1 || infos[0].LoadError!=nil || infos[0].RuleCount!=3 { t.Fatalf("patched pack not loaded: %+v",infos) }
	return pol
}

func TestInterpInertRealRules(t *testing.T) {
	pol := interpReviewPolicy(t)
	for _, pipeline := range []bool{false, true} {
		name := "fallback"
		if pipeline {
			name = "pipeline"
		}
		t.Run(name, func(t *testing.T) {
			var engine *policy.Engine
			var err error
			if pipeline {
				engine, err = policy.NewEngineWithAnalyzers(pol, 2)
			} else {
				engine, err = policy.NewEngine(pol)
			}
			if err != nil {
				t.Fatal(err)
			}
			files,err:=filepath.Glob("testdata/interp_inert/*/*.sh")
			if err!=nil || len(files)!=47 { t.Fatalf("probe manifest: files=%d err=%v",len(files),err) }
			for _, file := range files {
				t.Run(filepath.Base(file), func(t *testing.T) {
					b, err := os.ReadFile(file)
					if err != nil {
						t.Fatal(err)
					}
					cwd, err := os.Getwd()
					if err != nil {
						t.Fatal(err)
					}
					base:=filepath.Base(file)
					writeOnly:=strings.HasPrefix(base,"t01-") || strings.HasPrefix(base,"t02-") || strings.HasPrefix(base,"a02-") || strings.HasPrefix(base,"v1-") || strings.HasPrefix(base,"v2-")
					benign:=base=="zz-benign.sh"
					rule:="ts-block-home-redirect"
					if strings.HasPrefix(base,"a") { rule="ts-block-adb-am-start-shell-injection" }
					if strings.HasPrefix(base,"u") { rule="ts-block-ufw-disable"; if strings.HasPrefix(base,"u04-") { rule="ts-block-sudo-alternatives-shell" } }
					// Preserve opaque fixture bytes, and also mirror check
					// --shell-file's removal of one trailing line ending.
					for _,form:=range []struct{name,cmd string}{
						{"file-bytes",string(b)},
						{"cli",strings.TrimSuffix(strings.TrimSuffix(string(b),"\n"),"\r")},
					} { t.Run(form.name,func(t *testing.T){
						n:=normalize.NormalizeCommand(form.cmd,cwd)
						result:=engine.EvaluateWithParsedCwd(form.cmd,n.Paths,n.Parsed,cwd)
						named:=false;for _,r:=range result.TriggeredRules { if r==rule { named=true } }
						// #4441 split the inline-HOME shape into its own rule; for the BLOCK
						// expectation either home-redirect rule counts. Excusal (writeOnly) stays exact.
						if !writeOnly && rule=="ts-block-home-redirect" { for _,r:=range result.TriggeredRules { if r=="ts-block-home-redirect-inline" { named=true } } }
						if writeOnly {
							if result.Decision!=policy.DecisionAudit || named { t.Fatalf("want AUDIT without %s, got %s %v",rule,result.Decision,result.TriggeredRules) }
							if !hasNote(result,analyzer.NoteExcused,rule,"position:interp_heredoc_literal") && !(rule=="ts-block-home-redirect" && hasNote(result,analyzer.NoteExcused,"ts-block-home-redirect-inline","position:interp_heredoc_literal")) { t.Fatalf("missing real-rule excusal note: %v",result.Notes) }
							if strings.HasPrefix(base,"t02-") && !hasNote(result,analyzer.NoteExcused,"ts-block-home-redirect-inline","position:interp_heredoc_literal") { t.Fatalf("inline rule not excused: %v",result.Notes) }
						} else if benign {
							if result.Decision==policy.DecisionBlock { t.Fatalf("benign no-heredoc control BLOCKed: %v",result.TriggeredRules) }
						} else if result.Decision!=policy.DecisionBlock || !named {
							t.Fatalf("want BLOCK by %s, got %s %v",rule,result.Decision,result.TriggeredRules)
						}
					}) }
				})
			}
		})
	}
}
