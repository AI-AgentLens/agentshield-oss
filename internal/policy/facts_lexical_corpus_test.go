package policy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/psreader"
)

// lexicalHarmlessCorpora are the psreader corpora of agent and real-world
// PowerShell (corpus-attack is the one that is not).
var lexicalHarmlessCorpora = map[string]bool{
	"corpus-agent-oneliners": true, "corpus-agent-scripts": true, "corpus-blind-agent": true,
	"corpus-real": true, "corpus-synthetic": true,
}

type lexicalInput struct {
	src, text string
	harmless  bool
}

// lexicalInputs are every psreader corpus row and every PowerShell rule's TP
// and TN in the shipped packs.
func lexicalInputs(t *testing.T, pol *Policy) []lexicalInput {
	t.Helper()
	var out []lexicalInput
	paths, _ := filepath.Glob(filepath.Join("..", "psreader", "testdata", "corpora", "*.jsonl"))
	for _, p := range paths {
		name := strings.TrimSuffix(filepath.Base(p), ".jsonl")
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for i := 0; sc.Scan(); i++ {
			var row struct{ Command string }
			if json.Unmarshal(sc.Bytes(), &row) == nil && row.Command != "" {
				out = append(out, lexicalInput{fmt.Sprintf("%s#%d", name, i), row.Command, lexicalHarmlessCorpora[name]})
			}
		}
		f.Close()
	}
	corpus := len(out)
	for _, r := range pol.Rules {
		if r.Tests == nil || (r.Match.PowerShell == nil && len(r.Match.PowerShellStrings) == 0 && r.Match.PowerShellCalls == nil) {
			continue
		}
		for i, s := range r.Tests.TP {
			out = append(out, lexicalInput{fmt.Sprintf("%s#tp%d", r.ID, i), s, false})
		}
		for i, s := range r.Tests.TN {
			out = append(out, lexicalInput{fmt.Sprintf("%s#tn%d", r.ID, i), s, true})
		}
	}
	if corpus < 440 || len(out)-corpus < 300 {
		t.Fatalf("%d corpus rows, %d rule tests: the inputs moved?", corpus, len(out)-corpus)
	}
	return out
}

// TestEvaluateFacts_LexicalReading_NoNewBlockOnHarmlessInputs (#4830): over
// every repo PowerShell text, with the shipped packs, on a POSIX and a
// Windows home, managed and not, the lexical reading adds no BLOCK to a
// harmless input and never lowers anything. Its exposure is counted, so a
// reading that never applies cannot pass this vacuously.
func TestEvaluateFacts_LexicalReading_NoNewBlockOnHarmlessInputs(t *testing.T) {
	engine, pol := packsEngine(t)
	inputs := lexicalInputs(t, pol)
	harmless, exposed, raised := 0, 0, 0
	for _, home := range []string{"/home/u", psHome} {
		for _, managed := range []bool{false, true} {
			opt := FactsOptions{Managed: managed, Home: home}
			cwd := filepath.ToSlash(home)
			if !strings.HasPrefix(cwd, "/") {
				cwd = "/home/u" // the engine reads cwd as a POSIX path
			}
			for _, in := range inputs {
				f := psreader.Read(in.text, psreader.Env{Home: home})
				if _, ok := factsLexicalReading(f, home, factsPWD(f, cwd)); !ok {
					continue
				}
				exposed++
				asWritten := engine.evaluateFactsReading(f, cwd, opt, home)
				got := engine.EvaluateFacts(f, cwd, opt)
				if preDowngradeRank(got) < preDowngradeRank(asWritten) {
					t.Errorf("home=%s managed=%v %s: lowered %s %v -> %s %v", home, managed, in.src, asWritten.Decision, asWritten.TriggeredRules, got.Decision, got.TriggeredRules)
				}
				if preDowngradeRank(got) > preDowngradeRank(asWritten) {
					raised++
					if in.harmless {
						t.Errorf("home=%s managed=%v %s: a new %s %v on a harmless input\n  %.300s", home, managed, in.src, got.Decision, got.TriggeredRules, in.text)
					} else {
						t.Logf("raised: home=%s managed=%v %s: %s %v -> %s %v", home, managed, in.src, asWritten.Decision, asWritten.TriggeredRules, got.Decision, got.TriggeredRules)
					}
				}
				if in.harmless {
					harmless++
				}
			}
		}
	}
	t.Logf("%d input readings had a second reading (%d harmless), %d raised", exposed, harmless, raised)
	if harmless < 100 {
		t.Errorf("only %d harmless input readings have a lexical reading: the check is vacuous", harmless)
	}
}
