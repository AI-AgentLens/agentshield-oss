package guardian

import "testing"

// fstring4611Fire are commands that must raise eval_risk. The last four rows are
// #4621's probes: a and c decided AUDIT when #4619 spliced f-string field text
// back in place, and b and d are their controls, which BLOCKed throughout.
var fstring4611Fire = []struct{ name, cmd string }{
	{"control: bare eval", `python3 -c "x=eval(input())"`},
	{"f-string single quote", `python3 -c "x=f'{eval(input())}'"`},
	{"f-string escaped double quote", `python3 -c "x=f\"{eval(input())}\""`},
	{"F-string uppercase prefix", `python3 -c "x=F'{eval(input())}'"`},
	{"rf-string", `python3 -c "x=rf'{eval(input())}'"`},
	{"fr-string", `python3 -c "x=fr'{exec(input())}'"`},
	{"text before field", `python3 -c "x=f'out: {eval(input())} done'"`},
	{"literal brace then field", `python3 -c "x=f'{{ok}} {eval(input())}'"`},
	{"nested field", `python3 -c "x=f'{str(eval(input()))}'"`},
	{"second field", `python3 -c "x=f'{a} {eval(input())}'"`},
	{"triple-quoted f-string", `python3 -c "x=f'''{eval(input())}'''"`},
	{"heredoc f-string", "python3 << 'EOF'\nx = f'{eval(input())}'\nEOF"},
	{"4621 probe a: field holding << before a real eval", `python3 -c "x=f'{1<<2}'; eval(input())"`},
	{"4621 control b: same shape without <<", `python3 -c "x=f'{1+2}'; eval(input())"`},
	{"4621 probe c: field holding a lone quote before a real eval", `python3 -c "x=f'''{\"'\"}'''; eval(input()); y='z'"`},
	{"4621 control d: same shape without the lone quote", `python3 -c "x=f'''{\"q\"}'''; eval(input()); y='z'"`},
}

// fstring4611Quiet are commands whose eval/exec text is string data only.
var fstring4611Quiet = []struct{ name, cmd string }{
	{"plain string data", `python3 -c "x='eval(input())'"`},
	{"f-string literal text only", `python3 -c "x=f'eval(input()) is {name}'"`},
	{"escaped braces are literal", `python3 -c "x=f'{{eval(input())}}'"`},
	{"identifier ending in f is not a prefix", `python3 -c "pdf'{eval(input())}'"`},
	{"triple-quoted data", `python3 -c "code = '''eval(input())'''; print(len(code))"`},
}

// TestHeuristicProvider_EvalRisk_FStringFields4611 pins that eval/exec inside an
// f-string replacement field is a call site (Python evaluates it), while the
// literal text of the same f-string, and plain strings, stay data.
func TestHeuristicProvider_EvalRisk_FStringFields4611(t *testing.T) {
	p := NewHeuristicProvider()

	for _, tc := range fstring4611Fire {
		t.Run("fires/"+tc.name, func(t *testing.T) {
			resp, err := p.Analyze(GuardianRequest{RawCommand: tc.cmd})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !hasSignal(resp.Signals, "eval_risk") {
				t.Errorf("expected eval_risk:\n  %s", tc.cmd)
			}
		})
	}

	for _, tc := range fstring4611Quiet {
		t.Run("quiet/"+tc.name, func(t *testing.T) {
			resp, err := p.Analyze(GuardianRequest{RawCommand: tc.cmd})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if hasSignal(resp.Signals, "eval_risk") {
				t.Errorf("unexpected eval_risk:\n  %s", tc.cmd)
			}
		})
	}
}
