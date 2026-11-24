package assembly

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"

	"mvdan.cc/sh/v3/syntax"

	"github.com/AI-AgentLens/agentshield/internal/facts"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/psreader"
	"github.com/AI-AgentLens/agentshield/internal/route"
)

// The cmdlet bridge in the lane (PowerShellLane.CmdletBridge, facts.Facts.
// Twins). The texts are DATA: nothing here runs them. Attack spellings are
// assembled at run time, because the hook on a developer machine reads a
// test source it is asked to run as a command.

// twinLane is bridgeLane with the cmdlet bridge: its POSIX reading records
// each text and BLOCKs one that runs `rm -r` on a home directory (a stand-in
// for a bash rule).
func twinLane(t *testing.T, cmdlet bool, seen *[]string) *PowerShellLane {
	l := bridgeLane(t, true, seen)
	l.CmdletBridge = cmdlet
	l.POSIX = func(text string) policy.EvalResult {
		*seen = append(*seen, text)
		if strings.Contains(text, "rm "+"-r") && strings.Contains(text, "~/") {
			return policy.EvalResult{Decision: policy.DecisionBlock, OriginalDecision: policy.DecisionBlock,
				TriggeredRules: []string{"bash-rule"}, Reasons: []string{"bash reason"}, TaxonomyRefs: []string{"bash/taxonomy"}}
		}
		return policy.EvalResult{Decision: policy.DecisionAudit}
	}
	return l
}

// delHome is a recursive delete of a home directory's subdirectory, written
// the Windows way.
func delHome() string { return `Remove-Item -Recurse ` + `$env:USERPROFILE\proj` }

// TestPowerShellLane_CmdletBridge: with CmdletBridge set, the twins are a
// second POSIX text read after the native bridge's, whose BLOCK is the
// call's with the bash rule's record. The native bridge's text is the same
// with and without it. Without it (the control) the call decides as main.
func TestPowerShellLane_CmdletBridge(t *testing.T) {
	text := "git status; " + delHome()

	var seen []string
	r, err := twinLane(t, false, &seen).Read(text)
	if err != nil || r.Decision != policy.DecisionAudit || !slices.Equal(seen, []string{"git status"}) {
		t.Fatalf("control, cmdlet bridge off: %s %v, POSIX saw %q; want AUDIT and only the native bridge's text", r.Decision, err, seen)
	}

	seen = nil
	r, err = twinLane(t, true, &seen).Read(text)
	if err != nil || r.Decision != policy.DecisionBlock {
		t.Fatalf("cmdlet bridge on: %s %v; want the twin's BLOCK", r.Decision, err)
	}
	if !slices.Equal(r.TriggeredRules, []string{"bash-rule"}) || !slices.Equal(r.TaxonomyRefs, []string{"bash/taxonomy"}) {
		t.Errorf("record rules %v taxonomy %v; want the bash reading's", r.TriggeredRules, r.TaxonomyRefs)
	}
	if want := []string{"git status", "git status\nrm -r ~/proj"}; !slices.Equal(seen, want) {
		t.Errorf("POSIX saw %q, want the native text unchanged, then the twins in their place %q", seen, want)
	}

	// No twin anywhere: no second reading.
	seen = nil
	if r, _ := twinLane(t, true, &seen).Read(`git status; Get-ChildItem x`); r.Decision != policy.DecisionAudit || !slices.Equal(seen, []string{"git status"}) {
		t.Errorf("no twin: %s, POSIX saw %q; want one reading", r.Decision, seen)
	}

	// A twin and no native program: only the twins' text.
	seen = nil
	if r, _ := twinLane(t, true, &seen).Read(delHome()); r.Decision != policy.DecisionBlock || !slices.Equal(seen, []string{"rm -r ~/proj"}) {
		t.Errorf("twin alone: %s, POSIX saw %q", r.Decision, seen)
	}

	// Only where the native bridge runs.
	seen = nil
	l := twinLane(t, true, &seen)
	l.NativeBridge = false
	if r, _ := l.Read(text); r.Decision != policy.DecisionAudit || len(seen) != 0 {
		t.Errorf("native bridge off: %s, POSIX saw %q; want no bridge reading", r.Decision, seen)
	}

	// The lane's own BLOCK keeps its record on a tie.
	seen = nil
	r, _ = twinLane(t, true, &seen).Read("Get-Content ~/.s" + "sh/id_rsa; " + delHome())
	if r.Decision != policy.DecisionBlock || len(r.TriggeredRules) == 0 || r.TriggeredRules[0] != "protected-path" {
		t.Errorf("tie: rules %v, want the lane's own protected-path record kept", r.TriggeredRules)
	}
}

// TestPowerShellLane_CmdletBridge_EveryNestingLevel: the twins of every
// level the native bridge reads, in one text: a nested pwsh text, and cmd's
// delete built-ins, which the lane reads as Remove-Item.
func TestPowerShellLane_CmdletBridge_EveryNestingLevel(t *testing.T) {
	for _, c := range []struct{ name, text, twins string }{
		{"pwsh -c", `git status; pwsh -c '` + delHome() + `'`, "git status\nrm -r ~/proj"},
		{"powershell -EncodedCommand", "git status; powershell -enc " + encodePS(delHome()), "git status\nrm -r ~/proj"},
		{"cmd /c rd /s", `cmd /c "rd /s /q %USERPROFILE%\proj"`, "rm -rf ~/proj"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var seen []string
			r, err := twinLane(t, false, &seen).Read(c.text)
			if err != nil || r.Decision == policy.DecisionBlock {
				t.Fatalf("control, cmdlet bridge off: %s %v (POSIX saw %q)", r.Decision, err, seen)
			}
			seen = nil
			r, err = twinLane(t, true, &seen).Read(c.text)
			if err != nil || r.Decision != policy.DecisionBlock || len(seen) == 0 || seen[len(seen)-1] != c.twins {
				t.Errorf("%s %v, POSIX saw %q; want BLOCK on the twins' text %q", r.Decision, err, seen, c.twins)
			}
		})
	}
}

// TestPowerShellLane_TwinPOSIX: TwinPOSIX reads the cmdlet bridge's text of
// a call that is a known read (policy.FactsKnownRead), and its reading is the
// one combined. Every other call's twins are read with POSIX, even when the
// twin text alone is one read: `Get-Content <f>; Clear-Content <f>` leaves
// only the read's `cat` in it, because Clear-Content has no twin (#4841,
// Codex pass 1). nil reads the twins with POSIX, as before.
func TestPowerShellLane_TwinPOSIX(t *testing.T) {
	read := func(text string, withTwin bool) (policy.EvalResult, []string, []string) {
		var seen, twin []string
		l := twinLane(t, true, &seen)
		if withTwin {
			l.TwinPOSIX = func(text string) policy.EvalResult {
				twin = append(twin, text)
				return policy.EvalResult{Decision: policy.DecisionBlock, OriginalDecision: policy.DecisionBlock,
					TriggeredRules: []string{"twin-rule"}, Reasons: []string{"twin reason"}}
			}
		}
		r, err := l.Read(text)
		if err != nil {
			t.Fatal(err)
		}
		return r, seen, twin
	}

	// A known read: the twin goes to TwinPOSIX alone, whose BLOCK (this
	// test's) is the call's, where POSIX's reading of `cat` is AUDIT.
	text := "Get-Content ~/proj/a.txt"
	if !policy.FactsKnownRead(psreader.Read(text, psreader.Env{})) {
		t.Fatalf("precondition: %q is not a known read", text)
	}
	r, seen, _ := read(text, false)
	if r.Decision != policy.DecisionAudit || len(seen) != 1 || !strings.HasPrefix(seen[0], "cat ") {
		t.Fatalf("control, TwinPOSIX nil: %s, POSIX saw %q; want AUDIT on the twin `cat`", r.Decision, seen)
	}
	catText := seen[0]
	r, seen, twin := read(text, true)
	if r.Decision != policy.DecisionBlock || !slices.Equal(r.TriggeredRules, []string{"twin-rule"}) || len(seen) != 0 || !slices.Equal(twin, []string{catText}) {
		t.Errorf("known read, TwinPOSIX set: %s %v, POSIX saw %q, TwinPOSIX saw %q; want TwinPOSIX's BLOCK on %q", r.Decision, r.TriggeredRules, seen, twin, catText)
	}

	// Not a known read: TwinPOSIX is never called, though the twin text is
	// the same one `cat`.
	clear := "Clear" + "-Content ~/proj/a.txt"
	for _, text := range []string{
		"Get-Content ~/proj/a.txt; " + clear,
		"Get-Content ~/proj/a.txt; Get-Date",
	} {
		if policy.FactsKnownRead(psreader.Read(text, psreader.Env{})) {
			t.Fatalf("precondition: %q is a known read", text)
		}
		if r, seen, twin := read(text, true); r.Decision == policy.DecisionBlock || len(twin) != 0 || !slices.Equal(seen, []string{catText}) {
			t.Errorf("%q: %s, POSIX saw %q, TwinPOSIX saw %q; want POSIX alone on %q", text, r.Decision, seen, twin, catText)
		}
	}

	// Native programs, nested bash and a twin that is not a read: all POSIX.
	text = "git status; bash -c 'echo hi'; " + delHome()
	if r, seen, twin := read(text, true); r.Decision != policy.DecisionBlock || len(twin) != 0 || !slices.Equal(seen, []string{"echo hi", "git status", "git status\nrm -r ~/proj"}) {
		t.Errorf("TwinPOSIX set: %s, POSIX saw %q, TwinPOSIX saw %q; want every text on POSIX and its BLOCK", r.Decision, seen, twin)
	}
}

// encodePS is -EncodedCommand's encoding: UTF-16LE, base64.
func encodePS(s string) string {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = append(b, byte(u), byte(u>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}

// TestPowerShellLane_CmdletBridge_Bound: the twins' text is bounded like the
// native bridge's, with its own note, which floors the call at AUDIT.
func TestPowerShellLane_CmdletBridge_Bound(t *testing.T) {
	var seen []string
	l := twinLane(t, true, &seen)
	l.NativeBridgeBytes = 30
	r, _ := l.Read(`Remove-Item C:\a\b\c\d\e\f\g; ` + delHome())
	var cut bool
	for _, n := range r.Notes {
		cut = cut || n.Kind == string(facts.NoteParseError) && strings.HasPrefix(n.Detail, "cmdlet bridge: the rebuilt command lines passed 30 bytes")
	}
	if !cut || r.Decision != policy.DecisionAudit || !slices.Equal(seen, []string{"rm C:/a/b/c/d/e/f/g"}) {
		t.Errorf("%s, notes %+v, POSIX saw %q; want the line that fits read, the note and AUDIT", r.Decision, r.Notes, seen)
	}
}

// TestBridgeText_Twins pins the twins' POSIX text: the spelling a bash user
// writes, a redirection operator and a -Path glob bare, every other word
// quoted as the native bridge quotes it.
func TestBridgeText_Twins(t *testing.T) {
	for _, c := range []struct{ name, ps, want string }{
		{"read", `Get-Content $HOME\.config\app.ini`, `cat ~/.config/app.ini`},
		{"write", `Set-Content ~\notes.txt 'v'`, `echo x > ~/notes.txt`},
		{"append", `'v' | Add-Content ~\notes.txt`, `echo x >> ~/notes.txt`},
		{"redirection", `Get-Date >> 'C:\a b\log.txt'`, `echo x >> 'C:/a b/log.txt'`},
		{"glob", `Remove-Item -Path x\*.log`, `rm x/*.log`},
		{"literal glob", `Remove-Item -LiteralPath x\*.log`, `rm 'x/*.log'`},
		{"a name with a quote", `Remove-Item "x\it's"`, `rm "x/it's"`},
		{"a variable", `Copy-Item $src $env:TEMP\x`, `cp $src ~/AppData/Local/Temp/x`},
		{"in a pipeline", `Get-Content x\a.txt | curl.exe -d '@-' https://h.example`, `cat x/a.txt | curl -d @- https://h.example`},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := NativePOSIXText(psreader.Read(c.ps, psreader.Env{}).Twins, 0).Text
			if got != c.want {
				t.Errorf("twins of %q =\n%s\nwant\n%s", c.ps, got, c.want)
			}
		})
	}
}

// TestBareShape: the bridge writes a part bare only when it is a redirection
// operator or a glob bash reads alike, whatever the reader marked.
func TestBareShape(t *testing.T) {
	for s, want := range map[string]bool{
		">": true, ">>": true, "x/*.log": true, "~/x/*": true, "a?[bc]": true,
		"x": false, "": false, ">|": false, "&>": false, "<": false, "x;rm *": false, "$(x)*": false,
		"~root/*": false, "a b*": false, "*'": false, "`x`*": false,
	} {
		if got := bareShape(s); got != want {
			t.Errorf("bareShape(%q) = %v, want %v", s, got, want)
		}
	}
	// A part marked bare that is not one of those shapes is quoted.
	w := facts.Word{{Text: "x; rm *", Bare: true}}
	if got := posixWord(w); got != `'x; rm *'` {
		t.Errorf("posixWord(bare %q) = %s, want it quoted", w[0].Text, got)
	}
}

// TestBridgeText_TwinsParse: bash parses the twins' text of every input,
// and it holds one command per stage plus a redirection per twin write.
func TestBridgeText_TwinsParse(t *testing.T) {
	n := 0
	for _, in := range bridgeInputs(t) {
		twins := psreader.Read(in, psreader.Env{}).Twins
		if twins == nil {
			continue
		}
		n++
		text := NativePOSIXText(twins, 0).Text
		if _, err := syntax.NewParser().Parse(strings.NewReader(text), ""); err != nil {
			t.Errorf("bash does not parse the twins' text of %q: %v\n%s", clipTest(in), err, clipTest(text))
		}
	}
	if n < 100 {
		t.Errorf("only %d inputs had twins; the check is vacuous", n)
	}
}

// --- The differential over the repo's PowerShell inputs ---------------------

// diffInput is one PowerShell text, where it came from, and whether it is
// harmless (a benign corpus row or a PowerShell rule's TN).
type diffInput struct {
	src, text string
	harmless  bool
}

// harmlessCorpora are the benign corpora of the #4245 experiment checked in
// with the reader (the attack corpus is not one).
var harmlessCorpora = map[string]bool{
	"corpus-agent-oneliners": true, "corpus-agent-scripts": true, "corpus-blind-agent": true,
	"corpus-real": true, "corpus-synthetic": true,
}

// shippedPolicy is DefaultPolicy with every shipped pack, community and
// premium, as a premium install loads them.
func shippedPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	pol, infos, err := policy.LoadPacks(filepath.Join("..", "..", "packs"), policy.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range infos {
		if in.LoadError != nil {
			t.Fatalf("pack %s: %v", in.Path, in.LoadError)
		}
	}
	return pol
}

// diffInputs are the repo's PowerShell texts: every corpus row (the
// experiment's held-out corpus too, when PSREADER_EXPERIMENT_DIR names it),
// the bridge's synthetic shapes, and every PowerShell rule's TP and TN.
func diffInputs(t *testing.T, pol *policy.Policy) []diffInput {
	t.Helper()
	var out []diffInput
	read := func(path, name string) {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for i := 0; sc.Scan(); i++ {
			var row struct{ Command string }
			if json.Unmarshal(sc.Bytes(), &row) == nil && row.Command != "" {
				out = append(out, diffInput{fmt.Sprintf("%s#%d", name, i), row.Command, harmlessCorpora[name]})
			}
		}
	}
	paths, _ := filepath.Glob(filepath.Join("..", "psreader", "testdata", "corpora", "*.jsonl"))
	for _, p := range paths {
		read(p, strings.TrimSuffix(filepath.Base(p), ".jsonl"))
	}
	if dir := os.Getenv("PSREADER_EXPERIMENT_DIR"); dir != "" {
		read(filepath.Join(dir, "corpora", "corpus-heldout.jsonl"), "corpus-heldout")
		harmlessCorpora["corpus-heldout"] = true
		for i := range out {
			out[i].harmless = out[i].harmless || strings.HasPrefix(out[i].src, "corpus-heldout#")
		}
	}
	corpus := len(out)
	all := bridgeInputs(t)
	for _, s := range all[len(all)-11:] { // the synthetic shapes after the corpora
		out = append(out, diffInput{"synthetic", s, false})
	}
	nTN := 0
	for _, r := range pol.Rules {
		if r.Tests == nil || (r.Match.PowerShell == nil && len(r.Match.PowerShellStrings) == 0 && r.Match.PowerShellCalls == nil) {
			continue
		}
		for i, s := range r.Tests.TP {
			out = append(out, diffInput{fmt.Sprintf("%s#tp%d", r.ID, i), s, false})
		}
		for i, s := range r.Tests.TN {
			out = append(out, diffInput{fmt.Sprintf("%s#tn%d", r.ID, i), s, true})
			nTN++
		}
	}
	// The bash BLOCK rules' TPs in the class the bridge reads: a cat, cp,
	// mv, rm or echo command line, which PowerShell runs as the file cmdlet
	// its alias names (the gap the bridge closes, so the raises).
	nBash := 0
	for _, r := range pol.Rules {
		if r.Tests == nil || r.Decision != policy.DecisionBlock || r.Match.PowerShell != nil || len(r.Match.PowerShellStrings) > 0 || r.Match.PowerShellCalls != nil {
			continue
		}
		for i, s := range r.Tests.TP {
			if verb, _, _ := strings.Cut(s, " "); slices.Contains([]string{"cat", "cp", "mv", "rm", "echo"}, verb) {
				out = append(out, diffInput{fmt.Sprintf("bash:%s#tp%d", r.ID, i), s, false})
				nBash++
			}
		}
	}
	// Denominators: the corpora and the rules' tests are there. The floors
	// hold on the community-only tree too (264 bash TPs of the class there).
	if corpus < 440 || nTN < 150 || nBash < 200 {
		t.Fatalf("%d corpus rows, %d PowerShell rule TNs, %d bash TPs: the inputs moved?", corpus, nTN, nBash)
	}
	return out
}

// diffRow is one input read three ways: the cmdlet bridge off (main's
// reading), on, and the prototype's design, which joined the twins into the
// native bridge's text (the control).
type diffRow struct {
	in                     diffInput
	off, on, joined        policy.EvalResult
	offSeen, onSeen, jSeen []string
	// twinned: some level of the text the lane read had a twin.
	twinned bool
}

var (
	diffOnce sync.Once
	diffRows []diffRow
	diffErr  error
)

// cmdletDifferential reads every input with the shipped packs and the
// POSIX pipeline on the lane's engine, the way shield-server reads a nested
// text (no enterprise middleware; the hook-level tests cover it).
func cmdletDifferential(t *testing.T) []diffRow {
	t.Helper()
	diffOnce.Do(func() {
		pol := shippedPolicy(t)
		engine, err := ShellEngine(pol, 2, "")
		if err != nil {
			diffErr = err
			return
		}
		const home = "/home/u"
		lane := func(cmdlet, joined bool, seen *[]string, twinned *bool) *PowerShellLane {
			l := &PowerShellLane{Engine: engine, Env: psreader.Env{Home: home}, Opts: policy.FactsOptions{Home: home},
				Cwd: home, MaxDepth: 2, NativeBridge: true, CmdletBridge: cmdlet,
				POSIX: func(text string) policy.EvalResult {
					*seen = append(*seen, text)
					n := normalize.NormalizeCommand(text, home)
					return engine.EvaluateWithParsedCwd(text, n.Paths, n.Parsed, home)
				}}
			l.Reader = func(text string, env psreader.Env) facts.Facts {
				f := psreader.Read(text, env)
				if f.Twins != nil {
					*twinned = true
					if joined {
						f.Native = f.Twins
					}
				}
				return f
			}
			return l
		}
		for _, in := range diffInputs(t, pol) {
			var row diffRow
			row.in = in
			var e1, e2, e3 error
			var ignored bool
			row.off, e1 = lane(false, false, &row.offSeen, &ignored).Read(in.text)
			row.on, e2 = lane(true, false, &row.onSeen, &row.twinned).Read(in.text)
			row.joined, row.jSeen = row.off, row.offSeen // with no twin, the joined design is main's
			if row.twinned {
				row.jSeen = nil
				row.joined, e3 = lane(false, true, &row.jSeen, &ignored).Read(in.text)
			}
			if e1 != nil || e2 != nil || e3 != nil {
				diffErr = fmt.Errorf("%s: %v %v %v", in.src, e1, e2, e3)
				return
			}
			diffRows = append(diffRows, row)
		}
	})
	if diffErr != nil {
		t.Fatal(diffErr)
	}
	return diffRows
}

func rank(r policy.EvalResult) int {
	return route.Rank(route.Verdict{Decision: string(r.Decision), OriginalDecision: string(r.OriginalDecision)})
}

// TestCmdletBridge_NativeTextIsMains: for every input, the native bridge's
// text, the first text the lane hands POSIX after the nested ones, is byte
// for byte what it is with the cmdlet bridge off, and the twins add at most
// one reading after it. Facts.Native carries no bare part. The control: the
// prototype's design, the twins joined into the native text, changes it.
func TestCmdletBridge_NativeTextIsMains(t *testing.T) {
	rows := cmdletDifferential(t)
	extra, joinedChanged := 0, 0
	for _, r := range rows {
		if len(r.onSeen) < len(r.offSeen) || !slices.Equal(r.onSeen[:len(r.offSeen)], r.offSeen) {
			t.Errorf("%s: POSIX texts with the cmdlet bridge %q, without %q: main's texts changed", r.in.src, r.onSeen, r.offSeen)
			continue
		}
		switch n := len(r.onSeen) - len(r.offSeen); {
		case n > 1:
			t.Errorf("%s: %d extra POSIX readings, want at most the twins' one", r.in.src, n)
		case n == 1 && !r.twinned:
			t.Errorf("%s: a twins' reading %q for a text with no twin", r.in.src, r.onSeen[len(r.onSeen)-1])
		case n == 1:
			extra++
		}
		if !slices.Equal(r.jSeen, r.offSeen) {
			joinedChanged++
		}
		for _, st := range psreader.Read(r.in.text, psreader.Env{}).Native {
			for _, p := range st.Pipelines {
				for _, argv := range p.Stages {
					for _, w := range argv {
						for _, part := range w {
							if part.Bare {
								t.Errorf("%s: Facts.Native has a bare part %q", r.in.src, part.Text)
							}
						}
					}
				}
			}
		}
	}
	t.Logf("%d inputs, %d with a twins' reading; the joined design changed main's texts on %d", len(rows), extra, joinedChanged)
	if extra < 150 {
		t.Errorf("only %d inputs had a twins' reading: the check is vacuous", extra)
	}
	if joinedChanged == 0 {
		t.Errorf("control: the joined design changed no native text, so this test cannot see the break")
	}
}

// TestCmdletBridge_RaiseOnly: on every input, the lane decides at least what
// it decides with the cmdlet bridge off, before and after any audit-only
// downgrade. The control: the prototype's joined design lowers some.
func TestCmdletBridge_RaiseOnly(t *testing.T) {
	rows := cmdletDifferential(t)
	raised, joinedLowered := 0, []string{}
	for _, r := range rows {
		if rank(r.on) < rank(r.off) || decisionRank(string(r.on.Decision)) < decisionRank(string(r.off.Decision)) {
			t.Errorf("%s: %s %v with the cmdlet bridge, %s %v without: lowered\n  %s",
				r.in.src, r.on.Decision, r.on.TriggeredRules, r.off.Decision, r.off.TriggeredRules, clipTest(r.in.text))
		}
		if rank(r.on) > rank(r.off) {
			raised++
		}
		if rank(r.joined) < rank(r.off) {
			joinedLowered = append(joinedLowered, r.in.src)
		}
	}
	t.Logf("%d inputs: %d raised; the joined design lowered %d: %v", len(rows), raised, len(joinedLowered), joinedLowered)
	if raised < 100 { // 236 on the tree with premium packs
		t.Errorf("only %d inputs raised: the cmdlet bridge closes too little for this to be a differential", raised)
	}
	if len(joinedLowered) == 0 {
		t.Errorf("control: the joined design lowered nothing, so this test cannot see a lowering")
	}
}

func decisionRank(d string) int {
	return route.Rank(route.Verdict{Decision: d})
}

// cmdletBridgeResidualTNs are the harmless inputs the cmdlet bridge BLOCKs,
// each with why (Gary, 2026-11-07: pin, don't fix).
var cmdletBridgeResidualTNs = map[string]string{
	// `Add-Content ~/.bashrc.bak 'x'` is `echo x >> ~/.bashrc.bak`, which
	// ts-block-shell-profile-append BLOCKs on bash too: its echo/printf/cat
	// alternative keeps main's unbounded tail on purpose (#4699), so
	// `.bashrc.bak` matches `.bashrc`. The bridge imports that bash FP.
	// Fixing it is a narrowing of the bash rule (critical set), not this
	// change.
	"ps-block-shell-profile-write#tn4": "ts-block-shell-profile-append",
	// `Set-Content ~/.claude/settings.json.bak '{}'` is `echo x >
	// ~/.claude/settings.json.bak`, the same class: the bash rule's
	// `settings(?:\.local)?\.json` has no end anchor, so it BLOCKs the
	// backup on bash too. Its PowerShell twin's TN came with #4833, after the
	// prototype's measurement. Pinned like the one above, pending Gary's call.
	"ps-block-agent-settings-write#tn3": "ts-block-agent-settings-write",
}

// TestCmdletBridge_NoNewBlockOnHarmlessInputs: on every benign corpus row
// and every PowerShell rule's TN, the cmdlet bridge adds no BLOCK, except
// the pinned residuals, which BLOCK by exactly their named rule.
// TestPowerShellRuleYAMLTests grades only the PowerShell rule's own
// matcher, so it cannot see a BLOCK the bridge adds to its TN.
func TestCmdletBridge_NoNewBlockOnHarmlessInputs(t *testing.T) {
	rows := cmdletDifferential(t)
	harmless, exposed := 0, 0
	pinned := map[string]bool{}
	for _, r := range rows {
		if !r.in.harmless {
			continue
		}
		harmless++
		if r.twinned {
			exposed++
		}
		if r.on.Decision != policy.DecisionBlock || r.off.Decision == policy.DecisionBlock {
			continue
		}
		if rule, ok := cmdletBridgeResidualTNs[r.in.src]; ok && slices.Contains(r.on.TriggeredRules, rule) {
			pinned[r.in.src] = true
			continue
		}
		t.Errorf("%s: a new BLOCK %v on a harmless input\n  %s", r.in.src, r.on.TriggeredRules, clipTest(r.in.text))
	}
	for src, rule := range cmdletBridgeResidualTNs {
		if !pinned[src] {
			t.Errorf("pinned residual %s no longer BLOCKs by %s: update the pin (and .claude/agent-notes/tool-routing.md)", src, rule)
		}
	}
	t.Logf("%d harmless inputs, %d with a twin", harmless, exposed)
	if exposed < 100 {
		t.Errorf("only %d harmless inputs have a twin: the check is vacuous", exposed)
	}
}
