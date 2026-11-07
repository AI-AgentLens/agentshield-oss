package enterprise

import (
	"strconv"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// #4631: matchesSetupDisable returned "no match" whenever the bash parse
// failed, and one zsh-only statement is enough to make it fail. These tests
// use only symbols that exist on main (matchesSetupDisable,
// matchesSelfProtectRule, shellparse), so they also run there: the twins and
// the token-scan rows fail on main and the controls pass.

// zshTwinForms are zsh-only spellings of a command: the bash parser rejects
// each one and the zsh parser accepts it, so shellparse.ZshReading gives a
// reading (#4598). zsh runs the command they wrap.
var zshTwinForms = []struct {
	name string
	wrap func(string) string
}{
	{"zsh no-op prefix", func(c string) string { return ": ${(U)HOME}; " + c }},
	{"brace group", func(c string) string { return "{ " + c + " }" }},
	{"anonymous function", func(c string) string { return "() { " + c + " }" }},
}

// zshTwinSkips are the twins that are not a zsh-only spelling of their row.
// zshTwins fails on a twin that is not zsh-only and not listed here, and on a
// listed one that is, so the list cannot go stale.
var zshTwinSkips = map[string]string{
	"subshell/brace group":       "the bash parser accepts `{ (C) }`, so it is not a zsh-only twin",
	"comment/brace group":        "the comment swallows the closing brace and neither parser accepts the twin; see the token-scan rows",
	"comment/anonymous function": "the comment swallows the closing brace and neither parser accepts the twin; see the token-scan rows",
}

// allSetupDisableRows is every matchesSetupDisable expectation the package
// tables hold: TestMatchesSetupDisable's rows, its bool spellings and the
// discovery rows.
func allSetupDisableRows(t *testing.T) []setupDisableRow {
	t.Helper()
	rows := append([]setupDisableRow(nil), setupDisableRows...)
	for _, value := range []string{"1", "t", "T", "TRUE", "true", "True", "0", "f", "F", "FALSE", "false", "False"} {
		want, err := strconv.ParseBool(value)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, setupDisableRow{"bool=" + value, "agentshield setup --disable=" + value + " mcp", want})
	}
	for _, r := range setupDisableDiscoveryRows {
		rows = append(rows, setupDisableRow{"discovery " + r.name, r.cmd(), r.match})
	}
	return rows
}

// zshTwin is a row wrapped in a zsh-only form.
type zshTwin struct {
	name string
	row  setupDisableRow
	cmd  string
}

// zshTwins wraps every row that parses as bash in every zsh-only form. A row
// that does not parse is a token-scan row, not a twin source.
func zshTwins(t *testing.T) []zshTwin {
	t.Helper()
	var twins []zshTwin
	used := map[string]bool{}
	for _, row := range allSetupDisableRows(t) {
		if p := shellparse.Parse(row.cmd, 0); p == nil || p.Fallback {
			continue
		}
		for _, form := range zshTwinForms {
			name := row.name + "/" + form.name
			cmd := form.wrap(row.cmd)
			zshOnly := shellparse.Parse(cmd, 0).Fallback && shellparse.ZshReading(cmd) != ""
			if why, skip := zshTwinSkips[name]; skip {
				used[name] = true
				if zshOnly {
					t.Errorf("twin %q (%q) is zsh-only now; remove its skip (%s)", name, cmd, why)
				}
				continue
			}
			if !zshOnly {
				t.Errorf("twin %q (%q) is not zsh-only: the bash parser accepts it or ZshReading gives no reading", name, cmd)
				continue
			}
			twins = append(twins, zshTwin{name, row, cmd})
		}
	}
	for name := range zshTwinSkips {
		if !used[name] {
			t.Errorf("skip %q names no twin", name)
		}
	}
	if len(twins) < 200 {
		t.Fatalf("only %d zsh twins; the tables shrank or the forms stopped being zsh-only", len(twins))
	}
	return twins
}

// Every row decides the same behind a zsh-only statement as it does as
// written: a TP twin still matches, a TN twin still does not.
func TestMatchesSetupDisable_ZshTwins_4631(t *testing.T) {
	for _, tw := range zshTwins(t) {
		t.Run(tw.name, func(t *testing.T) {
			if got := matchesSetupDisable(tw.cmd); got != tw.row.want {
				t.Errorf("matchesSetupDisable(%q) = %v, want %v (as written: %q)", tw.cmd, got, tw.row.want, tw.row.cmd)
			}
		})
	}
}

// The same twins through every self-protection reading: a zsh-only statement
// may not change the decision or the rule id the as-written command gets.
// On main the TP twins that only the argv walk caught fail here; that list is
// what #4631 exposed.
func TestSelfProtect_SetupDisable_ZshTwinParity_4631(t *testing.T) {
	for _, tw := range zshTwins(t) {
		t.Run(tw.name, func(t *testing.T) {
			wantID, wantOK := matchesSelfProtectRule(tw.row.cmd)
			if tw.row.want && (!wantOK || wantID != "sp-block-setup-disable") {
				t.Fatalf("control: matchesSelfProtectRule(%q) = (%q, %v), want sp-block-setup-disable", tw.row.cmd, wantID, wantOK)
			}
			if id, ok := matchesSelfProtectRule(tw.cmd); id != wantID || ok != wantOK {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, %v), want (%q, %v) as for %q", tw.cmd, id, ok, wantID, wantOK, tw.row.cmd)
			}
		})
	}
}

// The other self-protection rules lean on the dequoted and unset-param-folded
// readings, which need a bash parse too: behind a zsh-only statement a quote
// or unset-parameter splice matched no rule on main. Each base command
// matches only through one of those readings (its raw text matches nothing),
// so the twin isolates the reading.
func TestSelfProtect_OtherRulesZshTwins_4631(t *testing.T) {
	for _, tc := range []struct{ cmd, id string }{
		{"rm -rf ~/.agentshi'e'ld", "sp-block-delete-config"},
		{"rm -rf ~/.agentshi${zqx}eld", "sp-block-delete-config"},
		{"export AGENTSHIELD_BYPA'S'S=1", "sp-block-bypass-env"},
		{"export AGENTSHIELD_BYPA${zqx}SS=1", "sp-block-bypass-env"},
		{"rm ~/.claude/settings.j'so'n", "sp-block-delete-hooks"},
		{"tee ~/.agentshi'e'ld/policy.yaml < /tmp/p", "sp-block-policy-write"},
		{"brew uninstall --cask agentshi'e'ld", "sp-block-brew-uninstall"},
		{"cp /tmp/x /usr/local/bin/agentshi'e'ld", "sp-block-binary-replace"},
		{"python3 -c 1 ~/.agentshi'e'ld/managed.json", "sp-block-config-touch"},
	} {
		for _, rule := range selfProtectRules {
			if rule.Pattern.MatchString(tc.cmd) {
				t.Fatalf("base %q matches %s as raw text; it must match only through a reading", tc.cmd, rule.ID)
			}
		}
		if id, ok := matchesSelfProtectRule(tc.cmd); !ok || id != tc.id {
			t.Fatalf("control: matchesSelfProtectRule(%q) = (%q, %v), want %s", tc.cmd, id, ok, tc.id)
		}
		for _, form := range zshTwinForms {
			if strings.HasPrefix(tc.cmd, "export ") && form.name != "zsh no-op prefix" {
				// TestSelfProtect_DeclarationInBraceGroupIsAResidual_4631.
				continue
			}
			cmd := form.wrap(tc.cmd)
			t.Run(tc.id+"/"+form.name+"/"+tc.cmd, func(t *testing.T) {
				if !shellparse.Parse(cmd, 0).Fallback || shellparse.ZshReading(cmd) == "" {
					t.Fatalf("twin %q is not zsh-only", cmd)
				}
				if id, ok := matchesSelfProtectRule(cmd); !ok || id != tc.id {
					t.Errorf("matchesSelfProtectRule(%q) = (%q, %v), want %s", cmd, id, ok, tc.id)
				}
			})
		}
	}
	// Controls: a zsh-only statement next to commands no rule names stays
	// unmatched, including reads and mentions of agentshield.
	for _, cmd := range []string{
		": ${(U)HOME}; echo hello",
		"{ ls ~/.agentshield }",
		"() { agentshield status }",
		": ${(U)HOME}; cat ~/.agentshield/audit.log",
	} {
		t.Run("control/"+cmd, func(t *testing.T) {
			if id, ok := matchesSelfProtectRule(cmd); ok {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, true), want no match", cmd, id)
			}
		})
	}
}

// A declaration builtin as the last statement of a brace group with no
// separator (`{ export X=1 }`) is rejected by the zsh parser too, the dialect
// gap #4598 budgets. With no parse there is no dequoted or folded reading, so
// a spliced spelling of the bypass variable matches no rule here. BypassGuard
// ignores the variable in managed mode whatever its spelling, so what is lost
// is the self-protection BLOCK and its record, not the bypass itself. Pinned
// so that closing it (a tolerant de-splice reading for the regex rules, as
// namesAgentshieldSetup does for setup) is a deliberate change.
func TestSelfProtect_DeclarationInBraceGroupIsAResidual_4631(t *testing.T) {
	for _, cmd := range []string{
		"{ export AGENTSHIELD_BYPA'S'S=1 }",
		"() { export AGENTSHIELD_BYPA${zqx}SS=1 }",
	} {
		t.Run(cmd, func(t *testing.T) {
			if !shellparse.Parse(cmd, 0).Fallback || shellparse.ZshReading(cmd) != "" {
				t.Fatalf("%q has a reading now; move it to TestSelfProtect_OtherRulesZshTwins_4631", cmd)
			}
			if id, ok := matchesSelfProtectRule(cmd); ok {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, true); the residual closed, update this pin", cmd, id)
			}
		})
	}
	// The plain spelling still matches as raw text.
	if id, ok := matchesSelfProtectRule("{ export AGENTSHIELD_BYPASS=1 }"); !ok || id != "sp-block-bypass-env" {
		t.Errorf("control: plain spelling = (%q, %v), want sp-block-bypass-env", id, ok)
	}
}

// When no reading parses, the token scan decides (#4631 part 2). Every row is
// checked to be a command neither parser accepts, so the rows test the scan
// and not a reading. `for i (1) C` is zsh's short for loop: real zsh runs C,
// and the pinned zsh parser (mvdan.cc/sh v3.14.1, syntax.LangZsh) rejects it
// (#4598's measured residual).
var setupDisableNoReadingRows = []setupDisableRow{
	{"short for", "for i (1) agentshield setup --disable mcp", true},
	{"short for, flag order", "for i (1) agentshield setup mcp --mode=enforce --disable", true},
	{"short for, value flag first", "for i (1) agentshield --mode enforce setup mcp --disable", true},
	{"short for, empty-quote splices", "for i (1) agent''shield set''up mcp --disable", true},
	{"short for, quote splices", "for i (1) agent'shield' se'tup' mcp --disa'ble'", true},
	{"short for, double-quote splices", `for i (1) agent"shield" se"tup" mcp --disable`, true},
	{"short for, unset splices", "for i (1) agentshi${zqx}eld se${zqx}tup mcp --disable", true},
	// Review round 2 on #4634: deletion lost the static expansion word.
	{"short for, default setup", "for i (1) agentshield ${zqx:-setup} --disable mcp", true},
	{"short for, default setup without colon", "for i (1) agentshield ${zqx-setup} --disable mcp", true},
	{"short for, default binary", "for i (1) ${zqx:-agentshield} setup --disable mcp", true},
	{"short for, alternate setup", "for i (1) agentshield ${zqx:+setup} --disable mcp", true},
	{"short for, alternate setup without colon", "for i (1) agentshield ${zqx+setup} --disable mcp", true},
	{"short for, positional default", "for i (1) agentshield ${1:-setup} --disable mcp", true},
	{"short for, special parameter alternate", "for i (1) agentshield ${@:+setup} --disable mcp", true},
	{"short for, assignment setup", "for i (1) agentshield ${zqx:=setup} --disable mcp", true},
	{"short for, assignment setup without colon", "for i (1) agentshield ${zqx=setup} --disable mcp", true},
	{"short for, default splices", "for i (1) agent${zqx:-shield} se${other:-tup} --disable mcp", true},
	{"short for, quoted default", "for i (1) agentshield ${zqx:-'se'\"tup\"} --disable mcp", true},
	{"short for, decoded default", "for i (1) agentshield ${zqx:-$'se\\x74up'} --disable mcp", true},
	{"short for, continued default", "for i (1) agentshield ${zqx:\\\n-setup} --disable mcp", true},
	{"short for, both default words", "for i (1) ${zqx:-agentshield} ${other:-setup} --disable mcp", true},
	{"short for, expansion inside the default word", "for i (1) agentshield ${zqx:-setup$y} --disable mcp", true},
	// Retaining the word must not replace the old deletion candidate.
	{"short for, deleted default splice", "for i (1) agentshi${zqx:-noise}eld setup --disable mcp", true},
	{"short for, deleted alternate splice", "for i (1) agentshield se${zqx:+noise}tup --disable mcp", true},
	// An earlier single-quoted dollar opens a false ANSI-C span. Raw
	// scanning must survive the decoder turning \a or \t into controls.
	{"short for, false ANSI-C span in binary", `for i (1) X='x$' \agentshield setup --disable mcp ''`, true},
	{"short for, false ANSI-C span in setup", `for i (1) X='x$' agentshield se\tup --disable mcp ''`, true},
	{"short for, false ANSI-C span with default", `for i (1) X='x$' \agentshield ${zqx:-setup} --disable mcp ''`, true},
	{"short for, bare unset splice", "for i (1) agent$zqx'shield' setup mcp --disable", true},
	{"short for, backslash splices", `for i (1) agent\shield se\tup mcp --disable`, true},
	{"short for, ANSI-C quoted", "for i (1) $'agentshield' $'setup' mcp --disable", true},
	{"short for, absolute path", "for i (1) /opt/bin/agentshield setup --disable mcp", true},
	{"short for, home path", "for i (1) ~/bin/agentshield setup --disable mcp", true},
	{"short for, quoted path", `for i (1) "/opt/Agent Shield/agentshield" setup --disable mcp`, true},
	{"short for, zsh EQUALS", "for i (1) =agentshield setup --disable mcp", true},
	{"short for, brace expansion", "for i (1) {agentshield,setup,mcp,--disable}", true},
	{"short for, wrapper", "for i (1) env agentshield setup --disable mcp", true},
	{"short for, backslash-newline splice", "for i (1) agent\\\nshield setup --disable mcp", true},
	{"short for, after another command", "for i (1) echo ready; agentshield setup --disable mcp", true},
	{"short for, in a substitution", "for i (1) echo $(agentshield setup --disable mcp)", true},
	// ANSI-C quoting is decoded before the strip, with the argv path's
	// decoder (review round 1 on #4634, Codex): zsh runs setup.
	{"short for, ANSI-C hex", "for i (1) agentshield $'se\\x74up' --disable mcp", true},
	{"short for, ANSI-C octal", "for i (1) agentshield $'se\\164up' --disable mcp", true},
	{"short for, ANSI-C \\u", "for i (1) agentshield $'se\\u0074up' --disable mcp", true},
	{"short for, ANSI-C \\U", "for i (1) agentshield $'se\\U00000074up' --disable mcp", true},
	{"short for, ANSI-C escape in the name", "for i (1) $'agent\\x73hield' setup --disable mcp", true},
	// Separators the scan must split on (review round 1, Opus mutants).
	{"short for, backtick substitution", "for i (1) echo `agentshield setup --disable mcp`", true},
	{"short for, newline-separated statement", "for i (1) echo hi\nagentshield setup --disable mcp", true},
	// Fail-closed on purpose: without a parse `--disable` cannot be
	// enumerated, so the two words are enough.
	{"short for, no flag", "for i (1) agentshield setup mcp", true},
	{"unterminated quote", "agentshield setup --disable mcp '", true},
	// bash runs the first line before it reaches the broken second one.
	{"broken second line", "echo $(agentshield setup --disable mcp)\n'", true},
	// The accepted false-positive shape: text that only mentions the two
	// words. zsh runs nothing from text it cannot parse, so this blocks a
	// command that would not have run.
	{"comment swallows the brace", "{ agentshield setup mcp # --disable }", true},
	{"mention in unparseable text", "for i (1) echo 'agentshield setup is how you install'", true},

	{"ordinary setup mention", "for i (1) echo 'setup is documented here'", false},
	{"default setup alone", "for i (1) echo ${zqx:-setup}", false},
	{"alternate setup alone", "for i (1) echo ${zqx:+setup}", false},
	{"default different subcommand", "for i (1) agentshield ${zqx:-status} --disable", false},
	{"alternate different subcommand", "for i (1) ${zqx:+agentshield} status --disable", false},
	{"default different binary", "for i (1) ${zqx:-other-agentshield} setup --disable", false},
	{"default setup before binary", "for i (1) echo ${zqx:-setup}; agentshield status", false},
	{"default setup prefix", "for i (1) agentshield ${zqx:-setupx} --disable", false},
	{"default directory", "for i (1) ${zqx:-/opt/agentshield/} setup --disable", false},
	{"error word is not a default", "for i (1) agentshield ${zqx:?ignored-setup} --disable", false},
	// zsh errors out on an unset `:?` and runs nothing, so its word is never
	// the argument (review of #4639: the row above could not catch `?` in the
	// retained-word operators).
	{"error word setup is not a default", "for i (1) agentshield ${zqx:?setup} --disable mcp", false},
	// Pinned residual (review of #4639): a false `$'` span followed by an
	// ANSI-C-encoded word. zsh runs setup, and no reading decodes the word
	// without the false span: the decoded text loses it to the span and the
	// raw text never decodes. Main decides the same. Closing it flips this row.
	{"residual: false ANSI-C span before an ANSI-C word", `for i (1) X='x$' agentshield $'se\x74up' --disable mcp`, false},
	{"false ANSI-C span without binary", `for i (1) X='x$' echo se\tup ''`, false},
	{"false ANSI-C span different subcommand", `for i (1) X='x$' \agentshield status ''`, false},

	{"agentshield alone", "for i (1) agentshield status --disable", false},
	{"agentshield alone, unterminated quote", "agentshield status --disable '", false},
	{"setup alone", "for i (1) echo setup --disable", false},
	{"setup before agentshield", "for i (1) echo setup; agentshield status --disable", false},
	{"different binary", "for i (1) other-agentshield setup --disable mcp", false},
	{"directory", "for i (1) /opt/agentshield/ setup --disable mcp", false},
	{"one word", "for i (1) agentshield-setup --disable", false},
	{"joined words", "for i (1) echo agentshieldsetup", false},
	{"setup prefix", "for i (1) agentshield setupx --disable", false},
	{"no agentshield", "for i (1) echo hello '", false},
}

func TestMatchesSetupDisable_NoReadingTokenScan_4631(t *testing.T) {
	for _, tc := range setupDisableNoReadingRows {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := syntax.NewParser(syntax.Variant(syntax.LangZsh)).Parse(strings.NewReader(tc.cmd), ""); err == nil {
				t.Fatalf("the zsh parser accepts %q; the row does not reach the token scan", tc.cmd)
			}
			if !shellparse.Parse(tc.cmd, 0).Fallback || shellparse.ZshReading(tc.cmd) != "" {
				t.Fatalf("%q has a reading; the row does not reach the token scan", tc.cmd)
			}
			if got := namesAgentshieldSetup(tc.cmd); got != tc.want {
				t.Errorf("namesAgentshieldSetup(%q) = %v, want %v", tc.cmd, got, tc.want)
			}
			if got := matchesSetupDisable(tc.cmd); got != tc.want {
				t.Errorf("matchesSetupDisable(%q) = %v, want %v", tc.cmd, got, tc.want)
			}
			if tc.want {
				if id, ok := matchesSelfProtectRule(tc.cmd); !ok || id != "sp-block-setup-disable" {
					t.Errorf("matchesSelfProtectRule(%q) = (%q, %v), want sp-block-setup-disable", tc.cmd, id, ok)
				}
			}
		})
	}
}

// The new readings run only after every reading main made has missed, so a
// command main matched keeps its rule id, even when the new readings would
// also match it under an earlier rule (sp-block-setup-disable comes before
// sp-block-delete-config in the table).
func TestSelfProtect_NewReadingsKeepMainsRuleID_4631(t *testing.T) {
	for _, tc := range []struct{ cmd, id string }{
		// The token scan would match; the raw regex already did.
		{"for i (1) echo agentshield setup; rm -rf ~/.agentshield", "sp-block-delete-config"},
		// The argv walk on the zsh reading would match; the raw regex
		// already did.
		{": ${(U)HOME}; agentshield setup --disable mcp; rm -rf ~/.agentshield", "sp-block-delete-config"},
		{"{ agentshield setup --disable mcp; export AGENTSHIELD_BYPASS=1 }", "sp-block-bypass-env"},
		// The fallback parse splits on `|` and carries argv words; the
		// first pass must not walk them, or setup-disable would win here.
		{": ${(U)HOME} | agentshield setup --disable mcp; rm -rf ~/.agentshield", "sp-block-delete-config"},
	} {
		t.Run(tc.cmd, func(t *testing.T) {
			if !matchesSetupDisable(tc.cmd) {
				t.Fatalf("control: matchesSetupDisable(%q) = false; the row does not test precedence", tc.cmd)
			}
			if id, ok := matchesSelfProtectRule(tc.cmd); !ok || id != tc.id {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, %v), want %s", tc.cmd, id, ok, tc.id)
			}
		})
	}
}

// A zsh reading writes a statement it cannot translate as `:`, so an
// agentshield statement carrying the untranslatable construct itself vanished
// from the reading, the reading still parsed, and nothing read the statement
// (review round 1 on #4634, Opus). Each erased statement's own text now gets
// the token scan. Every row is checked to have a reading that parses as bash,
// so the rows reach the erased-statement scan and not the no-reading scan.
var setupDisableErasedStatementRows = []setupDisableRow{
	{"default setup in the erased statement", "X=$((1.5)) agentshield ${zqx:-setup} --disable mcp", true},
	{"alternate setup in the erased statement", "X=$((1.5)) agentshield ${zqx:+setup} --disable mcp", true},
	{"false ANSI-C span in the erased statement", `X=$((1.5)) Y='x$' \agentshield setup --disable mcp ''`, true},
	{"false ANSI-C span with erased default", `X=$((1.5)) Y='x$' \agentshield ${zqx:-setup} --disable mcp ''`, true},
	{"float arithmetic assignment", "X=$((1.5)) agentshield --mode enforce setup mcp --disable", true},
	{"glob qualifier", "agentshield --mode enforce setup mcp --disable nomatch(N)", true},
	{"float arithmetic in a substitution", "agentshield --mode enforce setup mcp --disable $(: $((1.5)))", true},
	{"repeat short form", "repeat 1 (agentshield --mode enforce setup mcp --disable)", true},
	{"ANSI-C in the erased statement", "X=$((1.5)) agentshield $'se\\x74up' --disable mcp", true},
	{"quote splices in the erased statement", "X=$((1.5)) agent''shield set''up mcp --disable", true},
	// The words surviving in a translated statement neither help nor
	// hurt: the erased statement is scanned on its own.
	{"erased statement beside a grep for the words", "X=$((1.5)) agentshield setup --disable mcp; grep 'agentshield setup' README.md", true},
	// Accepted false-positive shape: an erased statement that only
	// mentions the two words.
	{"mention in an erased statement", "X=$((1.5)) echo agentshield setup", true},

	{"default setup mention erased", "X=$((1.5)) echo ${zqx:-setup}", false},
	// Pinned residual, the erased form of the no-reading row (review of #4639).
	{"residual: false ANSI-C span before an ANSI-C word, erased", `X=$((1.5)) Y='x$' agentshield $'se\x74up' --disable mcp`, false},
	{"default different subcommand erased", "X=$((1.5)) agentshield ${zqx:-status} --disable", false},
	{"false ANSI-C span different subcommand erased", `X=$((1.5)) Y='x$' \agentshield status ''`, false},
	{"default binary erased, setup translated", "X=$((1.5)) ${zqx:-agentshield} status; echo setup", false},
	{"grep for the words, nothing erased", ": ${(U)HOME}; grep 'agentshield setup' README.md", false},
	{"grep for the words beside an unrelated erased statement", "X=$((1.5)) echo hello; grep 'agentshield setup' README.md", false},
	{"agentshield erased, setup translated", "X=$((1.5)) agentshield status; echo setup", false},
	{"setup erased, agentshield translated", "X=$((1.5)) echo setup; agentshield status", false},
	{"erased statement without setup", "X=$((1.5)) agentshield status --disable", false},
}

func TestMatchesSetupDisable_ErasedStatementTokenScan_4631(t *testing.T) {
	for _, tc := range setupDisableErasedStatementRows {
		t.Run(tc.name, func(t *testing.T) {
			reading := shellparse.ZshReading(tc.cmd)
			if !shellparse.Parse(tc.cmd, 0).Fallback || reading == "" || shellparse.Parse(reading, 0).Fallback {
				t.Fatalf("%q: want a bash-rejected command with a reading that parses; reading %q", tc.cmd, reading)
			}
			if got := matchesSetupDisable(tc.cmd); got != tc.want {
				t.Errorf("matchesSetupDisable(%q) = %v, want %v (reading %q)", tc.cmd, got, tc.want, reading)
			}
			id, ok := matchesSelfProtectRule(tc.cmd)
			if tc.want && (!ok || id != "sp-block-setup-disable") {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, %v), want sp-block-setup-disable", tc.cmd, id, ok)
			}
			if !tc.want && ok {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, true), want no match", tc.cmd, id)
			}
		})
	}
	// Control: the bash-valid twins of the first row and the ANSI-C row
	// match through the argv walk, on main as here.
	for _, cmd := range []string{
		"X=$((15)) agentshield --mode enforce setup mcp --disable",
		"agentshield $'se\\x74up' --disable mcp",
	} {
		if id, ok := matchesSelfProtectRule(cmd); !ok || id != "sp-block-setup-disable" {
			t.Errorf("control: matchesSelfProtectRule(%q) = (%q, %v), want sp-block-setup-disable", cmd, id, ok)
		}
	}
}

// The other rules have no tolerant reading, so a splice inside an erased
// statement matches nothing: `rm -rf ~/.agentshi'e'ld/` behind `X=$((1.5))`
// is written `:` by the zsh reading, and the raw regex needs the plain
// spelling. Pinned as current behaviour; closing it is a separate decision
// (review round 1 on #4634).
func TestSelfProtect_ErasedStatementSpliceIsAResidual_4631(t *testing.T) {
	const cmd = "X=$((1.5)) rm -rf ~/.agentshi'e'ld/"
	if id, ok := matchesSelfProtectRule(cmd); ok {
		t.Errorf("matchesSelfProtectRule(%q) = (%q, true); the residual closed, update this pin", cmd, id)
	}
	if id, ok := matchesSelfProtectRule("X=$((1.5)) rm -rf ~/.agentshield/"); !ok || id != "sp-block-delete-config" {
		t.Errorf("control: plain spelling = (%q, %v), want sp-block-delete-config", id, ok)
	}
}

// A command the bash parser rejects only for a backslash in an assignment
// name has a reading (#3211's fold): the argv walk decides it, never the
// token scan, so `agentshield setup` without `--disable` stays unmatched.
func TestMatchesSetupDisable_BackslashFoldIsAReading_4631(t *testing.T) {
	for _, tc := range []struct {
		cmd  string
		want bool
	}{
		{`export FO\O=1; agentshield setup mcp`, false},
		{`export FO\O=1; agentshield setup mcp --mode=enforce --disable`, true},
		{`: ${(U)HOME}; export FO\O=1; agentshield setup mcp`, false},
		{`: ${(U)HOME}; export FO\O=1; agentshield setup mcp --mode=enforce --disable`, true},
	} {
		t.Run(tc.cmd, func(t *testing.T) {
			if !shellparse.Parse(tc.cmd, 0).Fallback {
				t.Fatalf("%q parses as bash; the row does not test the fold", tc.cmd)
			}
			if got := matchesSetupDisable(tc.cmd); got != tc.want {
				t.Errorf("matchesSetupDisable(%q) = %v, want %v", tc.cmd, got, tc.want)
			}
		})
	}
}
