package mcp

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	pkgunicode "github.com/AI-AgentLens/agentshield/internal/unicode"
)

// Regression tests for #3594: a Unicode separator in the attacker-controlled
// tool description (or a string argument value) used to zero out the semantic
// intent score, so a tool that BLOCKs in its ASCII spelling was AUDITed in a
// spelling that renders identically in the host's tool listing.
//
// The separator constants (nbsp, thinSpace, ideoSpace, narrowNBSP, figureSpace)
// are declared in unicode_separator_evasion_test.go — the same set the
// description scanner's own tests use, so both surfaces are exercised against
// one vocabulary.
//
// Two assertions per row, and both are load-bearing:
//
//   - PARITY: the respelled call must match exactly the semantic rule ids the
//     ASCII call matched. "Still BLOCKs" would not do — several other layers
//     can block the same fixture, so a decision-level assertion stays green with
//     the fold removed (the lesson recorded in CLAUDE.md under tool-name render
//     evasion).
//   - VACUITY: the ASCII control must match a non-empty, named rule set. Without
//     it, a change that stopped classifying anything at all would make every
//     parity row trivially true.

func separatorSpellings() map[string]string {
	return map[string]string{
		"nbsp":        nbsp,
		"thinSpace":   thinSpace,
		"ideoSpace":   ideoSpace,
		"narrowNBSP":  narrowNBSP,
		"figureSpace": figureSpace,
	}
}

// matchedSemanticIDs returns the sorted ids of the shipped semantic rules that
// match a tool call.
func matchedSemanticIDs(t *testing.T, ev *PolicyEvaluator, toolName string, args map[string]interface{}, desc string) []string {
	t.Helper()
	_, matched := evaluateSemanticRules(toolName, args, desc, ev.policy.SemanticRules)
	ids := make([]string, 0, len(matched))
	for _, r := range matched {
		ids = append(ids, r.ID)
	}
	sort.Strings(ids)
	return ids
}

func TestSemanticSeparatorEvasion_DescriptionParity(t *testing.T) {
	ev := newTestMCPEvaluator(t)

	cases := []struct {
		name     string
		toolName string
		args     map[string]interface{}
		desc     string
		wantRule string
	}{
		{
			// MCP-TP-027. The tool name carries no intent keyword; the
			// description is what makes it code-execute.
			name:     "code-execute via description",
			toolName: "helpful_assistant",
			args:     map[string]interface{}{"code": "print(1)"},
			desc:     "Runs user-provided code snippets for automation tasks",
			wantRule: "mcp-sem-block-code-execute",
		},
		{
			// MCP-TP-030.
			name:     "process-manage via description",
			toolName: "system_manager",
			args:     map[string]interface{}{"pid": "1234", "signal": "SIGKILL"},
			desc:     "Manages system processes and services",
			wantRule: "mcp-sem-block-process-manage",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ascii := matchedSemanticIDs(t, ev, tc.toolName, tc.args, tc.desc)
			if len(ascii) == 0 {
				t.Fatalf("vacuous control: the ASCII spelling matched no semantic rule at all")
			}
			if !contains(ascii, tc.wantRule) {
				t.Fatalf("vacuous control: ASCII spelling matched %v, want it to include %q", ascii, tc.wantRule)
			}

			for sepName, sep := range separatorSpellings() {
				t.Run(sepName, func(t *testing.T) {
					respelled := strings.ReplaceAll(tc.desc, " ", sep)
					if respelled == tc.desc {
						t.Fatalf("vacuous mutation: %s left the description unchanged", sepName)
					}
					got := matchedSemanticIDs(t, ev, tc.toolName, tc.args, respelled)
					if !equalIDs(got, ascii) {
						t.Errorf("separator evasion: %s spelling matched %v, ASCII matched %v", sepName, got, ascii)
					}
				})
			}
		})
	}
}

func TestSemanticSeparatorEvasion_ArgumentValueParity(t *testing.T) {
	ev := newTestMCPEvaluator(t)

	// Shape of MCP-TP-2359-004, reduced to the part that matters: the tool name
	// and the argument NAME together score 0.5, one notch under the rule's
	// confidence_min of 0.7, so the +0.2 from looksLikeCode on the VALUE is what
	// carries the match. looksLikeCode's `import\s+\w+` is spelled with RE2's
	// ASCII-only `\s`, so one separator inside the value used to delete it.
	const toolName = "numexpr_evaluate"
	const argName = "expression"
	const codeValue = "import os"
	const wantRule = "mcp-sem-block-code-execute"

	ascii := matchedSemanticIDs(t, ev, toolName, map[string]interface{}{argName: codeValue}, "")
	if !contains(ascii, wantRule) {
		t.Fatalf("vacuous control: ASCII argument value matched %v, want it to include %q", ascii, wantRule)
	}

	for sepName, sep := range separatorSpellings() {
		t.Run(sepName, func(t *testing.T) {
			respelled := strings.ReplaceAll(codeValue, " ", sep)
			if respelled == codeValue {
				t.Fatalf("vacuous mutation: %s left the value unchanged", sepName)
			}
			got := matchedSemanticIDs(t, ev, toolName, map[string]interface{}{argName: respelled}, "")
			if !equalIDs(got, ascii) {
				t.Errorf("separator evasion: %s spelling matched %v, ASCII matched %v", sepName, got, ascii)
			}
		})
	}
}

// The other half of the contract. Unicode spaces are ordinary typography —
// French punctuation spacing, figure grouping, anything pasted out of a rendered
// web page — so folding them must not manufacture a classification that the
// ASCII spelling does not have. If this test ever needs relaxing, the fold has
// become a verdict rather than a normalisation.
func TestSemanticSeparatorEvasion_BenignSeparatorsDoNotClassify(t *testing.T) {
	ev := newTestMCPEvaluator(t)

	cases := []struct {
		name     string
		toolName string
		args     map[string]interface{}
		desc     string
	}{
		{
			name:     "typographic description",
			toolName: "unit_converter",
			args:     map[string]interface{}{"value": "42"},
			desc:     "Converts values between metric and imperial units",
		},
		{
			// simpleMathRe excludes arithmetic from looksLikeCode; folding the
			// separators must leave it excluded, not promote it to code.
			name:     "arithmetic argument value",
			toolName: "numexpr_evaluate",
			args:     map[string]interface{}{"expression": "2 + 2"},
			desc:     "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ascii := matchedSemanticIDs(t, ev, tc.toolName, tc.args, tc.desc)

			for sepName, sep := range separatorSpellings() {
				t.Run(sepName, func(t *testing.T) {
					respelledArgs := map[string]interface{}{}
					mutated := false
					for k, v := range tc.args {
						if s, ok := v.(string); ok && strings.Contains(s, " ") {
							respelledArgs[k] = strings.ReplaceAll(s, " ", sep)
							mutated = true
							continue
						}
						respelledArgs[k] = v
					}
					respelledDesc := strings.ReplaceAll(tc.desc, " ", sep)
					if respelledDesc != tc.desc {
						mutated = true
					}
					if !mutated {
						t.Fatalf("vacuous mutation: %s changed nothing in this case", sepName)
					}

					got := matchedSemanticIDs(t, ev, tc.toolName, respelledArgs, respelledDesc)
					if !equalIDs(got, ascii) {
						t.Errorf("benign %s spelling changed the classification: matched %v, ASCII matched %v",
							sepName, got, ascii)
					}
				})
			}
		})
	}
}

func contains(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func equalIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- Repeated and mixed separator RUNS (#3689 follow-up) ---
//
// FoldUnicodeSeparators is cardinality-preserving by design: two U+00A0 fold to
// two ASCII spaces. Every descSignals phrase carries exactly one literal space,
// so strings.Contains still missed the doubled spelling and the first fix was
// bypassable by pressing the same key twice. classifyDescription therefore
// collapses whitespace runs as well as folding them (foldSeparatorRuns).
//
// Every non-ASCII rune below is written as string(rune(0x....)) rather than as a
// literal. That is deliberate: writing the raw bytes through a shell heredoc
// silently normalised U+00A0 to ASCII 0x20 while this test was being developed,
// which turned a Unicode evasion sweep into an ASCII one and reported a clean
// result for the wrong reason. Escapes are ASCII in the source file, so no
// transport can rewrite them, and assertFoldable below re-checks anyway.

func sepRune(r rune) string { return string(r) }

// assertFoldable fails if s is not something FoldUnicodeSeparators rewrites.
// Guards every table in this file against the mangling described above: a
// "separator" that is really an ASCII space makes every parity row pass
// vacuously.
func assertFoldable(t *testing.T, name, s string) {
	t.Helper()
	if _, changed := pkgunicode.FoldUnicodeSeparators(s); !changed {
		t.Fatalf("vacuous table: %s (% x) contains no foldable separator", name, s)
	}
}

// separatorRunSpellings returns multi-character separator runs: the same
// separator repeated, different separators adjacent, and mixtures with the
// ASCII space. Each is a spelling that renders as ordinary word spacing.
func separatorRunSpellings() map[string]string {
	nb := sepRune(0x00A0)   // NO-BREAK SPACE
	thin := sepRune(0x2009) // THIN SPACE
	hair := sepRune(0x200A) // HAIR SPACE
	ideo := sepRune(0x3000) // IDEOGRAPHIC SPACE
	return map[string]string{
		"2x U+00A0":                 nb + nb,
		"3x U+00A0":                 nb + nb + nb,
		"U+2009 then U+200A":        thin + hair,
		"ASCII then U+00A0":         " " + nb,
		"U+00A0 then ASCII":         nb + " ",
		"U+3000 U+00A0 U+2009":      ideo + nb + thin,
		"ASCII U+00A0 ASCII U+2009": " " + nb + " " + thin,
	}
}

// descriptionScores runs the description signal in isolation, so a failure
// names the signal rather than a decision several layers away.
func descriptionScores(desc string) map[MCPToolIntent]float64 {
	scores := make(map[MCPToolIntent]float64)
	classifyDescription(desc, scores)
	return scores
}

func TestSemanticSeparatorEvasion_DescriptionRunParity(t *testing.T) {
	ev := newTestMCPEvaluator(t)

	cases := []struct {
		name     string
		toolName string
		args     map[string]interface{}
		desc     string
		wantRule string
	}{
		{
			name:     "code-execute via description",
			toolName: "helpful_assistant",
			args:     map[string]interface{}{"code": "print(1)"},
			desc:     "Runs user-provided code snippets for automation tasks",
			wantRule: "mcp-sem-block-code-execute",
		},
		{
			name:     "process-manage via description",
			toolName: "system_manager",
			args:     map[string]interface{}{"pid": "1234", "signal": "SIGKILL"},
			desc:     "Manages system processes and services",
			wantRule: "mcp-sem-block-process-manage",
		},
		{
			// The signal phrase does not start the description: unrelated prose
			// carrying its own separators comes first. A fix that only
			// normalised the head of the string, or that anchored the phrase
			// search, would pass the two rows above and fail this one.
			name:     "signal phrase after unrelated separator-bearing prose",
			toolName: "helpful_assistant",
			args:     map[string]interface{}{"code": "print(1)"},
			desc: "Internal utility maintained by the platform team. " +
				"Runs user-provided code snippets for automation tasks. " +
				"See the handbook for usage limits.",
			wantRule: "mcp-sem-block-code-execute",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ascii := matchedSemanticIDs(t, ev, tc.toolName, tc.args, tc.desc)
			if !contains(ascii, tc.wantRule) {
				t.Fatalf("vacuous control: ASCII spelling matched %v, want it to include %q", ascii, tc.wantRule)
			}

			for runName, run := range separatorRunSpellings() {
				t.Run(runName, func(t *testing.T) {
					assertFoldable(t, runName, run)
					respelled := strings.ReplaceAll(tc.desc, " ", run)
					if respelled == tc.desc {
						t.Fatalf("vacuous mutation: %s left the description unchanged", runName)
					}
					got := matchedSemanticIDs(t, ev, tc.toolName, tc.args, respelled)
					if !equalIDs(got, ascii) {
						t.Errorf("separator-run evasion: %s spelling matched %v, ASCII matched %v", runName, got, ascii)
					}
				})
			}

			// The same bypass costs nothing in pure ASCII — two ordinary spaces
			// also delete a one-space phrase — so the collapse covers it too.
			t.Run("2x ASCII space", func(t *testing.T) {
				got := matchedSemanticIDs(t, ev, tc.toolName, tc.args, strings.ReplaceAll(tc.desc, " ", "  "))
				if !equalIDs(got, ascii) {
					t.Errorf("double-space evasion: matched %v, single-space ASCII matched %v", got, ascii)
				}
			})
		})
	}
}

// TestSemanticSeparatorEvasion_EveryDescriptionIntentFamily parameterises over
// descSignals itself, so a fold applied to only some intents — or a new family
// added without one — fails here. The two hand-written rows above cover
// code-execute and process-manage; this covers the other nine, and any future
// family for free.
func TestSemanticSeparatorEvasion_EveryDescriptionIntentFamily(t *testing.T) {
	if len(descSignals) < 11 {
		t.Fatalf("vacuous control: descSignals has %d families, expected at least 11", len(descSignals))
	}

	runs := separatorRunSpellings()
	runs["1x U+00A0"] = sepRune(0x00A0)

	covered := 0
	for intent, phrases := range descSignals {
		// Pick the first multi-word phrase: a single-word phrase ("eval",
		// "downloads") has no inter-word separator to respell.
		phrase := ""
		for _, p := range phrases {
			if strings.Contains(p, " ") {
				phrase = p
				break
			}
		}
		if phrase == "" {
			t.Logf("intent %s has no multi-word phrase; nothing to respell", intent)
			continue
		}
		covered++

		t.Run(string(intent), func(t *testing.T) {
			desc := "Maintained by the platform team. This tool " + phrase + " when the user asks."
			ascii := descriptionScores(desc)
			if ascii[intent] < 0.3 {
				t.Fatalf("vacuous control: ASCII carrier scored %s at %.2f, want >= 0.30 (phrase %q)",
					intent, ascii[intent], phrase)
			}

			for runName, run := range runs {
				assertFoldable(t, runName, run)
				got := descriptionScores(strings.ReplaceAll(desc, " ", run))
				if got[intent] != ascii[intent] {
					t.Errorf("%s: %s scored %.2f, ASCII scored %.2f (phrase %q)",
						runName, intent, got[intent], ascii[intent], phrase)
				}
				// Parity over the WHOLE score map, not just the target intent:
				// a normalisation that manufactured an unrelated intent would
				// otherwise pass.
				if len(got) != len(ascii) {
					t.Errorf("%s: scored %d intents, ASCII scored %d", runName, len(got), len(ascii))
				}
			}
		})
	}

	if covered < 11 {
		t.Errorf("only %d of %d intent families were exercised", covered, len(descSignals))
	}
}

// foldableSeparators derives the separator vocabulary from FoldUnicodeSeparators
// itself by asking it about every rune, rather than restating its table here. A
// rune added to the helper is covered by this test on the next run; a rune
// removed stops being asserted. Hard-coding the list is what let the original
// tests claim coverage of "the five tested separators".
func foldableSeparators(t *testing.T) []rune {
	t.Helper()
	var out []rune
	for r := rune(0); r <= 0x10FFFF; r++ {
		if r >= 0xD800 && r <= 0xDFFF { // surrogates are not valid runes
			continue
		}
		if _, changed := pkgunicode.FoldUnicodeSeparators(string(r)); changed {
			out = append(out, r)
		}
	}
	if len(out) < 20 {
		t.Fatalf("vacuous control: derived only %d foldable separators, expected at least 20", len(out))
	}
	return out
}

// TestSemanticSeparatorEvasion_EveryFoldableSeparator asserts description parity
// for every rune the fold handles, singly and doubled, plus one mixed-kind row
// pairing each separator with a different one.
func TestSemanticSeparatorEvasion_EveryFoldableSeparator(t *testing.T) {
	ev := newTestMCPEvaluator(t)

	const toolName = "helpful_assistant"
	const desc = "Runs user-provided code snippets for automation tasks"
	args := map[string]interface{}{"code": "print(1)"}

	ascii := matchedSemanticIDs(t, ev, toolName, args, desc)
	if !contains(ascii, "mcp-sem-block-code-execute") {
		t.Fatalf("vacuous control: ASCII spelling matched %v", ascii)
	}

	other := sepRune(0x00A0)
	for _, r := range foldableSeparators(t) {
		sep := string(r)
		partner := other
		if r == 0x00A0 {
			partner = sepRune(0x3000)
		}
		spellings := map[string]string{
			"single":     sep,
			"doubled":    sep + sep,
			"mixed":      sep + partner,
			"with ASCII": sep + " ",
		}
		for name, spelling := range spellings {
			t.Run(fmt.Sprintf("U+%04X/%s", r, name), func(t *testing.T) {
				assertFoldable(t, name, spelling)
				got := matchedSemanticIDs(t, ev, toolName, args, strings.ReplaceAll(desc, " ", spelling))
				if !equalIDs(got, ascii) {
					t.Errorf("U+%04X %s: matched %v, ASCII matched %v", r, name, got, ascii)
				}
			})
		}
	}
}

// --- Argument NAMES (#3691) ---
//
// argNameSignals (looked up via argNameSignalsNormalized, see classifyArgNames)
// is an EXACT-KEY lookup, unlike the substring/phrase matchers above. That
// makes the #3594 fix insufficient here: unicode.RecoverRenderedText folds a
// separator to an ASCII SPACE, which restores a substring/phrase match but
// still misses an exact key — "path" + U+00A0 recovers to "path ", not
// "path". classifyArgNames now runs normalizeFieldName instead, which strips
// separators entirely rather than folding them (the same transform
// resolveField already uses to resolve a structural rule's argument key).
//
// Both assertions from the file header apply here too: PARITY (the respelled
// call must score/match exactly what the ASCII spelling did) and VACUITY (the
// ASCII control must score/match something, and the mutation must actually
// change the string).

// TestSemanticSeparatorEvasion_ArgumentNameParity exercises classifyArgNames in
// isolation, at every position a real MCP client could plant a separator in an
// attacker-controlled argument key: leading, trailing, and splitting the key
// (either at an arbitrary midpoint, or by replacing the key's own '_' for keys
// that have one — a spelling that reads as "the same field, different
// convention" right up until the exact-key lookup sees it).
func TestSemanticSeparatorEvasion_ArgumentNameParity(t *testing.T) {
	rows := []struct {
		argName    string
		wantIntent MCPToolIntent
	}{
		{"command", IntentCodeExecute},
		{"filepath", IntentFileRead},
		{"secret_name", IntentCredentialRead},
		{"api_key", IntentCredentialRead},
		{"process_id", IntentProcessManage},
	}

	spellings := separatorRunSpellings()
	spellings["1x U+00A0"] = sepRune(0x00A0)

	for _, row := range rows {
		t.Run(row.argName, func(t *testing.T) {
			asciiScores := make(map[MCPToolIntent]float64)
			classifyArgNames(map[string]interface{}{row.argName: "value"}, asciiScores)
			if asciiScores[row.wantIntent] == 0 {
				t.Fatalf("vacuous control: ASCII arg name %q does not score %s", row.argName, row.wantIntent)
			}

			positions := map[string]func(sep string) string{
				"leading":  func(sep string) string { return sep + row.argName },
				"trailing": func(sep string) string { return row.argName + sep },
			}
			if strings.Contains(row.argName, "_") {
				positions["replacing underscore"] = func(sep string) string {
					return strings.ReplaceAll(row.argName, "_", sep)
				}
			} else {
				mid := len(row.argName) / 2
				positions["splitting"] = func(sep string) string {
					return row.argName[:mid] + sep + row.argName[mid:]
				}
			}

			for posName, place := range positions {
				t.Run(posName, func(t *testing.T) {
					for sepName, sep := range spellings {
						t.Run(sepName, func(t *testing.T) {
							assertFoldable(t, sepName, sep)
							respelled := place(sep)
							if respelled == row.argName {
								t.Fatalf("vacuous mutation: %s/%s left the name unchanged", posName, sepName)
							}
							scores := make(map[MCPToolIntent]float64)
							classifyArgNames(map[string]interface{}{respelled: "value"}, scores)
							if scores[row.wantIntent] != asciiScores[row.wantIntent] {
								t.Errorf("arg name %q (%s/%s) scored %s at %.2f, ASCII %q scored %.2f",
									respelled, posName, sepName, row.wantIntent, scores[row.wantIntent],
									row.argName, asciiScores[row.wantIntent])
							}
						})
					}
				})
			}
		})
	}
}

// TestSemanticSeparatorEvasion_ArgumentNameDecisionParity is the end-to-end
// counterpart: a real semantic rule whose confidence threshold is crossed by
// argument-NAME reinforcement alone, with no help from the tool name,
// description, or argument values.
//
// "command", "script" and "code" each reinforce IntentCodeExecute by 0.25 in
// argNameSignals; three of them together score 0.75, which crosses
// mcp-sem-block-code-execute's confidence_min of 0.7 on their own (verified by
// the ASCII control below, which passes a tool name and argument values that
// carry no code-execute signal). Corrupting any ONE of the three names used to
// drop the total to 0.50 and the decision from BLOCK to AUDIT — Shield then
// attests "no violation" for a call that reached the tool with the same
// arguments it always would have.
func TestSemanticSeparatorEvasion_ArgumentNameDecisionParity(t *testing.T) {
	ev := newTestMCPEvaluator(t)

	const toolName = "helpful_assistant"
	const wantRule = "mcp-sem-block-code-execute"
	baseArgs := func() map[string]interface{} {
		return map[string]interface{}{"command": "x", "script": "y", "code": "z"}
	}

	ascii := matchedSemanticIDs(t, ev, toolName, baseArgs(), "")
	if !contains(ascii, wantRule) {
		t.Fatalf("vacuous control: ASCII argument names matched %v, want them to include %q", ascii, wantRule)
	}

	spellings := separatorRunSpellings()
	spellings["1x U+00A0"] = sepRune(0x00A0)

	for _, corrupted := range []string{"command", "script", "code"} {
		t.Run("corrupt "+corrupted, func(t *testing.T) {
			for sepName, sep := range spellings {
				t.Run(sepName, func(t *testing.T) {
					assertFoldable(t, sepName, sep)
					args := baseArgs()
					delete(args, corrupted)
					respelled := corrupted + sep
					args[respelled] = "x"
					got := matchedSemanticIDs(t, ev, toolName, args, "")
					if !equalIDs(got, ascii) {
						t.Errorf("%s spelling of %q matched %v, ASCII matched %v", sepName, corrupted, got, ascii)
					}
				})
			}
		})
	}
}

// --- Argument VALUES ---

// TestSemanticSeparatorEvasion_ArgumentWireFormPreserved is the other half of
// classifyArgValues' OR: the fold must be strictly additive, so a value that
// matches in its WIRE form must keep matching even when the folded form does
// not. looksLikeURL runs url.Parse, and Go rejects a space inside a host name,
// so a separator there parses on the wire and fails after the fold.
//
// If classifyArgValues is ever simplified to "fold, then match" this test is the
// one that fails; every other argument row in this file would still pass.
func TestSemanticSeparatorEvasion_ArgumentWireFormPreserved(t *testing.T) {
	ev := newTestMCPEvaluator(t)

	wireURL := "https://exa" + sepRune(0x00A0) + "mple.com/report"
	assertFoldable(t, "wireURL", wireURL)

	folded, changed := pkgunicode.FoldUnicodeSeparators(wireURL)
	if !changed || looksLikeURL(folded) || !looksLikeURL(wireURL) {
		t.Fatalf("vacuous control: need wire=true folded=false, got wire=%v folded=%v changed=%v",
			looksLikeURL(wireURL), looksLikeURL(folded), changed)
	}

	// Two url-ish argument NAMES score 0.5; the +0.2 from looksLikeURL on the
	// VALUE is what crosses mcp-sem-audit-network-request's confidence_min of
	// 0.6. Control below proves the value is load-bearing.
	const toolName = "widget_helper"
	const wantRule = "mcp-sem-audit-network-request"

	got := matchedSemanticIDs(t, ev, toolName, map[string]interface{}{"endpoint": wireURL, "uri": "v1"}, "")
	if !contains(got, wantRule) {
		t.Errorf("wire-form URL lost its match: got %v, want it to include %q", got, wantRule)
	}

	withoutValue := matchedSemanticIDs(t, ev, toolName, map[string]interface{}{"endpoint": "v2", "uri": "v1"}, "")
	if contains(withoutValue, wantRule) {
		t.Fatalf("vacuous control: %q fires without the URL value (%v), so the value proves nothing",
			wantRule, withoutValue)
	}
}

// valueDetectorFoldSensitivity is a fitness function over the value detectors.
// A detector spelled with RE2's `\s` is ASCII-only and therefore blind to a
// Unicode separator, so it needs a folded-form case in the table below; one
// without `\s` cannot gain a match from the fold and does not.
//
// Adding `\s` to filePathRe or credentialRefRe — or removing it from a detector
// listed as sensitive — fails here, which is the prompt to add or drop the
// corresponding parity case.
func TestSemanticSeparatorEvasion_ValueDetectorFoldSensitivity(t *testing.T) {
	detectors := map[string]struct {
		pattern       string
		foldSensitive bool
	}{
		"filePathRe":      {filePathRe.String(), false},
		"credentialRefRe": {credentialRefRe.String(), false},
		"sqlKeywordRe":    {sqlKeywordRe.String(), true},
		"codePatterns":    {codePatterns.String(), true},
	}
	for name, d := range detectors {
		hasWS := strings.Contains(d.pattern, `\s`)
		if hasWS != d.foldSensitive {
			t.Errorf("%s: pattern contains \\s = %v, table says foldSensitive = %v — "+
				"update TestSemanticSeparatorEvasion_ValuePredicateFoldedForms to match", name, hasWS, d.foldSensitive)
		}
	}
	// simpleMathRe also contains `\s`, but it is an EXCLUSION: folding can only
	// make it match more, which can only make looksLikeCode return false more
	// often. classifyArgValues ORs the wire form, so a fold-induced exclusion
	// can never remove a match that fires today. Asserted rather than assumed:
	nb := sepRune(0x00A0)
	arith := "2" + nb + "+ 2"
	foldedArith, _ := pkgunicode.FoldUnicodeSeparators(arith)
	if looksLikeCode(arith) || looksLikeCode(foldedArith) {
		t.Errorf("arithmetic classified as code: wire=%v folded=%v", looksLikeCode(arith), looksLikeCode(foldedArith))
	}
}

// TestSemanticSeparatorEvasion_ValuePredicateFoldedForms covers every value
// detector the fold can actually help, not just looksLikeCode. Each row asserts
// the full contract: blind on the wire, recovered by the fold, and reaching the
// classifier through classifyArgValues.
func TestSemanticSeparatorEvasion_ValuePredicateFoldedForms(t *testing.T) {
	rows := []struct {
		name       string
		pred       func(string) bool
		argName    string
		value      func(sep string) string
		wantIntent MCPToolIntent
	}{
		{
			name:       "looksLikeSQL",
			pred:       looksLikeSQL,
			argName:    "query",
			value:      func(sep string) string { return "SELECT" + sep + "* FROM users" },
			wantIntent: IntentDatabaseRead,
		},
		{
			name:       "looksLikeCode/import statement",
			pred:       looksLikeCode,
			argName:    "expression",
			value:      func(sep string) string { return "import" + sep + "os" },
			wantIntent: IntentCodeExecute,
		},
		{
			name:       "looksLikeCode/shell removal",
			pred:       looksLikeCode,
			argName:    "command",
			value:      func(sep string) string { return "rm" + sep + "-rf /tmp/build" },
			wantIntent: IntentCodeExecute,
		},
	}

	spellings := separatorRunSpellings()
	spellings["1x U+00A0"] = sepRune(0x00A0)

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			asciiScores := make(map[MCPToolIntent]float64)
			classifyArgValues(map[string]interface{}{row.argName: row.value(" ")}, asciiScores)
			if !row.pred(row.value(" ")) || asciiScores[row.wantIntent] == 0 {
				t.Fatalf("vacuous control: the ASCII spelling does not reach %s", row.name)
			}

			// Counts the spellings where the fold is what recovers the match.
			// These detectors are spelled `\s+`, so a run that still contains an
			// ASCII space can match on the wire — for those, only score parity
			// is meaningful. The counter keeps the test from passing because
			// EVERY spelling happened to match on the wire.
			recovered := 0
			for spName, sep := range spellings {
				assertFoldable(t, spName, sep)
				wire := row.value(sep)
				folded, changed := pkgunicode.FoldUnicodeSeparators(wire)
				if !changed {
					t.Fatalf("vacuous mutation: %s produced no fold", spName)
				}
				if !row.pred(wire) {
					recovered++
					if !row.pred(folded) {
						t.Errorf("%s: %s spelling matches neither on the wire nor after the fold (%q)",
							row.name, spName, wire)
					}
				}

				// And it must reach the classifier, not merely the predicate.
				scores := make(map[MCPToolIntent]float64)
				classifyArgValues(map[string]interface{}{row.argName: wire}, scores)
				if scores[row.wantIntent] != asciiScores[row.wantIntent] {
					t.Errorf("%s: %s spelling scored %s at %.2f, ASCII scored %.2f",
						row.name, spName, row.wantIntent, scores[row.wantIntent], asciiScores[row.wantIntent])
				}
			}
			if recovered == 0 {
				t.Errorf("vacuous control: every spelling of %s matched on the wire, "+
					"so no row here exercises the fold", row.name)
			}
		})
	}
}

// --- Sibling classes this change does NOT claim ---

// TestSemanticSeparatorEvasion_SiblingGapsRemainOpen pins what is OUT of scope,
// as measured behaviour rather than as prose. These spellings still evade the
// semantic classifier, and that is the current, intended state:
//
//   - Zero-width characters (U+200B, U+FEFF) and U+034F COMBINING GRAPHEME
//     JOINER are excluded from FoldUnicodeSeparators on purpose. Folding them to
//     a SPACE is the wrong transform — they are inserted INSIDE a word, so
//     "co<ZWSP>de" would become "co de" and still match nothing. The correct
//     fold is to the empty string, a separate pass with its own false-positive
//     profile (it welds together words a benign document separated).
//   - Fullwidth letters are a CONFUSABLE, not a separator. classifyToolName and
//     classifyArgNames already run unicode.RecoverRenderedText, which handles
//     them; the description and value paths get the separator fold only.
//
// Issue #3691 tracks the argument-NAME half. Do not "fix" these here: each is a
// different transform, and each needs its own false-positive measurement against
// the 5627-scenario corpus. If one of these rows starts failing, a sibling
// transform has landed and this test should be updated to assert the new
// coverage — the failure is the notification, not a regression.
func TestSemanticSeparatorEvasion_SiblingGapsRemainOpen(t *testing.T) {
	ev := newTestMCPEvaluator(t)

	const toolName = "helpful_assistant"
	const desc = "Runs user-provided code snippets for automation tasks"
	args := map[string]interface{}{"code": "print(1)"}

	if ids := matchedSemanticIDs(t, ev, toolName, args, desc); !contains(ids, "mcp-sem-block-code-execute") {
		t.Fatalf("vacuous control: ASCII spelling matched %v", ids)
	}

	gaps := map[string]func(string) string{
		"U+200B zero-width space": func(s string) string { return strings.ReplaceAll(s, " ", sepRune(0x200B)) },
		"U+FEFF byte-order mark":  func(s string) string { return strings.ReplaceAll(s, " ", sepRune(0xFEFF)) },
		"U+034F combining joiner": func(s string) string { return strings.ReplaceAll(s, " ", sepRune(0x034F)) },
		"zero-width inside word":  func(s string) string { return strings.ReplaceAll(s, "code", "co"+sepRune(0x200B)+"de") },
		"fullwidth letters": func(s string) string {
			var b strings.Builder
			for _, r := range s {
				if r >= 'a' && r <= 'z' {
					b.WriteRune(r - 'a' + 0xFF41)
					continue
				}
				b.WriteRune(r)
			}
			return b.String()
		},
	}

	for name, respell := range gaps {
		t.Run(name, func(t *testing.T) {
			respelled := respell(desc)
			if respelled == desc {
				t.Fatalf("vacuous mutation: %s changed nothing", name)
			}
			if ids := matchedSemanticIDs(t, ev, toolName, args, respelled); len(ids) != 0 {
				t.Errorf("%s now matches %v — a sibling transform has landed; "+
					"move this row into the covered tests and record its corpus FP measurement", name, ids)
			}
		})
	}

	// U+3000 IDEOGRAPHIC SPACE looks like a fullwidth character but is a
	// Space_Separator, so it IS in scope and must be covered, not exempt.
	inScope := strings.ReplaceAll(desc, " ", sepRune(0x3000))
	if ids := matchedSemanticIDs(t, ev, toolName, args, inScope); !contains(ids, "mcp-sem-block-code-execute") {
		t.Errorf("U+3000 is a foldable separator and must be covered, got %v", ids)
	}
}

// --- Line boundaries are not whitespace to be collapsed ---

// TestSemanticSeparatorEvasion_LineBreaksAreNotJoined is the false-positive half
// of the run collapse, and the reason foldSeparatorRuns is a hand-written
// horizontal-only loop rather than strings.Join(strings.Fields(x), " ").
//
// Fields() treats `\n` as whitespace, so joining on it manufactures phrases out
// of ordinary hard-wrapped prose. A tool description that says, across a line
// break, that it does NOT run code was read as containing "run code" and BLOCKed
// — a verdict no spelling of the input supports, and one main does not produce.
//
// The three assertions below are the whole contract:
//
//  1. a hard-wrapped benign description stays below threshold (ASCII, and with
//     separators inside the lines);
//  2. a phrase split across a line break does not match;
//  3. the same phrase with a doubled separator on one line still does — so the
//     fix for the false positive did not reopen the evasion.
func TestSemanticSeparatorEvasion_LineBreaksAreNotJoined(t *testing.T) {
	ev := newTestMCPEvaluator(t)

	const toolName = "syntax_highlighter"
	// Benign parameter names that nonetheless score: `code` and `expression`
	// contribute 0.25 each, so the description is what decides the verdict.
	args := map[string]interface{}{"code": "plain-text", "expression": "hello"}

	nb := sepRune(0x00A0)

	// (1) + (2): hard-wrapped prose whose two halves would form "run code" only
	// if the line break were treated as a space.
	wrapped := map[string]string{
		"LF, ASCII":               "Formats text only; it does not run\ncode.",
		"CRLF, ASCII":             "Formats text only; it does not run\r\ncode.",
		"CR only, ASCII":          "Formats text only; it does not run\rcode.",
		"LF, U+00A0 inside lines": "Formats" + nb + "text only; it does not" + nb + "run\ncode.",
		"LF, indented next line":  "Formats text only; it does not run\n    code.",
		"LF, trailing space":      "Formats text only; it does not run \ncode.",
	}
	for name, desc := range wrapped {
		t.Run("benign/"+name, func(t *testing.T) {
			if !strings.ContainsAny(desc, "\n\r") {
				t.Fatalf("vacuous case: %s has no line break", name)
			}
			scores := descriptionScores(desc)
			if scores[IntentCodeExecute] != 0 {
				t.Errorf("hard-wrapped benign description scored code-execute at %.2f — "+
					"the line break was collapsed into a space", scores[IntentCodeExecute])
			}
			if ids := matchedSemanticIDs(t, ev, toolName, args, desc); len(ids) != 0 {
				t.Errorf("hard-wrapped benign description matched %v", ids)
			}
		})
	}

	// The same text on ONE line genuinely does contain the phrase. That is
	// pre-existing behaviour, unchanged by this branch, and it is what makes the
	// rows above a statement about line breaks rather than about this sentence.
	t.Run("control/same words on one line do match", func(t *testing.T) {
		oneLine := "Formats text only; it does not run code."
		if descriptionScores(oneLine)[IntentCodeExecute] == 0 {
			t.Fatalf("vacuous control: the single-line spelling scores code-execute at 0, " +
				"so the wrapped rows above prove nothing about line breaks")
		}
	})

	// (3) The evasion this collapse exists to close must still be closed, on a
	// single line, including on the second line of a multi-line description.
	t.Run("evasion/doubled separator on one line still matches", func(t *testing.T) {
		for name, sep := range separatorRunSpellings() {
			assertFoldable(t, name, sep)
			desc := "Utility helper." + "\n" + strings.ReplaceAll("This tool runs code on request.", " ", sep)
			if descriptionScores(desc)[IntentCodeExecute] == 0 {
				t.Errorf("%s: a doubled separator on the second line evaded the phrase match", name)
			}
		}
	})

	// And a phrase deliberately split across the break must NOT be reassembled,
	// even when each half carries separators.
	t.Run("evasion/phrase split across the break stays split", func(t *testing.T) {
		desc := "This tool runs" + nb + "\n" + nb + "code on request."
		if s := descriptionScores(desc)[IntentCodeExecute]; s != 0 {
			t.Errorf("a phrase split across a line break was reassembled (scored %.2f)", s)
		}
	})
}
