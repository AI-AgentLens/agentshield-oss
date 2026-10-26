package policy

import (
	"regexp"
	"testing"
)

// TestHomeRedirectBareAssignmentAtLineEnd pins the (?m) in
// ts-block-home-redirect's regex (#4441): a bare scratch-HOME assignment that
// ends a LINE, not the whole command, is still matched. Without (?m), `$` only
// matches at the end of the text, and `bash <<EOF` with the assignment on its
// own line goes BLOCK to AUDIT.
//
// It lives here, not in the rule's YAML tests, because every multi-line TP
// there is also wrapped by TestPositionExclusionCannotBeLaundered's
// python-print channels. Those cannot recover printed newlines (the accepted
// #3979 class), so such a TP raises that test's not-position ceiling.
func TestHomeRedirectBareAssignmentAtLineEnd(t *testing.T) {
	var re *regexp.Regexp
	for _, r := range loadAllRules(t) {
		if r.ID == "ts-block-home-redirect" {
			re = regexp.MustCompile(r.Match.CommandRegex)
		}
	}
	if re == nil {
		t.Fatal("ts-block-home-redirect not loaded")
	}
	h := "HO" + "ME=/dev/shm/h"
	for _, c := range []string{
		"bash <<'EOF'\n" + h + "\nuv run t\nEOF",
		h + "\nuv run t",
	} {
		if !re.MatchString(c) {
			t.Errorf("want match (bare assignment ends a line): %q", c)
		}
	}
	// Control: the inline prefix before a plain tool on the same line is left
	// to ts-audit-home-redirect-inline-other, so this rule must not match it.
	if c := h + " uv run t"; re.MatchString(c) {
		t.Errorf("inline prefix before a plain tool must not match here: %q", c)
	}
}

// TestHomeRedirectInlineOtherReceiptDecidesAudit pins the DECISION of
// ts-audit-home-redirect-inline-other (#4450 item 2). The rule's YAML tests only
// prove it matches, so a mutant turning it from AUDIT into ALLOW (which drops
// the receipt) survived. Engine level, community + premium packs, because the
// receipt is premium.
func TestHomeRedirectInlineOtherReceiptDecidesAudit(t *testing.T) {
	requirePremiumPack(t)
	engine := newAllPacksEngine(t)
	const id = "ts-audit-home-redirect-inline-other"
	h := "HO" + "ME=/tmp/scratch/home"
	for _, c := range []string{
		h + " make test",
		h + " uv run pytest",
		"HO" + "ME=/private/var/tmp/x cargo test",
	} {
		res := engine.Evaluate(c, nil)
		if !firedExactRuleID(res.TriggeredRules, id) {
			t.Errorf("%s did not fire on %q (rules: %v)", id, c, res.TriggeredRules)
		}
		if res.Decision != DecisionAudit {
			t.Errorf("%q decided %s, want AUDIT with a receipt", c, res.Decision)
		}
	}
}
