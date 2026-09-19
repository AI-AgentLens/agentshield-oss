package mcp

import (
	"sort"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/unicode"
)

// argFieldRecovered resolves a rule-authored (ASCII) argument key against an
// attacker-supplied MCP arguments map using EXACTLY two steps — deliberately
// narrower than resolveField, and the reason #3727 exists. It is the resolver
// for the fixed-key sites #3720 routed through the full ladder (argString,
// firstURLOrigin, firstNonEmptyStringArg, firstSkillIdentityArg,
// extractNumericArg); those sites read a FIXED name the rule author wrote, not
// a name the caller can respell, so they need separator recovery WITHOUT the
// rest of the ladder.
//
//  1. EXACT map index. If args[key] is present, that value is the sole result.
//     This is byte-for-byte the pre-#3720 raw-index behaviour, so every ASCII
//     spelling — an uppercase `URL`, a camelCase `workingDirectory`, a nested
//     `config.url` — decides EXACTLY as it did before those sites were routed
//     through a resolver. resolveField's case-insensitive / camelCase / dot-path
//     fallbacks are intentionally NOT applied here: importing them let an ASCII
//     `URL` or `config.url` input newly activate a sequence/composite rule —
//     including a BLOCK rule — that never fired before, a silent behaviour
//     change the scenario corpus does not catch (#3727 finding 1).
//
//  2. RENDER-RECOVERY fallback, and ONLY this. An MCP argument NAME is
//     attacker-declared AND attacker-resolved (see normalizeFieldName), so
//     `url` + U+00A0 is a working parameter an exact index silently misses —
//     and a missed argument makes the whole rule fail to fire. For every arg
//     key whose bytes unicode.RecoverRenderedText reports it CHANGED (it carried
//     a Unicode confusable / invisible / separator), the recovered spelling is
//     normalized and compared to the normalized rule key. An all-ASCII key never
//     enters this branch (RecoverRenderedText reports changed=false for it), so
//     the ASCII parity of step 1 is preserved exactly — no case-fold, no
//     camelCase map, no dot-path split is ever applied to an ASCII key.
//
// It returns EVERY matching value: the exact value alone when present, otherwise
// all render-recovery matches sorted by their raw key. Returning ALL of them —
// rather than the first map entry the range happens to visit — is what makes a
// normalized-name COLLISION deterministic. Two Unicode spellings of one key
// (`url`+U+00A0 and `url`+U+2009) with different values both fold to the same
// normalized name; Go map-iteration order would otherwise pick an arbitrary
// winner and flip a composite decision between identical runs (#3727 finding 3).
// A caller checks its positive security predicate against each candidate, so a
// BLOCK caller fails CLOSED: if ANY spelling carries a triggering value, the
// rule fires.
func argFieldRecovered(args map[string]interface{}, key string) []interface{} {
	if args == nil {
		return nil
	}
	// argmaplookup:allow exact fast path of the exact-then-render-recovery
	// resolver — routing this through full resolveField would break ASCII parity
	// (#3727 finding 1); the render-recovery loop below closes the Unicode
	// separator/confusable class without the case-insensitive/camelCase ladder.
	if v, ok := args[key]; ok {
		return []interface{}{v}
	}

	type recoveredMatch struct {
		rawKey string
		value  interface{}
	}
	var matches []recoveredMatch
	for k, v := range args {
		// Strip ONLY the disguise, then compare BYTE-EXACT to the rule key —
		// preserving case, punctuation AND any ASCII space the caller actually
		// typed (#3727 pass-2 finding 1, #3740 finding 3). Crucially this does
		// NOT call normalizeFieldName: that also lowercases and strips '_'/'-',
		// which would bring back the ASCII case/convention ladder we removed for
		// pure-ASCII keys — `URL`+ZWJ would fold to `url` and match key `url`, a
		// new activation. With byte-exact compare, `url`+NBSP recovers to `url`
		// and matches, while `URL`+ZWJ recovers to `URL` and does not.
		recovered, changed := recoverDisguiseOnly(k)
		if !changed {
			// An all-ASCII (or otherwise unchanged) key is resolved by the exact
			// index above and nowhere else — never folded. This is the guard that
			// keeps ASCII parity intact.
			continue
		}
		if recovered == key {
			matches = append(matches, recoveredMatch{rawKey: k, value: v})
		}
	}
	if len(matches) == 0 {
		return nil
	}
	// Sort by raw key so the candidate order is stable across runs; the caller
	// evaluates its predicate against every candidate regardless of order, so
	// this only removes the flakiness, it is not itself the security decision.
	sort.Slice(matches, func(i, j int) bool { return matches[i].rawKey < matches[j].rawKey })
	out := make([]interface{}, len(matches))
	for i, m := range matches {
		out[i] = m.value
	}
	return out
}

// recoverDisguiseOnly is RecoverRenderedText plus the last step of undoing a
// disguise: RecoverRenderedText folds a Unicode separator (NBSP and friends) to
// an ASCII space, so `url`+NBSP arrives here as `"url "` and the folded space
// has to go before a byte-exact compare can see `url`.
//
// What it must NOT do is delete a space the caller TYPED. #3727 stripped every
// ASCII space from the recovered string, on the stated assumption that "no real
// argument key contains a literal space" — but the resolver takes an arbitrary
// rule-authored key and an arbitrary attacker-declared one, and enforced that
// assumption nowhere. The consequence ran in the dangerous direction (#3740
// finding 3): the ASCII key `u rl` correctly does NOT resolve to `url`, yet
// `u r`+ZWJ+`l` made RecoverRenderedText report changed and the blanket strip
// turned it into `url` — newly activating fixed-key predicates, BLOCK rules
// among them, for a name whose undisguised spelling is `u rl`. The inverse hurt
// too: a rule that deliberately names `u rl` missed that disguised spelling.
//
// The fix is positional, not heuristic. Split on the ASCII spaces that are
// already in the raw key, recover each segment independently, and drop spaces
// only WITHIN a segment — where, by construction, every space was introduced by
// folding a Unicode separator, because the segment held no ASCII space to begin
// with. Rejoining with a literal " " reproduces the caller's spaces
// byte-for-byte. An INTERIOR separator with no adjacent typed space
// (`u`+NBSP+`rl`) still folds away to `url`, so #3691/#3712's evasion closure is
// untouched; what no longer folds away is a space the caller typed.
//
// The one deliberate exception is LEADING/TRAILING whitespace, which is trimmed
// after rejoining. `url` + " " + NBSP renders as `url` followed by blank space
// and is one of #3712's separator-run spellings (see the #3731 suite): the
// disguise is the run, and which half of the run is ASCII is the attacker's
// choice, not a signal. Interior spacing is different — it is a gap the reader
// SEES between two stretches of the name — so it is preserved.
//
// changed is the OR over segments, so the ASCII parity guard in
// argFieldRecovered still sees an all-ASCII key as unchanged and never folds it.
func recoverDisguiseOnly(s string) (string, bool) {
	segments := strings.Split(s, " ")
	changed := false
	for i, seg := range segments {
		recovered, segChanged := unicode.RecoverRenderedText(seg)
		if !segChanged {
			continue
		}
		changed = true
		segments[i] = strings.ReplaceAll(recovered, " ", "")
	}
	if !changed {
		return s, false
	}
	return strings.Trim(strings.Join(segments, " "), " "), true
}
