package mcp

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/AI-AgentLens/agentshield/internal/unicode"
)

// asciiOnlyWireName reports whether a wire tool name is pure ASCII.
//
// EVERY negative tool-name predicate must gate on this before doing a
// case-insensitive match. The reason is the mirror of toolNameForms below, and
// it is a step subtler: an exclusion does not have to be handed a *recovered*
// form to widen — Go's `(?i)` is ITSELF a Unicode fold. Under simple folding
// U+017F LATIN SMALL LETTER LONG S folds to `s`, and U+212A KELVIN SIGN to `k`.
// So `get_file_contentſ` satisfies `(?i)^…get[_-]file[_-]contents$`, while
// matchToolNameCaseInsensitive — whose ToLower + normalizeSeparators leave
// U+017F untouched — matches no positive rule at all.
//
// #3757 shipped exactly that pairing: the fold satisfied a catch-all's
// exclusion and switched it OFF, and the dedicated rules the carve-out deferred
// to never fired, so a credential-file read fell through to AUDIT with zero
// rules. Measured base-vs-merge in #3771. The PR's own reasoning ("matched on
// the wire name, never the recovered form") was right and still insufficient,
// because `(?i)` folds without anyone calling a recover function.
//
// The bound is ASCII rather than "the two characters we know about" on purpose:
// the fold table is Unicode's, it grows between Go releases, and a negative
// predicate that is wrong is silently permissive. A non-ASCII name simply gets
// no carve-out — it falls back to the broad rule and BLOCKs, which is the
// fail-safe direction and precisely the pre-#3757 behaviour.
//
// This does NOT weaken case-insensitivity for real tool names: `(?i)` over an
// ASCII-only name is plain ASCII case folding, which is what the positive side
// does too.
func asciiOnlyWireName(name string) bool {
	for i := 0; i < len(name); i++ {
		if name[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// normalizeSeparators lowercases and collapses '-' to '_' so hyphenated and
// underscored spellings of the same tool name compare equal — "git_checkout"
// and "git-checkout" both normalize to "git_checkout".
//
// Deliberately does NOT strip separators (contrast normalizeFieldName): a
// wildcard tool_name_any pattern like "*pay_*" relies on '_' as a literal
// word-boundary character to avoid matching "get_payload"/"payroll"/etc.
// Stripping it would widen the pattern to "*pay*", which then does match
// those — a real regression caught by TestPremiumMCPStructuralRuleYAMLTests
// while building this fix. Collapsing the two separator spellings to one
// preserves the boundary while still closing the vendor-naming-convention
// gap (issue #3443): a rule authored against a snake_case reference MCP
// server (git_checkout) still fires against a hyphenated JS/TS server
// (git-checkout).
func normalizeSeparators(s string) string {
	// Recover the rendered text FIRST. An MCP tool name is the one identifier
	// in this system that the ATTACKER both declares and resolves: the server
	// advertises `wr<U+0456>te_file` in tools/list, the model copies that string
	// verbatim into tools/call, and the server matches it against its own
	// registry. Nothing has to survive a shell parser, so — unlike a homoglyph
	// in a shell command word, which simply fails to execute — a rendering-
	// identical tool name costs the attacker nothing and is invisible to every
	// tool_name_any / tool_name / blocked_tools comparison in the corpus.
	//
	// Measured over every shipped rule's own TP fixtures (5632 that BLOCK):
	// substituting ONE character for a Cyrillic confusable downgraded 85.9% to
	// AUDIT; a fullwidth form 86.6%; inserting one zero-width character 86.7%.
	//
	// The stdio and HTTP proxies do filter such a tool out of tools/list
	// (SignalToolNameConfusable), so this is defence in depth there. It is the
	// ONLY defence on the agentless surface — `agentshield mcp-eval` and
	// shield-server's /v1/evaluate (#3315) receive {tool_name, args} and never
	// see a listing. It also decides whether the audit event carries a rule id
	// at all: an unmatched call is logged with no rule and no taxonomy, which
	// is the one shape the attestation chain cannot represent.
	//
	// RecoverRenderedText has an ASCII fast path (a byte scan), so a real tool
	// name pays a scan and no allocation. Folding can only ADD matches, never
	// remove one, so the risk it carries is a false BLOCK on a name that
	// renders as a blocked name — which is the thing we want blocked.
	if recovered, changed := unicode.RecoverRenderedText(s); changed {
		s = recovered
	}
	// Recovery folds Unicode separators (NBSP and friends) to a plain space,
	// which is a separator spelling no real tool name uses — treat it as one
	// more spelling of '_' rather than leaving `write<NBSP>file` unmatched.
	// Safe for the boundary semantics documented above: a wildcard pattern's
	// literal '_' still exists, and no benign tool name contains a space.
	return strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(s), "-", "_"), " ", "_")
}

// normalizeFieldName additionally strips separators entirely, collapsing
// snake_case, kebab-case, and camelCase argument names into one comparable
// form: "branch_name", "branchName", and "branch-name" all normalize to
// "branchname".
//
// Safe here in a way normalizeSeparators is not: MCP argument field names
// are always literal map keys, never glob/wildcard patterns, so there is no
// boundary-character semantics to preserve. Use this for argument field name
// resolution (resolveField); use normalizeSeparators for tool names, which
// may carry '*'/'?' wildcards.
func normalizeFieldName(s string) string {
	// An MCP argument NAME is attacker-controlled on both ends for exactly the
	// same reason a tool name is (see normalizeSeparators): the server declares
	// the parameter in its inputSchema, the model fills that key, and the
	// server reads it back. So `p<U+0430>th` is a working parameter that no
	// argument_patterns rule authored against `path` can resolve — and an
	// unresolved field makes matchRule return false, i.e. the rule does not
	// fire at all. Measured over every shipped rule's own TP fixtures (2806
	// that BLOCK), renaming the argument keys with one confusable character
	// leaked 84.4%; fullwidth and zero-width 87.0% each.
	//
	// Applying this to the exclusion predicates too (ExcludeArgumentPatterns,
	// ArgumentNotContains) is deliberate and costs nothing: those are keyed on
	// ASCII names the attacker can already spell exactly, so folding hands over
	// no capability they did not have.
	if recovered, changed := unicode.RecoverRenderedText(s); changed {
		s = recovered
	}
	s = strings.ToLower(s)
	if !strings.ContainsAny(s, "_- ") {
		return s
	}
	// Space is stripped alongside the separators: recovery folds NBSP and its
	// siblings to a plain space, and a real argument key never contains one.
	return strings.NewReplacer("_", "", "-", "", " ", "").Replace(s)
}

// toolNameForms returns the spellings of a wire tool name a POSITIVE rule
// predicate should be tried against: the wire form first, then its recovered
// rendering when the two differ.
//
// Only positive predicates get the second form. A NEGATIVE predicate
// (ToolNameRegexExclude, ToolNameNotPrefixAny) must keep seeing the wire name
// alone: folding an exclusion widens it, so `<U+0455>afe_read` would start
// satisfying an `^safe_` carve-out and switch the rule off — the exact
// inversion of what this fix is for.
func toolNameForms(name string) []string {
	recovered, changed := unicode.RecoverRenderedText(name)
	if !changed {
		return []string{name}
	}
	// Recovery folds Unicode separators to a plain space. Tool-name regexes are
	// authored against the snake_case wire convention and are usually anchored
	// (`^(insert|add)_(message|turn)$`), so leaving the space would hand back a
	// form that matches nothing — 474 of 2857 BLOCKing fixtures leaked exactly
	// here before this line existed. Substituting '_' mirrors what
	// normalizeSeparators does for the glob/exact paths.
	//
	// It does NOT also emit a '-' spelling: that is the pre-existing
	// hyphen-vs-underscore gap on the regex path (matchToolName collapses the
	// two, matchRule's regex never has), orthogonal to this fix and not worth
	// doubling every regex evaluation for.
	recovered = strings.ReplaceAll(recovered, " ", "_")
	if recovered == name {
		return []string{name}
	}
	return []string{name, recovered}
}

// toolNameRegexMatches reports whether re matches the wire tool name or its
// recovered rendering. See toolNameForms — use this for every positive
// tool-name regex predicate, never for an exclusion.
func toolNameRegexMatches(re *regexp.Regexp, name string) bool {
	if re.MatchString(name) {
		return true
	}
	forms := toolNameForms(name)
	if len(forms) < 2 {
		return false
	}
	// A pattern that itself talks about non-ASCII was authored against the WIRE
	// name, so handing it the recovered rendering is both incoherent and
	// actively FP-generating: recovery rewrites the Latin-lookalike letters of
	// a legitimately all-Cyrillic name into ASCII, turning a single-script
	// identifier into a mixed-script one — exactly the shape a homoglyph
	// detector is looking for. Measured while writing
	// mcp-agentic-block-tool-name-render-evasion: its all-Cyrillic TN fired,
	// and only on the recovered form.
	//
	// The check runs only after recovery has already reported a change, so an
	// ordinary ASCII tool name never pays for it.
	if patternTargetsNonASCII(re.String()) {
		return false
	}
	return re.MatchString(forms[1])
}

// identifierRenderEvasionCategories are the unicode.Threat categories that
// make an MCP tool name or argument KEY suspicious — see identifierRenderEvasion.
var identifierRenderEvasionCategories = map[string]bool{
	"zero-width":         true,
	"bidi-override":      true,
	"tag-char":           true,
	"control-char":       true,
	"invalid-utf8":       true,
	"variation-selector": true,
	"homoglyph-cyrillic": true,
	"homoglyph-greek":    true,
	"homoglyph-compat":   true,
}

// identifierRenderEvasion is the call-time counterpart of the listing-time
// mcp-desc-tool-name-confusable-sentinel (issue #3578). That sentinel only
// inspects a tools/list response via detectToolNameConfusable; the agentless
// surfaces — `agentshield mcp-eval` and shield-server's /v1/evaluate (#3315)
// — receive {tool_name, args} directly and never observe a listing, so this
// re-derives the same signal from the wire call itself.
//
// s is an MCP tool name or an argument KEY: both are identifiers the
// attacker declares AND resolves (see normalizeSeparators / normalizeFieldName
// doc comments), so both get the same check.
//
// An invisible/control/tag character has no legitimate reading in a short
// programmatic identifier — presence alone is the verdict, same as
// unicode.isZeroWidth's own design contract. A homoglyph (Cyrillic/Greek/
// compatibility-form) fires ONLY when s also contains a plain ASCII letter:
// that is what distinguishes impersonation ("reаd_file", ASCII "r" mixed
// with Cyrillic "а") from a legitimately non-Latin identifier ("читать", all
// Cyrillic, no ASCII letter at all) — the exact false positive
// detectMixedScriptDescription already guards against on the prose surface,
// applied here to identifiers instead of a length/ratio threshold that would
// exclude real short tool names.
func identifierRenderEvasion(s string) bool {
	if s == "" {
		return false
	}
	scan := unicode.Scan(s)
	if scan.Clean {
		return false
	}
	hasASCIILetter := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasASCIILetter = true
			break
		}
	}
	for _, threat := range scan.Threats {
		if !identifierRenderEvasionCategories[threat.Category] {
			continue
		}
		switch threat.Category {
		case "homoglyph-cyrillic", "homoglyph-greek", "homoglyph-compat":
			if hasASCIILetter {
				return true
			}
		default:
			return true
		}
	}
	return false
}

// patternTargetsNonASCII reports whether a regex source mentions non-ASCII —
// either literally, or through \x{...} / \p{...} / \P{...}.
func patternTargetsNonASCII(pattern string) bool {
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c >= 0x80 {
			return true
		}
		if c == '\\' && i+2 < len(pattern) && pattern[i+2] == '{' {
			switch pattern[i+1] {
			case 'x', 'p', 'P':
				return true
			}
		}
	}
	return false
}
