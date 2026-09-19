// Package pathnorm centralizes the shell quote/escape stripping that AgentShield
// applies before matching command tokens against protected-path and structural
// argument globs.
//
// A real shell removes single quotes, double quotes and backslash escapes during
// word-splitting/quote-removal before the command ever runs, so two spellings the
// shell treats as identical — cat ~/.ss'h'/id_r'sa' and cat ~/.ssh/id_rsa — must
// collapse to the same token before any glob/path comparison. Otherwise an inline
// quote-splice trivially bypasses the check (issue #2813, the GuardFall class).
//
// Keeping this in one leaf package (imported by shellparse, normalize and the
// structural analyzer) guarantees the executable-name, protected-path and
// argument-glob surfaces all strip quotes identically and can't drift apart.
package pathnorm

import "strings"

// StripShellQuotes removes the single quotes, double quotes and backslashes that
// a shell resolves away during quote-removal, so two spellings the shell treats
// as identical also compare identically here.
//
// Tokens carrying a dynamic expansion ($VAR, $(...), backticks) are returned
// unchanged — their runtime value can't be resolved statically, and blindly
// dropping the quotes would corrupt the expansion syntax. ANSI-C quoting
// ($'...') and locale-translated quoting ($"...") are the two "$"-prefixed
// forms that ARE statically resolvable — their content never depends on
// runtime state — so both are decoded first, via DecodeANSICEscapes and
// decodeDollarDoubleQuotedSpans respectively; only genuinely dynamic content
// left after that falls through to the unchanged-return path.
//
// $"..." (issue #3208): bash looks the enclosed text up in the current
// message catalog and falls back to the literal text when none matches —
// which, for the shell an AI agent drives, is always: no TEXTDOMAIN is set
// and no catalog is installed. So $"rm" runs exactly rm. Verified against
// bash 3.2.
func StripShellQuotes(s string) string {
	if s == "" {
		return s
	}
	working := s
	if decoded, ok := decodeDollarQuotedSpans(s); ok {
		working = decoded
	}
	if decoded, ok := decodeDollarDoubleQuotedSpans(working); ok {
		working = decoded
	}
	if strings.ContainsAny(working, "$`") {
		return s
	}
	if !strings.ContainsAny(working, `'"\`) {
		return working
	}
	var b strings.Builder
	b.Grow(len(working))
	for _, r := range working {
		if r == '\'' || r == '"' || r == '\\' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// FoldHomeVar rewrites a leading $HOME or ${HOME} to ~, the spelling the
// protected-path matcher already expands.
//
// $HOME is the one variable every shell binds before the command runs, and
// the one real scripts spell instead of `~`; the substitution analyzer folds
// it the same way. Kept here so the protected-path token check, the
// consumer-slot walk and the bind-mount source extractor cannot drift apart.
//
// The fold requires a `/` or end-of-string after the name, so $HOMEBREW_PREFIX
// is left alone rather than becoming ~BREW_PREFIX.
func FoldHomeVar(s string) string {
	for _, prefix := range [...]string{"${HOME}", "$HOME"} {
		if !strings.HasPrefix(s, prefix) {
			continue
		}
		rest := s[len(prefix):]
		if rest == "" || rest[0] == '/' {
			return "~" + rest
		}
		return s
	}
	return s
}
