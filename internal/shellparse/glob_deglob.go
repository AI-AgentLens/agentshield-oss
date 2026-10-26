package shellparse

import (
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// sensitiveGlobTargets are literal path segments where a single unquoted
// '?'/'*' hiding one or two interior bytes still resolves, at runtime, to
// the exact sensitive file — the same threat class ExpandBraces closes for
// brace expansion, one shell-expansion phase later. Bash performs brace
// expansion, tilde expansion, parameter expansion, arithmetic expansion,
// command substitution, and word splitting BEFORE pathname expansion
// (globbing) — the last expansion phase (bash manual, EXPANSION section).
// mvdan.cc/sh does not model globbing any more than it models brace
// expansion, so `cat /?tc/shadow` parses as a literal, unmatched argument
// even though a real shell resolves the `?` against the filesystem and
// reads /etc/shadow verbatim.
var sensitiveGlobTargets = []string{
	"/etc/shadow",
	"/etc/shadow-",
	"/etc/passwd",
	"/etc/passwd-",
	"/etc/sudoers",
	"/etc/gshadow",
	".ssh/id_rsa",
	".ssh/id_ed25519",
	".ssh/id_ecdsa",
	".ssh/id_dsa",
	".ssh/authorized_keys",
	".ssh/known_hosts",
	".ssh/config",
	".aws/credentials",
	".aws/config",
	".gnupg/secring.gpg",
	".gnupg/private-keys-v1.d",
	".kube/config",
	".docker/config.json",
	".npmrc",
	".netrc",
	// KeePass database (#4410). sec-block-keepassxc-db-read matches it by
	// regex, so a glob inside the extension resolved to nothing before
	// this entry.
	".kdbx",
	".pgpass",
	".git-credentials",
	".pypirc",
	"/etc/hosts",
	// Directory-only segments (no specific filename) — a masked directory
	// name alone still resolves to the sensitive tree, whether the command
	// reads/writes a file inside it (`~/.?sh/some_other_key`) or archives/
	// copies the directory wholesale (`tar czf keys.tar.gz ~/.?sh/`).
	".ssh/",
	".aws/",
	".gnupg/",
	".kube/",
	".docker/",
	".npm/",
	// Block-device prefix (issue #3103): the device NAME (sda, nvme0n1, ...)
	// is rarely what an attacker hides — masking "dev" itself
	// (`/?ev/sda`) is the demonstrated bypass shape, and the unmasked
	// device-name suffix is what isDevicePath/isBlockDevice then matches
	// against once this resolves the directory segment.
	"/dev/",
}

// Bounds on how much of a target a wildcard may cover, so resolution stays
// tightly anchored to the KNOWN target shape rather than degrading into a
// loose match — a genuinely open-ended glob (`build/*`, `/dev/sd*`, `*.log`)
// never appears in sensitiveGlobTargets in the first place, so it can never
// resolve to anything, wildcard or not.
const (
	// maxGlobWildcardSpan bounds how many target characters a single
	// contiguous wildcard run may stand in for.
	maxGlobWildcardSpan = 2
	// maxGlobAlternatives bounds the candidate list this returns, same
	// purpose as maxBraceAlternatives in brace_expand.go.
	maxGlobAlternatives = 16
	// minGlobEdgeLiteral is how many leading bytes of a target's final path
	// component a TRAILING wildcard must leave literal before it counts as
	// pinning that one name (#4410). A trailing '?' or '*' on /etc/shadow
	// or ~/.netrc pins it; a wildcard after "/etc/s" or "~/.n" matches
	// ordinary names too, so it stays unresolved and decides AUDIT.
	minGlobEdgeLiteral = 4
	// maxGlobEdgeSpan bounds how many trailing bytes a '*' may stand for.
	maxGlobEdgeSpan = 3
)

// globVariant is one precomputed (wildcard-text, resolved-target) pair.
type globVariant struct {
	text   string
	target string
	// atEnd marks a trailing-wildcard variant (#4410): it resolves only when
	// it ends the literal it is found in, so a byte after the wildcard is
	// never read as part of the protected name.
	atEnd bool
}

// singleCharClass matches a bracket class naming exactly one character,
// which pathname expansion resolves to that character.
var singleCharClass = regexp.MustCompile(`\[([^\]\[!^\\*?-])\]`)

// collapseSingleClasses replaces each one-character class with its character
// and reports whether it changed anything.
func collapseSingleClasses(text string) (string, bool) {
	out := singleCharClass.ReplaceAllString(text, "$1")
	return out, out != text
}

// matchGlobVariant returns where gv starts in text, or -1.
func matchGlobVariant(text string, gv globVariant) int {
	if gv.atEnd {
		if strings.HasSuffix(text, gv.text) {
			return len(text) - len(gv.text)
		}
		return -1
	}
	return strings.Index(text, gv.text)
}

// appendEdgeVariants adds the trailing-wildcard spellings of target (#4410):
// its last one to three bytes replaced by '?' or '*'. The interior builder
// keeps a literal byte on both sides of a wildcard, so a wildcard on the
// last byte resolved to nothing and the read was ALLOWed. A directory-only
// target has no final component.
func appendEdgeVariants(out []globVariant, seen map[string]bool, target string) []globVariant {
	if strings.HasSuffix(target, "/") {
		return out
	}
	name := target[strings.LastIndex(target, "/")+1:]
	for k := 1; k <= maxGlobEdgeSpan; k++ {
		if len(name)-k < minGlobEdgeLiteral {
			break
		}
		candidates := []string{"*"}
		if k <= maxGlobWildcardSpan {
			candidates = append(candidates, strings.Repeat("?", k))
		}
		for _, wc := range candidates {
			variant := target[:len(target)-k] + wc
			key := "end\x00" + variant + "\x00" + target
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, globVariant{text: variant, target: target, atEnd: true})
		}
	}
	return out
}

// globVariantIndex is built once at package init from sensitiveGlobTargets —
// it does not depend on the command being analyzed, so computing it per-call
// would be pure waste in a hot path invoked on every evaluated command.
var globVariantIndex = buildGlobVariantIndex()

func buildGlobVariantIndex() []globVariant {
	seen := make(map[string]bool)
	var out []globVariant
	for _, target := range sensitiveGlobTargets {
		for k := 1; k <= maxGlobWildcardSpan; k++ {
			// i is the start of the masked span; requiring i >= 1 and
			// i+k <= len(target)-1 keeps at least one literal character on
			// both sides of the wildcard — a wildcard is never allowed to
			// swallow the first or last character of the target, which is
			// what keeps this "tightly anchored" rather than a loose
			// prefix/suffix match.
			for i := 1; i+k <= len(target)-1; i++ {
				seg := target[i : i+k]
				if strings.Contains(seg, "/") {
					// A '?'/'*' in a real glob pattern never matches '/' —
					// pathname expansion is scoped to one path component.
					continue
				}
				candidates := []string{strings.Repeat("?", k), "*"}
				for _, wc := range candidates {
					variant := target[:i] + wc + target[i+k:]
					key := variant + "\x00" + target
					if seen[key] {
						continue
					}
					seen[key] = true
					out = append(out, globVariant{text: variant, target: target})
				}
			}
		}
		out = appendEdgeVariants(out, seen, target)
	}
	return out
}

// DeglobSensitivePaths returns every literal resolution produced by matching
// an unquoted '?'/'*' wildcard in command against the shape of a well-known
// sensitive path segment — the same additive-candidate wiring ExpandBraces
// uses (internal/analyzer/regex.go), extending the RegexAnalyzer's candidate
// list rather than replacing the raw command it still also checks.
//
// `cat /?tc/shadow`, `cat ~/.ssh/i?_rsa`, and `echo x > /?tc/sudoers` all
// look unrelated to any sensitive-path rule as written, but pathname
// expansion resolves each to the exact protected file before the command
// ever runs (issue #3102). A corpus-wide parity sweep — replacing one
// interior byte of a sensitive-path needle with '?' across every BLOCKing
// command — found 110/286 (38%) of sensitive-path BLOCKs degraded to
// AUDIT/ALLOW purely from this un-modeled expansion phase.
//
// Only an UNQUOTED wildcard is resolved — mirroring ExpandBraces and
// NormalizeIFS, only a top-level Lit WordPart is scanned, so a quoted
// literal like `echo "use a ? or * here"` is left alone: a real shell does
// not perform pathname expansion inside quotes either.
//
// Returns nil when command has no unquoted '?'/'*', when parsing fails, or
// when no wildcard resolves to a known sensitive path.
func DeglobSensitivePaths(command string) []string {
	if !strings.ContainsAny(command, "?*[") {
		return nil
	}

	reader := strings.NewReader(command)
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(reader, "")
	if err != nil {
		return nil
	}

	type span struct{ start, end int }
	var spans []span
	syntax.Walk(file, func(node syntax.Node) bool {
		w, ok := node.(*syntax.Word)
		if !ok {
			return true
		}
		for _, part := range w.Parts {
			lit, ok := part.(*syntax.Lit)
			if !ok {
				continue // SglQuoted/DblQuoted/dynamic — pathname expansion doesn't reach these
			}
			start := int(lit.Pos().Offset())
			end := int(lit.End().Offset())
			if start < 0 || end > len(command) || start >= end {
				continue
			}
			spans = append(spans, span{start, end})
		}
		return true
	})
	if len(spans) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	var alternatives []string
	for _, s := range spans {
		text, collapsed := collapseSingleClasses(command[s.start:s.end])
		if collapsed {
			// A one-character class is that character (#4410), so the
			// collapsed command is itself a candidate.
			resolved := command[:s.start] + text + command[s.end:]
			if !seen[resolved] {
				seen[resolved] = true
				alternatives = append(alternatives, resolved)
			}
		}
		if !strings.ContainsAny(text, "?*") {
			continue
		}
		for _, gv := range globVariantIndex {
			idx := matchGlobVariant(text, gv)
			if idx < 0 {
				continue
			}
			resolved := command[:s.start] + text[:idx] + gv.target + text[idx+len(gv.text):] + command[s.end:]
			if seen[resolved] {
				continue
			}
			seen[resolved] = true
			alternatives = append(alternatives, resolved)
			if len(alternatives) >= maxGlobAlternatives {
				return alternatives
			}
		}
	}
	return alternatives
}

// DeglobPath is the single-argument counterpart to DeglobSensitivePaths, for
// callers that already hold an isolated path string — e.g.
// ctx.Parsed.Segments[].Args entries in the structural analyzer, or a
// dataflow source/sink argument — rather than a whole raw command to
// re-parse. Those callers compare literal Args text directly and never
// retry through RegexAnalyzer's candidate list (internal/analyzer/regex.go),
// which is the exact architectural gap issue #3103 closes: a wildcard
// masking "/dev/" in a disk-write target (`dd ... of=/?ev/sda`), a system
// path in a chmod target (`chmod a+rwx /?tc/passwd`), or a credential
// directory in a dataflow source (`tar czf keys.tar.gz ~/.?sh/`) previously
// reached these comparisons unresolved.
//
// Uses the same globVariantIndex and matching rules as
// DeglobSensitivePaths — no quote-stripping or AST parsing here, since
// callers already pass an isolated, already-unquoted argument. Returns p
// unchanged if it has no unquoted wildcard or none resolves.
func DeglobPath(p string) string {
	if !strings.ContainsAny(p, "?*[") {
		return p
	}
	p, _ = collapseSingleClasses(p)
	if !strings.ContainsAny(p, "?*") {
		return p
	}
	for _, gv := range globVariantIndex {
		if idx := matchGlobVariant(p, gv); idx >= 0 {
			return p[:idx] + gv.target + p[idx+len(gv.text):]
		}
	}
	return p
}
