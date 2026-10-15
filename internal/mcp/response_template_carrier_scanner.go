package mcp

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// EchoLeak-shaped template carriers on the tools/call result surface (#4279,
// register row asi01-echoleak-zero-click-email).
//
// response_markdown_exfil_url looks for an image URL whose query value is
// already a long encoded string. An inbound message cannot carry that: the
// sender does not have the victim's data. The EchoLeak carrier is a TEMPLATE:
// an image (inline, reference-style, or an HTML <img>) pointing at an outside
// host whose query value is a slot, plus prose asking the assistant to fill the
// slot with something sensitive. The renderer then fetches the filled URL.
// Reference-style images matter because the published chain used them to slip
// past link redaction.
//
// Both halves are required: a placeholder image URL with no directive (a doc
// explaining templated URLs, a badge template) and a directive with no
// placeholder image both stay silent.
//
// AUDIT only, and the result type has no Blocked field. The shape is a
// probe-derived heuristic without a primary-source literal, so it records a
// receipt and nothing more ("only BLOCK what you can justify").
//
// Known limits, not addressed here: text content items only; tools/call only;
// no render recovery (a fullwidth or zero-width obfuscated directive is not
// folded); the directive must name the assistant, so a bare second-person
// "you" does not count.

// SignalResponseTemplateCarrier is the signal ScanToolCallResponseForTemplateCarrier emits.
const SignalResponseTemplateCarrier ResponseAddresseeMarkerSignal = "response_template_carrier"

// ResponseTemplateCarrierScanResult is the outcome of
// ScanToolCallResponseForTemplateCarrier. It has no Blocked field on purpose.
type ResponseTemplateCarrierScanResult struct {
	Found    bool
	Findings []ResponseAddresseeMarkerFinding
}

var (
	templateInlineImageRE = regexp.MustCompile(`!\[[^\]\n]{0,200}\]\(\s*<?(https?://[^\s)>]+)`)
	templateRefImageRE    = regexp.MustCompile(`!\[[^\]\n]{0,200}\]\[([^\]\n]{0,100})\]`)
	templateRefDefRE      = regexp.MustCompile(`(?m)^[ \t]{0,3}\[([^\]\n]{1,100})\]:[ \t]*(<)?(https?://\S+)`)
	templateHTMLImgRE     = regexp.MustCompile(`(?is)<img\b[^>]{0,400}?\bsrc\s*=\s*["']?(https?://[^\s"'>]+)`)

	// templatePlaceholderRE matches a whole query value that is a slot: {x},
	// {{x}}, <x>, [x], ..., a run of X, or a closed list of all-caps slot words.
	templatePlaceholderRE = regexp.MustCompile(`^(?:\{\{?[^{}]{0,60}\}?\}|<[^<>]{1,60}>|\[[^\[\]]{1,60}\]|\.{3,}|…|[xX]{3,}|(?:CODE|DATA|SECRET|SECRETS|TOKEN|SUMMARY|ANSWER|CONTENT|CONTEXT|INFO|PAYLOAD|KEY|PASSWORD|EMAIL|HISTORY|MESSAGE)(?:_[A-Z]+)?)$`)

	templateAssistantRE = regexp.MustCompile(`(?i)\b(?:assistant|ai|agent|model|llm|copilot|claude|chatgpt|gpt)\b`)
	templateFillRE      = regexp.MustCompile(`(?i)\b(?:fill(?:ing)?(?:\s+in)?|insert|include|append|replace|substitute|put|embed|encode|paste|add|complete|populate)\b`)
	templateTargetRE    = regexp.MustCompile(`(?i)\b(?:url|link|image|placeholder|parameter|query|slot|value|src)\b|[{<\[]`)
)

// templateDirectiveWindow is how far around the image markup the directive
// prose may sit.
const templateDirectiveWindow = 500

// templateQueryPlaceholder reports whether rawURL is external-looking and has
// at least one query value that is a placeholder slot.
func templateQueryPlaceholder(rawURL string) bool {
	q := strings.IndexByte(rawURL, '?')
	if q < 0 {
		return false
	}
	query := rawURL[q+1:]
	if h := strings.IndexByte(query, '#'); h >= 0 {
		query = query[:h]
	}
	for _, kv := range strings.FieldsFunc(query, func(r rune) bool { return r == '&' || r == ';' }) {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		val := kv[eq+1:]
		if dec, err := url.QueryUnescape(val); err == nil {
			val = dec
		}
		if templatePlaceholderRE.MatchString(strings.TrimSpace(val)) {
			return true
		}
	}
	return false
}

// templateDirectiveNear reports whether the text around [start,end) addresses
// the assistant and asks it to fill something into a link or image.
func templateDirectiveNear(text string, start, end int) bool {
	lo := start - templateDirectiveWindow
	if lo < 0 {
		lo = 0
	}
	hi := end + templateDirectiveWindow
	if hi > len(text) {
		hi = len(text)
	}
	w := text[lo:hi]
	return templateAssistantRE.MatchString(w) && templateFillRE.MatchString(w) && templateTargetRE.MatchString(w)
}

// ScanToolCallResponseForTemplateCarrier reports each text content item that
// carries a placeholder image URL together with a fill directive. AUDIT-tier
// only.
func ScanToolCallResponseForTemplateCarrier(items []ContentItem) ResponseTemplateCarrierScanResult {
	var result ResponseTemplateCarrierScanResult
	for i, item := range items {
		if item.Type != "text" || item.Text == "" {
			continue
		}
		text := item.Text
		type hit struct{ start, end int }
		var hits []hit

		for _, m := range templateInlineImageRE.FindAllStringSubmatchIndex(text, -1) {
			if templateQueryPlaceholder(text[m[2]:m[3]]) {
				hits = append(hits, hit{m[0], m[1]})
			}
		}
		for _, m := range templateHTMLImgRE.FindAllStringSubmatchIndex(text, -1) {
			if templateQueryPlaceholder(text[m[2]:m[3]]) {
				hits = append(hits, hit{m[0], m[1]})
			}
		}
		defs := map[string][2]int{}
		defURL := map[string]string{}
		for _, m := range templateRefDefRE.FindAllStringSubmatchIndex(text, -1) {
			id := strings.ToLower(strings.TrimSpace(text[m[2]:m[3]]))
			defs[id] = [2]int{m[0], m[1]}
			u := text[m[6]:m[7]]
			if m[4] >= 0 { // <angle-bracketed> destination
				u = strings.TrimSuffix(u, ">")
			}
			defURL[id] = u
		}
		for _, m := range templateRefImageRE.FindAllStringSubmatchIndex(text, -1) {
			id := strings.ToLower(strings.TrimSpace(text[m[2]:m[3]]))
			if id == "" { // collapsed reference: ![alt][] uses the alt text
				continue
			}
			u, ok := defURL[id]
			if ok && templateQueryPlaceholder(u) {
				hits = append(hits, hit{m[0], m[1]}, hit{defs[id][0], defs[id][1]})
			}
		}

		for _, h := range hits {
			if !templateDirectiveNear(text, h.start, h.end) {
				continue
			}
			snippet := text[h.start:h.end]
			if len(snippet) > addresseeMarkerSnippetMax {
				snippet = snippet[:addresseeMarkerSnippetMax]
			}
			result.Findings = append(result.Findings, ResponseAddresseeMarkerFinding{
				Signal:       SignalResponseTemplateCarrier,
				Detail:       fmt.Sprintf("content item %d carries an image URL with a placeholder query value and asks the assistant to fill it: %q", i, snippet),
				Snippet:      snippet,
				ContentIndex: i,
			})
			break // one finding per content item
		}
	}
	result.Found = len(result.Findings) > 0
	return result
}
