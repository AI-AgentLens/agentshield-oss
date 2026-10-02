package mcp

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// Icons (MCP 2025-11-25, SEP-973). A tool may carry `icons: [{src, mimeType,
// sizes, theme}]`, and a host fetches and renders them when it draws the tool
// list: no click, no approval. `src` is server-chosen. The spec says it is an
// http(s) URL or a `data:` URI and warns that SVG "can contain executable
// JavaScript". Nothing here parsed `icons` before (#4062).
//
// One BLOCK-tier signal, every member enumerable, none with a legitimate
// reading for an icon:
//
//   - a script scheme (`javascript:`, `vbscript:`);
//   - a UNC path, an `smb:` URL, or a `file:` URL naming a remote host — each
//     makes a Windows host send the user's NTLM hash when it resolves the
//     icon (the CVE-2023-23397 class);
//   - a `data:` SVG whose decoded body carries script, an event handler, a
//     javascript: href, <foreignObject>, or an embedded document.
//
// The scheme is read after the same WHATWG cleanup the URL-mode elicitation
// scanner applies, so `java\tscript:` is `javascript:`.
//
// Scope of this file: tools/list, initialize serverInfo, prompts/list,
// resources/list and resources/templates/list (#4062). The AUDIT half of that issue (http(s) icons
// to link-local / RFC1918 hosts) is deliberately not here: a finding on a tool
// hides the tool, and an internal-network icon has a legitimate reading.

// SignalIconUnsafeSource flags a tool icon whose src executes script or makes
// the host resolve an SMB/remote-file path while rendering the list. BLOCK.
const SignalIconUnsafeSource PoisonSignal = "icon_unsafe_source"

// ToolIcon is one entry of an `icons` array.
type ToolIcon struct {
	Src      string `json:"src"`
	MimeType string `json:"mimeType,omitempty"`
}

// An element is matched by its LOCAL name: XML namespaces let `<s:script>` (with
// s bound to the SVG namespace) run exactly like `<script>` (#4148).
var svgActiveContentRE = regexp.MustCompile(`(?is)<\s*(?:[a-z_][\w.-]*:)?(?:script|foreignobject|iframe|embed|object)\b|\bon[a-z]+\s*=|(?:java|vb)script\s*:`)

// svgEntityDeclRE finds DTD internal entity declarations. Old Illustrator
// exports declare harmless namespace entities, so a declaration alone is not
// a finding; one whose value carries an encoded `<` is markup smuggled past
// the regexp above (the parser expands it into an element).
var svgEntityDeclRE = regexp.MustCompile(`(?is)<!ENTITY\s+\S+\s+(?:"([^"]*)"|'([^']*)')`)
var svgEncodedLTRE = regexp.MustCompile(`(?i)&#0*60;|&#x0*3c;`)

func svgEntityCarriesMarkup(body string) bool {
	for _, m := range svgEntityDeclRE.FindAllStringSubmatch(body, -1) {
		if svgEncodedLTRE.MatchString(m[1] + m[2]) {
			return true
		}
	}
	return false
}

// scanToolIcons returns one finding per unsafe icon src.
func scanToolIcons(icons []ToolIcon) []PoisonFinding {
	return scanIconsFor("tool", icons)
}

// scanIconsFor is the one icon check every listing surface shares (tools,
// prompts, resources, resource templates): the same field, the same sources,
// the same verdict. owner only words the finding.
func scanIconsFor(owner string, icons []ToolIcon) []PoisonFinding {
	var out []PoisonFinding
	for _, ic := range icons {
		if why := unsafeIconSource(ic.Src); why != "" {
			out = append(out, PoisonFinding{
				Signal:  SignalIconUnsafeSource,
				Detail:  owner + " icon src " + why + " — a host resolves icons when it renders the tool list, with no user action",
				Snippet: truncateURL(normalizeElicitationURL(ic.Src)),
			})
		}
	}
	return out
}

// unsafeIconSource returns why src is unsafe, or "" when it is not.
func unsafeIconSource(src string) string {
	s := normalizeElicitationURL(src)
	if strings.HasPrefix(s, `\\`) {
		return "is a UNC path; resolving it leaks the user's NTLM hash on Windows"
	}
	m := urlSchemeRE.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	scheme := strings.ToLower(m[1])
	rest := s[len(m[0]):]
	switch scheme {
	case "javascript", "vbscript":
		return "uses the " + scheme + ": scheme, which runs script in the renderer"
	case "smb":
		return "is an smb: URL; resolving it leaks the user's NTLM hash on Windows"
	case "file":
		// file: authority is exactly two slashes then the host; `///` is an empty
		// (local) host, unlike http(s), which splitWebURL reads leniently.
		r := strings.ReplaceAll(rest, `\`, "/")
		if strings.HasPrefix(r, "//") && !strings.HasPrefix(r, "///") {
			host := strings.ToLower(strings.SplitN(r[2:], "/", 2)[0])
			if host != "" && host != "localhost" {
				return "is a file: URL naming remote host " + host + "; resolving it leaks the user's NTLM hash on Windows"
			}
		}
	case "data":
		if svgDataActive(rest) {
			return "is a data: SVG carrying executable content (script, event handler, foreignObject or embedded document)"
		}
	}
	return ""
}

// svgDataActive decodes the payload of a data: URI (the part after "data:")
// and reports whether it is SVG markup with active content.
func svgDataActive(rest string) bool {
	comma := strings.IndexByte(rest, ',')
	if comma < 0 {
		return false
	}
	meta, payload := strings.ToLower(rest[:comma]), rest[comma+1:]
	var body string
	if strings.Contains(meta, ";base64") {
		raw := pctDecodeLenient(payload, false)
		raw = strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, raw)
		b, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			b, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(raw, "="))
		}
		if err != nil {
			return false
		}
		body = string(b)
	} else {
		body = pctDecodeLenient(payload, false)
	}
	// The mime type is attacker-declared; judge by what the bytes are.
	if !strings.Contains(meta, "svg") && !strings.Contains(strings.ToLower(body), "<svg") {
		return false
	}
	return svgActiveContentRE.MatchString(body) || svgEntityCarriesMarkup(body)
}

// SignalPromptIconUnsafeSource is the prompts/list form of the icon check.
const SignalPromptIconUnsafeSource NotificationSignal = "prompt_icon_unsafe_source"
