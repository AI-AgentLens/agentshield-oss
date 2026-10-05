package mcp

import (
	"encoding/base64"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
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
// resources/list and resources/templates/list (#4062). On every listing
// surface a finding hides only the entry that carries it, and that entry
// gets its own receipt (MessageHandler.hideIconCarrier, #4159); serverInfo
// has no entry to hide, so there the handshake is blocked. The AUDIT half of
// #4062 (http(s) icons to link-local / RFC1918 hosts, scanIconsInternal) is a
// receipt only on tools, prompts, resources and templates: a finding never
// hides the entry, because an internal-network icon has a legitimate reading.
// serverInfo gets the receipt on the initialize event
// (FilterInitializeResponse). Not covered yet: resource_link (no receipt-only
// path there).

// SignalIconUnsafeSource flags a tool icon whose src executes script or makes
// the host resolve an SMB/remote-file path while rendering the list. BLOCK.
const SignalIconUnsafeSource PoisonSignal = "icon_unsafe_source"

// ToolIcon is one entry of an `icons` array. Sizes and Theme are the spec's
// two selector fields, typed so a kept entry's icons round-trip whole when a
// sibling is hidden (#4159); neither carries prose, and neither is scanned.
type ToolIcon struct {
	Src      string   `json:"src"`
	MimeType string   `json:"mimeType,omitempty"`
	Sizes    []string `json:"sizes,omitempty"`
	Theme    string   `json:"theme,omitempty"`
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

var svgNumRefRE = regexp.MustCompile(`(?i)&#(?:x([0-9a-f]{1,6})|([0-9]{1,7}));`)
var svgScriptSchemeRE = regexp.MustCompile(`(?i)(?:java|vb)script\s*:`)

// svgDecodeNumRefs expands numeric character references, so an entity value
// that spells a scheme with encoded letters (`&#106;avascript:`) reads as the
// scheme (#4151).
func svgDecodeNumRefs(s string) string {
	return svgNumRefRE.ReplaceAllStringFunc(s, func(m string) string {
		sub := svgNumRefRE.FindStringSubmatch(m)
		var n int64
		var err error
		if sub[1] != "" {
			n, err = strconv.ParseInt(sub[1], 16, 32)
		} else {
			n, err = strconv.ParseInt(sub[2], 10, 32)
		}
		if err != nil || n <= 0 || n > 0x10FFFF {
			return m
		}
		return string(rune(n))
	})
}

func svgEntityCarriesMarkup(body string) bool {
	for _, m := range svgEntityDeclRE.FindAllStringSubmatch(body, -1) {
		v := m[1] + m[2]
		if svgEncodedLTRE.MatchString(v) || svgScriptSchemeRE.MatchString(svgDecodeNumRefs(v)) {
			return true
		}
	}
	return false
}

// svgToUTF8 returns the payload as UTF-8 text. An XML parser honours a UTF-16
// byte-order mark, but the regexps here are ASCII, so a UTF-16 body (NUL
// between every character) matched nothing and the icon decided ALLOW (#4151).
// Without a BOM, a body whose even or odd bytes are almost all NUL is read as
// UTF-16 too: a declaration of encoding="UTF-16" does the same.
func svgToUTF8(b []byte) string {
	le := -1 // 1 = little endian, 0 = big endian
	switch {
	case len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE:
		le, b = 1, b[2:]
	case len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF:
		le, b = 0, b[2:]
	case len(b) >= 4:
		var even, odd int
		for i, c := range b {
			if c == 0 {
				if i%2 == 0 {
					even++
				} else {
					odd++
				}
			}
		}
		half := len(b) / 2
		if odd*10 >= half*9 {
			le = 1
		} else if even*10 >= half*9 {
			le = 0
		}
	}
	if le < 0 {
		return string(b)
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		if le == 1 {
			u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
		} else {
			u = append(u, uint16(b[i+1])|uint16(b[i])<<8)
		}
	}
	return string(utf16.Decode(u))
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
		body = svgToUTF8(b)
	} else {
		body = svgToUTF8([]byte(pctDecodeLenient(payload, false)))
	}
	// The mime type is attacker-declared; judge by what the bytes are.
	if !strings.Contains(meta, "svg") && !strings.Contains(strings.ToLower(body), "<svg") {
		return false
	}
	return svgActiveContentRE.MatchString(body) || svgEntityCarriesMarkup(body)
}

// SignalPromptIconUnsafeSource is the prompts/list form of the icon check.
const SignalPromptIconUnsafeSource NotificationSignal = "prompt_icon_unsafe_source"

// internalIconHost returns the host of an http(s) icon src that names the
// user's own network: a link-local or cloud-metadata address, an RFC1918 or
// unique-local address, or the GCP metadata name. The host fetches it from the
// user's machine when it renders the list, so a server can probe the internal
// network by GET (#4062). Loopback is excluded: a local stdio server may
// legitimately serve its own icons. AUDIT only — the entry is never hidden,
// because an internal icon has a legitimate reading (a corporate icon CDN).
func internalIconHost(src string) string {
	s := normalizeElicitationURL(src)
	m := urlSchemeRE.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	if sc := strings.ToLower(m[1]); sc != "http" && sc != "https" {
		return ""
	}
	host := splitWebURL(s[len(m[0]):]).host
	if host == "metadata.google.internal" {
		return host
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		ip = whatwgIPv4(host)
	}
	if ip == nil || ip.IsLoopback() {
		return ""
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return host
	}
	return ""
}

// scanIconsInternal returns one AUDIT-tier finding per icon src that names an
// internal-network host. Findings reuse SignalIconUnsafeSource's sentinel for
// attribution but are never a reason to hide an entry.
func scanIconsInternal(owner string, icons []ToolIcon) []PoisonFinding {
	var out []PoisonFinding
	for _, ic := range icons {
		if host := internalIconHost(ic.Src); host != "" {
			out = append(out, PoisonFinding{
				Signal:  SignalIconUnsafeSource,
				Detail:  owner + " icon src fetches from internal-network host " + host + " when the list renders (a GET from the user's machine into its own network)",
				Snippet: truncateURL(normalizeElicitationURL(ic.Src)),
			})
		}
	}
	return out
}

// whatwgIPv4 parses a host the way a browser's URL parser does when it ends in
// a number: 1-4 dot-separated parts, each decimal, 0x-hex or 0-leading octal,
// the last part filling the remaining bytes (`2852039166`, `0xa9fea9fe`,
// `169.254.43774`, `0251.0376.0251.0376`). net.ParseIP accepts only the
// dotted-decimal form, so every other spelling of an internal address read as
// a hostname (#4062). Returns nil when the host is not a number.
func whatwgIPv4(host string) net.IP {
	parts := strings.Split(host, ".")
	if len(parts) > 1 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 || len(parts) > 4 {
		return nil
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		base := 10
		switch {
		case len(p) >= 2 && (p[:2] == "0x" || p[:2] == "0X"):
			p, base = p[2:], 16
			if p == "" {
				p = "0"
			}
		case len(p) >= 2 && p[0] == '0':
			p, base = p[1:], 8
		}
		n, err := strconv.ParseUint(p, base, 32)
		if err != nil {
			return nil
		}
		nums[i] = n
	}
	last := len(nums) - 1
	if nums[last] >= 1<<(8*uint(4-last)) {
		return nil
	}
	v := nums[last]
	for i, n := range nums[:last] {
		if n > 255 {
			return nil
		}
		v += n << (8 * uint(3-i))
	}
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
