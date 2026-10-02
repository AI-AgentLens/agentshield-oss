package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"html"
	"net"
	"path"
	"regexp"
	"sort"
	"strings"
)

// URL-mode elicitation (MCP 2025-11-25, SEP-1036).
//
// A form-mode elicitation asks the human to type into a dialog the client
// draws. A URL-mode elicitation asks the client to OPEN a server-chosen URL,
// so the interaction happens out of band — the spec's motivating cases are
// OAuth authorization, payments, and credentials that must never pass through
// the client. The spec's own security section asks the client to show the full
// URL, highlight its domain, warn on Punycode, and never auto-open; it tells
// servers not to put credentials in the URL and to use HTTPS. Until this file,
// the proxy did not parse `mode` or `url` at all.
//
// Three verdicts, and the direction of the burden of proof differs:
//
//   - BLOCK, install deeplink. The URL is an AI host's own MCP-install deep
//     link (`vscode:mcp/install?…`, `cursor://…/mcp/install?…`, the web
//     redirects that forward to one, or one nested in another URL's query).
//     URL mode exists to take an interaction OUT of the client; an install
//     link routes it straight back IN, as a privileged act — registering and
//     launching a new MCP server — that the human consented to as "open this
//     page". It is the DeepJack / Envade class
//     (privilege-escalation/agent-containment/mcp-deeplink-consent-truncation-bypass),
//     whose own taxonomy note says the click "happens outside the agent's
//     mediated surface". URL-mode elicitation puts it inside: an MCP server can
//     deliver the link through the protocol itself. The message text and the
//     form schema are read too, because a client renders them and a link
//     there is one click from the same place.
//   - BLOCK, unsafe target. A scheme that executes or reaches the local
//     machine instead of navigating (`javascript:`, `vbscript:`, `data:`,
//     `file:`, `smb:`, a UNC path — the last three leak an NTLM hash on a
//     Windows host the moment they are resolved), or a URL carrying userinfo
//     (`https://github.com@evil.example/`: the display-spoof the spec's
//     "highlight the domain" advice exists for, and the credential-in-URL the
//     spec forbids servers to send). Every member is enumerable.
//   - AUDIT, weak target. Cleartext `http://` to a non-loopback host, an
//     IDN/Punycode host, a host-application scheme that is not an install
//     link (`vscode://file/…`), any other non-web scheme, or no scheme at all.
//     Each has a legitimate reading; the receipt is the response.
//
// The URL is normalised the way a browser does before the scheme is read:
// ASCII tab/CR/LF are deleted anywhere and leading/trailing C0 controls and
// spaces are stripped (WHATWG URL parsing), so `java\tscript:` is `javascript:`.

const (
	// SignalElicitationURLInstallDeeplink — an AI host's MCP-install deep link
	// delivered through URL-mode elicitation (url, message or schema). BLOCK.
	SignalElicitationURLInstallDeeplink ElicitationSignal = "elicitation_url_mcp_install_deeplink"
	// SignalElicitationURLUnsafeTarget — a script/data/file/SMB/UNC target, or
	// userinfo in the URL. BLOCK.
	SignalElicitationURLUnsafeTarget ElicitationSignal = "elicitation_url_unsafe_target"
	// SignalElicitationURLWeakTarget — cleartext, IDN, host-app non-install,
	// other non-web scheme, or no scheme. AUDIT.
	SignalElicitationURLWeakTarget ElicitationSignal = "elicitation_url_weak_target"
)

// elicitationURLSentinelEngine names the sentinel that attributes a URL-mode
// finding to a rule id and taxonomy node.
func elicitationURLSentinelEngine(sig ElicitationSignal) string {
	switch sig {
	case SignalElicitationURLInstallDeeplink:
		return "mcp-elicitation-url-mcp-install-deeplink"
	case SignalElicitationURLUnsafeTarget:
		return "mcp-elicitation-url-unsafe-target"
	case SignalElicitationURLWeakTarget:
		return "mcp-elicitation-url-weak-target"
	}
	return ""
}

// elicitationURLSignalBlocks reports whether a URL-mode signal is BLOCK-tier.
func elicitationURLSignalBlocks(sig ElicitationSignal) bool {
	return sig == SignalElicitationURLInstallDeeplink || sig == SignalElicitationURLUnsafeTarget
}

// hostAppSchemes are URI schemes registered by AI coding hosts and IDEs. An
// install deep link on one of them registers and starts an MCP server.
var hostAppSchemes = map[string]bool{
	"vscode": true, "vscode-insiders": true, "vscodium": true, "positron": true,
	"cursor": true, "windsurf": true, "kiro": true, "trae": true, "zed": true,
	"goose": true, "lmstudio": true, "claude": true,
}

// unsafeURLSchemes execute script or reach the local machine or network
// shares instead of navigating to a page.
var unsafeURLSchemes = map[string]string{
	"javascript": "script execution in whatever context opens it",
	"vbscript":   "script execution in whatever context opens it",
	"data":       "an inline document the server wrote, with no origin to show the human",
	"file":       "a local or network-share file; a remote host in a file: URL leaks the user's NTLM hash on Windows",
	"smb":        "a network share; resolving it leaks the user's NTLM hash on Windows",
}

var urlSchemeRE = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9+.\-]*):`)

// urlInTextRE finds URL-shaped tokens inside prose (message text, schema
// strings): any scheme, then everything up to whitespace or a Markdown/HTML
// delimiter. Deliberately general — an install link can hide in the query of
// ANY outer URL, not only a host-app or install-page one (Codex review of
// #4061, finding 4) — and only the install class is ever reported from prose.
var urlInTextRE = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.\-]*:[^\s<>"'` + "`" + `)\]]+`)

// normalizeElicitationURL applies the WHATWG pre-parse cleanup a browser
// performs, so the scheme read here is the scheme that will be acted on.
func normalizeElicitationURL(raw string) string {
	s := strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, raw)
	return strings.TrimFunc(s, func(r rune) bool { return r <= 0x20 })
}

// scanElicitationURLs returns the URL-mode findings for one elicitation.
func scanElicitationURLs(params *ElicitationCreateParams) []ElicitationFinding {
	var out []ElicitationFinding
	if params.URL != "" {
		out = append(out, classifyElicitationURL(params.URL)...)
	}
	// Install deep links anywhere the client renders text. Only the install
	// class is taken from prose: a `file:` path or an http link mentioned in a
	// sentence is a mention, not a target.
	type rendered struct{ text, where string }
	texts := []rendered{{params.Message, "message"}}
	if params.RequestedSchema != nil {
		for _, str := range elicitationSchemaStrings(params.RequestedSchema.Raw) {
			texts = append(texts, rendered{str, "requestedSchema"})
		}
	}
	// A Markdown renderer decodes HTML entities in a link destination, so
	// `[x](vscode&#58;mcp/install?…)` renders as a live install link. Read the
	// entity-decoded form of every text too.
	//
	// Two more renderer rewrites apply to a link destination (Opus review of
	// #4061): CommonMark drops a backslash before ASCII punctuation
	// (`vscode\:mcp/install`), and the URL parser deletes tab/CR/LF, so an
	// entity-encoded tab inside a scheme (`vs&#9;code:`) still opens it.
	for i, n := 0, len(texts); i < n; i++ {
		dec := html.UnescapeString(texts[i].text)
		for _, v := range []string{dec, markdownBackslashUnescape(dec), stripTabNewline(dec)} {
			if v != texts[i].text {
				texts = append(texts, rendered{v, texts[i].where})
			}
		}
	}
	seen := map[string]bool{}
	for _, rt := range texts {
		// No cap on candidates: a cap is a bypass (64 decoy tokens before the
		// link hid it — Opus review of #4061), and each candidate costs a
		// linear scan. A bare install route with no query or fragment
		// configures nothing, so in prose it is a mention, not a link.
		for _, cand := range urlInTextRE.FindAllString(rt.text, -1) {
			if seen[cand] {
				continue
			}
			seen[cand] = true
			if !strings.ContainsAny(cand, "?#") {
				continue
			}
			if detail, ok := installDeeplinkDetail(cand, 0); ok {
				out = append(out, ElicitationFinding{
					Signal:  SignalElicitationURLInstallDeeplink,
					Detail:  "MCP-install deep link in the elicitation " + rt.where + ": " + detail,
					Snippet: truncateURL(cand),
				})
			}
		}
	}
	return out
}

// classifyElicitationURL classifies the `url` of a URL-mode elicitation.
func classifyElicitationURL(raw string) []ElicitationFinding {
	s := normalizeElicitationURL(raw)
	snip := truncateURL(s)
	finding := func(sig ElicitationSignal, detail string) []ElicitationFinding {
		return []ElicitationFinding{{Signal: sig, Detail: detail, Snippet: snip}}
	}

	if strings.HasPrefix(s, `\\`) {
		return finding(SignalElicitationURLUnsafeTarget, "URL-mode elicitation target is a UNC path; resolving it leaks the user's NTLM hash on Windows")
	}
	if detail, ok := installDeeplinkDetail(s, 0); ok {
		return finding(SignalElicitationURLInstallDeeplink, "URL-mode elicitation target is an MCP-install deep link: "+detail+" — URL mode exists to take an interaction out of the client, and this routes it back in as a server install the human consented to as \"open this page\"")
	}

	m := urlSchemeRE.FindStringSubmatch(s)
	if m == nil {
		return finding(SignalElicitationURLWeakTarget, "URL-mode elicitation target has no scheme, so it is not an absolute URL; what it resolves against is up to the client")
	}
	scheme := strings.ToLower(m[1])
	if why, ok := unsafeURLSchemes[scheme]; ok {
		return finding(SignalElicitationURLUnsafeTarget, "URL-mode elicitation target uses the "+scheme+": scheme — "+why)
	}
	if hostAppSchemes[scheme] {
		return finding(SignalElicitationURLWeakTarget, "URL-mode elicitation target is a "+scheme+": deep link into an AI host application rather than a web page")
	}
	if scheme != "http" && scheme != "https" {
		return finding(SignalElicitationURLWeakTarget, "URL-mode elicitation target uses the non-web scheme "+scheme+":")
	}

	w := splitWebURL(s[len(m[0]):])
	if w.hasUserinfo {
		return finding(SignalElicitationURLUnsafeTarget, "URL-mode elicitation target carries userinfo ("+w.userinfo+"@) before the real host "+w.host+" — the display spoof the spec's highlight-the-domain advice exists for, and a credential in the URL, which the spec forbids a server to send")
	}
	if w.host == "" {
		return finding(SignalElicitationURLWeakTarget, "URL-mode elicitation target has no host")
	}
	var out []ElicitationFinding
	if scheme == "http" && !isLoopbackHost(w.host) {
		out = append(out, ElicitationFinding{Signal: SignalElicitationURLWeakTarget, Detail: "URL-mode elicitation target is cleartext http:// to a non-loopback host; the spec asks servers to use HTTPS outside development", Snippet: snip})
	}
	if isIDNHost(w.host) {
		out = append(out, ElicitationFinding{Signal: SignalElicitationURLWeakTarget, Detail: "URL-mode elicitation target host is internationalized (" + w.host + "); the spec asks clients to warn on Punycode", Snippet: snip})
	}
	return out
}

// webURL is the part of an http(s) URL this file needs, split the way a
// browser splits it (WHATWG special-scheme parsing) rather than the way
// net/url does. The Codex review of #4061 found three places the two
// disagree, each a bypass: `https:host` with no slashes is an authority to a
// browser and an opaque path to net/url; one malformed escape anywhere makes
// net/url reject the whole URL; and net/url keeps the port on the host.
type webURL struct {
	hasUserinfo bool
	userinfo    string
	host        string // lower-cased, port and trailing dot removed, fullwidth folded
	path        string // percent-decoded where valid
	query       string // raw
	fragment    string // raw
}

// splitWebURL splits the part of an http(s) URL after "scheme:". Backslashes
// are slashes, any number of leading slashes is allowed, the authority ends at
// the first of / ? #, and userinfo is everything before its last '@'.
func splitWebURL(rest string) webURL {
	var w webURL
	rest = strings.ReplaceAll(rest, `\`, "/")
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest, w.fragment = rest[:i], rest[i+1:]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest, w.query = rest[:i], rest[i+1:]
	}
	rest = strings.TrimLeft(rest, "/")
	authority := rest
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		// Dot segments (`.`, `..`, and their %2e spellings, decoded first)
		// are resolved as a browser resolves them, so `/docs/../install-mcp`
		// is the install page (Opus review of #4061).
		authority, w.path = rest[:i], path.Clean(pctDecodeLenient(rest[i:], false))
	}
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		w.hasUserinfo, w.userinfo, authority = true, authority[:at], authority[at+1:]
	}
	host := pctDecodeLenient(authority, false)
	if strings.HasPrefix(host, "[") {
		if i := strings.IndexByte(host, ']'); i >= 0 {
			host = host[:i+1]
		}
	} else if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	w.host = strings.TrimRight(strings.ToLower(foldFullwidth(host)), ".")
	return w
}

// foldFullwidth maps the fullwidth ASCII block and the ideographic full stops
// to ASCII, as IDNA mapping does before a browser resolves a host:
// `ｃｕｒｓｏｒ。com` is cursor.com.
func foldFullwidth(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 0xFF01 && r <= 0xFF5E:
			return r - 0xFEE0
		case r == 0x3002 || r == 0xFF0E || r == 0xFF61:
			return '.'
		}
		return r
	}, s)
}

// pctDecodeLenient decodes valid %XX escapes and leaves invalid ones as they
// are, as a browser does; plusIsSpace applies form encoding. It never fails,
// so one malformed escape cannot hide the rest of the string.
func pctDecodeLenient(s string, plusIsSpace bool) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		case c == '+' && plusIsSpace:
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// markdownBackslashUnescape removes a backslash before ASCII punctuation, as
// CommonMark does inside a link destination.
func markdownBackslashUnescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", s[i+1]) >= 0 {
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// stripTabNewline deletes ASCII tab, CR and LF, as the URL parser does.
func stripTabNewline(s string) string {
	if !strings.ContainsAny(s, "\t\r\n") {
		return s
	}
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

// lenientParams splits a query or fragment into decoded name/value pairs the
// way URLSearchParams does: on '&' only, each part at its first '=', every
// escape decoded leniently. A malformed parameter costs only itself.
func lenientParams(q string) [][2]string {
	var out [][2]string
	if q == "" {
		return out
	}
	for _, part := range strings.Split(q, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		out = append(out, [2]string{pctDecodeLenient(k, true), pctDecodeLenient(v, true)})
	}
	return out
}

// installRouteRE matches the route of a host-application install deep link:
// the authority and path (leading slashes removed, lower-cased) must BE an
// install route, not merely contain the words. `vscode:mcp/install`,
// `cursor://anysphere.cursor-deeplink/mcp/install`, `kiro://kiro.mcp/add` —
// but not `vscode://file/home/me/mcp/install.md` (Codex review of #4061,
// finding 5).
var installRouteRE = regexp.MustCompile(`^(?:[a-z0-9.\-]+/)?mcp/(?:install|add)/?$|^(?:[a-z0-9.\-]+\.)?mcp/(?:install|add)/?$|^add_mcp/?$`)

// installRedirectRoutes are the https pages that exist to forward a browser to
// an install deep link, by host, matched against the whole decoded path. The
// same hosts' documentation (`cursor.com/docs/mcp/install-links`) is not a
// route.
var installRedirectRoutes = map[string]*regexp.Regexp{
	"vscode.dev":          regexp.MustCompile(`^/redirect/mcp/install/?$`),
	"insiders.vscode.dev": regexp.MustCompile(`^/redirect/mcp/install/?$`),
	"cursor.com":          regexp.MustCompile(`^/(?:[a-z]{2}(?:-[a-z]{2,4})?/)?install-mcp/?$`),
	"www.cursor.com":      regexp.MustCompile(`^/(?:[a-z]{2}(?:-[a-z]{2,4})?/)?install-mcp/?$`),
	"lmstudio.ai":         regexp.MustCompile(`^/install-mcp/?$`),
}

// installDeeplinkDetail reports whether s is an MCP-install deep link — on a
// host-application scheme, on an install-redirect page, or nested in the
// query or fragment of any URL — and summarises what it installs.
func installDeeplinkDetail(s string, depth int) (string, bool) {
	if depth > 4 {
		return "", false
	}
	s = normalizeElicitationURL(s)
	m := urlSchemeRE.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	scheme := strings.ToLower(m[1])
	rest := s[len(m[0]):]

	var query, frag string
	switch {
	case hostAppSchemes[scheme]:
		head := rest
		if i := strings.IndexByte(head, '#'); i >= 0 {
			head, frag = head[:i], head[i+1:]
		}
		if i := strings.IndexByte(head, '?'); i >= 0 {
			head, query = head[:i], head[i+1:]
		}
		route := strings.ToLower(strings.TrimLeft(pctDecodeLenient(head, false), "/"))
		// `vscode://file/<path>` opens a file; its path is never a route.
		if strings.HasPrefix(route, "file/") {
			break
		}
		if installRouteRE.MatchString(route) || (scheme == "goose" && strings.TrimRight(route, "/") == "extension") {
			return describeInstall(scheme, query), true
		}
	case scheme == "http" || scheme == "https":
		w := splitWebURL(rest)
		query, frag = w.query, w.fragment
		if re, ok := installRedirectRoutes[w.host]; ok && re.MatchString(strings.ToLower(w.path)) {
			return describeInstall(w.host, query), true
		}
	default:
		if i := strings.IndexByte(rest, '#'); i >= 0 {
			rest, frag = rest[:i], rest[i+1:]
		}
		if i := strings.IndexByte(rest, '?'); i >= 0 {
			query = rest[i+1:]
		}
	}

	// Nested: DeepJack's second variant parks the install link inside a
	// parameter the outer handler never decodes. Every parameter name and
	// value of the query and the fragment is a candidate, and so is the whole
	// decoded fragment.
	var candidates []string
	for _, part := range []string{query, frag} {
		for _, kv := range lenientParams(part) {
			candidates = append(candidates, kv[0], kv[1])
		}
	}
	if frag != "" {
		candidates = append(candidates, pctDecodeLenient(frag, false))
	}
	for _, v := range candidates {
		// Gate on the same normalisation the recursive call applies: a
		// leading C0 control or a tab inside the scheme is stripped by the
		// browser that follows the redirect (Opus review of #4061).
		if urlSchemeRE.MatchString(normalizeElicitationURL(v)) {
			if detail, ok := installDeeplinkDetail(v, depth+1); ok {
				return "nested inside " + scheme + ": URL — " + detail, true
			}
		}
	}
	return "", false
}

// describeInstall summarises an install link's configuration for the audit
// record: name, command, args, env keys, headers, remote url, and whether any
// value carries the whitespace padding DeepJack used to push the command past
// a single-line confirm dialog. Best-effort — the verdict does not depend on it.
func describeInstall(via, query string) string {
	cfg := installConfig(query)
	if len(cfg) == 0 {
		return "installs an MCP server via " + via
	}
	var parts []string
	if name, _ := cfg["name"].(string); name != "" {
		parts = append(parts, "name "+quoteShort(name))
	}
	if cmd, _ := cfg["command"].(string); cmd != "" {
		parts = append(parts, "stdio command "+quoteShort(cmd))
	}
	if args, ok := cfg["args"].([]interface{}); ok && len(args) > 0 {
		var as []string
		for _, a := range args {
			if s, ok := a.(string); ok {
				as = append(as, s)
			}
		}
		parts = append(parts, "args "+quoteShort(strings.Join(as, " ")))
	}
	if u, _ := cfg["url"].(string); u != "" {
		parts = append(parts, "remote url "+quoteShort(u))
	}
	for _, key := range []string{"env", "headers"} {
		if m, ok := cfg[key].(map[string]interface{}); ok && len(m) > 0 {
			parts = append(parts, key+" "+strings.Join(sortedMapKeys(m), ","))
		}
	}
	if ef, _ := cfg["envFile"].(string); ef != "" {
		parts = append(parts, "envFile "+quoteShort(ef))
	}
	// Padding is checked on the decoded config and on the query read with
	// form encoding too: VS Code's whole-query JSON is decodeURIComponent'd
	// (a '+' stays a '+'), but a link built with form encoding spells its
	// spaces as '+'.
	if b, err := json.Marshal(cfg); err == nil && (hasPaddingRun(string(b)) || hasPaddingRun(pctDecodeLenient(query, true))) {
		parts = append(parts, "whitespace padding that pushes the rest past a single-line dialog")
	}
	return "installs an MCP server via " + via + " (" + strings.Join(parts, "; ") + ")"
}

// installConfig extracts the server configuration from an install link's
// query: VS Code's whole-query JSON, a `config` parameter holding JSON or
// base64 JSON (Cursor, LM Studio, the vscode.dev redirect), or Goose's
// cmd/arg parameters. Decoding is lenient throughout.
func installConfig(query string) map[string]interface{} {
	cfg := map[string]interface{}{}
	if obj := jsonObject(pctDecodeLenient(query, false)); obj != nil {
		return obj
	}
	params := lenientParams(query)
	get := func(name string) string {
		for _, kv := range params {
			if kv[0] == name {
				return kv[1]
			}
		}
		return ""
	}
	if c := get("config"); c != "" {
		if obj := jsonObject(c); obj != nil {
			cfg = obj
		} else {
			for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
				if b, err := enc.DecodeString(c); err == nil {
					if obj := jsonObject(string(b)); obj != nil {
						cfg = obj
						break
					}
				}
			}
		}
	}
	if n := get("name"); n != "" {
		if _, ok := cfg["name"]; !ok {
			cfg["name"] = n
		}
	}
	if c := get("cmd"); c != "" {
		cfg["command"] = c
		var args []interface{}
		for _, kv := range params {
			if kv[0] == "arg" {
				args = append(args, kv[1])
			}
		}
		if len(args) > 0 {
			cfg["args"] = args
		}
	}
	return cfg
}

func jsonObject(s string) map[string]interface{} {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	var m map[string]interface{}
	if dec.Decode(&m) != nil {
		return nil
	}
	return m
}

func hasPaddingRun(s string) bool {
	run := 0
	for _, r := range s {
		if r == ' ' || r == '\t' || r == 0xa0 {
			run++
			if run >= 16 {
				return true
			}
			continue
		}
		run = 0
	}
	return false
}

func quoteShort(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 60 {
		s = s[:60] + "..."
	}
	return `"` + s + `"`
}

func truncateURL(s string) string {
	if len(s) > 160 {
		return s[:160] + "..."
	}
	return s
}

func sortedMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func isLoopbackHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func isIDNHost(host string) bool {
	for _, label := range strings.Split(host, ".") {
		if strings.HasPrefix(label, "xn--") {
			return true
		}
	}
	for _, r := range host {
		if r > 0x7f {
			return true
		}
	}
	return false
}

// elicitationSchemaStrings returns every key and string value in the raw
// requested schema, decoded (a regex over the raw bytes would read `\/`
// escapes, not slashes). UseNumber keeps a 1e400 from failing the decode.
func elicitationSchemaStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if dec.Decode(&v) != nil {
		return nil
	}
	var out []string
	var walk func(n interface{})
	walk = func(n interface{}) {
		switch x := n.(type) {
		case string:
			out = append(out, x)
		case []interface{}:
			for _, e := range x {
				walk(e)
			}
		case map[string]interface{}:
			for _, k := range sortedMapKeys(x) {
				out = append(out, k)
				walk(x[k])
			}
		}
	}
	walk(v)
	return out
}
