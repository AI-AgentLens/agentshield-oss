package analyzer

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode"

	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
)

// Outbound destination allowlist (#4437).
//
// The stage is opt-in: BuildAnalyzerPipeline registers it only when the
// operator's policy sets `network.enforce_allowlist: true`, so with the switch
// off it does not exist and every decision is what it was before. When it is
// registered it does one thing: for a network command it can parse, it names
// each destination host and emits a BLOCK for a host that is not on the
// operator's own `network.allow_domains` list. Loopback (localhost,
// *.localhost, 127.0.0.0/8, ::1) is not egress and is never blocked.
//
// "Only deny what you can justify" is the whole design. A BLOCK needs a
// concrete host, extracted from a command this file knows how to read. Every
// doubt — a host in a variable, an option this file does not know, an argv it
// cannot split into options and operands, a URL two parsers would read
// differently — produces NO finding, so the existing rules and the AUDIT
// default decide exactly as they would have. Never "I do not recognise this,
// so block it".

const (
	// EgressAllowlistRuleID is the rule id every allowlist finding carries.
	// Fixed, like the data-label stage's mechanism node: the destination is
	// operator data, and it rides in the reason, not the id.
	EgressAllowlistRuleID = "ne-block-unlisted-destination"

	// EgressAllowlistTaxonomy is the node whose own recommendation is an
	// outbound-domain allowlist. Reused, not new (Gary, 2026-10-20).
	EgressAllowlistTaxonomy = "data-exfiltration/network-egress/network-http-request"
)

// EgressAllowlist answers "may a command reach this host?" for one operator
// list. Matching is case-insensitive and ignores ports.
//
//   - A host entry (`github.com`) allows that host and every subdomain of it
//     (`api.github.com`), and nothing else: not `github.com.evil.example`,
//     `evilgithub.com`, `github.io` or `githubusercontent.com`.
//   - A wildcard entry (`*.github.com`) allows subdomains only.
//   - An IP entry allows that address only. An IP is never matched by a
//     host entry or by a subdomain rule.
type EgressAllowlist struct {
	domains   map[string]bool // entry and its subdomains
	wildcards map[string]bool // subdomains of entry only
	ips       map[netip.Addr]bool
}

// NewEgressAllowlist builds the matcher from operator entries. It returns the
// entries it could not read as a host, a `*.host` wildcard or an IP address;
// those are ignored (the caller reports them as a config warning). An entry
// written as a URL or with a port (`https://github.com/`, `github.com:443`) is
// read for its host.
func NewEgressAllowlist(entries []string) (*EgressAllowlist, []string) {
	l := &EgressAllowlist{
		domains:   map[string]bool{},
		wildcards: map[string]bool{},
		ips:       map[netip.Addr]bool{},
	}
	var invalid []string
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		wildcard := false
		if strings.HasPrefix(e, "*.") {
			wildcard = true
			e = e[2:]
		}
		host, ok := entryHost(e)
		if !ok {
			invalid = append(invalid, raw)
			continue
		}
		if ip, isIP := parseHostIP(host); isIP {
			if wildcard {
				invalid = append(invalid, raw)
				continue
			}
			l.ips[ip] = true
			continue
		}
		if wildcard {
			l.wildcards[host] = true
		} else {
			l.domains[host] = true
		}
	}
	return l, invalid
}

// entryHost reads one allow_domains entry. A bare host is the common case; a
// URL or host:port is accepted for its host, because the operator's intent is
// unambiguous and ignoring the entry would block what they meant to allow.
func entryHost(e string) (string, bool) {
	if e == "" {
		return "", false
	}
	if h, ok := normalizeHost(e); ok {
		return h, true
	}
	hosts, ok := authorityHosts(e, false, nil)
	if !ok || len(hosts) != 1 {
		return "", false
	}
	return hosts[0], true
}

// Allows reports whether host (already normalized by normalizeHost) is on
// the list. Loopback is always allowed — see isLoopbackHost.
func (l *EgressAllowlist) Allows(host string) bool {
	if isLoopbackHost(host) {
		return true
	}
	if ip, isIP := parseHostIP(host); isIP {
		return l.ips[ip]
	}
	if l.domains[host] {
		return true
	}
	for i := 0; i < len(host); i++ {
		if host[i] != '.' {
			continue
		}
		parent := host[i+1:]
		if l.domains[parent] || l.wildcards[parent] {
			return true
		}
	}
	return false
}

// isLoopbackHost reports whether a normalized host is loopback, which the
// allowlist never blocks: a request to this machine is not egress (Gary,
// 2026-10-20). Exactly three forms:
//
//   - `localhost` and any `*.localhost` name (RFC 6761 reserves both for
//     loopback);
//   - an IPv4 literal in 127.0.0.0/8, including its IPv4-mapped IPv6 form;
//   - the IPv6 literal ::1.
//
// Nothing else is: not 0.0.0.0 or ::, which mean "all interfaces" rather
// than "this host", and not an alternate spelling such as `127.1`, which is
// not an IP literal by the rule parseHostIP applies everywhere else in this
// file and so stays an unlisted name.
func isLoopbackHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip, isIP := parseHostIP(host)
	if !isIP {
		return false
	}
	return ip.Is4() && ip.IsLoopback() || ip == netip.IPv6Loopback()
}

// EgressAllowlistAnalyzer is the conditional pipeline stage. See the file
// comment for what it does and, more importantly, what it refuses to do.
type EgressAllowlistAnalyzer struct {
	list *EgressAllowlist
}

// NewEgressAllowlistAnalyzer wraps a built allowlist.
func NewEgressAllowlistAnalyzer(list *EgressAllowlist) *EgressAllowlistAnalyzer {
	return &EgressAllowlistAnalyzer{list: list}
}

// Name returns the analyzer identifier.
func (a *EgressAllowlistAnalyzer) Name() string { return "egress-allowlist" }

// Analyze emits one BLOCK per distinct named destination that is not on the
// list. It reads ctx.Parsed, so it must run after the structural stage; with
// no parse it returns nothing.
func (a *EgressAllowlistAnalyzer) Analyze(ctx *AnalysisContext) []Finding {
	if a == nil || a.list == nil || ctx == nil || ctx.Parsed == nil {
		return nil
	}
	var findings []Finding
	seen := map[string]bool{}
	walkSegments(ctx.Parsed, func(seg CommandSegment) {
		for _, host := range NetworkDestinations(seg) {
			if seen[host] || a.list.Allows(host) {
				continue
			}
			seen[host] = true
			findings = append(findings, Finding{
				AnalyzerName: "egress-allowlist",
				RuleID:       EgressAllowlistRuleID,
				Decision:     "BLOCK",
				Confidence:   0.95,
				Reason:       fmt.Sprintf("Destination %s is not on the allowed destinations list (network.allow_domains)", host),
				TaxonomyRef:  EgressAllowlistTaxonomy,
			})
		}
	})
	return findings
}

// walkSegments visits every segment of pc and of every command it runs
// indirectly (`bash -c '…'`, `$(…)`), which the parser has already decomposed
// into Subcommands. Text that is not executed (an echo argument, a commit
// message, a heredoc fed to cat) never becomes a segment, so it is never read.
func walkSegments(pc *ParsedCommand, visit func(CommandSegment)) {
	if pc == nil {
		return
	}
	for _, seg := range pc.Segments {
		visit(seg)
	}
	for _, sub := range pc.Subcommands {
		walkSegments(sub, visit)
	}
}

// NetworkDestinations returns the destination hosts a segment names, in
// argv order, normalized for matching. It returns nil when the program is not
// one this file parses, or when the argv cannot be read with confidence.
//
// The parsed-tool set is deliberately closed and enumerated here. Anything
// else — ssh/scp/rsync (a host operand may be an ~/.ssh/config alias, not a
// host name), nc, httpie, language one-liners, package managers — names no
// destination and is left to the existing rules.
func NetworkDestinations(seg CommandSegment) []string {
	prog := seg.Program
	if prog == "" {
		prog = seg.Executable
	}
	words := make([]string, len(seg.RawWords))
	for i, w := range seg.RawWords {
		words[i] = egressWordText(w)
	}
	switch strings.ToLower(prog) {
	case "curl":
		return curlDestinations(words)
	case "wget":
		return wgetDestinations(words)
	case "git":
		return gitDestinations(words)
	}
	return nil
}

// --- word handling -----------------------------------------------------------

// egressWordText performs shell quote removal on one printed AST word. `$` and
// backquotes survive, so an expansion is still visible to the callers, which
// treat it as "cannot name". ANSI-C `$'…'` spans are decoded by pathnorm's
// stripper when that leaves no expansion behind.
func egressWordText(w string) string {
	if strings.Contains(w, "$'") || strings.Contains(w, `$"`) {
		if s := pathnorm.StripShellQuotes(w); !strings.ContainsAny(s, "$`") {
			return s
		}
	}
	return dequoteShellWord(w)
}

// dequoteShellWord is POSIX quote removal: single quotes are literal, double
// quotes keep `$`/backquote live and unescape \$ \` \" \\, and an unquoted
// backslash escapes the next character.
func dequoteShellWord(w string) string {
	if !strings.ContainsAny(w, `'"\`) {
		return w
	}
	var b strings.Builder
	inSingle, inDouble := false, false
	for i := 0; i < len(w); i++ {
		c := w[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			} else {
				b.WriteByte(c)
			}
		case inDouble:
			if c == '"' {
				inDouble = false
			} else if c == '\\' && i+1 < len(w) && strings.IndexByte("$`\"\\", w[i+1]) >= 0 {
				i++
				b.WriteByte(w[i])
			} else {
				b.WriteByte(c)
			}
		default:
			switch {
			case c == '\'':
				inSingle = true
			case c == '"':
				inDouble = true
			case c == '\\' && i+1 < len(w):
				i++
				b.WriteByte(w[i])
			default:
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}

// isDynamicWord reports whether a word starts with an expansion. Such a word
// can expand to an option (`"$OPTS"` → `-e`) that would consume the next word,
// so an argv containing one cannot be split into options and operands.
func isDynamicWord(w string) bool {
	return strings.HasPrefix(w, "$") || strings.HasPrefix(w, "`")
}

// --- host and URL parsing ------------------------------------------------------

// normalizeHost lowercases a host, strips one trailing dot and IPv6 brackets,
// and reports whether what remains is a concrete host name or IP literal.
// Anything carrying an expansion, a glob, an escape or percent-encoding is not.
func normalizeHost(h string) (string, bool) {
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		inner := h[1 : len(h)-1]
		ip, err := netip.ParseAddr(inner)
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return "", false
		}
		return strings.ToLower(inner), true
	}
	h = strings.ToLower(h)
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "", false
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		if ip.Zone() != "" {
			return "", false
		}
		return h, true
	}
	for _, label := range strings.Split(h, ".") {
		runes := []rune(label)
		if len(runes) == 0 || !hostEdgeRune(runes[0]) || !hostEdgeRune(runes[len(runes)-1]) {
			return "", false
		}
		for _, r := range runes {
			if r != '-' && !hostEdgeRune(r) {
				return "", false
			}
		}
	}
	return h, true
}

// hostEdgeRune is a rune a host label may start or end with.
func hostEdgeRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// parseHostIP reports whether a normalized host is an IP literal, unmapping
// IPv4-in-IPv6 so ::ffff:192.0.2.1 and 192.0.2.1 compare equal.
func parseHostIP(h string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(h)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

// endpoint is one destination a URL-shaped string names: the normalized
// host, the port written for it ("" when none is), and the scheme ("" when
// the string has none).
type endpoint struct {
	host, port, scheme string
}

// authorityEndpoints returns the endpoint(s) a URL-shaped string names.
//
// With a scheme (`https://…`), the scheme must be in schemes (nil accepts any)
// — so `file://` and `ipfs://`, which name no network host, are refused by
// the callers that pass a set. Without one, requireScheme refuses it, else
// the whole string is read as `[user@]host[:port][/path]`, which is how curl
// and wget read a bare operand.
//
// The authority is the text between `//` and the first `/`, `?` or `#`.
// More than one literal `@` in it is refused, because parsers disagree on
// which one ends the userinfo. After the userinfo, host and port must be
// fully literal: an expansion there could move the host (`host:$P` with
// P=`x@other` makes `other` the host), so it is refused. An expansion in the
// userinfo alone (`https://user:$TOKEN@host/`, the usual way a token rides in
// a git remote) leaves the written host as the destination. A single-level
// `{a,b}` group in the host is expanded, as both the shell and curl's URL
// globbing would, so it yields one endpoint per alternative.
func authorityEndpoints(s string, requireScheme bool, schemes map[string]bool) ([]endpoint, bool) {
	rest, scheme := s, ""
	if sc, after, ok := splitScheme(s); ok {
		if schemes != nil && !schemes[sc] {
			return nil, false
		}
		rest, scheme = after, sc
	} else if requireScheme {
		return nil, false
	}
	authority := rest
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		authority = rest[:end]
	}
	if authority == "" || strings.ContainsAny(authority, "\\%\"' \t\r\n*") {
		return nil, false
	}
	hostport := authority
	switch strings.Count(authority, "@") {
	case 0:
	case 1:
		hostport = authority[strings.IndexByte(authority, '@')+1:]
	default:
		return nil, false
	}
	if strings.ContainsAny(hostport, "$`") {
		return nil, false
	}
	expanded, ok := expandBraceGroups(hostport)
	if !ok {
		return nil, false
	}
	var eps []endpoint
	for _, a := range expanded {
		h, port, ok := hostPort(a)
		if !ok {
			return nil, false
		}
		eps = append(eps, endpoint{host: h, port: port, scheme: scheme})
	}
	return eps, true
}

// authorityHosts is authorityEndpoints without the ports.
func authorityHosts(s string, requireScheme bool, schemes map[string]bool) ([]string, bool) {
	eps, ok := authorityEndpoints(s, requireScheme, schemes)
	if !ok {
		return nil, false
	}
	hosts := make([]string, len(eps))
	for i, e := range eps {
		hosts[i] = e.host
	}
	return hosts, true
}

// hostPort reads `host[:port]`, where host may be a bracketed IPv6 literal.
// The port is returned canonical ("" when none or empty is written).
func hostPort(a string) (host, port string, ok bool) {
	rest := ""
	if strings.HasPrefix(a, "[") {
		end := strings.IndexByte(a, ']')
		if end < 0 {
			return "", "", false
		}
		host, rest = a[:end+1], a[end+1:]
	} else {
		if strings.ContainsAny(a, "[]") {
			return "", "", false
		}
		switch strings.Count(a, ":") {
		case 0:
			host = a
		case 1:
			i := strings.IndexByte(a, ':')
			host, rest = a[:i], a[i:]
		default:
			return "", "", false
		}
	}
	if !validPort(rest, true) {
		return "", "", false
	}
	h, ok := normalizeHost(host)
	if !ok {
		return "", "", false
	}
	return h, canonicalPort(strings.TrimPrefix(rest, ":")), true
}

// canonicalPort drops leading zeros so "0443" and "443" compare equal.
func canonicalPort(p string) string {
	if p == "" {
		return ""
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return p
	}
	return strconv.Itoa(n)
}

// validPort accepts "", or ":" followed by digits (an empty port is the
// scheme default to curl).
func validPort(p string, allowEmpty bool) bool {
	if p == "" {
		return allowEmpty
	}
	if p[0] != ':' {
		return false
	}
	for _, r := range p[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// splitScheme splits "scheme://rest" when the text before "://" is a valid
// URL scheme. `host/x?u=https://y` has no scheme: its "://" is in the query.
func splitScheme(s string) (scheme, rest string, ok bool) {
	idx := strings.Index(s, "://")
	if idx < 0 {
		return "", "", false
	}
	scheme = strings.ToLower(s[:idx])
	if !validScheme(scheme) {
		return "", "", false
	}
	return scheme, s[idx+3:], true
}

func validScheme(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, r := range s {
		letterOrDigit := r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		if !letterOrDigit && r != '+' && r != '-' && r != '.' {
			return false
		}
	}
	return true
}

// maxBraceExpansions caps a brace-expanded authority. Past it the host set is
// not something to enumerate, so the caller emits nothing.
const maxBraceExpansions = 32

// expandBraceGroups expands comma groups (`{a,b}`) left to right, without
// nesting. A group with no comma (`{x}`) or a sequence (`{1..3}`) is left to
// the shell's and curl's differing rules, so it is refused.
func expandBraceGroups(s string) ([]string, bool) {
	open := strings.IndexByte(s, '{')
	if open < 0 {
		if strings.IndexByte(s, '}') >= 0 {
			return nil, false
		}
		return []string{s}, true
	}
	if strings.IndexByte(s[:open], '}') >= 0 {
		return nil, false
	}
	closeRel := strings.IndexByte(s[open+1:], '}')
	if closeRel < 0 {
		return nil, false
	}
	body := s[open+1 : open+1+closeRel]
	if strings.IndexByte(body, '{') >= 0 || !strings.Contains(body, ",") {
		return nil, false
	}
	tails, ok := expandBraceGroups(s[open+1+closeRel+1:])
	if !ok {
		return nil, false
	}
	var out []string
	for _, alt := range strings.Split(body, ",") {
		for _, t := range tails {
			out = append(out, s[:open]+alt+t)
			if len(out) > maxBraceExpansions {
				return nil, false
			}
		}
	}
	return out, true
}

// --- curl ----------------------------------------------------------------------

// curlSchemes are the curl URL schemes that name a network host. file:// names
// none, and ipfs:// / ipns:// name a content id that curl fetches through a
// gateway, so an operand with those schemes names no destination here.
var curlSchemes = setOf("http", "https", "ftp", "ftps", "sftp", "scp", "ws", "wss",
	"smtp", "smtps", "imap", "imaps", "pop3", "pop3s", "ldap", "ldaps",
	"mqtt", "telnet", "dict", "gopher", "gophers", "tftp", "rtsp", "smb", "smbs")

// proxySchemes are what curl accepts in a proxy string.
var proxySchemes = setOf("http", "https", "socks4", "socks4a", "socks5", "socks5h")

// curlValueLong / curlBoolLong are every long option in `curl --help all`
// (curl 8.7.1), split by whether it takes a value, plus the value-taking
// options added since (ech, ip-tos, vlan-priority, ssl-sessions, upload-flags,
// sigalgs, knownhosts, parallel-max-host) and five booleans (mptcp,
// skip-existing, tls-earlydata, follow, out-null). An option in neither set
// makes the whole argv unreadable — its next word may be its value — so the
// segment names nothing. A missing entry can only cost coverage, never cause
// a block; a boolean wrongly listed as value-taking would only hide the next
// word.
var curlValueLong = setOf("abstract-unix-socket", "alt-svc", "aws-sigv4", "cacert", "capath", "cert",
	"cert-type", "ciphers", "config", "connect-timeout", "connect-to", "continue-at", "cookie",
	"cookie-jar", "create-file-mode", "crlfile", "curves", "data", "data-ascii", "data-binary",
	"data-raw", "data-urlencode", "delegation", "dns-interface", "dns-ipv4-addr", "dns-ipv6-addr",
	"dns-servers", "doh-url", "dump-header", "egd-file", "engine", "etag-compare", "etag-save",
	"expect100-timeout", "form", "form-string", "ftp-account", "ftp-alternative-to-user",
	"ftp-method", "ftp-port", "ftp-ssl-ccc-mode", "happy-eyeballs-timeout-ms", "haproxy-clientip",
	"header", "help", "hostpubmd5", "hostpubsha256", "hsts", "interface", "ipfs-gateway", "json",
	"keepalive-time", "key", "key-type", "krb", "libcurl", "limit-rate", "local-port",
	"login-options", "mail-auth", "mail-from", "mail-rcpt", "max-filesize", "max-redirs",
	"max-time", "netrc-file", "noproxy", "oauth2-bearer", "output", "output-dir", "parallel-max",
	"pass", "pinnedpubkey", "preproxy", "proto", "proto-default", "proto-redir", "proxy",
	"proxy-cacert", "proxy-capath", "proxy-cert", "proxy-cert-type", "proxy-ciphers",
	"proxy-crlfile", "proxy-header", "proxy-key", "proxy-key-type", "proxy-pass",
	"proxy-pinnedpubkey", "proxy-service-name", "proxy-tls13-ciphers", "proxy-tlsauthtype",
	"proxy-tlspassword", "proxy-tlsuser", "proxy-user", "proxy1.0", "pubkey", "quote",
	"random-file", "range", "rate", "referer", "request", "request-target", "resolve", "retry",
	"retry-delay", "retry-max-time", "sasl-authzid", "service-name", "socks4", "socks4a",
	"socks5", "socks5-gssapi-service", "socks5-hostname", "speed-limit", "speed-time", "stderr",
	"telnet-option", "tftp-blksize", "time-cond", "tls-max", "tls13-ciphers", "tlsauthtype",
	"tlspassword", "tlsuser", "trace", "trace-ascii", "trace-config", "unix-socket",
	"upload-file", "url", "url-query", "user", "user-agent", "variable", "write-out",
	// Added after 8.7.1.
	"ech", "ip-tos", "vlan-priority", "ssl-sessions", "upload-flags", "sigalgs", "knownhosts",
	"parallel-max-host")

var curlBoolLong = setOf("anyauth", "append", "basic", "ca-native", "cert-status", "compressed",
	"compressed-ssh", "create-dirs", "crlf", "digest", "disable", "disable-eprt", "disable-epsv",
	"disallow-username-in-url", "doh-cert-status", "doh-insecure", "fail", "fail-early",
	"fail-with-body", "false-start", "form-escape", "ftp-create-dirs", "ftp-pasv", "ftp-pret",
	"ftp-skip-pasv-ip", "ftp-ssl-ccc", "ftp-ssl-control", "get", "globoff", "haproxy-protocol",
	"head", "http0.9", "http1.0", "http1.1", "http2", "http2-prior-knowledge", "http3",
	"http3-only", "ignore-content-length", "include", "insecure", "ipv4", "ipv6",
	"junk-session-cookies", "list-only", "location", "location-trusted", "mail-rcpt-allowfails",
	"manual", "metalink", "negotiate", "netrc", "netrc-optional", "next", "no-alpn", "no-buffer",
	"no-clobber", "no-keepalive", "no-npn", "no-progress-meter", "no-sessionid", "ntlm", "ntlm-wb",
	"parallel", "parallel-immediate", "path-as-is", "post301", "post302", "post303",
	"progress-bar", "proxy-anyauth", "proxy-basic", "proxy-ca-native", "proxy-digest",
	"proxy-http2", "proxy-insecure", "proxy-negotiate", "proxy-ntlm", "proxy-ssl-allow-beast",
	"proxy-ssl-auto-client-cert", "proxy-tlsv1", "proxytunnel", "raw", "remote-header-name",
	"remote-name", "remote-name-all", "remote-time", "remove-on-error", "retry-all-errors",
	"retry-connrefused", "sasl-ir", "show-error", "silent", "socks5-basic", "socks5-gssapi",
	"socks5-gssapi-nec", "ssl", "ssl-allow-beast", "ssl-auto-client-cert", "ssl-no-revoke",
	"ssl-reqd", "ssl-revoke-best-effort", "sslv2", "sslv3", "styled-output",
	"suppress-connect-headers", "tcp-fastopen", "tcp-nodelay", "tftp-no-options", "tlsv1",
	"tlsv1.0", "tlsv1.1", "tlsv1.2", "tlsv1.3", "tr-encoding", "trace-ids", "trace-time",
	"use-ascii", "verbose", "version", "xattr",
	// Added after 8.7.1.
	"mptcp", "skip-existing", "tls-earlydata", "follow", "out-null")

// curlShortLong maps each short option to its long name.
var curlShortLong = map[rune]string{
	'E': "cert", 'K': "config", 'C': "continue-at", 'b': "cookie", 'c': "cookie-jar", 'd': "data",
	'D': "dump-header", 'F': "form", 'P': "ftp-port", 'H': "header", 'h': "help", 'm': "max-time",
	'o': "output", 'x': "proxy", 'U': "proxy-user", 'Q': "quote", 'r': "range", 'e': "referer",
	'X': "request", 'Y': "speed-limit", 'y': "speed-time", 't': "telnet-option", 'z': "time-cond",
	'T': "upload-file", 'u': "user", 'A': "user-agent", 'w': "write-out",
	'a': "append", 'q': "disable", 'f': "fail", 'G': "get", 'g': "globoff", 'I': "head",
	'0': "http1.0", 'i': "include", 'k': "insecure", '4': "ipv4", '6': "ipv6",
	'j': "junk-session-cookies", 'l': "list-only", 'L': "location", 'M': "manual", 'n': "netrc",
	':': "next", 'N': "no-buffer", 'Z': "parallel", '#': "progress-bar", 'p': "proxytunnel",
	'J': "remote-header-name", 'O': "remote-name", 'R': "remote-time", 'S': "show-error",
	's': "silent", '2': "sslv2", '3': "sslv3", '1': "tlsv1", 'B': "use-ascii", 'v': "verbose",
	'V': "version",
}

// curlNoTransfer options make curl print something and exit without a
// transfer, so the command reaches no destination.
var curlNoTransfer = setOf("help", "manual", "version")

// curlOverridesConnection options send the request somewhere other than a
// network host the command names (a local socket), so the URL host is not the
// destination and the segment names nothing.
var curlOverridesConnection = setOf("unix-socket", "abstract-unix-socket")

// curlDefaultPorts are the ports curl uses for a URL without one.
var curlDefaultPorts = map[string]string{"http": "80", "https": "443", "ftp": "21",
	"ftps": "990", "sftp": "22", "scp": "22", "ws": "80", "wss": "443", "smtp": "25",
	"smtps": "465", "imap": "143", "imaps": "993", "pop3": "110", "pop3s": "995",
	"ldap": "389", "ldaps": "636", "mqtt": "1883", "telnet": "23", "dict": "2628",
	"gopher": "70", "gophers": "70", "tftp": "69", "rtsp": "554", "smb": "445", "smbs": "445"}

// curlGuessedSchemes is curl's guess for a URL written without a scheme and
// without --proto-default: a host starting with one of these prefixes gets
// that protocol, anything else HTTP.
var curlGuessedSchemes = []struct{ prefix, scheme string }{
	{"ftp.", "ftp"}, {"dict.", "dict"}, {"ldap.", "ldap"}, {"imap.", "imap"},
	{"smtp.", "smtp"}, {"pop3.", "pop3"},
}

// curlRoute is one --resolve or --connect-to entry. It sends a connection
// for a matching source somewhere else, so its targets are destinations only
// when its source matches a transfer in the same operation (curl's own rule):
// --resolve needs HOST (or `*`) and PORT to match; --connect-to matches any
// host when HOST1 is empty and any port when PORT1 is empty.
type curlRoute struct {
	resolve    bool
	host, port string
	targets    []string
}

func (r curlRoute) matches(host, port string) bool {
	if r.host != "" && r.host != "*" && r.host != host {
		return false
	}
	return r.port == "" || r.port == port
}

// curlOp is one curl operation: the arguments between `--next` separators.
// Routing entries apply only to the transfers of their own operation.
type curlOp struct {
	direct       []string   // destinations on their own: URL hosts, proxies, DoH
	transfers    []endpoint // URL operands and --url
	proxies      []endpoint // a --resolve entry also reroutes a proxy's name
	routes       []curlRoute
	protoDefault string
}

// curlDestinations reads a curl argv. Destinations are the URL operands,
// --url, every proxy the command names (the bytes go there), --doh-url (name
// lookups go there), and the targets of --connect-to and --resolve entries
// that apply to a transfer of the same operation (the connection goes there
// instead of to the URL's host).
func curlDestinations(words []string) []string {
	ops := []*curlOp{{}}
	op := ops[0]
	addTransfer := func(v string) {
		if eps, ok := authorityEndpoints(v, false, curlSchemes); ok {
			for _, e := range eps {
				op.direct = append(op.direct, e.host)
				op.transfers = append(op.transfers, e)
			}
		}
	}
	// handle consumes one option's value; false means the argv is unreadable.
	handle := func(name, value string) bool {
		switch name {
		case "url":
			addTransfer(value)
		case "proxy", "preproxy", "proxy1.0", "socks4", "socks4a", "socks5", "socks5-hostname":
			if value == "" {
				break
			}
			if eps, ok := authorityEndpoints(value, false, proxySchemes); ok {
				for _, e := range eps {
					op.direct = append(op.direct, e.host)
					op.proxies = append(op.proxies, e)
				}
			}
		case "doh-url":
			if hosts, ok := authorityHosts(value, true, setOf("https", "http")); ok {
				op.direct = append(op.direct, hosts...)
			}
		case "connect-to":
			r, ok := curlConnectTo(value)
			if !ok {
				return false
			}
			if len(r.targets) > 0 {
				op.routes = append(op.routes, r)
			}
		case "resolve":
			r, ok := curlResolve(value)
			if !ok {
				return false
			}
			if len(r.targets) > 0 {
				op.routes = append(op.routes, r)
			}
		case "proto-default":
			op.protoDefault = strings.ToLower(value)
		}
		return true
	}
	next := func() {
		op = &curlOp{}
		ops = append(ops, op)
	}

	endOfOptions := false
	for i := 0; i < len(words); i++ {
		w := words[i]
		if !endOfOptions && isDynamicWord(w) {
			return nil
		}
		switch {
		case endOfOptions || w == "-" || !strings.HasPrefix(w, "-"):
			addTransfer(w)
		case w == "--":
			endOfOptions = true
		case strings.HasPrefix(w, "--"):
			name := w[2:]
			switch {
			case curlValueLong[name]:
				if curlNoTransfer[name] || curlOverridesConnection[name] {
					return nil
				}
				if i+1 >= len(words) {
					break
				}
				i++
				if isDynamicWord(words[i]) && (name == "url" || name == "connect-to" || name == "resolve") {
					return nil
				}
				if !handle(name, words[i]) {
					return nil
				}
			case curlBoolLong[name] || strings.HasPrefix(name, "no-") && curlBoolLong[name[3:]]:
				if curlNoTransfer[name] {
					return nil
				}
				if name == "next" {
					next()
				}
			default:
				return nil
			}
		default:
			cluster := []rune(w[1:])
			for j, r := range cluster {
				name, known := curlShortLong[r]
				if !known || curlNoTransfer[name] {
					return nil
				}
				if name == "next" {
					next()
				}
				if !curlValueLong[name] {
					continue
				}
				value := string(cluster[j+1:])
				if value == "" {
					if i+1 >= len(words) {
						break
					}
					i++
					value = words[i]
				}
				if !handle(name, value) {
					return nil
				}
				break
			}
		}
	}

	var dests []string
	for _, op := range ops {
		dests = append(dests, op.direct...)
		for _, r := range op.routes {
			matched, certain := op.routeApplies(r)
			if !certain {
				return nil
			}
			if matched {
				dests = append(dests, r.targets...)
			}
		}
	}
	return dests
}

// routeApplies reports whether a routing entry matches a transfer (or, for
// --resolve, a proxy) of the operation. certain is false when a transfer's
// port cannot be known (a scheme-less URL under an unknown --proto-default),
// in which case the segment names nothing rather than guess.
func (op *curlOp) routeApplies(r curlRoute) (matched, certain bool) {
	for _, t := range op.transfers {
		port, known := op.transferPort(t)
		if !known {
			if r.host == "" || r.host == "*" || r.host == t.host {
				if r.port != "" {
					return false, false
				}
				return true, true
			}
			continue
		}
		if r.matches(t.host, port) {
			return true, true
		}
	}
	if r.resolve {
		for _, p := range op.proxies {
			port := p.port
			if port == "" {
				// curl's default proxy port: 443 for an HTTPS proxy, else 1080.
				port = "1080"
				if p.scheme == "https" {
					port = "443"
				}
			}
			if r.matches(p.host, port) {
				return true, true
			}
		}
	}
	return false, true
}

// transferPort is the port curl connects to for a transfer endpoint.
func (op *curlOp) transferPort(t endpoint) (string, bool) {
	if t.port != "" {
		return t.port, true
	}
	scheme := t.scheme
	if scheme == "" {
		scheme = op.protoDefault
		if scheme == "" {
			scheme = "http"
			for _, g := range curlGuessedSchemes {
				if strings.HasPrefix(t.host, g.prefix) {
					scheme = g.scheme
					break
				}
			}
		}
	}
	port, ok := curlDefaultPorts[scheme]
	return port, ok
}

// splitHostPortFields splits on ':' outside [...] (IPv6 literals).
func splitHostPortFields(s string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case ':':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

// routeSource reads the HOST and PORT of a routing entry. An empty field is
// returned as "" (meaning any, where curl allows it); `*` is kept as is.
func routeSource(host, port string) (string, string, bool) {
	if port != "" && !validPort(":"+port, false) {
		return "", "", false
	}
	if host == "" || host == "*" {
		return host, canonicalPort(port), true
	}
	h, ok := normalizeHost(host)
	if !ok {
		return "", "", false
	}
	return h, canonicalPort(port), true
}

// curlConnectTo reads HOST1:PORT1:HOST2:PORT2. An empty HOST2 keeps the
// original host, so the entry has no target. false when unreadable.
func curlConnectTo(v string) (curlRoute, bool) {
	f := splitHostPortFields(v)
	if len(f) != 4 {
		return curlRoute{}, false
	}
	host, port, ok := routeSource(f[0], f[1])
	if !ok {
		return curlRoute{}, false
	}
	r := curlRoute{host: host, port: port}
	if f[2] != "" {
		h, ok := normalizeHost(f[2])
		if !ok {
			return curlRoute{}, false
		}
		r.targets = []string{h}
	}
	return r, true
}

// curlResolve reads [+]HOST:PORT:ADDR[,ADDR]... . A "-HOST:PORT" removal
// has no target. HOST and PORT are required.
func curlResolve(v string) (curlRoute, bool) {
	if strings.HasPrefix(v, "-") {
		return curlRoute{}, true
	}
	v = strings.TrimPrefix(v, "+")
	f := splitHostPortFields(v)
	if len(f) < 3 || f[0] == "" || f[1] == "" {
		return curlRoute{}, false
	}
	host, port, ok := routeSource(f[0], f[1])
	if !ok {
		return curlRoute{}, false
	}
	r := curlRoute{resolve: true, host: host, port: port}
	// The address list is everything after the second ':'; an IPv6 address
	// in it is bracketed, so rejoin the remaining fields.
	for _, a := range strings.Split(strings.Join(f[2:], ":"), ",") {
		h, ok := normalizeHost(a)
		if !ok {
			return curlRoute{}, false
		}
		r.targets = append(r.targets, h)
	}
	return r, true
}

// --- wget ----------------------------------------------------------------------

var wgetSchemes = setOf("http", "https", "ftp", "ftps")

// wgetValueLong / wgetBoolLong follow GNU Wget 1.21's --help. Long options
// with a required value take it as `--opt=value` or the next word; a boolean
// takes an optional `=value` only. Unknown options (including GNU getopt's
// abbreviations) make the argv unreadable, exactly as for curl.
var wgetValueLong = setOf("execute", "output-file", "append-output", "report-speed", "input-file",
	"base", "config", "rejected-log", "tries", "retry-on-http-error", "output-document",
	"start-pos", "progress", "timeout", "dns-timeout", "connect-timeout", "read-timeout", "wait",
	"waitretry", "quota", "bind-address", "bind-dns-address", "dns-servers", "limit-rate",
	"restrict-file-names", "prefer-family", "user", "password", "use-askpass", "local-encoding",
	"remote-encoding", "directory-prefix", "cut-dirs", "http-user", "http-password",
	"default-page", "header", "compression", "max-redirect", "proxy-user", "proxy-password",
	"referer", "user-agent", "load-cookies", "save-cookies", "post-data", "post-file", "method",
	"body-data", "body-file", "secure-protocol", "certificate", "certificate-type", "private-key",
	"private-key-type", "ca-certificate", "ca-directory", "crl-file", "pinnedpubkey",
	"random-file", "egd-file", "ciphers", "hsts-file", "ftp-user", "ftp-password", "warc-file",
	"warc-header", "warc-max-size", "warc-dedup", "warc-tempdir", "level", "backups", "accept",
	"reject", "accept-regex", "reject-regex", "regex-type", "domains", "exclude-domains",
	"follow-tags", "ignore-tags", "include-directories", "exclude-directories", "input-metalink",
	"metalink-index", "preferred-location")

var wgetBoolLong = setOf("version", "help", "background", "debug", "quiet", "verbose",
	"no-verbose", "force-html", "no-config", "retry-connrefused", "retry-on-host-error",
	"no-clobber", "no-netrc", "continue", "show-progress", "timestamping",
	"no-if-modified-since", "no-use-server-timestamps", "server-response", "spider",
	"random-wait", "no-proxy", "proxy", "no-dns-cache", "ignore-case", "inet4-only",
	"inet6-only", "ask-password", "no-iri", "iri", "unlink", "xattr", "no-directories",
	"force-directories", "no-host-directories", "protocol-directories", "no-cache",
	"adjust-extension", "html-extension", "ignore-length", "save-headers", "no-http-keep-alive",
	"no-cookies", "keep-session-cookies", "content-disposition", "content-on-error",
	"auth-no-challenge", "https-only", "no-check-certificate", "check-certificate", "no-hsts",
	"no-remove-listing", "no-glob", "no-passive-ftp", "preserve-permissions", "retr-symlinks",
	"ftps-implicit", "ftps-resume-ssl", "ftps-clear-data-connection", "ftps-fallback-to-ftp",
	"warc-cdx", "no-warc-compression", "no-warc-digests", "no-warc-keep-log", "recursive",
	"delete-after", "convert-links", "convert-file-only", "backup-converted", "mirror",
	"page-requisites", "strict-comments", "follow-ftp", "span-hosts", "relative",
	"trust-server-names", "no-parent", "metalink-over-http", "keep-badhash")

// wgetShortValue / wgetShortBool are wget's short options. -n takes a value
// (the -nv, -nc, -nd, -nH, -np forms are -n with an attached letter).
var wgetShortValue = map[rune]bool{'e': true, 'o': true, 'a': true, 'i': true, 'B': true,
	't': true, 'O': true, 'T': true, 'w': true, 'Q': true, 'P': true, 'U': true, 'l': true,
	'A': true, 'R': true, 'D': true, 'I': true, 'X': true, 'n': true}

var wgetShortBool = map[rune]bool{'b': true, 'd': true, 'q': true, 'v': true, 'F': true,
	'c': true, 'N': true, 'S': true, '4': true, '6': true, 'x': true, 'E': true, 'r': true,
	'k': true, 'K': true, 'm': true, 'p': true, 'H': true, 'L': true}

// wgetShortNoTransfer print and exit.
var wgetShortNoTransfer = map[rune]bool{'V': true, 'h': true}

// wgetDestinations reads a wget argv. Destinations are the URL operands.
// wgetrc commands (-e), proxies from the environment and URLs read from a
// file (-i) are not visible here.
func wgetDestinations(words []string) []string {
	var dests []string
	endOfOptions := false
	for i := 0; i < len(words); i++ {
		w := words[i]
		if !endOfOptions && isDynamicWord(w) {
			return nil
		}
		switch {
		case endOfOptions || w == "-" || !strings.HasPrefix(w, "-"):
			if hosts, ok := authorityHosts(w, false, wgetSchemes); ok {
				dests = append(dests, hosts...)
			}
		case w == "--":
			endOfOptions = true
		case strings.HasPrefix(w, "--"):
			name, _, hasValue := strings.Cut(w[2:], "=")
			switch {
			case name == "version" || name == "help":
				return nil
			case wgetValueLong[name]:
				if !hasValue {
					i++
				}
			case wgetBoolLong[name] || strings.HasPrefix(name, "no-") && wgetBoolLong[name[3:]]:
			default:
				return nil
			}
		default:
			cluster := []rune(w[1:])
			for j, r := range cluster {
				if wgetShortNoTransfer[r] {
					return nil
				}
				if wgetShortBool[r] {
					continue
				}
				if !wgetShortValue[r] {
					return nil
				}
				if j == len(cluster)-1 {
					i++
				}
				break
			}
		}
	}
	return dests
}

// --- git -----------------------------------------------------------------------

// gitNetworkSubcommands are the subcommands whose repository argument is
// contacted. `remote add` / `remote set-url` only record a URL; submodule,
// archive --remote and the rest are not read.
var gitNetworkSubcommands = setOf("clone", "fetch", "pull", "push", "ls-remote")

// gitSchemes are the URL forms read as a remote. scp-like `user@host:path`
// and ssh:// are not: the host there may be an ~/.ssh/config alias, so the
// text does not name the host the connection reaches.
var gitSchemes = setOf("http", "https", "git")

// gitGlobalValue take the next word as a value (or `=value`); gitGlobalBool
// take none. Anything else before the subcommand makes the argv unreadable.
var gitGlobalValue = setOf("C", "c", "git-dir", "work-tree", "namespace", "super-prefix",
	"config-env", "attr-source")

var gitGlobalBool = setOf("p", "P", "paginate", "no-pager", "bare", "no-replace-objects",
	"no-lazy-fetch", "literal-pathspecs", "glob-pathspecs", "noglob-pathspecs",
	"icase-pathspecs", "no-optional-locks", "no-advice", "exec-path", "html-path", "man-path",
	"info-path", "list-cmds")

// gitSubcommandOptions is each network subcommand's option arity, from
// `git <subcommand> -h` (git 2.50.1). A value option takes `--opt=value` or
// the next word (`-o value`, `-ovalue`); an optional one takes a value only
// attached (`--opt=value`, `-j4`); a boolean takes none. Without arity a
// URL-shaped option value (`ls-remote -o <url> <repo>`) reads as the
// repository. An option in none of the sets — including git's abbreviations
// — makes the argv unreadable, so the segment names nothing.
var gitSubcommandOptions = map[string]gitOptions{
	"clone": {
		valueLong:     setOf("branch", "bundle-uri", "config", "depth", "filter", "jobs", "origin", "ref-format", "reference", "reference-if-able", "revision", "separate-git-dir", "server-option", "shallow-exclude", "shallow-since", "template", "upload-pack"),
		optionalLong:  setOf("recurse-submodules", "recursive"),
		boolLong:      setOf("also-filter-submodules", "bare", "checkout", "dissociate", "hardlinks", "ipv4", "ipv6", "local", "mirror", "no-also-filter-submodules", "no-bare", "no-branch", "no-bundle-uri", "no-checkout", "no-config", "no-depth", "no-dissociate", "no-filter", "no-hardlinks", "no-jobs", "no-local", "no-mirror", "no-origin", "no-progress", "no-quiet", "no-recurse-submodules", "no-recursive", "no-ref-format", "no-reference", "no-reference-if-able", "no-reject-shallow", "no-remote-submodules", "no-revision", "no-separate-git-dir", "no-server-option", "no-shallow-exclude", "no-shallow-since", "no-shallow-submodules", "no-shared", "no-single-branch", "no-sparse", "no-tags", "no-template", "no-upload-pack", "no-verbose", "progress", "quiet", "reject-shallow", "remote-submodules", "shallow-submodules", "shared", "single-branch", "sparse", "tags", "verbose"),
		valueShort:    runeSet('b', 'c', 'j', 'o', 'u'),
		optionalShort: runeSet(),
		boolShort:     runeSet('4', '6', 'l', 'n', 'q', 's', 'v'),
	},
	"fetch": {
		valueLong:     setOf("deepen", "depth", "filter", "jobs", "negotiation-tip", "refmap", "server-option", "shallow-exclude", "shallow-since", "upload-pack"),
		optionalLong:  setOf("recurse-submodules"),
		boolLong:      setOf("all", "append", "atomic", "auto-gc", "auto-maintenance", "dry-run", "force", "ipv4", "ipv6", "keep", "multiple", "negotiate-only", "no-all", "no-append", "no-atomic", "no-auto-gc", "no-auto-maintenance", "no-deepen", "no-depth", "no-dry-run", "no-filter", "no-force", "no-jobs", "no-keep", "no-multiple", "no-negotiate-only", "no-negotiation-tip", "no-porcelain", "no-prefetch", "no-progress", "no-prune", "no-prune-tags", "no-quiet", "no-recurse-submodules", "no-server-option", "no-set-upstream", "no-shallow-exclude", "no-shallow-since", "no-show-forced-updates", "no-stdin", "no-tags", "no-update-head-ok", "no-update-shallow", "no-upload-pack", "no-verbose", "no-write-commit-graph", "no-write-fetch-head", "porcelain", "prefetch", "progress", "prune", "prune-tags", "quiet", "refetch", "set-upstream", "show-forced-updates", "stdin", "tags", "unshallow", "update-head-ok", "update-shallow", "verbose", "write-commit-graph", "write-fetch-head"),
		valueShort:    runeSet('j', 'o'),
		optionalShort: runeSet(),
		boolShort:     runeSet('4', '6', 'P', 'a', 'f', 'k', 'm', 'n', 'p', 'q', 't', 'u', 'v'),
	},
	"pull": {
		valueLong:     setOf("cleanup", "deepen", "depth", "negotiation-tip", "refmap", "server-option", "shallow-exclude", "shallow-since", "strategy", "strategy-option", "upload-pack"),
		optionalLong:  setOf("gpg-sign", "jobs", "log", "rebase", "recurse-submodules", "signoff"),
		boolLong:      setOf("all", "allow-unrelated-histories", "append", "autostash", "commit", "dry-run", "edit", "ff", "ff-only", "force", "ipv4", "ipv6", "keep", "no-all", "no-allow-unrelated-histories", "no-append", "no-autostash", "no-cleanup", "no-commit", "no-deepen", "no-depth", "no-dry-run", "no-edit", "no-ff", "no-force", "no-gpg-sign", "no-ipv4", "no-ipv6", "no-jobs", "no-keep", "no-log", "no-negotiation-tip", "no-progress", "no-prune", "no-quiet", "no-rebase", "no-recurse-submodules", "no-server-option", "no-set-upstream", "no-shallow-exclude", "no-shallow-since", "no-show-forced-updates", "no-signoff", "no-squash", "no-stat", "no-strategy", "no-strategy-option", "no-tags", "no-update-shallow", "no-upload-pack", "no-verbose", "no-verify", "no-verify-signatures", "progress", "prune", "quiet", "set-upstream", "show-forced-updates", "squash", "stat", "tags", "unshallow", "update-shallow", "verbose", "verify", "verify-signatures"),
		valueShort:    runeSet('X', 'o', 's'),
		optionalShort: runeSet('S', 'j', 'r'),
		boolShort:     runeSet('4', '6', 'a', 'f', 'k', 'n', 'p', 'q', 't', 'v'),
	},
	"push": {
		valueLong:     setOf("exec", "push-option", "receive-pack", "recurse-submodules", "repo"),
		optionalLong:  setOf("force-with-lease", "signed"),
		boolLong:      setOf("all", "atomic", "branches", "delete", "dry-run", "follow-tags", "force", "force-if-includes", "ipv4", "ipv6", "mirror", "no-all", "no-atomic", "no-branches", "no-delete", "no-dry-run", "no-exec", "no-follow-tags", "no-force", "no-force-if-includes", "no-force-with-lease", "no-mirror", "no-porcelain", "no-progress", "no-prune", "no-push-option", "no-quiet", "no-receive-pack", "no-recurse-submodules", "no-repo", "no-set-upstream", "no-signed", "no-tags", "no-thin", "no-verbose", "no-verify", "porcelain", "progress", "prune", "quiet", "set-upstream", "tags", "thin", "verbose", "verify"),
		valueShort:    runeSet('o'),
		optionalShort: runeSet(),
		boolShort:     runeSet('4', '6', 'd', 'f', 'n', 'q', 'u', 'v'),
	},
	"ls-remote": {
		valueLong:     setOf("server-option", "sort", "upload-pack"),
		optionalLong:  setOf(),
		boolLong:      setOf("branches", "exit-code", "get-url", "no-branches", "no-exit-code", "no-get-url", "no-quiet", "no-refs", "no-server-option", "no-sort", "no-symref", "no-tags", "no-upload-pack", "quiet", "refs", "symref", "tags"),
		valueShort:    runeSet('o'),
		optionalShort: runeSet(),
		boolShort:     runeSet('b', 'q', 't'),
	},
}

type gitOptions struct {
	valueLong, optionalLong, boolLong    map[string]bool
	valueShort, optionalShort, boolShort map[rune]bool
}

// gitDestinations reads `git [global options] <subcommand> …`. For a network
// subcommand the destination is the repository: the first operand, after
// options are bound to their values — or every operand under `fetch
// --multiple`, or `push --repo` when no operand is given — when it is written
// as an http(s) or git:// URL. A later operand is a directory or a refspec.
// A `-c url.<base>.insteadOf=…` rewrite (global, or `clone -c`) makes <base>
// a destination too, and a `-c …proxy=<url>` makes the proxy one.
func gitDestinations(words []string) []string {
	var configDests []string
	addConfig := func(kv string) bool {
		d, ok := gitConfigDestination(kv)
		if ok && d != "" {
			configDests = append(configDests, d)
		}
		return ok
	}
	i := 0
	for ; i < len(words); i++ {
		w := words[i]
		if isDynamicWord(w) {
			return nil
		}
		if !strings.HasPrefix(w, "-") {
			break
		}
		var name, value string
		hasValue := false
		if strings.HasPrefix(w, "--") {
			name, value, hasValue = strings.Cut(w[2:], "=")
		} else {
			name = w[1:]
		}
		switch {
		case name == "version" || name == "help" || name == "v" || name == "h":
			return nil
		case gitGlobalValue[name]:
			if !hasValue {
				if i+1 >= len(words) {
					return nil
				}
				i++
				value = words[i]
			}
			if name == "config-env" {
				// The value comes from an environment variable this text
				// cannot see; a rewrite or proxy set that way hides the
				// destination.
				key, _, _ := strings.Cut(value, "=")
				if gitRoutingKey(key) {
					return nil
				}
			}
			if name == "c" && !addConfig(value) {
				return nil
			}
		case gitGlobalBool[name]:
		default:
			return nil
		}
	}
	if i >= len(words) || !gitNetworkSubcommands[words[i]] {
		return nil
	}
	sub := words[i]
	opts := gitSubcommandOptions[sub]

	var operands []string
	repoOpt := ""
	multiple := false
	// option applies an option's side effect; false makes the argv unreadable.
	option := func(name, value string) bool {
		switch {
		case sub == "clone" && name == "config":
			return addConfig(value)
		case sub == "push" && name == "repo":
			repoOpt = value
		case sub == "fetch" && name == "multiple":
			multiple = true
		}
		return true
	}
	shortName := map[rune]string{'c': "config", 'm': "multiple"}

	endOfOptions := false
	for j := i + 1; j < len(words); j++ {
		w := words[j]
		if !endOfOptions && isDynamicWord(w) {
			return nil
		}
		switch {
		case endOfOptions || w == "-" || !strings.HasPrefix(w, "-"):
			operands = append(operands, w)
		case w == "--":
			endOfOptions = true
		case strings.HasPrefix(w, "--"):
			name, value, hasValue := strings.Cut(w[2:], "=")
			switch {
			case opts.valueLong[name]:
				if !hasValue {
					if j+1 >= len(words) {
						return nil
					}
					j++
					value = words[j]
				}
			case opts.optionalLong[name]:
			case opts.boolLong[name] && !hasValue:
			default:
				return nil
			}
			if !option(name, value) {
				return nil
			}
		default:
			cluster := []rune(w[1:])
			for k, r := range cluster {
				rest := string(cluster[k+1:])
				if opts.boolShort[r] {
					if !option(shortName[r], "") {
						return nil
					}
					continue
				}
				if opts.optionalShort[r] {
					break
				}
				if !opts.valueShort[r] {
					return nil
				}
				if rest == "" {
					if j+1 >= len(words) {
						return nil
					}
					j++
					rest = words[j]
				}
				if !option(shortName[r], rest) {
					return nil
				}
				break
			}
		}
	}

	repos := operands
	if !multiple && len(repos) > 1 {
		repos = repos[:1]
	}
	if len(repos) == 0 && repoOpt != "" {
		repos = []string{repoOpt}
	}
	dests := configDests
	for _, r := range repos {
		scheme, _, ok := splitScheme(r)
		if !ok || !gitSchemes[scheme] {
			continue
		}
		if hosts, ok := authorityHosts(r, true, gitSchemes); ok {
			dests = append(dests, hosts...)
		}
	}
	return dests
}

// gitConfigDestination reads one `-c key=value`. It returns the destination a
// URL rewrite or proxy setting names, "" for any other key, and false when a
// rewrite or proxy is present but cannot be read (the URL the command reaches
// is then unknown).
func gitConfigDestination(kv string) (string, bool) {
	key, value, _ := strings.Cut(kv, "=")
	lk := strings.ToLower(key)
	switch {
	case gitRewriteKey(lk):
		base := key[len("url.") : len(key)-len(lk[strings.LastIndexByte(lk, '.'):])]
		hosts, ok := authorityHosts(base, true, gitSchemes)
		if !ok || len(hosts) != 1 {
			return "", false
		}
		return hosts[0], true
	case strings.HasSuffix(lk, ".proxy"):
		if value == "" {
			return "", true
		}
		hosts, ok := authorityHosts(value, false, proxySchemes)
		if !ok || len(hosts) != 1 {
			return "", false
		}
		return hosts[0], true
	}
	return "", true
}

func gitRewriteKey(lk string) bool {
	return strings.HasPrefix(lk, "url.") && (strings.HasSuffix(lk, ".insteadof") || strings.HasSuffix(lk, ".pushinsteadof"))
}

// gitRoutingKey reports whether a config key changes where git connects.
func gitRoutingKey(key string) bool {
	lk := strings.ToLower(key)
	return gitRewriteKey(lk) || strings.HasSuffix(lk, ".proxy")
}

func runeSet(rs ...rune) map[rune]bool {
	m := make(map[rune]bool, len(rs))
	for _, r := range rs {
		m[r] = true
	}
	return m
}

func setOf(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}
