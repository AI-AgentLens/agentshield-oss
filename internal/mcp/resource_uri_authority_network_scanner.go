package mcp

import (
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Three additional resources/list URI signals (Opus deep-dive 2026-05-27):
//
//  1. SignalResourceListAuthoritySpoofing — the URI authority section is shaped
//     for deceit or unsafe cross-host fetch: userinfo with embedded credentials
//     on HTTP(S) (where the agent might later present these creds to the host),
//     authority-confusion that visually impersonates a trusted host
//     (https://github.com@evil.com/...), or a non-empty/non-localhost authority
//     on a file:// URI (UNC-style remote fetch on Windows, hostname-spoofed
//     file pivots elsewhere).
//
//  2. SignalResourceListInternalNetwork — the URI targets a host that is
//     structurally internal to the agent runtime (RFC 1918, loopback,
//     link-local, IPv6 ULA, 0.0.0.0, IMDS) including alternative-form encodings
//     that defeat naive string checks (octal/decimal/hex IPv4, IPv6 short form,
//     bare 0). A malicious MCP server has no legitimate reason to list a URI
//     targeting the agent runtime's local or internal network — every such URI
//     is asking the agent to perform an SSRF gadget on the server's behalf.
//
//  3. SignalResourceListSchemeEvasion — the URI scheme contains embedded
//     control characters (TAB/NEWLINE/CR/NUL/VT/FF) or percent-encoded scheme
//     characters that, once stripped/decoded by a permissive renderer (WebKit
//     strips control chars during URL parsing; some HTML hosts re-decode
//     percent-encoded scheme bytes), resolve to a dangerous scheme
//     (javascript:, data:, vbscript:, etc.). The existing dangerous-scheme
//     check normalizes only whitespace and case — these payloads slip through.
//
//  4. SignalResourceListMetadataSmuggling — the URI's path / query / fragment
//     embeds a cloud instance-metadata (IMDS) target while the authority looks
//     benign. checkResourceListInternalNetwork only inspects the authority
//     (u.Hostname()), so a URI like
//     `https://proxy.example.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`
//     passes the authority check — the outer host is a public proxy — yet a
//     server that fetches the resource and follows the embedded target performs
//     an SSRF against the metadata endpoint and harvests instance credentials.
//     Scoped to IMDS-only indicators (the 169.254.169.254 literal, the cloud
//     metadata FQDNs, and provider IMDS path markers) so it does NOT fire on the
//     loopback/RFC1918 values that legitimately appear in OAuth redirect_uri
//     query params during local development.
const (
	SignalResourceListAuthoritySpoofing ResourceListSignal = "resource_list_authority_spoofing"
	SignalResourceListInternalNetwork   ResourceListSignal = "resource_list_internal_network"
	SignalResourceListSchemeEvasion     ResourceListSignal = "resource_list_scheme_evasion"
	SignalResourceListMetadataSmuggling ResourceListSignal = "resource_list_metadata_smuggling"
)

// schemesWithLegitimateUserinfo lists URI schemes where userinfo (user@host or
// user:pass@host) is normal protocol syntax rather than an injection signal.
// SSH-family schemes always carry a username; git+ssh and ssh+git are common
// rewrites used in agent-fetched repository URIs.
var schemesWithLegitimateUserinfo = map[string]struct{}{
	"ssh":     {},
	"git":     {},
	"git+ssh": {},
	"ssh+git": {},
	"sftp":    {},
	"scp":     {},
	"rsync":   {},
	"ftp":     {},
	"ftps":    {},
	"telnet":  {},
}

// localhostAuthorityForms is the set of authority strings RFC 8089 permits on a
// file:// URI. Anything outside this set on a file:// URI is either a UNC-style
// remote fetch hint (Windows file:////host/share → \\host\share) or a hostname
// spoof. Empty authority ("file:///path") is canonical local; "localhost" is
// the explicit-local form the spec allows.
var localhostAuthorityForms = map[string]struct{}{
	"":          {}, // file:///path — canonical
	"localhost": {},
}

// checkResourceListAuthoritySpoofing inspects the URI authority for the three
// authority-shape attack patterns. Returns nil when the URI parses cleanly and
// none of the three patterns match.
func checkResourceListAuthoritySpoofing(uri string) *ResourceListFinding {
	if uri == "" {
		return nil
	}
	scheme := schemeOf(uri)
	if scheme == "" {
		return nil
	}
	// Skip dangerous schemes — those are covered by SignalResourceListDangerousScheme
	// and re-flagging adds no evidence.
	if _, dangerous := dangerousURISchemes[scheme]; dangerous {
		return nil
	}

	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil || u == nil {
		return nil
	}

	// file:// URIs: authority MUST be empty or "localhost" per RFC 8089. Anything
	// else is an attempt to coerce the host into a remote fetch (UNC on Windows,
	// hostname-spoofed file pivot on Unix when symlinks or chroot are present).
	if scheme == "file" {
		host := strings.ToLower(u.Host)
		if _, ok := localhostAuthorityForms[host]; !ok {
			return &ResourceListFinding{
				Signal: SignalResourceListAuthoritySpoofing,
				Detail: "file:// URI declares a non-local authority — RFC 8089 requires empty or 'localhost' authority; non-local authority on Windows hosts is resolved as UNC (\\\\host\\share) and on permissive hosts may force a hostname-spoofed file pivot",
				URI:    uri,
			}
		}
		// Backslash UNC slipped past the URL parser as a path component:
		// file:////host/share or file:///\\host\share.
		if strings.HasPrefix(u.Path, `//`) || strings.HasPrefix(u.Path, `/\\`) || strings.HasPrefix(u.Path, `\\`) {
			return &ResourceListFinding{
				Signal: SignalResourceListAuthoritySpoofing,
				Detail: "file:// URI path begins with a UNC-style separator (`//` or `\\\\`) — Windows resolves this as `\\\\host\\share`, causing the agent runtime to mount or fetch a remote SMB share",
				URI:    uri,
			}
		}
		return nil
	}

	if u.User != nil {
		// SSH-family schemes legitimately carry a username — exempt them.
		if _, ok := schemesWithLegitimateUserinfo[scheme]; ok {
			return nil
		}
		// Userinfo present on a non-SSH-family scheme. Differentiate:
		//   - userinfo contains a colon → embedded password (always flag)
		//   - bare username on http(s) → authority-confusion pattern
		//     (e.g. https://github.com@attacker.com — agent skim-reads the URL
		//     and trusts "github.com" while the request goes to attacker.com)
		username := u.User.Username()
		_, hasPassword := u.User.Password()
		if hasPassword {
			return &ResourceListFinding{
				Signal: SignalResourceListAuthoritySpoofing,
				Detail: "URI embeds credentials in the userinfo component (user:password@host) — secrets in the URI travel to network logs, browser history, referer headers, and the receiving server's access logs",
				URI:    uri,
			}
		}
		// Authority-confusion: a bare userinfo that looks like a trusted hostname
		// is the highest-confidence form of this attack. Even a generic bare
		// userinfo on http(s) is suspicious for an MCP-listed resource — agents
		// fetching listed URIs have no reason to present a username to a public
		// HTTP host.
		looksLikeHostname := strings.ContainsRune(username, '.') ||
			strings.EqualFold(username, "localhost")
		detail := "URI userinfo on http(s) scheme — MCP-listed resources should not require username-based authentication; pattern is a known authority-confusion vector (a bare userinfo that looks like a hostname makes the URL appear to point at the userinfo rather than at the actual host)"
		if looksLikeHostname {
			detail = "URI userinfo on http(s) is a hostname-shaped string (e.g. https://" + username + "@" + u.Host + ") — classic authority-confusion: skim-readers and the LLM consent surface see '" + username + "' as the destination while the actual fetch targets '" + u.Host + "'"
		}
		return &ResourceListFinding{
			Signal: SignalResourceListAuthoritySpoofing,
			Detail: detail,
			URI:    uri,
		}
	}
	return nil
}

// rfc1918OrLoopbackIPv4Re matches RFC 1918 / loopback / link-local / 0.0.0.0
// IPv4 ranges in decimal-dotted form. The regex is purposefully strict so it
// doesn't fire on octets that happen to start with a private prefix
// (e.g. 100.0.0.1 is NOT 10.x.x.x — the boundary `\b` enforces octet integrity).
var rfc1918OrLoopbackIPv4Re = regexp.MustCompile(
	`^(` +
		`10\.\d{1,3}\.\d{1,3}\.\d{1,3}` + `|` +
		`127\.\d{1,3}\.\d{1,3}\.\d{1,3}` + `|` +
		`169\.254\.\d{1,3}\.\d{1,3}` + `|` +
		`172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}` + `|` +
		`192\.168\.\d{1,3}\.\d{1,3}` + `|` +
		`0\.0\.0\.0` + `|` +
		`0` +
		`)$`,
)

// internalHostnames is the set of literal hostnames that resolve to the agent's
// own runtime or to cloud-internal metadata endpoints. Lowercase, dot-trimmed.
var internalHostnames = map[string]struct{}{
	"localhost":                {},
	"localhost.localdomain":    {},
	"metadata.google.internal": {},
	"metadata.goog":            {},
	"metadata.azure.com":       {},
	"instance-data":            {},
	"metadata-service":         {},
}

// cloudMetadataIPv4 is the set of cloud instance-metadata (IMDS) IPv4 literals
// that live OUTSIDE the RFC 1918 / loopback / link-local ranges that
// rfc1918OrLoopbackIPv4Re already covers. The AWS/GCP/Azure/OpenStack IMDS at
// 169.254.169.254 is link-local and already matched by that regex; these two
// are not:
//
//   100.100.100.200 — Alibaba Cloud ECS metadata service. It sits in the RFC
//                     6598 Carrier-Grade-NAT block (100.64.0.0/10), NOT RFC 1918,
//                     so a string/regex denylist built for AWS misses it entirely.
//   192.0.0.192     — Oracle Cloud Infrastructure legacy IMDS. It sits in the
//                     IANA IETF-Protocol-Assignments block (192.0.0.0/24, RFC
//                     6890) — not private, not loopback, not link-local — so it
//                     too slips past RFC1918/IMDS-literal checks tuned to AWS.
//
// These addresses have ZERO legitimate reason to appear as the authority of an
// MCP resource URI: a server advertising resources/read on one of them is
// staging an SSRF that harvests cloud credentials on the agent's behalf. The
// set is reused by both the literal-authority check and the alternative-form
// (decimal/octal/hex) IP check so encoding evasion is covered automatically.
var cloudMetadataIPv4 = map[string]struct{}{
	"169.254.169.254": {}, // AWS / GCP / Azure / OpenStack / DigitalOcean IMDS (link-local)
	"100.100.100.200": {}, // Alibaba Cloud ECS metadata (RFC 6598 CGNAT — bypasses RFC1918 denylists)
	"192.0.0.192":     {}, // Oracle Cloud legacy IMDS (192.0.0.0/24 IETF-assignments — bypasses RFC1918 denylists)
}

// checkResourceListInternalNetwork inspects the URI host for internal-network
// targeting, including alternative-form IPv4 encodings (decimal-int, octal,
// hex) and IPv6 loopback/link-local/ULA ranges. Returns nil when the URI does
// not parse, has no host, or points at a public address.
func checkResourceListInternalNetwork(uri string) *ResourceListFinding {
	if uri == "" {
		return nil
	}
	scheme := schemeOf(uri)
	if scheme == "" {
		return nil
	}
	// Only network-fetch schemes are relevant. file:// is handled by other rules;
	// mailto:/tel:/etc. don't carry a network host.
	if !isNetworkFetchScheme(scheme) {
		return nil
	}

	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil || u == nil {
		return nil
	}
	rawHost := u.Hostname() // strips port and brackets for IPv6
	if rawHost == "" {
		return nil
	}
	host := strings.ToLower(rawHost)

	if _, ok := internalHostnames[host]; ok {
		return &ResourceListFinding{
			Signal: SignalResourceListInternalNetwork,
			Detail: "URI targets internal-network hostname '" + host + "' — MCP servers have no legitimate reason to list a resource targeting the agent runtime's loopback or cloud-internal metadata services; fetching this URI causes an SSRF on the agent's behalf",
			URI:    uri,
		}
	}

	// Cloud IMDS literals that fall outside the RFC1918/loopback/link-local
	// regex (Alibaba 100.100.100.200, Oracle 192.0.0.192). 169.254.169.254 is
	// also in the set but already matched by rfc1918OrLoopbackIPv4Re above.
	if _, ok := cloudMetadataIPv4[host]; ok {
		return &ResourceListFinding{
			Signal: SignalResourceListInternalNetwork,
			Detail: "URI targets a cloud instance-metadata (IMDS) endpoint (" + host + ") — e.g. Alibaba 100.100.100.200 (RFC 6598 CGNAT) or Oracle 192.0.0.192 (192.0.0.0/24); these live outside RFC 1918 so naive denylists miss them. No MCP resource legitimately points at an IMDS endpoint; fetching it harvests cloud credentials via SSRF",
			URI:    uri,
		}
	}

	// IPv4 dotted-decimal in the standard private/loopback/link-local ranges.
	if rfc1918OrLoopbackIPv4Re.MatchString(host) {
		return &ResourceListFinding{
			Signal: SignalResourceListInternalNetwork,
			Detail: "URI targets a private/loopback/link-local IPv4 address (" + host + ") — MCP servers should not list resources pointing at the agent runtime's internal network; fetching it is an SSRF gadget",
			URI:    uri,
		}
	}

	// IPv6 loopback (::1) and link-local (fe80::/10) and unique-local (fc00::/7).
	if isInternalIPv6(host) {
		return &ResourceListFinding{
			Signal: SignalResourceListInternalNetwork,
			Detail: "URI targets an internal IPv6 address (" + host + ") — loopback (::1), link-local (fe80::/10), or unique-local (fc00::/7) addresses are agent-runtime-internal; no legitimate MCP resource lives there",
			URI:    uri,
		}
	}

	// Alternative-form IPv4 encodings that resolve to a private/loopback/link-local
	// or IMDS address.
	if normalized, ok := ipv4FromAltForm(host); ok {
		if _, isIMDS := cloudMetadataIPv4[normalized]; isIMDS || rfc1918OrLoopbackIPv4Re.MatchString(normalized) {
			return &ResourceListFinding{
				Signal: SignalResourceListInternalNetwork,
				Detail: "URI host '" + host + "' is an alternative-form IPv4 encoding (octal/decimal/hex/short-form) that resolves to " + normalized + " — a known IMDS (AWS/Alibaba/Oracle) or internal-network address; this is a classic bypass for naive string-based allowlists",
				URI:    uri,
			}
		}
	}

	// Internal IPv4 smuggled into the DNS labels of a public-looking hostname —
	// the wildcard-DNS rebinding signature (nip.io/sslip.io/xip.io/traefik.me).
	// The authority parses as a hostname, not a bare IP, so every check above
	// (which expects an IP literal) misses it.
	if normalized, ok := embeddedInternalIPv4InHost(host); ok {
		return &ResourceListFinding{
			Signal: SignalResourceListInternalNetwork,
			Detail: "URI authority '" + host + "' embeds an internal IPv4 (" + normalized + ") as DNS labels — the signature of a wildcard-DNS rebinding service (nip.io / sslip.io / xip.io / traefik.me and similar) that resolves a public-looking hostname to a private, loopback, link-local, or cloud-IMDS address. This defeats bare-IP authority checks and is an SSRF gadget; legitimate hostnames embed only public IPs (reverse-DNS / EC2-style naming)",
			URI:    uri,
		}
	}
	return nil
}

// dashedQuadRe matches a single DNS label that encodes a dotted-quad IPv4 with
// '-' separators (e.g. "169-254-169-254"), the form wildcard-DNS rebinding
// services accept alongside the dotted form.
var dashedQuadRe = regexp.MustCompile(`^\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}$`)

// embeddedInternalIPv4InHost detects a private/loopback/link-local/IMDS IPv4
// address smuggled into a DNS hostname's labels — the structural signature of a
// wildcard-DNS rebinding service used to pass an internal target through an
// authority check that only recognises bare IP literals. Both forms these
// services accept are covered:
//
//	dotted:  169.254.169.254.nip.io   -> 4 consecutive numeric labels
//	dashed:  169-254-169-254.nip.io   -> one label, octets joined by '-'
//
// Detection is RANGE-gated, not service-gated: it fires on any hostname (a known
// rebinder or not) embedding an IPv4 in an internal range, and stays silent on
// embedded PUBLIC IPs — which is what legitimate reverse-DNS / EC2-style
// hostnames carry (e.g. ec2-54-12-34-56.compute-1.amazonaws.com). Returns the
// canonical dotted-quad and true on a hit.
func embeddedInternalIPv4InHost(host string) (string, bool) {
	if host == "" {
		return "", false
	}
	labels := strings.Split(host, ".")

	// Dashed single-label form: NNN-NNN-NNN-NNN anywhere in the name.
	for _, label := range labels {
		if dashedQuadRe.MatchString(label) {
			if norm, ok := internalDottedQuad(strings.ReplaceAll(label, "-", ".")); ok {
				return norm, true
			}
		}
	}

	// Dotted form: 4 consecutive all-numeric labels forming a valid IPv4.
	for i := 0; i+3 < len(labels); i++ {
		if isNumericLabel(labels[i]) && isNumericLabel(labels[i+1]) &&
			isNumericLabel(labels[i+2]) && isNumericLabel(labels[i+3]) {
			cand := labels[i] + "." + labels[i+1] + "." + labels[i+2] + "." + labels[i+3]
			if norm, ok := internalDottedQuad(cand); ok {
				return norm, true
			}
		}
	}
	return "", false
}

// isNumericLabel reports whether s is a 1–3 digit all-numeric DNS label (an IPv4
// octet candidate).
func isNumericLabel(s string) bool {
	if s == "" || len(s) > 3 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// internalDottedQuad validates cand as a dotted-quad IPv4 (net.ParseIP rejects
// octets > 255) and reports whether it falls in a private/loopback/link-local
// range or is a cloud-IMDS literal — reusing the exact range definitions the
// bare-IP checks use. Returns the canonical form on a hit.
func internalDottedQuad(cand string) (string, bool) {
	ip := net.ParseIP(cand)
	if ip == nil || ip.To4() == nil {
		return "", false
	}
	norm := ip.String()
	if _, ok := cloudMetadataIPv4[norm]; ok {
		return norm, true
	}
	if rfc1918OrLoopbackIPv4Re.MatchString(norm) {
		return norm, true
	}
	return "", false
}

// metadataSmugglingIndicators are substrings that have no legitimate place in
// the path, query, or fragment of an MCP resource URI: each is a cloud
// instance-metadata (IMDS) target. The set is deliberately IMDS-only — the
// link-local IMDS IPv4 literal, the three cloud-provider metadata FQDNs, and the
// AWS/GCP IMDS path markers. Loopback (127.0.0.1 / localhost) and RFC1918
// addresses are intentionally NOT here: those legitimately appear inside query
// params (OAuth `redirect_uri=http://localhost:3000/callback`, local webhook
// callbacks) so matching them in a query would be false-positive-prone. An IMDS
// endpoint, by contrast, has zero benign reason to appear anywhere in a resource
// URI. All entries are lowercase for case-insensitive matching.
var metadataSmugglingIndicators = []string{
	"169.254.169.254",          // AWS/GCP/Azure/OpenStack IMDS link-local IPv4
	"100.100.100.200",          // Alibaba Cloud ECS metadata IPv4 (RFC 6598 CGNAT)
	"192.0.0.192",              // Oracle Cloud legacy IMDS IPv4 (192.0.0.0/24)
	"metadata.google.internal", // GCP metadata server FQDN
	"metadata.goog",            // GCP metadata server FQDN (short form)
	"metadata.azure.com",       // Azure Instance Metadata Service FQDN
	"/latest/meta-data",        // AWS / Alibaba IMDS data path (v1 + v2)
	"/computemetadata/",        // GCP IMDS path prefix
}

// checkResourceListMetadataSmuggling detects a cloud instance-metadata (IMDS)
// target embedded in the path, query, or fragment of an otherwise-benign-looking
// resource URI — the SSRF-by-proxy gadget that checkResourceListInternalNetwork
// (authority-only) cannot see. Returns nil unless an IMDS indicator appears
// outside the authority.
//
// The authority itself is deliberately excluded from the scan: if the IMDS
// target IS the authority, checkResourceListInternalNetwork already flags it, so
// scanning only path/query/fragment isolates the smuggling case and avoids
// double-flagging the same row.
func checkResourceListMetadataSmuggling(uri string) *ResourceListFinding {
	if uri == "" {
		return nil
	}
	scheme := schemeOf(uri)
	if scheme == "" || !isNetworkFetchScheme(scheme) {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil || u == nil {
		return nil
	}

	// Build the post-authority surface: path + query + fragment only.
	var sb strings.Builder
	sb.WriteString(u.EscapedPath())
	if u.RawQuery != "" {
		sb.WriteByte('?')
		sb.WriteString(u.RawQuery)
	}
	if u.Fragment != "" {
		sb.WriteByte('#')
		sb.WriteString(u.Fragment)
	}
	target := sb.String()
	if target == "" {
		return nil
	}

	// Percent-decode up to two passes to defeat single and double URL-encoding
	// of the embedded target (e.g. url=http%3A%2F%2F169.254.169.254%2Flatest...).
	// Match against both the raw and decoded forms: the IMDS IP and FQDNs are
	// not percent-encoded (digits/letters/dots), so the raw form catches them
	// even when QueryUnescape rejects a malformed escape elsewhere in the URI.
	decoded := target
	for i := 0; i < 2; i++ {
		d, derr := url.QueryUnescape(decoded)
		if derr != nil || d == decoded {
			break
		}
		decoded = d
	}
	hay := strings.ToLower(target + "\x00" + decoded)

	for _, ind := range metadataSmugglingIndicators {
		if strings.Contains(hay, ind) {
			return &ResourceListFinding{
				Signal: SignalResourceListMetadataSmuggling,
				Detail: "URI path/query/fragment embeds a cloud instance-metadata (IMDS) target ('" + ind +
					"') while the authority is benign — an SSRF-by-proxy gadget: a server that fetches this resource and follows the embedded target reaches the metadata endpoint and can exfiltrate instance credentials/IAM tokens. No legitimate MCP resource embeds an IMDS endpoint in its query or path.",
				URI: uri,
			}
		}
	}
	return nil
}

// isNetworkFetchScheme returns true for schemes whose resources are retrieved
// by the agent runtime via a network request — http(s), ws(s), and a handful
// of common database/remote schemes that some MCP servers expose.
func isNetworkFetchScheme(scheme string) bool {
	switch scheme {
	case "http", "https", "ws", "wss",
		"redis", "mongodb", "postgres", "postgresql", "mysql",
		"ssh", "sftp", "ftp", "ftps", "git", "git+ssh", "ssh+git":
		return true
	}
	return false
}

// ipv6LinkLocal is the fe80::/10 prefix as a *net.IPNet.
var ipv6LinkLocal = mustCIDR("fe80::/10")

// ipv6UniqueLocal is the fc00::/7 prefix as a *net.IPNet.
var ipv6UniqueLocal = mustCIDR("fc00::/7")

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err) // compile-time constant — failure is a programmer error
	}
	return n
}

// isInternalIPv6 returns true when host (already lowercased, no brackets) is an
// IPv6 address in the loopback / link-local / unique-local ranges. Uses
// net.ParseIP for correctness across short-form, embedded-IPv4, and
// long-form notations.
func isInternalIPv6(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() != nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	if ipv6LinkLocal.Contains(ip) || ipv6UniqueLocal.Contains(ip) {
		return true
	}
	return false
}

// ipv4FromAltForm decodes alternative-form IPv4 encodings to canonical
// dotted-decimal. Returns ("", false) when host is not an alt-form (e.g. it's a
// hostname, an IPv6, or a normal dotted-decimal IPv4). Supports:
//
//   - Single 32-bit integer: "2852039166" → "169.254.169.254"
//   - Single hex 32-bit:     "0xa9fea9fe" → "169.254.169.254"
//   - Dotted with octal/hex octets: "0251.0376.0251.0376" → "169.254.169.254"
//   - Dotted hex octets:    "0xa9.0xfe.0xa9.0xfe" → "169.254.169.254"
//
// We deliberately do not normalize standard dotted-decimal forms; those flow
// through rfc1918OrLoopbackIPv4Re directly.
func ipv4FromAltForm(host string) (string, bool) {
	if host == "" {
		return "", false
	}
	parts := strings.Split(host, ".")
	switch len(parts) {
	case 1:
		// Single integer form. Try base 0 (Go semantics: 0x → hex, 0 → octal, else decimal).
		// "0" alone is already covered by rfc1918OrLoopbackIPv4Re's "^0$" branch and would
		// not have reached here, but stay defensive.
		n, err := strconv.ParseUint(parts[0], 0, 32)
		if err != nil {
			return "", false
		}
		return formatIPv4(uint32(n)), true
	case 4:
		// All four octets must parse as base 0 (decimal/octal/hex) and fit in 8 bits.
		// We require at least one non-pure-decimal octet to call this "alt-form" — if
		// every octet is a plain decimal in 0–255, that's a standard dotted-decimal IPv4
		// already covered by rfc1918OrLoopbackIPv4Re.
		isAlt := false
		var bytes [4]uint64
		for i, p := range parts {
			if p == "" {
				return "", false
			}
			n, err := strconv.ParseUint(p, 0, 16)
			if err != nil || n > 255 {
				return "", false
			}
			bytes[i] = n
			if isNonDecimalOctet(p) {
				isAlt = true
			}
		}
		if !isAlt {
			return "", false
		}
		return formatIPv4Bytes(bytes), true
	}
	return "", false
}

// isNonDecimalOctet reports whether p uses a non-decimal base (octal/hex). A
// leading "0" with another digit indicates octal; a leading "0x"/"0X" indicates
// hex. A bare "0" is decimal-zero, not octal.
func isNonDecimalOctet(p string) bool {
	if len(p) >= 2 && (p[:2] == "0x" || p[:2] == "0X") {
		return true
	}
	if len(p) >= 2 && p[0] == '0' {
		return true // leading-zero octet is octal
	}
	return false
}

func formatIPv4(n uint32) string {
	return strconv.FormatUint(uint64((n>>24)&0xff), 10) + "." +
		strconv.FormatUint(uint64((n>>16)&0xff), 10) + "." +
		strconv.FormatUint(uint64((n>>8)&0xff), 10) + "." +
		strconv.FormatUint(uint64(n&0xff), 10)
}

func formatIPv4Bytes(b [4]uint64) string {
	return strconv.FormatUint(b[0], 10) + "." +
		strconv.FormatUint(b[1], 10) + "." +
		strconv.FormatUint(b[2], 10) + "." +
		strconv.FormatUint(b[3], 10)
}

// schemeEvasionControlChars is the set of control characters known to be
// stripped by permissive URL parsers (WebKit, some Electron renderers, certain
// HTML preview tools) during scheme parsing. Their presence inside the
// scheme-portion of a URI is unambiguously adversarial.
const schemeEvasionControlChars = "\t\n\r\x00\v\f"

// checkResourceListSchemeEvasion looks for embedded control characters or
// percent-encoded scheme characters inside the pre-colon portion of a URI.
// When stripped/decoded, the resulting scheme is checked against the same
// dangerousURISchemes map the existing dangerous-scheme rule uses. Fires when
// the cleaned scheme is dangerous but the raw scheme was rejected (by the
// strict RFC 3986 char check inside schemeOf) — i.e., the existing rule MISSED
// this URI.
func checkResourceListSchemeEvasion(uri string) *ResourceListFinding {
	if uri == "" {
		return nil
	}
	trimmed := strings.TrimSpace(uri)
	idx := strings.IndexByte(trimmed, ':')
	if idx <= 0 {
		return nil
	}
	rawScheme := trimmed[:idx]
	// If schemeOf already accepts this URI cleanly, then either the existing
	// dangerous-scheme rule will fire (no need for this rule) or the scheme is
	// genuinely benign. Either way, this rule has nothing to add.
	if s := schemeOf(uri); s != "" {
		return nil
	}
	// Clean: strip control chars + percent-decode + lowercase.
	cleaned := strings.Map(func(r rune) rune {
		if strings.ContainsRune(schemeEvasionControlChars, r) {
			return -1
		}
		return r
	}, rawScheme)
	// Percent-decode using net/url with a synthetic key=value pair so we get
	// permissive behaviour identical to a browser address-bar decoder.
	if decoded, err := url.QueryUnescape(cleaned); err == nil {
		cleaned = decoded
	}
	cleaned = strings.ToLower(strings.TrimSpace(cleaned))
	if cleaned == "" {
		return nil
	}
	if _, dangerous := dangerousURISchemes[cleaned]; !dangerous {
		return nil
	}
	return &ResourceListFinding{
		Signal: SignalResourceListSchemeEvasion,
		Detail: "URI scheme contains embedded control characters or percent-encoded scheme bytes that resolve to dangerous scheme '" + cleaned + ":' once stripped/decoded by a permissive renderer (WebKit and some Electron hosts strip TAB/CR/NUL during URL parsing; HTML-preview tools may re-decode percent-encoded scheme bytes); a render-host that performs either normalization will execute or fetch the cleaned scheme while the raw URI evades string-based scheme allowlists",
		URI:    uri,
	}
}
