package mcp

import (
	"net/url"
	"strings"
)

// altFormSSRFArgNames are the tool-call argument keys that commonly carry an
// outbound HTTP(S)/fetch target: generic fetch-shaped tools use "url",
// MCP resource-access tools (resources/read, read_resource, fetch_resource)
// use "uri", and REST-client/SDK-wrapper tool shapes commonly use one of
// endpoint/target/server/base_url.
var altFormSSRFArgNames = []string{"url", "uri", "endpoint", "target", "server", "base_url"}

// checkToolCallArgsAltFormSSRF scans a tool call's arguments for alternative-
// form IPv4 host encodings (octal/decimal/hex, dotted-per-octet or a single
// integer) that decode to a private, loopback, link-local, or cloud-IMDS
// address. It reuses ipv4FromAltForm / cloudMetadataIPv4 / rfc1918OrLoopbackIPv4Re
// — the same decoder and range tables the resources/list authority scanner
// (resource_uri_authority_network_scanner.go) already uses for the
// server-declared-URI surface — so the agent-supplied tool-call-argument
// surface classifies an identical encoding identically, instead of
// enumerating literal address spellings per surface.
//
// Closes #3675: the YAML rules mcp-agentic-block-ssrf-alt-ip-encoding-url/-uri
// enumerate two hardcoded addresses in their octal/decimal alternations
// (127.0.0.1 as "0177.", and 169.254.169.254/127.0.0.1 as two decimal
// literals) and missed the dotted-octal AWS IMDS spelling
// (0251.0376.0251.0376). Any other unenumerated target — the ECS task-role
// IMDS at 169.254.170.2, ordinary RFC 1918 hosts, or GCP/Azure/Alibaba/Tencent
// IMDS addresses — was equally uncovered by that enumeration. Decoding the
// host generically and classifying the canonical result against the range
// tables closes the whole class at once rather than one literal at a time.
//
// Returns the matching argument name, the raw host string as it appeared in
// the argument, and its canonical dotted-decimal form when a hit is found.
func checkToolCallArgsAltFormSSRF(arguments map[string]interface{}) (argName, rawHost, canonical string, hit bool) {
	for _, name := range altFormSSRFArgNames {
		// argFieldRecovered (not resolveField, not a raw map index): the names
		// above are FIXED keys this file authored, so they need the Unicode
		// separator/confusable recovery of #3691/#3712 WITHOUT the rest of the
		// ladder. Full resolveField also lowercases and strips '_'/'-'/spaces,
		// so an ASCII `URL` or `Base_URL` the caller spelled differently would
		// newly activate this rule where a flat index never fired — the exact
		// ASCII-parity change #3727 removed from its own four sites (#3731).
		//
		// Every candidate is checked, not just the first: two Unicode spellings
		// of one key normalize together, and map-iteration order would
		// otherwise pick an arbitrary winner. This is an AUDIT-side detector,
		// so scanning all of them fails CLOSED (#3727 finding 3).
		for _, raw := range argFieldRecovered(arguments, name) {
			s, isStr := raw.(string)
			if !isStr || s == "" {
				continue
			}
			u, err := url.Parse(strings.TrimSpace(s))
			if err != nil || u == nil {
				continue
			}
			host := strings.ToLower(u.Hostname())
			if host == "" {
				continue
			}
			norm, isAlt := ipv4FromAltForm(host)
			if !isAlt {
				// Standard dotted-decimal hosts are deliberately out of scope here —
				// they are covered by the literal-form YAML rules on this same
				// surface (e.g. mcp-agentic-block-oracle-imds-ssrf-uri) and by the
				// existing shell/MCP protected-path and credential rules; this check
				// exists specifically for the alt-form decoding gap.
				continue
			}
			if _, isIMDS := cloudMetadataIPv4[norm]; isIMDS || rfc1918OrLoopbackIPv4Re.MatchString(norm) {
				return name, host, norm, true
			}
		}
	}
	return "", "", "", false
}
