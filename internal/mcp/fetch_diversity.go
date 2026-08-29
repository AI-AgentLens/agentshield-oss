package mcp

import (
	"net/url"
	"strings"
	"time"
)

// FetchDiversitySignal identifies a detected public-metadata side-channel
// exfiltration pattern (CVE-2026-54316 / GHSA-fg94-h982-f3mm): a session
// fetching many distinct resources under one namespace/organization on a
// single host, where the resource names follow an enumerable template
// (`char-a`, `char-b`, ... or bare single characters). See taxonomy:
// data-exfiltration/network-egress/public-metadata-side-channel-exfiltration.
type FetchDiversitySignal string

const (
	// SignalFetchDiversityBurst fires when a session fetches
	// fetchDiversityBurstThreshold or more distinct resources under the same
	// (host, namespace) within fetchDiversityWindow, regardless of naming.
	// AUDIT — a security audit or multi-repo comparison task can legitimately
	// touch many resources under one org; this is a review signal, not proof.
	SignalFetchDiversityBurst FetchDiversitySignal = "fetch_diversity_burst"

	// SignalFetchEnumerablePattern fires when a session fetches
	// fetchDiversityEnumerableThreshold or more distinct resources under the
	// same (host, namespace), where the resource names share a common
	// template (a common prefix followed by a 1-3 character suffix) — the
	// "one resource per secret character" shape the CVE's PoC used. BLOCK —
	// no legitimate development workflow names resources this way.
	SignalFetchEnumerablePattern FetchDiversitySignal = "fetch_enumerable_pattern"
)

// Synthetic virtual tool names injected into the policy engine when the above
// signals fire — mirroring the approval-fatigue / lethal-trifecta approach.
const (
	syntheticFetchDiversityBurst    = "__mcp_fetch_diversity_burst__"
	syntheticFetchEnumerablePattern = "__mcp_fetch_enumerable_pattern__"
)

const (
	// fetchDiversityWindow bounds how far back a fetch counts toward the
	// current session's diversity tally — the taxonomy describes this as a
	// "short session window", not a rapid burst, since the attacker's polling
	// of public counters happens out of band and the agent's own fetches can
	// be paced by ordinary tool-call latency.
	fetchDiversityWindow = 5 * time.Minute

	// fetchDiversityBurstThreshold is the distinct-resource count (under one
	// host+namespace) that trips the naming-agnostic AUDIT signal.
	fetchDiversityBurstThreshold = 8

	// fetchDiversityEnumerableThreshold is the distinct-resource count
	// required before the (stronger, lower-count) enumerable-naming BLOCK
	// signal is even considered.
	fetchDiversityEnumerableThreshold = 5

	// fetchDiversityHistoryMax bounds per-session memory.
	fetchDiversityHistoryMax = 200
)

// fetchRecord is one fetch-shaped tool call captured for diversity tracking.
type fetchRecord struct {
	at        time.Time
	host      string
	namespace string
	resource  string
}

// FetchDiversityTracker tracks, per session, the distinct resources fetched
// under each (host, namespace) pair so the public-metadata side-channel
// exfiltration pattern can be detected: many enumerable-named resources
// fetched under one namespace on a single (necessarily allowlisted, or the
// fetch would not have been permitted at all) host. No single fetch in this
// attack is abnormal — an allowlisted domain, an ordinary-looking path — the
// signal is the cardinality and naming shape of the *set* of resources
// touched in one session, which only session-level tracking can see.
//
// Add it to MessageHandler; a nil tracker silently disables detection.
type FetchDiversityTracker struct {
	history boundedHistory[fetchRecord]
}

// NewFetchDiversityTracker returns a ready tracker.
func NewFetchDiversityTracker() *FetchDiversityTracker {
	return &FetchDiversityTracker{history: newBoundedHistory[fetchRecord](fetchDiversityHistoryMax)}
}

// Scan checks whether the incoming fetch-shaped tool call completes a
// diversity or enumerable-pattern signal, given prior session history within
// the window. Call this BEFORE Record so the current call is counted exactly
// once. Returns "" for non-fetch tools or calls with no extractable
// namespaced resource (nothing to track).
func (t *FetchDiversityTracker) Scan(toolName string, args map[string]interface{}) FetchDiversitySignal {
	if t == nil || !isFetchTool(toolName) {
		return ""
	}
	host, namespace, resource, ok := extractFetchResource(args)
	if !ok {
		return ""
	}

	var signal FetchDiversitySignal
	t.history.view(func(history []fetchRecord) {
		cutoff := time.Now().Add(-fetchDiversityWindow)
		seen := map[string]bool{resource: true}
		resources := []string{resource}
		for _, r := range history {
			if r.at.Before(cutoff) || r.host != host || r.namespace != namespace {
				continue
			}
			if !seen[r.resource] {
				seen[r.resource] = true
				resources = append(resources, r.resource)
			}
		}
		switch {
		case len(resources) >= fetchDiversityEnumerableThreshold && looksEnumerable(resources):
			signal = SignalFetchEnumerablePattern
		case len(resources) >= fetchDiversityBurstThreshold:
			signal = SignalFetchDiversityBurst
		}
	})
	return signal
}

// Record adds a fetch-shaped tool call to session history. No-ops for
// non-fetch tools or calls with no extractable namespaced resource.
func (t *FetchDiversityTracker) Record(toolName string, args map[string]interface{}) {
	if t == nil || !isFetchTool(toolName) {
		return
	}
	host, namespace, resource, ok := extractFetchResource(args)
	if !ok {
		return
	}
	t.history.append(fetchRecord{at: time.Now(), host: host, namespace: namespace, resource: resource})
}

// fetchToolNames are tool names shaped like a read-only remote resource
// fetch — the surface this attack requires (WebFetch and its MCP-server
// equivalents). Compared case-insensitively with separators collapsed
// (matchToolName's normalization), so "WebFetch", "web_fetch", and
// "web-fetch" all match the single "webfetch" entry.
var fetchToolNames = map[string]bool{
	"webfetch":       true,
	"web_fetch":      true,
	"fetch_url":      true,
	"fetch":          true,
	"fetch_resource": true,
	"http_get":       true,
	"get_url":        true,
	"read_resource":  true,
	"get_resource":   true,
	"browse":         true,
	"browse_url":     true,
	"download":       true,
	"download_url":   true,
	"request_url":    true,
	"curl":           true,
	"wget":           true,
}

// isFetchTool reports whether toolName is shaped like a read-only remote
// resource fetch.
func isFetchTool(toolName string) bool {
	return fetchToolNames[normalizeSeparators(toolName)]
}

// extractFetchResource extracts (host, namespace, resource) from a fetch
// call's url/uri/path argument, where namespace and resource are the first
// two non-empty path segments (e.g. "huggingface.co" / "attacker" /
// "char-a" from "https://huggingface.co/attacker/char-a/resolve/main/config.json").
// ok is false when no such argument is present, it doesn't parse as a URL
// with a host, or its path has fewer than two segments — there is no
// namespace to track diversity within.
func extractFetchResource(args map[string]interface{}) (host, namespace, resource string, ok bool) {
	raw := firstNonEmptyStringArg(args, "url", "uri", "path")
	if raw == "" {
		return "", "", "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", "", "", false
	}
	segments := pathSegments(u.Path)
	if len(segments) < 2 {
		return "", "", "", false
	}
	return strings.ToLower(u.Host), segments[0], segments[1], true
}

// firstNonEmptyStringArg returns the first non-empty string value found in
// args for any of keys, tried in order. Returns "" if none is present or all
// are empty/non-string.
func firstNonEmptyStringArg(args map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := args[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// pathSegments splits a URL path into its non-empty segments.
func pathSegments(path string) []string {
	var out []string
	for _, seg := range strings.Split(path, "/") {
		if seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

// looksEnumerable reports whether resources share the CVE-2026-54316 PoC's
// templated-naming shape: a common prefix (possibly empty, as with bare
// single-character names) followed by a short (1-3 character) suffix that
// varies per resource — "char-a".."char-z", or bare "a".."z". Requires at
// least an 80% majority match so a handful of coincidentally short names
// among otherwise-normal resource names does not trip the signal.
func looksEnumerable(resources []string) bool {
	if len(resources) == 0 {
		return false
	}
	prefix := commonStringPrefix(resources)
	matching := 0
	for _, r := range resources {
		suffix := r[len(prefix):]
		if len(suffix) >= 1 && len(suffix) <= 3 && isASCIIAlnumOrDash(suffix) {
			matching++
		}
	}
	return matching*10 >= len(resources)*8
}

// commonStringPrefix returns the longest common prefix shared by all strs.
// Returns "" for an empty slice.
func commonStringPrefix(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	prefix := strs[0]
	for _, s := range strs[1:] {
		for !strings.HasPrefix(s, prefix) {
			prefix = prefix[:len(prefix)-1]
			if prefix == "" {
				return ""
			}
		}
	}
	return prefix
}

// isASCIIAlnumOrDash reports whether s consists solely of ASCII letters,
// digits, '-', or '_'.
func isASCIIAlnumOrDash(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			continue
		default:
			return false
		}
	}
	return true
}
