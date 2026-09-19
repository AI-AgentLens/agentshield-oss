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

	// fetchDiversityHistoryMax bounds per-session memory. Records are keyed by
	// DISTINCT (host, namespace, resource), not per call, so re-fetching one
	// resource cannot consume the bound — see fetchRecord.
	//
	// The bound is deliberately GLOBAL rather than per (host, namespace). A
	// per-namespace bound would multiply memory by a count the ATTACKER chooses
	// (namespaces are just path segments), turning a precision fix into a
	// memory-exhaustion vector — a worse failure than the one it closes. What
	// makes a global bound safe is the eviction POLICY in Record: entries are
	// ordered least-recently-fetched first, and collision provenance outranks
	// ordinary records for retention. So cross-namespace traffic, at any volume,
	// can no longer evict this namespace's evidence.
	fetchDiversityHistoryMax = 200

	// fetchDiversityProvenanceMax caps how much of the bound collision-provenanced
	// records may hold, reserving the rest for ordinary recent-fetch capacity.
	//
	// Without a cap, retention preference becomes a STARVATION vector: ~100 cheap
	// colliding calls in junk namespaces fill every slot with provenance, after
	// which each new ordinary fetch is the only un-provenanced record and is
	// evicted the instant it is appended. No ordinary history can ever accumulate
	// again — not an enumeration, not a bare whole-set match, not the burst count
	// — so a handful of calls switch the whole detector off for the session.
	// Reserving half the bound guarantees ordinary capacity far above both
	// detection thresholds (5 and 8), so every arm keeps working under saturation.
	fetchDiversityProvenanceMax = fetchDiversityHistoryMax / 2
)

// fetchRecord is one DISTINCT (host, namespace, resource) observed in this
// session, not one tool call. Repeated fetches of the same resource update the
// existing record rather than appending a new one.
//
// Per-call records made the history evictable by repetition: 200 duplicate
// fetches of one resource flushed the window, taking collision provenance with
// them, so an attacker could flood away the evidence that a decoy was injected
// and then run the enumeration unblocked (#3754 F1). Keying by distinct resource
// makes the bound count resources — the thing the detector actually reasons
// about — so a flood of duplicates is free.
type fetchRecord struct {
	host      string
	namespace string
	resource  string
	// at is the LAST time this resource was fetched, for the in-window count.
	at time.Time
	// collidedAt is the last time this resource appeared in a call that resolved
	// to MORE THAN ONE candidate — a normalized-name collision, i.e. two disguised
	// spellings of `url` in one call. Zero when never. That is the only way a
	// decoy is smuggled in to collapse the whole-set prefix (#3740 finding 1), so
	// it gates the enumerable CLUSTER arm (#3754 regression 1).
	//
	// It carries its OWN timestamp so collision provenance ages out on its own
	// window rather than riding on the lifetime of individual call entries.
	collidedAt time.Time
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
	refs := extractFetchResources(args)
	if len(refs) == 0 {
		return ""
	}

	// Evaluate EVERY resolved resource, not just the first (#3727 pass-2 finding
	// 2). A normalized-name collision — two disguised spellings of `url` carrying
	// different resources — must not let a benign spelling that sorts first hide
	// the enumerable one; the strongest signal any candidate produces wins.
	// A call resolving to more than one candidate resource IS the collision the
	// cluster arm exists to defend against (#3740 finding 1). Passing it through
	// lets the current call's own ambiguity — not only history's — arm the
	// cluster gate.
	collisionNow := len(refs) > 1
	var signal FetchDiversitySignal
	t.history.view(func(history []fetchRecord) {
		for _, ref := range refs {
			signal = strongerFetchSignal(signal, fetchSignalForResource(history, ref, collisionNow))
		}
	})
	return signal
}

// fetchSignalForResource computes the diversity/enumerable signal for one
// candidate resource against the in-window history. currentCallAmbiguous is
// true when the scanning call itself resolved to more than one candidate.
func fetchSignalForResource(history []fetchRecord, ref fetchResourceRef, currentCallAmbiguous bool) FetchDiversitySignal {
	cutoff := time.Now().Add(-fetchDiversityWindow)
	seen := map[string]bool{ref.resource: true}
	resources := []string{ref.resource}
	// collided is the set of resources under THIS (host, namespace) that were
	// seen in a colliding call within the window — the collision provenance the
	// cluster arm below consults. Scoping it to the ref's own host+namespace is
	// load-bearing: a collision in a different namespace says nothing about this
	// one, and reading it namespace-wide would let one unrelated ambiguous call
	// re-enable the cluster arm for every later cluster on the host.
	collided := map[string]bool{}
	if currentCallAmbiguous {
		collided[ref.resource] = true
	}
	for _, r := range history {
		if r.host != ref.host || r.namespace != ref.namespace {
			continue
		}
		// Collision provenance is judged on its OWN timestamp, so it survives for
		// its window no matter how often the resource was re-fetched since.
		if !r.collidedAt.IsZero() && !r.collidedAt.Before(cutoff) {
			collided[r.resource] = true
		}
		if r.at.Before(cutoff) {
			continue
		}
		if !seen[r.resource] {
			seen[r.resource] = true
			resources = append(resources, r.resource)
		}
	}
	switch {
	case len(resources) >= fetchDiversityEnumerableThreshold && looksEnumerable(resources):
		return SignalFetchEnumerablePattern
	// looksEnumerable is a WHOLE-SET predicate: it takes one common prefix
	// across every in-window resource and needs an 80% majority to keep it. That
	// makes it non-monotonic in exactly the direction #3727 opened up (#3740
	// finding 1): since Record now stores EVERY resolved candidate, a single
	// constant decoy resource — `/attacker/documentation` fetched under a second
	// disguised spelling of `url` alongside `/attacker/char-a`..`char-e` —
	// collapses the common prefix to "", drops the majority to zero, and the
	// BLOCK never fires for a session that fires without the decoy. Adding a
	// candidate must never subtract a signal.
	//
	// enumerableClusterSize asks the question per CANDIDATE instead: how many
	// in-window resources share THIS call's template? An unrelated resource is
	// simply not in the cluster, so it can no longer invalidate it. The whole-set
	// test above is kept as the first arm, so no session that BLOCKed before
	// stops BLOCKing; this arm only adds firings, which is the conservative
	// direction for a detector whose miss is an exfiltration.
	//
	// Anchoring on ref.resource (the resource THIS call fetched) is what keeps it
	// honest: a qualifying cluster the current call is not a member of does not
	// make the current call a signal.
	//
	// Gated on collision provenance (#3754 regression 1): the whole-set arm can
	// only be *wrongly* subtracted by a candidate smuggled in via a colliding
	// `url` key. When no collision touched this cluster, a resource that drops
	// the majority is a genuine, separately-fetched benign neighbour and MUST
	// subtract — so benign pagination/version/shard sets alongside an ordinary
	// index/README/overview no longer BLOCK, while the #3740 collision attack
	// still does.
	//
	// The evidence is matched to the CLUSTER, not the namespace (#3754 F2): the
	// arm fires only when a member of the anchor's own cluster carries collision
	// provenance. A namespace-wide flag let one unrelated ambiguous call (say a
	// colliding {docs, help}) re-enable the arm for every later cluster in that
	// namespace, resurrecting the exact precision regression this gate fixes.
	case enumerableClusterHasCollision(resources, ref.resource, collided, fetchDiversityEnumerableThreshold):
		return SignalFetchEnumerablePattern
	case len(resources) >= fetchDiversityBurstThreshold:
		return SignalFetchDiversityBurst
	}
	return ""
}

// enumerableClusterSize returns the size of the largest set of resources that
// share the CVE-2026-54316 templated-naming shape WITH anchor: a common stem
// followed by a 1-3 character suffix that varies per resource. anchor itself is
// always a member, so the count is 1 for a resource nothing else resembles.
//
// The stem is derived from the anchor rather than from the whole set — that is
// the entire point. Every 1-3 character tail of the anchor is tried, so
// "char-a" clusters with "char-b".."char-e" (stem "char-") and a bare "a"
// clusters with "b".."e" (stem "", the PoC's other spelling), while
// "documentation" clusters with nothing because no other resource shares
// "documentatio"/"documentati"/"documentat" plus a short tail.
func enumerableClusterSize(resources []string, anchor string) int {
	best := 0
	for tail := 1; tail <= 3; tail++ {
		if len(anchor) < tail {
			break
		}
		if !isASCIIAlnumOrDash(anchor[len(anchor)-tail:]) {
			// The anchor would not be a member of its own cluster.
			continue
		}
		stem := anchor[:len(anchor)-tail]
		n := 0
		for _, r := range resources {
			if !strings.HasPrefix(r, stem) {
				continue
			}
			suffix := r[len(stem):]
			if len(suffix) >= 1 && len(suffix) <= 3 && isASCIIAlnumOrDash(suffix) {
				n++
			}
		}
		if n > best {
			best = n
		}
	}
	return best
}

// enumerableClusterHasCollision reports whether ANY cluster around anchor that
// reaches min members contains a member carrying collision provenance.
//
// This is the cluster arm's gate. It asks the question that actually matters:
// was the templated set the current call belongs to polluted by a decoy smuggled
// in under a colliding `url` key? Only then can the whole-set arm have been
// wrongly subtracted, and only then may the cluster arm restore the BLOCK.
//
// Every 1-3 character tail of the anchor is tried (as in enumerableClusterSize)
// and each resulting cluster judged on its own, so a qualifying cluster is never
// missed because a larger, un-collided one existed for a different tail.
func enumerableClusterHasCollision(resources []string, anchor string, collided map[string]bool, min int) bool {
	for tail := 1; tail <= 3; tail++ {
		if len(anchor) < tail {
			break
		}
		if !isASCIIAlnumOrDash(anchor[len(anchor)-tail:]) {
			// The anchor would not be a member of its own cluster.
			continue
		}
		stem := anchor[:len(anchor)-tail]
		n := 0
		sawCollided := false
		for _, r := range resources {
			if !strings.HasPrefix(r, stem) {
				continue
			}
			suffix := r[len(stem):]
			if len(suffix) >= 1 && len(suffix) <= 3 && isASCIIAlnumOrDash(suffix) {
				n++
				if collided[r] {
					sawCollided = true
				}
			}
		}
		if n >= min && sawCollided {
			return true
		}
	}
	return false
}

// strongerFetchSignal keeps the higher-severity of two signals: an enumerable
// pattern outranks a diversity burst, which outranks none.
func strongerFetchSignal(a, b FetchDiversitySignal) FetchDiversitySignal {
	rank := func(s FetchDiversitySignal) int {
		switch s {
		case SignalFetchEnumerablePattern:
			return 2
		case SignalFetchDiversityBurst:
			return 1
		default:
			return 0
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// Record adds a fetch-shaped tool call to session history. No-ops for
// non-fetch tools or calls with no extractable namespaced resource.
func (t *FetchDiversityTracker) Record(toolName string, args map[string]interface{}) {
	if t == nil || !isFetchTool(toolName) {
		return
	}
	// Record EVERY resolved resource so a collision cannot keep the dangerous
	// candidate out of history (#3727 pass-2 finding 2). A call resolving to more
	// than one candidate is a normalized-name collision; stamp collidedAt on every
	// resource it resolved so the cluster arm can later tell a decoy-polluted
	// cluster from a benign one (#3754 regression 1).
	//
	// UPSERT by distinct (host, namespace, resource): a repeat fetch refreshes the
	// existing record instead of appending. Appending per call let 200 duplicate
	// fetches evict the window — and with it the collision provenance — which was
	// a complete bypass of the gate (#3754 F1).
	refs := extractFetchResources(args)
	if len(refs) == 0 {
		return
	}
	ambiguous := len(refs) > 1
	now := time.Now()
	t.history.mutate(func(entries []fetchRecord) []fetchRecord {
		for _, ref := range refs {
			// Take the existing record OUT of the slice, refresh it, and re-append at
			// the newest position. Refreshing in place left the record in its old
			// slot, and boundedHistory evicts by POSITION — so a freshly-created
			// collision could be evicted the instant it was made, purely because the
			// resource had been first seen long ago (#3754 capacity edge). Keeping
			// the slice ordered least-recently-fetched first is what makes
			// position-based eviction mean "evict the stalest".
			rec := fetchRecord{host: ref.host, namespace: ref.namespace, resource: ref.resource}
			for i := range entries {
				if entries[i].host == ref.host && entries[i].namespace == ref.namespace && entries[i].resource == ref.resource {
					rec = entries[i]
					entries = append(entries[:i], entries[i+1:]...)
					break
				}
			}
			rec.at = now
			if ambiguous {
				rec.collidedAt = now
			}
			entries = append(entries, rec)
		}
		return evictFetchRecords(entries, now)
	})
}

// evictFetchRecords trims entries (ordered least-recently-fetched first) to the
// bound. Records carrying LIVE collision provenance are retained ahead of
// ordinary ones — ordinary fetch traffic must not be able to flush security
// evidence, or a flood of unrelated resources evicts the very records proving a
// decoy was injected and the enumeration that follows runs unblocked.
//
// Two limits keep that preference from becoming a weapon:
//
//	expiry      provenance protects a record only while the collision is still
//	            inside its own window. An expired collidedAt is ordinary for
//	            eviction, exactly as it is already ignored for detection, so
//	            protection cannot outlive the evidence it represents.
//	saturation  provenanced records may hold at most fetchDiversityProvenanceMax
//	            of the bound. Over that share the STALEST live-provenanced record
//	            is evicted instead of the newest ordinary one, which is what
//	            preserves ordinary recent-fetch capacity. Without it, filling the
//	            history with provenance starves every arm of the detector.
//
// Trimming here, inside the mutate callback, leaves boundedHistory's own
// position-based trim a no-op — the shared helper's semantics are unchanged for
// the other trackers that use it.
func evictFetchRecords(entries []fetchRecord, now time.Time) []fetchRecord {
	cutoff := now.Add(-fetchDiversityWindow)
	// protected reports whether a record's collision provenance is still live.
	protected := func(r fetchRecord) bool {
		return !r.collidedAt.IsZero() && !r.collidedAt.Before(cutoff)
	}
	for len(entries) > fetchDiversityHistoryMax {
		live := 0
		for _, r := range entries {
			if protected(r) {
				live++
			}
		}
		// Over its share, provenance yields; otherwise ordinary records yield.
		// Entries are ordered least-recently-fetched first, so the first match in
		// either scan is the stalest of its kind.
		wantProtected := live > fetchDiversityProvenanceMax
		victim := -1
		for i := range entries {
			if protected(entries[i]) == wantProtected {
				victim = i
				break
			}
		}
		// Unreachable as long as fetchDiversityProvenanceMax < fetchDiversityHistoryMax:
		// wantProtected is true only when live > the cap, so a protected record
		// exists; and when it is false the un-protected count is at least
		// len(entries)-cap > 0, since the loop runs only while len(entries) exceeds
		// the bound. Kept as a safety net so a future cap change degrades into a
		// stale eviction rather than an index panic.
		if victim < 0 {
			victim = 0
		}
		entries = append(entries[:victim], entries[victim+1:]...)
	}
	return entries
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
// fetchResourceRef is one (host, namespace, resource) triple extracted from a
// fetch call's url/uri/path argument.
type fetchResourceRef struct {
	host      string
	namespace string
	resource  string
}

func extractFetchResources(args map[string]interface{}) []fetchResourceRef {
	var out []fetchResourceRef
	seen := map[fetchResourceRef]bool{}
	for _, raw := range nonEmptyStringArgs(args, "url", "uri", "path") {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		segments := pathSegments(u.Path)
		if len(segments) < 2 {
			continue
		}
		ref := fetchResourceRef{host: strings.ToLower(u.Host), namespace: segments[0], resource: segments[1]}
		if !seen[ref] {
			seen[ref] = true
			out = append(out, ref)
		}
	}
	return out
}

// nonEmptyStringArgs returns the non-empty string values of the FIRST of keys
// that resolves to any (keys tried in order). It returns EVERY such value for
// that key, not just the first: a normalized-name collision resolves one key to
// several candidates, and a benign one that sorts first must not hide the
// dangerous one (#3727 pass-2 finding 2).
//
// Resolution is argFieldRecovered (exact-then-render-recovery, not a raw map
// index and not full resolveField), so a Unicode-separator-corrupted argument
// name still resolves while an ASCII casing/convention variant does not — see
// #3691/#3712/#3720/#3727.
func nonEmptyStringArgs(args map[string]interface{}, keys ...string) []string {
	for _, k := range keys {
		var vals []string
		for _, v := range argFieldRecovered(args, k) {
			if s, ok := v.(string); ok && s != "" {
				vals = append(vals, s)
			}
		}
		if len(vals) > 0 {
			return vals
		}
	}
	return nil
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
