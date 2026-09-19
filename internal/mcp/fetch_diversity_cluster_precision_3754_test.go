package mcp

import (
	"strconv"
	"testing"
	"time"
)

// Regression tests for #3754 -- the post-merge review of #3744 (issue #3740).
// #3744 added a second arm to fetchSignalForResource:
//
//	enumerableClusterSize(resources, ref.resource) >= threshold
//
// It fires the BLOCK-mapped SignalFetchEnumerablePattern whenever five in-window
// resources share a stem + 1-3 char suffix, regardless of anything else in the
// window. That arm was added so a collision-injected decoy could not SUBTRACT a
// signal (#3740 finding 1); the side effect is that an unrelated *benign*
// neighbour fetched as its own genuine call (overview, README, index) no longer
// prevents an ordinary pagination/version/shard cluster from BLOCKing.
//
// The invariant these tests pin:
//   - no benign single-namespace enumerable-looking fetch set fetched WITHOUT a
//     collision BLOCKs (A/B/C below), AND
//   - the #3740 attack (a colliding decoy across disguised `url` keys) still
//     BLOCKs (the control at the bottom).
//
// Every benign case carries a VACUITY note: on the merge that introduced the
// regression the same session returns SignalFetchEnumerablePattern; these tests
// FAIL on that merge (they assert clean) and pass after the fix.

// benignFetch builds a single-`url` fetch call for resource under namespace ns on
// one host. One url key => extractFetchResources yields exactly one ref => no
// collision, the benign shape.
func benignFetch(ns, resource string) map[string]interface{} {
	return map[string]interface{}{"url": "https://docs.example.com/" + ns + "/" + resource}
}

// runFetchSession scans+records each resource in order and returns the signal on
// the LAST call (the measurement point the issue used).
func runFetchSession(t *testing.T, resources []string) FetchDiversitySignal {
	t.Helper()
	tr := NewFetchDiversityTracker()
	var last FetchDiversitySignal
	for _, r := range resources {
		args := benignFetch("guide", r)
		last = tr.Scan("fetch_url", args)
		tr.Record("fetch_url", args)
	}
	return last
}

func TestFetchClusterArm_BenignSetsDoNotBlock(t *testing.T) {
	cases := []struct {
		name      string
		resources []string // last element is the measurement call (a cluster member)
	}{
		// A: an ordinary doc index + 5 pagination pages. page-1..page-5 form a
		// cluster; overview drops the whole-set majority below 80%. Before the
		// fix the cluster arm BLOCKs anyway.
		{"A/overview+pagination", []string{"overview", "page-1", "page-2", "page-3", "page-4", "page-5"}},
		// B: a readme + 5 version tags.
		{"B/README+versions", []string{"README", "v1.0", "v1.1", "v1.2", "v1.3", "v1.4"}},
		// C: an index + 5 shard parts.
		{"C/index+shards", []string{"index", "part-a", "part-b", "part-c", "part-d", "part-e"}},
		// C2: dotted test file names -- clean at merge too (the dot breaks the
		// short-suffix cluster); kept as a control that stays clean.
		{"C2/dotted test files", []string{"test_a.py", "test_b.py", "test_c.py", "test_d.py", "test_e.py"}},
		// C3: locale files -- clean at merge too; kept as a control.
		{"C3/locale files", []string{"en.json", "de.json", "fr.json", "es.json", "it.json"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runFetchSession(t, tc.resources); got == SignalFetchEnumerablePattern {
				t.Fatalf("benign single-namespace set %v produced %q (a BLOCK) with no collision present; want no enumerable BLOCK",
					tc.resources, got)
			}
		})
	}
}

// TestFetchClusterArm_AttackStillBlocks is the vacuity control for the fix: the
// #3740 finding-1 attack -- a constant non-enumerable decoy fetched under a
// SECOND disguised spelling of `url` alongside the varying enumerable stream --
// must still BLOCK before AND after the fix. This proves the collision gate did
// not weaken the #3740 decoy-suppression fix.
func TestFetchClusterArm_AttackStillBlocks(t *testing.T) {
	nbsp := sepRune(0x00A0) // sorts before U+200D
	zwj := sepRune(0x200D)

	tr := NewFetchDiversityTracker()
	var last FetchDiversitySignal
	for _, n := range enumerableNames { // char-a..char-e
		args := map[string]interface{}{
			"url" + nbsp: fetchRes("documentation"), // constant decoy, collapses whole-set prefix
			"url" + zwj:  fetchRes(n),               // the varying enumerable stream
		}
		last = tr.Scan("fetch_url", args)
		tr.Record("fetch_url", args)
	}
	if last != SignalFetchEnumerablePattern {
		t.Fatalf("#3740 collision attack no longer BLOCKs: got %q, want %q", last, SignalFetchEnumerablePattern)
	}
}

// TestFetchClusterArm_HistoryCollisionStillBlocks proves the collision gate
// reads HISTORY, not only the current call: the decoy is smuggled in under a
// colliding `url` key on the first four calls, then the fifth (char-e) is a
// plain single-`url` fetch. collisionNow is false on that last call, so only the
// history-recorded ambiguity keeps the cluster arm live. Kills the mutation
// "drop the `if r.ambiguous { sawCollision = true }` history scan".
func TestFetchClusterArm_HistoryCollisionStillBlocks(t *testing.T) {
	nbsp := sepRune(0x00A0)
	zwj := sepRune(0x200D)

	tr := NewFetchDiversityTracker()
	var last FetchDiversitySignal
	for i, n := range enumerableNames {
		var args map[string]interface{}
		if i < len(enumerableNames)-1 {
			args = map[string]interface{}{
				"url" + nbsp: fetchRes("documentation"), // colliding decoy on early calls only
				"url" + zwj:  fetchRes(n),
			}
		} else {
			args = map[string]interface{}{"url": fetchRes(n)} // last call: plain, single-resource
		}
		last = tr.Scan("fetch_url", args)
		tr.Record("fetch_url", args)
	}
	if last != SignalFetchEnumerablePattern {
		t.Fatalf("a decoy recorded via an EARLIER colliding call must keep the cluster arm live on a later clean call: got %q, want %q",
			last, SignalFetchEnumerablePattern)
	}
}

// --- #3754 follow-up: the collision gate's own two edges (F2 / F1) ---

// nsFetch builds a single-`url` fetch under an explicit host + namespace.
func nsFetch(host, ns, resource string) map[string]interface{} {
	return map[string]interface{}{"url": "https://" + host + "/" + ns + "/" + resource}
}

// collidingFetch builds ONE call whose `url` key collides into two spellings,
// resolving to two candidate resources under host+ns -- the #3740 attack shape.
func collidingFetch(host, ns, first, second string) map[string]interface{} {
	return map[string]interface{}{
		"url" + sepRune(0x00A0): "https://" + host + "/" + ns + "/" + first,
		"url" + sepRune(0x200D): "https://" + host + "/" + ns + "/" + second,
	}
}

// runNSSession scans+records each call in order and returns the LAST signal.
func runNSSession(calls []map[string]interface{}) FetchDiversitySignal {
	tr := NewFetchDiversityTracker()
	var last FetchDiversitySignal
	for _, c := range calls {
		last = tr.Scan("fetch_url", c)
		tr.Record("fetch_url", c)
	}
	return last
}

// TestFetchClusterArm_UnrelatedCollisionDoesNotArmOtherClusters is the F2
// regression. Collision evidence must be matched to the CLUSTER it actually
// affected, not to the namespace. A namespace-wide flag meant one unrelated
// ambiguous call ({docs, help}) re-enabled the cluster arm for every later
// cluster in that namespace -- resurrecting the very precision regression this
// gate exists to fix.
func TestFetchClusterArm_UnrelatedCollisionDoesNotArmOtherClusters(t *testing.T) {
	const host, ns = "docs.example.com", "x"

	// The exact F2 sequence. 8 distinct resources (docs, help, overview,
	// page-1..page-5) reaches fetchDiversityBurstThreshold, so the naming-agnostic
	// AUDIT burst is expected here; what must NOT happen is the enumerable BLOCK.
	t.Run("unrelated collision then benign pagination does not BLOCK", func(t *testing.T) {
		calls := []map[string]interface{}{collidingFetch(host, ns, "docs", "help")}
		for _, r := range []string{"overview", "page-1", "page-2", "page-3", "page-4", "page-5"} {
			calls = append(calls, nsFetch(host, ns, r))
		}
		if got := runNSSession(calls); got == SignalFetchEnumerablePattern {
			t.Fatalf("an unrelated collision re-armed the cluster arm for a benign cluster: got %q, want no enumerable BLOCK", got)
		}
	})

	// Same shape one resource lighter (no `overview`), so the burst threshold is
	// not reached either: the result must be STRICTLY clean. This proves the case
	// above is clean because the cluster arm is off, not because a burst masked it.
	t.Run("below the burst threshold it is strictly clean", func(t *testing.T) {
		calls := []map[string]interface{}{collidingFetch(host, ns, "docs", "help")}
		for _, r := range []string{"page-1", "page-2", "page-3", "page-4", "page-5"} {
			calls = append(calls, nsFetch(host, ns, r))
		}
		if got := runNSSession(calls); got != "" {
			t.Fatalf("7 distinct resources with an unrelated collision gave %q, want no signal at all", got)
		}
	})

	// VACUITY CONTROL: the gate is not simply dead. The identical shape where the
	// collision DOES touch the cluster (a decoy smuggled in alongside `page-1`)
	// must still BLOCK -- otherwise the two cases above prove nothing.
	t.Run("control/a collision touching the cluster still BLOCKs", func(t *testing.T) {
		calls := []map[string]interface{}{collidingFetch(host, ns, "overview", "page-1")}
		for _, r := range []string{"page-2", "page-3", "page-4", "page-5"} {
			calls = append(calls, nsFetch(host, ns, r))
		}
		if got := runNSSession(calls); got != SignalFetchEnumerablePattern {
			t.Fatalf("control: a decoy colliding WITH a cluster member must still BLOCK, got %q", got)
		}
	})
}

// TestFetchClusterArm_CollisionProvenanceIsScoped kills the mutation "read the
// collision flag without filtering on host/namespace". The collision happens on
// resources that WOULD be cluster members of the measured cluster, but under a
// different namespace (and, in the second case, a different host). Neither may
// arm the measured cluster.
func TestFetchClusterArm_CollisionProvenanceIsScoped(t *testing.T) {
	const host, ns = "docs.example.com", "guide"
	benign := []string{"overview", "page-1", "page-2", "page-3", "page-4", "page-5"}

	cases := []struct {
		name                 string
		collideHost, collide string
	}{
		{"different namespace, same host", host, "otherns"},
		{"different host, same namespace", "other.example.com", ns},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The colliding pair names resources identical to the measured cluster's
			// members, so only host/namespace scoping can keep them apart.
			calls := []map[string]interface{}{collidingFetch(tc.collideHost, tc.collide, "page-1", "page-2")}
			for _, r := range benign {
				calls = append(calls, nsFetch(host, ns, r))
			}
			if got := runNSSession(calls); got == SignalFetchEnumerablePattern {
				t.Fatalf("collision provenance leaked across host/namespace: got %q, want no enumerable BLOCK", got)
			}
		})
	}
}

// TestFetchClusterArm_CollisionProvenanceSurvivesFlood is the F1 regression: a
// complete BYPASS of the gate. The attack opens with a REAL colliding decoy
// ({documentation, char-a}) -- squarely inside #3740 scope -- then floods the
// session with plain re-fetches of the decoy. When history was keyed per CALL,
// those duplicates evicted the two ambiguous records while the attack set was
// still in-window, switching the cluster arm off; the decoy then defeated the
// whole-set arm and six distinct resources stayed under the burst threshold, so
// the enumeration ran with NO signal at all.
//
// Keying history by DISTINCT resource (and giving collision provenance its own
// timestamp) makes the flood free, so the provenance survives its window.
func TestFetchClusterArm_CollisionProvenanceSurvivesFlood(t *testing.T) {
	const host, ns = "docs.example.com", "attacker"
	// Enough duplicate appends that a per-call history would evict the opening
	// colliding pair: 2 (collision) + flood + 4 (char-b,c,d,a) > the bound.
	flood := fetchDiversityHistoryMax - 4

	build := func(withFlood bool) []map[string]interface{} {
		calls := []map[string]interface{}{collidingFetch(host, ns, "documentation", "char-a")}
		if withFlood {
			for i := 0; i < flood; i++ {
				calls = append(calls, nsFetch(host, ns, "documentation"))
			}
		}
		for _, r := range []string{"char-b", "char-c", "char-d", "char-a", "char-e"} {
			calls = append(calls, nsFetch(host, ns, r))
		}
		return calls
	}

	// VACUITY CONTROL (F1-control): the identical attack with NO flood BLOCKs both
	// before and after the fix -- so a bypass in the flooded case is attributable
	// purely to the eviction, not to the attack shape being undetectable.
	t.Run("control/same attack without the flood BLOCKs", func(t *testing.T) {
		if got := runNSSession(build(false)); got != SignalFetchEnumerablePattern {
			t.Fatalf("control: the un-flooded colliding attack gave %q, want %q", got, SignalFetchEnumerablePattern)
		}
	})

	t.Run("a duplicate flood must not evict collision provenance", func(t *testing.T) {
		if got := runNSSession(build(true)); got != SignalFetchEnumerablePattern {
			t.Fatalf("flooding %d duplicate fetches bypassed the detector: got %q, want %q",
				flood, got, SignalFetchEnumerablePattern)
		}
	})
}

// TestFetchClusterArm_LateCollisionOnKnownResourceArms pins that provenance is
// stamped on a resource ALREADY in history when a later call collides on it.
// Ordering matters to an attacker: fetching char-a plainly first and only then
// smuggling the decoy in beside it would, if the upsert path skipped the stamp,
// leave provenance solely on `documentation` -- which is not a member of the
// char- cluster, so the cluster arm would never arm and the enumeration would
// run unblocked.
func TestFetchClusterArm_LateCollisionOnKnownResourceArms(t *testing.T) {
	const host, ns = "docs.example.com", "attacker"

	calls := []map[string]interface{}{
		nsFetch(host, ns, "char-a"),                         // seen plainly FIRST
		collidingFetch(host, ns, "documentation", "char-a"), // decoy smuggled in beside it
	}
	for _, r := range []string{"char-b", "char-c", "char-d", "char-e"} {
		calls = append(calls, nsFetch(host, ns, r))
	}
	if got := runNSSession(calls); got != SignalFetchEnumerablePattern {
		t.Fatalf("a collision on an already-recorded cluster member must arm the cluster: got %q, want %q",
			got, SignalFetchEnumerablePattern)
	}

	// VACUITY CONTROL: drop the colliding call and the same session is the
	// accepted non-colliding residual -- so the case above measures the stamp,
	// not merely the shape.
	plain := []map[string]interface{}{nsFetch(host, ns, "char-a"), nsFetch(host, ns, "documentation")}
	for _, r := range []string{"char-b", "char-c", "char-d", "char-e"} {
		plain = append(plain, nsFetch(host, ns, r))
	}
	if got := runNSSession(plain); got == SignalFetchEnumerablePattern {
		t.Fatalf("control: with no collision this is the accepted residual, got %q", got)
	}
}

// TestFetchClusterArm_ProvenanceSurvivesDistinctResourceCapacity pins that
// collision provenance survives a session that FILLS the distinct-resource
// bound. Two eviction bypasses lived here, both of the same class -- ordinary
// fetch traffic flushing security evidence:
//
//	position    the upsert refreshed a record's timestamps in place while
//	            boundedHistory evicts by slice POSITION, so a collision created
//	            on a long-known resource was evictable the instant it was made;
//	filler      the bound is GLOBAL, so resources in wholly unrelated namespaces
//	            evicted this namespace's provenance -- before OR after the
//	            colliding call.
//
// Records are now ordered least-recently-fetched first, and a record carrying
// provenance is never evicted while an un-provenanced one remains.
func TestFetchClusterArm_ProvenanceSurvivesDistinctResourceCapacity(t *testing.T) {
	const host, ns = "docs.example.com", "attacker"

	// filler distinct resources, each in its OWN namespace, so nothing but the
	// global bound connects them to the attack namespace.
	fill := func(calls []map[string]interface{}, n int) []map[string]interface{} {
		for i := 0; i < n; i++ {
			calls = append(calls, nsFetch(host, "ns"+strconv.Itoa(i), "r"))
		}
		return calls
	}
	enumerate := func(calls []map[string]interface{}, names ...string) []map[string]interface{} {
		for _, r := range names {
			calls = append(calls, nsFetch(host, ns, r))
		}
		return calls
	}

	// char-a is fetched plainly FIRST, so the later colliding call refreshes an
	// existing (and, with filler, long-stale-by-position) record.
	beforeCollision := func(filler int) FetchDiversitySignal {
		calls := []map[string]interface{}{nsFetch(host, ns, "char-a")}
		calls = fill(calls, filler)
		calls = append(calls, collidingFetch(host, ns, "documentation", "char-a"))
		return runNSSession(enumerate(calls, "char-a", "char-b", "char-c", "char-d", "char-e"))
	}

	// VACUITY CONTROLS: the same attack below capacity BLOCKs, so a bypass at
	// capacity is attributable to eviction rather than to the shape.
	for _, filler := range []int{0, 150} {
		t.Run("control/filler="+strconv.Itoa(filler)+" BLOCKs", func(t *testing.T) {
			if got := beforeCollision(filler); got != SignalFetchEnumerablePattern {
				t.Fatalf("control: filler=%d gave %q, want %q", filler, got, SignalFetchEnumerablePattern)
			}
		})
	}

	// At exactly the bound, the colliding call's refresh landed in an old slot and
	// the trim evicted it immediately -- a complete bypass.
	t.Run("collision refreshing a record at full capacity survives", func(t *testing.T) {
		if got := beforeCollision(fetchDiversityHistoryMax - 1); got != SignalFetchEnumerablePattern {
			t.Fatalf("a collision created at full capacity was evicted: got %q, want %q",
				got, SignalFetchEnumerablePattern)
		}
	})

	// The mirror image: collide FIRST, then flood past the bound. The provenance
	// records are the oldest by then, so position-ordered eviction alone would
	// still drop them.
	t.Run("unrelated flood after the collision must not evict provenance", func(t *testing.T) {
		calls := []map[string]interface{}{collidingFetch(host, ns, "documentation", "char-a")}
		calls = fill(calls, fetchDiversityHistoryMax+50)
		if got := runNSSession(enumerate(calls, "char-b", "char-c", "char-d", "char-e")); got != SignalFetchEnumerablePattern {
			t.Fatalf("an unrelated-namespace flood evicted collision provenance: got %q, want %q",
				got, SignalFetchEnumerablePattern)
		}
	})
}

// TestFetchRecord_RefreshMovesToNewestPosition pins the general half of the
// eviction invariant: a record refreshed by upsert must not be evictable ahead
// of genuinely older records. The provenance preference covers records carrying
// collision evidence; this covers every OTHER record, where the only thing
// keeping position-based eviction honest is that a refresh moves the record to
// the newest slot.
//
// Observed through the naming-agnostic burst (a distinct-resource COUNT), so the
// enumerable arms play no part: the names deliberately do not cluster.
func TestFetchRecord_RefreshMovesToNewestPosition(t *testing.T) {
	const host, ns = "docs.example.com", "target"
	names := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"}
	if len(names) != fetchDiversityBurstThreshold {
		t.Fatalf("test setup: need exactly %d names to sit on the burst threshold, got %d",
			fetchDiversityBurstThreshold, len(names))
	}

	run := func(refresh bool) FetchDiversitySignal {
		var calls []map[string]interface{}
		filler := 0
		fill := func(n int) {
			for i := 0; i < n; i++ {
				calls = append(calls, nsFetch(host, "filler"+strconv.Itoa(filler), "r"))
				filler++
			}
		}
		calls = append(calls, nsFetch(host, ns, names[0])) // first seen, oldest slot
		fill(fetchDiversityHistoryMax - 1)                 // sit exactly on the bound
		if refresh {
			calls = append(calls, nsFetch(host, ns, names[0])) // re-fetched: freshly live
		}
		fill(50) // push past the bound -- evictions happen here
		for _, n := range names[1:] {
			calls = append(calls, nsFetch(host, ns, n))
		}
		return runNSSession(calls)
	}

	// VACUITY CONTROL: with no refresh the first resource really is the stalest,
	// is correctly evicted, and the namespace ends one short of the threshold --
	// so the case below measures the refresh rather than the bound being loose.
	if got := run(false); got == SignalFetchDiversityBurst {
		t.Fatalf("control: an un-refreshed stale resource should have been evicted, got %q", got)
	}
	if got := run(true); got != SignalFetchDiversityBurst {
		t.Fatalf("a re-fetched resource was evicted ahead of older ones: got %q, want %q",
			got, SignalFetchDiversityBurst)
	}
}

// TestEvictFetchRecords_PrefersStalestUnprovenancedRecord pins the eviction
// policy directly, including that the bound is still honoured.
func TestEvictFetchRecords_PrefersStalestUnprovenancedRecord(t *testing.T) {
	now := time.Now()
	// Oldest-first: a provenanced record sits at the FRONT (stalest by position),
	// followed by enough plain records to exceed the bound by one.
	entries := []fetchRecord{{host: "h", namespace: "n", resource: "evidence", at: now, collidedAt: now}}
	for i := 0; i <= fetchDiversityHistoryMax-1; i++ {
		entries = append(entries, fetchRecord{host: "h", namespace: "n", resource: "r" + strconv.Itoa(i), at: now})
	}

	got := evictFetchRecords(entries, now)
	if len(got) != fetchDiversityHistoryMax {
		t.Fatalf("eviction must honour the bound: got %d entries, want %d", len(got), fetchDiversityHistoryMax)
	}
	if got[0].resource != "evidence" || got[0].collidedAt.IsZero() {
		t.Fatalf("the provenanced record must survive ahead of un-provenanced ones, got %q", got[0].resource)
	}
	if got[1].resource != "r1" {
		t.Fatalf("the stalest UN-provenanced record (r0) should have been the victim, got %q at index 1", got[1].resource)
	}
}

// TestEvictFetchRecords_ProtectionExpiresWithTheEvidence pins invariant (1):
// eviction protection lasts exactly as long as the collision evidence itself.
// A record whose collidedAt has aged out of the window is ordinary for eviction,
// matching the way detection already ignores it — protection must never outlive
// the thing it protects.
func TestEvictFetchRecords_ProtectionExpiresWithTheEvidence(t *testing.T) {
	now := time.Now()
	stale := now.Add(-2 * fetchDiversityWindow)

	build := func(collidedAt time.Time) []fetchRecord {
		e := []fetchRecord{{host: "h", namespace: "n", resource: "evidence", at: now, collidedAt: collidedAt}}
		for i := 0; i <= fetchDiversityHistoryMax-1; i++ {
			e = append(e, fetchRecord{host: "h", namespace: "n", resource: "r" + strconv.Itoa(i), at: now})
		}
		return e
	}

	// VACUITY CONTROL: with LIVE provenance the record is retained (as above).
	if got := evictFetchRecords(build(now), now); got[0].resource != "evidence" {
		t.Fatalf("control: a live-provenanced record must be retained, got %q", got[0].resource)
	}
	// Expired provenance earns no protection: it is the stalest record, so it goes.
	got := evictFetchRecords(build(stale), now)
	if got[0].resource == "evidence" {
		t.Fatal("a record whose collision provenance expired must be ordinary for eviction, but it was protected")
	}
}

// TestEvictFetchRecords_SaturationEvictsStalestProvenanced pins invariant (2):
// when provenance would exceed its share of the bound, the victim is the STALEST
// LIVE-PROVENANCED record, not the newest ordinary one. Evicting the newest
// ordinary record is what starved the detector: no ordinary history could ever
// accumulate again.
func TestEvictFetchRecords_SaturationEvictsStalestProvenanced(t *testing.T) {
	now := time.Now()
	// Every slot provenanced (oldest first), then one fresh ordinary record.
	var entries []fetchRecord
	for i := 0; i < fetchDiversityHistoryMax; i++ {
		entries = append(entries, fetchRecord{
			host: "h", namespace: "n", resource: "p" + strconv.Itoa(i), at: now, collidedAt: now,
		})
	}
	entries = append(entries, fetchRecord{host: "h", namespace: "n", resource: "ordinary", at: now})

	got := evictFetchRecords(entries, now)
	if len(got) != fetchDiversityHistoryMax {
		t.Fatalf("eviction must honour the bound: got %d, want %d", len(got), fetchDiversityHistoryMax)
	}
	if got[0].resource != "p1" {
		t.Fatalf("under saturation the STALEST provenanced record (p0) must be the victim, got %q at index 0", got[0].resource)
	}
	if got[len(got)-1].resource != "ordinary" {
		t.Fatal("the fresh ordinary record must survive under saturation, or the detector starves")
	}
}

// clusterHistory is the shared five-record history used by the two unit tests
// below: a non-enumerable decoy plus char-a..char-d, all freshly fetched under
// one (host, namespace). The measured call is char-e, so the cluster is
// char-a..char-e (5) and the decoy defeats the whole-set arm.
func clusterHistory(now time.Time) ([]fetchRecord, fetchResourceRef) {
	const host, ns = "docs.example.com", "attacker"
	h := []fetchRecord{
		{host: host, namespace: ns, resource: "documentation", at: now},
		{host: host, namespace: ns, resource: "char-a", at: now},
		{host: host, namespace: ns, resource: "char-b", at: now},
		{host: host, namespace: ns, resource: "char-c", at: now},
		{host: host, namespace: ns, resource: "char-d", at: now},
	}
	return h, fetchResourceRef{host: host, namespace: ns, resource: "char-e"}
}

// TestFetchSignal_ExpiredCollisionProvenanceDoesNotArm pins that collision
// provenance ages out on its OWN timestamp. Driving fetchSignalForResource
// directly is what makes the window testable without waiting five minutes.
func TestFetchSignal_ExpiredCollisionProvenanceDoesNotArm(t *testing.T) {
	now := time.Now()
	history, ref := clusterHistory(now)
	// char-a collided, but longer ago than the window.
	history[1].collidedAt = now.Add(-2 * fetchDiversityWindow)
	if got := fetchSignalForResource(history, ref, false); got == SignalFetchEnumerablePattern {
		t.Fatalf("collision provenance older than the window must not arm the cluster arm, got %q", got)
	}

	// VACUITY CONTROL: the identical history with FRESH provenance BLOCKs, so the
	// case above measures expiry rather than a dead gate.
	history[1].collidedAt = now
	if got := fetchSignalForResource(history, ref, false); got != SignalFetchEnumerablePattern {
		t.Fatalf("control: fresh collision provenance must BLOCK, got %q", got)
	}
}

// TestFetchSignal_StaleResourcesFallOutOfTheWindow pins the in-window count.
// Keying history by DISTINCT resource redefined `at` from "when this call
// happened" to "when this resource was last fetched", so the window semantics
// are worth pinning explicitly rather than inherited by assumption.
func TestFetchSignal_StaleResourcesFallOutOfTheWindow(t *testing.T) {
	const host, ns = "docs.example.com", "attacker"
	now := time.Now()
	ref := fetchResourceRef{host: host, namespace: ns, resource: "char-e"}
	enumeration := func(at time.Time) []fetchRecord {
		var h []fetchRecord
		for _, r := range []string{"char-a", "char-b", "char-c", "char-d"} {
			h = append(h, fetchRecord{host: host, namespace: ns, resource: r, at: at})
		}
		return h
	}

	// VACUITY CONTROL: in-window this is a pure enumeration and BLOCKs via the
	// whole-set arm, so the aged case below measures the window, not a dead path.
	if got := fetchSignalForResource(enumeration(now), ref, false); got != SignalFetchEnumerablePattern {
		t.Fatalf("control: an in-window enumeration must BLOCK, got %q", got)
	}
	if got := fetchSignalForResource(enumeration(now.Add(-2*fetchDiversityWindow)), ref, false); got != "" {
		t.Fatalf("resources last fetched outside the window must not count: got %q, want no signal", got)
	}
}

// TestFetchSignal_CurrentCallAmbiguityIsProvenance pins that the SCANNING call's
// own collision counts as provenance for its resource (which is always the
// cluster anchor). Its negative half also documents the accepted residual: a
// session where a decoy was only ever fetched plainly is shape-identical to a
// benign mixed session and is deliberately NOT caught.
func TestFetchSignal_CurrentCallAmbiguityIsProvenance(t *testing.T) {
	history, ref := clusterHistory(time.Now())

	// Negative control / accepted residual: no collision anywhere.
	if got := fetchSignalForResource(history, ref, false); got == SignalFetchEnumerablePattern {
		t.Fatalf("a session with no collision at all must stay the accepted residual, got %q", got)
	}
	// The same history, but THIS call resolved to more than one candidate.
	if got := fetchSignalForResource(history, ref, true); got != SignalFetchEnumerablePattern {
		t.Fatalf("the scanning call's own collision must arm its cluster, got %q", got)
	}
}

// TestFetchClusterArm_EnumerableAloneStillBlocks pins the whole-set arm: a pure
// enumeration with no benign neighbour and no collision (char-a..char-e alone)
// still BLOCKs via the first arm. The collision gate only touches the SECOND
// arm, so this must be unaffected.
func TestFetchClusterArm_EnumerableAloneStillBlocks(t *testing.T) {
	tr := NewFetchDiversityTracker()
	var last FetchDiversitySignal
	for _, n := range enumerableNames {
		args := map[string]interface{}{"url": fetchRes(n)}
		last = tr.Scan("fetch_url", args)
		tr.Record("fetch_url", args)
	}
	if last != SignalFetchEnumerablePattern {
		t.Fatalf("pure enumeration alone must still BLOCK via the whole-set arm: got %q, want %q",
			last, SignalFetchEnumerablePattern)
	}
}

// --- #3754 round 4: provenance SATURATION must not starve the detector ---

const satHost = "docs.example.com"

// saturateFresh issues n colliding pairs, each in its OWN junk namespace, so the
// history fills with LIVE-provenanced records that are irrelevant to any later
// detection. 2 records per pair.
func saturateFresh(calls []map[string]interface{}, pairs int) []map[string]interface{} {
	for i := 0; i < pairs; i++ {
		calls = append(calls, collidingFetch(satHost, "junk"+strconv.Itoa(i), "a", "b"))
	}
	return calls
}

// bareEnumeration appends a plain char-a..char-e enumeration -- no collision at
// all, so only the WHOLE-SET arm can catch it.
func bareEnumeration(calls []map[string]interface{}) []map[string]interface{} {
	for _, r := range []string{"char-a", "char-b", "char-c", "char-d", "char-e"} {
		calls = append(calls, nsFetch(satHost, "attacker", r))
	}
	return calls
}

// collidingAttack appends the real #3740 shape: a decoy smuggled in beside
// char-a, then the rest of the enumeration plainly. Only the CLUSTER arm catches
// it, and only if the real collision's provenance survived.
func collidingAttack(calls []map[string]interface{}) []map[string]interface{} {
	calls = append(calls, collidingFetch(satHost, "attacker", "documentation", "char-a"))
	for _, r := range []string{"char-b", "char-c", "char-d", "char-e"} {
		calls = append(calls, nsFetch(satHost, "attacker", r))
	}
	return calls
}

// burstSet appends exactly fetchDiversityBurstThreshold non-clustering resources
// under one namespace, so only the naming-agnostic COUNT can fire.
func burstSet(calls []map[string]interface{}) []map[string]interface{} {
	for _, r := range []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"} {
		calls = append(calls, nsFetch(satHost, "target", r))
	}
	return calls
}

// TestFetchDiversity_FreshProvenanceSaturationDoesNotStarveDetection is the
// round-4 regression. Retaining provenanced records ahead of ordinary ones is
// what stops a flood from flushing evidence -- but without a cap it becomes a
// STARVATION vector: once every slot carries provenance, each new ordinary fetch
// is the only un-provenanced record and is evicted the instant it is appended.
// No ordinary history can accumulate again, so the cluster arm, the whole-set
// arm AND the burst count all go deaf for the rest of the session, bought with
// ~100 cheap colliding calls in junk namespaces.
func TestFetchDiversity_FreshProvenanceSaturationDoesNotStarveDetection(t *testing.T) {
	// pairs needed to fill the bound: 2 records each.
	full := fetchDiversityHistoryMax / 2

	cases := []struct {
		name  string
		build func([]map[string]interface{}) []map[string]interface{}
		want  FetchDiversitySignal
	}{
		{"bare enumeration (whole-set arm)", bareEnumeration, SignalFetchEnumerablePattern},
		{"colliding decoy attack (cluster arm)", collidingAttack, SignalFetchEnumerablePattern},
		{"burst count", burstSet, SignalFetchDiversityBurst},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// VACUITY CONTROLS: below saturation the same follow-on fires, so a
			// failure at saturation is attributable to eviction starvation.
			for _, pairs := range []int{0, 90} {
				if got := runNSSession(tc.build(saturateFresh(nil, pairs))); got != tc.want {
					t.Fatalf("control: pairs=%d gave %q, want %q", pairs, got, tc.want)
				}
			}
			// At and far beyond saturation the detector must still work.
			for _, pairs := range []int{full, full + 50, 500} {
				if got := runNSSession(tc.build(saturateFresh(nil, pairs))); got != tc.want {
					t.Fatalf("provenance saturation (%d junk pairs) starved detection: got %q, want %q",
						pairs, got, tc.want)
				}
			}
		})
	}
}

// seedExpiredProvenance fills a tracker's history with records whose collision
// provenance is OUTSIDE the window. Seeding directly is what makes expiry
// testable: a session test cannot advance the clock.
func seedExpiredProvenance(tr *FetchDiversityTracker, n int) {
	old := time.Now().Add(-2 * fetchDiversityWindow)
	tr.history.mutate(func(entries []fetchRecord) []fetchRecord {
		for i := 0; i < n; i++ {
			entries = append(entries, fetchRecord{
				host: satHost, namespace: "junk" + strconv.Itoa(i), resource: "r",
				at: old, collidedAt: old,
			})
		}
		return entries
	})
}

// TestFetchDiversity_ExpiredProvenanceSaturationDoesNotStarveDetection pins that
// eviction protection dies with the evidence. Junk provenance that has aged out
// of its own window must not keep excluding new resources -- otherwise a
// long-finished burst of collisions leaves the tracker deaf for the whole
// session, long after anything it proved stopped being true.
func TestFetchDiversity_ExpiredProvenanceSaturationDoesNotStarveDetection(t *testing.T) {
	cases := []struct {
		name  string
		build func([]map[string]interface{}) []map[string]interface{}
		want  FetchDiversitySignal
	}{
		{"bare enumeration (whole-set arm)", bareEnumeration, SignalFetchEnumerablePattern},
		{"colliding decoy attack (cluster arm)", collidingAttack, SignalFetchEnumerablePattern},
		{"burst count", burstSet, SignalFetchDiversityBurst},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// VACUITY CONTROL: with an empty history the follow-on fires.
			if got := runNSSession(tc.build(nil)); got != tc.want {
				t.Fatalf("control: unseeded session gave %q, want %q", got, tc.want)
			}

			tr := NewFetchDiversityTracker()
			seedExpiredProvenance(tr, fetchDiversityHistoryMax)
			var last FetchDiversitySignal
			for _, c := range tc.build(nil) {
				last = tr.Scan("fetch_url", c)
				tr.Record("fetch_url", c)
			}
			if last != tc.want {
				t.Fatalf("stale provenance filling the history starved detection: got %q, want %q", last, tc.want)
			}
		})
	}
}
