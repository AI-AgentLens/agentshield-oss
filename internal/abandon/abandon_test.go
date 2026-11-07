package abandon

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// parkSignal makes a parked goroutine report and unwind (runtime.Goexit)
// instead of sleeping for good, so a test can tell parked from passed.
func parkSignal(t *testing.T) (parked *atomic.Int32) {
	t.Helper()
	parked = new(atomic.Int32)
	restore := SetParkForTest(func() {
		parked.Add(1)
		runtime.Goexit()
	})
	t.Cleanup(func() { restore(); ResetForTest() })
	return parked
}

// runOn runs f on a fresh goroutine and reports whether f returned (true)
// or the goroutine was parked (false).
func runOn(f func()) (returned bool) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		f()
		returned = true
	}()
	wg.Wait()
	return returned
}

// TestCheckpoint_ReturnsUntilStop: before Stop a Checkpoint returns on every
// goroutine, the bound one included. This is the property that keeps an
// evaluation the watchdog never answers exactly as it was.
func TestCheckpoint_ReturnsUntilStop(t *testing.T) {
	parked := parkSignal(t)
	if !runOn(func() { Bind(); Checkpoint(); Checkpoint() }) {
		t.Fatal("the bound goroutine parked before Stop")
	}
	if !runOn(Checkpoint) {
		t.Fatal("an unbound goroutine parked before Stop")
	}
	if parked.Load() != 0 {
		t.Fatalf("parked %d times before Stop", parked.Load())
	}
	if Stopped() {
		t.Fatal("Stopped() before Stop")
	}
}

// TestCheckpoint_ParksOnlyTheBoundGoroutine: after Stop, the goroutine Bind
// named parks at its next Checkpoint and every other goroutine passes: the
// watchdog answering the call reaches no Checkpoint today, and if it ever
// did it must not park itself.
func TestCheckpoint_ParksOnlyTheBoundGoroutine(t *testing.T) {
	parked := parkSignal(t)
	bound := make(chan struct{})
	stop := make(chan struct{})
	var after atomic.Int32
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		Bind()
		close(bound)
		<-stop
		Checkpoint()
		after.Add(1) // never reached: the goroutine parks
	}()
	<-bound
	Stop()
	if !Stopped() {
		t.Fatal("Stopped() false after Stop")
	}
	if !runOn(Checkpoint) {
		t.Fatal("a goroutine other than the bound one parked")
	}
	close(stop)
	wg.Wait()
	if parked.Load() != 1 || after.Load() != 0 {
		t.Fatalf("bound goroutine: parked %d, ran past its Checkpoint %d; want parked once, never past", parked.Load(), after.Load())
	}
}

// TestCheckpoint_UnboundParksNothing: with no goroutine bound (every process
// but the hook, and a hook call with no budget), Stop parks nothing.
func TestCheckpoint_UnboundParksNothing(t *testing.T) {
	parked := parkSignal(t)
	Stop()
	if !runOn(Checkpoint) || parked.Load() != 0 {
		t.Fatalf("an unbound process parked a goroutine after Stop (parked %d)", parked.Load())
	}
}

// TestGoid: ids are positive, stable on one goroutine and distinct across
// goroutines; a Checkpoint keyed on a wrong id would park the wrong one.
func TestGoid(t *testing.T) {
	a, a2 := goid(), goid()
	if a <= 0 || a != a2 {
		t.Fatalf("goid on one goroutine: %d then %d; want one positive id", a, a2)
	}
	var b int64
	runOn(func() { b = goid() })
	if b <= 0 || b == a {
		t.Fatalf("goid on another goroutine: %d (this one %d); want a different positive id", b, a)
	}
}

// TestPark_Sleeps: the production park never returns, and sleeps rather
// than spinning (a parked goroutine must not compete for the CPU).
func TestPark_Sleeps(t *testing.T) {
	done := make(chan struct{})
	go func() { park(); close(done) }()
	select {
	case <-done:
		t.Fatal("park returned")
	case <-time.After(50 * time.Millisecond):
	}
}
