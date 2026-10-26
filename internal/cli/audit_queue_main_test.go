package cli

import (
	"os"
	"testing"
)

// Environment switches for the #4467 upload tests. They are read by TestMain,
// so they apply to this test binary and to every copy of it the tests re-exec.
const (
	// envAuditFlushHelper makes this binary behave as `agentshield
	// audit-flush`: TestMain runs one uploader pass and exits, before the
	// testing framework starts. It is what the detached spawn re-execs.
	envAuditFlushHelper = "AGENTSHIELD_TEST_AUDIT_FLUSH_HELPER"
	// envAuditDetachedSpawn keeps the production detached spawner (the only
	// change is that it re-execs this binary as the uploader). The hook
	// latency, pipe and concurrency tests set it on their hook children.
	envAuditDetachedSpawn = "AGENTSHIELD_TEST_AUDIT_DETACHED_SPAWN"
)

// TestMain decides how the package's tests upload audit events.
//
// By default the upload runs in-process and synchronously (startAuditFlusher
// is replaced by one flushAuditQueue pass). Two reasons: the many tests that
// assert on a capture server's /api/audit bodies right after evaluateCommand
// keep working, now through the real queue and uploader instead of a direct
// POST; and a test can never accidentally re-exec this test binary with
// "audit-flush", which would run the whole suite again in the background.
//
// The detached spawn itself is covered by the helper-process tests in
// audit_queue_e2e_test.go, which set envAuditDetachedSpawn.
func TestMain(m *testing.M) {
	switch {
	case os.Getenv(envAuditFlushHelper) == "1":
		flushAuditQueue()
		os.Exit(0)
	case os.Getenv(envAuditDetachedSpawn) == "1":
		auditFlusherArgv = func() ([]string, []string, error) {
			exe, err := os.Executable()
			if err != nil {
				return nil, nil, err
			}
			return []string{exe}, []string{envAuditFlushHelper + "=1"}, nil
		}
	default:
		startAuditFlusher = func() error {
			flushAuditQueue()
			return nil
		}
	}
	os.Exit(m.Run())
}
