package cli

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
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
	// First: a test that sets no HOME gets an empty profile, never the
	// developer's real one (#4777). The binary runs itself again in that
	// profile, so state read at package init sees it too.
	if code, ran := runInTestProfile(); ran {
		os.Exit(code)
	}
	// Every test, and every child the tests re-exec, finds the account's
	// home through the test fake, never the real user database (#4565).
	pinTestAccountHome()
	// No test, and no child a test re-execs, installs a real heartbeat daemon
	// (512 leaked launchd jobs on 2026-11-03).
	daemonAutoStartDisabled = true
	// The same for the shell engine's `~<login>/` reading (#4748).
	pinTestTildeAccount()
	// The routing key's host OS, so a Windows row runs on any CI (#4245).
	pinTestHostOS()
	// The hook's decision budget: a test budget, a slow evaluation, and the
	// claim race (#4772).
	pinTestHookBudget()
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

// envTestProfilePinned names the throwaway profile a process of this test
// binary runs in (runInTestProfile). A child the tests re-exec inherits it
// together with whatever HOME its test gave it, and runs right there, so a
// test that runs the hook against a HOME it prepared (or with no HOME at all)
// gets exactly that. Not AGENTSHIELD_-prefixed: bare_hook_test.go strips
// those from its children.
const envTestProfilePinned = "TESTMAIN_PROFILE_PINNED"

// runInTestProfile runs this test binary again, with the same arguments and
// standard streams, in a fresh, empty profile (pinTestProfile), and returns
// its exit code (#4777). On 2026-11-04 an in-process test that did not set
// HOME read the developer's real ~/.agentshield/credentials.json, and
// sendRemoteAudit queued its fake event for the production SaaS, which the
// in-process flusher then sent.
//
// It re-runs the binary rather than setting HOME in this process because
// package variables are set before TestMain: internal/mcp's config guard
// builds its protected patterns from the home directory in init, so pinning
// HOME here would leave them naming the developer's real home
// (TestScanShellProfileGuardBlocks_WithoutHOME_4717 caught that). A process
// that already runs in one (envTestProfilePinned set: the re-run, and every
// child the tests re-exec) returns ran=false and runs the tests itself.
// Interrupt and terminate are passed on to the re-run.
func runInTestProfile() (code int, ran bool) {
	if os.Getenv(envTestProfilePinned) != "" {
		return 0, false
	}
	dir, err := os.MkdirTemp("", "agentshield-cli-test-profile-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: cannot create the test profile: %v\n", err)
		return 1, true
	}
	defer func() { _ = os.RemoveAll(dir) }()
	pinTestProfile(dir)

	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: cannot run the tests in the test profile: %v\n", err)
		return 1, true
	}
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()
	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() > 0 {
			return ee.ExitCode(), true
		}
		fmt.Fprintf(os.Stderr, "TestMain: the tests in the test profile did not finish: %v\n", err)
		return 1, true
	}
	return 0, true
}

// pinTestProfile points this process's environment at the empty profile dir.
//
// The code finds the profile only through os.UserHomeDir (HOME; USERPROFILE
// on Windows), the account lookup pinTestAccountHome fakes, and COPILOT_HOME
// (setup copilot-cli). On Windows USERPROFILE, APPDATA and LOCALAPPDATA point
// into dir too. Elsewhere they are unset: nothing there reads them as the
// profile, but the PowerShell lane resolves `$env:USERPROFILE` from the
// process environment, and its tests expect the reader's Windows default
// (`~`, under the HOME each test sets), which is what every Mac and Linux CI
// host gives them. A test that sets its own HOME (t.Setenv,
// newFailSafeHome) is unaffected.
func pinTestProfile(dir string) {
	_ = os.Setenv("HOME", dir)
	for k, v := range windowsProfileVars(dir) {
		if runtime.GOOS == "windows" {
			_ = os.Setenv(k, v)
		} else {
			_ = os.Unsetenv(k)
		}
	}
	_ = os.Unsetenv("COPILOT_HOME")
	_ = os.Setenv(envTestProfilePinned, dir)
}

// windowsProfileVars are the Windows profile variables pinTestProfile points
// into the throwaway profile dir on Windows and unsets elsewhere.
func windowsProfileVars(dir string) map[string]string {
	return map[string]string{
		"USERPROFILE":  dir,
		"APPDATA":      filepath.Join(dir, "AppData", "Roaming"),
		"LOCALAPPDATA": filepath.Join(dir, "AppData", "Local"),
	}
}
