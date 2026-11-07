package cli

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/auth"
)

// The test profile (#4777): TestMain re-runs the test binary with HOME (and
// on Windows USERPROFILE, APPDATA and LOCALAPPDATA) at a throwaway directory
// (runInTestProfile), so a test that sets no HOME can never read the
// developer's real credentials or queue an upload to the production SaaS.
// TestScanShellProfileGuardBlocks_WithoutHOME_4717 is the check that state
// built at package init sees that profile too.

// TestProfile_TestThatSetsNoHomeReadsNoCredentials is the guard: with no HOME
// of its own, a test's profile is not the account's real home, holds no
// credentials, and an evaluation queues nothing for upload. The control below
// shows the same evaluation does upload once credentials exist, so this
// check can fail. It checks the pin first and stops there when it is
// missing: with no pin, reading credentials and evaluating would be the very
// upload this test guards against.
func TestProfile_TestThatSetsNoHomeReadsNoCredentials(t *testing.T) {
	home := os.Getenv("HOME")
	pinned := os.Getenv(envTestProfilePinned)
	if pinned == "" || home != pinned {
		t.Fatalf("HOME = %q, the pinned profile is %q: TestMain did not pin it", home, pinned)
	}
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		if real, _ := filepath.EvalSymlinks(u.HomeDir); real != "" {
			if got, _ := filepath.EvalSymlinks(home); got == real {
				t.Fatalf("HOME is the account's real home %q", u.HomeDir)
			}
		}
	}
	// The names are listed here, not taken from windowsProfileVars, so the
	// guard does not shrink with the list it checks.
	for _, k := range []string{"USERPROFILE", "APPDATA", "LOCALAPPDATA"} {
		want := windowsProfileVars(pinned)[k]
		v, set := os.LookupEnv(k)
		switch {
		case runtime.GOOS == "windows" && v != want:
			t.Errorf("%s = %q, want %q under the test profile", k, v, want)
		case runtime.GOOS != "windows" && set:
			t.Errorf("%s = %q leaked into the tests", k, v)
		}
	}
	if v, set := os.LookupEnv("COPILOT_HOME"); set {
		t.Errorf("COPILOT_HOME = %q leaked into the tests", v)
	}
	if p := auth.CredentialsPath(); !strings.HasPrefix(p, pinned) {
		t.Errorf("credentials path %q is outside the test profile", p)
	}
	if c := remoteAuditCredentials(); c != nil {
		t.Fatalf("a test with no HOME of its own found credentials for %q", c.Server)
	}

	evaluateCommand("echo hello", home, "claude-code-hook", "profile-4777")
	if entries, err := os.ReadDir(auditQueueDir()); err == nil && len(entries) > 0 {
		t.Errorf("the evaluation queued %d upload file(s) in %s", len(entries), auditQueueDir())
	}
}

// TestProfile_ControlUploadsWithCredentials is the guard's positive control:
// the same evaluation, in a HOME that holds credentials (for a local capture
// server), uploads its event.
func TestProfile_ControlUploadsWithCredentials(t *testing.T) {
	home, _ := newFailSafeHome(t, false, "")
	posted := captureAuditPOSTs(t)
	if remoteAuditCredentials() == nil {
		t.Fatal("control: no credentials after auth.Save")
	}
	evaluateCommand("echo hello", home, "claude-code-hook", "profile-4777-control")
	if n := len(posted()); n != 1 {
		t.Fatalf("control: %d uploads, want 1", n)
	}
}

// TestHelperProfileProcess prints the HOME a re-executed child of this test
// binary runs with.
func TestHelperProfileProcess(t *testing.T) {
	if os.Getenv("AGENTSHIELD_TEST_PROFILE_HELPER") != "1" {
		return
	}
	_, _ = os.Stdout.WriteString(os.Getenv("HOME"))
	os.Exit(0)
}

// TestProfile_ChildrenKeepTheirTestsHome: a child the tests re-exec inherits
// the pinned profile, and a child given its own HOME keeps it (its TestMain
// does not pin again).
func TestProfile_ChildrenKeepTheirTestsHome(t *testing.T) {
	run := func(extra ...string) string {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProfileProcess$")
		cmd.Env = append(append(os.Environ(), "AGENTSHIELD_TEST_PROFILE_HELPER=1"), extra...)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("child: %v", err)
		}
		return string(out)
	}
	if got, want := run(), os.Getenv("HOME"); got != want {
		t.Errorf("child HOME = %q, want the inherited %q", got, want)
	}
	own := t.TempDir()
	if got := run("HOME=" + own); got != own {
		t.Errorf("child HOME = %q, want its test's %q", got, own)
	}
}
