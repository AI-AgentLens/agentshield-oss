package cli

import (
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// #4476: a second HOME must not share the real user's launchd label.
func TestLaunchdLabel_ScratchHomeGetsOwnLabel(t *testing.T) {
	u, err := user.Current()
	if err != nil || u.HomeDir == "" {
		t.Skip("no current user home")
	}
	t.Setenv("HOME", u.HomeDir)
	if got := launchdLabel(); got != launchdBaseLabel {
		t.Fatalf("real home label = %q, want the bare label (no migration)", got)
	}
	a, b := t.TempDir(), t.TempDir()
	t.Setenv("HOME", a)
	la := launchdLabel()
	t.Setenv("HOME", b)
	lb := launchdLabel()
	if la == launchdBaseLabel || lb == launchdBaseLabel || la == lb {
		t.Fatalf("scratch labels must be unique and not the global one: %q %q", la, lb)
	}
	if !strings.HasPrefix(la, launchdBaseLabel+".") {
		t.Fatalf("label %q lost its prefix", la)
	}
	t.Setenv("HOME", a)
	if !strings.HasSuffix(plistPath(), la+".plist") || !strings.Contains(plistPath(), filepath.Join(a, "Library")) {
		t.Fatalf("plist path %q does not follow the label", plistPath())
	}
}

func TestLaunchctlLoadRefused(t *testing.T) {
	for _, out := range []string{"service already loaded", "Load failed: 5: Input/output error", "Could not find specified service"} {
		if !launchctlLoadRefused(out) {
			t.Errorf("%q must be a refusal", out)
		}
	}
	for _, out := range []string{"", "ok"} {
		if launchctlLoadRefused(out) {
			t.Errorf("%q must not be a refusal", out)
		}
	}
}
