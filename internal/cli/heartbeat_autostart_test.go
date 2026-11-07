package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/homedir"
)

// TestMain must keep daemon auto-start off: before it did, every test HOME
// holding credentials installed a real KeepAlive launchd job (512 on one
// developer Mac, 2026-11-03).
func TestDaemonAutoStart_DisabledUnderTest(t *testing.T) {
	if !daemonAutoStartDisabled {
		t.Fatal("daemonAutoStartDisabled is false: TestMain no longer disables heartbeat daemon auto-start")
	}
	if mayAutoStartHeartbeatDaemon() {
		t.Fatal("mayAutoStartHeartbeatDaemon is true under test")
	}
}

// The guard's truth table, with the TestMain switch lifted for the duration
// and the daemon functions stubbed, so nothing real is started.
func TestDaemonAutoStart_OnlyForTheAccountHome(t *testing.T) {
	home := t.TempDir()
	other := t.TempDir()
	cases := []struct {
		name    string
		account func() (string, error)
		want    bool
	}{
		{"HOME is the account home", func() (string, error) { return home, nil }, true},
		{"HOME is the account home, unclean spelling", func() (string, error) { return home + string(filepath.Separator) + ".", nil }, true},
		{"HOME points elsewhere", func() (string, error) { return other, nil }, false},
		{"account lookup fails", func() (string, error) { return "", errors.New("user: unknown userid") }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("HOME", home)
			defer homedir.SetAccountLookupForTest(c.account)()
			prev := daemonAutoStartDisabled
			daemonAutoStartDisabled = false
			defer func() { daemonAutoStartDisabled = prev }()

			if got := mayAutoStartHeartbeatDaemon(); got != c.want {
				t.Errorf("mayAutoStartHeartbeatDaemon() = %v, want %v", got, c.want)
			}
		})
	}
}

// End to end through sendOpportunisticHeartbeat: with credentials present and
// the daemon "dead", a scratch HOME does not start it and the account's home
// does. The start and liveness functions are stubs.
func TestOpportunisticHeartbeat_StartsTheDaemonOnlyForTheAccountHome(t *testing.T) {
	for _, tc := range []struct {
		name         string
		accountIsHom bool
		wantStarts   int
	}{
		{"scratch HOME", false, 0},
		{"account home", true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			// A cooldown stamp from now, so no heartbeat is POSTed.
			cfg := filepath.Join(home, ".agentshield")
			if err := os.MkdirAll(cfg, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(cfg, "credentials.json"), []byte(`{"token":"test-token","server":"http://127.0.0.1:9"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(cfg, "last_heartbeat"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			account := t.TempDir()
			if tc.accountIsHom {
				account = home
			}
			defer homedir.SetAccountLookupForTest(func() (string, error) { return account, nil })()

			starts := 0
			prevRunning, prevStart, prevDisabled := heartbeatRunning, heartbeatStart, daemonAutoStartDisabled
			heartbeatRunning = func() bool { return false }
			heartbeatStart = func() error { starts++; return nil }
			daemonAutoStartDisabled = false
			defer func() { heartbeatRunning, heartbeatStart, daemonAutoStartDisabled = prevRunning, prevStart, prevDisabled }()

			sendOpportunisticHeartbeat()
			if starts != tc.wantStarts {
				t.Errorf("daemon starts = %d, want %d", starts, tc.wantStarts)
			}
		})
	}
}
