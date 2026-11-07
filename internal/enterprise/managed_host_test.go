package enterprise

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/homedir"
)

// TestManagedHost_AgreesWithCheckDisableAllowed pins ManagedHost to the
// enforcement it describes. The BLOCK hints print "this rule cannot be
// disabled locally" exactly when ManagedHost is true (#4321), so it must say
// "managed" in exactly the states where CheckDisableAllowed refuses. That
// includes a corrupt managed.json, which #3620 reads as managed.
func TestManagedHost_AgreesWithCheckDisableAllowed(t *testing.T) {
	cases := []struct {
		name    string
		content *string // nil: no managed.json at all
		want    bool
	}{
		{"no managed.json", nil, false},
		{"managed: false", strPtr(`{"managed": false}`), false},
		{"managed: true", strPtr(`{"managed": true}`), true},
		{"corrupt file reads as managed (#3620)", strPtr(`{not json`), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			// The account's home is HOME, as on a normal install, so the
			// answer comes from this file and not from the developer's real
			// home (#4565).
			defer homedir.SetAccountLookupForTest(func() (string, error) { return home, nil })()
			if c.content != nil {
				dir := filepath.Join(home, ".agentshield")
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "managed.json"), []byte(*c.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := ManagedHost(); got != c.want {
				t.Errorf("ManagedHost() = %v, want %v", got, c.want)
			}
			if refused := CheckDisableAllowed() != nil; refused != ManagedHost() {
				t.Errorf("CheckDisableAllowed refused=%v but ManagedHost=%v: the hint and the enforcement disagree", refused, ManagedHost())
			}
		})
	}
}

func strPtr(s string) *string { return &s }

// writeManagedFile writes content as home's .agentshield/managed.json.
func writeManagedFile(t *testing.T, home, content string) {
	t.Helper()
	dir := filepath.Join(home, ".agentshield")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "managed.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Managed is a property of the account (#4565). ManagedHost is true when
// managed.json says so under $HOME or under the account's home from the user
// database. When the account lookup fails, or the account's managed.json
// cannot be read, it reads $HOME alone, as main did: an error is no evidence
// of management, so it never denies on its own (Gary, 2026-10-26). The #3620
// rule still holds for $HOME (unreadable or corrupt reads as managed), and
// for corrupt content in a readable file under the account's home. The
// account lookup is faked: a test cannot change the real user database, and
// must not read the developer's home.
//
// The two rows a reverted guard gets wrong: "HOME empty" (main's
// os.UserHomeDir guard errors and reads unmanaged) and "HOME redirected"
// (a $HOME-only reading never sees the account's managed.json).
func TestManagedHost_EitherHomeManaged(t *testing.T) {
	const (
		none      = "none"      // no managed.json
		unmanaged = "unmanaged" // managed: false
		managed   = "managed"   // managed: true
		corrupt   = "corrupt"   // unparseable
		eacces    = "eacces"    // managed: true, in a directory this user cannot read
		dirFile   = "dir-file"  // managed.json is a directory, not a regular file
		same      = "same"      // account home is $HOME
		lookupErr = "lookup-error"
	)
	cases := []struct {
		name    string
		home    string // none, unmanaged, managed, corrupt, eacces, dir-file, or "" for HOME empty
		account string // none, unmanaged, managed, corrupt, eacces, dir-file, same, lookup-error
		want    bool
	}{
		{"normal install, unmanaged", none, same, false},
		{"normal install, managed", managed, same, true},
		{"normal install, managed: false", unmanaged, same, false},
		{"HOME managed, account not", managed, none, true},
		{"HOME redirected away from a managed account", none, managed, true},
		{"HOME redirected to managed: false, account managed", unmanaged, managed, true},
		{"HOME empty, account managed", "", managed, true},
		{"HOME empty, account unmanaged", "", none, false},
		{"HOME unmanaged, account managed.json corrupt (#3620)", none, corrupt, true},
		{"HOME and account both unmanaged, different directories", none, none, false},
		{"account lookup fails, HOME unmanaged: $HOME alone, as main", none, lookupErr, false},
		{"account lookup fails, HOME managed: $HOME alone, as main", managed, lookupErr, true},
		{"account lookup fails, HOME corrupt (#3620): $HOME alone, as main", corrupt, lookupErr, true},
		{"account lookup fails, HOME empty: $HOME alone, as main", "", lookupErr, false},
		{"account managed.json unreadable (EACCES), HOME unmanaged: $HOME alone, as main", none, eacces, false},
		{"account managed.json unreadable (EACCES), HOME managed", managed, eacces, true},
		{"account managed.json not a regular file, HOME unmanaged: $HOME alone, as main", none, dirFile, false},
		{"account managed.json corrupt but readable: managed (#3620)", unmanaged, corrupt, true},
		{"HOME managed.json unreadable (EACCES): managed (#3620)", eacces, none, true},
		{"HOME managed.json not a regular file: managed (#3620)", dirFile, none, true},
	}
	contents := map[string]string{
		unmanaged: `{"managed": false}`,
		managed:   `{"managed": true}`,
		corrupt:   `{not json`,
	}
	// prepare gives dir the managed.json state named by state.
	prepare := func(t *testing.T, dir, state string) {
		t.Helper()
		switch state {
		case eacces:
			if os.Geteuid() == 0 {
				t.Skip("root reads a mode-000 directory, so EACCES cannot be produced")
			}
			writeManagedFile(t, dir, `{"managed": true}`)
			locked := filepath.Join(dir, ".agentshield")
			if err := os.Chmod(locked, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
			if _, err := os.ReadFile(filepath.Join(locked, "managed.json")); !errors.Is(err, os.ErrPermission) {
				t.Fatalf("precondition: reading the locked managed.json gave %v, want permission denied", err)
			}
		case dirFile:
			if err := os.MkdirAll(filepath.Join(dir, ".agentshield", "managed.json"), 0o700); err != nil {
				t.Fatal(err)
			}
		default:
			if body, ok := contents[state]; ok {
				writeManagedFile(t, dir, body)
			}
		}
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := ""
			if c.home != "" {
				home = t.TempDir()
				prepare(t, home, c.home)
			}
			t.Setenv("HOME", home)

			var lookup func() (string, error)
			switch c.account {
			case same:
				lookup = func() (string, error) { return home, nil }
			case lookupErr:
				lookup = func() (string, error) { return "", errors.New("user: unknown userid 4242") }
			default:
				account := t.TempDir()
				prepare(t, account, c.account)
				lookup = func() (string, error) { return account, nil }
			}
			defer homedir.SetAccountLookupForTest(lookup)()

			if got := ManagedHost(); got != c.want {
				t.Errorf("ManagedHost() = %v, want %v", got, c.want)
			}
			if refused := CheckDisableAllowed() != nil; refused != c.want {
				t.Errorf("CheckDisableAllowed refused=%v, want %v: the hint and the enforcement disagree", refused, c.want)
			}
		})
	}
}

// LoadManagedConfig, which the hook reads fail_closed and the rest of the
// enrollment from, still reads $HOME only (#4565 step 1 changes the disable
// check, not where enrollment lives). It finds home with homedir.Dir, so an
// empty HOME reads nil as before.
func TestLoadManagedConfig_ReadsHOMEOnly(t *testing.T) {
	account := t.TempDir()
	writeManagedFile(t, account, `{"managed": true}`)
	defer homedir.SetAccountLookupForTest(func() (string, error) { return account, nil })()

	t.Setenv("HOME", "")
	if cfg := LoadManagedConfig(); cfg != nil {
		t.Errorf("LoadManagedConfig() with HOME empty = %+v, want nil", cfg)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	if cfg := LoadManagedConfig(); cfg != nil {
		t.Errorf("LoadManagedConfig() with no managed.json under HOME = %+v, want nil", cfg)
	}
	writeManagedFile(t, home, `{"managed": true, "fail_closed": true}`)
	if cfg := LoadManagedConfig(); cfg == nil || !cfg.Managed || !cfg.FailClosed {
		t.Errorf("LoadManagedConfig() = %+v, want the managed.json under HOME", cfg)
	}
}
