package homedir

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestDir_ReturnsHOME(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	got, err := Dir()
	if err != nil || got != home {
		t.Fatalf("Dir() = %q, %v; want %q, nil", got, err, home)
	}
}

// An empty or unset HOME is ErrNoHome, never "" with a nil error: a caller
// that joined "" with ".claude" would write relative to the working
// directory (#4565).
func TestDir_EmptyOrUnsetHOMEIsErrNoHome(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		t.Setenv("HOME", "")
		if got, err := Dir(); !errors.Is(err, ErrNoHome) || got != "" {
			t.Fatalf("Dir() with HOME empty = %q, %v; want \"\", ErrNoHome", got, err)
		}
	})
	t.Run("unset", func(t *testing.T) {
		t.Setenv("HOME", "") // registers the restore
		if err := os.Unsetenv("HOME"); err != nil {
			t.Fatal(err)
		}
		if got, err := Dir(); !errors.Is(err, ErrNoHome) || got != "" {
			t.Fatalf("Dir() with HOME unset = %q, %v; want \"\", ErrNoHome", got, err)
		}
	})
}

func TestAccount_UsesTheLookup(t *testing.T) {
	want := t.TempDir()
	defer SetAccountLookupForTest(func() (string, error) { return want, nil })()
	if got, err := Account(); err != nil || got != want {
		t.Fatalf("Account() = %q, %v; want %q, nil", got, err, want)
	}
}

// A lookup that fails, or answers with no directory, is an error: the
// managed check then reads $HOME alone (enterprise.ManagedHost).
func TestAccount_LookupErrorOrEmptyIsAnError(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		defer SetAccountLookupForTest(func() (string, error) { return "", errors.New("no such user") })()
		if got, err := Account(); err == nil {
			t.Fatalf("Account() = %q, nil; want an error", got)
		}
	})
	t.Run("empty", func(t *testing.T) {
		defer SetAccountLookupForTest(func() (string, error) { return "", nil })()
		if got, err := Account(); err == nil {
			t.Fatalf("Account() = %q, nil; want an error", got)
		}
	})
}

// A nil lookup falls back to the user database rather than panicking.
func TestAccount_NilLookupUsesTheUserDatabase(t *testing.T) {
	want, wantErr := userDatabaseHome()
	defer SetAccountLookupForTest(nil)()
	got, err := Account()
	if (err != nil) != (wantErr != nil) || (err == nil && got != want) {
		t.Fatalf("Account() with a nil lookup = %q, %v; the user database says %q, %v", got, err, want, wantErr)
	}
}

const envAccountHelper = "AGENTSHIELD_TEST_HOMEDIR_ACCOUNT_HELPER"

// TestHelperAccountProcess is the re-exec target of
// TestAccount_IgnoresHOME: it prints Account() and exits.
func TestHelperAccountProcess(t *testing.T) {
	if os.Getenv(envAccountHelper) != "1" {
		return
	}
	h, err := Account()
	if err != nil {
		os.Stdout.WriteString("error: " + err.Error())
		os.Exit(1)
	}
	os.Stdout.WriteString(h)
	os.Exit(0)
}

// The production lookup ignores $HOME: with HOME pointed elsewhere, empty or
// unset, Account() still names the account's own home. This is what makes
// the redirected-HOME check work (#4565). It runs in a child process per
// HOME value because os/user caches the first answer for the life of a
// process. It reads the user database only, never a file under any home.
//
// Measured with the release build (CGO_ENABLED=0) on darwin. A CGO_ENABLED=0
// linux build reads /etc/passwd and falls back to $HOME for an account that
// is not in it; on such a host this test fails, and that is the gap it names.
func TestAccount_IgnoresHOME(t *testing.T) {
	want, err := Account()
	if err != nil {
		t.Skipf("this account has no home in the user database (%v); nothing to compare", err)
	}
	elsewhere := t.TempDir()
	cases := []struct {
		name string
		home *string // nil: unset
	}{
		{"HOME elsewhere", &elsewhere},
		{"HOME empty", new(string)},
		{"HOME unset", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestHelperAccountProcess$")
			env := []string{envAccountHelper + "=1"}
			for _, kv := range os.Environ() {
				if !strings.HasPrefix(kv, "HOME=") {
					env = append(env, kv)
				}
			}
			if c.home != nil {
				env = append(env, "HOME="+*c.home)
			}
			cmd.Env = env
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("helper: %v\n%s", err, out)
			}
			if got := string(out); got != want {
				t.Errorf("Account() with %s = %q, want the account's home %q: the lookup follows $HOME", c.name, got, want)
			}
		})
	}
}
