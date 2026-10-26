package auth

import (
	"os"
	"path/filepath"
	"testing"
)

// scratchHome points HOME at a fresh directory holding an empty config
// dir, so Load and Save resolve CredentialsPath inside it.
func scratchHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".agentshield"), 0o700); err != nil {
		t.Fatal(err)
	}
	return home
}

func TestLoad_Missing(t *testing.T) {
	scratchHome(t)
	creds, err := Load()
	if creds != nil || err != nil {
		t.Fatalf("Load() = %+v, %v; want nil, nil for a missing file", creds, err)
	}
}

// TestLoad_SaveRoundTrip is the positive control for every "reads as no
// credentials" case: a file Save wrote loads.
func TestLoad_SaveRoundTrip(t *testing.T) {
	scratchHome(t)
	want := &Credentials{Server: "https://saas.example", Token: "tok-4474"}
	want.User.ID = 7
	want.User.Email = "dev@example.com"
	if err := Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil || got == nil {
		t.Fatalf("Load() = %+v, %v; want the saved credentials", got, err)
	}
	if got.Server != want.Server || got.Token != want.Token || got.User.ID != 7 || got.User.Email != want.User.Email {
		t.Errorf("Load() = %+v, want %+v", got, want)
	}
}

func TestLoad_MalformedIsAnError(t *testing.T) {
	scratchHome(t)
	if err := os.WriteFile(CredentialsPath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if creds, err := Load(); creds != nil || err == nil {
		t.Fatalf("Load() = %+v, %v; want nil and a parse error", creds, err)
	}
}

// TestLoad_CapBoundary pins the 64 KiB cap from both sides: a valid file
// of exactly the cap loads, one byte more reads as no credentials. The
// size is written out rather than taken from credentialsMaxBytes, so that
// changing the cap is a visible decision in this test, not a silent shift.
func TestLoad_CapBoundary(t *testing.T) {
	const capBytes = 64 << 10
	scratchHome(t)
	body := func(n int) []byte {
		prefix := `{"server":"https://saas.example","token":"`
		suffix := `"}`
		pad := make([]byte, n-len(prefix)-len(suffix))
		for i := range pad {
			pad[i] = 'a'
		}
		return []byte(prefix + string(pad) + suffix)
	}

	if err := os.WriteFile(CredentialsPath(), body(capBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	if creds, err := Load(); err != nil || creds == nil || creds.Server != "https://saas.example" {
		t.Fatalf("file of exactly %d bytes: Load() returned credentials=%v, err=%v; want it loaded", capBytes, creds != nil, err)
	}

	if err := os.WriteFile(CredentialsPath(), body(capBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if creds, err := Load(); creds != nil || err != nil {
		t.Fatalf("file of %d bytes: Load() returned credentials=%v, err=%v; want nil, nil (over the cap)", capBytes+1, creds != nil, err)
	}
}
